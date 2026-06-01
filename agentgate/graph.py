"""Knowledge-object dependency graph: the deterministic core of blast-radius analysis.

Builds a NetworkX DiGraph from Splunk's saved searches + KV store assets:
  saved_search --references--> {index, sourcetype, host, field}
  saved_search --tagged--> {mitre_technique, compliance_tag}
  saved_search --covers--> asset      (derived: search referent intersects asset_id)

Then `blast_radius(saved_search_name)` answers: if I remove or disable this search,
what assets / compliance tags / MITRE techniques lose coverage, and which other
searches share that coverage (the redundancy story).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

import networkx as nx
from rich.console import Console

from .splunk_client import get_service, rest

console = Console()


# --- SPL extraction --------------------------------------------------------

_INDEX_RE = re.compile(r"\bindex\s*=\s*([\w*:_-]+)", re.IGNORECASE)
_SOURCETYPE_RE = re.compile(r"\bsourcetype\s*=\s*([\w*:_-]+)", re.IGNORECASE)
_HOST_RE = re.compile(r"\bhost\s*=\s*([\w*._-]+)", re.IGNORECASE)
_FIELD_EQ_RE = re.compile(r"\b([A-Za-z_][\w]*)\s*=\s*", re.IGNORECASE)
_USER_RE = re.compile(r"\buser\s*=\s*\"?([\w_*-]+)\"?", re.IGNORECASE)

# In description text: [MITRE: T1110.001, T1110] [Compliance: PCI, SOX]
_MITRE_TAG_RE = re.compile(r"\[MITRE:\s*([^\]]+)\]", re.IGNORECASE)
_COMPLIANCE_TAG_RE = re.compile(r"\[Compliance:\s*([^\]]+)\]", re.IGNORECASE)


def _extract_set(regex: re.Pattern[str], text: str) -> set[str]:
    return {m.lower() for m in regex.findall(text or "")}


def _extract_tags(regex: re.Pattern[str], text: str) -> set[str]:
    out: set[str] = set()
    for m in regex.findall(text or ""):
        for tag in m.split(","):
            tag = tag.strip()
            if tag:
                out.add(tag.upper())
    return out


def parse_spl_references(spl: str) -> dict[str, set[str]]:
    """Cheap, intentionally-permissive SPL parser. Catches the common predicates we seed."""
    return {
        "indexes": _extract_set(_INDEX_RE, spl),
        "sourcetypes": _extract_set(_SOURCETYPE_RE, spl),
        "hosts": _extract_set(_HOST_RE, spl),
        "users": _extract_set(_USER_RE, spl),
        "fields": _extract_set(_FIELD_EQ_RE, spl),
    }


# --- Graph build -----------------------------------------------------------


@dataclass
class GraphArtifact:
    graph: nx.DiGraph
    saved_searches: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n, **(d or {})}
                for n, d in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **(d or {})}
                for u, v, d in self.graph.edges(data=True)
            ],
            "saved_searches": self.saved_searches,
            "assets": self.assets,
        }


def _node(kind: str, value: str) -> str:
    return f"{kind}:{value}".lower()


def _add_asset_nodes(g: nx.DiGraph, assets: Iterable[dict[str, Any]]) -> list[str]:
    """Merge asset metadata onto the underlying kind:value node (no separate asset:X node).
    Sets is_asset=True and copies compliance_tags / criticality / owner / asset_type onto it."""
    asset_ids: list[str] = []
    for a in assets:
        nid = a["asset_id"].lower()
        existing = dict(g.nodes.get(nid, {}))
        kind, value = nid.split(":", 1) if ":" in nid else ("asset", nid)
        existing.update({
            "kind": kind,
            "value": value,
            "is_asset": True,
            "asset_type": a.get("asset_type", kind),
            "compliance_tags": a.get("compliance_tags", []),
            "criticality": a.get("criticality", "medium"),
            "owner": a.get("owner", ""),
        })
        g.add_node(nid, **existing)
        asset_ids.append(nid)
    return asset_ids


def _add_search_node(g: nx.DiGraph, name: str, spec: dict[str, Any]) -> None:
    spl = spec.get("search", "") or ""
    desc = spec.get("description", "") or ""
    refs = parse_spl_references(spl)
    mitre = _extract_tags(_MITRE_TAG_RE, desc)
    compliance = _extract_tags(_COMPLIANCE_TAG_RE, desc)

    g.add_node(
        _node("saved_search", name),
        kind="saved_search",
        name=name,
        spl=spl,
        description=desc,
        cron_schedule=spec.get("cron_schedule"),
        mitre_techniques=sorted(mitre),
        compliance_tags=sorted(compliance),
        references=refs,
    )
    for index in refs["indexes"]:
        n = _node("index", index)
        g.add_node(n, kind="index", value=index)
        g.add_edge(_node("saved_search", name), n, edge="references")
    for st in refs["sourcetypes"]:
        n = _node("sourcetype", st)
        g.add_node(n, kind="sourcetype", value=st)
        g.add_edge(_node("saved_search", name), n, edge="references")
    for h in refs["hosts"]:
        n = _node("host", h)
        g.add_node(n, kind="host", value=h)
        g.add_edge(_node("saved_search", name), n, edge="references")
    for u in refs["users"]:
        n = _node("user", u)
        g.add_node(n, kind="user", value=u)
        g.add_edge(_node("saved_search", name), n, edge="references")
    for t in mitre:
        n = _node("mitre", t)
        g.add_node(n, kind="mitre", value=t)
        g.add_edge(_node("saved_search", name), n, edge="tagged")
    for c in compliance:
        n = _node("compliance", c)
        g.add_node(n, kind="compliance", value=c)
        g.add_edge(_node("saved_search", name), n, edge="tagged")


def _wire_search_to_asset_coverage(g: nx.DiGraph) -> None:
    """For each node flagged is_asset, look back at incoming 'references' edges
    from saved-search nodes and add a parallel 'covers' edge so blast-radius queries
    can ignore non-asset references."""
    asset_nodes = [n for n, d in g.nodes(data=True) if d.get("is_asset")]
    for asset in asset_nodes:
        for u, _, d in list(g.in_edges(asset, data=True)):
            if d.get("edge") == "references" and g.nodes[u].get("kind") == "saved_search":
                g.add_edge(u, asset, edge="covers")


def build_graph() -> GraphArtifact:
    """Walk Splunk via REST to pull saved searches + assets, then build the graph.

    Uses the stateless REST helper rather than the SDK Collection iteration
    because the SDK mutates internal namespace state when crossing endpoints
    (saved_searches → kvstore → saved_searches), producing flaky cross-test
    results. REST is order-independent and deterministic.
    """
    g = nx.DiGraph()

    # 1) Saved searches via REST, count=0 means all.
    search_names: list[str] = []
    r = rest("GET", "/services/saved/searches", params={"count": "0"})
    r.raise_for_status()
    for entry in r.json().get("entry", []):
        name = entry["name"]
        if not name.startswith("AG:"):
            continue
        content = entry.get("content", {})
        spec = {
            "search": content.get("search", ""),
            "description": content.get("description", ""),
            "cron_schedule": content.get("cron_schedule", ""),
        }
        _add_search_node(g, name, spec)
        search_names.append(name)

    # 2) Assets via REST. The KV store query endpoint returns plain JSON.
    r = rest("GET", "/servicesNS/nobody/search/storage/collections/data/agentgate_assets")
    if r.status_code == 200:
        assets_raw = r.json() if r.text else []
    else:
        # Fallback to the SDK only if REST fails (last resort).
        assets_raw = list(get_service().kvstore["agentgate_assets"].data.query())
    assets: list[dict[str, Any]] = []
    for raw in assets_raw:
        a = dict(raw)
        a.pop("_user", None)
        a.pop("_key", None)
        tags = a.get("compliance_tags", "")
        if isinstance(tags, str):
            a["compliance_tags"] = [t.strip() for t in tags.split(",") if t.strip()]
        assets.append(a)
    asset_ids = _add_asset_nodes(g, assets)

    _wire_search_to_asset_coverage(g)
    return GraphArtifact(graph=g, saved_searches=search_names, assets=asset_ids)


# --- Blast-radius analysis -------------------------------------------------


@dataclass
class BlastRadiusReport:
    target_search: str
    techniques_lost: list[str]
    compliance_lost: list[str]
    assets_affected: list[dict[str, Any]]
    redundant_searches: dict[str, list[str]]  # asset_id -> [other search names covering it]
    severity: str  # low/medium/high/critical

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_search": self.target_search,
            "techniques_lost": self.techniques_lost,
            "compliance_lost": self.compliance_lost,
            "assets_affected": self.assets_affected,
            "redundant_searches": self.redundant_searches,
            "severity": self.severity,
        }


def blast_radius(artifact: GraphArtifact, search_name: str) -> BlastRadiusReport:
    g = artifact.graph
    src = _node("saved_search", search_name)
    if src not in g:
        return BlastRadiusReport(
            target_search=search_name,
            techniques_lost=[],
            compliance_lost=[],
            assets_affected=[],
            redundant_searches={},
            severity="low",
        )

    # MITRE & compliance tags this search alone holds vs. shared
    own_tags: dict[str, set[str]] = defaultdict(set)
    shared_tags: dict[str, set[str]] = defaultdict(set)
    for _, target, d in g.out_edges(src, data=True):
        if d.get("edge") != "tagged":
            continue
        kind = g.nodes[target].get("kind")
        peers = [u for u, _, dd in g.in_edges(target, data=True)
                 if dd.get("edge") == "tagged" and u != src and g.nodes[u].get("kind") == "saved_search"]
        if peers:
            shared_tags[kind].add(g.nodes[target]["value"])
        else:
            own_tags[kind].add(g.nodes[target]["value"])

    # Assets this search covers
    covered_assets = [
        target for _, target, d in g.out_edges(src, data=True)
        if d.get("edge") == "covers"
    ]
    assets_affected: list[dict[str, Any]] = []
    redundant: dict[str, list[str]] = {}
    for a in covered_assets:
        peers = [
            g.nodes[u]["name"]
            for u, _, dd in g.in_edges(a, data=True)
            if dd.get("edge") == "covers" and u != src and g.nodes[u].get("kind") == "saved_search"
        ]
        node = g.nodes[a]
        assets_affected.append({
            "asset_id": a,
            "criticality": node.get("criticality", "medium"),
            "compliance_tags": node.get("compliance_tags", []),
            "owner": node.get("owner", ""),
            "redundancy": len(peers),
        })
        redundant[a] = sorted(peers)

    # Severity: assets-with-zero-redundancy + critical/PCI/HIPAA tag escalates
    lone = [a for a in assets_affected if a["redundancy"] == 0]
    critical_lone = [a for a in lone if a["criticality"] in ("high", "critical")
                     or any(t in ("PCI", "HIPAA", "SOX") for t in a["compliance_tags"])]
    if critical_lone:
        severity = "critical"
    elif lone:
        severity = "high"
    elif own_tags.get("mitre") or own_tags.get("compliance"):
        severity = "medium"
    else:
        severity = "low"

    return BlastRadiusReport(
        target_search=search_name,
        techniques_lost=sorted(own_tags.get("mitre", set())),
        compliance_lost=sorted(own_tags.get("compliance", set())),
        assets_affected=assets_affected,
        redundant_searches=redundant,
        severity=severity,
    )


# --- CLI smoke entry -------------------------------------------------------


def main() -> int:
    artifact = build_graph()
    g = artifact.graph
    console.rule("[bold cyan]AgentGate dependency graph[/bold cyan]")
    console.print(f"  nodes: {g.number_of_nodes()}  edges: {g.number_of_edges()}")
    console.print(f"  saved searches indexed: {len(artifact.saved_searches)}")
    console.print(f"  assets indexed: {len(artifact.assets)}")
    if artifact.saved_searches:
        sample = artifact.saved_searches[0]
        report = blast_radius(artifact, sample)
        console.print(f"\nsample blast radius for [bold]{sample}[/bold]:")
        console.print_json(json.dumps(report.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
