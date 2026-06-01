"""Stage 5: deterministic policy rule engine.

Consults prior stages plus the tool-call arguments and matches against POLICIES.
A single match drives the final decision (BLOCK / REQUIRE_APPROVAL); multiple
matches escalate to the strongest action.
"""

from __future__ import annotations

import re
import time
from typing import Iterable

from ..models import Decision, Severity, StageResult, ToolCall
from ..policies import POLICIES, POLICY_BY_ID, Policy

DESTRUCTIVE_SPL_RE = re.compile(
    r"\b(?:\|\s*delete\b|\bcrawl\b|outputlookup[^|]*append\s*=\s*false|"
    r"output(?:csv|lookup)\s+[^|]*[\s\"']_internal|[\s|](_internal|_audit|_introspection))",
    re.IGNORECASE,
)


def _strongest(a: Decision, b: Decision) -> Decision:
    order = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.BLOCK: 2}
    return a if order[a] >= order[b] else b


def _matches(tc: ToolCall, prior: dict[str, StageResult]) -> Iterable[tuple[Policy, str]]:
    spl = (
        tc.arguments.get("query")
        or tc.arguments.get("search")
        or tc.arguments.get("new_search")
        or ""
    )

    # POL-006: injection
    if prior.get("injection") and not prior["injection"].passed:
        yield POLICY_BY_ID["POL-006"], "Injection stage flagged hits."

    # POL-004 / POL-009: destructive primitives / system index writes
    if DESTRUCTIVE_SPL_RE.search(spl):
        if re.search(r"\b_audit\b|\b_internal\b|\b_introspection\b", spl, re.IGNORECASE):
            yield POLICY_BY_ID["POL-009"], f"SPL touches a system index: {spl[:120]!r}"
        else:
            yield POLICY_BY_ID["POL-004"], f"SPL contains destructive primitive: {spl[:120]!r}"

    # POL-001 / POL-002 / POL-003 / POL-010 / POL-011: blast radius
    br = prior.get("blast_radius")
    if br and br.details.get("applicable") is not False:
        details = br.details
        # POL-002 PCI sole-cover
        for a in details.get("assets_affected", []):
            if a["redundancy"] == 0 and "PCI" in a["compliance_tags"]:
                yield POLICY_BY_ID["POL-002"], f"Sole-coverage of PCI asset {a['asset_id']!r}"
            if a["redundancy"] == 0 and "HIPAA" in a["compliance_tags"]:
                yield POLICY_BY_ID["POL-003"], f"Sole-coverage of HIPAA asset {a['asset_id']!r}"
            if a["redundancy"] == 0 and a["criticality"] == "critical":
                yield POLICY_BY_ID["POL-001"], f"Sole-coverage of critical asset {a['asset_id']!r}"
        if br.severity == Severity.CRITICAL:
            yield POLICY_BY_ID["POL-010"], "Blast-radius severity = critical"
        elif br.severity == Severity.HIGH:
            yield POLICY_BY_ID["POL-011"], "Blast-radius severity = high"

    # POL-007: cost
    cost = prior.get("cost")
    if cost and not cost.passed:
        yield POLICY_BY_ID["POL-007"], f"Cost {cost.details.get('estimated_svc_hours')} SVC-h"

    # POL-008: mass change attempt (bulk arg)
    targets = tc.arguments.get("targets") or tc.arguments.get("names")
    if isinstance(targets, list) and len(targets) > 5:
        yield POLICY_BY_ID["POL-008"], f"{len(targets)} targets in one call"

    # POL-012: cross-index reach
    indexes_referenced = (cost.details.get("indexes_referenced", []) if cost else [])
    if len(set(indexes_referenced)) > 5:
        yield POLICY_BY_ID["POL-012"], f"{len(set(indexes_referenced))} distinct indexes"


class PolicyStage:
    name = "policy"

    def evaluate(self, tc: ToolCall, prior: list[StageResult] | None = None) -> StageResult:
        t0 = time.perf_counter()
        prior_map = {s.stage: s for s in (prior or [])}
        matches = list(_matches(tc, prior_map))

        if not matches:
            return StageResult(
                stage=self.name,
                passed=True,
                severity=Severity.LOW,
                reasons=[],
                details={"matched": [], "decision": Decision.ALLOW.value},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        decision = Decision.ALLOW
        matched_details: list[dict[str, object]] = []
        for policy, evidence in matches:
            decision = _strongest(decision, policy.action_on_match)
            matched_details.append({
                "id": policy.id,
                "title": policy.title,
                "rationale": policy.rationale,
                "standards": list(policy.standards),
                "action": policy.action_on_match.value,
                "evidence": evidence,
            })

        passed = decision == Decision.ALLOW
        sev = {
            Decision.ALLOW: Severity.LOW,
            Decision.REQUIRE_APPROVAL: Severity.MEDIUM,
            Decision.BLOCK: Severity.CRITICAL,
        }[decision]
        return StageResult(
            stage=self.name,
            passed=passed,
            severity=sev,
            reasons=[f"{m['id']}: {m['title']}" for m in matched_details],
            details={"matched": matched_details, "decision": decision.value},
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
