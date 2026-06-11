"""Draft a Finding into a Splunk KV-store collection that mimics ES 8 v2
/public/v2/investigations/{id}/findings.

On a real ES 8 deployment, swap this for the corresponding REST call. The
schema mirrors the ES Finding shape: status, severity, description, owner.
"""

from __future__ import annotations

import json

from rich.console import Console

from .models import GateVerdict
from .splunk_client import get_service

console = Console()

COLLECTION = "agentgate_findings"

FIELDS = {
    "field.finding_id": "string",
    "field.created_at": "string",
    "field.agent_id": "string",
    "field.tool_name": "string",
    "field.arguments": "string",
    "field.decision": "string",
    "field.severity": "string",
    "field.summary": "string",
    "field.status": "string",
    "field.matched_policies": "string",
    "field.stages_json": "string",
}


def ensure_collection() -> None:
    service = get_service()
    if COLLECTION in service.kvstore:
        return
    service.kvstore.create(COLLECTION, **FIELDS)


def draft(verdict: GateVerdict) -> str | None:
    """Persist a Finding for every non-ALLOW verdict. REQUIRE_APPROVAL goes in
    as status=pending (waiting on analyst), BLOCK goes in as status=blocked
    (historical record). ALLOW verdicts don't draft a Finding (they live in
    the audit index only)."""
    from .models import Decision

    if verdict.decision == Decision.ALLOW:
        return None
    if verdict.finding_id is None:
        import uuid
        verdict.finding_id = f"finding-{uuid.uuid4().hex[:12]}"
    ensure_collection()
    service = get_service()
    coll = service.kvstore[COLLECTION].data

    pol = next((s for s in verdict.stages if s.stage == "policy"), None)
    matched_policies = []
    if pol:
        for m in pol.details.get("matched", []):
            matched_policies.append(f"{m['id']}: {m['title']}")

    max_sev = max(
        (s.severity for s in verdict.stages),
        key=lambda x: {"low": 0, "medium": 1, "high": 2, "critical": 3}[x.value],
        default=None,
    )

    body = {
        "finding_id": verdict.finding_id,
        "created_at": verdict.tool_call.requested_at.isoformat(),
        "agent_id": verdict.tool_call.agent_id,
        "tool_name": verdict.tool_call.tool_name,
        "arguments": json.dumps(verdict.tool_call.arguments),
        "decision": verdict.decision.value,
        "severity": (max_sev.value if max_sev else "low"),
        "summary": verdict.summary,
        "status": "blocked" if verdict.decision.value == "block" else "pending",
        "matched_policies": "; ".join(matched_policies),
        "stages_json": json.dumps([
            {
                "stage": s.stage,
                "passed": s.passed,
                "severity": s.severity.value,
                "reasons": s.reasons,
                "details": s.details,
                "elapsed_ms": s.elapsed_ms,
            } for s in verdict.stages
        ]),
    }
    coll.insert(json.dumps(body))
    return verdict.finding_id
