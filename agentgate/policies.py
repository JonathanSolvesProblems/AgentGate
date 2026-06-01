"""Seed policy library mapped to NIST AI RMF, OWASP LLM Top 10, EU AI Act Art. 14,
PCI DSS 10, HIPAA 164.308, SOX, ISO/IEC 42001. Twelve policies."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Decision


@dataclass(frozen=True)
class Policy:
    id: str
    title: str
    rationale: str
    action_on_match: Decision
    standards: tuple[str, ...] = field(default_factory=tuple)


POLICIES: list[Policy] = [
    Policy(
        id="POL-001",
        title="Critical asset, zero coverage redundancy",
        rationale="Disabling the only detection covering an asset with criticality=critical "
                  "removes mandatory monitoring required by EU AI Act Article 14 human oversight.",
        action_on_match=Decision.BLOCK,
        standards=("EU AI Act Art. 14", "NIST AI RMF MANAGE-2.3"),
    ),
    Policy(
        id="POL-002",
        title="PCI-tagged asset, no redundant coverage",
        rationale="PCI DSS 10.6 requires daily review of cardholder-data-environment logs. "
                  "Removing the sole detection violates the standard.",
        action_on_match=Decision.BLOCK,
        standards=("PCI DSS 10.6", "PCI DSS 10.2.4"),
    ),
    Policy(
        id="POL-003",
        title="HIPAA-tagged asset, no redundant coverage",
        rationale="HIPAA 164.308(a)(1)(ii)(D) Information System Activity Review requires "
                  "detection of unauthorized access to ePHI.",
        action_on_match=Decision.BLOCK,
        standards=("HIPAA 164.308(a)(1)(ii)(D)",),
    ),
    Policy(
        id="POL-004",
        title="Destructive SPL primitive",
        rationale="SPL containing `delete`, `crawl`, `outputlookup append=false`, or write "
                  "to indexes prefixed `_` is destructive and not allowed without human approval.",
        action_on_match=Decision.BLOCK,
        standards=("NIST AI RMF GOVERN-1.4", "OWASP LLM08 Excessive Agency"),
    ),
    Policy(
        id="POL-005",
        title="Cross-team lookup modification",
        rationale="Changing a lookup owned by a different team without their approval violates "
                  "SOX segregation of duties.",
        action_on_match=Decision.REQUIRE_APPROVAL,
        standards=("SOX SoD",),
    ),
    Policy(
        id="POL-006",
        title="Prompt injection detected",
        rationale="Tool inputs contain instructions consistent with OWASP LLM01 indirect "
                  "injection. The user's intent cannot be trusted.",
        action_on_match=Decision.BLOCK,
        standards=("OWASP LLM01",),
    ),
    Policy(
        id="POL-007",
        title="High predicted scan cost",
        rationale="Predicted SVC consumption exceeds 1 SVC-hour. Surface to a human to confirm "
                  "the cost is intentional.",
        action_on_match=Decision.REQUIRE_APPROVAL,
        standards=("NIST AI RMF MEASURE-2.7",),
    ),
    Policy(
        id="POL-008",
        title="Mass-change attempt",
        rationale="A single tool call affecting more than five saved searches or one whole "
                  "index is an Excessive Agency pattern.",
        action_on_match=Decision.BLOCK,
        standards=("OWASP LLM08 Excessive Agency", "ISO/IEC 42001"),
    ),
    Policy(
        id="POL-009",
        title="Mutation of internal/audit index",
        rationale="Writes or deletes against indexes beginning with `_` (e.g., _internal, _audit) "
                  "are forbidden — they store the system of record.",
        action_on_match=Decision.BLOCK,
        standards=("SOX audit integrity",),
    ),
    Policy(
        id="POL-010",
        title="Severity-critical blast radius",
        rationale="Blast-radius analyser graded the action as critical (unique coverage of a "
                  "high-criticality, regulated asset).",
        action_on_match=Decision.BLOCK,
        standards=("NIST AI RMF MANAGE-2.3",),
    ),
    Policy(
        id="POL-011",
        title="Severity-high blast radius",
        rationale="Blast-radius analyser graded the action as high — unique coverage on a "
                  "non-regulated asset. A human should confirm.",
        action_on_match=Decision.REQUIRE_APPROVAL,
        standards=("NIST AI RMF MANAGE-2.3",),
    ),
    Policy(
        id="POL-012",
        title="Cross-index reach",
        rationale="A single SPL search referencing more than five indexes is anomalous and "
                  "may be data exfiltration. Surface to a human.",
        action_on_match=Decision.REQUIRE_APPROVAL,
        standards=("NIST AI RMF MEASURE-2.7",),
    ),
]

POLICY_BY_ID = {p.id: p for p in POLICIES}
