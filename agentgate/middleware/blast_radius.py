"""Stage 2: blast-radius analysis using the KO dependency graph.

Only meaningful for write actions that affect saved searches or assets.
For read-only tool calls (e.g. splunk_run_query), this stage passes through.
"""

from __future__ import annotations

import time

from ..graph import GraphArtifact, blast_radius
from ..models import Severity, StageResult, ToolCall

WRITE_TOOLS_THAT_TARGET_SEARCH: frozenset[str] = frozenset({
    "propose_disable_saved_search",
    "propose_modify_saved_search",
    "propose_delete_saved_search",
})

SEVERITY_MAP: dict[str, Severity] = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class BlastRadiusStage:
    name = "blast_radius"

    def __init__(self, artifact: GraphArtifact) -> None:
        self.artifact = artifact

    def evaluate(self, tc: ToolCall) -> StageResult:
        t0 = time.perf_counter()
        if tc.tool_name not in WRITE_TOOLS_THAT_TARGET_SEARCH:
            return StageResult(
                stage=self.name,
                passed=True,
                severity=Severity.LOW,
                reasons=[],
                details={"applicable": False},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        name = tc.arguments.get("name") or tc.arguments.get("saved_search")
        if not name:
            return StageResult(
                stage=self.name,
                passed=False,
                severity=Severity.MEDIUM,
                reasons=["tool call missing 'name' argument"],
                details={},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        report = blast_radius(self.artifact, name)
        severity = SEVERITY_MAP[report.severity]
        passed = severity in (Severity.LOW, Severity.MEDIUM)
        reasons: list[str] = []
        critical_lone = [a for a in report.assets_affected
                         if a["redundancy"] == 0 and a["criticality"] in ("high", "critical")]
        for a in critical_lone:
            reasons.append(
                f"removes sole coverage of {a['asset_id']} (criticality={a['criticality']}, "
                f"tags={','.join(a['compliance_tags']) or 'none'})"
            )
        if report.techniques_lost:
            reasons.append(f"loses unique MITRE coverage: {', '.join(report.techniques_lost)}")
        if report.compliance_lost:
            reasons.append(f"loses unique compliance coverage: {', '.join(report.compliance_lost)}")

        return StageResult(
            stage=self.name,
            passed=passed,
            severity=severity,
            reasons=reasons,
            details=report.to_dict(),
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
