"""Stage 3: cost / scan-size prediction for SPL search calls.

The Cisco Deep Time Series Model would baseline event volume on Splunk Cloud.
On a dev license we approximate with a fast static heuristic over the search
text + index size hints from REST. Replaceable with CDTSM in a Cloud deploy.
"""

from __future__ import annotations

import re
import time

from ..models import Severity, StageResult, ToolCall

_INDEX_RE = re.compile(r"\bindex\s*=\s*([\w*:_-]+)", re.IGNORECASE)
_TIME_HINT_RE = re.compile(r"earliest\s*=\s*(-?\d+)([smhdw])", re.IGNORECASE)
_NO_TERMS_AFTER_PIPE_RE = re.compile(r"\|\s*(?:stats|table|chart|timechart)\b", re.IGNORECASE)

# Rough scan-cost weights: longer windows + more indexes + post-pipe heavy = costlier.
INDEX_COST = 0.10  # SVC-hour per index reference, baseline
WIDE_WINDOW_MULT = 4.0  # >24h window
NO_FILTER_PENALTY = 2.0


def estimate_svc_hours(spl: str) -> float:
    if not spl:
        return 0.0
    indexes = _INDEX_RE.findall(spl)
    cost = max(len(indexes), 1) * INDEX_COST

    # Time-window heuristic
    tm = _TIME_HINT_RE.search(spl)
    if tm:
        n = int(tm.group(1))
        unit = tm.group(2).lower()
        seconds = abs(n) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        if seconds > 86400:
            cost *= WIDE_WINDOW_MULT
    else:
        # No explicit window in SPL string → defaults to "all time"; assume wide.
        cost *= WIDE_WINDOW_MULT

    # No early-filter penalty (search starts with `| stats ...` without preceding filter)
    if spl.strip().startswith("|") or _NO_TERMS_AFTER_PIPE_RE.search(spl[:100]):
        cost *= NO_FILTER_PENALTY

    return cost


class CostStage:
    name = "cost"
    high_threshold_svc_h = 1.0

    def evaluate(self, tc: ToolCall) -> StageResult:
        t0 = time.perf_counter()
        spl: str | None = None
        if tc.tool_name == "splunk_run_query":
            spl = tc.arguments.get("query") or tc.arguments.get("search") or tc.arguments.get("spl")
        elif tc.tool_name == "propose_modify_saved_search":
            spl = tc.arguments.get("new_search") or tc.arguments.get("search")

        if not spl:
            return StageResult(
                stage=self.name,
                passed=True,
                severity=Severity.LOW,
                reasons=[],
                details={"applicable": False},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        svc_h = estimate_svc_hours(spl)
        passed = svc_h <= self.high_threshold_svc_h
        severity = Severity.MEDIUM if not passed else Severity.LOW
        reasons = [] if passed else [
            f"predicted SVC consumption {svc_h:.2f} SVC-h exceeds threshold {self.high_threshold_svc_h:.2f}",
        ]
        indexes = _INDEX_RE.findall(spl)
        return StageResult(
            stage=self.name,
            passed=passed,
            severity=severity,
            reasons=reasons,
            details={"estimated_svc_hours": round(svc_h, 3), "indexes_referenced": indexes},
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
