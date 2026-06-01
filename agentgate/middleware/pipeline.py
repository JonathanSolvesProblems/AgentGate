"""The orchestrator: runs the six-stage pipeline and synthesises a GateVerdict.

Stage 6 = synthesis. Decision rule:
- any BLOCK from policy stage   → BLOCK
- any REQUIRE_APPROVAL          → REQUIRE_APPROVAL  (a Finding is drafted)
- everything passes             → ALLOW
"""

from __future__ import annotations

import time
import uuid
from typing import Protocol

from ..graph import GraphArtifact, build_graph
from ..models import Decision, GateVerdict, StageResult, ToolCall
from .blast_radius import BlastRadiusStage
from .cost import CostStage
from .injection import InjectionStage
from .policy import PolicyStage
from .reasoning import ReasoningStage


class Stage(Protocol):
    name: str

    def evaluate(self, tc: ToolCall, prior: list[StageResult] | None = ...) -> StageResult: ...


def _summary_line(verdict: GateVerdict) -> str:
    pol = next((s for s in verdict.stages if s.stage == "policy"), None)
    if pol and pol.reasons:
        return f"{verdict.decision.value.upper()}: {'; '.join(pol.reasons)}"
    return f"{verdict.decision.value.upper()}: no policy match"


class Pipeline:
    def __init__(self, stages: list[Stage]) -> None:
        self.stages = stages

    def evaluate(self, tc: ToolCall) -> GateVerdict:
        t0 = time.perf_counter()
        prior: list[StageResult] = []

        for stage in self.stages:
            # Reasoning + Policy stages want prior context; others ignore it.
            try:
                if stage.name in ("reasoning", "policy"):
                    result = stage.evaluate(tc, prior)  # type: ignore[call-arg]
                else:
                    result = stage.evaluate(tc)
            except Exception as exc:
                from ..models import Severity
                result = StageResult(
                    stage=stage.name,
                    passed=True,
                    severity=Severity.LOW,
                    reasons=[],
                    details={"error": str(exc)[:200]},
                )
            prior.append(result)

        decision = _decide(prior)
        verdict = GateVerdict(
            tool_call=tc,
            decision=decision,
            stages=prior,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
        if decision == Decision.REQUIRE_APPROVAL:
            verdict.finding_id = f"finding-{uuid.uuid4().hex[:12]}"
        verdict.summary = _summary_line(verdict)
        return verdict


def _decide(prior: list[StageResult]) -> Decision:
    pol = next((s for s in prior if s.stage == "policy"), None)
    if pol:
        d = pol.details.get("decision")
        if d == Decision.BLOCK.value:
            return Decision.BLOCK
        if d == Decision.REQUIRE_APPROVAL.value:
            return Decision.REQUIRE_APPROVAL
    return Decision.ALLOW


def build_default_pipeline(artifact: GraphArtifact | None = None) -> Pipeline:
    artifact = artifact or build_graph()
    return Pipeline([
        InjectionStage(),
        BlastRadiusStage(artifact),
        CostStage(),
        ReasoningStage(),
        PolicyStage(),
    ])
