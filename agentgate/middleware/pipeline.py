"""The orchestrator: runs the pipeline and synthesises a GateVerdict.

The decision is driven entirely by the policy stage. Five deterministic stages
plus one ADVISORY sixth (reasoning) — the verdict reads only the policy stage,
so reasoning's paragraph informs the analyst but never gates the call. This
keeps the decision reproducible from the policy library alone (a property
compliance auditors demand) while still giving analysts semantic context.

Decision rule (policy-stage output only):
- BLOCK from policy stage         → BLOCK
- REQUIRE_APPROVAL from policy    → REQUIRE_APPROVAL  (a Finding is drafted)
- everything passes               → ALLOW

Fail-closed semantics: if the policy stage raises, the verdict is BLOCK with
severity=HIGH. Other stages that raise degrade to a passing low-severity
StageResult with the error recorded in details — they are not gate-deciding,
so a transient failure should not deny a benign call. This split (advisory
stages fail open, the gating stage fails closed) is enforced and tested.
"""

from __future__ import annotations

import time
import uuid
from typing import Protocol

from ..graph import GraphArtifact, build_graph
from ..models import Decision, GateVerdict, Severity, StageResult, ToolCall
from .blast_radius import BlastRadiusStage
from .cost import CostStage
from .injection import InjectionStage
from .policy import PolicyStage
from .reasoning import ReasoningStage

GATING_STAGE = "policy"


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
                if stage.name == GATING_STAGE:
                    # Fail closed on the gating stage. A crash here would otherwise
                    # silently degrade BLOCK to ALLOW (the verdict reads details
                    # ['decision']; missing key means ALLOW). Force BLOCK instead.
                    result = StageResult(
                        stage=stage.name,
                        passed=False,
                        severity=Severity.HIGH,
                        reasons=[f"gating stage raised: {type(exc).__name__}"],
                        details={
                            "decision": Decision.BLOCK.value,
                            "error": str(exc)[:200],
                            "fail_closed": True,
                        },
                    )
                else:
                    # Advisory / non-gating stages fail open with a low-severity
                    # passing result — a transient model or network blip should
                    # not deny a benign call.
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
