"""Stage 4: side-effect reasoning via Foundation-Sec-8B.

Only invoked when prior stages produced a non-trivial signal (severity >= medium
or any blast-radius / cost concern). The model returns a structured paragraph
that gets stored as a stage detail for human reviewers in the Finding.

To keep the demo snappy we cap output to 180 tokens and use temperature 0.1.
"""

from __future__ import annotations

import time

from ollama import Client

from ..config import get_settings
from ..models import Severity, StageResult, ToolCall

SYSTEM_PROMPT = (
    "You are a Splunk security architect reviewing an automated AI-agent action. "
    "Given the proposed tool call and the prior pipeline findings, write 3-5 sentences "
    "naming the specific risk to the organisation. Cite MITRE techniques and compliance "
    "frameworks by name when relevant. Be concrete. Do not hedge."
)


class ReasoningStage:
    name = "reasoning"

    def __init__(self, client: Client | None = None) -> None:
        s = get_settings()
        self.client = client or Client(host=s.ollama_host)
        self.model = s.ollama_model

    def evaluate(self, tc: ToolCall, prior: list[StageResult] | None = None) -> StageResult:
        t0 = time.perf_counter()
        prior = prior or []
        # Only reason when stakes are non-trivial.
        max_severity = max((s.severity for s in prior), default=Severity.LOW, key=_sev_rank)
        if _sev_rank(max_severity) < _sev_rank(Severity.MEDIUM):
            return StageResult(
                stage=self.name,
                passed=True,
                severity=Severity.LOW,
                reasons=[],
                details={"skipped": True, "reason": "low prior severity"},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        prior_summary = "\n".join(
            f"- stage {s.stage}: severity={s.severity.value} reasons={'; '.join(s.reasons) or 'n/a'}"
            for s in prior
        )
        user_prompt = (
            f"Proposed tool call: {tc.tool_name}({tc.arguments})\n\n"
            f"Prior pipeline findings:\n{prior_summary}\n\n"
            "What is the concrete security risk if this action is allowed?"
        )
        try:
            resp = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0.1, "num_predict": 180},
            )
            text = resp["message"]["content"].strip()
            return StageResult(
                stage=self.name,
                passed=True,  # reasoning never blocks; it informs
                severity=Severity.LOW,
                reasons=[],
                details={"reasoning": text, "model": self.model, "tokens": resp.get("eval_count")},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )
        except Exception as exc:  # never break the pipeline on model errors
            return StageResult(
                stage=self.name,
                passed=True,
                severity=Severity.LOW,
                reasons=[],
                details={"error": str(exc)[:200]},
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )


def _sev_rank(s: Severity) -> int:
    return {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}[s]
