"""Stage 1: prompt-injection detection on tool inputs and any incoming context the
agent has been exposed to (Splunk log lines it just read, etc.).

This is intentionally heuristic, not ML. Heuristics are deterministic, auditable,
and have a publishable false-positive rate — properties enterprise compliance teams
want. A future iteration could call splunklib.ai.detect_injection() as a second
opinion.
"""

from __future__ import annotations

import re
import time
from typing import Iterable

from ..models import Severity, StageResult, ToolCall

# Patterns drawn from published injection corpora (NIST AISC, Anthropic redteam,
# WithSecure indirect-injection examples, Simon Willison's living taxonomy).
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("override_instruction", re.compile(
        r"\b(?:ignore|disregard|forget|reset)\s+(?:all\s+|the\s+|any\s+)?"
        r"(?:previous|prior|above|earlier|your|the\s+system)?\s*"
        r"(?:instructions?|prompts?|messages?|rules?|policies|policy|guidelines?|context)\b",
        re.IGNORECASE,
    )),
    ("system_persona", re.compile(
        r"<\|?\s*(?:system|assistant|im_start|im_end)\s*\|?>",
        re.IGNORECASE,
    )),
    ("jailbreak_persona", re.compile(
        r"\b(?:you\s+are\s+now|act\s+as(?:\s+if(?:\s+you\s+are)?)?|pretend\s+to\s+be|behave\s+as|roleplay\s+as)\s+"
        r"(?:an?\s+)?(?:\w+\s+){0,4}"
        r"(?:DAN|developer\s+mode|jailbroken|unrestricted|uncensored|no\s+filter|root\s+access|no\s+policy\s+constraints?)",
        re.IGNORECASE,
    )),
    ("data_exfil_request", re.compile(
        r"\b(?:send|post|upload|email|exfiltrate|leak|dump)\s+"
        r"(?:the\s+|all\s+|any\s+|my\s+)?(?:\w+\s+){0,3}"
        r"(?:keys?|secrets?|tokens?|passwords?|env|credentials?|api\s+keys?|session\s+tokens?|cookies?|private\s+keys?)",
        re.IGNORECASE,
    )),
    ("destructive_command", re.compile(
        r"\b(?:delete|drop|truncate|rm\s+-rf|wipe|format|destroy|erase)\s+"
        r"(?:the\s+|all\s+|every\s+|/)?\s*"
        r"(?:index|table|database|disk|partition|file|all|everything|/)",
        re.IGNORECASE,
    )),
    ("policy_disable", re.compile(
        r"\b(?:disable|turn\s+off|deactivate|suppress|bypass|skip|override)\s+"
        r"(?:the\s+|all\s+|any\s+)?(?:\w+\s+){0,2}"
        r"(?:safety|filter|guardrail|moderation|content\s+moderation|polic(?:y|ies)|"
        r"logging|audit|approval|review|gate|check|protection|restriction)",
        re.IGNORECASE,
    )),
    ("system_override_tag", re.compile(
        r"\[\s*(?:SYSTEM\s+OVERRIDE|ADMIN\s+OVERRIDE|JAILBREAK|DEBUG\s+MODE|ROOT)\s*\]",
        re.IGNORECASE,
    )),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")),
    ("hidden_unicode_tag", re.compile(r"[\U000E0000-\U000E007F]")),
    ("zero_width_smuggle", re.compile(r"[​-‍⁠﻿]{4,}")),
]


def _scan(text: str, results: list[tuple[str, str]]) -> None:
    for name, pat in PATTERNS:
        m = pat.search(text)
        if m:
            results.append((name, m.group(0)[:120]))


def detect(strings: Iterable[str]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for s in strings:
        if not s:
            continue
        _scan(s, hits)
    return hits


class InjectionStage:
    name = "injection"

    def evaluate(self, tc: ToolCall) -> StageResult:
        t0 = time.perf_counter()
        # Surfaces we scan: tool arguments (any string values), user prompt,
        # and any incoming context the agent has read (log lines, etc.).
        scanned: list[str] = []
        if tc.raw_user_prompt:
            scanned.append(tc.raw_user_prompt)
        scanned.extend(tc.incoming_context)
        for v in tc.arguments.values():
            if isinstance(v, str):
                scanned.append(v)
            elif isinstance(v, (list, tuple)):
                scanned.extend(str(x) for x in v)

        hits = detect(scanned)
        passed = not hits
        severity = Severity.LOW if passed else Severity.CRITICAL
        return StageResult(
            stage=self.name,
            passed=passed,
            severity=severity,
            reasons=[f"matched pattern {name!r}: {snippet!r}" for name, snippet in hits],
            details={"hits": [{"pattern": n, "snippet": s} for n, s in hits]},
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
