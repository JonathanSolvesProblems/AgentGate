"""HEC audit emitter. Every gate verdict is written to the agentgate_audit index."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import urllib3

from .config import get_settings
from .models import GateVerdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def emit(verdict: GateVerdict) -> bool:
    """Write a structured audit event. Returns True on success, False on failure
    (never raises — the gate must remain operational even if HEC is unavailable)."""
    s = get_settings()
    if not s.hec_token:
        return False

    event = {
        "agent_id": verdict.tool_call.agent_id,
        "tool_name": verdict.tool_call.tool_name,
        "arguments": verdict.tool_call.arguments,
        "decision": verdict.decision.value,
        "summary": verdict.summary,
        "finding_id": verdict.finding_id,
        "elapsed_ms": verdict.elapsed_ms,
        "stages": [
            {
                "stage": st.stage,
                "passed": st.passed,
                "severity": st.severity.value,
                "reasons": st.reasons,
                "details": st.details,
                "elapsed_ms": st.elapsed_ms,
            }
            for st in verdict.stages
        ],
    }
    body: dict[str, Any] = {
        "time": time.time(),
        "host": "agentgate",
        "source": "agentgate:gate",
        "sourcetype": "agentgate:event",
        "index": s.audit_index,
        "event": event,
    }
    try:
        r = httpx.post(
            s.hec_url,
            headers={"Authorization": f"Splunk {s.hec_token}"},
            content=json.dumps(body),
            verify=False,
            timeout=5.0,
        )
        return r.status_code == 200
    except Exception:
        return False
