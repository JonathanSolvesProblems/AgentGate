"""Pydantic models for tool calls, decisions, findings, and audit events."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """An LLM agent's proposed tool invocation, the unit AgentGate intercepts."""

    agent_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_user_prompt: str | None = None
    incoming_context: list[str] = Field(default_factory=list)
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StageResult(BaseModel):
    stage: str
    passed: bool
    severity: Severity = Severity.LOW
    reasons: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    elapsed_ms: float = 0.0


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class GateVerdict(BaseModel):
    """Final pipeline verdict on a single ToolCall."""

    tool_call: ToolCall
    decision: Decision
    stages: list[StageResult] = Field(default_factory=list)
    finding_id: str | None = None
    elapsed_ms: float = 0.0
    summary: str = ""


class AssetTag(BaseModel):
    """Per-asset compliance and criticality metadata stored in KV."""

    key: str
    asset_type: str
    compliance_tags: list[str] = Field(default_factory=list)
    criticality: Severity = Severity.MEDIUM
    owner: str = ""


class Policy(BaseModel):
    """A single deterministic rule in the policy library."""

    id: str
    title: str
    when: dict[str, Any]
    action: Decision
    rationale: str
    standards: list[str] = Field(default_factory=list)
