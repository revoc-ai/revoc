from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AuditEventCreate(BaseModel):
    request_id: str
    timestamp: str
    org_id: str | None = None
    caller_id: str | None = None
    caller_team: str | None = None
    environment: str | None = None
    decision: str
    effective_action: str
    enforcement_mode: str = "enforce"
    violated_rules: list[str] | None = None
    finding_types: list[str] | None = None
    model: str | None = None
    provider: str | None = None
    tool_name: str | None = None
    request_type: str | None = None
    governance_depth: int | None = 0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    estimated_cost_usd: float | None = None
    duration_ms: float | None = None
    detection_ms: float | None = None
    policy_ms: float | None = None
    was_normalized: bool | None = False
    manifest_warnings: int | None = 0
    trace_id: str | None = None
    policy_engine: str | None = None


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    request_id: str
    timestamp: str
    org_id: str | None
    caller_id: str | None
    caller_team: str | None
    environment: str | None
    decision: str
    effective_action: str
    enforcement_mode: str
    violated_rules: str | None   # stored as JSON text
    finding_types: str | None    # stored as JSON text
    model: str | None
    provider: str | None
    tool_name: str | None
    request_type: str | None
    governance_depth: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    estimated_cost_usd: float | None
    duration_ms: float | None
    detection_ms: float | None
    policy_ms: float | None
    was_normalized: int | None
    manifest_warnings: int | None
    trace_id: str | None
    policy_engine: str | None
    created_at: str


class AuditStatsResponse(BaseModel):
    total: int
    blocked: int
    redacted: int
    allowed: int
    top_rules: list[dict[str, int | str]] = Field(default_factory=list)
    top_callers: list[dict[str, int | str]] = Field(default_factory=list)


class RuleCount(BaseModel):
    rule_id: str
    count: int


class ShadowModeReport(BaseModel):
    total_shadow_would_block: int
    by_rule: list[RuleCount] = Field(default_factory=list)
