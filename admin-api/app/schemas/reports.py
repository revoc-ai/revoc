from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.audit import AuditStatsResponse


class ComplianceReportRequest(BaseModel):
    org_id: str
    start_time: datetime
    end_time: datetime
    format: Literal["json", "csv", "pdf"] = "json"


class ComplianceReportResponse(BaseModel):
    org_id: str
    start_time: datetime
    end_time: datetime
    summary: AuditStatsResponse
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    top_violations: list[dict[str, Any]] = Field(default_factory=list)
    generated_at: datetime
