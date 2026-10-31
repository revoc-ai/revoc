from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Float, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("idx_ae_org_time", "org_id", "timestamp"),
        Index("idx_ae_decision", "decision", "timestamp"),
        Index("idx_ae_trace", "trace_id"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=_uuid)
    org_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[str] = mapped_column(Text, nullable=False, default=_now)
    caller_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    caller_team: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    effective_action: Mapped[str] = mapped_column(Text, nullable=False)
    enforcement_mode: Mapped[str] = mapped_column(Text, nullable=False, default="enforce")
    violated_rules: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON array
    finding_types: Mapped[str | None] = mapped_column(Text, nullable=True)    # JSON array
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    governance_depth: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    detection_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    policy_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    was_normalized: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    manifest_warnings: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    trace_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_engine: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=_now)
