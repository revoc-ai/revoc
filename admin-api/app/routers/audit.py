from __future__ import annotations

import hmac
import json
from typing import Any, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.audit import AuditEvent
from app.schemas.audit import (
    AuditEventCreate,
    AuditEventResponse,
    AuditStatsResponse,
    RuleCount,
    ShadowModeReport,
)
from app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


# ── helpers ────────────────────────────────────────────────────────────────────


def _internal_key_guard(
    x_revoc_internal_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    """Validate the internal ingest key (used by the proxy, not by human callers)."""
    provided = (x_revoc_internal_key or "").encode()
    expected = settings.admin_key.encode()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Revoc-Internal-Key",
        )


# ── routes ─────────────────────────────────────────────────────────────────────


@router.get("", response_model=PaginatedResponse[AuditEventResponse])
async def list_audit_events(
    org_id: str | None = Query(default=None),
    caller_id: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    environment: str | None = Query(default=None),
    from_time: str | None = Query(default=None),
    to_time: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> PaginatedResponse[AuditEventResponse]:
    """List audit events with optional filters (paginated)."""
    q = select(AuditEvent)

    if org_id is not None:
        q = q.where(AuditEvent.org_id == org_id)
    if caller_id is not None:
        q = q.where(AuditEvent.caller_id == caller_id)
    if decision is not None:
        q = q.where(AuditEvent.decision == decision)
    if environment is not None:
        q = q.where(AuditEvent.environment == environment)
    if from_time is not None:
        q = q.where(AuditEvent.timestamp >= from_time)
    if to_time is not None:
        q = q.where(AuditEvent.timestamp <= to_time)

    count_q = select(func.count()).select_from(q.subquery())
    total: int = (await db.execute(count_q)).scalar_one()

    offset = (page - 1) * page_size
    rows = (
        (
            await db.execute(
                q.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(page_size)
            )
        )
        .scalars()
        .all()
    )

    items = [AuditEventResponse.model_validate(e) for e in rows]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


@router.get("/stats", response_model=AuditStatsResponse)
async def audit_stats(
    org_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> AuditStatsResponse:
    """Aggregate counts and top-N rules/callers."""
    q = select(AuditEvent)
    if org_id is not None:
        q = q.where(AuditEvent.org_id == org_id)

    events = (await db.execute(q)).scalars().all()

    total = len(events)
    blocked = sum(1 for e in events if e.decision == "block")
    redacted = sum(1 for e in events if e.decision == "redact")
    allowed = sum(1 for e in events if e.decision == "allow")

    rule_counts: dict[str, int] = {}
    for ev in events:
        if ev.violated_rules:
            try:
                for r in json.loads(ev.violated_rules):
                    rule_counts[r] = rule_counts.get(r, 0) + 1
            except (ValueError, TypeError):
                pass

    caller_counts: dict[str, int] = {}
    for ev in events:
        if ev.caller_id:
            caller_counts[ev.caller_id] = caller_counts.get(ev.caller_id, 0) + 1

    top_rules: list[dict[str, int | str]] = sorted(  # type: ignore[assignment]
        [{"rule_id": k, "count": v} for k, v in rule_counts.items()],
        key=lambda x: cast(int, x["count"]),
        reverse=True,
    )[:10]
    top_callers: list[dict[str, int | str]] = sorted(  # type: ignore[assignment]
        [{"caller_id": k, "count": v} for k, v in caller_counts.items()],
        key=lambda x: cast(int, x["count"]),
        reverse=True,
    )[:10]

    return AuditStatsResponse(
        total=total,
        blocked=blocked,
        redacted=redacted,
        allowed=allowed,
        top_rules=top_rules,
        top_callers=top_callers,
    )


@router.get("/shadow", response_model=ShadowModeReport)
async def shadow_mode_report(
    org_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> ShadowModeReport:
    """Show events that would have been blocked in shadow mode."""
    q = select(AuditEvent).where(AuditEvent.enforcement_mode == "shadow")
    if org_id is not None:
        q = q.where(AuditEvent.org_id == org_id)

    events = (await db.execute(q)).scalars().all()

    # Shadow events where decision was block (would-be blocks)
    would_block = [e for e in events if e.decision == "block"]

    rule_counts: dict[str, int] = {}
    for ev in would_block:
        if ev.violated_rules:
            try:
                for r in json.loads(ev.violated_rules):
                    rule_counts[r] = rule_counts.get(r, 0) + 1
            except (ValueError, TypeError):
                pass

    by_rule_final: list[RuleCount] = [
        RuleCount(rule_id=k, count=v)
        for k, v in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    return ShadowModeReport(
        total_shadow_would_block=len(would_block),
        by_rule=by_rule_final,
    )


@router.get("/{trace_id}", response_model=list[AuditEventResponse])
async def get_audit_by_trace(
    trace_id: str,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> list[AuditEventResponse]:
    """Return all audit events for a given trace ID."""
    rows = (
        (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.trace_id == trace_id)
                .order_by(AuditEvent.timestamp.asc())
            )
        )
        .scalars()
        .all()
    )
    return [AuditEventResponse.model_validate(e) for e in rows]


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_audit_events(
    events: list[AuditEventCreate],
    db: AsyncSession = Depends(get_db),
    _auth: None = Depends(_internal_key_guard),
) -> dict[str, int]:
    """Bulk-insert audit events. Auth: X-Revoc-Internal-Key header."""

    def _to_row(ev: AuditEventCreate) -> AuditEvent:
        return AuditEvent(
            request_id=ev.request_id,
            timestamp=ev.timestamp,
            org_id=ev.org_id,
            caller_id=ev.caller_id,
            caller_team=ev.caller_team,
            environment=ev.environment,
            decision=ev.decision,
            effective_action=ev.effective_action,
            enforcement_mode=ev.enforcement_mode,
            violated_rules=(
                json.dumps(ev.violated_rules) if ev.violated_rules else None
            ),
            finding_types=(json.dumps(ev.finding_types) if ev.finding_types else None),
            model=ev.model,
            provider=ev.provider,
            tool_name=ev.tool_name,
            request_type=ev.request_type,
            governance_depth=ev.governance_depth,
            prompt_tokens=ev.prompt_tokens,
            completion_tokens=ev.completion_tokens,
            estimated_cost_usd=ev.estimated_cost_usd,
            duration_ms=ev.duration_ms,
            detection_ms=ev.detection_ms,
            policy_ms=ev.policy_ms,
            was_normalized=1 if ev.was_normalized else 0,
            manifest_warnings=ev.manifest_warnings or 0,
            trace_id=ev.trace_id,
            policy_engine=ev.policy_engine,
        )

    rows = [_to_row(ev) for ev in events]
    db.add_all(rows)
    await db.flush()
    return {"inserted": len(rows)}
