from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.security import require_role
from app.models.emergency import KillSwitchLog
from app.schemas.emergency import (
    KillSwitchActivateRequest,
    KillSwitchDeactivateRequest,
    KillSwitchLogResponse,
    KillSwitchStatusResponse,
)
from app.services.emergency_service import EmergencyService

router = APIRouter(prefix="/api/v1/emergency", tags=["emergency"])

_emergency_svc = EmergencyService()


@router.post("/kill-switch/activate", response_model=KillSwitchLogResponse)
async def activate_kill_switch(
    payload: KillSwitchActivateRequest,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(require_role("admin")),
    settings: Settings = Depends(get_settings),
) -> KillSwitchLogResponse:
    """Activate the emergency kill-switch (admin only).

    Forwards to the proxy internal API and writes a kill_switch_log entry.
    """
    entry = await _emergency_svc.activate(db, payload, settings)
    return KillSwitchLogResponse.model_validate(entry)


@router.post("/kill-switch/deactivate", response_model=KillSwitchLogResponse)
async def deactivate_kill_switch(
    payload: KillSwitchDeactivateRequest,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(require_role("admin")),
    settings: Settings = Depends(get_settings),
) -> KillSwitchLogResponse:
    """Deactivate the emergency kill-switch (admin only)."""
    entry = await _emergency_svc.deactivate(db, payload, settings)
    return KillSwitchLogResponse.model_validate(entry)


@router.get("/kill-switch/status", response_model=KillSwitchStatusResponse)
async def kill_switch_status(
    _user: Any = Depends(require_role("viewer")),
    settings: Settings = Depends(get_settings),
) -> KillSwitchStatusResponse:
    """Return the current kill-switch state from the proxy (viewer role)."""
    return await _emergency_svc.status(settings)


@router.get("/kill-switch/log", response_model=list[KillSwitchLogResponse])
async def kill_switch_log(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(require_role("audit_viewer")),
) -> list[KillSwitchLogResponse]:
    """Return the most-recent kill-switch log entries (audit_viewer role)."""
    rows = (
        await db.execute(
            select(KillSwitchLog)
            .order_by(KillSwitchLog.timestamp.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [KillSwitchLogResponse.model_validate(r) for r in rows]
