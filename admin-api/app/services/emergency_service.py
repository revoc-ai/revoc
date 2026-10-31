from __future__ import annotations

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.logging import get_logger
from app.models.emergency import KillSwitchLog
from app.schemas.emergency import (
    KillSwitchActivateRequest,
    KillSwitchDeactivateRequest,
    KillSwitchStatusResponse,
)

_log = get_logger(__name__)

_TIMEOUT = 5.0


class EmergencyService:
    """Manage the REVOC emergency kill-switch via the proxy internal API."""

    async def activate(
        self,
        db: AsyncSession,
        request: KillSwitchActivateRequest,
        settings: Settings,
    ) -> KillSwitchLog:
        """Activate the kill-switch at the requested scope.

        Forwards to the proxy, then writes a kill_switch_log entry regardless
        of whether the proxy call succeeds (local state is ground truth for audit).
        """
        proxy_url = (
            f"{settings.proxy_internal_url}"
            "/internal/emergency/kill-switch/activate"
        )
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                await client.post(
                    proxy_url,
                    json={
                        "scope": request.scope,
                        "reason": request.reason,
                        "activated_by": request.activated_by,
                        "target": request.target_id,
                    },
                )
            except httpx.RequestError as exc:
                _log.warning(
                    "kill_switch_proxy_unreachable",
                    action="activate",
                    error=str(exc),
                )

        entry = KillSwitchLog(
            scope=request.scope,
            scope_value=request.target_id,
            action="activate",
            activated_by=request.activated_by,
            reason=request.reason,
        )
        db.add(entry)
        await db.flush()
        return entry

    async def deactivate(
        self,
        db: AsyncSession,
        scope: KillSwitchDeactivateRequest,
        settings: Settings,
    ) -> KillSwitchLog:
        """Deactivate the kill-switch at the requested scope."""
        proxy_url = (
            f"{settings.proxy_internal_url}"
            "/internal/emergency/kill-switch/deactivate"
        )
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                await client.post(
                    proxy_url,
                    json={"scope": scope.scope, "target": scope.target_id},
                )
            except httpx.RequestError as exc:
                _log.warning(
                    "kill_switch_proxy_unreachable",
                    action="deactivate",
                    error=str(exc),
                )

        entry = KillSwitchLog(
            scope=scope.scope,
            scope_value=scope.target_id,
            action="deactivate",
            activated_by="admin",
            reason=None,
        )
        db.add(entry)
        await db.flush()
        return entry

    async def status(self, settings: Settings) -> KillSwitchStatusResponse:
        """Fetch current kill-switch status from the proxy internal API."""
        proxy_url = (
            f"{settings.proxy_internal_url}"
            "/internal/emergency/kill-switch/status"
        )
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                resp = await client.get(proxy_url)
                if resp.is_success:
                    data = resp.json()
                    return KillSwitchStatusResponse(**data)
                _log.warning(
                    "kill_switch_status_failed",
                    status=resp.status_code,
                )
            except httpx.RequestError as exc:
                _log.warning("kill_switch_proxy_unreachable", action="status", error=str(exc))

        # Proxy unreachable — return safe default (not globally active)
        return KillSwitchStatusResponse(
            global_active=False,
            active_orgs=[],
            active_callers=[],
        )
