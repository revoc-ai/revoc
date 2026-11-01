from __future__ import annotations

from typing import Any

import httpx
import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db

router = APIRouter(prefix="/api/v1", tags=["health"])
logger = structlog.get_logger(__name__)


@router.get("/health")
async def health(
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Liveness + readiness probe.  Checks DB connectivity and OPA reachability."""
    checks: dict[str, str] = {}

    # Database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        # Log the detail server-side only; never return exception text to callers.
        logger.warning("health_check_database_failed", error=str(exc))
        checks["database"] = "error"

    # OPA (optional — OPA may not be running in all tiers)
    opa_url = f"{settings.opa_url}/health"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(opa_url)
            checks["opa"] = "ok" if resp.is_success else f"http_{resp.status_code}"
    except httpx.RequestError:
        checks["opa"] = "unreachable"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks, "version": "0.1.0-beta.1"}
