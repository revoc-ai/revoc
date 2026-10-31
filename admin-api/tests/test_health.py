"""tests/test_health.py — /api/v1/health endpoint coverage."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_database_ok(async_client: AsyncClient) -> None:
    """GET /api/v1/health must return 200 with database=ok."""
    resp = await async_client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "checks" in data
    assert "version" in data
    assert data["checks"]["database"] == "ok"


@pytest.mark.asyncio
async def test_health_opa_unreachable_degrades_status(async_client: AsyncClient) -> None:
    """When OPA is not running the overall status must be 'degraded'."""
    resp = await async_client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    # OPA is never running in the test environment
    assert data["checks"]["opa"] == "unreachable"
    assert data["status"] == "degraded"
