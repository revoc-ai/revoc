"""tests/test_emergency.py — 3 emergency kill-switch tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

_ACTIVATE_PAYLOAD = {
    "scope": "global",
    "reason": "test emergency stop",
    "activated_by": "ci-test",
}

_DEACTIVATE_PAYLOAD = {
    "scope": "global",
}


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_activate_requires_admin(
    async_client: AsyncClient,
    viewer_headers: dict[str, str],
) -> None:
    """POST /emergency/kill-switch/activate must reject viewer role with 403."""
    resp = await async_client.post(
        "/api/v1/emergency/kill-switch/activate",
        json=_ACTIVATE_PAYLOAD,
        headers=viewer_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_activate_succeeds_admin(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """POST /emergency/kill-switch/activate succeeds for admin and returns a log entry."""
    # Patch the proxy HTTP call so tests don't need a real proxy
    with patch(
        "app.services.emergency_service.EmergencyService.activate",
        new_callable=AsyncMock,
    ) as mock_activate:
        from app.models.emergency import KillSwitchLog

        fake_entry = KillSwitchLog(
            scope="global",
            action="activate",
            activated_by="ci-test",
            reason="test emergency stop",
        )
        mock_activate.return_value = fake_entry

        resp = await async_client.post(
            "/api/v1/emergency/kill-switch/activate",
            json=_ACTIVATE_PAYLOAD,
            headers=auth_headers,
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scope"] == "global"
    assert data["action"] == "activate"


@pytest.mark.asyncio
async def test_status_viewer_can_read(
    async_client: AsyncClient,
    viewer_headers: dict[str, str],
) -> None:
    """GET /emergency/kill-switch/status is accessible to viewer role."""
    with patch(
        "app.services.emergency_service.EmergencyService.status",
        new_callable=AsyncMock,
        return_value={
            "global_active": False,
            "active_orgs": [],
            "active_callers": [],
        },
    ):
        resp = await async_client.get(
            "/api/v1/emergency/kill-switch/status",
            headers=viewer_headers,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "global_active" in data
