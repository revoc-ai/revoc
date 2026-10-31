"""tests/test_extra_coverage.py — additional tests to reach 85% coverage.

Targets uncovered lines in:
  - app/routers/users.py   (me, register, list keys, delete key, bad login)
  - app/routers/audit.py   (stats, by trace_id)
  - app/routers/policies.py (list, validate, get single, archive/DELETE)
  - app/routers/reports.py  (JSON report)
  - app/services/emergency_service.py (real activate / deactivate / status via proxy)
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from tests.conftest import VALID_POLICY_YAML

# ── helpers ───────────────────────────────────────────────────────────────────

_REPORT_PARAMS = (
    "?org_id=test-org"
    "&start_time=2026-06-06T00:00:00"
    "&end_time=2026-06-06T23:59:59"
)

_INGEST_EVENT = {
    "request_id": "req-extra-001",
    "timestamp": "2026-06-06T10:00:00+00:00",
    "org_id": "test-org",
    "caller_id": "service-extra",
    "decision": "block",
    "effective_action": "block",
    "enforcement_mode": "enforce",
    "violated_rules": ["sec_prompt_injection_v1"],
    "trace_id": "trace-extra-001",
}


async def _create_bundle(
    client: AsyncClient,
    headers: dict[str, str],
    version: str = "99.0.0",
) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/policies",
        json={
            "org_id": "test-org",
            "name": "extra-policy",
            "environment": "production",
            "version": version,
            "yaml_content": VALID_POLICY_YAML,
            "created_by": "test-user",
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[return-value]


# ── users / auth ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_me_returns_profile(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """GET /api/v1/users/me should return the authenticated user's profile."""
    resp = await async_client.get("/api/v1/users/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "testadmin"
    assert data["org_id"] == "test-org"


@pytest.mark.asyncio
async def test_register_new_user_in_test_env(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """POST /api/v1/auth/register should succeed in non-production env."""
    resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "org_id": "test-org",
            "username": "newuser_extra",
            "email": "newuser_extra@example.com",
            "password": "securepassword123",
            "role": "viewer",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["username"] == "newuser_extra"


@pytest.mark.asyncio
async def test_login_wrong_password_401(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """POST /api/v1/auth/token with wrong password must return 401."""
    from app.core.security import hash_password
    from app.models.user import User

    user = User(
        org_id="test-org",
        username="logintest",
        email="logintest@example.com",
        hashed_pw=hash_password("correct-password"),
        role="viewer",
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/token",
        data={"username": "logintest", "password": "wrong-password"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_and_delete_api_key(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    test_user: User,
) -> None:
    """List and DELETE /api/v1/api-keys cover the list + delete endpoints."""
    # Create an API key
    create_resp = await async_client.post(
        "/api/v1/api-keys",
        json={
            "org_id": test_user.org_id,
            "user_id": test_user.id,
            "name": "test-key-extra",
            "caller_id": "svc-extra",
        },
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    key_id = create_resp.json()["id"]

    # List — key field must be None
    list_resp = await async_client.get("/api/v1/api-keys", headers=auth_headers)
    assert list_resp.status_code == 200
    ids = [k["id"] for k in list_resp.json()]
    assert key_id in ids

    # Delete → 204
    del_resp = await async_client.delete(
        f"/api/v1/api-keys/{key_id}", headers=auth_headers
    )
    assert del_resp.status_code == 204


# ── audit ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_stats_returns_counts(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """GET /api/v1/audit/stats should aggregate decision counts."""
    await async_client.post(
        "/api/v1/audit/ingest",
        json=[_INGEST_EVENT],
        headers=internal_key_headers,
    )
    resp = await async_client.get("/api/v1/audit/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "blocked" in data
    assert "top_rules" in data
    assert "top_callers" in data


@pytest.mark.asyncio
async def test_audit_by_trace_id(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """GET /api/v1/audit/{trace_id} should return events for that trace."""
    await async_client.post(
        "/api/v1/audit/ingest",
        json=[_INGEST_EVENT],
        headers=internal_key_headers,
    )
    resp = await async_client.get(
        "/api/v1/audit/trace-extra-001", headers=auth_headers
    )
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    assert any(e["trace_id"] == "trace-extra-001" for e in events)


# ── policies ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_policies(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """GET /api/v1/policies?org_id= should return a paginated bundle list."""
    await _create_bundle(async_client, auth_headers, version="50.0.0")
    resp = await async_client.get(
        "/api/v1/policies?org_id=test-org", headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_validate_policy_valid_yaml(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """POST /api/v1/policies/validate with valid YAML should return is_valid=True."""
    resp = await async_client.post(
        "/api/v1/policies/validate",
        json={"yaml_content": VALID_POLICY_YAML},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["errors"] == []


@pytest.mark.asyncio
async def test_get_single_policy(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """GET /api/v1/policies/{id} should return the bundle."""
    bundle = await _create_bundle(async_client, auth_headers, version="51.0.0")
    resp = await async_client.get(
        f"/api/v1/policies/{bundle['id']}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == bundle["id"]


@pytest.mark.asyncio
async def test_archive_policy_returns_204(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """DELETE /api/v1/policies/{id} should archive (not delete) the bundle."""
    bundle = await _create_bundle(async_client, auth_headers, version="52.0.0")
    resp = await async_client.delete(
        f"/api/v1/policies/{bundle['id']}", headers=auth_headers
    )
    assert resp.status_code == 204

    # Confirm bundle still exists in DB with status=archived
    get_resp = await async_client.get(
        f"/api/v1/policies/{bundle['id']}", headers=auth_headers
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "archived"


# ── reports ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_json_report_returns_summary(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """GET /api/v1/reports should return a ComplianceReportResponse."""
    await async_client.post(
        "/api/v1/audit/ingest",
        json=[_INGEST_EVENT],
        headers=internal_key_headers,
    )
    resp = await async_client.get(
        "/api/v1/reports" + _REPORT_PARAMS, headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "org_id" in data
    assert data["org_id"] == "test-org"


# ── emergency (real service — proxy unreachable, RequestError caught) ─────────


@pytest.mark.asyncio
async def test_emergency_activate_real_service_covers_proxy_error_path(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """Calling activate without a mock exercises the proxy-unreachable except branch."""
    resp = await async_client.post(
        "/api/v1/emergency/kill-switch/activate",
        json={
            "scope": "global",
            "reason": "coverage-test",
            "activated_by": "ci",
        },
        headers=auth_headers,
    )
    # Proxy is unreachable but the service gracefully creates a log entry
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == "global"
    assert data["action"] == "activate"


@pytest.mark.asyncio
async def test_emergency_deactivate_real_service(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """Deactivate covers the proxy-unreachable path in EmergencyService.deactivate."""
    resp = await async_client.post(
        "/api/v1/emergency/kill-switch/deactivate",
        json={"scope": "global"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == "global"
    assert data["action"] == "deactivate"


@pytest.mark.asyncio
async def test_emergency_status_real_service_proxy_unreachable(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    """Status falls back to safe default when proxy is unreachable."""
    # Patch the httpx.AsyncClient used inside EmergencyService.status so the
    # test is environment-independent (port 8081 may be in use in CI).
    mock_inner = AsyncMock()
    mock_inner.get = AsyncMock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_inner)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.emergency_service.httpx.AsyncClient", return_value=mock_ctx):
        resp = await async_client.get(
            "/api/v1/emergency/kill-switch/status",
            headers=auth_headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "global_active" in data
    # Proxy unreachable → safe default
    assert data["global_active"] is False
