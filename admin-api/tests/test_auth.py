"""tests/test_auth.py — 3 authentication tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.user import User

# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_returns_jwt(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """POST /auth/token with valid credentials should return a JWT."""
    user = User(
        org_id="auth-org",
        username="loginuser",
        email="loginuser@example.com",
        hashed_pw=hash_password("secret1234"),
        role="viewer",
    )
    db_session.add(user)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/token",
        data={"username": "loginuser", "password": "secret1234"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str)
    assert len(body["access_token"]) > 20
    assert body["expires_in"] > 0


@pytest.mark.asyncio
async def test_jwt_required(
    async_client: AsyncClient,
) -> None:
    """Protected endpoints must return 401 when no Authorization header is sent."""
    # Policy list requires auth
    resp = await async_client.get("/api/v1/policies?org_id=test-org")
    assert resp.status_code == 401

    # Users/me requires auth
    resp2 = await async_client.get("/api/v1/users/me")
    assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_api_key_once_only(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    test_user: User,
) -> None:
    """The raw API key is returned only on creation; subsequent list never shows it."""
    # Create
    create_resp = await async_client.post(
        "/api/v1/api-keys",
        json={
            "org_id": "test-org",
            "user_id": test_user.id,
            "name": "ci-key",
            "caller_id": "ci-service",
        },
        headers=auth_headers,
    )
    assert create_resp.status_code == 201, create_resp.text
    created = create_resp.json()
    assert created["key"] is not None  # shown once

    # List — key field must be None
    list_resp = await async_client.get("/api/v1/api-keys", headers=auth_headers)
    assert list_resp.status_code == 200
    for key_obj in list_resp.json():
        assert key_obj.get("key") is None
