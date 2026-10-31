"""tests/test_policies.py — 6 policy router tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import VALID_POLICY_YAML

# ── helpers ───────────────────────────────────────────────────────────────────

async def _create_bundle(
    client: AsyncClient,
    headers: dict[str, str],
    version: str = "1.0.0",
) -> dict[str, object]:
    resp = await client.post(
        "/api/v1/policies",
        json={
            "org_id": "test-org",
            "name": "test-policy",
            "environment": "production",
            "version": version,
            "yaml_content": VALID_POLICY_YAML,
            "created_by": "test-user",
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[return-value]


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_valid_yaml_201(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """POST /policies with valid YAML should return 201 with a bundle ID."""
    data = await _create_bundle(async_client, auth_headers, version="2.0.0")
    assert data["status"] == "draft"
    assert data["org_id"] == "test-org"
    assert isinstance(data["id"], str)
    assert data["rego_content"] is not None


@pytest.mark.asyncio
async def test_create_invalid_yaml_422_with_errors(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler_fail: object,
) -> None:
    """POST /policies with failing compilation should return 422 + error list."""
    resp = await async_client.post(
        "/api/v1/policies",
        json={
            "org_id": "test-org",
            "name": "bad-policy",
            "environment": "production",
            "version": "1.0.0",
            "yaml_content": "garbage: yaml: :",
            "created_by": "test-user",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422
    body = resp.json()
    assert "compilation_errors" in body["error"]
    assert len(body["error"]["compilation_errors"]) > 0


@pytest.mark.asyncio
async def test_activate_status_active(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """POST /policies/{id}/activate should set status to 'active'."""
    bundle = await _create_bundle(async_client, auth_headers, version="3.0.0")
    bundle_id = bundle["id"]

    resp = await async_client.post(
        f"/api/v1/policies/{bundle_id}/activate",
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "active"
    assert data["bundle_id"] == bundle_id


@pytest.mark.asyncio
async def test_rollback_reactivates_previous(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """POST /policies/{id}/rollback should reactivate the archived bundle."""
    # Create v1 and activate it
    v1 = await _create_bundle(async_client, auth_headers, version="4.0.0")
    await async_client.post(
        f"/api/v1/policies/{v1['id']}/activate", headers=auth_headers
    )

    # Create v2 and activate it — archives v1
    v2 = await _create_bundle(async_client, auth_headers, version="4.1.0")
    await async_client.post(
        f"/api/v1/policies/{v2['id']}/activate", headers=auth_headers
    )

    # Rollback from v2 should restore v1
    resp = await async_client.post(
        f"/api/v1/policies/{v2['id']}/rollback", headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["id"] == v1["id"]
    assert data["status"] == "active"


@pytest.mark.asyncio
async def test_get_rego_text_plain(
    async_client: AsyncClient,
    auth_headers: dict[str, str],
    mock_compiler: object,
) -> None:
    """GET /policies/{id}/rego should return text/plain Rego content."""
    bundle = await _create_bundle(async_client, auth_headers, version="5.0.0")
    resp = await async_client.get(
        f"/api/v1/policies/{bundle['id']}/rego", headers=auth_headers
    )
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "package" in resp.text


@pytest.mark.asyncio
async def test_unauthenticated_401(
    async_client: AsyncClient,
) -> None:
    """Any policy endpoint without auth must return 401."""
    resp = await async_client.get("/api/v1/policies?org_id=test-org")
    assert resp.status_code == 401
