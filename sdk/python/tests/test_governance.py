"""tests/test_governance.py — GovernanceClient HTTP wrapper behavior."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from revoc_sdk import GovernanceClient

# Captured before any monkeypatching replaces httpx.AsyncClient, so the
# patched factory below can construct a real client against a mock transport
# without recursing into itself.
_RealAsyncClient = httpx.AsyncClient


@pytest.fixture
def governance_client() -> GovernanceClient:
    return GovernanceClient(base_url="http://revoc.local:3000", api_key="test-admin-key")


@pytest.mark.asyncio
async def test_get_audit_stats_sends_authorization_header(
    governance_client: GovernanceClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"total": 0, "blocked": 0, "redacted": 0, "allowed": 0})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: _RealAsyncClient(transport=transport, base_url=kw.get("base_url", "")),
    )

    await governance_client.get_audit_stats(
        datetime(2026, 6, 6, tzinfo=UTC), datetime(2026, 6, 7, tzinfo=UTC)
    )
    assert captured["request"].headers["authorization"] == "Bearer test-admin-key"
    assert captured["request"].url.path == "/api/v1/audit/stats"


@pytest.mark.asyncio
async def test_validate_policy_returns_json(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GovernanceClient(base_url="http://revoc.local:3000")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"is_valid": True, "errors": []})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: _RealAsyncClient(transport=transport, base_url=kw.get("base_url", "")),
    )

    result = await client.validate_policy("apiVersion: revoc.io/v1\nkind: PolicyManifest\n")
    assert result["is_valid"] is True


@pytest.mark.asyncio
async def test_activate_kill_switch_posts_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GovernanceClient(base_url="http://revoc.local:3000")
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"scope": "global", "action": "activate"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: _RealAsyncClient(transport=transport, base_url=kw.get("base_url", "")),
    )

    result = await client.activate_kill_switch("global", "incident-123")
    assert result["action"] == "activate"
    assert captured["request"].url.path == "/api/v1/emergency/kill-switch/activate"
