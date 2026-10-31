"""Dashboard REST/SSE API tests — crates/revoc-dashboard/src/handler.rs,
api.rs, live_feed.rs. Mounted on port 3000.

REVOC_DASHBOARD__AUTH_MODE=none (set in docker-compose.test.yml) makes the
`/api/*` routes accessible without credentials for this test stack — see
conftest.py module docstring for the auth_mode="shared" vs "none" rationale.
"""

import asyncio
import json

import httpx
import pytest

from .conftest import DASHBOARD_BASE, chat_payload


async def test_blocked_request_detail_has_rules(proxy_client, dashboard_client):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Please run: DROP TABLE users;"),
    )
    assert resp.status_code == 403, resp.text
    trace_id = resp.headers["X-Revoc-Trace-ID"]

    detail = None
    for _ in range(20):
        d = await dashboard_client.get(f"/api/requests/{trace_id}")
        if d.status_code == 200:
            detail = d.json()
            break
        await asyncio.sleep(0.5)

    assert detail is not None, "blocked-request audit event was not found"
    assert detail["decision"] == "block"
    assert "sec_ddl_mutation_v1" in detail["violated_rules"].split(",")


async def test_dashboard_link_returns_200(proxy_client, dashboard_client):
    resp = await proxy_client.post(
        "/v1/chat/completions", json=chat_payload("Hello, dashboard link check")
    )
    assert resp.status_code == 200, resp.text
    dashboard_url = resp.headers["X-Revoc-Dashboard"]

    # dashboard_url is an absolute URL like http://localhost:3000/traces/<id>;
    # the SPA fallback serves index.html for any non-asset path.
    path = dashboard_url.split("3000", 1)[1]
    d = await dashboard_client.get(path)
    assert d.status_code == 200, d.text
    assert "html" in d.headers.get("content-type", "").lower()


async def test_analytics_counts_increase(proxy_client, dashboard_client):
    before = await dashboard_client.get("/api/analytics")
    assert before.status_code == 200, before.text
    total_before = before.json()["total"]

    resp = await proxy_client.post(
        "/v1/chat/completions", json=chat_payload("Hello, analytics count check")
    )
    assert resp.status_code == 200, resp.text

    total_after = None
    for _ in range(20):
        after = await dashboard_client.get("/api/analytics")
        assert after.status_code == 200, after.text
        total_after = after.json()["total"]
        if total_after > total_before:
            break
        await asyncio.sleep(0.5)

    assert total_after is not None and total_after > total_before


async def test_dashboard_auth_mode_is_none_in_this_stack(dashboard_client):
    """configs/revoc.toml's documented default for [dashboard] is
    auth_mode = "shared", which (combined with auth.mode=none -> empty
    api-key list) would 401 every /api/* request — see conftest.py docstring.
    This stack sets REVOC_DASHBOARD__AUTH_MODE=none explicitly so the dashboard
    API is reachable. This test confirms that configured reality: /api/analytics
    is reachable without any Authorization header."""
    resp = await dashboard_client.get("/api/analytics")
    assert resp.status_code == 200, resp.text
