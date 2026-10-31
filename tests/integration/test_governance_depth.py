"""Governance depth limiting tests (D9) — crates/revoc-proxy/src/depth.rs.

X-Revoc-Depth on the INCOMING request is checked at Step 1 of every handler
(>= 10 => 503 REVOC_GOVERNANCE_DEPTH_EXCEEDED). On the outgoing upstream
request, depth+1 is set. X-Revoc-Depth is NEVER present on the response to
the client (SPEC.md §23 Rule 12).
"""

import pytest

from .conftest import chat_payload, wiremock_last_request


async def test_depth_9_passes(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Hello at depth 9"),
        headers={"X-Revoc-Depth": "9"},
    )
    assert resp.status_code == 200, resp.text
    assert "X-Revoc-Depth" not in resp.headers


async def test_depth_10_blocked(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Hello at depth 10"),
        headers={"X-Revoc-Depth": "10"},
    )
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["error"]["code"] == "REVOC_GOVERNANCE_DEPTH_EXCEEDED"
    assert "X-Revoc-Depth" not in resp.headers


async def test_upstream_receives_depth_plus_one(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Hello at depth 3, check upstream header"),
        headers={"X-Revoc-Depth": "3"},
    )
    assert resp.status_code == 200, resp.text
    assert "X-Revoc-Depth" not in resp.headers

    last = await wiremock_last_request(wiremock_llm, "/v1/chat/completions")
    assert last is not None
    upstream_headers = {k.lower(): v for k, v in last["headers"].items()}
    assert upstream_headers.get("x-revoc-depth") == "4"
