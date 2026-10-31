"""End-to-end header compliance tests — SPEC.md §16.

Verifies the non-negotiable header contract against the live single-container
stack: X-Revoc-Dashboard and X-Revoc-Timing must appear on EVERY response from
EVERY handler regardless of decision, method, or error condition.
"""

import pytest

from .conftest import ADMIN_KEY, chat, mcp_call


ALWAYS_PRESENT = ["X-Revoc-Dashboard", "X-Revoc-Timing", "X-Revoc-Trace-ID", "X-Revoc-Request-ID"]


def _assert_mandatory(resp, context: str) -> None:
    for h in ALWAYS_PRESENT:
        assert h in resp.headers, (
            f"[{context}] Missing non-negotiable header: {h}"
        )
    # X-Revoc-Depth must NEVER appear on the response (Rule 12)
    assert "X-Revoc-Depth" not in resp.headers, (
        f"[{context}] X-Revoc-Depth must not be present on client-facing response"
    )


# ── LLM handler ───────────────────────────────────────────────────────────────

async def test_headers_on_llm_allow(proxy):
    resp = await proxy.post("/v1/chat/completions", json=chat("Hello"))
    assert resp.status_code == 200
    _assert_mandatory(resp, "LLM allow")
    assert resp.headers["X-Revoc-Decision"] == "allow"


async def test_headers_on_llm_redact(proxy):
    resp = await proxy.post("/v1/chat/completions", json=chat("My SSN is 123-45-6789"))
    assert resp.status_code == 200
    _assert_mandatory(resp, "LLM redact")
    assert resp.headers["X-Revoc-Decision"] == "redact"


async def test_headers_on_llm_block(proxy):
    resp = await proxy.post(
        "/v1/chat/completions", json=chat("DROP TABLE accounts;")
    )
    assert resp.status_code == 403
    _assert_mandatory(resp, "LLM block")
    assert resp.headers["X-Revoc-Decision"] == "block"


async def test_headers_on_depth_exceeded(proxy):
    resp = await proxy.post(
        "/v1/chat/completions",
        json=chat("Hello"),
        headers={"X-Revoc-Depth": "10"},
    )
    assert resp.status_code == 503
    _assert_mandatory(resp, "depth exceeded")


async def test_headers_on_kill_switch(proxy, internal):
    await internal.post(
        "/internal/emergency/kill-switch/activate",
        json={"scope": "global", "reason": "header-e2e", "activated_by": "ci"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    try:
        resp = await proxy.post("/v1/chat/completions", json=chat("Hello"))
        assert resp.status_code == 503
        _assert_mandatory(resp, "kill-switch")
    finally:
        await internal.post(
            "/internal/emergency/kill-switch/deactivate",
            json={"scope": "global"},
            headers={"X-Admin-Key": ADMIN_KEY},
        )


# ── MCP handler ───────────────────────────────────────────────────────────────

async def test_headers_on_mcp_allow(proxy):
    resp = await proxy.post("/mcp", json=mcp_call("calculator", {"expression": "2+2"}))
    assert resp.status_code == 200
    _assert_mandatory(resp, "MCP allow")


async def test_headers_on_mcp_block(proxy):
    resp = await proxy.post("/mcp", json=mcp_call("execute_sql", {"query": "DROP TABLE users;"}))
    # MCP blocks return HTTP 200 with a JSON-RPC error body
    assert resp.status_code == 200
    _assert_mandatory(resp, "MCP block")
    assert resp.headers.get("X-Revoc-Block") == "true"


# ── X-Revoc-Timing format ─────────────────────────────────────────────────────

async def test_timing_contains_total_field(proxy):
    resp = await proxy.post("/v1/chat/completions", json=chat("timing check"))
    timing = resp.headers["X-Revoc-Timing"]
    assert "total" in timing, f"X-Revoc-Timing must contain 'total': {timing!r}"


async def test_timing_contains_detection_field(proxy):
    resp = await proxy.post("/v1/chat/completions", json=chat("timing check 2"))
    timing = resp.headers["X-Revoc-Timing"]
    assert "detection" in timing, f"X-Revoc-Timing must contain 'detection': {timing!r}"


# ── X-Revoc-Dashboard is absolute URL containing trace_id ────────────────────

async def test_dashboard_url_absolute_and_contains_trace_id(proxy):
    resp = await proxy.post("/v1/chat/completions", json=chat("Hello dashboard"))
    trace_id = resp.headers["X-Revoc-Trace-ID"]
    dashboard = resp.headers["X-Revoc-Dashboard"]
    assert dashboard.startswith("http"), "Dashboard URL must be absolute"
    assert trace_id in dashboard, (
        f"Dashboard URL must contain trace_id={trace_id!r}; got {dashboard!r}"
    )
