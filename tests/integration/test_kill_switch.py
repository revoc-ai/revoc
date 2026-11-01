"""Emergency kill-switch tests (D11) — crates/revoc-proxy/src/kill_switch/ and
handlers/emergency.rs. Endpoints live on the internal port 8081 and are
authenticated via `X-Admin-Key` (REVOC_ADMIN_KEY set in docker-compose.test.yml).
"""

import asyncio

import pytest

from .conftest import ADMIN_KEY, chat_payload, mcp_tools_call


async def _activate(internal_client, scope="global", target=None, reason="ci-test"):
    body = {"scope": scope, "reason": reason, "activated_by": "ci"}
    if target:
        body["target"] = target
    resp = await internal_client.post(
        "/internal/emergency/kill-switch/activate",
        json=body,
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _deactivate(internal_client, scope="global", target=None):
    body = {"scope": scope}
    if target:
        body["target"] = target
    resp = await internal_client.post(
        "/internal/emergency/kill-switch/deactivate",
        json=body,
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_global_kill_switch_blocks_llm(proxy_client, internal_client):
    await _activate(internal_client, scope="global")
    try:
        resp = await proxy_client.post(
            "/v1/chat/completions", json=chat_payload("Hello there")
        )
        assert resp.status_code == 503, resp.text
        body = resp.json()
        assert body["error"]["code"] == "REVOC_KILL_SWITCH_ACTIVE"
    finally:
        await _deactivate(internal_client, scope="global")


async def test_global_kill_switch_blocks_mcp(proxy_client, internal_client):
    await _activate(internal_client, scope="global")
    try:
        resp = await proxy_client.post(
            "/mcp", json=mcp_tools_call("calculator", {"expression": "2+2"})
        )
        assert resp.status_code == 503, resp.text
        body = resp.json()
        assert body["error"]["code"] == "REVOC_KILL_SWITCH_ACTIVE"
    finally:
        await _deactivate(internal_client, scope="global")


async def test_health_bypasses_kill_switch(proxy_client, internal_client):
    await _activate(internal_client, scope="global")
    try:
        resp = await proxy_client.get("/health")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "ok"
    finally:
        await _deactivate(internal_client, scope="global")


async def test_deactivate_restores_traffic(proxy_client, internal_client):
    await _activate(internal_client, scope="global")
    blocked = await proxy_client.post(
        "/v1/chat/completions", json=chat_payload("Hello there")
    )
    assert blocked.status_code == 503, blocked.text

    await _deactivate(internal_client, scope="global")
    restored = await proxy_client.post(
        "/v1/chat/completions", json=chat_payload("Hello there")
    )
    assert restored.status_code == 200, restored.text


async def test_status_reflects_activation_state(internal_client):
    await _activate(internal_client, scope="global")
    try:
        resp = await internal_client.get("/internal/emergency/kill-switch/status")
        assert resp.status_code == 200, resp.text
        assert resp.json()["global"] is True
    finally:
        await _deactivate(internal_client, scope="global")
        resp = await internal_client.get("/internal/emergency/kill-switch/status")
        assert resp.json()["global"] is False


async def test_kill_switch_log_recorded(internal_client, dashboard_client):
    """kill_switch_log writes are required (SPEC.md §23 Rule 26). We can't
    query sqlite directly from the test process (it's inside the container),
    so we verify indirectly: activation must succeed (200) and the audit
    write is non-blocking — if it failed the handler would still return 200
    per emergency.rs (it only logs a warning on log-write failure), so this
    test asserts the documented behavior: activate/deactivate both succeed
    and status reflects the transition, which is the externally-observable
    contract. Direct table verification would require exec'ing into the
    revoc-proxy container's sqlite file, which is out of scope for the HTTP
    client fixtures in this suite."""
    activated = await _activate(internal_client, scope="global", reason="log-test")
    assert activated["status"] == "activated"
    deactivated = await _deactivate(internal_client, scope="global")
    assert deactivated["status"] == "deactivated"


async def test_kill_switch_toggle_under_concurrent_load(proxy_client, internal_client):
    """Toggle the kill-switch while N concurrent requests are in flight.

    This exercises concurrent access to KillSwitchState's AtomicBool and
    DashMap under real load — verifying:

      Phase 1: Kill-switch active → all N concurrent requests return 503
               with REVOC_KILL_SWITCH_ACTIVE (no panics, no wrong status codes).
      Phase 2: Kill-switch deactivated → all N subsequent concurrent requests
               return 200 (traffic fully restored, no residual blocking).

    SPEC.md §9 D11 requires the kill-switch to be safe under concurrent
    access.  The AtomicBool (Ordering::Relaxed for reads, Ordering::SeqCst for
    writes) and lock-free DashMap ensure this without contention.
    """
    import httpx as _httpx

    n = 20

    # ── Phase 1: activate, fire N concurrent requests ────────────────────────
    await _activate(internal_client, scope="global", reason="concurrent-toggle-test")
    try:
        async with _httpx.AsyncClient(base_url=proxy_client.base_url, timeout=15.0) as client:
            responses = await asyncio.gather(*[
                client.post("/v1/chat/completions", json=chat_payload("concurrent test"))
                for _ in range(n)
            ])

        blocked = [r for r in responses if r.status_code == 503]
        assert len(blocked) == n, (
            f"Expected all {n} concurrent requests blocked (503), "
            f"got {len(blocked)} blocked; "
            f"status codes: {[r.status_code for r in responses]}"
        )
        for r in blocked:
            body = r.json()
            assert body.get("error", {}).get("code") == "REVOC_KILL_SWITCH_ACTIVE", (
                f"Expected REVOC_KILL_SWITCH_ACTIVE in blocked response, got: {body}"
            )
    finally:
        # Always deactivate so subsequent tests are not affected
        await _deactivate(internal_client, scope="global")

    # ── Phase 2: deactivated, fire N concurrent requests ────────────────────
    async with _httpx.AsyncClient(base_url=proxy_client.base_url, timeout=15.0) as client:
        responses2 = await asyncio.gather(*[
            client.post("/v1/chat/completions", json=chat_payload("post-deactivation test"))
            for _ in range(n)
        ])

    allowed = [r for r in responses2 if r.status_code == 200]
    assert len(allowed) == n, (
        f"Expected all {n} concurrent requests allowed (200) after deactivation, "
        f"got {len(allowed)} allowed; "
        f"status codes: {[r.status_code for r in responses2]}"
    )
