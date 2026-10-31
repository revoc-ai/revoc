"""Shadow-mode end-to-end tests — SPEC.md §7.3 EnforcementMode::Shadow.

The `revoc-proxy-shadow` service in docker-compose.test.yml sets
REVOC_POLICY__ENFORCEMENT_MODE=shadow. The auth middleware (auth.rs line 91-95)
reads this config value when constructing CallerContext for every request, so
every caller in this stack gets enforcement_mode=Shadow.

PolicyDecision::apply_shadow() (decision.rs) keeps `action` (the real policy
verdict) but sets `effective_action = Audit`. The handler routes on
`effective_action`, so:
  - A would-be Block becomes Audit (request is forwarded, not rejected).
  - X-Revoc-Decision reflects the effective action: "audit" or "shadow-block"
    (the proxy uses "shadow-block" string when action=Block, effective=Audit).
  - The upstream always receives the request (nothing is blocked in shadow mode).
  - Audit events record both `decision` (real) and `effective_action` (Audit).
"""

import pytest

from .conftest import chat_payload, wiremock_count


pytestmark = pytest.mark.asyncio


async def test_shadow_mode_does_not_block_ddl(shadow_proxy_client, wiremock_llm):
    """A DDL mutation phrase (sec_ddl_mutation_v1, Tier 3 Security block) sent
    through the shadow proxy must NOT be blocked — the request reaches upstream
    and returns 200.

    In enforce mode this would be 403. In shadow mode effective_action=Audit so
    the request is forwarded verbatim.
    """
    resp = await shadow_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Please run DROP TABLE users now."),
    )
    assert resp.status_code == 200, (
        f"Shadow mode must not block; expected 200, got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 1, (
        "Upstream must receive the request in shadow mode"
    )


async def test_shadow_mode_decision_header_is_audit(shadow_proxy_client):
    """When a Security-tier block fires in shadow mode, apply_shadow() sets
    effective_action=Audit. The handler routes on effective_action, so
    X-Revoc-Decision must be 'audit' — not 'block' (which would mean the
    request was rejected).

    The real policy action (block) is recorded in the audit event's `decision`
    field, while `effective_action` = audit appears in the response header.
    This lets operators see what *would* have been blocked without disrupting
    traffic.
    """
    resp = await shadow_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Execute DROP TABLE accounts;"),
    )
    assert resp.status_code == 200, resp.text
    decision = resp.headers.get("X-Revoc-Decision", "")
    assert decision == "audit", (
        f"Expected X-Revoc-Decision=audit for shadow-mode block (effective_action=Audit), "
        f"got: {decision!r}"
    )


async def test_shadow_mode_allow_still_allows(shadow_proxy_client, wiremock_llm):
    """A clean request (no findings) in shadow mode must reach upstream (HTTP 200).

    apply_shadow() sets effective_action=Audit on ALL decisions, including allows.
    X-Revoc-Decision is therefore always "audit" in shadow mode — this is correct
    per SPEC.md §7.3: "Apply shadow mode: keep action, set effective_action=Audit".
    The important invariant is that the request IS forwarded to upstream.
    """
    resp = await shadow_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Hello, what is the weather today?"),
    )
    assert resp.status_code == 200, resp.text
    decision = resp.headers.get("X-Revoc-Decision", "")
    assert decision == "audit", (
        f"Expected X-Revoc-Decision=audit in shadow mode (apply_shadow sets effective_action=Audit), "
        f"got: {decision!r}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 1


async def test_shadow_mode_dashboard_header_always_present(shadow_proxy_client):
    """X-Revoc-Dashboard is NON-NEGOTIABLE (SPEC.md Principle 11) — it must
    appear on every response including shadow-mode blocked ones.
    """
    resp = await shadow_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("DROP TABLE users; -- shadow test"),
    )
    assert resp.status_code == 200, resp.text
    assert "X-Revoc-Dashboard" in resp.headers, (
        "X-Revoc-Dashboard must be present on shadow-mode responses"
    )
    assert "X-Revoc-Timing" in resp.headers, (
        "X-Revoc-Timing must be present on shadow-mode responses"
    )
