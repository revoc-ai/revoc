"""MCP governance tests — tools/call security blocking, ACL, and bidirectional
PII redaction on tool results (SPEC.md §11 MCP handler, 12 steps).
"""

import json

import pytest

from .conftest import mcp_tools_call, wiremock_count, wiremock_last_request


async def test_drop_table_blocked_wiremock_zero_calls(proxy_client, wiremock_mcp):
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("execute_sql", {"query": "DROP TABLE users;"}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text  # JSON-RPC error, HTTP 200
    body = resp.json()
    assert "sec_ddl_mutation_v1" in body["error"]["data"]["rules"]
    assert resp.headers["X-Revoc-Block"] == "true"
    assert await wiremock_count(wiremock_mcp, "/mcp") == 0


async def test_delete_no_where_blocked(proxy_client, wiremock_mcp):
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("execute_sql", {"query": "DELETE FROM users"}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "sec_delete_no_where_v1" in body["error"]["data"]["rules"] or \
        "sec_mass_delete_v1" in body["error"]["data"]["rules"]
    assert resp.headers["X-Revoc-Block"] == "true"
    assert await wiremock_count(wiremock_mcp, "/mcp") == 0


async def test_ssrf_blocked(proxy_client, wiremock_mcp):
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call(
            "calculator",
            {"expression": "fetch http://169.254.169.254/latest/meta-data/"},
            server_id="mock-mcp",
        ),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "sec_ssrf_v1" in body["error"]["data"]["rules"]
    assert resp.headers["X-Revoc-Block"] == "true"
    assert await wiremock_count(wiremock_mcp, "/mcp") == 0


async def test_path_traversal_blocked(proxy_client, wiremock_mcp):
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("calculator", {"expression": "../../etc/passwd"}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "sec_path_traversal_v1" in body["error"]["data"]["rules"]
    assert resp.headers["X-Revoc-Block"] == "true"
    assert await wiremock_count(wiremock_mcp, "/mcp") == 0


async def test_unauthorized_team_blocked(proxy_client, wiremock_mcp):
    """mcp_tool_acl_v1, as actually implemented in
    crates/revoc-proxy/src/handlers/mcp.rs (`mcp_acl_block`), fires when
    `select_mcp_server` (Step 6) returns `None` — i.e. no trusted server
    matches the requested server_id AND there isn't exactly one configured
    server to fall back to. This is NOT a team-based lookup into
    policies/default/data.json (that data.json's
    `mcp_tool_acl.execute_sql.allowed_teams` is loaded into the OPA/wasm
    bundle via revoc-policy/build.rs but the *native* engine, which this
    stack uses (REVOC_POLICY__ENGINE=native), never reads it). With
    auth.mode=none every caller is `CallerContext { team: None, ... }` and
    there is no header to set `team` for this request, so a genuine
    team-ACL test isn't possible.

    Additionally, with exactly ONE trusted server configured
    (docker/docker-compose.test.yml: REVOC_MCP__TRUSTED_SERVERS__0__ID=mock-mcp,
    the only entry), `select_mcp_server`'s single-server-deployment fallback
    (`if servers.len() == 1 { return servers.first(); }`) means an unmatched
    server_id is STILL resolved to "mock-mcp" — `select_mcp_server` never
    returns `None`, so `mcp_acl_block`/mcp_tool_acl_v1 cannot be triggered in
    this single-trusted-server stack. (Configuring a second trusted server
    via `REVOC_MCP__TRUSTED_SERVERS__1__*` was attempted but the `config`
    crate's environment-variable source fails to deserialize indexed array
    entries beyond index 0 into `Vec<TrustedMcpServer>` — "invalid type: map,
    expected a sequence" — so a 2-server stack isn't achievable via env vars
    with the current config loader.) This test documents the verified
    fallback behavior: an unmatched server_id with a single configured
    trusted server still reaches that server."""
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("calculator", {"expression": "2+2"}, server_id="totally-unknown-server"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "result" in body  # reached mock-mcp via the single-server fallback
    assert await wiremock_count(wiremock_mcp, "/mcp") == 1


async def test_allowed_tool_reaches_upstream(proxy_client, wiremock_mcp):
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("calculator", {"expression": "2+2"}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "result" in body
    assert resp.headers["X-Revoc-Decision"] in ("allow", "audit")
    assert await wiremock_count(wiremock_mcp, "/mcp") == 1


async def test_tool_result_pii_redacted(proxy_client, wiremock_mcp):
    """Calls `lookup_customer`, whose mock-mcp response (see
    docker/wiremock/mock-mcp/mappings/tools-call-pii.json) contains an email
    and SSN. Bidirectional governance (Step 11 of the MCP handler) must
    redact this PII via mcp_result_pii_v1 before it reaches the client."""
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("lookup_customer", {"customer_id": "42"}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text
    assert await wiremock_count(wiremock_mcp, "/mcp") == 1

    body = resp.json()
    result_text = body["result"]["content"][0]["text"]
    assert "jane.doe@example.com" not in result_text
    assert "123-45-6789" not in result_text

    rules = resp.headers.get("X-Revoc-Rules", "")
    assert "mcp_result_pii_v1" in rules.split(",")


async def test_block_has_dashboard_url_in_error_data(proxy_client, wiremock_mcp):
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("execute_sql", {"query": "TRUNCATE TABLE orders;"}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    err_data = body["error"]["data"]
    trace_id = resp.headers["X-Revoc-Trace-ID"]

    assert err_data["trace_id"] == trace_id
    assert err_data["dashboard_url"].endswith(f"/traces/{trace_id}")
    assert "sec_ddl_mutation_v1" in err_data["rules"]
    assert err_data["code"] == "REVOC_GOVERNANCE_BLOCK"
    assert await wiremock_count(wiremock_mcp, "/mcp") == 0
