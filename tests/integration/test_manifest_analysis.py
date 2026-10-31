"""Tool manifest analysis tests (D10) — crates/revoc-detector/src/manifest_analyzer.rs
and its integration in crates/revoc-proxy/src/handlers/mcp.rs (Step 4 of the MCP
handler lifecycle).

IMPORTANT — documented real behavior (not aspirational spec):
`analyze_tools_list()` looks for `value.get("tools")` or a bare top-level array
in the bytes it's given. The MCP handler passes it the RAW upstream response
bytes for `tools/list`, which is a JSON-RPC envelope:
    {"jsonrpc":"2.0","id":..., "result": {"tools":[...]}}
`value.get("tools")` on this envelope is `None` (the key is nested under
`result`), and `value.as_array()` is also `None` (it's an object, not an
array). So `analyze_tools_list` ALWAYS returns `tools_analyzed: 0,
findings: []` for any real MCP `tools/list` response in this stack —
`X-Revoc-Manifest-Warnings` is therefore never set, even though
docker/wiremock/mock-mcp/mappings/tools-list.json defines an `execute_sql`
tool with a `query` parameter (which matches the "query"/"sql" entries in
DANGEROUS_PARAM_KEYWORDS and would be flagged if the envelope were unwrapped
first). These tests assert the REAL, current behavior.
"""

import pytest

from .conftest import mcp_tools_list


async def test_tools_list_with_dangerous_param_no_warning_header(proxy_client, wiremock_mcp):
    """execute_sql's `query` parameter matches DANGEROUS_PARAM_KEYWORDS
    ("sql"/"query"), but because analyze_tools_list() cannot see inside the
    {"result":{"tools":[...]}} envelope, no X-Revoc-Manifest-Warnings header
    is produced. This documents the current (un-fixed) behavior."""
    resp = await proxy_client.post("/mcp", json=mcp_tools_list(call_id="1"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "execute_sql" in [t["name"] for t in body["result"]["tools"]]
    assert "X-Revoc-Manifest-Warnings" not in resp.headers


async def test_tools_list_clean_no_warning(proxy_client, wiremock_mcp):
    """A tools/list response containing only the `calculator` tool (no
    dangerous parameter names or suspicious descriptions) — regardless of the
    envelope issue above, this case has zero findings either way, so no
    X-Revoc-Manifest-Warnings header is set."""
    resp = await proxy_client.post("/mcp", json=mcp_tools_list(call_id="clean-check"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [t["name"] for t in body["result"]["tools"]] == ["calculator"]
    assert "X-Revoc-Manifest-Warnings" not in resp.headers


async def test_manifest_warnings_never_recorded_in_audit(proxy_client, dashboard_client):
    """spawn_mcp_audit() (crates/revoc-proxy/src/handlers/mcp.rs) hardcodes
    `manifest_warnings: 0` for every MCP audit event regardless of any
    manifest_analyzer findings — there is no code path that writes a non-zero
    manifest_warnings value to the audit_events table. This test issues a
    tools/list request (which would, per the envelope issue documented above,
    never produce findings anyway) and confirms the response carries
    X-Revoc-Trace-ID so a corresponding audit row would exist, while no
    X-Revoc-Manifest-Warnings header is ever observable on the response —
    consistent with the hardcoded `manifest_warnings: 0` in the audit writer."""
    resp = await proxy_client.post("/mcp", json=mcp_tools_list(call_id="1"))
    assert resp.status_code == 200, resp.text
    assert "X-Revoc-Trace-ID" in resp.headers
    assert "X-Revoc-Manifest-Warnings" not in resp.headers
