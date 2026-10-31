"""
REVOC MCP Governance Example — complete, runnable governed MCP agent.

Demonstrates:
- MCP tool call governance (block dangerous SQL, allow safe queries)
- Bidirectional governance (inspect tool results for PII)
- Tool manifest analysis (detect suspicious parameter names)

Before running:
    docker run -d -p 8080:8080 -p 3000:3000 -p 8081:8081 \
      -e REVOC_UPSTREAM__MOCK_MODE=true \
      -e REVOC_AUTH__MODE=none \
      --name revoc ghcr.io/revoc-ai/revoc:latest

    pip install openai httpx
"""

import json
import sys
import urllib.request
from typing import Any

import httpx

REVOC_MCP_URL = "http://localhost:8080/mcp"
REVOC_HEALTH_URL = "http://localhost:8080/health"


def check_health() -> bool:
    """Verify REVOC is accepting MCP traffic."""
    try:
        with urllib.request.urlopen(REVOC_HEALTH_URL, timeout=3) as resp:
            data = json.loads(resp.read())
            return data.get("status") == "ok"
    except Exception:
        return False


def mcp_call(method: str, params: dict[str, Any], call_id: str = "1") -> dict[str, Any]:
    """Send a JSON-RPC MCP request through REVOC and return the parsed response."""
    payload = {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": method,
        "params": params,
    }
    with httpx.Client(timeout=10.0) as client:
        response = client.post(
            REVOC_MCP_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        # Surface REVOC governance headers
        for header in ("x-revoc-decision", "x-revoc-rules", "x-revoc-dashboard", "x-revoc-block"):
            if value := response.headers.get(header):
                print(f"  [{header}]: {value}")
        return response.json()


def demo_initialize() -> None:
    """Step 1: Initialize the MCP session — REVOC forwards directly."""
    print("\n--- MCP initialize ---")
    result = mcp_call(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "revoc-example", "version": "1.0.0"},
        },
    )
    if "result" in result:
        print(f"  MCP session initialized successfully")
    else:
        print(f"  Response: {json.dumps(result, indent=2)}")


def demo_tools_list() -> None:
    """Step 2: tools/list — REVOC runs manifest analysis on the response."""
    print("\n--- MCP tools/list (manifest analysis) ---")
    # In mock mode, REVOC returns a synthetic tool manifest for demonstration
    result = mcp_call("tools/list", {}, call_id="2")
    if "result" in result:
        tools = result["result"].get("tools", [])
        print(f"  Tools returned: {len(tools)}")
    else:
        print(f"  Response: {json.dumps(result, indent=2)}")
    # X-Revoc-Manifest-Warnings header will be set if any dangerous param names detected


def demo_safe_tool_call() -> None:
    """Step 3: A safe SELECT query — REVOC allows it."""
    print("\n--- Safe tool call (SELECT query) ---")
    result = mcp_call(
        "tools/call",
        {
            "name": "execute_sql",
            "arguments": {"query": "SELECT count(*) FROM orders WHERE created_at > '2026-01-01'"},
        },
        call_id="3",
    )
    if "result" in result:
        print(f"  Tool call allowed. Result: {result['result']}")
    elif "error" in result:
        print(f"  Blocked: {result['error']['data']['code']}")


def demo_ddl_block() -> None:
    """Step 4: A DDL mutation — sec_ddl_mutation_v1 blocks it before the MCP server receives it."""
    print("\n--- DDL mutation (should be blocked) ---")
    result = mcp_call(
        "tools/call",
        {
            "name": "execute_sql",
            "arguments": {"query": "DROP TABLE users"},
        },
        call_id="4",
    )
    if "error" in result:
        code = result["error"]["data"]["code"]
        rules = result["error"]["data"]["rules"]
        trace = result["error"]["data"]["dashboard_url"]
        print(f"  Blocked: {code}")
        print(f"  Rules: {rules}")
        print(f"  Dashboard: {trace}")
    else:
        print(f"  Unexpected allow: {result}")


def demo_ssrf_block() -> None:
    """Step 5: SSRF attempt — sec_ssrf_v1 blocks it."""
    print("\n--- SSRF attempt (should be blocked) ---")
    result = mcp_call(
        "tools/call",
        {
            "name": "http_request",
            "arguments": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
        call_id="5",
    )
    if "error" in result:
        print(f"  Blocked: {result['error']['data']['code']}")
        print(f"  Rules: {result['error']['data']['rules']}")
    else:
        print(f"  Unexpected allow: {result}")


def demo_unicode_evasion_block() -> None:
    """Step 6: Unicode evasion — normalization catches fullwidth DROP before detection."""
    print("\n--- Unicode evasion attempt (fullwidth DROP TABLE) ---")
    result = mcp_call(
        "tools/call",
        {
            "name": "execute_sql",
            # Fullwidth ASCII: ＤＲＯＰTable — looks different but normalizes to DROP TABLE
            "arguments": {"query": "ＤＲＯＰTable users"},
        },
        call_id="6",
    )
    if "error" in result:
        print(f"  Blocked after normalization: {result['error']['data']['code']}")
        print(f"  Rules: {result['error']['data']['rules']}")
    else:
        print(f"  Unexpected allow: {result}")


def main() -> None:
    print("REVOC MCP Governance Example")
    print(f"Dashboard: http://localhost:3000")

    if not check_health():
        print("\nERROR: REVOC proxy is not running on port 8080.")
        print("Start it with:")
        print("  docker run -d -p 8080:8080 -p 3000:3000 -p 8081:8081 \\")
        print("    -e REVOC_UPSTREAM__MOCK_MODE=true \\")
        print("    -e REVOC_AUTH__MODE=none \\")
        print("    --name revoc ghcr.io/revoc-ai/revoc:latest")
        sys.exit(1)

    demo_initialize()
    demo_tools_list()
    demo_safe_tool_call()
    demo_ddl_block()
    demo_ssrf_block()
    demo_unicode_evasion_block()

    print("\n--- Complete ---")
    print("View all MCP traces at: http://localhost:3000")


if __name__ == "__main__":
    main()
