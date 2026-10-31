# MCP Governance

REVOC governs the Model Context Protocol (MCP) at every method level.
MCP tool calls, tool results, resource reads, and sampling requests are all
inspected bidirectionally before reaching either the AI client or the MCP server.

## MCP Methods and Governance Level

| Method | Governance required | Response inspected |
|---|---|---|
| `initialize` | No — forwarded directly | No |
| `ping` | No — forwarded directly | No |
| `tools/list` | Manifest analysis on response | Yes (manifest analyzer) |
| `tools/call` | Full governance on arguments | Yes (result inspection) |
| `resources/list` | No — forwarded directly | No |
| `resources/read` | Full governance | Yes |
| `prompts/list` | No — forwarded directly | No |
| `prompts/get` | No — forwarded directly | No |
| `sampling/createMessage` | Routed to LLM handler (depth+1) | Yes |
| `logging/setLevel` | No — forwarded directly | No |

## tools/call Governance (12 Steps)

```
Step  0: Kill-switch check
Step  1: Depth check
Step  2: Parse McpRawRequest
Step  3: initialize/ping → forward directly
Step  4: tools/list → analyze manifest, set X-Revoc-Manifest-Warnings
Step  5: sampling/createMessage → route to LLM handler (depth+1)
Step  6: Validate server in trusted registry
Step  7: Run detection engine on tool arguments
Step  8: Evaluate policy (conflict::resolve())
Step  9: BLOCK → return McpBlockResponse (HTTP 200, JSON-RPC error -32603)
           X-Revoc-Block: true header set
           UPSTREAM MCP SERVER NEVER RECEIVES A BLOCKED REQUEST
Step 10: ALLOW → forward to MCP server with X-Revoc-Depth set
Step 11: Receive tool result → run detection on result → redact PII
Step 12: Write audit, SSE, metrics
```

## MCP Block Response

When REVOC blocks an MCP tool call, it returns HTTP 200 with a JSON-RPC error body.
The MCP server never receives the request. The AI client sees:

```json
{
  "jsonrpc": "2.0",
  "id": "call-id-from-request",
  "error": {
    "code": -32603,
    "message": "Request blocked by governance policy.",
    "data": {
      "code": "REVOC_GOVERNANCE_BLOCK",
      "rules": ["sec_ddl_mutation_v1"],
      "trace_id": "01932abc-...",
      "dashboard_url": "http://localhost:3000/traces/01932abc-..."
    }
  }
}
```

!!! note "HTTP 200 for MCP blocks"
    The MCP protocol uses JSON-RPC over HTTP. Governance blocks return HTTP 200
    with a JSON-RPC error object — this is intentional. The AI client reads the
    JSON-RPC error code, not the HTTP status code.
    LLM endpoint blocks use HTTP 403, not 200.

## Trusted Server Registry

REVOC only forwards MCP tool calls to servers in the trusted registry:

```toml
[[mcp.trusted_servers]]
id = "database-mcp"
url = "http://database-mcp:3001"
tls_verify = true

[[mcp.trusted_servers]]
id = "filesystem-mcp"
url = "http://filesystem-mcp:3002"
tls_verify = true
```

A `tools/call` targeting a server not in this list is blocked with
`REVOC_GOVERNANCE_BLOCK` before any network connection is made.

## sampling/createMessage

When an MCP server sends a `sampling/createMessage` request (asking the AI client
to perform an LLM completion on its behalf), REVOC intercepts this and routes it
through the LLM governance handler with `governance_depth + 1`. This prevents MCP
servers from bypassing governance by initiating their own LLM calls.

## Configuring MCP Governance

```toml
[mcp]
analyze_tool_manifests = true          # Run manifest analysis on tools/list responses
auto_disable_dangerous_tools = false   # Remove dangerous tools from tools/list response
dangerous_tool_action = "audit"        # Action on dangerous manifest findings: audit | block
```
