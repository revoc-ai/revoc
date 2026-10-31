# Bidirectional Governance

REVOC governs traffic in both directions: incoming requests from your application
to the LLM, and outgoing responses from the LLM back to your application.

## Why Bidirectional Matters

A one-directional proxy only governs what your application sends to the model.
It cannot prevent:

- A model trained on poisoned data from returning secrets it memorized
- A RAG pipeline returning PII from a database query in the model's response
- An MCP tool returning customer SSNs from a database call to the AI client
- A model hallucinating a real-looking credit card number in its response

REVOC runs the full detection pipeline on LLM responses and MCP tool results,
not just on requests.

## LLM Response Governance

After the upstream LLM returns a response, REVOC inspects it before forwarding
to your application:

```
Upstream LLM response
  ↓ Parse response body
  ↓ Extract content from choices[].message.content (non-streaming)
     or accumulate delta.content chunks (streaming)
  ↓ Run detection pipeline on each content field
  ↓ Evaluate policy on output findings
  ↓ Route on effective_action:
      BLOCK  → do not forward; return 403 RevocErrorResponse
      REDACT → redact response body before forwarding
      ALLOW  → forward unchanged
```

**Upstream error transparency:** If the LLM returns a 4xx or 5xx error, REVOC
forwards it verbatim without inspection. Error responses from the upstream
are never modified — only the `X-Revoc-Trace-ID` header is added.

## MCP Tool Result Governance

When an MCP tool returns a result, REVOC inspects the result before it reaches
the AI client (which would include it in the next LLM context window):

```
MCP tool result (JSON-RPC response)
  ↓ Extract result content fields
  ↓ Run detection pipeline
  ↓ Rule mcp_result_pii_v1: if PII found → Redact
  ↓ Redact result JSON before forwarding to AI client
```

This prevents a database query tool from returning a customer's SSN into the
model's context window, even if your application's policy does not explicitly
restrict what the tool returns.

## Streaming Response Governance

For streaming responses (`stream: true`), REVOC uses a sliding window scanner:

1. Each SSE chunk's `delta.content` is appended to a 256-byte rolling window
2. The window is scanned for patterns on each chunk
3. The safe prefix (window minus the maximum pattern length) is forwarded
4. If a pattern spans a chunk boundary, it is detected when the window fills past it
5. If a block-level finding is detected mid-stream: the stream is terminated,
   a synthetic `content_filter` chunk is injected, and no further chunks forwarded

**Tool call accumulation:** When `finish_reason = tool_calls` is received in a
streaming response, REVOC has accumulated all tool call arguments across chunks.
It runs full MCP governance on the accumulated calls before allowing any tool
invocation. If blocked, a synthetic content filter chunk is injected and the
MCP server never receives the call.

## Governance Direction Summary

| Direction | What is inspected | Rules that apply |
|---|---|---|
| Request (App → LLM) | All message content, system prompt, tool call arguments | All 30 default rules |
| Response (LLM → App) | Message content, tool call arguments in streaming | PII rules, secret rules, security rules |
| MCP request (App → MCP) | Tool arguments | All rules, especially sec_ddl_mutation_v1, sec_ssrf_v1 |
| MCP result (MCP → App) | Tool result JSON content | mcp_result_pii_v1, secret rules |
| Sampling request | Full LLM request via MCP sampling/createMessage | Same as LLM request (depth+1) |
