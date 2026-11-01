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

For streaming responses (`stream: true`), REVOC governs the text as it streams,
with the same policy as non-streamed responses:

1. Each choice (OpenAI) or content block (Anthropic) is tracked separately.
2. The last `stream.hold_back_chars` characters (default 128) of each are held
   back. Text is released only after it has been scanned together with the text
   before it, so a pattern split across chunks is still caught before any of it
   reaches your application.
3. PII is redacted in-stream. The client receives the text with the span
   replaced.
4. A blocking finding (a secret, a security pattern) stops the stream. OpenAI
   clients receive a synthetic `content_filter` chunk followed by `[DONE]`;
   Anthropic clients receive an `error` event. Nothing held is released.

**Tool calls** are never streamed through as they arrive. Every tool-call delta
is held until the call is complete. The assembled calls go through full tool-call
governance before `finish_reason = tool_calls` (or Anthropic's `stop_reason`) is
forwarded. If a call is blocked, the stream stops instead, and your application
never sees the call.

**Shadow mode** records what would have been redacted or blocked without
changing the stream.

**`stream.buffer_output = true`** holds the whole response until it has been
governed. A block then becomes an HTTP 403 rather than a stopped stream.

## Governance Direction Summary

| Direction | What is inspected | Rules that apply |
|---|---|---|
| Request (App → LLM) | All message content, system prompt, tool call arguments | All 30 default rules |
| Response (LLM → App) | Message content, tool call arguments in streaming | PII rules, secret rules, security rules |
| MCP request (App → MCP) | Tool arguments | All rules, especially sec_ddl_mutation_v1, sec_ssrf_v1 |
| MCP result (MCP → App) | Tool result JSON content | mcp_result_pii_v1, secret rules |
| Sampling request | Full LLM request via MCP sampling/createMessage | Same as LLM request (depth+1) |
