# Governance Depth

REVOC tracks how many times a single request has passed through the governance pipeline.
When depth reaches 10, the request is blocked with `REVOC_GOVERNANCE_DEPTH_EXCEEDED`.

## The Infinite Recursion Problem

Autonomous AI agents can call tools, and those tools can themselves trigger LLM calls.
If those LLM calls go through REVOC, they increment the governance depth counter.
Without a depth limit, a malicious or misbehaving agent can create an infinite loop:

```
Agent → LLM call (depth 1)
  Model calls tool_A (depth 2)
    tool_A calls LLM (depth 3)
      Model calls tool_B (depth 4)
        tool_B calls LLM (depth 5)
          ... (infinite)
```

This burns API tokens, exhausts rate limits, and can cause downstream system failures.

## How REVOC Tracks Depth

The `X-Revoc-Depth` header carries the current governance depth:

- REVOC reads `X-Revoc-Depth` from the **incoming** request (default: 0 if absent)
- If the value is ≥ 10, the request is rejected immediately with HTTP 503 before any
  detection or policy evaluation
- When forwarding to the **upstream** LLM or MCP server, REVOC sets `X-Revoc-Depth: {depth+1}`
- The `X-Revoc-Depth` header is **never** set on responses back to the client

```
Client → REVOC (reads: X-Revoc-Depth: 3)
  REVOC → Upstream (sets: X-Revoc-Depth: 4)
    Upstream → REVOC (reads: X-Revoc-Depth: 4)
      ... until depth=10 → 503 DepthExceeded
```

## Response When Depth Is Exceeded

HTTP 503 with body:

```json
{
  "error": {
    "code": "REVOC_GOVERNANCE_DEPTH_EXCEEDED",
    "message": "Governance depth limit (10/10) reached. Possible infinite agent loop.",
    "type": "depth_exceeded",
    "trace_id": "01932abc-...",
    "dashboard_url": "http://localhost:3000/traces/01932abc-...",
    "documentation_url": "https://revoc.io/docs/concepts/governance-depth"
  }
}
```

## Configuration

```toml
[governance]
max_depth = 10                    # fixed at 10 — not configurable per-org
depth_exceeded_action = "block"   # always block — not configurable
```

The depth limit of 10 is a hard constant (`MAX_GOVERNANCE_DEPTH`) defined in
`revoc-proxy/src/depth.rs`. It cannot be raised at runtime.

## Testing Depth Enforcement

```bash
# Simulate a request arriving at depth 10
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Revoc-Depth: 10" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | python3 -m json.tool
```

Expected: HTTP 503, `"code": "REVOC_GOVERNANCE_DEPTH_EXCEEDED"`.

## Dashboard Integration

The audit log stores `governance_depth` on every event. The dashboard shows:

- A "Depth" badge on any event with `governance_depth > 0`
- A warning indicator when depth > 5
- A `DepthExceeded` decision type on blocked events

## Legitimate Deep Agents

For orchestration frameworks that legitimately nest agent calls, ensure each layer
sets `X-Revoc-Depth` correctly when forwarding calls. The depth counter exists to
catch runaway loops, not to limit the number of steps a well-behaved agent can take
(10 levels of nesting is sufficient for all known production orchestration patterns).
