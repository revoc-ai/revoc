# Proxy Response Headers

Every response from REVOC — whether allowed, redacted, blocked, or from the health
check — includes a set of `X-Revoc-*` headers. Two headers are non-negotiable on
every response: `X-Revoc-Dashboard` and `X-Revoc-Timing`.

## Complete Header Reference

### `X-Revoc-Trace-ID`

**Always present.** UUID v7 uniquely identifying this governed request.

```
X-Revoc-Trace-ID: 01932abc-1234-7abc-9def-000000000001
```

Use this to correlate client-side logs with the REVOC dashboard trace detail page.

---

### `X-Revoc-Dashboard` ⚠️ NON-NEGOTIABLE

**Always present.** Direct URL to the dashboard trace detail page.

```
X-Revoc-Dashboard: http://localhost:3000/traces/01932abc-1234-7abc-9def-000000000001
```

This header exists so that any developer who sees a REVOC response — even without
knowing about the dashboard — can immediately navigate to the full trace detail.
It is set on every response, including 403 blocks.

---

### `X-Revoc-Timing` ⚠️ NON-NEGOTIABLE

**Always present.** Per-stage latency breakdown.

```
X-Revoc-Timing: detection=2ms,policy=0ms,redaction=1ms,upstream=312ms,total=315ms
```

Stages:
- `detection` — total detection pipeline duration
- `policy` — policy evaluation duration
- `redaction` — body mutation duration (0ms if action was allow/block)
- `upstream` — upstream LLM/MCP call duration (0ms if blocked before upstream)
- `total` — end-to-end proxy duration

This header is non-negotiable because it allows operators to distinguish REVOC
overhead from upstream latency without any additional tooling.

---

### `X-Revoc-Decision`

**Always present.** The governance decision applied to this request.

| Value | Meaning |
|---|---|
| `allow` | Request passed all governance checks unchanged |
| `redact` | PII or secrets were redacted before forwarding |
| `block` | Request was rejected (HTTP 403 or JSON-RPC error) |
| `audit` | Request observed and logged, no action taken |
| `shadow-block` | Shadow mode: would have been blocked, was allowed |
| `shadow-redact` | Shadow mode: would have been redacted, was allowed |

---

### `X-Revoc-Request-ID`

**Always present.** UUID v7 for the raw HTTP request (before governance processing).
Distinct from `X-Revoc-Trace-ID`.

---

### `X-Revoc-Depth`

**Always present.** The governance depth of this request (0 = not nested).

!!! note
    This header is set on **responses to clients**. A different header,
    also named `X-Revoc-Depth`, is set on **outgoing upstream requests** with
    value `depth + 1`. These are distinct: the response header reflects the
    current request's depth; the upstream header signals the next level.

---

### `X-Revoc-Rules`

**Present when decision != allow.** Comma-separated list of violated rule IDs.

```
X-Revoc-Rules: pii_ssn_v1,pii_email_v1
```

---

### `X-Revoc-Block`

**MCP blocks only.** Set to `true` on blocked MCP tool call responses.

```
X-Revoc-Block: true
```

---

### `X-Revoc-Manifest-Warnings`

**tools/list responses with findings only.** Count of manifest analysis findings.

```
X-Revoc-Manifest-Warnings: 3
```

---

### `X-Upstream-Request-ID`

**Present when upstream provides a request ID.** The upstream provider's request ID
(e.g., OpenAI's `x-request-id` response header).

---

## Header Value Sanitization

All header values are passed through `sanitize_header_value()` which strips `\r`, `\n`,
and `\0` characters to prevent header injection attacks. This applies to every
`X-Revoc-*` header and to values derived from request content.

## Headers on Upstream Error Responses

When the upstream LLM returns a 4xx or 5xx error, REVOC forwards the response verbatim
and adds only `X-Revoc-Trace-ID`. It does not add the full `X-Revoc-*` header set to
upstream error responses. This ensures your application sees the original error without
REVOC headers that would be misleading (no policy decision was made — the upstream failed).
