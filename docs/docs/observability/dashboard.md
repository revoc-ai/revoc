# Dashboard

REVOC ships an embedded React SPA served on port 3000. The dashboard requires
no separate deployment — it is compiled into the proxy binary and served directly.

## Accessing the Dashboard

```
http://localhost:3000
```

In production with auth enabled, the dashboard requires the shared dashboard
password configured in `[dashboard] auth_mode = "shared"`.

## Live Feed

The dashboard home page shows a real-time stream of governed requests via
Server-Sent Events (SSE). Each row shows:

| Column | Value |
|---|---|
| Timestamp | Request received time |
| Caller | `caller_id` from authentication |
| Model | LLM model name or MCP tool name |
| Decision | `allow` / `redact` / `block` / `audit` / `shadow-block` / `shadow-redact` |
| Rules | Comma-separated list of violated rule IDs |
| Duration | Total proxy overhead in ms |

Click any row to open the full trace detail view.

## Trace Detail View

The trace detail page for a single governed request shows:

- **Request summary** — caller, model, provider, request type, governance depth
- **Findings** — all detected entities with type, severity, field name, and character position
  (values are never shown)
- **Policy decision** — action, applicable rules, conflict resolution result, enforcement mode
- **Redaction diff** — which fields were modified and by which strategy
- **Timing breakdown** — `detection=Xms`, `policy=Xms`, `redaction=Xms`, `upstream=Xms`, `total=Xms`
- **Raw audit event** — the full JSON stored in the `audit_events` table
- **Response headers** — all `X-Revoc-*` headers sent to the client

Navigate to a trace directly from the `X-Revoc-Dashboard` response header:

```bash
curl -si http://localhost:8080/v1/chat/completions -d '...' | grep X-Revoc-Dashboard
# X-Revoc-Dashboard: http://localhost:3000/traces/01932abc-1234-7abc-...
```

## Rules View

`http://localhost:3000/rules` — shows all active governance rules with:

- Current status (active / shadow / disabled)
- Trigger count (last 24h / 7d / 30d)
- Source (default / profile / custom)
- Policy bundle that provides the rule

## Sessions View

`http://localhost:3000/sessions` — shows active caller sessions:

- Session ID and caller context
- Tools called in this session
- PII entity types encountered
- `external_send_attempted` flag
- Whether exfiltration pattern is active

## Emergency Stop View

`http://localhost:3000/emergency` — shows kill-switch status:

- Global kill-switch state
- Per-org and per-caller active suspensions
- Activation log (who activated, when, why)
- Deactivate button (requires admin authentication)

## SSE Connection Limit

The dashboard maintains SSE connections to stream live events. The maximum
number of concurrent SSE connections is configurable:

```toml
[dashboard]
max_sse_connections = 100
```

Connections beyond the limit receive `429 Too Many Requests` on the SSE endpoint.

## Disabling the Dashboard

```toml
[server]
dashboard_port = 0    # 0 = dashboard disabled
```

The proxy continues to function normally. All governance, audit, and metrics still
operate — only the web UI is unavailable.
