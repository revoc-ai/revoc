# Emergency Kill-Switch

The kill-switch stops all AI traffic governed by REVOC within 50 milliseconds.
It is the highest-precedence action (Emergency tier, precedence 4) and cannot be
overridden by any policy rule.

## When to Use It

- Detected ongoing data exfiltration via AI tool calls
- Security incident requiring immediate cessation of all AI activity
- Compliance requirement to suspend AI during an audit window
- Runaway agent burning budget faster than rate limits can stop it

The kill-switch is a last resort. For per-caller or per-org throttling, use
`token_quota_v1` rate limiting instead.

## Activation

### Global (all traffic)

```bash
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{
    "scope": "global",
    "reason": "Security incident — exfiltration detected via execute_sql tool",
    "activated_by": "alice@example.com"
  }'
```

Response:

```json
{
  "status": "activated",
  "scope": "global",
  "activated_at": "2026-01-15T14:32:00Z",
  "propagation_ms": 12
}
```

### Per-Organization

```bash
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{
    "scope": "org",
    "target": "org_acme_prod",
    "reason": "Tenant investigation in progress",
    "activated_by": "security-team"
  }'
```

### Per-Caller

```bash
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{
    "scope": "caller",
    "target": "agent-finance-prod-7",
    "reason": "Agent exhibiting anomalous data access pattern",
    "activated_by": "on-call-engineer"
  }'
```

## Response When Kill-Switch Is Active

All governed traffic returns HTTP 503:

```json
{
  "error": {
    "code": "REVOC_KILL_SWITCH_ACTIVE",
    "message": "All AI traffic suspended by emergency stop. Contact your AI platform team.",
    "type": "emergency_stop",
    "trace_id": "01932abc-...",
    "dashboard_url": "http://localhost:3000/emergency",
    "documentation_url": "https://revoc.io/docs/operations/emergency-kill-switch"
  }
}
```

!!! warning "Health checks always bypass the kill-switch"
    `GET /health`, `GET /ready`, and `GET /startup` always return 200 regardless of
    kill-switch state. This ensures your container orchestrator does not restart the
    proxy during an intentional suspension.

## Status Check

```bash
curl -s http://localhost:8081/internal/emergency/kill-switch/status \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool
```

```json
{
  "global_active": false,
  "active_org_count": 1,
  "active_caller_count": 0,
  "active_orgs": ["org_acme_prod"],
  "active_callers": []
}
```

## Deactivation

```bash
# Deactivate global kill-switch
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/deactivate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{"scope": "global"}'

# Deactivate for a specific org
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/deactivate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{"scope": "org", "target": "org_acme_prod"}'
```

## Durable State and Multi-Instance Propagation

Kill-switch state is a single versioned document, signed with HMAC-SHA256, in a
durable store:

- **Redis** when `REDIS_URL` is set. Every instance shares it. The document
  lives at `revoc:kill_switch:state`.
- **The local SQLite database** otherwise (single instance).

The proxy loads the state **before it serves traffic**, so an active switch
stays active across restarts and redeploys.

When you activate:

1. The instance that receives the request blocks traffic immediately.
2. It writes the next version of the document with an atomic compare-and-set,
   so two operators acting at once cannot overwrite each other.
3. With Redis, the new document is published on `revoc:kill_switch`, and the
   other instances apply it within ~50 ms.
4. Every instance also re-reads the store every `reconcile_interval_ms`
   (default 2 s). An instance that missed the message still converges.

**Signing.** Set `REVOC_KILL_SWITCH_KEY` (at least 32 bytes, the same on every
instance; `openssl rand -hex 32`). The proxy refuses to start with Redis and no
key. A document or message that fails verification is ignored, so write access
to Redis alone cannot switch traffic on or off. Instances never adopt a version
older than the one they hold, so replaying an old document cannot roll them back.
The Helm chart generates the key on first install if you do not supply
`secrets.killSwitchSigningKey`.

**If the store is unavailable:**

```toml
[kill_switch]
on_redis_unavailable = "local_only"    # default — keep the last known state
# on_redis_unavailable = "fail_closed" # block all traffic until the store is readable
```

- **Activation** always takes effect locally at once. If it cannot be persisted,
  the response says `"durable": false` and the instance retries on every reconcile.
- **Deactivation** is persisted first. If the store cannot be written, the API
  returns 503 and the switch stays active everywhere.

`GET /ready` includes the kill-switch state. It shows the version, the store,
whether the store was read recently, and any activations not yet persisted.
With `fail_closed` and an unreadable store, `/ready` returns 503. With
`local_only` it reports `"status": "degraded"`.

## Admin Credentials

The kill-switch is operated with the **admin key** (`REVOC_ADMIN_KEY` /
`auth.admin_key`, at least 16 characters), never with a client API key:

- The internal API (`/internal/emergency/...`, loopback by default) requires
  `X-Admin-Key`.
- The dashboard's kill-switch buttons also require the admin key. You type it
  in on the Settings page and it is sent per request, never stored. Client API
  keys can view the dashboard but get 403 when changing the switch. This holds
  even when dashboard auth is `none`.
- The proxy refuses to start if the admin key is also configured as a client
  API key.

## Audit Trail

Every activation and deactivation is written to the `kill_switch_log` table:

```sql
SELECT * FROM kill_switch_log ORDER BY timestamp DESC LIMIT 10;
```

```
id                    | scope  | action     | activated_by       | reason              | timestamp
01932abc-0001-...     | global | activated  | alice@example.com  | Security incident   | 2026-01-15 14:32:00
01932abc-0002-...     | global | deactivated| alice@example.com  |                     | 2026-01-15 14:45:00
```

Kill-switch activations cannot be deleted from the audit log — the table has no
soft-delete or hard-delete path in the admin API.

## Recovery Checklist

After deactivating the kill-switch:

1. Verify status is clear: `GET /internal/emergency/kill-switch/status`
2. Verify traffic resumes: `GET /health` on port 8080
3. Review the dashboard at `:3000` for the blocked request window
4. Export audit events for the incident window via the admin API
5. File a post-mortem and update governance rules to prevent recurrence
