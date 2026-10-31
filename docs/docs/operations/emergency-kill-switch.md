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

## Multi-Instance Propagation

In multi-instance deployments (Helm, docker compose scale), the kill-switch must
reach all proxy instances within 50ms. REVOC uses Redis pub/sub for propagation:

1. The activating instance writes to the `revoc:kill_switch` Redis channel
2. All other instances have a background subscriber that receives the message
3. Each instance updates its local `AtomicBool` (for global) or `DashMap` (for org/caller)
4. Local state update is an in-memory operation — always < 1ms after message receipt

Redis propagation latency is typically 2–10ms on a local cluster. The 50ms budget
covers Redis RTT + subscriber wakeup + local state update.

**If Redis is unavailable during activation:**

```toml
[kill_switch]
on_redis_unavailable = "local_only"   # default — activates on this instance only
# on_redis_unavailable = "fail"       # rejects activation if Redis is down
```

With `local_only`, activation succeeds on the receiving instance immediately.
Other instances will pick up the state on their next Redis reconnect.

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
