# Storage Configuration

REVOC stores audit events and policy bundles in a relational database.
The cache layer (policy decision cache, session state) uses an in-memory store
or Redis.

## Storage Backends

```toml
[storage]
backend = "sqlite"              # sqlite | postgres
sqlite_path = "revoc-audit.db"
postgres_url_env = "DATABASE_URL"
pool_size = 20
migrations_auto_run = true
audit_write_batch_size = 100
audit_write_interval_ms = 100
audit_retention_days = 90
```

### SQLite (Tier 1)

SQLite is the default. The database file is created at `sqlite_path` on first start.
Suitable for single-node deployments and development.

```toml
[storage]
backend = "sqlite"
sqlite_path = "/var/lib/revoc/audit.db"
```

### Postgres (Tier 2/3)

```toml
[storage]
backend = "postgres"
postgres_url_env = "DATABASE_URL"   # name of the env var holding the URL
pool_size = 20
migrations_auto_run = true          # create tables on startup
```

```bash
DATABASE_URL=postgres://revoc:password@postgres:5432/revoc
```

Use Postgres when more than one proxy instance runs: every instance writes to
the same `audit_events` table, and the admin API and dashboard read it.

- The proxy refuses to start when `DATABASE_URL` is unset or the database is
  unreachable; it does not serve traffic it cannot audit.
- With `migrations_auto_run = true` the proxy creates `audit_events`,
  `kill_switch_log` and `kill_switch_state` if they are missing. Instances
  starting together take an advisory lock so they don't race. The table
  layout matches the admin API's migration, so either service can create it.
- Without Redis, kill-switch state is kept in `kill_switch_state` and every
  instance reconciles against it. Because the database is shared, the state
  is signed: `REVOC_KILL_SWITCH_KEY` (at least 32 bytes, the same on every
  instance) is required. The Helm chart generates one.

## Audit Write Pipeline

Audit writes never block the request path:

1. Each governed request builds an `AuditEvent` (entity types, rule IDs and
   timings — never matched values).
2. The event goes onto a bounded in-memory queue (100,000 events); the
   request does not wait.
3. A single writer task takes whatever is queued, up to
   `audit_write_batch_size` events, and stores it in one transaction. Under
   load, batches form on their own; at low load each event is written at once.
4. A failed batch is retried 3 times, pausing `audit_write_interval_ms`
   and doubling each time. Only then are its events counted as dropped.
5. On shutdown the proxy waits for the queue to drain before exiting.

`/ready` reports the writer's counters under `audit` (`queued`, `written`,
`dropped`, `batches`). It reports `"status": "degraded"` once any event has
been dropped. SQLite runs in WAL mode, so dashboard reads don't block writes.
The proof run (`scripts/proof.sh`, see [CLAIMS.md](https://github.com/revoc-ai/revoc/blob/main/CLAIMS.md))
fails if any event is dropped under its load test.

### Every exit is audited

Every authenticated request on `/v1/chat/completions`, `/v1/completions`,
`/v1/embeddings` and `/mcp` leaves at least one audit record. That includes
exits that end before policy runs: kill switch, depth limit, malformed body,
rate limit (429), upstream failure and fail-closed governance errors. Such
exits get a minimal record:

| Field | Value |
|---|---|
| `decision` / `effective_action` | `reject` (4xx), `error` (5xx), `block` (403), otherwise the response's `X-Revoc-Decision` |
| `policy_engine` | `exit:<status>`, e.g. `exit:503` |
| `trace_id`, `violated_rules` | from `X-Revoc-Trace-ID` / `X-Revoc-Rules` when present |

The body is never read for these records. Unauthenticated (401) requests are
counted in metrics but not audited, so callers without a key cannot fill the
audit store.

## Audit Retention

Events older than `audit_retention_days` are deleted by a background cleanup task
that runs once daily:

```toml
[storage]
audit_retention_days = 90   # Delete events older than 90 days
```

For compliance requirements:
- PCI-DSS: minimum 365 days (`audit_retention_days = 365`)
- HIPAA: minimum 365 days
- GDPR: use the shortest defensible period (`audit_retention_days = 90`)

## Cache Configuration

```toml
[cache]
backend = "memory"    # memory | redis
redis_url_env = "REDIS_URL"
```

### In-Process Memory Cache (Tier 1)

Policy decisions are cached in a `DashMap` keyed by a hash of the `PolicyInput`.
The cache holds up to `decision_cache_max_entries` entries with TTL of
`decision_cache_ttl_secs`. Cache hit rate is reported in Prometheus metrics.

### Redis Cache (Tier 2/3)

```bash
REDIS_URL=redis://redis:6379
```

Redis enables:
- Session state shared across instances, stored as `revoc:session:<org>:<caller>`
  with the `[session] ttl_secs` TTL (needed for `session_data_exfil_v1` when
  more than one instance runs)
- Kill-switch state and propagation via pub/sub

### Session recording

LLM and MCP traffic from one caller share a session
(`<org_id>:<caller_id>`). Each MCP `tools/call` records:

- the tool name, keeping the last 256 per session
- rows returned: the largest array in `structuredContent`, or in a top-level
  `rows`/`data`/`results`, otherwise the number of `content` items
- PII entity *types* seen in arguments and results, never values
- whether the tool sends data out (its name contains `http`, `fetch`,
  `request`, `post`, `send`, `mail`, `upload`, `webhook`, `slack`, `publish`,
  `notify`, `sms` or `tweet`)

The call is added to the session before policy runs. A send that completes
the pattern (more than 500 rows read, PII seen, external send) is blocked by
`session_data_exfil_v1` before it reaches the tool server.

## Database Schema

The proxy creates its own tables on startup (`migrations_auto_run = true`), from
`crates/revoc-proxy/sql/schema.sql` (SQLite) or `sql/schema_postgres.sql`
(Postgres). The admin API's alembic migration
(`admin-api/alembic/versions/001_initial_schema.py`) creates the same audit
tables plus its own.

Create the proxy tables without starting it:

```bash
revoc-proxy migrate --config configs/revoc.toml
```

| Table | Created by | Purpose |
|---|---|---|
| `audit_events` | proxy, admin API | Governance decisions: one or more rows per request |
| `kill_switch_log` | proxy, admin API | Kill-switch activation/deactivation log |
| `kill_switch_state` | proxy | Signed, versioned kill-switch document (when not using Redis) |
| `organizations`, `policy_bundles`, `policy_audit_log`, `users`, `api_keys` | admin API | Admin plane |
