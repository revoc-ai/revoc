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
postgres_url_env = "DATABASE_URL"
pool_size = 20
```

```bash
DATABASE_URL=postgres://revoc:password@postgres:5432/revoc
```

## Audit Write Pipeline

Audit events are written asynchronously in batches to avoid blocking the request path:

1. After each governed request, an `AuditEvent` is constructed and sent to an async channel
2. A background task collects up to `audit_write_batch_size` events
3. Every `audit_write_interval_ms` milliseconds, the batch is written in a single transaction
4. On shutdown, the batch writer flushes any pending events before the process exits

**Batch defaults:** 100 events per batch, 100ms interval — at 1000 req/s, each batch
is flushed in 10ms intervals. P99 write latency < 5ms.

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
- Policy decision cache shared across all proxy instances
- Session state shared across instances (required for `session_data_exfil_v1`)
- Kill-switch propagation via pub/sub

## Database Schema

REVOC applies migrations automatically on startup (`migrations_auto_run = true`).
The schema is defined in `admin-api/alembic/versions/001_initial_schema.py` and
the Rust migration files under `sqlx/migrations/`.

Run migrations manually:

```bash
revoc-proxy migrate --config configs/revoc.toml
```

Tables created:

| Table | Purpose |
|---|---|
| `organizations` | Org registry |
| `policy_bundles` | Versioned policy YAML + compiled Rego |
| `policy_audit_log` | Who changed which policy and when |
| `audit_events` | Governance decisions — one row per governed request |
| `kill_switch_log` | Kill-switch activation/deactivation log |
| `users` | Dashboard and admin API users |
| `api_keys` | Hashed API keys with caller metadata |
