# Audit Log

Every request governed by REVOC produces an audit event stored in the `audit_events`
table. Audit events are written asynchronously in batches and never block the request path.

## Audit Event Schema

```sql
CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    org_id TEXT,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    caller_id TEXT,
    caller_team TEXT,
    environment TEXT,
    decision TEXT NOT NULL,           -- allow | redact | block | audit | shadow-block | shadow-redact
    effective_action TEXT NOT NULL,   -- the action actually taken
    enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
    violated_rules TEXT,              -- comma-separated rule IDs
    finding_types TEXT,               -- comma-separated finding types (no values)
    model TEXT,
    provider TEXT,
    tool_name TEXT,
    request_type TEXT,
    governance_depth INTEGER DEFAULT 0,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    estimated_cost_usd REAL,
    duration_ms REAL,
    detection_ms REAL,
    policy_ms REAL,
    was_normalized INTEGER DEFAULT 0, -- 1 if normalization changed the input
    manifest_warnings INTEGER DEFAULT 0,
    trace_id TEXT,
    policy_engine TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

## Privacy Guarantees

The audit log stores **no PII values**. The `finding_types` field records which
entity types were detected (e.g., `EMAIL_ADDRESS,PHONE_NUMBER`) but never the
actual email address or phone number. The `violated_rules` field records rule IDs,
not matched content.

This is enforced at the type level: `TextSpan.value` has `#[serde(skip)]` — it is
excluded from all serialization paths and is never written to the database.

## Querying Audit Events

```bash
# All blocked requests in the last 24 hours
curl -s "http://localhost:8081/internal/audit?decision=block&hours=24" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool

# Requests with normalization evasion detected
curl -s "http://localhost:8081/internal/audit?was_normalized=true&hours=168" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool

# By caller
curl -s "http://localhost:8081/internal/audit?caller_id=agent-finance-prod&limit=50" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool
```

## Exporting Audit Events

```bash
# Export as JSON
curl -s "http://localhost:8081/internal/audit/export?start=2026-01-01&end=2026-02-01" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" > audit-jan-2026.json

# Export as CSV
curl -s "http://localhost:8081/internal/audit/export?format=csv&start=2026-01-01&end=2026-02-01" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" > audit-jan-2026.csv
```

## Audit Statistics

```bash
curl -s "http://localhost:8081/internal/audit/stats?hours=168" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool
```

```json
{
  "period_hours": 168,
  "total_requests": 47832,
  "by_decision": {
    "allow": 45102,
    "redact": 2481,
    "block": 249,
    "audit": 0
  },
  "top_rules": [
    {"rule_id": "pii_email_v1", "count": 1842},
    {"rule_id": "pii_phone_v1", "count": 639},
    {"rule_id": "sec_prompt_injection_v1", "count": 47}
  ],
  "evasion_attempts": 3,
  "total_tokens": 18432901,
  "estimated_cost_usd": 184.33
}
```

## Retention and Cleanup

Audit events are retained for `audit_retention_days` (default: 90). A background
task runs daily at midnight UTC to delete events older than the retention window.

For compliance requirements:
```toml
[storage]
audit_retention_days = 365   # PCI-DSS, HIPAA
# or
audit_retention_days = 90    # GDPR minimum defensible
```

## Direct Database Access

For SQLite (Tier 1), the audit database can be queried directly:

```bash
sqlite3 revoc-audit.db "
SELECT decision, count(*) as cnt
FROM audit_events
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY decision
ORDER BY cnt DESC;
"
```
