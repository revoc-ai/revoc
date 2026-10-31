# Session Tracking

REVOC tracks state across multiple requests from the same caller within a session
window. Session tracking enables detection of exfiltration patterns that are
invisible when examining individual requests in isolation.

## What Is a Session

A session groups all requests from the same `caller_id` within a rolling 1-hour
window (configurable via `session.ttl_secs`). The session state is stored in
Redis (Tier 2/3) or in-process memory (Tier 1).

## Session State

```rust
pub struct SessionState {
    pub session_id: String,
    pub org_id: String,
    pub caller_id: String,
    pub tools_called: Vec<(String, DateTime<Utc>)>,  // tool name + timestamp
    pub total_rows_read: u64,
    pub pii_entities_seen: HashSet<String>,           // entity types only, never values
    pub external_send_attempted: bool,
    pub started_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}
```

## The Exfiltration Pattern

The rule `session_data_exfil_v1` fires when all three of these conditions are
true within a single session:

```rust
pub fn is_exfil_pattern_detected(&self) -> bool {
    self.total_rows_read > 500          // large bulk read
        && !self.pii_entities_seen.is_empty()  // PII was encountered
        && self.external_send_attempted         // attempt to send externally
}
```

This detects a classic AI agent data exfiltration scenario:
1. Agent calls a database tool and reads hundreds of customer records
2. Those records contain PII (detected by REVOC during MCP tool result inspection)
3. The agent then attempts to call an HTTP tool to send data to an external URL

No single request looks suspicious. The session view reveals the pattern.

## What REVOC Tracks Per Session

| Field | Updated when |
|---|---|
| `tools_called` | Any MCP `tools/call` request is allowed |
| `total_rows_read` | MCP tool result contains a `rows` or `count` field > 0 |
| `pii_entities_seen` | Detection pipeline finds PII in any request or result |
| `external_send_attempted` | MCP tool call targets an external URL (not on trusted server list) |

Only entity *types* are stored in `pii_entities_seen` — never the actual values.

## Configuration

```toml
[session]
enabled = true
ttl_secs = 3600           # 1-hour session window
max_rows_before_alert = 500  # threshold for bulk read detection
```

```bash
REVOC_SESSION__ENABLED=true
REVOC_SESSION__TTL_SECS=3600
REVOC_SESSION__MAX_ROWS_BEFORE_ALERT=500
```

## Viewing Session Activity

The dashboard at `:3000` shows active sessions under the **Sessions** tab:

- Session ID and caller context
- Tools called (count and names, no argument values)
- PII entity types encountered during the session
- `external_send_attempted` flag
- Whether the exfiltration pattern is active

## Session Storage

| Tier | Storage | Multi-instance sharing |
|---|---|---|
| Tier 1 | In-process HashMap | No — each instance has independent session state |
| Tier 2 / 3 | Redis (TTL-based keys) | Yes — all instances share the same session view |

For multi-instance deployments, Tier 2 or Tier 3 with Redis is required for
session tracking to work correctly across proxy instances.
