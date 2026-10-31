# Internal API Reference

The internal API on port 8081 exposes all admin operations. This page documents
every endpoint with request/response schemas.

## Authentication

All internal API endpoints require:

```
X-Admin-Key: <admin-key>
```

The admin key is configured via the `REVOC_ADMIN_KEY` environment variable.
It is distinct from proxy API keys used by governed callers.

## Governance Endpoints

### `POST /internal/emergency/kill-switch/activate`

Activates the emergency kill-switch for the specified scope.

**Request:**
```json
{
  "scope": "global",
  "target": null,
  "reason": "Security incident",
  "activated_by": "alice@example.com"
}
```

For `org` or `caller` scope, `target` is the org ID or caller ID.

**Response:**
```json
{
  "status": "activated",
  "scope": "global",
  "activated_at": "2026-01-15T14:32:00Z",
  "propagation_ms": 12
}
```

---

### `POST /internal/emergency/kill-switch/deactivate`

**Request:**
```json
{"scope": "global"}
```

**Response:**
```json
{"status": "deactivated", "scope": "global"}
```

---

### `GET /internal/emergency/kill-switch/status`

**Response:**
```json
{
  "global_active": false,
  "active_org_count": 1,
  "active_caller_count": 0,
  "active_orgs": ["org-acme"],
  "active_callers": []
}
```

---

## Policy Endpoints

### `GET /internal/policies`

Returns all active policy bundles.

**Response:**
```json
[
  {
    "policy_id": "01932abc-...",
    "name": "hipaa-baseline",
    "version": "1.0",
    "org_id": "org-acme",
    "environment": "production",
    "status": "active",
    "activated_at": "2026-01-15T10:30:00Z",
    "rules_loaded": 12
  }
]
```

---

### `POST /internal/policies`

Activate a new policy bundle. Body: YAML or JSON policy bundle.

**Response:**
```json
{
  "status": "activated",
  "policy_id": "01932abc-...",
  "rules_loaded": 12,
  "effective_at": "2026-01-15T10:30:00Z"
}
```

---

### `POST /internal/policies/validate`

Validate a policy bundle without activating it. Same body format as `POST /internal/policies`.

**Response (valid):**
```json
{"valid": true, "rules_parsed": 5}
```

**Response (invalid):**
```json
{"valid": false, "error": "Rule 'sec_ddl_mutation_v1' is a Security-tier rule and cannot be modified"}
```

---

### `POST /internal/policies/{policy_id}/rollback`

Roll back to the previous version of a policy bundle.

---

### `POST /internal/policies/reload`

Force the policy engine to reload all active bundles from storage.

---

## Audit Endpoints

### `GET /internal/audit`

Query parameters: `decision`, `org_id`, `caller_id`, `hours`, `was_normalized`, `limit`, `offset`.

---

### `GET /internal/audit/export`

Query parameters: `start`, `end` (ISO 8601), `format` (`json` | `csv`).

Returns a streaming response with all matching events.

---

### `GET /internal/audit/stats`

Query parameters: `hours`, `org_id`.

**Response:**
```json
{
  "period_hours": 24,
  "total_requests": 4782,
  "by_decision": {"allow": 4501, "redact": 241, "block": 40, "audit": 0},
  "top_rules": [{"rule_id": "pii_email_v1", "count": 184}],
  "evasion_attempts": 0,
  "total_tokens": 1843290,
  "estimated_cost_usd": 18.43
}
```

---

## User and Key Management

### `GET /internal/users`
### `POST /internal/users`
### `DELETE /internal/users/{user_id}`
### `GET /internal/api-keys`
### `POST /internal/api-keys`
### `DELETE /internal/api-keys/{key_id}`

See [Admin API](admin-api.md) for request/response details.

---

## Grafana Dashboard Export

### `GET /internal/grafana-dashboard`

Returns a Grafana dashboard JSON that can be imported directly.

---

## Health

### `GET /internal/health`

Returns the proxy health status as seen from the admin API process.
