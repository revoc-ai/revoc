# Admin API

The admin API runs on port 8081 and provides policy management, audit access,
and user management. **Port 8081 must never be internet-facing.**

All endpoints require `X-Admin-Key: <key>` authentication.

## Policy Management

### List active policy bundles

```
GET /internal/policies
```

```bash
curl -s http://localhost:8081/internal/policies \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool
```

### Activate a policy bundle

```
POST /internal/policies
Content-Type: application/yaml
```

```bash
curl -s -X POST http://localhost:8081/internal/policies \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  --data-binary @my-policy.yaml
```

Response:
```json
{"status": "activated", "policy_id": "01932abc-...", "rules_loaded": 5}
```

### Validate a policy bundle (dry-run)

```
POST /internal/policies/validate
Content-Type: application/yaml
```

### Rollback a policy bundle

```
POST /internal/policies/{policy_id}/rollback
```

### Reload the policy engine

```
POST /internal/policies/reload
```

Forces the policy engine to reload all active bundles. Required after updating
WASM bundle files on disk.

---

## Audit Access

### Query audit events

```
GET /internal/audit
```

Query parameters:

| Parameter | Description |
|---|---|
| `decision` | Filter: `allow`, `redact`, `block`, `audit`, `shadow-block`, `shadow-redact` |
| `org_id` | Filter by organization |
| `caller_id` | Filter by caller |
| `hours` | Events from the last N hours (default: 24) |
| `was_normalized` | `true` to filter evasion attempts |
| `limit` | Max results (default: 100, max: 10000) |
| `offset` | Pagination offset |

### Export audit events

```
GET /internal/audit/export
```

Query parameters: `start`, `end` (ISO 8601), `format` (`json` or `csv`).

### Audit statistics

```
GET /internal/audit/stats
```

Query parameters: `hours`, `org_id`.

---

## Kill-Switch

### Activate

```
POST /internal/emergency/kill-switch/activate
Content-Type: application/json

{"scope": "global|org|caller", "target": "id", "reason": "...", "activated_by": "..."}
```

### Deactivate

```
POST /internal/emergency/kill-switch/deactivate
Content-Type: application/json

{"scope": "global|org|caller", "target": "id"}
```

### Status

```
GET /internal/emergency/kill-switch/status
```

---

## User Management

### List users

```
GET /internal/users
```

### Create user

```
POST /internal/users
Content-Type: application/json

{"username": "alice", "email": "alice@example.com", "role": "viewer|admin|superuser"}
```

### Delete user

```
DELETE /internal/users/{user_id}
```

---

## API Key Management

### Generate a new API key

```
POST /internal/api-keys
Content-Type: application/json

{"label": "agent-finance-prod", "org_id": "org-acme", "policy_profile": "hipaa"}
```

Response:
```json
{
  "key": "revoc_k_AbCdEf...",   ← store securely; shown only once
  "key_id": "01932abc-...",
  "caller_id": "agent-finance-prod"
}
```

### Revoke an API key

```
DELETE /internal/api-keys/{key_id}
```

---

## Health (admin port)

```
GET /internal/health
```

Returns proxy health from the admin API perspective, including database and Redis status.
