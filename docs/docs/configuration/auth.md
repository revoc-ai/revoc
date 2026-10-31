# Authentication Configuration

REVOC authenticates callers on the proxy port (`:8080`) and dashboard port (`:3000`).
The internal admin port (`:8081`) uses a separate `X-Admin-Key` header.

## Authentication Modes

### `apikey` (default)

Callers present an API key in the `Authorization: Bearer <key>` header or as
`api-key: <key>` (Azure SDK style). Keys are validated using constant-time
comparison (`subtle::ConstantTimeEq`) to prevent timing attacks.

```toml
[auth]
mode = "apikey"
api_keys_file = "/etc/revoc/api-keys.json"   # preferred in production
# OR
api_keys_env = "REVOC_API_KEYS"              # comma-separated key list
```

**`REVOC_API_KEYS` format (comma-separated, no spaces):**

```bash
REVOC_API_KEYS=revoc_k_key1here,revoc_k_key2here
```

Generate a key first with `revoc-proxy generate-key --label myapp`, then paste the `Key:` value here. Multiple callers each get their own key.

**`api-keys.json` format (preferred for production — supports per-key caller metadata):**

```json
[
  {
    "key_hash": "sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "caller_id": "agent-finance-prod",
    "org_id": "org-acme",
    "team": "finance",
    "policy_profile": "hipaa"
  },
  {
    "key_hash": "sha256:...",
    "caller_id": "agent-dev-sandbox",
    "org_id": "org-acme",
    "team": "engineering",
    "policy_profile": null
  }
]
```

Generate a new key and its hash:

```bash
revoc-proxy generate-key --label "agent-finance-prod"
```

Output:
```
Key:  revoc_k_AbCdEfGh...   ← store this securely; give to the caller
Hash: sha256:a665a45...      ← store this in api-keys.json
```

### `jwt`

Callers present a signed JWT in `Authorization: Bearer <token>`. REVOC validates
the signature using the secret from `REVOC_JWT_SECRET`.

```toml
[auth]
mode = "jwt"
jwt_secret_env = "REVOC_JWT_SECRET"
```

JWT claims mapped to CallerContext:
- `sub` → `caller_id`
- `org` → `org_id`
- `team` → `team`
- `profile` → `policy_profile`
- `env` → `environment`

### `none`

No authentication. Every request is accepted. **Development only.**

```toml
[auth]
mode = "none"
```

!!! danger
    Never use `mode = "none"` in production. It allows any caller to reach your
    upstream LLM with no identity tracking, no per-caller quota enforcement,
    and no audit attribution.

## CallerContext Extraction

Regardless of auth mode, REVOC extracts a `CallerContext` from each authenticated
request. This context flows through the entire governance pipeline:

```rust
pub struct CallerContext {
    pub org_id: String,
    pub caller_id: String,
    pub team: Option<String>,
    pub agent_id: Option<String>,
    pub service_name: Option<String>,
    pub environment: String,
    pub policy_profile: Option<String>,
    pub enforcement_mode: EnforcementMode,
    pub governance_depth: u8,
    pub attributes: HashMap<String, String>,
}
```

The `caller_id` appears on every audit event and in the dashboard.

## Admin API Authentication

Port 8081 (internal admin) uses a separate `X-Admin-Key` header:

```bash
curl -H "X-Admin-Key: $REVOC_ADMIN_KEY" http://localhost:8081/internal/emergency/kill-switch/status
```

Set the admin key:

```toml
[auth]
admin_key_env = "REVOC_ADMIN_KEY"
```

```bash
export REVOC_ADMIN_KEY=your-admin-key-here
```

Or pass it directly via Docker:

```bash
docker run ... -e REVOC_ADMIN_KEY=your-secure-admin-key ghcr.io/revoc-ai/revoc:latest
```

!!! warning
    If `REVOC_ADMIN_KEY` is not set, the admin API uses `dev-admin-key` as the default.
    Always set a strong key in production.
