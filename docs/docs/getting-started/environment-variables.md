# Environment Variables

All configuration keys in `revoc.toml` can be overridden with environment variables.
The pattern is `REVOC_` + section name in uppercase + `__` + key name in uppercase.

## Examples

| TOML key | Environment variable |
|---|---|
| `[server] port = 8080` | `REVOC_SERVER__PORT=8080` |
| `[policy] enforcement_mode = "shadow"` | `REVOC_POLICY__ENFORCEMENT_MODE=shadow` |
| `[upstream] mock_mode = true` | `REVOC_UPSTREAM__MOCK_MODE=true` |
| `[detection] onnx_enabled = true` | `REVOC_DETECTION__ONNX_ENABLED=true` |
| `[storage] backend = "postgres"` | `REVOC_STORAGE__BACKEND=postgres` |

## Required Variables

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | OpenAI API key — forwarded to upstream on OpenAI provider requests |
| `ANTHROPIC_API_KEY` | Anthropic API key — required if using the Anthropic provider |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI key — required if using the Azure provider |

## Authentication Variables

| Variable | Description |
|---|---|
| `REVOC_AUTH__MODE` | `apikey` (default), `jwt`, or `none` (dev only) |
| `REVOC_JWT_SECRET` | Secret for JWT signing — required when `auth.mode = jwt` |
| `REVOC_API_KEYS` | Comma-separated list of valid API keys — used when `auth.mode = apikey` |

## Database Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | Postgres connection string — e.g. `postgres://user:pass@host:5432/revoc` |

## Cache Variables

| Variable | Description |
|---|---|
| `REDIS_URL` | Redis connection string — e.g. `redis://localhost:6379` |

## Telemetry Variables

| Variable | Description |
|---|---|
| `REVOC_TELEMETRY__OTLP_ENDPOINT` | OTel collector gRPC endpoint — e.g. `http://otel:4317` |
| `REVOC_TELEMETRY__LOG_LEVEL` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `REVOC_TELEMETRY__LOG_FORMAT` | `json` (default) or `pretty` |

## Zero-Code-Change Deployment

To govern any application that respects the OpenAI SDK environment variables,
set only these two variables — no source code changes required:

```bash
export REVOC_BASE_URL=http://localhost:8080
export OPENAI_API_KEY=sk-your-key-here
# The standard OpenAI env var also works:
export OPENAI_BASE_URL=http://localhost:8080
```

The OpenAI Python SDK reads `OPENAI_BASE_URL` automatically. LangChain reads
`OPENAI_API_BASE`. LlamaIndex reads `OPENAI_API_BASE`. All route through REVOC
without any code changes.

## Full Variable Reference

All variables and their defaults:

```bash
# Server
REVOC_SERVER__HOST=0.0.0.0
REVOC_SERVER__PORT=8080
REVOC_SERVER__DASHBOARD_PORT=3000
REVOC_SERVER__ENVIRONMENT=production
REVOC_SERVER__MAX_REQUEST_BODY_BYTES=10485760
REVOC_SERVER__MAX_RESPONSE_BODY_BYTES=52428800
REVOC_SERVER__SHUTDOWN_TIMEOUT_SECS=120
REVOC_SERVER__HTTP2_ENABLED=true
REVOC_SERVER__DASHBOARD_BASE_URL=http://localhost:3000

# Upstream
REVOC_UPSTREAM__TIMEOUT_MS=120000
REVOC_UPSTREAM__CONNECT_TIMEOUT_MS=5000
REVOC_UPSTREAM__MOCK_MODE=false
REVOC_UPSTREAM__MOCK_RESPONSE="Mock response. Governance pipeline ran."

# Policy
REVOC_POLICY__ENGINE=native
REVOC_POLICY__ENFORCEMENT_MODE=enforce
REVOC_POLICY__OPA_URL=http://localhost:8181
REVOC_POLICY__OPA_TIMEOUT_MS=2000
REVOC_POLICY__FAIL_OPEN=false
REVOC_POLICY__DECISION_CACHE_TTL_SECS=60
REVOC_POLICY__DECISION_CACHE_MAX_ENTRIES=10000

# Detection
REVOC_DETECTION__NORMALIZE_BEFORE_SCAN=true
REVOC_DETECTION__REGEX_ENABLED=true
REVOC_DETECTION__ONNX_ENABLED=false
REVOC_DETECTION__ONNX_MODEL_PATH=models/bert-base-ner.onnx
REVOC_DETECTION__ONNX_TOKENIZER_PATH=models/bert-base-ner-tokenizer.json
REVOC_DETECTION__PRESIDIO_ENABLED=false
REVOC_DETECTION__PRESIDIO_URL=
REVOC_DETECTION__DECODE_BASE64_ARGS=true
REVOC_DETECTION__DECODE_URL_ENCODED_ARGS=true

# Stream
REVOC_STREAM__BUFFER_OUTPUT=false
REVOC_STREAM__SLIDING_WINDOW_SIZE=256
REVOC_STREAM__TOOL_CALL_ACCUMULATE=true

# MCP
REVOC_MCP__ANALYZE_TOOL_MANIFESTS=true
REVOC_MCP__AUTO_DISABLE_DANGEROUS_TOOLS=false
REVOC_MCP__DANGEROUS_TOOL_ACTION=audit

# Storage
REVOC_STORAGE__BACKEND=sqlite
REVOC_STORAGE__SQLITE_PATH=revoc-audit.db
REVOC_STORAGE__POOL_SIZE=20
REVOC_STORAGE__MIGRATIONS_AUTO_RUN=true
REVOC_STORAGE__AUDIT_WRITE_BATCH_SIZE=100
REVOC_STORAGE__AUDIT_WRITE_INTERVAL_MS=100
REVOC_STORAGE__AUDIT_RETENTION_DAYS=90

# Cache
REVOC_CACHE__BACKEND=memory

# Telemetry
REVOC_TELEMETRY__OTLP_ENDPOINT=
REVOC_TELEMETRY__SERVICE_NAME=revoc-proxy
REVOC_TELEMETRY__SERVICE_VERSION=1.0.0
REVOC_TELEMETRY__SAMPLE_RATE=1.0
REVOC_TELEMETRY__PROMETHEUS_PORT=9090
REVOC_TELEMETRY__LOG_LEVEL=info
REVOC_TELEMETRY__LOG_FORMAT=json

# Auth
REVOC_AUTH__MODE=apikey
REVOC_AUTH__JWT_SECRET_ENV=REVOC_JWT_SECRET
REVOC_AUTH__API_KEYS_ENV=REVOC_API_KEYS
REVOC_AUTH__API_KEYS_FILE=

# Governance
REVOC_GOVERNANCE__MAX_DEPTH=10
REVOC_GOVERNANCE__DEPTH_EXCEEDED_ACTION=block

# Kill switch
REVOC_KILL_SWITCH__ENABLED=true
REVOC_KILL_SWITCH__REDIS_CHANNEL=revoc:kill_switch
REVOC_KILL_SWITCH__ON_REDIS_UNAVAILABLE=local_only
```
