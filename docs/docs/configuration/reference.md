# Configuration Reference

REVOC is configured via `revoc.toml` (or `revoc.yaml`). Every key can be overridden
with an environment variable using the `REVOC_SECTION__KEY` pattern.

The default configuration file is loaded from `configs/revoc.toml` relative to the
working directory. Override with `--config PATH` on the CLI.

## [server]

```toml
[server]
host = "0.0.0.0"
port = 8080
dashboard_port = 3000           # 0 = dashboard disabled
environment = "production"
max_request_body_bytes = 10485760    # 10 MB
max_response_body_bytes = 52428800   # 50 MB
shutdown_timeout_secs = 120
http2_enabled = true
dashboard_base_url = "http://localhost:3000"
```

## [upstream]

```toml
[upstream]
timeout_ms = 120000
connect_timeout_ms = 5000
max_idle_connections_per_host = 100
mock_mode = false
mock_response = "Mock response. Governance pipeline ran."

[[upstream.providers]]
name = "openai"
base_url = "https://api.openai.com"
api_key_env = "OPENAI_API_KEY"
api_key_file = ""
format = "openai"
default = true

[[upstream.providers]]
name = "anthropic"
base_url = "https://api.anthropic.com"
api_key_env = "ANTHROPIC_API_KEY"
format = "anthropic"
default = false

[[upstream.providers]]
name = "azure"
base_url = ""                    # e.g. https://mydeployment.openai.azure.com
api_key_env = "AZURE_OPENAI_API_KEY"
format = "azure"
default = false
```

## [policy]

```toml
[policy]
engine = "native"               # native | sidecar | wasm
enforcement_mode = "enforce"    # enforce | shadow
opa_url = "http://localhost:8181"
opa_timeout_ms = 2000
wasm_bundle_path = ""
fail_open = false               # NEVER true in production
decision_cache_ttl_secs = 60
decision_cache_max_entries = 10000
conflict_resolution = "tier_based"
```

## [governance]

```toml
[governance]
max_depth = 10
depth_exceeded_action = "block"
```

## [kill_switch]

```toml
[kill_switch]
enabled = true
redis_channel = "revoc:kill_switch"
on_redis_unavailable = "local_only"   # local_only | fail
```

## [detection]

```toml
[detection]
normalize_before_scan = true
regex_enabled = true
onnx_enabled = false
onnx_model_path = "models/bert-base-ner.onnx"
onnx_tokenizer_path = "models/bert-base-ner-tokenizer.json"
presidio_enabled = false
presidio_url = ""
decode_base64_args = true
decode_url_encoded_args = true
```

## [stream]

```toml
[stream]
buffer_output = false           # true = buffer full response (HIPAA/PCI mode)
sliding_window_size = 256
tool_call_accumulate = true
```

## [mcp]

```toml
[mcp]
analyze_tool_manifests = true
auto_disable_dangerous_tools = false
dangerous_tool_action = "audit"   # audit | block
# trusted_servers listed as [[mcp.trusted_servers]] entries
```

## [session]

```toml
[session]
enabled = true
ttl_secs = 3600
max_rows_before_alert = 500
```

## [storage]

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

## [cache]

```toml
[cache]
backend = "memory"              # memory | redis
redis_url_env = "REDIS_URL"
```

## [telemetry]

```toml
[telemetry]
otlp_endpoint = ""
service_name = "revoc-proxy"
service_version = "1.0.0"
sample_rate = 1.0
prometheus_port = 9090
log_level = "info"
log_format = "json"             # json | pretty
```

## [auth]

```toml
[auth]
mode = "apikey"                 # apikey | jwt | none
jwt_secret_env = "REVOC_JWT_SECRET"
api_keys_env = "REVOC_API_KEYS"
api_keys_file = ""
```

## [dashboard]

```toml
[dashboard]
auth_mode = "shared"            # shared | none
max_sse_connections = 100
```

## [webhooks]

```toml
[webhooks]
enabled = false

[[webhooks.endpoints]]
url = "https://hooks.example.com/revoc"
events = ["block", "quota_exceeded"]
min_severity = "high"
cooldown_minutes = 5
```

## Validation

```bash
revoc-proxy validate-config --config configs/revoc.toml
```

Exits 0 if valid, 1 with error messages if any field is invalid.
