# Changelog

All notable changes to REVOC are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-beta.1] — Unreleased

First public beta. Not yet recommended as the only control in front of
production traffic; see "Project status" in the README.

### Security
- Every governance failure now fails closed (unless `policy.fail_open = true`):
  detection timeouts and failed detector stages, policy evaluation errors on
  the MCP and streamed tool-call paths, and redaction errors on LLM requests
  and MCP tool results all return 503 instead of forwarding the request.
- A WASM policy bundle that is missing or fails to load stops startup instead
  of silently falling back to the native engine.
- The internal admin API binds to `127.0.0.1` by default
  (`server.internal_host` / `server.internal_port`).
- No default admin key: the images no longer ship `dev-admin-key`, and an
  unset or short (< 16 characters) key disables the admin API.
- `/internal/reload` and `/internal/emergency/kill-switch/status` now require
  `X-Admin-Key`; client API keys (`REVOC_API_KEYS`) are no longer accepted as
  admin keys.
- The policy decision cache is off by default (`decision_cache_ttl_secs = 0`)
  because its key does not cover tool arguments or session state.

### Fixed
- The container image now has a writable `/data` directory and stores the
  SQLite audit DB at `/data/revoc-audit.db`.
- Streaming governance uses the configured detection engine instead of a
  regex-only test engine.
- `revoc-proxy emergency` CLI commands send `X-Admin-Key` (they previously sent
  a bearer token the server ignored); `status` now takes `--admin-key`.

### Changed
- Version numbers are aligned on 0.1.0-beta.1 (Python packages 0.1.0b1).
  Pre-release tags publish images as `:beta`, npm under the `beta` dist-tag,
  and GitHub releases as pre-releases.
- README and docs no longer claim production readiness, tamper-proof audit,
  compliance certification, published latency numbers, a chart repository or
  Postgres audit storage on the proxy.

## [0.1.0] — 2024-01-01

### Added

#### Core Architecture
- Nine-crate Rust workspace in strict dependency order:
  `revoc-core` → `revoc-config` → `revoc-telemetry` → `revoc-detector` →
  `revoc-pipeline` → `revoc-policy` → `revoc-redaction` → `revoc-dashboard` →
  `revoc-proxy`
- `RevocError` enum covering all failure modes with `http_status()` and
  `is_transient()` helpers
- Complete type hierarchy: `Finding`, `PolicyDecision`, `CallerContext`,
  `SessionState`, `PolicyInput`, `ChatMessage`, `TokenUsage`
- Full `McpRawRequest`, `McpBlockResponse`, `McpToolCall`, `ToolManifestFinding`
  MCP type set
- `RevocErrorResponse` for all REVOC-originated errors (never wraps upstream errors)
- Trait definitions: `DetectionStage`, `PolicyEngine`, `Redactor`

#### Detection Engine
- **D8 — Unicode normalization** (`normalization.rs`): NFKC + zero-width removal
  (7 chars) + RTLO/BIDI removal (9 chars) + control char strip — runs before
  every regex pass, guaranteed idempotent
- **D10 — Tool manifest analysis** (`manifest_analyzer.rs`): scans `tools/list`
  responses for dangerous parameter keywords (40 terms) and suspicious description
  patterns before the AI client sees them
- PII detection patterns: US_SSN, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD
  (Luhn validated), IBAN_CODE (mod-97 validated), IP_ADDRESS_V4/V6, US_PASSPORT,
  US_DRIVER_LICENSE, DATE_OF_BIRTH, MEDICAL_RECORD_NUMBER, NPI_NUMBER, DEA_NUMBER
- Secret detection patterns: AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN,
  OPENAI_KEY, ANTHROPIC_KEY, GENERIC_API_KEY, PRIVATE_KEY, JWT_TOKEN,
  PASSWORD_IN_JSON
- Security patterns: DDL_MUTATION, DELETE_NO_WHERE, SSRF_INTERNAL,
  PATH_TRAVERSAL, PROMPT_INJECTION, SYSTEM_PROMPT_EXTRACTION, MASS_DELETE
- Financial patterns: SWIFT_BIC, ROUTING_NUMBER (ABA checksum), BANK_ACCOUNT
- ONNX NER detector stub (activated when `onnx_enabled = true`)
- HTTP plugin interface for community detection extensions
- Presidio and Azure enricher integrations (optional, configured via URL)
- Encoding detection: base64 decode + URL decode before scanning
  (`was_encoded` flag on findings)
- Pipeline deduplication: merges overlapping spans, keeps higher-confidence hit

#### Policy Engine
- **D12 — Tier-based conflict resolution**: Emergency (4) > Security (3) >
  Profile (2) > Custom (1) > Default (0) — security-tier blocks always win
- Native Rust policy engine with all 30 default rules active from first run
- OPA HTTP sidecar mode for enterprise Rego policies
- OPA WASM mode via `wasmtime` for in-process Rego evaluation
- Decision cache (LRU, configurable TTL and max entries)
- Shadow mode: effective_action always Audit regardless of configured action
- `SECURITY_RULE_IDS` constant — 10 rules that cannot be overridden by custom allow

#### 30 Default Rules (active with zero configuration)
- **PII redaction** (11 rules): SSN, credit card, IBAN, bank account, passport,
  driver license, email, phone, IP address, MRN, date of birth
- **Secret blocking** (10 rules): AWS keys, GitHub token, OpenAI key, Anthropic key,
  generic API key, private key, JWT, password-in-JSON
- **Security blocks** (9 rules, Tier 3 — cannot be overridden): prompt injection,
  system prompt extraction, DDL mutation, DELETE without WHERE, SSRF, path
  traversal, encoded evasion, mass delete, session data exfiltration
- **MCP result PII redaction** (1 rule): PII in tool results redacted before
  reaching AI client
- **Operational rules** (2 rules): MCP tool ACL, token quota enforcement

#### Proxy Handlers
- **D9 — Governance depth limit**: `X-Revoc-Depth` header enforced at Step 1
  in every handler; depth ≥ 10 → HTTP 503 before body is read
- **D11 — Emergency kill-switch**: atomic `AtomicBool` + `DashMap` per-org/caller;
  Redis pub/sub propagation to all instances within ~50ms; Step 0 in every handler
- LLM handler: 22-step lifecycle covering kill-switch, depth, detection, policy,
  redaction, upstream forwarding, streaming governance, response headers, audit
- MCP handler: 12-step lifecycle covering kill-switch, depth, method routing,
  manifest analysis, tool argument detection, bidirectional governance,
  block response (JSON-RPC error, HTTP 200), audit
- Embeddings handler
- Emergency admin handler (internal port 8081 only)
- Health/readiness/startup/metrics endpoints (bypass kill-switch)

#### Streaming
- Sliding window scanner (default 256 bytes): scans SSE chunks for PII/secrets
  as they stream without buffering the full response
- Tool call accumulator: collects `function.name` + `function.arguments` across
  SSE chunks; runs full MCP governance when `finish_reason = "tool_calls"`;
  injects synthetic content-filter chunk if blocked
- `buffer_output = true` mode for full-buffer compliance (HIPAA/PCI-DSS)

#### Response Headers (all mandatory on every response)
- `X-Revoc-Trace-ID` — UUID v7 per request
- `X-Revoc-Decision` — allow / redact / block / audit / shadow-block
- `X-Revoc-Dashboard` — **NON-NEGOTIABLE** direct link to trace in dashboard
- `X-Revoc-Timing` — **NON-NEGOTIABLE** breakdown of detection/policy/redaction/upstream/total ms
- `X-Revoc-Request-ID` — UUID v7
- `X-Revoc-Depth` — current governance depth (on upstream requests, not client responses)
- `X-Revoc-Rules` — comma-separated rule IDs when decision ≠ allow
- `X-Revoc-Block: true` — MCP blocks only
- `X-Revoc-Manifest-Warnings: {count}` — tools/list responses with findings
- All values sanitized: `\r`, `\n`, `\0` stripped

#### Security Properties
- Fail-closed by default: `fail_open = false` non-negotiable
- Constant-time API key comparison via `subtle::ConstantTimeEq`
- SSRF protection: upstream URL resolved from config allowlist only, never
  from request headers
- Header injection prevention: `sanitize_header_value()` on every outgoing value
- Upstream error transparency: 4xx/5xx forwarded verbatim, never wrapped
- No PII in logs or audit values: `TextSpan.value` has `#[serde(skip)]`
- `#![forbid(unsafe_code)]` on all library crates

#### Redaction
- Remove strategy: replaces span with `[REDACTED]`
- Mask strategy: replaces span with entity-type placeholder (e.g. `[EMAIL_ADDRESS]`)
- Hash strategy: SHA-256 hex of original value (for JWT deduplication)
- JSON mutator: in-place redaction preserving JSON structure
- All redaction entity types and field positions logged; values never logged

#### Dashboard
- React SPA pre-built and committed to `crates/revoc-dashboard/ui/dist/`
- Embedded in Rust binary via `include_dir!` — no Node.js required at runtime
- Live feed via Server-Sent Events (`/dashboard/live`)
- REST API: audit events, policy decisions, kill-switch status, reports
- Dashboard auth mode: shared token or none (dev)
- `X-Revoc-Dashboard` header on every response links directly to the trace

#### Configuration
- Complete TOML config schema: `[server]`, `[upstream]`, `[[upstream.providers]]`,
  `[policy]`, `[governance]`, `[kill_switch]`, `[detection]`, `[stream]`,
  `[mcp]`, `[session]`, `[storage]`, `[cache]`, `[telemetry]`, `[auth]`,
  `[dashboard]`, `[webhooks]`
- `revoc.toml` (production) and `revoc.dev.toml` (development/mock) configs
- Environment variable overrides for all secrets
- Config validation CLI subcommand

#### CLI Subcommands
- `serve` — start the proxy
- `migrate` — run database migrations
- `validate-config` — validate config file without starting
- `check-policies` — validate Rego policy files
- `generate-key` — generate API key with label
- `version` — print version info
- `benchmark` — run quick performance smoke test
- `emergency activate/deactivate/status` — kill-switch management

#### Observability
- OpenTelemetry tracing with W3C `traceparent` propagation
- Prometheus metrics on configurable port (default 9090)
- Structured JSON logging (production) and pretty logging (development)
- `X-Revoc-Timing` header on every response for per-request latency breakdown
- Async batched audit writes to SQLite/Postgres (never blocks request path)

#### Database
- SQLite (Tier 1, zero dependencies) and Postgres (Tier 2/3) backends
- Auto-migration on startup
- Tables: `organizations`, `policy_bundles`, `policy_audit_log`, `audit_events`,
  `kill_switch_log`, `users`, `api_keys`
- Audit retention: 90 days default
- `kill_switch_log` write mandatory on every activate/deactivate

#### Admin API (Python/FastAPI)
- Full CRUD for policy bundles with Rego compilation and activation
- Audit query and export endpoints
- User management with RBAC (viewer / operator / admin / superuser)
- Emergency kill-switch endpoints
- Report generation (PDF via WeasyPrint)
- OpenTelemetry instrumentation
- Alembic migrations
- 85%+ test coverage requirement enforced in CI

#### SDKs
- Python SDK (`revoc-sdk`): drop-in `OpenAI` client wrapper, MCP governance helpers
- Node.js SDK (`@revoc-io/sdk`): TypeScript, same API surface as Python SDK

#### Infrastructure
- Single-container Dockerfile: proxy + dashboard + SQLite, zero external deps
- Docker Compose (Tier 2): adds Postgres + Redis
- Docker Compose observability overlay: adds Prometheus + Grafana + Tempo
- Helm chart with production values, HA configuration, OPA sidecar, autoscaling
- GitHub Actions: CI, release, security scan, docs deployment workflows

#### Policies
- Default Rego policies: `main.rego`, `llm_governance.rego`, `mcp_governance.rego`,
  `quota_governance.rego`, `conflict_resolution.rego` with full test coverage
- Compliance profiles: HIPAA, PCI-DSS, GDPR, SOC2, financial-services, internal-dev
- Example policy bundles for each compliance profile

#### Performance Targets (all benchmarked with criterion)
- P95 proxy overhead < 10ms, P99 < 25ms
- Regex detection throughput: >100K req/s (no PII), >50K req/s (3 PII findings)
- Full pipeline (regex + policy + redaction): >40K req/s
- Policy cache hit: >1M ops/s
- Normalization overhead: <0.5ms added latency
- Manifest analysis (10 tools): <1ms

[0.1.0]: https://github.com/revoc-ai/revoc/releases/tag/v0.1.0
