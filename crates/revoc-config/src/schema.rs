//! Complete REVOC configuration schema.
//!
//! Every struct corresponds to a TOML section from SPEC.md Section 13.
//! All fields carry `#[serde(default = "default_xxx")]` functions so the
//! crate compiles and validates with zero config files present.

use serde::{Deserialize, Serialize};

use revoc_core::RevocError;

// ── Top-level ─────────────────────────────────────────────────────────────────

/// Root configuration object. Deserialised from `revoc.toml` plus env overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// HTTP server settings.
    #[serde(default)]
    pub server: ServerConfig,

    /// Upstream AI provider routing.
    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// Policy engine settings.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Governance depth and recursion limits.
    #[serde(default)]
    pub governance: GovernanceConfig,

    /// Emergency kill-switch subsystem.
    #[serde(default)]
    pub kill_switch: KillSwitchConfig,

    /// Detection engine configuration.
    #[serde(default)]
    pub detection: DetectionConfig,

    /// Streaming response configuration.
    #[serde(default)]
    pub stream: StreamConfig,

    /// MCP protocol governance settings.
    #[serde(default)]
    pub mcp: McpConfig,

    /// Session state tracking.
    #[serde(default)]
    pub session: SessionConfig,

    /// Audit event and policy bundle storage.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Decision cache backend.
    #[serde(default)]
    pub cache: CacheConfig,

    /// OpenTelemetry and Prometheus telemetry.
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// Proxy authentication mode.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Embedded dashboard settings.
    #[serde(default)]
    pub dashboard: DashboardConfig,

    /// Outbound webhook delivery.
    #[serde(default)]
    pub webhooks: WebhooksConfig,
}

impl Config {
    /// Returns `true` when this is a production deployment.
    pub fn is_production(&self) -> bool {
        self.server.environment == "production"
    }

    /// Returns `true` when this is a development deployment.
    pub fn is_development(&self) -> bool {
        self.server.environment == "development"
    }

    /// Validate all security invariants and required field combinations.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] on any invariant violation.
    pub fn validate(&self) -> Result<(), RevocError> {
        // fail_open must never be true (SPEC.md §23 Rule 4, Principle 7)
        if self.policy.fail_open {
            return Err(RevocError::Configuration(
                "fail_open=true is not permitted. REVOC must always fail closed.".into(),
            ));
        }

        // No-auth mode is forbidden in production (SPEC.md §13 auth.mode)
        if self.is_production() && self.auth.mode == "none" {
            return Err(RevocError::Configuration(
                "auth.mode=\"none\" is not permitted in production environment.".into(),
            ));
        }

        // Exactly one provider must be the default
        let default_count = self.upstream.providers.iter().filter(|p| p.default).count();
        match default_count {
            0 => {
                return Err(RevocError::Configuration(
                    "No upstream provider has default=true. Exactly one is required.".into(),
                ))
            }
            2.. => {
                return Err(RevocError::Configuration(format!(
                    "{default_count} upstream providers have default=true. \
                     Exactly one is required."
                )))
            }
            _ => {}
        }

        // Governance depth must be sane
        if self.governance.max_depth == 0 || self.governance.max_depth > 20 {
            return Err(RevocError::Configuration(format!(
                "governance.max_depth={} is out of range [1, 20].",
                self.governance.max_depth
            )));
        }

        // Sample rate must be in [0.0, 1.0]
        if !(0.0..=1.0).contains(&self.telemetry.sample_rate) {
            return Err(RevocError::Configuration(format!(
                "telemetry.sample_rate={} is out of range [0.0, 1.0].",
                self.telemetry.sample_rate
            )));
        }

        // OPA sidecar requires a non-empty URL
        if self.policy.engine == "sidecar" && self.policy.opa_url.trim().is_empty() {
            return Err(RevocError::Configuration(
                "policy.engine=\"sidecar\" requires a non-empty policy.opa_url.".into(),
            ));
        }

        // Security warnings for disabled mitigations in production
        if self.is_production() && !self.detection.normalize_before_scan {
            tracing::warn!(
                "Security warning: normalization disabled (detection.normalize_before_scan=false). \
                 This allows Unicode evasion attacks (SPEC.md Principle 5)."
            );
        }
        if self.is_production() && !self.mcp.analyze_tool_manifests {
            tracing::warn!(
                "Security warning: manifest analysis disabled (mcp.analyze_tool_manifests=false). \
                 This allows schema-poisoning attacks (SPEC.md Principle 13)."
            );
        }

        Ok(())
    }
}

// ── [server] ──────────────────────────────────────────────────────────────────

fn default_host() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    8080
}
fn default_dashboard_port() -> u16 {
    3000
}
fn default_environment() -> String {
    "production".into()
}
fn default_max_request_body_bytes() -> usize {
    10_485_760
}
fn default_max_response_body_bytes() -> usize {
    52_428_800
}
fn default_shutdown_timeout_secs() -> u64 {
    120
}
fn default_http2_enabled() -> bool {
    true
}
fn default_dashboard_base_url() -> String {
    "http://localhost:3000".into()
}

/// HTTP listener and process-level settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address (default `"0.0.0.0"`).
    #[serde(default = "default_host")]
    pub host: String,

    /// Proxy listener port (default `8080`).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Dashboard port; `0` disables the dashboard (default `3000`).
    #[serde(default = "default_dashboard_port")]
    pub dashboard_port: u16,

    /// Deployment environment label (default `"production"`).
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Maximum request body size in bytes (default 10 MB).
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,

    /// Maximum response body size in bytes (default 50 MB).
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,

    /// Graceful shutdown timeout in seconds (default `120`).
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,

    /// Enable HTTP/2 on the listener (default `true`).
    #[serde(default = "default_http2_enabled")]
    pub http2_enabled: bool,

    /// Base URL of the dashboard, used to build `X-Revoc-Dashboard` values.
    #[serde(default = "default_dashboard_base_url")]
    pub dashboard_base_url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            dashboard_port: default_dashboard_port(),
            environment: default_environment(),
            max_request_body_bytes: default_max_request_body_bytes(),
            max_response_body_bytes: default_max_response_body_bytes(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            http2_enabled: default_http2_enabled(),
            dashboard_base_url: default_dashboard_base_url(),
        }
    }
}

impl ServerConfig {
    /// Returns `true` when the dashboard is enabled (`dashboard_port > 0`).
    pub fn is_dashboard_enabled(&self) -> bool {
        self.dashboard_port > 0
    }
}

// ── [upstream] ────────────────────────────────────────────────────────────────

fn default_timeout_ms() -> u64 {
    120_000
}
fn default_connect_timeout_ms() -> u64 {
    5_000
}
fn default_max_idle_connections_per_host() -> usize {
    100
}
fn default_mock_response() -> String {
    "Mock response. Governance pipeline ran.".into()
}
fn default_providers() -> Vec<ProviderConfig> {
    vec![ProviderConfig {
        name: "openai".into(),
        base_url: "https://api.openai.com".into(),
        api_key_env: "OPENAI_API_KEY".into(),
        api_key_file: String::new(),
        format: "openai".into(),
        default: true,
    }]
}

/// Upstream AI provider routing and HTTP client settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// End-to-end request timeout in milliseconds (default `120_000`).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// TCP connection timeout in milliseconds (default `5_000`).
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    /// Maximum idle keep-alive connections per upstream host (default `100`).
    #[serde(default = "default_max_idle_connections_per_host")]
    pub max_idle_connections_per_host: usize,

    /// When `true`, return a synthetic response without calling upstream (default `false`).
    #[serde(default)]
    pub mock_mode: bool,

    /// Synthetic response body used when `mock_mode = true`.
    #[serde(default = "default_mock_response")]
    pub mock_response: String,

    /// One or more upstream providers; at least one must have `default = true`.
    #[serde(default = "default_providers")]
    pub providers: Vec<ProviderConfig>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            connect_timeout_ms: default_connect_timeout_ms(),
            max_idle_connections_per_host: default_max_idle_connections_per_host(),
            mock_mode: false,
            mock_response: default_mock_response(),
            providers: default_providers(),
        }
    }
}

/// A single upstream AI provider definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Logical name (e.g. `"openai"`, `"anthropic"`).
    pub name: String,

    /// Base URL (no path segments), e.g. `"https://api.openai.com"`.
    pub base_url: String,

    /// Environment variable containing the API key.
    #[serde(default)]
    pub api_key_env: String,

    /// Path to a file containing the API key (takes precedence over `api_key_env`).
    #[serde(default)]
    pub api_key_file: String,

    /// Wire format: `"openai"` | `"anthropic"` | `"azure"`.
    #[serde(default = "default_format")]
    pub format: String,

    /// Whether this provider receives requests that do not specify a provider.
    #[serde(default)]
    pub default: bool,
}

fn default_format() -> String {
    "openai".into()
}

impl ProviderConfig {
    /// Read the API key from file (preferred) or environment variable.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] if neither source yields a value.
    pub fn api_key(&self) -> Result<String, RevocError> {
        if !self.api_key_file.is_empty() {
            return std::fs::read_to_string(&self.api_key_file)
                .map(|s| s.trim().to_string())
                .map_err(|e| {
                    RevocError::Configuration(format!(
                        "Failed to read API key file '{}' for provider '{}': {e}",
                        self.api_key_file, self.name
                    ))
                });
        }
        std::env::var(&self.api_key_env).map_err(|_| {
            RevocError::Configuration(format!(
                "Environment variable '{}' is not set for provider '{}'.",
                self.api_key_env, self.name
            ))
        })
    }
}

// ── [policy] ──────────────────────────────────────────────────────────────────

fn default_policy_engine() -> String {
    "native".into()
}
fn default_enforcement_mode() -> String {
    "enforce".into()
}
fn default_opa_url() -> String {
    "http://localhost:8181".into()
}
fn default_opa_timeout_ms() -> u64 {
    2_000
}
fn default_decision_cache_ttl_secs() -> u64 {
    60
}
fn default_decision_cache_max_entries() -> usize {
    10_000
}
fn default_conflict_resolution() -> String {
    "tier_based".into()
}

/// Policy engine selection and enforcement settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy engine backend: `"native"` | `"sidecar"` | `"wasm"` (default `"native"`).
    #[serde(default = "default_policy_engine")]
    pub engine: String,

    /// Enforcement mode: `"enforce"` | `"shadow"` (default `"enforce"`).
    #[serde(default = "default_enforcement_mode")]
    pub enforcement_mode: String,

    /// OPA HTTP server URL (used when `engine = "sidecar"`).
    #[serde(default = "default_opa_url")]
    pub opa_url: String,

    /// OPA HTTP evaluation timeout in milliseconds (default `2_000`).
    #[serde(default = "default_opa_timeout_ms")]
    pub opa_timeout_ms: u64,

    /// Path to compiled OPA WASM bundle (used when `engine = "wasm"`).
    #[serde(default)]
    pub wasm_bundle_path: String,

    /// **CRITICAL**: must always be `false` in production (SPEC.md Principle 7).
    #[serde(default)]
    pub fail_open: bool,

    /// Decision cache TTL in seconds (default `60`).
    #[serde(default = "default_decision_cache_ttl_secs")]
    pub decision_cache_ttl_secs: u64,

    /// Maximum entries in the decision LRU cache (default `10_000`).
    #[serde(default = "default_decision_cache_max_entries")]
    pub decision_cache_max_entries: usize,

    /// Conflict resolution strategy: `"tier_based"` | `"strict_deny"`.
    #[serde(default = "default_conflict_resolution")]
    pub conflict_resolution: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            engine: default_policy_engine(),
            enforcement_mode: default_enforcement_mode(),
            opa_url: default_opa_url(),
            opa_timeout_ms: default_opa_timeout_ms(),
            wasm_bundle_path: String::new(),
            fail_open: false,
            decision_cache_ttl_secs: default_decision_cache_ttl_secs(),
            decision_cache_max_entries: default_decision_cache_max_entries(),
            conflict_resolution: default_conflict_resolution(),
        }
    }
}

impl PolicyConfig {
    /// Returns the full OPA v1 evaluation URL for the main decision endpoint.
    pub fn opa_eval_url(&self) -> String {
        format!(
            "{}/v1/data/revoc/governance/main/decision",
            self.opa_url.trim_end_matches('/')
        )
    }

    /// Returns `true` when shadow (observe-only) mode is configured.
    pub fn is_shadow_mode(&self) -> bool {
        self.enforcement_mode == "shadow"
    }
}

// ── [governance] ──────────────────────────────────────────────────────────────

fn default_max_depth() -> u8 {
    10
}
fn default_depth_exceeded_action() -> String {
    "block".into()
}

/// Governance recursion depth limiting (SPEC.md §9 D9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Maximum governance nesting depth before returning HTTP 503 (default `10`).
    ///
    /// Do not increase above 10 (SPEC.md Principle 6).
    #[serde(default = "default_max_depth")]
    pub max_depth: u8,

    /// Action when depth is exceeded: `"block"` | `"allow"` (default `"block"`).
    #[serde(default = "default_depth_exceeded_action")]
    pub depth_exceeded_action: String,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            max_depth: default_max_depth(),
            depth_exceeded_action: default_depth_exceeded_action(),
        }
    }
}

// ── [kill_switch] ─────────────────────────────────────────────────────────────

fn default_kill_switch_enabled() -> bool {
    true
}
fn default_redis_channel() -> String {
    "revoc:kill_switch".into()
}
fn default_on_redis_unavailable() -> String {
    "local_only".into()
}

/// Emergency kill-switch subsystem (SPEC.md §9 D11).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchConfig {
    /// Enable the kill-switch subsystem (default `true`).
    #[serde(default = "default_kill_switch_enabled")]
    pub enabled: bool,

    /// Redis pub/sub channel for cross-instance propagation (default `"revoc:kill_switch"`).
    #[serde(default = "default_redis_channel")]
    pub redis_channel: String,

    /// Behaviour when Redis is unavailable: `"local_only"` | `"fail"`.
    #[serde(default = "default_on_redis_unavailable")]
    pub on_redis_unavailable: String,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        Self {
            enabled: default_kill_switch_enabled(),
            redis_channel: default_redis_channel(),
            on_redis_unavailable: default_on_redis_unavailable(),
        }
    }
}

// ── [detection] ───────────────────────────────────────────────────────────────

fn default_normalize_before_scan() -> bool {
    true
}
fn default_regex_enabled() -> bool {
    true
}
fn default_onnx_model_path() -> String {
    "models/bert-base-ner.onnx".into()
}
fn default_onnx_tokenizer_path() -> String {
    "models/bert-base-ner-tokenizer.json".into()
}
fn default_decode_base64_args() -> bool {
    true
}
fn default_decode_url_encoded_args() -> bool {
    true
}

/// Detection engine configuration (all tiers).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// **CRITICAL**: NFKC + zero-width + BIDI normalization before every regex pass.
    ///
    /// Must remain `true` in production (SPEC.md Principle 5, §9 D8).
    #[serde(default = "default_normalize_before_scan")]
    pub normalize_before_scan: bool,

    /// Enable the Rust regex detection engine (default `true`).
    #[serde(default = "default_regex_enabled")]
    pub regex_enabled: bool,

    /// Enable ONNX NER model detection (requires model file, default `false`).
    #[serde(default)]
    pub onnx_enabled: bool,

    /// Path to the ONNX NER model file.
    #[serde(default = "default_onnx_model_path")]
    pub onnx_model_path: String,

    /// Path to the tokenizer config for the ONNX model.
    #[serde(default = "default_onnx_tokenizer_path")]
    pub onnx_tokenizer_path: String,

    /// Enable Microsoft Presidio enricher (default `false`).
    #[serde(default)]
    pub presidio_enabled: bool,

    /// URL of the Presidio analyzer service (used when `presidio_enabled = true`).
    #[serde(default)]
    pub presidio_url: String,

    /// Attempt to base64-decode argument values before scanning (default `true`).
    #[serde(default = "default_decode_base64_args")]
    pub decode_base64_args: bool,

    /// Attempt to URL-decode argument values before scanning (default `true`).
    #[serde(default = "default_decode_url_encoded_args")]
    pub decode_url_encoded_args: bool,

    /// HTTP plugin detectors (community extensions).
    #[serde(default)]
    pub http_plugins: Vec<HttpPluginConfig>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            normalize_before_scan: default_normalize_before_scan(),
            regex_enabled: default_regex_enabled(),
            onnx_enabled: false,
            onnx_model_path: default_onnx_model_path(),
            onnx_tokenizer_path: default_onnx_tokenizer_path(),
            presidio_enabled: false,
            presidio_url: String::new(),
            decode_base64_args: default_decode_base64_args(),
            decode_url_encoded_args: default_decode_url_encoded_args(),
            http_plugins: vec![],
        }
    }
}

/// Configuration for a single HTTP-based community detection plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPluginConfig {
    /// Unique plugin name (used in tracing and findings).
    pub name: String,

    /// HTTP endpoint of the plugin analyzer.
    pub url: String,

    /// Request timeout in milliseconds (default `500`).
    #[serde(default = "default_http_plugin_timeout_ms")]
    pub timeout_ms: u64,

    /// Whether this plugin is active (default `true`).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_http_plugin_timeout_ms() -> u64 {
    500
}
fn default_true() -> bool {
    true
}

// ── [stream] ──────────────────────────────────────────────────────────────────

fn default_sliding_window_size() -> usize {
    256
}
fn default_tool_call_accumulate() -> bool {
    true
}

/// Streaming SSE response governance settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Buffer entire response before governance when `true` (default `false`).
    ///
    /// Set `true` for HIPAA/PCI-DSS full-buffer compliance mode.
    #[serde(default)]
    pub buffer_output: bool,

    /// Sliding window size in bytes for the streaming scanner (default `256`).
    #[serde(default = "default_sliding_window_size")]
    pub sliding_window_size: usize,

    /// Accumulate tool call arguments across SSE chunks and run governance on
    /// `finish_reason = "tool_calls"` (default `true`).
    #[serde(default = "default_tool_call_accumulate")]
    pub tool_call_accumulate: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            buffer_output: false,
            sliding_window_size: default_sliding_window_size(),
            tool_call_accumulate: default_tool_call_accumulate(),
        }
    }
}

// ── [mcp] ─────────────────────────────────────────────────────────────────────

fn default_analyze_tool_manifests() -> bool {
    true
}
fn default_dangerous_tool_action() -> String {
    "audit".into()
}

/// MCP protocol governance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// **CRITICAL**: scan `tools/list` responses for dangerous params/descriptions.
    ///
    /// Must remain `true` in production (SPEC.md Principle 13, §9 D10).
    #[serde(default = "default_analyze_tool_manifests")]
    pub analyze_tool_manifests: bool,

    /// Remove dangerous tools from `tools/list` before forwarding (default `false`).
    #[serde(default)]
    pub auto_disable_dangerous_tools: bool,

    /// Action for tools with High manifest findings: `"audit"` | `"block"` | `"allow"`.
    #[serde(default = "default_dangerous_tool_action")]
    pub dangerous_tool_action: String,

    /// Allow-listed MCP servers that may receive tool calls.
    #[serde(default)]
    pub trusted_servers: Vec<TrustedMcpServer>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            analyze_tool_manifests: default_analyze_tool_manifests(),
            auto_disable_dangerous_tools: false,
            dangerous_tool_action: default_dangerous_tool_action(),
            trusted_servers: vec![],
        }
    }
}

/// A trusted MCP server entry in the allow-list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedMcpServer {
    /// Logical identifier (e.g. `"my-database-tool"`).
    pub id: String,

    /// Base URL of the MCP server.
    pub url: String,

    /// Whether to verify the server's TLS certificate (default `true`).
    #[serde(default = "default_true")]
    pub tls_verify: bool,
}

// ── [session] ─────────────────────────────────────────────────────────────────

fn default_session_enabled() -> bool {
    true
}
fn default_session_ttl_secs() -> u64 {
    3_600
}
fn default_max_rows_before_alert() -> u64 {
    500
}

/// Per-session governance state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Enable session state tracking (default `true`).
    #[serde(default = "default_session_enabled")]
    pub enabled: bool,

    /// Session TTL in seconds (default `3600`).
    #[serde(default = "default_session_ttl_secs")]
    pub ttl_secs: u64,

    /// Row count threshold before triggering a `SessionAnomaly` finding (default `500`).
    #[serde(default = "default_max_rows_before_alert")]
    pub max_rows_before_alert: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: default_session_enabled(),
            ttl_secs: default_session_ttl_secs(),
            max_rows_before_alert: default_max_rows_before_alert(),
        }
    }
}

// ── [storage] ─────────────────────────────────────────────────────────────────

fn default_storage_backend() -> String {
    "sqlite".into()
}
fn default_sqlite_path() -> String {
    "revoc-audit.db".into()
}
fn default_postgres_url_env() -> String {
    "DATABASE_URL".into()
}
fn default_pool_size() -> u32 {
    20
}
fn default_migrations_auto_run() -> bool {
    true
}

/// Audit event and policy bundle storage settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend: `"sqlite"` | `"postgres"` (default `"sqlite"`).
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// Path to the `SQLite` database file (default `"revoc-audit.db"`).
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,

    /// Environment variable containing the Postgres connection URL.
    #[serde(default = "default_postgres_url_env")]
    pub postgres_url_env: String,

    /// Database connection pool size (default `20`).
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// Run pending migrations automatically on startup (default `true`).
    #[serde(default = "default_migrations_auto_run")]
    pub migrations_auto_run: bool,

    /// Audit write settings (batch size, interval, retention).
    #[serde(flatten)]
    pub audit: AuditConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            sqlite_path: default_sqlite_path(),
            postgres_url_env: default_postgres_url_env(),
            pool_size: default_pool_size(),
            migrations_auto_run: default_migrations_auto_run(),
            audit: AuditConfig::default(),
        }
    }
}

fn default_audit_write_batch_size() -> usize {
    100
}
fn default_audit_write_interval_ms() -> u64 {
    100
}
fn default_audit_retention_days() -> u32 {
    90
}

/// Audit event write and retention settings (flattened into [`StorageConfig`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Events to accumulate before flushing to the database (default `100`).
    #[serde(default = "default_audit_write_batch_size")]
    pub audit_write_batch_size: usize,

    /// Maximum hold time in milliseconds before flushing (default `100`).
    #[serde(default = "default_audit_write_interval_ms")]
    pub audit_write_interval_ms: u64,

    /// Audit event retention period in days (default `90`).
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            audit_write_batch_size: default_audit_write_batch_size(),
            audit_write_interval_ms: default_audit_write_interval_ms(),
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

// ── [cache] ───────────────────────────────────────────────────────────────────

fn default_cache_backend() -> String {
    "memory".into()
}
fn default_redis_url_env() -> String {
    "REDIS_URL".into()
}

/// Policy decision cache backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache backend: `"memory"` | `"redis"` (default `"memory"`).
    #[serde(default = "default_cache_backend")]
    pub backend: String,

    /// Environment variable containing the Redis connection URL.
    #[serde(default = "default_redis_url_env")]
    pub redis_url_env: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: default_cache_backend(),
            redis_url_env: default_redis_url_env(),
        }
    }
}

// ── [telemetry] ───────────────────────────────────────────────────────────────

fn default_service_name() -> String {
    "revoc-proxy".into()
}
fn default_service_version() -> String {
    "1.0.0".into()
}
fn default_sample_rate() -> f64 {
    1.0
}
fn default_prometheus_port() -> u16 {
    9090
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

/// OpenTelemetry tracing, Prometheus metrics, and structured logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// gRPC `OTel` collector endpoint (empty = disabled).
    #[serde(default)]
    pub otlp_endpoint: String,

    /// Service name reported in `OTel` spans and Prometheus labels.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Service version reported in `OTel` resource attributes.
    #[serde(default = "default_service_version")]
    pub service_version: String,

    /// Trace sampling rate in `[0.0, 1.0]` (default `1.0`).
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Port for the Prometheus `/metrics` scrape endpoint (default `9090`).
    #[serde(default = "default_prometheus_port")]
    pub prometheus_port: u16,

    /// Minimum log level: `"trace"` | `"debug"` | `"info"` | `"warn"` | `"error"`.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log format: `"json"` | `"pretty"` (default `"json"`).
    #[serde(default = "default_log_format")]
    pub log_format: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: String::new(),
            service_name: default_service_name(),
            service_version: default_service_version(),
            sample_rate: default_sample_rate(),
            prometheus_port: default_prometheus_port(),
            log_level: default_log_level(),
            log_format: default_log_format(),
        }
    }
}

// ── [auth] ────────────────────────────────────────────────────────────────────

fn default_auth_mode() -> String {
    "apikey".into()
}
fn default_jwt_secret_env() -> String {
    "REVOC_JWT_SECRET".into()
}
fn default_api_keys_env() -> String {
    "REVOC_API_KEYS".into()
}
fn default_admin_key() -> String {
    "dev-admin-key".into()
}

/// Proxy authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication mode: `"apikey"` | `"jwt"` | `"none"` (default `"apikey"`).
    ///
    /// `"none"` is forbidden in production.
    #[serde(default = "default_auth_mode")]
    pub mode: String,

    /// Environment variable containing the JWT signing secret.
    #[serde(default = "default_jwt_secret_env")]
    pub jwt_secret_env: String,

    /// Environment variable containing comma-separated API keys.
    #[serde(default = "default_api_keys_env")]
    pub api_keys_env: String,

    /// Path to a file containing one API key per line (takes precedence).
    #[serde(default)]
    pub api_keys_file: String,

    /// Admin key for the internal emergency/kill-switch API (port 8081),
    /// compared via constant-time equality against the `X-Admin-Key` header.
    ///
    /// Defaults to `"dev-admin-key"` so the single-container smoke test
    /// (`auth.mode = "none"`) and Tier-1 quickstart work out of the box.
    /// Production deployments MUST override this — e.g. via
    /// `REVOC_AUTH__ADMIN_KEY` — with a strong, randomly generated secret.
    #[serde(default = "default_admin_key")]
    pub admin_key: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            jwt_secret_env: default_jwt_secret_env(),
            api_keys_env: default_api_keys_env(),
            api_keys_file: String::new(),
            admin_key: default_admin_key(),
        }
    }
}

// ── [dashboard] ───────────────────────────────────────────────────────────────

fn default_dashboard_auth_mode() -> String {
    "shared".into()
}
fn default_max_sse_connections() -> usize {
    100
}

/// Embedded React dashboard settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Dashboard auth mode: `"shared"` | `"none"` (default `"shared"`).
    #[serde(default = "default_dashboard_auth_mode")]
    pub auth_mode: String,

    /// Maximum concurrent SSE live-feed connections (default `100`).
    #[serde(default = "default_max_sse_connections")]
    pub max_sse_connections: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            auth_mode: default_dashboard_auth_mode(),
            max_sse_connections: default_max_sse_connections(),
        }
    }
}

// ── [webhooks] ────────────────────────────────────────────────────────────────

/// Outbound webhook delivery settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhooksConfig {
    /// Enable webhook delivery (default `false`).
    #[serde(default)]
    pub enabled: bool,

    /// Webhook endpoint definitions.
    #[serde(default)]
    pub endpoints: Vec<WebhookEndpoint>,
}

/// A single webhook delivery target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// HTTPS URL to deliver governance events to.
    pub url: String,

    /// Event types to deliver (e.g. `["block", "quota_exceeded"]`).
    #[serde(default)]
    pub events: Vec<String>,

    /// Minimum finding severity to deliver: `"info"` | `"low"` | `"medium"` | `"high"` | `"critical"`.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Minimum minutes between deliveries per rule (default `5`).
    #[serde(default = "default_cooldown_minutes")]
    pub cooldown_minutes: u32,
}

fn default_min_severity() -> String {
    "high".into()
}
fn default_cooldown_minutes() -> u32 {
    5
}
