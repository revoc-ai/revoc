//! Config file loading with environment variable overrides.
//!
//! Uses the [`config`] crate: TOML file source first, then environment
//! variables with prefix `REVOC_` and separator `__`.
//!
//! # Example
//! ```no_run
//! let cfg = revoc_config::loader::load(Some("configs/revoc.toml")).unwrap();
//! ```

use revoc_core::RevocError;
use tracing::{debug, info};

use crate::schema::Config;

// ── Public API ────────────────────────────────────────────────────────────────

/// Load configuration from an explicit file path plus environment overrides.
///
/// Environment variables override file values using the `REVOC_` prefix and
/// `__` as the nesting separator:
/// ```bash
/// REVOC_SERVER__PORT=9090  # overrides server.port
/// ```
///
/// Calls [`Config::validate`] before returning.
///
/// # Errors
/// Returns [`RevocError::Configuration`] if the file cannot be parsed, a
/// required value is missing, or validation fails.
pub fn load(path: Option<&str>) -> Result<Config, RevocError> {
    let mut builder = config::Config::builder();

    if let Some(p) = path {
        debug!(path = p, "Loading config file");
        builder = builder.add_source(
            config::File::with_name(p)
                .required(true)
                .format(config::FileFormat::Toml),
        );
    }

    // The config crate lowercases all keys internally. Using prefix "REVOC" with
    // prefix_separator "_" means REVOC_SERVER__PORT → strip "revoc_" →
    // "server__port" → split on "__" → key path server.port.
    builder = builder.add_source(
        config::Environment::with_prefix("REVOC")
            .prefix_separator("_")
            .separator("__")
            .try_parsing(true),
    );

    // `config::Environment` cannot materialize `Vec<T>` fields from indexed
    // env vars (e.g. `REVOC_MCP__TRUSTED_SERVERS__0__ID`) — it merges them
    // into a map keyed by numeric strings ("0", "1", ...), which fails to
    // deserialize into `Vec<TrustedMcpServer>` / `Vec<ProviderConfig>` with
    // "invalid type: map, expected a sequence". Build a small JSON overlay
    // for these two array fields from any matching env vars and layer it on
    // top with the highest priority so indexed env-var configuration of
    // upstream providers and trusted MCP servers works as documented in
    // SPEC.md §13.
    if let Some(overlay) = build_array_overlay() {
        builder = builder.add_source(config::File::from_str(&overlay, config::FileFormat::Json));
    }

    let raw = builder
        .build()
        .map_err(|e| RevocError::Configuration(format!("Config build error: {e}")))?;

    let cfg: Config = raw
        .try_deserialize()
        .map_err(|e| RevocError::Configuration(format!("Config deserialize error: {e}")))?;

    cfg.validate()?;

    info!(
        environment = %cfg.server.environment,
        engine      = %cfg.policy.engine,
        "Configuration loaded and validated"
    );

    Ok(cfg)
}

/// Scan the process environment for indexed array overrides of
/// `upstream.providers` and `mcp.trusted_servers` (e.g.
/// `REVOC_UPSTREAM__PROVIDERS__0__NAME`, `REVOC_MCP__TRUSTED_SERVERS__1__URL`)
/// and build a JSON document containing real `[...]` arrays for any field
/// that has at least one indexed entry.
///
/// Returns `None` if no such env vars are set, so callers can skip adding an
/// empty overlay source.
fn build_array_overlay() -> Option<String> {
    use std::collections::BTreeMap;

    let mut providers: BTreeMap<u32, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();
    let mut servers: BTreeMap<u32, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();

    for (key, value) in std::env::vars() {
        if let Some(rest) = key.strip_prefix("REVOC_UPSTREAM__PROVIDERS__") {
            if let Some((idx, field)) = split_index_field(rest) {
                insert_field(providers.entry(idx).or_default(), field, &value);
            }
        } else if let Some(rest) = key.strip_prefix("REVOC_MCP__TRUSTED_SERVERS__") {
            if let Some((idx, field)) = split_index_field(rest) {
                insert_field(servers.entry(idx).or_default(), field, &value);
            }
        }
    }

    if providers.is_empty() && servers.is_empty() {
        return None;
    }

    let mut root = serde_json::Map::new();

    if !providers.is_empty() {
        let arr: Vec<serde_json::Value> = providers
            .into_values()
            .map(serde_json::Value::Object)
            .collect();
        let mut upstream = serde_json::Map::new();
        upstream.insert("providers".to_owned(), serde_json::Value::Array(arr));
        root.insert("upstream".to_owned(), serde_json::Value::Object(upstream));
    }

    if !servers.is_empty() {
        let arr: Vec<serde_json::Value> = servers
            .into_values()
            .map(serde_json::Value::Object)
            .collect();
        let mut mcp = serde_json::Map::new();
        mcp.insert("trusted_servers".to_owned(), serde_json::Value::Array(arr));
        root.insert("mcp".to_owned(), serde_json::Value::Object(mcp));
    }

    serde_json::to_string(&serde_json::Value::Object(root)).ok()
}

/// Split `"0__FIELD_NAME"` into `(0, "field_name")`. Field names are
/// lowercased to match the struct's `serde` field names.
fn split_index_field(rest: &str) -> Option<(u32, String)> {
    let (idx_str, field) = rest.split_once("__")?;
    let idx = idx_str.parse::<u32>().ok()?;
    Some((idx, field.to_lowercase()))
}

/// Insert a raw env-var string into a JSON object, coercing `"true"`/`"false"`
/// to booleans since `config::File::from_str` with JSON does not do the
/// `try_parsing` string coercion that `config::Environment` does.
fn insert_field(obj: &mut serde_json::Map<String, serde_json::Value>, field: String, value: &str) {
    let json_value = match value {
        "true" => serde_json::Value::Bool(true),
        "false" => serde_json::Value::Bool(false),
        _ => serde_json::Value::String(value.to_owned()),
    };
    obj.insert(field, json_value);
}

/// Load configuration by searching standard locations, falling back to compiled defaults.
///
/// Search order:
/// 1. `REVOC_CONFIG` environment variable (if set)
/// 2. `./revoc.toml` (relative to current working directory)
/// 3. Compiled defaults (all fields at their `default_xxx` values) plus env overrides
///
/// # Errors
/// Returns [`RevocError::Configuration`] if a found file fails to parse or
/// validation fails.
pub fn load_or_default() -> Result<Config, RevocError> {
    // 1. Explicit path via REVOC_CONFIG env var
    if let Ok(env_path) = std::env::var("REVOC_CONFIG") {
        debug!(path = %env_path, "Loading config from REVOC_CONFIG");
        return load(Some(&env_path));
    }

    // 2. ./revoc.toml in current directory
    if std::path::Path::new("revoc.toml").exists() {
        debug!("Loading config from ./revoc.toml");
        return load(Some("revoc.toml"));
    }

    // 3. Compiled defaults + env overrides only
    debug!("No config file found; using compiled defaults with env overrides");
    load(None)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // Path to configs/ relative to this crate's manifest directory
    fn dev_config_path() -> String {
        format!(
            "{}/../../configs/revoc.dev.toml",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn test_load_dev_config() {
        let cfg = load(Some(&dev_config_path())).expect("dev config should load");
        assert_eq!(cfg.server.environment, "development");
        assert!(cfg.upstream.mock_mode);
        assert_eq!(cfg.auth.mode, "none");
    }

    #[test]
    fn test_validate_rejects_fail_open() {
        let mut cfg = Config::default();
        cfg.policy.fail_open = true;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("fail_open"));
    }

    #[test]
    fn test_validate_rejects_none_auth_in_production() {
        let mut cfg = Config::default();
        cfg.server.environment = "production".into();
        cfg.auth.mode = "none".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("auth.mode"));
    }

    #[test]
    fn test_validate_rejects_multiple_defaults() {
        let mut cfg = Config::default();
        // Give both providers default = true
        let mut p2 = cfg.upstream.providers[0].clone();
        p2.name = "anthropic".into();
        p2.default = true;
        cfg.upstream.providers.push(p2);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("default=true"));
    }

    #[test]
    fn test_validate_rejects_no_default_provider() {
        let mut cfg = Config::default();
        cfg.upstream.providers[0].default = false;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("default=true"));
    }

    #[test]
    fn test_validate_rejects_empty_opa_url_sidecar() {
        let mut cfg = Config::default();
        cfg.policy.engine = "sidecar".into();
        cfg.policy.opa_url = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("opa_url"));
    }

    #[test]
    fn test_governance_max_depth_default() {
        let cfg = Config::default();
        assert_eq!(cfg.governance.max_depth, 10);
    }

    #[test]
    fn test_kill_switch_enabled_default() {
        let cfg = Config::default();
        assert!(cfg.kill_switch.enabled);
    }

    #[test]
    fn test_normalize_default_true() {
        let cfg = Config::default();
        assert!(cfg.detection.normalize_before_scan);
    }

    #[test]
    fn test_analyze_manifests_default_true() {
        let cfg = Config::default();
        assert!(cfg.mcp.analyze_tool_manifests);
    }

    #[test]
    fn test_is_shadow_mode() {
        let mut policy = crate::schema::PolicyConfig::default();
        assert!(!policy.is_shadow_mode());
        policy.enforcement_mode = "shadow".into();
        assert!(policy.is_shadow_mode());
    }

    #[test]
    fn test_dashboard_disabled() {
        let mut server = crate::schema::ServerConfig::default();
        assert!(server.is_dashboard_enabled());
        server.dashboard_port = 0;
        assert!(!server.is_dashboard_enabled());
    }

    #[test]
    fn test_api_key_from_env() {
        // Unique name keeps this test isolated from parallel runs.
        let var = "REVOC_TEST_API_KEY_FROM_ENV_LOADER_12345";
        // set_var / remove_var are safe functions in Rust 1.80 + edition 2021.
        std::env::set_var(var, "test-key-value");

        let provider = crate::schema::ProviderConfig {
            name: "test".into(),
            base_url: "https://example.com".into(),
            api_key_env: var.into(),
            api_key_file: String::new(),
            format: "openai".into(),
            default: false,
        };

        let key = provider.api_key().expect("should read from env");
        assert_eq!(key, "test-key-value");

        std::env::remove_var(var);
    }

    #[test]
    fn test_api_key_from_file() {
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        tmp.write_all(b"file-api-key\n").expect("write");
        let path = tmp.path().to_str().unwrap().to_string();

        let provider = crate::schema::ProviderConfig {
            name: "test".into(),
            base_url: "https://example.com".into(),
            api_key_env: String::new(),
            api_key_file: path,
            format: "openai".into(),
            default: false,
        };

        let key = provider.api_key().expect("should read from file");
        assert_eq!(key, "file-api-key");
    }

    #[test]
    fn test_env_var_override() {
        // set_var / remove_var are safe functions in Rust 1.80 + edition 2021.
        std::env::set_var("REVOC_SERVER__PORT", "9191");

        // Build config from defaults + env only (no file).
        let cfg = load(None).expect("load with env override");
        assert_eq!(cfg.server.port, 9191);

        std::env::remove_var("REVOC_SERVER__PORT");
    }

    #[test]
    fn test_policy_opa_eval_url() {
        let mut policy = crate::schema::PolicyConfig::default();
        policy.opa_url = "http://opa:8181".into();
        assert_eq!(
            policy.opa_eval_url(),
            "http://opa:8181/v1/data/revoc/governance/main/decision"
        );
        // Trailing slash is stripped
        policy.opa_url = "http://opa:8181/".into();
        assert_eq!(
            policy.opa_eval_url(),
            "http://opa:8181/v1/data/revoc/governance/main/decision"
        );
    }

    #[test]
    fn test_validate_rejects_invalid_depth() {
        let mut cfg = Config::default();
        cfg.governance.max_depth = 0;
        assert!(cfg.validate().is_err());

        cfg.governance.max_depth = 21;
        assert!(cfg.validate().is_err());

        cfg.governance.max_depth = 10;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_invalid_sample_rate() {
        let mut cfg = Config::default();
        cfg.telemetry.sample_rate = 1.1;
        assert!(cfg.validate().is_err());

        cfg.telemetry.sample_rate = -0.1;
        assert!(cfg.validate().is_err());

        cfg.telemetry.sample_rate = 0.5;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_fail_open_default_false() {
        let cfg = Config::default();
        assert!(!cfg.policy.fail_open);
    }
}
