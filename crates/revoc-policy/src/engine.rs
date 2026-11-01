//! Top-level policy engine dispatcher.
//!
//! Selects the backend from `cfg.policy.engine` ("native" | "sidecar" | "wasm")
//! and dispatches [`PolicyEngine`] calls to the appropriate implementation.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use revoc_config::Config;
use revoc_core::{
    EnforcementMode, PolicyDecision, PolicyEngine, PolicyEngineMode, PolicyInput, RevocError,
};
use revoc_telemetry::RevocMetrics;

use crate::{
    cache::DecisionCache, native::NativePolicyEngine, sidecar::SidecarPolicyEngine,
    wasm::WasmPolicyEngine,
};

/// Unified policy engine that dispatches to the configured backend.
pub enum RevocPolicyEngine {
    /// Pure-Rust native engine (Tier 1/2 default).
    Native(Arc<NativePolicyEngine>),
    /// OPA HTTP sidecar engine (Tier 3).
    Sidecar(Arc<SidecarPolicyEngine>),
    /// OPA WASM engine (Tier 3 alternative).
    Wasm(Arc<WasmPolicyEngine>),
}

impl RevocPolicyEngine {
    /// Build the configured policy engine from a full [`Config`].
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] for unknown `engine` values.
    pub fn new(cfg: &Config, _metrics: &'static RevocMetrics) -> Result<Self, RevocError> {
        let enforcement_mode = if cfg.policy.enforcement_mode == "shadow" {
            EnforcementMode::Shadow
        } else {
            EnforcementMode::Enforce
        };

        let cache = Arc::new(DecisionCache::new(
            Duration::from_secs(cfg.policy.decision_cache_ttl_secs),
            cfg.policy.decision_cache_max_entries,
        ));

        let engine = match cfg.policy.engine.as_str() {
            "native" | "" => RevocPolicyEngine::Native(Arc::new(NativePolicyEngine::new(
                cache,
                enforcement_mode,
            ))),

            "sidecar" => {
                let opa_url = cfg.policy.opa_eval_url();
                RevocPolicyEngine::Sidecar(Arc::new(SidecarPolicyEngine::new(
                    opa_url,
                    cfg.policy.fail_open,
                    Duration::from_millis(cfg.policy.opa_timeout_ms),
                    enforcement_mode,
                    cache,
                )))
            }

            "wasm" => RevocPolicyEngine::Wasm(Arc::new(WasmPolicyEngine::new(
                &cfg.policy.wasm_bundle_path,
                cache,
                enforcement_mode,
                cfg.policy.fail_open,
            )?)),

            other => {
                return Err(RevocError::Configuration(format!(
                    "Unknown policy engine: '{other}'. Valid values: native | sidecar | wasm"
                )))
            }
        };

        Ok(engine)
    }

    /// Invalidate the decision cache across all instances.
    ///
    /// Call this after a policy bundle update to force re-evaluation.
    pub async fn reload_on_notification(&self) {
        let _ = self.reload().await;
    }
}

#[async_trait]
impl PolicyEngine for RevocPolicyEngine {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, RevocError> {
        match self {
            Self::Native(e) => e.evaluate(input).await,
            Self::Sidecar(e) => e.evaluate(input).await,
            Self::Wasm(e) => e.evaluate(input).await,
        }
    }

    async fn reload(&self) -> Result<(), RevocError> {
        match self {
            Self::Native(e) => e.reload().await,
            Self::Sidecar(e) => e.reload().await,
            Self::Wasm(e) => e.reload().await,
        }
    }

    fn engine_type(&self) -> PolicyEngineMode {
        match self {
            Self::Native(_) => PolicyEngineMode::Native,
            Self::Sidecar(_) => PolicyEngineMode::OpaHttp,
            Self::Wasm(_) => PolicyEngineMode::OpaWasm,
        }
    }
}
