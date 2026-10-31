//! OPA HTTP sidecar policy engine (Tier 3).
//!
//! Delegates evaluation to an external OPA process via its v1 HTTP API.
//! Fail-closed by default: if OPA is unreachable and `fail_open = false`,
//! all traffic is blocked (SPEC.md Principle 7).

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, warn};

use revoc_core::{
    EnforcementMode, PolicyDecision, PolicyEngine, PolicyEngineMode, PolicyInput, PolicyRuleTier,
    RevocError,
};

use crate::cache::DecisionCache;

/// OPA HTTP sidecar policy engine.
pub struct SidecarPolicyEngine {
    client: reqwest::Client,
    /// Full evaluation URL (e.g. `http://opa:8181/v1/data/revoc/governance/main/decision`).
    opa_url: String,
    /// When `false`: OPA unavailability → Block. When `true`: OPA unavailability → Allow.
    fail_open: bool,
    enforcement_mode: EnforcementMode,
    cache: Arc<DecisionCache>,
}

impl SidecarPolicyEngine {
    /// Create a new sidecar engine.
    pub fn new(
        opa_url: impl Into<String>,
        fail_open: bool,
        timeout: Duration,
        enforcement_mode: EnforcementMode,
        cache: Arc<DecisionCache>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        Self {
            client,
            opa_url: opa_url.into(),
            fail_open,
            enforcement_mode,
            cache,
        }
    }

    /// Check whether the OPA server is reachable.
    pub async fn health_check(&self) -> bool {
        // Derive the base URL from the eval URL by stripping the path
        let base = self.opa_url.split("/v1/").next().unwrap_or(&self.opa_url);
        self.client
            .get(format!("{base}/health"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }

    fn fail_decision(&self) -> PolicyDecision {
        if self.fail_open {
            warn!("OPA sidecar unreachable — fail_open=true, allowing request");
            PolicyDecision::allow()
        } else {
            warn!("OPA sidecar unreachable — fail_open=false, blocking request (fail-closed)");
            let mut d = PolicyDecision::block(
                "Policy engine unreachable — failing closed (SPEC.md Principle 7)",
                vec!["opa_unreachable".into()],
            );
            // Emergency-tier so nothing can override it
            d.tier = PolicyRuleTier::Emergency;
            d
        }
    }
}

#[async_trait]
impl PolicyEngine for SidecarPolicyEngine {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, RevocError> {
        let cache_key = DecisionCache::cache_key(input);

        if let Some(cached) = self.cache.get(&cache_key) {
            debug!(cache_hit = true, "OPA sidecar: decision served from cache");
            let result = if self.enforcement_mode == EnforcementMode::Shadow {
                cached.apply_shadow()
            } else {
                cached
            };
            return Ok(result);
        }

        let start = Instant::now();

        let body = json!({ "input": input });

        let resp = match self.client.post(&self.opa_url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, opa_url = %self.opa_url, "OPA HTTP request failed");
                let d = self.fail_decision();
                return Ok(d);
            }
        };

        let status = resp.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RevocError::PolicyEvaluation(
                "Policy package not found at OPA endpoint (404)".into(),
            ));
        }

        if !status.is_success() {
            warn!(status = %status, "OPA returned non-success status");
            return Ok(self.fail_decision());
        }

        let raw: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "OPA response parse failed");
                return Ok(self.fail_decision());
            }
        };

        let result_val = raw
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let mut decision: PolicyDecision = match serde_json::from_value(result_val) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "OPA result does not match PolicyDecision schema");
                return Ok(self.fail_decision());
            }
        };

        decision.eval_duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        decision.policy_engine = PolicyEngineMode::OpaHttp;

        self.cache.set(&cache_key, decision.clone());

        if self.enforcement_mode == EnforcementMode::Shadow {
            decision = decision.apply_shadow();
        }

        Ok(decision)
    }

    async fn reload(&self) -> Result<(), RevocError> {
        self.cache.invalidate_all();
        Ok(())
    }

    fn engine_type(&self) -> PolicyEngineMode {
        PolicyEngineMode::OpaHttp
    }
}
