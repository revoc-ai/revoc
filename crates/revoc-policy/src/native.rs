//! Native Rust policy engine — implements all 30 default rules from SPEC.md §14.
//!
//! Zero external dependencies in the hot path. Used by default in Tier 1 and Tier 2.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tracing::debug;

use revoc_core::{
    EnforcementMode, Finding, FindingType, PiiEntityType, PolicyDecision,
    PolicyEngine, PolicyEngineMode, PolicyInput, PolicyRuleTier, RequestType, RevocError,
    Severity,
};

use crate::cache::DecisionCache;
use crate::conflict;

// ── NativePolicyEngine ────────────────────────────────────────────────────────

/// Pure-Rust policy engine implementing all 30 default governance rules.
pub struct NativePolicyEngine {
    cache: Arc<DecisionCache>,
    enforcement_mode: EnforcementMode,
}

impl NativePolicyEngine {
    /// Create a new engine with the given cache and enforcement mode.
    pub fn new(cache: Arc<DecisionCache>, enforcement_mode: EnforcementMode) -> Self {
        Self { cache, enforcement_mode }
    }

    /// Evaluate all 30 default rules synchronously and return the resolved decision.
    pub fn evaluate_sync(&self, input: &PolicyInput) -> PolicyDecision {
        let cache_key = DecisionCache::cache_key(input);

        // Cache hit
        if let Some(cached) = self.cache.get(&cache_key) {
            debug!(cache_hit = true, "Policy decision served from cache");
            let result = if self.enforcement_mode == EnforcementMode::Shadow {
                cached.apply_shadow()
            } else {
                cached
            };
            return result;
        }

        let start = Instant::now();
        let mut violations: Vec<PolicyDecision> = Vec::new();

        // ── Process each finding through the 30 rules ─────────────────────────
        for finding in &input.findings {
            Self::apply_finding_rules(finding, input, &mut violations);
        }

        // ── Session-level exfiltration check (session_data_exfil_v1) ─────────
        if let Some(session) = &input.session_state {
            if session.is_exfil_pattern_detected() {
                violations.push(security_block(
                    "Session data exfiltration pattern detected",
                    "session_data_exfil_v1",
                ));
            }
        }

        // ── Resolve all violations ────────────────────────────────────────────
        let mut decision = if violations.is_empty() {
            PolicyDecision::allow()
        } else {
            conflict::resolve(&violations)
        };

        decision.eval_duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        decision.policy_engine = PolicyEngineMode::Native;

        // Store in cache (before applying shadow so the stored decision is real)
        self.cache.set(&cache_key, decision.clone());

        // Apply shadow mode: keep action for recording, set effective_action=Audit
        if self.enforcement_mode == EnforcementMode::Shadow {
            decision = decision.apply_shadow();
        }

        decision
    }

    fn apply_finding_rules(
        finding: &Finding,
        input: &PolicyInput,
        violations: &mut Vec<PolicyDecision>,
    ) {
        // If found in encoded content, always fire sec_encoded_evasion_v1 (Security tier)
        if finding.was_encoded {
            violations.push(security_block(
                "Security pattern detected in encoded (evasion) content",
                "sec_encoded_evasion_v1",
            ));
        }

        match &finding.finding_type {
            // ── Secret rules (Section 14 — umbrella block at Security tier) ──
            FindingType::SecretExposure => {
                let rule = secret_rule_id(finding.pii_entity.as_ref());
                violations.push(security_block(
                    format!("Secret credential detected: {rule}"),
                    "secret_block_v1",
                ));
            }

            // ── Security rules (Section 14 — Tier 3, cannot be overridden) ──
            FindingType::DdlMutation => {
                let (reason, rule_id) = match finding
                    .metadata
                    .get("pattern_name")
                    .and_then(|v| v.as_str())
                {
                    Some("DELETE_NO_WHERE") => (
                        "DELETE statement without a WHERE clause detected",
                        "sec_delete_no_where_v1",
                    ),
                    Some("MASS_DELETE") => (
                        "Mass delete operation detected",
                        "sec_mass_delete_v1",
                    ),
                    _ => (
                        "DDL mutation (DROP/TRUNCATE/ALTER) detected",
                        "sec_ddl_mutation_v1",
                    ),
                };
                violations.push(security_block(reason, rule_id));
            }
            FindingType::PromptInjection => {
                violations.push(security_block(
                    "Prompt injection attempt detected",
                    "sec_prompt_injection_v1",
                ));
            }
            FindingType::SystemPromptExtraction => {
                violations.push(security_block(
                    "System prompt extraction attempt detected",
                    "sec_sysextract_v1",
                ));
            }
            FindingType::SsrfAttempt => {
                violations.push(security_block(
                    "SSRF: internal network address detected in argument",
                    "sec_ssrf_v1",
                ));
            }
            FindingType::PathTraversal => {
                violations.push(security_block(
                    "Path traversal sequence detected in file argument",
                    "sec_path_traversal_v1",
                ));
            }
            FindingType::SessionAnomaly => {
                violations.push(security_block(
                    "Session anomaly / data exfiltration pattern",
                    "session_data_exfil_v1",
                ));
            }

            // ── PII rules (Section 14 — Profile tier, Redact) ────────────────
            FindingType::Pii => {
                // mcp_result_pii_v1: PII in MCP tool results gets Security-tier redact
                if input.request_type == RequestType::McpToolResult {
                    let mut d = PolicyDecision::redact(
                        "PII detected in MCP tool result",
                        vec!["mcp_result_pii_v1".into()],
                    );
                    d.tier = PolicyRuleTier::Security;
                    violations.push(d);
                } else {
                    let rule = pii_rule_id(finding.pii_entity.as_ref());
                    violations.push(PolicyDecision::redact(
                        format!("PII entity detected: {rule}"),
                        vec![rule],
                    ));
                }
            }

            // ── Operational rules ─────────────────────────────────────────────
            FindingType::McpToolBlock => {
                violations.push(profile_block(
                    "MCP tool call blocked by ACL policy",
                    "mcp_tool_acl_v1",
                ));
            }
            FindingType::QuotaExceeded => {
                violations.push(profile_block(
                    "Token quota exceeded",
                    "token_quota_v1",
                ));
            }

            // Informational — no automatic governance action
            FindingType::KeywordMatch
            | FindingType::ToolManifestRisk
            | FindingType::Custom(_) => {}
        }
    }
}

#[async_trait]
impl PolicyEngine for NativePolicyEngine {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, RevocError> {
        Ok(self.evaluate_sync(input))
    }

    async fn reload(&self) -> Result<(), RevocError> {
        self.cache.invalidate_all();
        Ok(())
    }

    fn engine_type(&self) -> PolicyEngineMode {
        PolicyEngineMode::Native
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a Security-tier block decision for a single rule.
fn security_block(reason: impl Into<String>, rule_id: &str) -> PolicyDecision {
    PolicyDecision::block(reason.into(), vec![rule_id.into()])
    // PolicyDecision::block() already sets tier = Security, severity = Critical
}

/// Build a Profile-tier block decision for operational rules.
fn profile_block(reason: impl Into<String>, rule_id: &str) -> PolicyDecision {
    let mut d = PolicyDecision::block(reason.into(), vec![rule_id.into()]);
    d.tier = PolicyRuleTier::Profile;
    d.severity = Severity::High;
    d
}

/// Map a PII entity type to its canonical rule ID.
fn pii_rule_id(entity: Option<&PiiEntityType>) -> String {
    let id = match entity {
        Some(PiiEntityType::UsSsn) => "pii_ssn_v1",
        Some(PiiEntityType::CreditCard) => "pii_credit_card_v1",
        Some(PiiEntityType::IbanCode) => "pii_iban_v1",
        Some(PiiEntityType::BankAccount | PiiEntityType::RoutingNumber | PiiEntityType::SwiftBic) => "pii_bank_account_v1",
        Some(PiiEntityType::UsPassport) => "pii_passport_v1",
        Some(PiiEntityType::UsDriverLicense) => "pii_driver_license_v1",
        Some(PiiEntityType::EmailAddress) => "pii_email_v1",
        Some(PiiEntityType::PhoneNumber) => "pii_phone_v1",
        Some(PiiEntityType::IpAddressV4 | PiiEntityType::IpAddressV6) => "pii_ip_address_v1",
        Some(PiiEntityType::MedicalRecordNumber | PiiEntityType::NpiNumber | PiiEntityType::DeaNumber) => "pii_mrn_v1",
        Some(PiiEntityType::DateOfBirth) => "pii_dob_v1",
        _ => "pii_generic_v1",
    };
    id.to_string()
}

/// Map a secret entity type to its specific rule ID.
fn secret_rule_id(entity: Option<&PiiEntityType>) -> String {
    let id = match entity {
        Some(PiiEntityType::AwsAccessKey) => "secret_aws_key_v1",
        Some(PiiEntityType::AwsSecretKey) => "secret_aws_secret_v1",
        Some(PiiEntityType::GithubToken) => "secret_github_token_v1",
        Some(PiiEntityType::OpenaiKey) => "secret_openai_key_v1",
        Some(PiiEntityType::AnthropicKey) => "secret_anthropic_key_v1",
        Some(PiiEntityType::GenericApiKey) => "secret_generic_api_key_v1",
        Some(PiiEntityType::PrivateKey) => "secret_private_key_v1",
        Some(PiiEntityType::JwtToken) => "secret_jwt_v1",
        Some(PiiEntityType::PasswordInJson) => "secret_password_json_v1",
        _ => "secret_block_v1",
    };
    id.to_string()
}
