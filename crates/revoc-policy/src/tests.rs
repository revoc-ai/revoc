use std::sync::Arc;
use std::time::Duration;

use revoc_core::{
    Action, CallerContext, DetectionTier, EnforcementMode, Finding, FindingType, PiiEntityType,
    PolicyDecision, PolicyEngine, PolicyInput, PolicyRuleTier, RequestType, Severity, TextSpan,
};

use crate::{
    cache::DecisionCache,
    conflict::{is_security_rule, resolve, SECURITY_RULE_IDS},
    native::NativePolicyEngine,
    sidecar::SidecarPolicyEngine,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_cache() -> Arc<DecisionCache> {
    Arc::new(DecisionCache::new(Duration::from_secs(60), 1000))
}

fn make_short_cache(ttl_ms: u64) -> Arc<DecisionCache> {
    Arc::new(DecisionCache::new(Duration::from_millis(ttl_ms), 1000))
}

fn native(mode: EnforcementMode) -> NativePolicyEngine {
    NativePolicyEngine::new(mode)
}

fn make_finding(ft: FindingType, sev: Severity, entity: Option<PiiEntityType>) -> Finding {
    let mut f = Finding::new(ft, sev, DetectionTier::Regex);
    if let Some(e) = entity {
        f = f.with_pii(e);
    }
    f
}

/// Build a finding with a span — used in deduplication-style tests.
#[allow(dead_code)]
fn make_finding_with_span(
    ft: FindingType,
    sev: Severity,
    entity: Option<PiiEntityType>,
    field: &str,
    start: usize,
    end: usize,
) -> Finding {
    let mut f = Finding::new(ft, sev, DetectionTier::Regex);
    if let Some(e) = entity {
        f = f.with_pii(e);
    }
    f.span = Some(TextSpan {
        start,
        end,
        field: field.into(),
        value: None,
    });
    f
}

fn make_input(findings: Vec<Finding>) -> PolicyInput {
    PolicyInput {
        request_id: uuid::Uuid::now_v7().to_string(),
        request_type: RequestType::LlmRequest,
        caller: CallerContext::default(),
        findings,
        model: None,
        provider: None,
        messages: None,
        tool_call: None,
        tool_result: None,
        token_usage: None,
        session_state: None,
        governance_depth: 0,
        timestamp: 0,
    }
}

// ── NativePolicyEngine tests ──────────────────────────────────────────────────

#[test]
fn test_native_allow_on_empty_findings() {
    let engine = native(EnforcementMode::Enforce);
    let decision = engine.evaluate_sync(&make_input(vec![]));
    assert_eq!(
        decision.effective_action,
        Action::Allow,
        "Empty findings must allow"
    );
}

#[test]
fn test_native_block_on_ddl_mutation() {
    let engine = native(EnforcementMode::Enforce);
    let finding = make_finding(FindingType::DdlMutation, Severity::Critical, None);
    let decision = engine.evaluate_sync(&make_input(vec![finding]));
    assert_eq!(decision.effective_action, Action::Block);
    assert!(decision
        .applicable_rules
        .iter()
        .any(|r| r == "sec_ddl_mutation_v1"));
}

#[test]
fn test_native_block_on_secret_exposure() {
    let engine = native(EnforcementMode::Enforce);
    let finding = make_finding(
        FindingType::SecretExposure,
        Severity::Critical,
        Some(PiiEntityType::AwsAccessKey),
    );
    let decision = engine.evaluate_sync(&make_input(vec![finding]));
    assert_eq!(decision.effective_action, Action::Block);
    assert!(decision
        .applicable_rules
        .iter()
        .any(|r| r == "secret_block_v1"));
}

#[test]
fn test_native_block_on_prompt_injection() {
    let engine = native(EnforcementMode::Enforce);
    let finding = make_finding(FindingType::PromptInjection, Severity::Critical, None);
    let decision = engine.evaluate_sync(&make_input(vec![finding]));
    assert_eq!(decision.effective_action, Action::Block);
    assert!(decision
        .applicable_rules
        .iter()
        .any(|r| r == "sec_prompt_injection_v1"));
}

#[test]
fn test_native_redact_on_pii_only() {
    let engine = native(EnforcementMode::Enforce);
    let finding = make_finding(
        FindingType::Pii,
        Severity::High,
        Some(PiiEntityType::EmailAddress),
    );
    let decision = engine.evaluate_sync(&make_input(vec![finding]));
    assert_eq!(decision.effective_action, Action::Redact);
    assert!(decision
        .applicable_rules
        .iter()
        .any(|r| r == "pii_email_v1"));
}

#[test]
fn test_native_shadow_mode_effective_action_is_audit() {
    let engine = native(EnforcementMode::Shadow);
    // Even with a DDL finding that would normally block
    let finding = make_finding(FindingType::DdlMutation, Severity::Critical, None);
    let decision = engine.evaluate_sync(&make_input(vec![finding]));
    // action is preserved for recording
    assert_eq!(decision.action, Action::Block);
    // effective_action must be Audit in shadow mode
    assert_eq!(
        decision.effective_action,
        Action::Audit,
        "Shadow mode must set effective_action=Audit"
    );
}

// ── conflict::resolve tests ───────────────────────────────────────────────────

#[test]
fn test_conflict_empty_violations_allow() {
    let decision = resolve(&[]);
    assert_eq!(decision.action, Action::Allow);
}

#[test]
fn test_conflict_security_wins_over_custom() {
    // DDL block at Security tier vs any other Allow at Custom tier
    let ddl_block = PolicyDecision::block("DDL detected", vec!["sec_ddl_mutation_v1".into()]);
    assert_eq!(ddl_block.tier, PolicyRuleTier::Security);

    let mut custom_allow = PolicyDecision::allow();
    custom_allow.tier = PolicyRuleTier::Custom;

    let result = resolve(&[custom_allow, ddl_block]);
    assert_eq!(
        result.action,
        Action::Block,
        "Security block must win over Custom allow"
    );
    assert!(result
        .applicable_rules
        .contains(&"sec_ddl_mutation_v1".into()));
}

#[test]
fn test_conflict_block_beats_redact_same_tier() {
    let mut block = PolicyDecision::block("reason", vec!["rule_a".into()]);
    block.tier = PolicyRuleTier::Profile;
    block.severity = Severity::High;

    let redact = PolicyDecision::redact("reason", vec!["rule_b".into()]);
    // redact is already Profile tier

    let result = resolve(&[redact, block.clone()]);
    assert_eq!(
        result.action,
        Action::Block,
        "Block must beat Redact at same tier"
    );
}

#[test]
fn test_conflict_profile_loses_to_security() {
    // A HIPAA block (Profile tier) and a DDL block (Security tier)
    let mut hipaa_block = PolicyDecision::block("HIPAA PHI", vec!["hipaa_phi_v1".into()]);
    hipaa_block.tier = PolicyRuleTier::Profile;

    let ddl_block = PolicyDecision::block("DDL detected", vec!["sec_ddl_mutation_v1".into()]);
    // ddl_block is Security tier (from ::block constructor)

    let result = resolve(&[hipaa_block, ddl_block]);
    assert_eq!(
        result.tier,
        PolicyRuleTier::Security,
        "Security must beat Profile"
    );
    assert!(result
        .applicable_rules
        .contains(&"sec_ddl_mutation_v1".into()));
}

// ── is_security_rule tests ────────────────────────────────────────────────────

#[test]
fn test_is_security_rule_true() {
    assert!(is_security_rule("sec_ddl_mutation_v1"));
    assert!(is_security_rule("sec_prompt_injection_v1"));
    assert!(is_security_rule("session_data_exfil_v1"));
    // All built-in security rule IDs
    for &rule in SECURITY_RULE_IDS {
        assert!(is_security_rule(rule), "{rule} must be a security rule");
    }
}

#[test]
fn test_is_security_rule_false() {
    assert!(!is_security_rule("pii_email_v1"));
    assert!(!is_security_rule("pii_redaction_v1"));
    assert!(!is_security_rule("token_quota_v1"));
    assert!(!is_security_rule("mcp_tool_acl_v1"));
    assert!(!is_security_rule("unknown_rule"));
}

// ── DecisionCache tests ───────────────────────────────────────────────────────

#[test]
fn test_native_engine_never_serves_cached_decisions() {
    let engine = NativePolicyEngine::new(EnforcementMode::Enforce);
    let input = make_input(vec![]);
    assert!(!engine.evaluate_sync(&input).cache_hit);
    assert!(!engine.evaluate_sync(&input).cache_hit);
}

#[test]
fn test_cache_hit_on_second_lookup() {
    let cache = make_cache();
    let key = DecisionCache::cache_key(&make_input(vec![])).expect("key");
    assert!(cache.get(&key).is_none());
    cache.set(&key, PolicyDecision::allow());
    assert!(cache.get(&key).is_some_and(|d| d.cache_hit));
}

#[test]
fn test_cache_key_ignores_per_request_fields() {
    let input1 = make_input(vec![make_finding(
        FindingType::Pii,
        Severity::Medium,
        Some(PiiEntityType::EmailAddress),
    )]);
    let mut input2 = input1.clone();
    input2.request_id = "completely-different-id".into();
    input2.timestamp += 1000;
    // Fresh finding id / detected_at, same content
    input2.findings = vec![make_finding(
        FindingType::Pii,
        Severity::Medium,
        Some(PiiEntityType::EmailAddress),
    )];
    assert_eq!(
        DecisionCache::cache_key(&input1),
        DecisionCache::cache_key(&input2),
        "cache key must not depend on request_id, timestamp or finding ids"
    );
}

#[test]
fn test_cache_key_covers_tool_arguments() {
    let mut a = make_input(vec![]);
    a.tool_call = Some(revoc_core::McpToolCall {
        tool_name: "execute_sql".into(),
        arguments: serde_json::json!({"query": "SELECT 1"}),
        server_id: None,
        call_id: None,
    });
    let mut b = a.clone();
    if let Some(tc) = b.tool_call.as_mut() {
        tc.arguments = serde_json::json!({"query": "DROP TABLE users"});
    }
    assert_ne!(DecisionCache::cache_key(&a), DecisionCache::cache_key(&b));
}

#[test]
fn test_cache_key_covers_encoded_flag_and_depth() {
    let plain = make_input(vec![make_finding(
        FindingType::Pii,
        Severity::Medium,
        Some(PiiEntityType::EmailAddress),
    )]);
    let mut encoded = plain.clone();
    encoded.findings[0].was_encoded = true;
    assert_ne!(
        DecisionCache::cache_key(&plain),
        DecisionCache::cache_key(&encoded)
    );
    let mut deeper = plain.clone();
    deeper.governance_depth = 3;
    assert_ne!(
        DecisionCache::cache_key(&plain),
        DecisionCache::cache_key(&deeper)
    );
}

#[tokio::test]
async fn test_cache_evicts_after_ttl() {
    let cache = make_short_cache(1);
    let key = DecisionCache::cache_key(&make_input(vec![])).expect("key");
    cache.set(&key, PolicyDecision::allow());
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(cache.get(&key).is_none(), "Entry must be evicted after TTL");
}

// ── SidecarPolicyEngine tests (fail-open / fail-closed) ───────────────────────

#[tokio::test]
async fn test_sidecar_fail_closed() {
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Mount a 500 error response — simulates OPA malfunction
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let engine = SidecarPolicyEngine::new(
        format!("{}/v1/data/revoc/governance/main/decision", server.uri()),
        false, // fail_open = false
        Duration::from_secs(2),
        EnforcementMode::Enforce,
        make_cache(),
    );

    let decision = engine.evaluate(&make_input(vec![])).await.unwrap();
    assert_eq!(
        decision.effective_action,
        Action::Block,
        "fail_open=false must block when OPA is unreachable"
    );
}

#[tokio::test]
async fn test_sidecar_fail_open() {
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // 500 error — OPA malfunction
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let engine = SidecarPolicyEngine::new(
        format!("{}/v1/data/revoc/governance/main/decision", server.uri()),
        true, // fail_open = true
        Duration::from_secs(2),
        EnforcementMode::Enforce,
        make_cache(),
    );

    let decision = engine.evaluate(&make_input(vec![])).await.unwrap();
    assert_eq!(
        decision.effective_action,
        Action::Allow,
        "fail_open=true must allow when OPA is unreachable"
    );
}
