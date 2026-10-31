use chrono::Utc;

use crate::error::RevocError;
use crate::types::decision::{
    Action, CallerContext, EnforcementMode, PolicyDecision, PolicyRuleTier, SessionState,
};
use crate::types::finding::{
    DetectionTier, Finding, FindingType, PiiEntityType, Severity, TextSpan,
};
use crate::types::mcp::McpBlockResponse;
use crate::types::openai::RevocErrorResponse;

// ── Finding ───────────────────────────────────────────────────────────────────

#[test]
fn test_finding_new_defaults() {
    let f = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex);
    assert!(!f.was_normalized);
    assert!(!f.was_encoded);
    assert!(!f.redaction_applied);
    assert!(f.span.is_none());
    assert!(f.pii_entity.is_none());
    assert_eq!(f.confidence, 1.0);
    // UUID v7 — just verify it is non-nil
    assert_ne!(f.id, uuid::Uuid::nil());
}

#[test]
fn test_finding_builders() {
    let span = TextSpan {
        start: 0,
        end: 11,
        field: "messages[0].content".into(),
        value: Some("test-value".into()),
    };
    let f = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_span(span)
        .with_confidence(0.87)
        .with_pii(PiiEntityType::EmailAddress);

    assert!(f.span.is_some());
    assert_eq!(f.span.as_ref().unwrap().start, 0);
    assert_eq!(f.confidence, 0.87);
    assert_eq!(f.pii_entity, Some(PiiEntityType::EmailAddress));
}

// ── Severity ordering ─────────────────────────────────────────────────────────

#[test]
fn test_severity_ordering() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

// ── PolicyRuleTier ordering ───────────────────────────────────────────────────

#[test]
fn test_policy_rule_tier_ordering() {
    assert!(PolicyRuleTier::Default < PolicyRuleTier::Custom);
    assert!(PolicyRuleTier::Custom < PolicyRuleTier::Profile);
    assert!(PolicyRuleTier::Profile < PolicyRuleTier::Security);
    assert!(PolicyRuleTier::Security < PolicyRuleTier::Emergency);
}

#[test]
fn test_security_tier_greater_than_profile() {
    assert!(PolicyRuleTier::Security > PolicyRuleTier::Profile);
}

// ── Action ────────────────────────────────────────────────────────────────────

#[test]
fn test_action_is_blocking() {
    assert!(Action::Block.is_blocking());
    assert!(!Action::Allow.is_blocking());
    assert!(!Action::Redact.is_blocking());
    assert!(!Action::Audit.is_blocking());
}

#[test]
fn test_action_requires_redaction() {
    assert!(Action::Redact.requires_redaction());
    assert!(!Action::Allow.requires_redaction());
    assert!(!Action::Block.requires_redaction());
    assert!(!Action::Audit.requires_redaction());
}

// ── EnforcementMode ───────────────────────────────────────────────────────────

#[test]
fn test_enforcement_mode_default() {
    assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
}

// ── CallerContext ─────────────────────────────────────────────────────────────

#[test]
fn test_caller_context_is_shadow_mode() {
    let mut ctx = CallerContext::default();
    ctx.enforcement_mode = EnforcementMode::Shadow;
    assert!(ctx.is_shadow_mode());

    ctx.enforcement_mode = EnforcementMode::Enforce;
    assert!(!ctx.is_shadow_mode());
}

// ── PolicyDecision constructors ───────────────────────────────────────────────

#[test]
fn test_policy_decision_allow_constructor() {
    let d = PolicyDecision::allow();
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.effective_action, Action::Allow);
    assert_eq!(d.tier, PolicyRuleTier::Default);
    assert!(d.applicable_rules.is_empty());
}

#[test]
fn test_policy_decision_block_constructor() {
    let d = PolicyDecision::block("DDL detected", vec!["sec_ddl_mutation_v1".into()]);
    assert_eq!(d.action, Action::Block);
    assert_eq!(d.effective_action, Action::Block);
    assert_eq!(d.tier, PolicyRuleTier::Security);
    assert!(!d.reason.is_empty());
    assert_eq!(d.applicable_rules, vec!["sec_ddl_mutation_v1"]);
}

#[test]
fn test_policy_decision_apply_shadow() {
    let d = PolicyDecision::block("reason", vec![]).apply_shadow();
    // action is preserved for recording
    assert_eq!(d.action, Action::Block);
    // effective_action is demoted to Audit so nothing is actually blocked
    assert_eq!(d.effective_action, Action::Audit);
}

// ── McpMethod governance flags ────────────────────────────────────────────────

#[test]
fn test_mcp_requires_governance() {
    use crate::types::mcp::McpMethod;
    assert!(McpMethod::ToolsCall.requires_governance());
    assert!(McpMethod::ResourcesRead.requires_governance());
    assert!(McpMethod::SamplingCreateMessage.requires_governance());
    assert!(!McpMethod::Initialize.requires_governance());
    assert!(!McpMethod::Ping.requires_governance());
    assert!(!McpMethod::ToolsList.requires_governance());
}

#[test]
fn test_mcp_response_requires_inspection() {
    use crate::types::mcp::McpMethod;
    assert!(McpMethod::ToolsCall.response_requires_inspection());
    assert!(McpMethod::ResourcesRead.response_requires_inspection());
    assert!(!McpMethod::Initialize.response_requires_inspection());
    assert!(!McpMethod::SamplingCreateMessage.response_requires_inspection());
}

// ── McpBlockResponse ──────────────────────────────────────────────────────────

#[test]
fn test_mcp_block_response_dashboard_url_in_error_data() {
    let resp = McpBlockResponse::new(
        serde_json::json!("req-1"),
        "trace-abc",
        vec!["sec_ddl_mutation_v1".into()],
        "DDL mutation blocked",
        "http://localhost:3000/traces/trace-abc",
    );
    assert_eq!(
        resp.error.data.dashboard_url,
        "http://localhost:3000/traces/trace-abc"
    );
    assert_eq!(resp.error.data.code, "REVOC_GOVERNANCE_BLOCK");
}

#[test]
fn test_mcp_block_response_code_minus_32603() {
    let resp = McpBlockResponse::new(
        serde_json::json!(1),
        "t",
        vec![],
        "blocked",
        "http://localhost:3000",
    );
    assert_eq!(resp.error.code, -32603);
    assert_eq!(resp.jsonrpc, "2.0");
}

// ── RevocErrorResponse constructors ──────────────────────────────────────────

#[test]
fn test_revoc_error_kill_switch_code() {
    let r = RevocErrorResponse::kill_switch_active("trace-1", "http://localhost:3000");
    assert_eq!(r.error.code, "REVOC_KILL_SWITCH_ACTIVE");
    assert_eq!(r.error.r#type, "emergency_stop");
    assert_eq!(r.error.dashboard_url, "http://localhost:3000/emergency");
}

#[test]
fn test_revoc_error_depth_exceeded_code() {
    let r = RevocErrorResponse::depth_exceeded("trace-2", 10, "http://localhost:3000");
    assert_eq!(r.error.code, "REVOC_GOVERNANCE_DEPTH_EXCEEDED");
    assert!(r.error.message.contains("10/10"));
    assert!(r.error.documentation_url.is_some());
}

#[test]
fn test_revoc_error_governance_block_has_documentation_url() {
    let r = RevocErrorResponse::governance_block(
        "trace-3",
        "reason",
        vec!["sec_ssrf_v1".into()],
        "http://localhost:3000",
    );
    assert!(r.error.documentation_url.is_some());
    let doc = r.error.documentation_url.unwrap();
    assert!(doc.contains("sec_ssrf_v1"));
}

#[test]
fn test_revoc_error_governance_block_has_blocked_by() {
    let r = RevocErrorResponse::governance_block(
        "trace-4",
        "reason",
        vec!["sec_prompt_injection_v1".into(), "sec_ssrf_v1".into()],
        "http://localhost:3000",
    );
    assert_eq!(r.error.blocked_by, Some("sec_prompt_injection_v1".into()));
    assert_eq!(r.error.rules.as_ref().unwrap().len(), 2);
}

// ── RevocError HTTP status codes ──────────────────────────────────────────────

#[test]
fn test_http_status_kill_switch() {
    let e1 = RevocError::GovernanceDepthExceeded { depth: 10 };
    assert_eq!(e1.http_status(), 503);

    let e2 = RevocError::KillSwitchActive { scope: "global".into() };
    assert_eq!(e2.http_status(), 503);
}

#[test]
fn test_http_status_auth() {
    let e1 = RevocError::Authentication { reason: "invalid key".into() };
    assert_eq!(e1.http_status(), 401);

    let e2 = RevocError::RateLimitExceeded { caller_id: "svc-a".into() };
    assert_eq!(e2.http_status(), 429);

    let e3 = RevocError::BodyTooLarge { size: 20_000_000, max: 10_485_760 };
    assert_eq!(e3.http_status(), 413);
}

// ── PiiEntityType Display ─────────────────────────────────────────────────────

#[test]
fn test_pii_entity_display() {
    assert_eq!(PiiEntityType::UsSsn.to_string(), "US_SSN");
    assert_eq!(PiiEntityType::EmailAddress.to_string(), "EMAIL_ADDRESS");
    assert_eq!(PiiEntityType::CreditCard.to_string(), "CREDIT_CARD");
    assert_eq!(PiiEntityType::IpAddressV4.to_string(), "IP_ADDRESS_V4");
    assert_eq!(PiiEntityType::AwsAccessKey.to_string(), "AWS_ACCESS_KEY");
    assert_eq!(PiiEntityType::JwtToken.to_string(), "JWT_TOKEN");
    assert_eq!(PiiEntityType::Custom("MY_ENTITY".into()).to_string(), "MY_ENTITY");
}

// ── SessionState exfiltration heuristic ──────────────────────────────────────

#[test]
fn test_session_state_exfil_detected() {
    let now = Utc::now();
    let mut state = SessionState {
        session_id: "s1".into(),
        org_id: "org1".into(),
        caller_id: "caller1".into(),
        tools_called: vec![],
        total_rows_read: 501,
        pii_entities_seen: ["EMAIL_ADDRESS".to_string()].into_iter().collect(),
        external_send_attempted: true,
        started_at: now,
        last_active: now,
    };
    assert!(state.is_exfil_pattern_detected());

    // Boundary: exactly 500 rows should NOT trigger
    state.total_rows_read = 500;
    assert!(!state.is_exfil_pattern_detected());
}

#[test]
fn test_session_state_exfil_partial() {
    let now = Utc::now();
    // High rows + PII but NO external send
    let state = SessionState {
        session_id: "s2".into(),
        org_id: "org1".into(),
        caller_id: "caller1".into(),
        tools_called: vec![],
        total_rows_read: 1000,
        pii_entities_seen: ["US_SSN".to_string()].into_iter().collect(),
        external_send_attempted: false,
        started_at: now,
        last_active: now,
    };
    assert!(!state.is_exfil_pattern_detected());
}

// ── Serde round-trips ─────────────────────────────────────────────────────────

#[test]
fn test_serde_roundtrip_finding() {
    let f = Finding::new(FindingType::SecretExposure, Severity::Critical, DetectionTier::Regex)
        .with_confidence(0.99)
        .with_pii(PiiEntityType::AwsAccessKey);

    let json = serde_json::to_string(&f).expect("serialize");
    let back: Finding = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.id, f.id);
    assert_eq!(back.severity, Severity::Critical);
    assert_eq!(back.pii_entity, Some(PiiEntityType::AwsAccessKey));
    assert_eq!(back.confidence, 0.99);
}

#[test]
fn test_serde_roundtrip_policy_decision() {
    let d = PolicyDecision::block("injection detected", vec!["sec_prompt_injection_v1".into()]);
    let json = serde_json::to_string(&d).expect("serialize");
    let back: PolicyDecision = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.action, Action::Block);
    assert_eq!(back.tier, PolicyRuleTier::Security);
    assert_eq!(back.applicable_rules, vec!["sec_prompt_injection_v1"]);
}

// ── TextSpan privacy: value must not appear in JSON ───────────────────────────

#[test]
fn test_text_span_value_not_in_json() {
    let span = TextSpan {
        start: 5,
        end: 16,
        field: "messages[0].content".into(),
        // This secret value must NEVER appear in serialized output
        value: Some("sk-supersecret".into()),
    };
    let f = Finding::new(FindingType::SecretExposure, Severity::Critical, DetectionTier::Regex)
        .with_span(span);

    let json = serde_json::to_string(&f).expect("serialize");

    // The matched value must not leak into the JSON representation
    assert!(
        !json.contains("sk-supersecret"),
        "PII value leaked into serialized Finding: {json}"
    );
    // But the position metadata must be present
    assert!(json.contains("messages[0].content"));
}
