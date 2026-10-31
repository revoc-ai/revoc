use revoc_core::{
    DetectionTier, Finding, FindingType, PiiEntityType, PolicyDecision, Severity, TextSpan,
};

use crate::json_mutator::{apply_span_redactions, SpanReplacement};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn pii_finding_with_span(entity: PiiEntityType, field: &str, start: usize, end: usize) -> Finding {
    let mut f =
        Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex).with_pii(entity);
    f.span = Some(TextSpan {
        start,
        end,
        field: field.into(),
        value: None,
    });
    f
}

fn redact_decision() -> PolicyDecision {
    PolicyDecision::redact("test redact", vec!["pii_email_v1".into()])
}

fn allow_decision() -> PolicyDecision {
    PolicyDecision::allow()
}

// ── apply_span_redactions ─────────────────────────────────────────────────────

#[test]
fn test_apply_span_replaces_email_in_content() {
    // "messages[0].content" = "Email me at foo@bar.com please"
    //                                   012345678901234567890123456789
    // "foo@bar.com" is at bytes 12..23
    let body = br#"{"messages":[{"role":"user","content":"Email me at foo@bar.com please"}]}"#;
    let replacements = vec![(
        "messages[0].content".to_string(),
        vec![SpanReplacement {
            start: 12,
            end: 23,
            replacement: "[REDACTED-EMAIL_ADDRESS]".to_string(),
        }],
    )];
    let result = apply_span_redactions(body, &replacements).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert!(!s.contains("foo@bar.com"), "Original email must not appear");
    assert!(
        s.contains("[REDACTED-EMAIL_ADDRESS]"),
        "Replacement must appear"
    );
}

#[test]
fn test_apply_span_replaces_ssn_with_empty() {
    // Remove strategy → empty string replacement
    let body = br#"{"messages":[{"role":"user","content":"SSN: 123-45-6789 done"}]}"#;
    let replacements = vec![(
        "messages[0].content".to_string(),
        vec![SpanReplacement {
            start: 5,
            end: 16,
            replacement: String::new(),
        }],
    )];
    let result = apply_span_redactions(body, &replacements).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert!(!s.contains("123-45-6789"), "SSN must be removed");
    assert!(s.contains("SSN:"), "Surrounding text must be preserved");
}

#[test]
fn test_apply_span_multiple_replacements_same_field() {
    // Two replacements in the same field: email at 0..15, SSN at 22..33
    // Apply descending by start so offsets stay valid.
    let body = br#"{"messages":[{"role":"user","content":"foo@bar.com and 123-45-6789"}]}"#;
    let replacements = vec![(
        "messages[0].content".to_string(),
        vec![
            SpanReplacement {
                start: 0,
                end: 11,
                replacement: "[REDACTED-EMAIL_ADDRESS]".to_string(),
            },
            SpanReplacement {
                start: 16,
                end: 27,
                replacement: String::new(),
            },
        ],
    )];
    let result = apply_span_redactions(body, &replacements).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert!(!s.contains("foo@bar.com"));
    assert!(!s.contains("123-45-6789"));
}

#[test]
fn test_apply_span_missing_field_silently_skips() {
    // Field path that does not exist in the JSON → no error, body unchanged.
    let body = br#"{"messages":[{"role":"user","content":"hello"}]}"#;
    let replacements = vec![(
        "messages[99].content".to_string(),
        vec![SpanReplacement {
            start: 0,
            end: 5,
            replacement: "X".to_string(),
        }],
    )];
    let result = apply_span_redactions(body, &replacements).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result).unwrap(),
        serde_json::from_slice::<serde_json::Value>(body).unwrap(),
    );
}

#[test]
fn test_apply_span_invalid_json_returns_error() {
    let not_json = b"not json at all";
    let replacements = vec![(
        "messages[0].content".to_string(),
        vec![SpanReplacement {
            start: 0,
            end: 1,
            replacement: "X".to_string(),
        }],
    )];
    assert!(apply_span_redactions(not_json, &replacements).is_err());
}

#[test]
fn test_apply_span_hash_replacement() {
    // Hash strategy produces a deterministic [hash:XXXX] token.
    use sha2::Digest as _;
    let secret = "sk-secret123";
    let digest = sha2::Sha256::digest(secret.as_bytes());
    let expected_hash = format!("[hash:{}]", hex::encode(&digest[..4]));

    let body_str = format!(r#"{{"messages":[{{"role":"user","content":"key: {secret}"}}]}}"#);
    let start = 5; // "key: " is 5 bytes, secret starts at 5
    let replacements = vec![(
        "messages[0].content".to_string(),
        vec![SpanReplacement {
            start,
            end: start + secret.len(),
            replacement: expected_hash.clone(),
        }],
    )];
    let result = apply_span_redactions(body_str.as_bytes(), &replacements).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert!(!s.contains(secret));
    assert!(s.contains(&expected_hash));
}

// ── redact_body integration tests ─────────────────────────────────────────────

#[test]
fn test_redact_body_no_findings_returns_original() {
    use revoc_core::Redactor;

    let metrics = revoc_telemetry::RevocMetrics::global();
    let redactor = crate::RevocRedactor::new(metrics);
    let body = br#"{"messages":[{"role":"user","content":"Hello world"}]}"#;
    let (out, _findings) = redactor.redact_body(body, &[], &redact_decision()).unwrap();
    assert_eq!(out, body.to_vec());
}

#[test]
fn test_redact_body_allow_decision_skips_redaction() {
    use revoc_core::Redactor;

    let metrics = revoc_telemetry::RevocMetrics::global();
    let redactor = crate::RevocRedactor::new(metrics);
    let body = br#"{"messages":[{"role":"user","content":"SSN: 123-45-6789"}]}"#;
    let finding = pii_finding_with_span(PiiEntityType::UsSsn, "messages[0].content", 5, 16);
    // Allow decision + finding is High but not Critical → redact only if requires_redaction
    // allow_decision().effective_action = Allow → requires_redaction() = false
    // However is_high_severity() = true for High severity → redactor still applies it
    let (out, applied) = redactor
        .redact_body(body, &[finding], &allow_decision())
        .unwrap();
    let s = std::str::from_utf8(&out).unwrap();
    // High severity SSN must be redacted even under Allow decision
    // (redact_impl filter: decision.requires_redaction() || f.is_high_severity())
    assert!(
        !s.contains("123-45-6789"),
        "High-severity SSN must be redacted regardless of decision"
    );
    assert!(applied.iter().any(|f| f.redaction_applied));
}

#[test]
fn test_redact_body_tool_manifest_risk_skipped() {
    use revoc_core::Redactor;

    let metrics = revoc_telemetry::RevocMetrics::global();
    let redactor = crate::RevocRedactor::new(metrics);
    let body = br#"{"messages":[{"role":"user","content":"tool manifest risk test"}]}"#;
    let mut finding = Finding::new(
        FindingType::ToolManifestRisk,
        Severity::High,
        DetectionTier::Regex,
    );
    finding.span = Some(TextSpan {
        start: 0,
        end: 4,
        field: "messages[0].content".into(),
        value: None,
    });
    let (out, _) = redactor
        .redact_body(body, &[finding], &redact_decision())
        .unwrap();
    // ToolManifestRisk findings must be skipped by the redactor
    assert_eq!(
        out,
        body.to_vec(),
        "ToolManifestRisk must not trigger body mutation"
    );
}

// ── redact_mcp_result tests ───────────────────────────────────────────────────

#[test]
fn test_redact_mcp_result_pii_removed() {
    use revoc_core::Redactor;

    let metrics = revoc_telemetry::RevocMetrics::global();
    let redactor = crate::RevocRedactor::new(metrics);
    // Simulate MCP result JSON containing SSN
    let result_json = br#"{"content":[{"type":"text","text":"Customer SSN: 123-45-6789"}]}"#;
    let finding = pii_finding_with_span(PiiEntityType::UsSsn, "content[0].text", 13, 24);
    let (out, _) = redactor
        .redact_mcp_result(result_json, &[finding], &redact_decision())
        .unwrap();
    let s = std::str::from_utf8(&out).unwrap();
    assert!(
        !s.contains("123-45-6789"),
        "SSN must be removed from MCP result"
    );
}

#[test]
fn test_redact_mcp_result_no_findings_passthrough() {
    use revoc_core::Redactor;

    let metrics = revoc_telemetry::RevocMetrics::global();
    let redactor = crate::RevocRedactor::new(metrics);
    let result_json = br#"{"content":[{"type":"text","text":"The answer is 4."}]}"#;
    let (out, _) = redactor
        .redact_mcp_result(result_json, &[], &redact_decision())
        .unwrap();
    assert_eq!(out, result_json.to_vec());
}
