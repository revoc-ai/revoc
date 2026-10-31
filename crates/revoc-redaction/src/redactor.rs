//! [`RevocRedactor`] — implements the [`Redactor`] trait for LLM and MCP bodies.
//!
//! # Privacy invariant (SPEC.md §23 Rule 2)
//! This module **never** logs original matched values. Only entity types and
//! field names appear in log output.

use std::collections::HashMap;

use tracing::info;

use revoc_core::{
    Finding, FindingType, PiiEntityType, PolicyDecision, Redactor, RevocError,
};
use revoc_telemetry::RevocMetrics;

use crate::{
    json_mutator::{apply_span_redactions, get_field_text, normalize_body_fields, SpanReplacement},
    strategy::strategy_for,
};

// ── RevocRedactor ─────────────────────────────────────────────────────────────

/// Applies redaction strategies to LLM and MCP request/response bodies.
pub struct RevocRedactor {
    #[allow(dead_code)]
    metrics: &'static RevocMetrics,
}

impl RevocRedactor {
    /// Create a new redactor using the global metrics singleton.
    pub fn new(metrics: &'static RevocMetrics) -> Self {
        Self { metrics }
    }
}

impl Redactor for RevocRedactor {
    fn redact_body(
        &self,
        body: &[u8],
        findings: &[Finding],
        decision: &PolicyDecision,
    ) -> Result<(Vec<u8>, Vec<Finding>), RevocError> {
        redact_impl(body, findings, decision)
    }

    fn redact_mcp_result(
        &self,
        result_json: &[u8],
        findings: &[Finding],
        decision: &PolicyDecision,
    ) -> Result<(Vec<u8>, Vec<Finding>), RevocError> {
        // MCP results use the same strategy: scan for content fields in the result JSON
        redact_impl(result_json, findings, decision)
    }
}

// ── Implementation ────────────────────────────────────────────────────────────

fn redact_impl(
    body: &[u8],
    findings: &[Finding],
    decision: &PolicyDecision,
) -> Result<(Vec<u8>, Vec<Finding>), RevocError> {
    // Filter to findings that should be redacted
    let applicable: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            // Must have a span to know where to redact
            f.span.is_some()
            // Skip tool manifest risk — audit only (SPEC.md §14)
            && f.finding_type != FindingType::ToolManifestRisk
            // Apply when decision requires redaction OR finding is high-severity
            && (decision.effective_action.requires_redaction() || f.is_high_severity())
        })
        .collect();

    if applicable.is_empty() {
        return Ok((body.to_vec(), findings.to_vec()));
    }

    // D8: findings with `was_normalized = true` carry span offsets computed
    // against the *normalized* field text (e.g. zero-width chars stripped),
    // not the raw body. Re-serialize those fields' values in their normalized
    // form first so the byte offsets below land on valid char boundaries in
    // the body we actually redact (SPEC.md §9 D8).
    let normalized_fields: Vec<String> = applicable
        .iter()
        .filter(|f| f.was_normalized)
        .filter_map(|f| f.span.as_ref().map(|s| s.field.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let body: std::borrow::Cow<'_, [u8]> = if normalized_fields.is_empty() {
        std::borrow::Cow::Borrowed(body)
    } else {
        std::borrow::Cow::Owned(normalize_body_fields(body, &normalized_fields)?)
    };
    let body = body.as_ref();

    // Parse body once for immutable text extraction (needed by Hash strategy)
    let parsed = serde_json::from_slice::<serde_json::Value>(body)
        .unwrap_or(serde_json::Value::Null);

    // Build span replacements grouped by field path
    let mut field_groups: HashMap<String, Vec<SpanReplacement>> = HashMap::new();

    for finding in &applicable {
        let Some(span) = finding.span.as_ref() else {
            // Filtered to f.span.is_some() above — defensive skip if absent.
            continue;
        };
        let strategy = strategy_for(finding);

        // Extract original text from the parsed JSON (for Hash strategy)
        // NEVER log this value — it is used only for hashing
        let original = get_field_text(&parsed, &span.field)
            .and_then(|s| {
                let start = span.start.min(s.len());
                let end = span.end.min(s.len());
                (start < end).then(|| s[start..end].to_string())
            })
            .unwrap_or_default();

        let entity = finding
            .pii_entity
            .clone()
            .unwrap_or_else(|| PiiEntityType::Custom("UNKNOWN".into()));

        let replacement = strategy.apply(&original, &entity);

        field_groups
            .entry(span.field.clone())
            .or_default()
            .push(SpanReplacement {
                start: span.start,
                end: span.end,
                replacement,
            });
    }

    let redactions: Vec<(String, Vec<SpanReplacement>)> = field_groups.into_iter().collect();
    let redacted_body = apply_span_redactions(body, &redactions)?;

    // Mark the applicable findings as redacted
    let mut modified_findings = findings.to_vec();
    for f in &mut modified_findings {
        if f.span.is_some()
            && f.finding_type != FindingType::ToolManifestRisk
            && (decision.effective_action.requires_redaction() || f.is_high_severity())
        {
            f.redaction_applied = true;
        }
    }

    // Log entity types and field names — NEVER log matched values
    let entity_types: Vec<String> = applicable
        .iter()
        .filter_map(|f| f.pii_entity.as_ref())
        .map(ToString::to_string)
        .collect();

    info!(
        count = applicable.len(),
        entity_types = ?entity_types,
        "Redacted {} findings from body",
        applicable.len()
    );

    Ok((redacted_body, modified_findings))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use revoc_core::{
        DetectionTier, Finding, FindingType, PiiEntityType, PolicyDecision,
        Severity, TextSpan,
    };
    use revoc_telemetry::RevocMetrics;

    fn redactor() -> RevocRedactor {
        RevocRedactor::new(RevocMetrics::global())
    }

    fn redact_decision() -> PolicyDecision {
        PolicyDecision::redact("test", vec!["pii_ssn_v1".into()])
    }

    /// Build a JSON body with a single user message.
    fn user_body(content: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": content}]
        }))
        .unwrap()
    }

    /// Build a finding with a span into messages[0].content.
    fn msg_finding(
        ft: FindingType,
        entity: PiiEntityType,
        start: usize,
        end: usize,
    ) -> Finding {
        let mut f = Finding::new(ft, Severity::High, DetectionTier::Regex).with_pii(entity);
        f.span = Some(TextSpan {
            start,
            end,
            field: "messages[0].content".into(),
            value: None,
        });
        f
    }

    // ── Redaction correctness ─────────────────────────────────────────────────

    #[test]
    fn test_ssn_not_in_output_after_redaction() {
        // "My SSN is 123-45-6789" — SSN starts at byte 10, len 11
        let body = user_body("My SSN is 123-45-6789");
        let finding = msg_finding(FindingType::Pii, PiiEntityType::UsSsn, 10, 21);
        let (out, findings) = redactor().redact_body(&body, &[finding], &redact_decision()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = json["messages"][0]["content"].as_str().unwrap();
        assert!(!content.contains("123-45-6789"), "SSN must be removed from output");
        assert!(findings[0].redaction_applied);
    }

    #[test]
    fn test_email_masked_as_redacted_email() {
        // "Contact: alice@example.com" — email starts at byte 9, len 17
        let body = user_body("Contact: alice@example.com");
        let finding = msg_finding(FindingType::Pii, PiiEntityType::EmailAddress, 9, 26);
        let (out, _) = redactor().redact_body(&body, &[finding], &redact_decision()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = json["messages"][0]["content"].as_str().unwrap();
        assert!(!content.contains("alice@"), "Original email must not appear");
        assert!(content.contains("REDACTED"), "Masked content must contain REDACTED");
    }

    #[test]
    fn test_aws_key_hashed_in_output() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        let body = user_body(&format!("key: {key}"));
        // "key: " = 5 bytes
        let finding = msg_finding(FindingType::SecretExposure, PiiEntityType::AwsAccessKey, 5, 5 + key.len());
        let (out, _) = redactor().redact_body(&body, &[finding], &redact_decision()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = json["messages"][0]["content"].as_str().unwrap();
        assert!(!content.contains("AKIA"), "AWS key must not appear in output");
        assert!(content.contains("[hash:"), "AWS key must be replaced with hash");
    }

    #[test]
    fn test_credit_card_removed_from_output() {
        let body = user_body("card: 4532015112830366");
        let finding = msg_finding(FindingType::Pii, PiiEntityType::CreditCard, 6, 22);
        let (out, _) = redactor().redact_body(&body, &[finding], &redact_decision()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = json["messages"][0]["content"].as_str().unwrap();
        assert!(!content.contains("4532"), "Credit card must be removed");
    }

    #[test]
    fn test_multiple_findings_same_field_all_applied() {
        // "SSN: 123-45-6789 email: foo@bar.com"
        let text = "SSN: 123-45-6789 email: foo@bar.com";
        let body = user_body(text);
        let ssn = msg_finding(FindingType::Pii, PiiEntityType::UsSsn, 5, 16);
        let email = msg_finding(FindingType::Pii, PiiEntityType::EmailAddress, 23, 34);

        let (out, findings) =
            redactor().redact_body(&body, &[ssn, email], &redact_decision()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = json["messages"][0]["content"].as_str().unwrap();
        assert!(!content.contains("123-45-6789"), "SSN must be gone");
        assert!(!content.contains("foo@bar"), "email must be gone");
        assert!(findings.iter().all(|f| f.redaction_applied));
    }

    #[test]
    fn test_finding_without_span_skipped() {
        // Finding with no span should not trigger redaction
        let body = user_body("hello world");
        let mut f = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
            .with_pii(PiiEntityType::UsSsn);
        f.span = None;

        let (out, findings) = redactor().redact_body(&body, &[f], &redact_decision()).unwrap();

        let json_out: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            json_out["messages"][0]["content"].as_str().unwrap(),
            "hello world",
            "Body must be unchanged when finding has no span"
        );
        assert!(!findings[0].redaction_applied);
    }

    #[test]
    fn test_output_valid_json_after_redaction() {
        let body = user_body("My SSN is 123-45-6789 and email is test@test.com");
        let ssn = msg_finding(FindingType::Pii, PiiEntityType::UsSsn, 10, 21);
        let (out, _) = redactor().redact_body(&body, &[ssn], &redact_decision()).unwrap();

        let result = serde_json::from_slice::<serde_json::Value>(&out);
        assert!(result.is_ok(), "Output must be valid JSON after redaction");
    }

    #[test]
    fn test_all_other_fields_unchanged() {
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user",   "content": "My SSN is 123-45-6789"}
            ]
        }))
        .unwrap();

        let ssn = {
            let mut f = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
                .with_pii(PiiEntityType::UsSsn);
            f.span = Some(TextSpan {
                start: 10,
                end: 21,
                field: "messages[1].content".into(),
                value: None,
            });
            f
        };

        let (out, _) = redactor().redact_body(&body, &[ssn], &redact_decision()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(json["model"].as_str().unwrap(), "gpt-4o", "model field must be unchanged");
        assert_eq!(
            json["messages"][0]["content"].as_str().unwrap(),
            "You are a helpful assistant.",
            "system message must be unchanged"
        );
    }

    #[test]
    fn test_tool_manifest_risk_not_redacted() {
        let body = user_body("dangerous tool description");
        let mut f =
            Finding::new(FindingType::ToolManifestRisk, Severity::High, DetectionTier::ManifestAnalysis);
        f.span = Some(TextSpan {
            start: 0,
            end: 9,
            field: "messages[0].content".into(),
            value: None,
        });

        let (out, findings) = redactor().redact_body(&body, &[f], &redact_decision()).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            json["messages"][0]["content"].as_str().unwrap(),
            "dangerous tool description",
            "ToolManifestRisk finding must not modify the body"
        );
        assert!(!findings[0].redaction_applied, "ToolManifestRisk must not be marked redacted");
    }

    #[test]
    fn test_redact_mcp_result_targets_content_field() {
        let result = serde_json::to_vec(&serde_json::json!({
            "content": "SSN: 123-45-6789 in MCP result"
        }))
        .unwrap();

        let mut f = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
            .with_pii(PiiEntityType::UsSsn);
        f.span = Some(TextSpan {
            start: 5,
            end: 16,
            field: "content".into(),
            value: None,
        });

        let (out, _) = redactor()
            .redact_mcp_result(&result, &[f], &redact_decision())
            .unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = json["content"].as_str().unwrap();
        assert!(!content.contains("123-45-6789"), "SSN must be redacted from MCP result");
    }

    // ── Proptest: must never panic, output must be valid UTF-8 ────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest_no_panic_valid_utf8(
            text in ".*",
            starts in proptest::collection::vec(0usize..300, 0..5),
            ends   in proptest::collection::vec(0usize..300, 0..5),
        ) {
            let body = serde_json::to_vec(&serde_json::json!({
                "messages": [{"role": "user", "content": text}]
            })).unwrap();

            let spans: Vec<SpanReplacement> = starts
                .iter()
                .zip(ends.iter())
                .map(|(&s, &e)| SpanReplacement {
                    start: s.min(e),
                    end: s.max(e),
                    replacement: "[R]".into(),
                })
                .collect();

            let result = apply_span_redactions(
                &body,
                &[("messages[0].content".into(), spans)],
            );

            // Must not panic. If Ok, output must be valid UTF-8.
            if let Ok(out) = result {
                prop_assert!(
                    std::str::from_utf8(&out).is_ok(),
                    "Redacted output must be valid UTF-8"
                );
            }
        }
    }
}
