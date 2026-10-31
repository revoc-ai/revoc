//! Regex-based detection stage — the primary detection tier (SPEC.md §10).
//!
//! Pipeline:
//! 1. Extract all text fields from the `InspectionInput`.
//! 2. For each field: normalize (D8) → prepare scan targets (D10) →
//!    apply PII / secret / security / financial patterns.
//! 3. Return raw findings (deduplication happens in `revoc-pipeline`).

use async_trait::async_trait;
use tracing::warn;

use revoc_core::{
    DetectionStage, DetectionTier, Finding, FindingType, InspectionInput, RequestType, RevocError,
    TextSpan,
};

use crate::{
    encoding::prepare_scan_targets,
    normalization::normalize,
    patterns::{financial, pii, secrets, security},
};

/// Maximum number of bytes scanned after a security pattern match when
/// checking for suppression keywords (e.g. WHERE after DELETE FROM).
const POST_MATCH_WINDOW: usize = 512;

/// The Rust regex detection stage — always active, zero external dependencies.
#[derive(Debug, Default)]
pub struct RegexDetector;

#[allow(clippy::too_many_lines)]
#[async_trait]
impl DetectionStage for RegexDetector {
    fn name(&self) -> &'static str {
        "regex"
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Regex
    }

    async fn detect(&self, input: &InspectionInput) -> Result<Vec<Finding>, RevocError> {
        let mut findings: Vec<Finding> = Vec::new();
        let fields = extract_all_text_fields(input);

        for (field, raw_text) in &fields {
            // D8: normalize BEFORE any regex pass
            let n = normalize(raw_text);
            let targets = prepare_scan_targets(&n.text);

            for (text, was_decoded) in &targets {
                // ── PII patterns ────────────────────────────────────────────
                for pattern in pii::all_pii_patterns() {
                    for result in pattern.regex.find_iter(text) {
                        let m = match result {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(pattern = pattern.name, error = %e, "PII regex error");
                                continue;
                            }
                        };
                        let matched = &text[m.start()..m.end()];
                        if let Some(validator) = pattern.validator {
                            if !validator(matched) {
                                continue;
                            }
                        }
                        let mut f = Finding::new(
                            FindingType::Pii,
                            pattern.severity.clone(),
                            DetectionTier::Regex,
                        )
                        .with_span(TextSpan {
                            start: m.start(),
                            end: m.end(),
                            field: field.clone(),
                            value: None, // NEVER store matched value
                        })
                        .with_confidence(pattern.confidence)
                        .with_pii(pattern.entity_type.clone());
                        f.was_normalized = n.was_modified;
                        f.was_encoded = *was_decoded;
                        findings.push(f);
                    }
                }

                // ── Secret patterns ─────────────────────────────────────────
                for pattern in secrets::all_secret_patterns() {
                    for result in pattern.regex.find_iter(text) {
                        let m = match result {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(pattern = pattern.name, error = %e, "Secret regex error");
                                continue;
                            }
                        };
                        let mut f = Finding::new(
                            FindingType::SecretExposure,
                            pattern.severity.clone(),
                            DetectionTier::Regex,
                        )
                        .with_span(TextSpan {
                            start: m.start(),
                            end: m.end(),
                            field: field.clone(),
                            value: None,
                        })
                        .with_confidence(pattern.confidence)
                        .with_pii(pattern.entity_type.clone());
                        f.was_normalized = n.was_modified;
                        f.was_encoded = *was_decoded;
                        findings.push(f);
                    }
                }

                // ── Security patterns ───────────────────────────────────────
                for pattern in security::all_security_patterns() {
                    for result in pattern.regex.find_iter(text) {
                        let m = match result {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(
                                    pattern = pattern.name,
                                    error = %e,
                                    "Security regex error"
                                );
                                continue;
                            }
                        };

                        // Post-match suppression (e.g. DELETE_NO_WHERE)
                        if let Some(suppress_kw) = pattern.skip_if_after_contains {
                            let after = &text[m.end()..];
                            let window = &after[..after.len().min(POST_MATCH_WINDOW)];
                            if window.to_uppercase().contains(&suppress_kw.to_uppercase()) {
                                continue;
                            }
                        }

                        let mut f = Finding::new(
                            pattern.finding_type.clone(),
                            pattern.severity.clone(),
                            DetectionTier::Regex,
                        )
                        .with_span(TextSpan {
                            start: m.start(),
                            end: m.end(),
                            field: field.clone(),
                            value: None,
                        })
                        .with_confidence(pattern.confidence);
                        f.was_normalized = n.was_modified;
                        f.was_encoded = *was_decoded;
                        f.metadata.insert(
                            "pattern_name".to_string(),
                            serde_json::Value::String(pattern.name.to_string()),
                        );
                        findings.push(f);
                    }
                }

                // ── Financial patterns (reuse PiiPattern type) ──────────────
                for pattern in financial::all_financial_patterns() {
                    for result in pattern.regex.find_iter(text) {
                        let m = match result {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(
                                    pattern = pattern.name,
                                    error = %e,
                                    "Financial regex error"
                                );
                                continue;
                            }
                        };
                        let matched = &text[m.start()..m.end()];
                        if let Some(validator) = pattern.validator {
                            if !validator(matched) {
                                continue;
                            }
                        }
                        let mut f = Finding::new(
                            FindingType::Pii,
                            pattern.severity.clone(),
                            DetectionTier::Regex,
                        )
                        .with_span(TextSpan {
                            start: m.start(),
                            end: m.end(),
                            field: field.clone(),
                            value: None,
                        })
                        .with_confidence(pattern.confidence)
                        .with_pii(pattern.entity_type.clone());
                        f.was_normalized = n.was_modified;
                        f.was_encoded = *was_decoded;
                        findings.push(f);
                    }
                }
            }
        }

        // Sort by severity (descending) for consistent output
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        Ok(findings)
    }
}

/// Extract all scannable text fields from an `InspectionInput`.
///
/// Covers:
/// - `messages[N].content` strings and content-array `.text` parts
/// - `tool_call.arguments` — all string values recursively
/// - `tool_result` — all string values recursively
/// - Raw body fallback when nothing else is available
///
/// `pub` so tests can call it directly.
pub fn extract_all_text_fields(input: &InspectionInput) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();

    // Messages
    if let Some(messages) = &input.parsed_messages {
        for (i, msg) in messages.iter().enumerate() {
            match &msg.content {
                serde_json::Value::String(s) => {
                    fields.push((format!("messages[{i}].content"), s.clone()));
                }
                serde_json::Value::Array(parts) => {
                    for (j, part) in parts.iter().enumerate() {
                        if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                            fields.push((format!("messages[{i}].content[{j}].text"), t.to_owned()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // MCP tool call arguments (only for the call itself, not the result)
    if input.request_type != RequestType::McpToolResult {
        if let Some(call) = &input.mcp_call {
            extract_json_strings(&call.arguments, "tool_call.arguments", &mut fields);
        }
    }

    // MCP tool result: scan the raw JSON-RPC result body recursively
    if input.request_type == RequestType::McpToolResult {
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_slice::<serde_json::Value>(&input.raw_body)
        {
            for (key, val) in &map {
                extract_json_strings(val, key, &mut fields);
            }
        }
    }

    // Raw body fallback
    if fields.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&input.raw_body) {
            if !body_str.is_empty() {
                fields.push(("body".to_owned(), body_str.to_owned()));
            }
        }
    }

    fields
}

/// Recursively extract all string leaf values from a JSON value.
fn extract_json_strings(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::String(s) => {
            out.push((path.to_owned(), s.clone()));
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                extract_json_strings(val, &format!("{path}.{key}"), out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                extract_json_strings(val, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

// ── Convenience helpers for tests ─────────────────────────────────────────────

impl RegexDetector {
    /// Run detection synchronously (blocking) for use in non-async tests.
    #[cfg(test)]
    pub fn detect_sync(&self, input: &InspectionInput) -> Vec<Finding> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        rt.block_on(async { self.detect(input).await.unwrap_or_default() })
    }
}

/// Build a minimal `InspectionInput` containing `text` as a single user message.
#[cfg(test)]
pub(crate) fn make_test_input(text: &str) -> InspectionInput {
    use revoc_core::{CallerContext, ChatMessage, RequestType};
    InspectionInput {
        request_id: "test-req".into(),
        request_type: RequestType::LlmRequest,
        raw_body: bytes::Bytes::new(),
        parsed_messages: Some(vec![ChatMessage {
            role: "user".into(),
            content: serde_json::Value::String(text.into()),
            name: None,
            tool_call_id: None,
            tool_calls: None,
        }]),
        mcp_call: None,
        caller: CallerContext::default(),
        governance_depth: 0,
    }
}
