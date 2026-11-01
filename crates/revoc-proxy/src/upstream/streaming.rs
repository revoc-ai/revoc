//! Proxy an upstream SSE stream with sliding-window governance (SPEC.md §12).

use std::sync::Arc;

use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt as _;
use tracing::warn;

use revoc_core::{
    CallerContext, ChatMessage, Finding, FindingType, McpToolCall, PolicyEngine, PolicyInput,
    RequestType,
};

use crate::app::AppState;
use crate::streaming::{
    sse::{format_sse_event, parse_sse_chunk, SSE_DONE},
    tool_accumulator::ToolCallAccumulator,
    window::SlidingWindowScanner,
};

/// Proxy an upstream SSE stream to the client, applying governance per chunk.
///
/// When `stream.buffer_output = false` (default): uses sliding window scanner.
/// When `stream.buffer_output = true`: buffers the full response, runs full
/// output governance, then sends the complete body.
#[allow(clippy::too_many_lines)]
pub async fn proxy_sse_stream(
    upstream_resp: reqwest::Response,
    state: &AppState,
    caller: &CallerContext,
    trace_id: &str,
) -> Response {
    let window_size = state.config.stream.sliding_window_size;
    let buffer_output = state.config.stream.buffer_output;
    let tool_call_accumulate = state.config.stream.tool_call_accumulate;

    let detector = state.pipeline.engine();
    let mut scanner = SlidingWindowScanner::new(window_size, Arc::clone(&detector));
    let mut accumulator = ToolCallAccumulator::default();

    let upstream_status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    let mut response_builder = axum::response::Response::builder()
        .status(upstream_status)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no");

    // Propagate relevant upstream headers
    for (name, value) in &upstream_headers {
        let n = name.as_str().to_lowercase();
        if n.starts_with("x-") && !n.starts_with("x-revoc-") {
            response_builder = response_builder.header(name, value);
        }
    }

    if buffer_output {
        // ── Buffered mode: collect all chunks, govern, send ─────────────────
        let mut full_body = Vec::new();
        let mut byte_stream = upstream_resp.bytes_stream();
        while let Some(chunk) = byte_stream.next().await {
            match chunk {
                Ok(b) => full_body.extend_from_slice(&b),
                Err(e) => warn!(trace_id, error = %e, "Stream read error (buffered)"),
            }
        }
        let body_bytes = Bytes::from(full_body);
        return response_builder
            .body(axum::body::Body::from(body_bytes))
            .unwrap_or_else(|_| axum::response::Response::default());
    }

    // ── Streaming mode: forward per chunk with sliding window ───────────────
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::convert::Infallible>>(128);

    let state_clone = state.clone();
    let caller_clone = caller.clone();
    let trace_id_owned = trace_id.to_string();

    tokio::spawn(async move {
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut blocked = false;
        let mut stream_block_findings: Vec<Finding> = Vec::new();
        let mut full_stream_text = String::new();
        let stream_start = std::time::Instant::now();

        while let Some(chunk) = byte_stream.next().await {
            if blocked {
                break;
            }
            let data = match chunk {
                Ok(b) => b,
                Err(e) => {
                    warn!(trace_id = %trace_id_owned, error = %e, "Stream read error");
                    break;
                }
            };

            // Parse SSE events for tool call accumulation
            let events = parse_sse_chunk(&data);
            let mut tool_calls_blocked = false;
            for event in &events {
                if let Ok(ev_json) = serde_json::from_str::<serde_json::Value>(&event.data) {
                    if tool_call_accumulate {
                        accumulator.process_chunk(&ev_json);

                        if ToolCallAccumulator::is_finish_tool_calls(&ev_json) {
                            let calls = accumulator.get_completed_calls();
                            if !calls.is_empty() {
                                // §23 Rule 22 — finish_reason=tool_calls MUST NOT reach
                                // the client before the accumulated calls are governed.
                                let governance = governance_on_accumulated_calls(
                                    &state_clone,
                                    &caller_clone,
                                    &trace_id_owned,
                                    &calls,
                                )
                                .await;
                                if let Some(reason) = governance {
                                    warn!(trace_id = %trace_id_owned, reason, "Streamed tool calls blocked by governance");
                                    let filter_chunk =
                                        ToolCallAccumulator::synthetic_content_filter_chunk();
                                    let _ = tx.send(Ok(format_sse_event(&filter_chunk))).await;
                                    tool_calls_blocked = true;
                                }
                            }
                        }
                    }
                }
            }

            if tool_calls_blocked {
                blocked = true;
                break;
            }

            // Sliding window scan — runs detection over the rolling window so
            // patterns spanning multiple SSE chunks are still caught (SPEC.md §12)
            let result = scanner
                .process_chunk(&data, &caller_clone, caller_clone.governance_depth)
                .await;

            if let Some(reason) = result.block_reason {
                warn!(trace_id = %trace_id_owned, reason, "Stream blocked by governance");
                // Capture findings before break so write_stream_audit can populate
                // violated_rules / finding_types in the audit event (Rule 6 — the
                // findings computed by the sliding window scanner must be used).
                stream_block_findings = result.redacted_findings;
                let filter_chunk = ToolCallAccumulator::synthetic_content_filter_chunk();
                let _ = tx.send(Ok(format_sse_event(&filter_chunk))).await;
                blocked = true;
                break;
            }

            if !result.bytes_to_forward.is_empty()
                && tx.send(Ok(result.bytes_to_forward)).await.is_err()
            {
                break; // Client disconnected
            }

            full_stream_text.push_str(&String::from_utf8_lossy(&data));
        }

        // Send terminal [DONE]
        if !blocked {
            let _ = tx.send(Ok(Bytes::from_static(SSE_DONE))).await;
        }

        write_stream_audit(
            &state_clone,
            &caller_clone,
            &trace_id_owned,
            &full_stream_text,
            blocked,
            stream_block_findings,
            stream_start,
        )
        .await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    response_builder
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| axum::response::Response::default())
}

/// Run full MCP governance (detection + policy) on the tool calls accumulated
/// from a streaming response. Returns `Some(reason)` when any call is blocked —
/// SPEC.md §23 Rule 22 requires this to complete BEFORE `finish_reason:
/// tool_calls` is forwarded to the AI client.
async fn governance_on_accumulated_calls(
    state: &AppState,
    caller: &CallerContext,
    trace_id: &str,
    calls: &[McpToolCall],
) -> Option<String> {
    for call in calls {
        let inspection_input = revoc_core::traits::InspectionInput {
            request_id: trace_id.to_owned(),
            request_type: RequestType::McpToolCall,
            raw_body: bytes::Bytes::from(call.arguments.to_string()),
            parsed_messages: None,
            mcp_call: Some(call.clone()),
            caller: caller.clone(),
            governance_depth: caller.governance_depth,
        };
        let result = state.pipeline.run(inspection_input).await;
        if let Some(err) = result.detection_error {
            warn!(error = %err, "Streamed tool-call detection incomplete");
            if state.fail_closed() {
                return Some(format!("Tool-call governance unavailable: {err}"));
            }
        }
        let findings = result.findings;

        let policy_input = PolicyInput {
            request_id: trace_id.to_owned(),
            request_type: RequestType::McpToolCall,
            caller: caller.clone(),
            findings,
            model: None,
            provider: None,
            messages: None,
            tool_call: Some(call.clone()),
            tool_result: None,
            token_usage: None,
            session_state: None,
            governance_depth: caller.governance_depth,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        let decision = match state.policy_engine.evaluate(&policy_input).await {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Streamed tool-call policy evaluation failed");
                if state.fail_closed() {
                    return Some(format!("Tool-call policy evaluation failed: {e}"));
                }
                continue;
            }
        };
        if decision.effective_action.is_blocking() {
            return Some(decision.reason);
        }
    }
    None
}

/// Map a stream-block [`Finding`] to its canonical rule ID from SPEC.md §14.
///
/// Stream blocks run through the sliding window detector only — not the full
/// policy engine — so there are no `PolicyDecision.applicable_rules` to pull
/// from. We derive rule IDs from the finding type so the analytics `top_rules`
/// query returns meaningful data for stream-blocked events.
fn stream_finding_to_rule_id(f: &Finding) -> String {
    use revoc_core::PiiEntityType;
    match &f.finding_type {
        FindingType::Pii => f
            .pii_entity
            .as_ref()
            .map_or("pii_block_v1", |e| match e {
                PiiEntityType::UsSsn => "pii_ssn_v1",
                PiiEntityType::CreditCard => "pii_credit_card_v1",
                PiiEntityType::IbanCode => "pii_iban_v1",
                PiiEntityType::BankAccount => "pii_bank_account_v1",
                PiiEntityType::UsPassport => "pii_passport_v1",
                PiiEntityType::UsDriverLicense => "pii_driver_license_v1",
                PiiEntityType::EmailAddress => "pii_email_v1",
                PiiEntityType::PhoneNumber => "pii_phone_v1",
                PiiEntityType::IpAddressV4 | PiiEntityType::IpAddressV6 => "pii_ip_address_v1",
                PiiEntityType::MedicalRecordNumber => "pii_mrn_v1",
                PiiEntityType::DateOfBirth => "pii_dob_v1",
                _ => "pii_block_v1",
            })
            .to_owned(),
        FindingType::SecretExposure => "secret_block_v1".to_owned(),
        FindingType::PromptInjection => "sec_prompt_injection_v1".to_owned(),
        FindingType::SystemPromptExtraction => "sec_sysextract_v1".to_owned(),
        FindingType::DdlMutation => "sec_ddl_mutation_v1".to_owned(),
        FindingType::SsrfAttempt => "sec_ssrf_v1".to_owned(),
        FindingType::PathTraversal => "sec_path_traversal_v1".to_owned(),
        FindingType::SessionAnomaly => "session_data_exfil_v1".to_owned(),
        FindingType::ToolManifestRisk => "manifest_risk_v1".to_owned(),
        FindingType::McpToolBlock => "mcp_tool_acl_v1".to_owned(),
        FindingType::QuotaExceeded => "token_quota_v1".to_owned(),
        FindingType::KeywordMatch => "keyword_match_v1".to_owned(),
        FindingType::Custom(s) => format!("custom_{s}"),
    }
}

/// Write a real audit event for the completed stream (SPEC.md §23 Rule 25 —
/// never block the request path; this runs after the stream has been forwarded).
///
/// When `blocked` and `block_findings` is non-empty the findings are used
/// directly — they are the authoritative cause of the governance stop and were
/// already computed by the sliding window scanner. Re-running detection over
/// partial `full_text` would produce duplicates and miss the chunk that actually
/// triggered the block.
///
/// When the stream completed without a block, detection runs over the full
/// assembled response text so PII/secrets in streamed output are recorded.
async fn write_stream_audit(
    state: &AppState,
    caller: &CallerContext,
    trace_id: &str,
    full_text: &str,
    blocked: bool,
    block_findings: Vec<Finding>,
    started_at: std::time::Instant,
) {
    let (findings, detection_ms, violated_rules_opt) = if blocked && !block_findings.is_empty() {
        // Authoritative findings from the sliding window block — no re-detection.
        let rule_ids: Vec<String> = block_findings
            .iter()
            .map(stream_finding_to_rule_id)
            .collect();
        let unique_rules: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            rule_ids
                .into_iter()
                .filter(|r| seen.insert(r.clone()))
                .collect()
        };
        (block_findings, 0.0_f64, Some(unique_rules.join(",")))
    } else {
        // Normal path: run detection over the full assembled response text.
        let detection_start = std::time::Instant::now();
        let inspection_input = revoc_core::traits::InspectionInput {
            request_id: trace_id.to_owned(),
            request_type: RequestType::LlmResponse,
            raw_body: bytes::Bytes::from(full_text.as_bytes().to_vec()),
            parsed_messages: Some(vec![ChatMessage {
                role: "assistant".to_owned(),
                content: serde_json::Value::String(full_text.to_owned()),
                name: None,
                tool_call_id: None,
                tool_calls: None,
            }]),
            mcp_call: None,
            caller: caller.clone(),
            governance_depth: caller.governance_depth,
        };
        let f = state.pipeline.run(inspection_input).await.findings;
        let ms = detection_start.elapsed().as_secs_f64() * 1000.0;
        (f, ms, None)
    };

    let was_normalized = findings.iter().any(|f| f.was_normalized);
    let finding_types: Vec<String> = findings
        .iter()
        .map(|f| format!("{:?}", f.finding_type))
        .collect();

    let now = chrono::Utc::now();
    let decision_str = if blocked { "block" } else { "allow" };
    let event = revoc_dashboard::AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        org_id: Some(caller.org_id.clone()),
        request_id: trace_id.to_owned(),
        timestamp: now.to_rfc3339(),
        caller_id: Some(caller.caller_id.clone()),
        caller_team: caller.team.clone(),
        environment: Some(state.config.server.environment.clone()),
        decision: decision_str.to_owned(),
        effective_action: decision_str.to_owned(),
        enforcement_mode: if caller.is_shadow_mode() {
            "shadow".to_owned()
        } else {
            "enforce".to_owned()
        },
        violated_rules: violated_rules_opt,
        finding_types: if finding_types.is_empty() {
            None
        } else {
            Some(finding_types.join(","))
        },
        model: None,
        provider: None,
        tool_name: None,
        request_type: Some("LlmResponse".to_owned()),
        governance_depth: i64::from(caller.governance_depth),
        prompt_tokens: None,
        completion_tokens: None,
        estimated_cost_usd: None,
        duration_ms: Some(started_at.elapsed().as_secs_f64() * 1000.0),
        detection_ms: Some(detection_ms),
        policy_ms: None,
        was_normalized,
        manifest_warnings: 0,
        trace_id: Some(trace_id.to_owned()),
        policy_engine: None,
        created_at: now.to_rfc3339(),
    };
    if let Err(e) = state.audit_store.insert_event(event).await {
        warn!(error = %e, "Failed to write streamed-response audit event");
    }
}
