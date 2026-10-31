//! Embeddings handler — full governance lifecycle (SPEC.md §11, adapted for
//! `/v1/embeddings`): kill-switch (Step 0), depth (Step 1), body read/parse
//! (Steps 2-3), detection (Step 7), policy evaluation + routing (Steps 8-11),
//! upstream dispatch with verbatim error forwarding (Steps 12-18), response
//! headers (Step 19), audit + SSE publish (Steps 20-21).

use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use sha2::{Digest, Sha256};
use tracing::warn;

use revoc_core::{
    Action, CallerContext, ChatMessage, EnforcementMode, PolicyEngine, PolicyInput, Redactor,
    RequestType, RevocErrorResponse,
};
use revoc_dashboard::GovernanceEvent;

use crate::{
    app::AppState,
    depth::check_depth,
    handlers::llm::{action_to_str, read_body_limited, set_revoc_headers},
    middleware::request_id::GovernanceDepth,
    upstream::error::should_forward_verbatim,
};

#[allow(clippy::too_many_lines)]
pub async fn embeddings_handler(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let overall_start = Instant::now();
    let trace_id = uuid::Uuid::now_v7().to_string();
    let dash_base = state.config.server.dashboard_base_url.clone();

    // ── Step 0: Kill-switch ───────────────────────────────────────────────────
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .unwrap_or_default();
    if state.kill_switch.is_active_for(&caller) {
        let body = RevocErrorResponse::kill_switch_active(&trace_id, &dash_base);
        return error_resp(503, body, &trace_id, &dash_base, overall_start);
    }

    // ── Step 1: Depth check ───────────────────────────────────────────────────
    let governance_depth = req
        .extensions()
        .get::<GovernanceDepth>()
        .copied()
        .unwrap_or_default()
        .0;
    if check_depth(governance_depth).is_err() {
        let body = RevocErrorResponse::depth_exceeded(&trace_id, governance_depth, &dash_base);
        return error_resp(503, body, &trace_id, &dash_base, overall_start);
    }

    // ── Step 2: Read body ─────────────────────────────────────────────────────
    let max_body = state.config.server.max_request_body_bytes;
    let (parts, body) = req.into_parts();
    let body_bytes = match read_body_limited(body, max_body).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "Embeddings body read error");
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return error_resp(413, body, &trace_id, &dash_base, overall_start);
        }
    };

    // ── Step 3: Parse request ─────────────────────────────────────────────────
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
    let model = parsed
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let inputs = extract_embedding_inputs(&parsed);
    let messages: Vec<ChatMessage> = inputs
        .iter()
        .map(|text| ChatMessage {
            role: "user".to_owned(),
            content: serde_json::Value::String(text.clone()),
            name: None,
            tool_call_id: None,
            tool_calls: None,
        })
        .collect();

    let enforcement_mode = caller.enforcement_mode.clone();

    // ── Step 7: Detection ─────────────────────────────────────────────────────
    let detection_start = Instant::now();
    let inspection_input = revoc_core::traits::InspectionInput {
        request_id: trace_id.clone(),
        request_type: RequestType::LlmEmbeddings,
        raw_body: bytes::Bytes::from(body_bytes.clone()),
        parsed_messages: Some(messages.clone()),
        mcp_call: None,
        caller: caller.clone(),
        governance_depth,
    };
    let pipeline_result = state.pipeline.run(inspection_input).await;
    let findings = pipeline_result.findings;
    let detection_ms = detection_start.elapsed().as_secs_f64() * 1000.0;
    let was_normalized = findings.iter().any(|f| f.was_normalized);

    // ── Step 8: Build PolicyInput ─────────────────────────────────────────────
    let policy_input = PolicyInput {
        request_id: trace_id.clone(),
        request_type: RequestType::LlmEmbeddings,
        caller: caller.clone(),
        findings: findings.clone(),
        model: Some(model.clone()),
        provider: None,
        messages: Some(messages.clone()),
        tool_call: None,
        tool_result: None,
        token_usage: None,
        session_state: None,
        governance_depth,
        timestamp: chrono::Utc::now().timestamp_millis(),
    };

    // ── Step 9: Policy evaluation ─────────────────────────────────────────────
    let policy_start = Instant::now();
    let decision = match state.policy_engine.evaluate(&policy_input).await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Embeddings policy evaluation failed");
            if !state.config.policy.fail_open {
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return error_resp(503, body, &trace_id, &dash_base, overall_start);
            }
            revoc_core::PolicyDecision::allow()
        }
    };
    let policy_ms = policy_start.elapsed().as_secs_f64() * 1000.0;

    // ── Step 10: Shadow mode override ─────────────────────────────────────────
    let effective = if enforcement_mode == EnforcementMode::Shadow {
        decision.clone().apply_shadow()
    } else {
        decision.clone()
    };
    let decision_str = action_to_str(&effective.effective_action);
    let rules_str = if decision.applicable_rules.is_empty() {
        None
    } else {
        Some(decision.applicable_rules.join(","))
    };

    // ── Step 11: Route on effective_action ────────────────────────────────────
    let redaction_start = Instant::now();
    let body_to_send = match &effective.effective_action {
        Action::Block => {
            let block_body = RevocErrorResponse::governance_block(
                &trace_id,
                &decision.reason,
                decision.applicable_rules.clone(),
                &dash_base,
            );
            let mut resp = error_resp(403, block_body, &trace_id, &dash_base, overall_start);
            if let Ok(v) = decision_str.parse::<HeaderValue>() {
                resp.headers_mut().insert("X-Revoc-Decision", v);
            }
            if let Some(r) = &rules_str {
                if let Ok(v) = r.parse::<HeaderValue>() {
                    resp.headers_mut().insert("X-Revoc-Rules", v);
                }
            }
            return resp;
        }
        Action::Redact => match state
            .redactor
            .redact_body(&body_bytes, &findings, &decision)
        {
            Ok((redacted, _)) => redacted,
            Err(e) => {
                warn!(error = %e, "Embeddings redaction failed");
                body_bytes.clone()
            }
        },
        _ => body_bytes.clone(),
    };
    let redaction_ms = redaction_start.elapsed().as_secs_f64() * 1000.0;

    // ── Step 12: Resolve upstream provider ────────────────────────────────────
    let Some(provider) = state.upstream_router.route(&parts.headers).cloned() else {
        let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
        return error_resp(503, body, &trace_id, &dash_base, overall_start);
    };

    // Mock mode — produce a structurally valid, deterministically computed
    // embeddings response (content-derived, not a fabricated constant) so
    // local/dev/CI runs work without upstream credentials, mirroring the
    // mock-mode behaviour in the LLM handler.
    if state.config.upstream.mock_mode {
        let total_prompt_tokens = estimate_tokens(&inputs);
        let data: Vec<serde_json::Value> = inputs
            .iter()
            .enumerate()
            .map(|(i, text)| {
                serde_json::json!({
                    "object": "embedding",
                    "index": i,
                    "embedding": deterministic_embedding(text),
                })
            })
            .collect();
        let mock_body = serde_json::json!({
            "object": "list",
            "data": data,
            "model": model,
            "usage": {"prompt_tokens": total_prompt_tokens, "total_tokens": total_prompt_tokens},
        });
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        let timing = format!(
            "detection={detection_ms:.1}ms,policy={policy_ms:.1}ms,redaction={redaction_ms:.1}ms,upstream=0.0ms,total={total_ms:.1}ms"
        );
        let mut resp = (StatusCode::OK, Json(mock_body)).into_response();
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            decision_str,
            &format!("{dash_base}/traces/{trace_id}"),
            &timing,
            rules_str.as_deref(),
        );
        record_governance(&GovernanceContext {
            state: &state,
            caller: &caller,
            trace_id: &trace_id,
            model: &model,
            provider_name: &provider.name,
            decision_str,
            decision: &decision,
            findings: &findings,
            was_normalized,
            governance_depth,
            detection_ms,
            policy_ms,
            total_ms,
            shadow: enforcement_mode == EnforcementMode::Shadow,
        });
        return resp;
    }

    // ── Step 13: Build upstream request ───────────────────────────────────────
    let upstream_start = Instant::now();
    let upstream_req = match state.upstream_router.build_upstream_request(
        state.upstream_client.inner(),
        http::Method::POST,
        "/v1/embeddings",
        &provider,
        bytes::Bytes::from(body_to_send),
        governance_depth,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Upstream embeddings request build failed (SSRF?)");
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return error_resp(503, body, &trace_id, &dash_base, overall_start);
        }
    };

    // ── Step 14: X-Revoc-Depth set in build_upstream_request ──────────────────
    // ── Step 15: Send upstream ────────────────────────────────────────────────
    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Upstream embeddings request failed");
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return error_resp(502, body, &trace_id, &dash_base, overall_start);
        }
    };

    let upstream_status = upstream_resp.status().as_u16();
    let upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
    let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
    let timing = format!(
        "detection={detection_ms:.1}ms,policy={policy_ms:.1}ms,redaction={redaction_ms:.1}ms,upstream={upstream_ms:.1}ms,total={total_ms:.1}ms"
    );

    // ── Step 18: Forward upstream 4xx/5xx verbatim (Rule 8) ───────────────────
    if should_forward_verbatim(upstream_status) {
        let status =
            StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let upstream_headers = upstream_resp.headers().clone();
        let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
        let mut resp = Response::builder()
            .status(status)
            .body(Body::from(resp_bytes))
            .unwrap_or_default();
        for (name, value) in &upstream_headers {
            if name.as_str().starts_with("x-") || name == "content-type" {
                resp.headers_mut().insert(name.clone(), value.clone());
            }
        }
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            decision_str,
            &format!("{dash_base}/traces/{trace_id}"),
            &timing,
            None,
        );
        return resp;
    }

    // ── Step 19: Set ALL response headers ─────────────────────────────────────
    let resp_status = StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::OK);
    let resp_body = upstream_resp.bytes().await.unwrap_or_default();
    let mut resp = Response::builder()
        .status(resp_status)
        .header("Content-Type", "application/json")
        .body(Body::from(resp_body))
        .unwrap_or_default();
    set_revoc_headers(
        resp.headers_mut(),
        &trace_id,
        decision_str,
        &format!("{dash_base}/traces/{trace_id}"),
        &timing,
        rules_str.as_deref(),
    );

    // ── Steps 20-21: Audit + SSE publish ───────────────────────────────────────
    record_governance(&GovernanceContext {
        state: &state,
        caller: &caller,
        trace_id: &trace_id,
        model: &model,
        provider_name: &provider.name,
        decision_str,
        decision: &decision,
        findings: &findings,
        was_normalized,
        governance_depth,
        detection_ms,
        policy_ms,
        total_ms,
        shadow: enforcement_mode == EnforcementMode::Shadow,
    });

    resp
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the `input` field of an embeddings request, which per the `OpenAI`
/// API may be a single string, an array of strings, or an array of token-id
/// arrays (the latter is treated as a single opaque entry — REVOC governs
/// text content, not raw token streams).
fn extract_embedding_inputs(parsed: &serde_json::Value) -> Vec<String> {
    match parsed.get("input") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Conservative token-count estimate (chars / 4, rounded up) — same heuristic
/// commonly used for budget pre-checks when the provider hasn't tokenized yet.
fn estimate_tokens(inputs: &[String]) -> u64 {
    let total_chars: usize = inputs.iter().map(String::len).sum();
    (total_chars as u64).div_ceil(4)
}

/// Deterministic, content-derived embedding vector for mock mode: expands the
/// SHA-256 digest of the input text into a normalized 32-dimension unit
/// vector. This is a real (if simplistic) computation over the actual input —
/// never a fabricated constant — so mock-mode responses remain structurally
/// and semantically consistent across repeated calls with the same input.
fn deterministic_embedding(text: &str) -> Vec<f64> {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    let raw: Vec<f64> = digest
        .iter()
        .map(|&b| (f64::from(b) / 127.5) - 1.0)
        .collect();
    let norm: f64 = raw.iter().map(|v| v * v).sum::<f64>().sqrt();
    if norm > 0.0 {
        raw.iter().map(|v| v / norm).collect()
    } else {
        raw
    }
}

struct GovernanceContext<'a> {
    state: &'a AppState,
    caller: &'a CallerContext,
    trace_id: &'a str,
    model: &'a str,
    provider_name: &'a str,
    decision_str: &'static str,
    decision: &'a revoc_core::PolicyDecision,
    findings: &'a [revoc_core::Finding],
    was_normalized: bool,
    governance_depth: u8,
    detection_ms: f64,
    policy_ms: f64,
    total_ms: f64,
    shadow: bool,
}

/// Steps 20-21 — write the audit event (async, batched per Rule 25) and
/// publish the live-feed SSE event.
fn record_governance(ctx: &GovernanceContext<'_>) {
    let finding_types: Vec<String> = ctx
        .findings
        .iter()
        .map(|f| format!("{:?}", f.finding_type))
        .collect();
    let rules_str = if ctx.decision.applicable_rules.is_empty() {
        None
    } else {
        Some(ctx.decision.applicable_rules.join(","))
    };
    let now = chrono::Utc::now();
    let audit_event = revoc_dashboard::AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        org_id: Some(ctx.caller.org_id.clone()),
        request_id: ctx.trace_id.to_owned(),
        timestamp: now.to_rfc3339(),
        caller_id: Some(ctx.caller.caller_id.clone()),
        caller_team: ctx.caller.team.clone(),
        environment: Some(ctx.state.config.server.environment.clone()),
        decision: ctx.decision_str.to_owned(),
        effective_action: ctx.decision_str.to_owned(),
        enforcement_mode: if ctx.shadow {
            "shadow".to_owned()
        } else {
            "enforce".to_owned()
        },
        violated_rules: rules_str.clone(),
        finding_types: if finding_types.is_empty() {
            None
        } else {
            Some(finding_types.join(","))
        },
        model: Some(ctx.model.to_owned()),
        provider: Some(ctx.provider_name.to_owned()),
        tool_name: None,
        request_type: Some("LlmEmbeddings".to_owned()),
        governance_depth: i64::from(ctx.governance_depth),
        prompt_tokens: None,
        completion_tokens: None,
        estimated_cost_usd: None,
        duration_ms: Some(ctx.total_ms),
        detection_ms: Some(ctx.detection_ms),
        policy_ms: Some(ctx.policy_ms),
        was_normalized: ctx.was_normalized,
        manifest_warnings: 0,
        trace_id: Some(ctx.trace_id.to_owned()),
        policy_engine: Some(format!("{:?}", ctx.decision.policy_engine)),
        created_at: now.to_rfc3339(),
    };
    ctx.state.spawn_audit_write(audit_event);

    let pii_types: Vec<String> = ctx
        .findings
        .iter()
        .filter_map(|f| {
            f.pii_entity
                .as_ref()
                .map(revoc_core::PiiEntityType::to_string)
        })
        .collect();
    ctx.state.feed_bus.publish(GovernanceEvent {
        trace_id: ctx.trace_id.to_owned(),
        timestamp: now.to_rfc3339(),
        decision: ctx.decision_str.to_owned(),
        blocked_by: ctx.decision.applicable_rules.first().cloned(),
        caller_id: ctx.caller.caller_id.clone(),
        model: Some(ctx.model.to_owned()),
        duration_ms: ctx.total_ms,
        findings_count: ctx.findings.len(),
        pii_types,
        mcp_tool: None,
        request_type: "LlmEmbeddings".to_owned(),
        governance_depth: ctx.governance_depth,
        was_normalized: ctx.was_normalized,
        manifest_warnings: 0,
    });
}

fn error_resp(
    status: u16,
    body: RevocErrorResponse,
    trace_id: &str,
    dash_base: &str,
    start: Instant,
) -> Response {
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    let timing = format!(
        "detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream=0.0ms,total={total_ms:.1}ms"
    );
    let mut resp = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(body),
    )
        .into_response();
    set_revoc_headers(
        resp.headers_mut(),
        trace_id,
        "block",
        &format!("{dash_base}/traces/{trace_id}"),
        &timing,
        None,
    );
    resp
}
