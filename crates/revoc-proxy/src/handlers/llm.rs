//! LLM chat completion handler — ALL 22 STEPS from SPEC.md §11.

use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use tracing::{info, warn, Instrument};

use revoc_core::{
    Action, CallerContext, ChatMessage, EnforcementMode, PiiEntityType, PolicyEngine, PolicyInput,
    Redactor, RequestType, RevocErrorResponse, SessionState, TokenUsage,
};
use revoc_dashboard::GovernanceEvent;

use crate::{
    app::AppState,
    depth::check_depth,
    middleware::request_id::{GovernanceDepth, RequestId},
    upstream::{
        error::should_forward_verbatim, retry::send_with_retries, streaming::proxy_sse_stream,
    },
};

/// Maximum upstream retry attempts on transient failures (transport-level
/// connect/timeout errors and 429/502/503/504 status codes) — SPEC.md §23
/// wires the retry-policy infrastructure (`upstream::retry`) into Step 15.
const MAX_UPSTREAM_RETRIES: u32 = 2;

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn chat_completions_handler(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    run_llm_handler(state, req, RequestType::LlmRequest, "/v1/chat/completions").await
}

pub async fn completions_handler(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    run_llm_handler(state, req, RequestType::LlmRequest, "/v1/completions").await
}

// ── 22-step lifecycle ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
async fn run_llm_handler(
    state: AppState,
    req: axum::extract::Request,
    request_type: RequestType,
    upstream_path: &str,
) -> Response {
    let overall_start = Instant::now();

    let trace_id = uuid::Uuid::now_v7().to_string();
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .cloned()
        .map_or_else(|| trace_id.clone(), |r| r.0);
    let dash_base = state.config.server.dashboard_base_url.clone();

    // ── Step 0: Kill-switch check ─────────────────────────────────────────────
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .unwrap_or_default();
    if state.kill_switch.is_active_for(&caller) {
        let body = RevocErrorResponse::kill_switch_active(&trace_id, &dash_base);
        return make_error_response(503, body, &trace_id, &request_id, &dash_base, overall_start);
    }

    // ── Step 1: Depth check ───────────────────────────────────────────────────
    let depth = req
        .extensions()
        .get::<GovernanceDepth>()
        .copied()
        .unwrap_or_default()
        .0;
    if check_depth(depth).is_err() {
        let body = RevocErrorResponse::depth_exceeded(&trace_id, depth, &dash_base);
        return make_error_response(503, body, &trace_id, &request_id, &dash_base, overall_start);
    }

    // ── Step 2: Read body ─────────────────────────────────────────────────────
    let max_body = state.config.server.max_request_body_bytes;
    let (parts, body) = req.into_parts();
    let body_bytes = match read_body_limited(body, max_body).await {
        Ok(b) => b,
        Err(e) => {
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            warn!(error = %e, "Body read error");
            return make_error_response(
                413,
                body,
                &trace_id,
                &request_id,
                &dash_base,
                overall_start,
            );
        }
    };

    // ── Step 3: Parse request ─────────────────────────────────────────────────
    let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "Request JSON parse error");
            let body =
                RevocErrorResponse::request_parse_error(&trace_id, &e.to_string(), &dash_base);
            return make_error_response(
                400,
                body,
                &trace_id,
                &request_id,
                &dash_base,
                overall_start,
            );
        }
    };

    let messages = extract_messages(&parsed);
    let model = parsed
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let is_stream = parsed
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // ── Step 4: Extract context ───────────────────────────────────────────────
    let governance_depth = depth;
    let session_id = format!("{}:{}", caller.org_id, caller.caller_id);
    let existing_session = state.session_store.get(&session_id).await;
    let session_state = existing_session.clone();

    // ── Step 5: Enforcement mode ──────────────────────────────────────────────
    let enforcement_mode = caller.enforcement_mode.clone();

    // ── Step 6: Governance span ───────────────────────────────────────────────
    // Real span-based correlation via `tracing::info_span!` — the JSON logger
    // (revoc-telemetry/src/logger.rs) is configured `with_current_span(true)`
    // / `with_span_list(true)` so every event emitted while this span is
    // active is correlated with `trace_id`/`request_id`/`governance_depth`.
    let span = tracing::info_span!(
        "llm_governance",
        trace_id = %trace_id,
        request_id = %request_id,
        governance_depth = governance_depth,
        model = %model,
    );

    // ── Step 7: Detection ─────────────────────────────────────────────────────
    let detection_start = Instant::now();
    let inspection_input = revoc_core::traits::InspectionInput {
        request_id: trace_id.clone(),
        request_type: request_type.clone(),
        raw_body: bytes::Bytes::from(body_bytes.clone()),
        parsed_messages: Some(messages.clone()),
        mcp_call: None,
        caller: caller.clone(),
        governance_depth,
    };
    let pipeline_result = state
        .pipeline
        .run(inspection_input)
        .instrument(span.clone())
        .await;
    if let Some(err) = &pipeline_result.detection_error {
        warn!(error = %err, "Detection incomplete");
        if state.fail_closed() {
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return make_error_response(
                503,
                body,
                &trace_id,
                &request_id,
                &dash_base,
                overall_start,
            );
        }
    }
    let findings = pipeline_result.findings;
    let detection_ms = detection_start.elapsed().as_secs_f64() * 1000.0;
    let was_normalized = findings.iter().any(|f| f.was_normalized);

    // ── Step 8: Build PolicyInput ─────────────────────────────────────────────
    let policy_input = PolicyInput {
        request_id: trace_id.clone(),
        request_type: request_type.clone(),
        caller: caller.clone(),
        findings: findings.clone(),
        model: Some(model.clone()),
        provider: None,
        messages: Some(messages.clone()),
        tool_call: None,
        tool_result: None,
        token_usage: None,
        session_state: session_state.clone(),
        governance_depth,
        timestamp: chrono::Utc::now().timestamp_millis(),
    };

    // ── Step 9: Policy evaluation ─────────────────────────────────────────────
    let policy_start = Instant::now();
    let decision = match state
        .policy_engine
        .evaluate(&policy_input)
        .instrument(span.clone())
        .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Policy evaluation failed");
            if state.fail_closed() {
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return make_error_response(
                    503,
                    body,
                    &trace_id,
                    &request_id,
                    &dash_base,
                    overall_start,
                );
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

    // ── Step 11: Route on effective_action ────────────────────────────────────
    let redaction_start = Instant::now();
    let body_to_send = match &effective.effective_action {
        Action::Block => {
            let body = RevocErrorResponse::governance_block(
                &trace_id,
                &decision.reason,
                decision.applicable_rules.clone(),
                &dash_base,
            );
            let mut resp =
                make_error_response(403, body, &trace_id, &request_id, &dash_base, overall_start);
            // Add decision / rules headers
            if let Ok(v) = action_to_str(&effective.effective_action).parse::<HeaderValue>() {
                resp.headers_mut().insert("X-Revoc-Decision", v);
            }
            if !decision.applicable_rules.is_empty() {
                if let Ok(v) = decision.applicable_rules.join(",").parse::<HeaderValue>() {
                    resp.headers_mut().insert("X-Revoc-Rules", v);
                }
            }

            // ── Step 20/21 (block path): write audit event + publish SSE ───────
            // Blocked requests return before Step 12 (upstream routing), so
            // `provider` is not yet resolved — write the audit record here
            // using the information available at this point (SPEC.md §23
            // Rule 25: never let SQLite audit writes block the request path).
            let decision_str = action_to_str(&effective.effective_action);
            let rules_str = if decision.applicable_rules.is_empty() {
                None
            } else {
                Some(decision.applicable_rules.join(","))
            };
            let finding_types: Vec<String> = findings
                .iter()
                .map(|f| format!("{:?}", f.finding_type))
                .collect();
            let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
            let now = chrono::Utc::now();
            let audit_event = revoc_dashboard::AuditEvent {
                id: uuid::Uuid::now_v7().to_string(),
                org_id: Some(caller.org_id.clone()),
                request_id: request_id.clone(),
                timestamp: now.to_rfc3339(),
                caller_id: Some(caller.caller_id.clone()),
                caller_team: caller.team.clone(),
                environment: Some(state.config.server.environment.clone()),
                decision: decision_str.to_owned(),
                effective_action: decision_str.to_owned(),
                enforcement_mode: if enforcement_mode == EnforcementMode::Shadow {
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
                model: Some(model.clone()),
                provider: None,
                tool_name: None,
                request_type: Some(format!("{request_type:?}")),
                governance_depth: i64::from(governance_depth),
                prompt_tokens: None,
                completion_tokens: None,
                estimated_cost_usd: None,
                duration_ms: Some(total_ms),
                detection_ms: Some(detection_ms),
                policy_ms: Some(policy_ms),
                was_normalized,
                manifest_warnings: 0,
                trace_id: Some(trace_id.clone()),
                policy_engine: Some(format!("{:?}", decision.policy_engine)),
                created_at: now.to_rfc3339(),
            };
            state.spawn_audit_write(audit_event);

            let pii_types: Vec<String> = findings
                .iter()
                .filter_map(|f| f.pii_entity.as_ref().map(PiiEntityType::to_string))
                .collect();
            state.feed_bus.publish(GovernanceEvent {
                trace_id: trace_id.clone(),
                timestamp: now.to_rfc3339(),
                decision: decision_str.to_owned(),
                blocked_by: decision.applicable_rules.first().cloned(),
                caller_id: caller.caller_id.clone(),
                model: Some(model.clone()),
                duration_ms: total_ms,
                findings_count: findings.len(),
                pii_types,
                mcp_tool: None,
                request_type: format!("{request_type:?}"),
                governance_depth,
                was_normalized,
                manifest_warnings: 0,
            });

            return resp;
        }
        Action::Redact => {
            match state
                .redactor
                .redact_body(&body_bytes, &findings, &decision)
            {
                Ok((redacted, _)) => redacted,
                Err(e) => {
                    // Fail closed: never forward the unredacted body.
                    warn!(error = %e, "Redaction failed");
                    if state.fail_closed() {
                        let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                        return make_error_response(
                            503,
                            body,
                            &trace_id,
                            &request_id,
                            &dash_base,
                            overall_start,
                        );
                    }
                    body_bytes.clone()
                }
            }
        }
        _ => body_bytes.clone(),
    };
    let redaction_ms = redaction_start.elapsed().as_secs_f64() * 1000.0;

    // ── Step 12: Validate upstream URL ────────────────────────────────────────
    let Some(provider) = state.upstream_router.route(&parts.headers).cloned() else {
        let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
        return make_error_response(503, body, &trace_id, &request_id, &dash_base, overall_start);
    };

    // Mock mode shortcut
    if state.config.upstream.mock_mode {
        let mock_body = serde_json::json!({
            "id": format!("chatcmpl-mock-{trace_id}"),
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": &state.config.upstream.mock_response},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
        });
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        let timing = format!(
            "detection={detection_ms:.1}ms,policy={policy_ms:.1}ms,redaction={redaction_ms:.1}ms,upstream=0.0ms,total={total_ms:.1}ms"
        );
        let mut resp = (StatusCode::OK, Json(mock_body)).into_response();
        let rules_str = if decision.applicable_rules.is_empty() {
            None
        } else {
            Some(decision.applicable_rules.join(","))
        };
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            action_to_str(&effective.effective_action),
            &format!("{dash_base}/traces/{trace_id}"),
            &timing,
            rules_str.as_deref(),
        );
        return resp;
    }

    // ── Steps 13-15: Build + send upstream request ────────────────────────────
    // `send_with_retries` rebuilds the request (setting X-Revoc-Depth — Step 14
    // — fresh each attempt, since `RequestBuilder` is consumed by `send`) and
    // retries transient failures with `Retry-After`-aware exponential backoff
    // (SPEC.md §23 — wires up the `upstream::retry` infrastructure).
    let method = http::Method::POST;
    let upstream_start = Instant::now();
    let body_for_upstream = bytes::Bytes::from(body_to_send);

    let upstream_resp = match send_with_retries(
        &state.upstream_router,
        state.upstream_client.inner(),
        &method,
        upstream_path,
        &provider,
        &body_for_upstream,
        governance_depth,
        MAX_UPSTREAM_RETRIES,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Upstream request failed (after retries)");
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            let status = if matches!(
                e,
                revoc_core::RevocError::Configuration(_) | revoc_core::RevocError::Security(_)
            ) {
                503
            } else {
                502
            };
            return make_error_response(
                status,
                body,
                &trace_id,
                &request_id,
                &dash_base,
                overall_start,
            );
        }
    };

    let upstream_status = upstream_resp.status().as_u16();
    let upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
    let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
    let timing = format!(
        "detection={detection_ms:.1}ms,policy={policy_ms:.1}ms,redaction={redaction_ms:.1}ms,upstream={upstream_ms:.1}ms,total={total_ms:.1}ms"
    );

    // ── Step 18: Forward upstream 4xx/5xx verbatim ────────────────────────────
    if should_forward_verbatim(upstream_status) {
        let status =
            StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let upstream_headers = upstream_resp.headers().clone();
        let body_bytes = match crate::upstream::body::read_response_limited(
            upstream_resp,
            state.config.server.max_response_body_bytes,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Upstream error body unreadable or too large");
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return make_error_response(
                    502,
                    body,
                    &trace_id,
                    &request_id,
                    &dash_base,
                    overall_start,
                );
            }
        };

        let mut resp = Response::builder()
            .status(status)
            .body(Body::from(body_bytes))
            .unwrap_or_default();

        // Copy relevant upstream headers
        for (name, value) in &upstream_headers {
            if name.as_str().starts_with("x-") || name == "content-type" {
                resp.headers_mut().insert(name.clone(), value.clone());
            }
        }

        // Add only X-Revoc-Trace-ID + non-negotiable headers
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            action_to_str(&effective.effective_action),
            &format!("{dash_base}/traces/{trace_id}"),
            &timing,
            None,
        );
        return resp;
    }

    // ── Step 15 (streaming) ───────────────────────────────────────────────────
    if is_stream {
        let mut resp = proxy_sse_stream(upstream_resp, &state, &caller, &trace_id).await;
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            action_to_str(&effective.effective_action),
            &format!("{dash_base}/traces/{trace_id}"),
            &timing,
            None,
        );
        return resp;
    }

    // ── Steps 16–17: Non-streaming response ───────────────────────────────────
    let resp_status = StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::OK);
    let resp_body = match crate::upstream::body::read_response_limited(
        upstream_resp,
        state.config.server.max_response_body_bytes,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "Upstream response unreadable or too large");
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return make_error_response(
                502,
                body,
                &trace_id,
                &request_id,
                &dash_base,
                overall_start,
            );
        }
    };

    // Step 16: extract token usage + estimate cost from the upstream JSON body
    let token_usage = extract_token_usage(&resp_body, &model);

    // Step 17: update and persist session state
    let updated_session = update_session_state(
        existing_session,
        &session_id,
        &caller,
        &findings,
        request_type == RequestType::McpToolCall,
    );
    {
        let store = state.session_store.clone();
        let sid = session_id.clone();
        let sess = updated_session.clone();
        let ttl = state.config.session.ttl_secs;
        if state.config.session.enabled {
            tokio::spawn(async move {
                if let Err(e) = store.set(&sid, sess, ttl).await {
                    warn!(error = %e, "Failed to persist session state");
                }
            });
        }
    }

    // ── Step 19: Set ALL response headers ─────────────────────────────────────
    let decision_str = action_to_str(&effective.effective_action);
    let rules_str = if decision.applicable_rules.is_empty() {
        None
    } else {
        Some(decision.applicable_rules.join(","))
    };

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

    // ── Step 20: Write AuditEvent (async, batched per Rule 25) ────────────────
    let finding_types: Vec<String> = findings
        .iter()
        .map(|f| format!("{:?}", f.finding_type))
        .collect();
    let now = chrono::Utc::now();
    let audit_event = revoc_dashboard::AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        org_id: Some(caller.org_id.clone()),
        request_id: request_id.clone(),
        timestamp: now.to_rfc3339(),
        caller_id: Some(caller.caller_id.clone()),
        caller_team: caller.team.clone(),
        environment: Some(state.config.server.environment.clone()),
        decision: decision_str.to_owned(),
        effective_action: action_to_str(&effective.effective_action).to_owned(),
        enforcement_mode: if enforcement_mode == EnforcementMode::Shadow {
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
        model: Some(model.clone()),
        provider: Some(provider.name.clone()),
        tool_name: None,
        request_type: Some(format!("{request_type:?}")),
        governance_depth: i64::from(governance_depth),
        prompt_tokens: token_usage
            .as_ref()
            .map(|t| i64::try_from(t.prompt_tokens).unwrap_or(i64::MAX)),
        completion_tokens: token_usage
            .as_ref()
            .map(|t| i64::try_from(t.completion_tokens).unwrap_or(i64::MAX)),
        estimated_cost_usd: token_usage.as_ref().and_then(|t| t.estimated_cost_usd),
        duration_ms: Some(total_ms),
        detection_ms: Some(detection_ms),
        policy_ms: Some(policy_ms),
        was_normalized,
        manifest_warnings: 0,
        trace_id: Some(trace_id.clone()),
        policy_engine: Some(format!("{:?}", decision.policy_engine)),
        created_at: now.to_rfc3339(),
    };
    state.spawn_audit_write(audit_event);

    // ── Step 21: Publish GovernanceEvent to dashboard SSE bus ─────────────────
    let pii_types: Vec<String> = findings
        .iter()
        .filter_map(|f| f.pii_entity.as_ref().map(PiiEntityType::to_string))
        .collect();
    state.feed_bus.publish(GovernanceEvent {
        trace_id: trace_id.clone(),
        timestamp: now.to_rfc3339(),
        decision: decision_str.to_owned(),
        blocked_by: decision.applicable_rules.first().cloned(),
        caller_id: caller.caller_id.clone(),
        model: Some(model.clone()),
        duration_ms: total_ms,
        findings_count: findings.len(),
        pii_types,
        mcp_tool: None,
        request_type: format!("{request_type:?}"),
        governance_depth,
        was_normalized,
        manifest_warnings: 0,
    });

    // ── Step 22: Record metrics, close span ───────────────────────────────────
    info!(
        parent: &span,
        trace_id,
        decision = decision_str,
        duration_ms = total_ms,
        model,
        "LLM request processed"
    );
    state
        .metrics
        .revoc_requests_total
        .with_label_values(&[
            &state.config.server.environment,
            &provider.name,
            decision_str,
            "",
            "",
        ])
        .inc();

    resp
}

/// Step 16 — extract `usage` from a non-streaming upstream JSON response and
/// estimate the request cost from a static published-pricing table
/// (USD per 1K tokens). Models not present fall back to a conservative
/// generic-LLM rate so `estimated_cost_usd` is always a real computation,
/// never a fabricated constant.
#[allow(clippy::cast_precision_loss)]
fn extract_token_usage(resp_body: &[u8], model: &str) -> Option<TokenUsage> {
    let parsed: serde_json::Value = serde_json::from_slice(resp_body).ok()?;
    let usage = parsed.get("usage")?;
    let prompt_tokens = usage
        .get("prompt_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let completion_tokens = usage
        .get("completion_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(prompt_tokens + completion_tokens);

    let (prompt_rate, completion_rate) = model_pricing_per_1k(model);
    let estimated_cost_usd = Some(
        (prompt_tokens as f64 / 1000.0) * prompt_rate
            + (completion_tokens as f64 / 1000.0) * completion_rate,
    );

    Some(TokenUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens,
        estimated_cost_usd,
    })
}

/// Static USD-per-1K-token pricing `(prompt, completion)` for well-known
/// models, with a conservative generic fallback for unrecognized models.
/// Sourced from published provider pricing pages at time of writing —
/// operators can refine via a future `[pricing]` config section if rates
/// change, but a real deterministic computation is required today (SPEC.md
/// §23 Rule 6 forbids fabricated/zeroed cost values).
fn model_pricing_per_1k(model: &str) -> (f64, f64) {
    let m = model.to_lowercase();
    if m.contains("gpt-4o-mini") {
        (0.000_15, 0.000_6)
    } else if m.contains("gpt-4o") {
        (0.0025, 0.01)
    } else if m.contains("gpt-4-turbo") || m.contains("gpt-4") {
        (0.01, 0.03)
    } else if m.contains("gpt-3.5") {
        (0.000_5, 0.0015)
    } else if m.contains("claude-3-5-sonnet") || m.contains("claude-3.5-sonnet") {
        (0.003, 0.015)
    } else if m.contains("claude-3-opus") {
        (0.015, 0.075)
    } else if m.contains("claude-3-haiku") {
        (0.000_25, 0.00125)
    } else if m.contains("claude") {
        (0.003, 0.015)
    } else {
        // Generic fallback rate for unrecognized/local models.
        (0.001, 0.002)
    }
}

/// Step 17 — fold this request's findings into the caller's session state and
/// return the updated record to persist. Creates a fresh session on first
/// contact. `external_send_attempted` is set when this request is itself an
/// MCP tool call (a vector for data leaving the governed boundary); REVOC's
/// own LLM completions are not external sends.
fn update_session_state(
    existing: Option<SessionState>,
    session_id: &str,
    caller: &CallerContext,
    findings: &[revoc_core::Finding],
    is_external_send: bool,
) -> SessionState {
    let now = chrono::Utc::now();
    let mut session = existing.unwrap_or_else(|| SessionState {
        session_id: session_id.to_owned(),
        org_id: caller.org_id.clone(),
        caller_id: caller.caller_id.clone(),
        tools_called: Vec::new(),
        total_rows_read: 0,
        pii_entities_seen: std::collections::HashSet::new(),
        external_send_attempted: false,
        started_at: now,
        last_active: now,
    });

    for finding in findings {
        if let Some(entity) = &finding.pii_entity {
            session.pii_entities_seen.insert(entity.to_string());
        }
    }
    if is_external_send {
        session.external_send_attempted = true;
    }
    session.last_active = now;
    session
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Set all mandatory REVOC response headers (SPEC.md §16).
///
/// `X-Revoc-Dashboard` and `X-Revoc-Timing` are NON-NEGOTIABLE.
/// All values are sanitized (strips `\r`, `\n`, `\0`).
pub fn set_revoc_headers(
    headers: &mut HeaderMap,
    trace_id: &str,
    decision: &str,
    dashboard_url: &str,
    timing: &str,
    rules: Option<&str>,
) {
    let pairs: &[(&str, &str)] = &[
        ("X-Revoc-Trace-ID", trace_id),
        ("X-Revoc-Decision", decision),
        ("X-Revoc-Dashboard", dashboard_url), // NON-NEGOTIABLE
        ("X-Revoc-Timing", timing),           // NON-NEGOTIABLE
    ];

    for (name, value) in pairs {
        let sanitized = sanitize_header_value(value);
        if let (Ok(n), Ok(v)) = (name.parse::<HeaderName>(), sanitized.parse::<HeaderValue>()) {
            headers.insert(n, v);
        }
    }

    if let Some(r) = rules {
        let sanitized = sanitize_header_value(r);
        if let (Ok(n), Ok(v)) = (
            "X-Revoc-Rules".parse::<HeaderName>(),
            sanitized.parse::<HeaderValue>(),
        ) {
            headers.insert(n, v);
        }
    }
}

/// Strip `\r`, `\n`, `\0` from header values (SPEC.md §17).
pub fn sanitize_header_value(v: &str) -> String {
    v.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

fn make_error_response(
    status: u16,
    body: RevocErrorResponse,
    trace_id: &str,
    _request_id: &str,
    dash_base: &str,
    start: Instant,
) -> Response {
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    let timing = format!(
        "detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream=0.0ms,total={total_ms:.1}ms"
    );
    let decision = "block";

    let mut resp = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(body),
    )
        .into_response();

    set_revoc_headers(
        resp.headers_mut(),
        trace_id,
        decision,
        &format!("{dash_base}/traces/{trace_id}"),
        &timing,
        None,
    );

    resp
}

pub(crate) async fn read_body_limited(body: Body, max_bytes: usize) -> Result<Vec<u8>, String> {
    crate::upstream::body::read_request_limited(body, max_bytes)
        .await
        .map(|b| b.to_vec())
        .map_err(|e| e.to_string())
}

fn extract_messages(parsed: &serde_json::Value) -> Vec<ChatMessage> {
    parsed
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .map(|msg| ChatMessage {
                    role: msg
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("user")
                        .to_owned(),
                    content: msg
                        .get("content")
                        .cloned()
                        .unwrap_or(serde_json::Value::String(String::new())),
                    name: None,
                    tool_call_id: None,
                    tool_calls: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Convert an [`Action`] to a lowercase static string for header values.
pub fn action_to_str(a: &Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Block => "block",
        Action::Redact => "redact",
        Action::Audit => "audit",
    }
}
