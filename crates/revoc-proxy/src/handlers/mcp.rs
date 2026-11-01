//! MCP handler — ALL 12 STEPS from SPEC.md §11.

use std::time::Instant;

use axum::{body::Body, extract::State, http::StatusCode, response::Response};
use tracing::{info, warn, Instrument};

use revoc_core::{
    CallerContext, ChatMessage, McpBlockResponse, McpRawRequest, McpToolCall, PolicyEngine,
    PolicyInput, Redactor, RequestType, RevocErrorResponse,
};
use revoc_dashboard::GovernanceEvent;
use revoc_detector::manifest_analyzer::{self, ManifestAnalysisResult, ManifestFinding};

use crate::{
    app::AppState,
    depth::check_depth,
    handlers::llm::{action_to_str, set_revoc_headers},
    middleware::request_id::{GovernanceDepth, RequestId},
};

#[allow(clippy::too_many_lines)]
pub async fn mcp_handler(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let overall_start = Instant::now();
    let trace_id = uuid::Uuid::now_v7().to_string();
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .cloned()
        .map_or_else(|| trace_id.clone(), |r| r.0);
    let dash_base = state.config.server.dashboard_base_url.clone();

    // ── Step 0: Kill-switch ────────────────────────────────────────────────────
    let caller = req
        .extensions()
        .get::<CallerContext>()
        .cloned()
        .unwrap_or_default();
    if state.kill_switch.is_active_for(&caller) {
        let body = RevocErrorResponse::kill_switch_active(&trace_id, &dash_base);
        return mcp_error_resp(503, body, &trace_id, &dash_base);
    }

    // ── Step 1: Depth ──────────────────────────────────────────────────────────
    let depth = req
        .extensions()
        .get::<GovernanceDepth>()
        .copied()
        .unwrap_or_default()
        .0;
    if check_depth(depth).is_err() {
        let body = RevocErrorResponse::depth_exceeded(&trace_id, depth, &dash_base);
        return mcp_error_resp(503, body, &trace_id, &dash_base);
    }

    // ── Step 2: Read body ──────────────────────────────────────────────────────
    let max_body = state.config.server.max_request_body_bytes;
    let (parts, body) = req.into_parts();
    let body_bytes = match crate::upstream::body::read_request_limited(body, max_body).await {
        Ok(b) => b,
        Err(revoc_core::RevocError::BodyTooLarge { .. }) => {
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return mcp_error_resp(413, body, &trace_id, &dash_base);
        }
        Err(e) => {
            warn!(error = %e, "MCP body read error");
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return mcp_error_resp(400, body, &trace_id, &dash_base);
        }
    };

    // ── Step 2b: Parse MCP JSON-RPC request ───────────────────────────────────
    let Ok(mcp_req) = serde_json::from_slice::<McpRawRequest>(&body_bytes) else {
        let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
        return mcp_error_resp(400, body, &trace_id, &dash_base);
    };

    let method = mcp_req.method.clone();
    let span = tracing::info_span!(
        "mcp_governance",
        trace_id = %trace_id,
        request_id = %request_id,
        governance_depth = depth,
        method = %method,
    );

    // ── Step 3: initialize/ping/notifications → forward to upstream MCP server ─
    if matches!(
        method.as_str(),
        "initialize" | "ping" | "notifications/initialized"
    ) {
        let Some(server) = select_mcp_server(&state, &parts.headers, &mcp_req) else {
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return mcp_error_resp(503, body, &trace_id, &dash_base);
        };
        let upstream_start = Instant::now();
        let (status, resp_bytes) = match forward_to_mcp_server(
            &state,
            server,
            bytes::Bytes::from(body_bytes.to_vec()),
            depth,
        )
        .instrument(span.clone())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "MCP upstream forward failed");
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return mcp_error_resp(502, body, &trace_id, &dash_base);
            }
        };
        let upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        let mut resp = Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
            .header("Content-Type", "application/json")
            .body(Body::from(resp_bytes))
            .unwrap_or_default();
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            "allow",
            &format!("{dash_base}/traces/{trace_id}"),
            &format!("detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream={upstream_ms:.1}ms,total={total_ms:.1}ms"),
            None,
        );
        return resp;
    }

    // ── Step 4: tools/list or resources/list — forward + manifest analysis ────
    if matches!(method.as_str(), "tools/list" | "resources/list") {
        let Some(server) = select_mcp_server(&state, &parts.headers, &mcp_req) else {
            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
            return mcp_error_resp(503, body, &trace_id, &dash_base);
        };
        let upstream_start = Instant::now();
        let (status, resp_bytes) = match forward_to_mcp_server(
            &state,
            server,
            bytes::Bytes::from(body_bytes.to_vec()),
            depth,
        )
        .instrument(span.clone())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "MCP upstream forward failed");
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return mcp_error_resp(502, body, &trace_id, &dash_base);
            }
        };
        let upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;

        // Rule D10 / §23 Rule 17 — analyze the UPSTREAM RESPONSE before it
        // reaches the AI client, never the inbound request.
        let manifest_result = if state.config.mcp.analyze_tool_manifests {
            manifest_analyzer::analyze_tools_list(&resp_bytes)
        } else {
            ManifestAnalysisResult {
                findings: vec![],
                tools_analyzed: 0,
            }
        };

        let final_body = if state.config.mcp.auto_disable_dangerous_tools
            && !manifest_result.findings.is_empty()
        {
            remove_dangerous_tools(&resp_bytes, &manifest_result.findings)
        } else {
            resp_bytes.to_vec()
        };

        let mut resp = Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
            .header("Content-Type", "application/json")
            .body(Body::from(final_body))
            .unwrap_or_default();

        if !manifest_result.findings.is_empty() {
            if let Ok(v) = manifest_result.findings.len().to_string().parse() {
                resp.headers_mut().insert("X-Revoc-Manifest-Warnings", v);
            }
            warn!(
                trace_id,
                tools_analyzed = manifest_result.tools_analyzed,
                findings = manifest_result.findings.len(),
                "MCP tool manifest analysis flagged dangerous tool definitions"
            );
        }

        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            "allow",
            &format!("{dash_base}/traces/{trace_id}"),
            &format!("detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream={upstream_ms:.1}ms,total={total_ms:.1}ms"),
            None,
        );
        return resp;
    }

    // ── Step 5: sampling/createMessage — route to LLM governance (depth+1) ────
    if method == "sampling/createMessage" {
        return handle_sampling_create_message(
            &state,
            &mcp_req,
            &caller,
            depth,
            &trace_id,
            &request_id,
            &dash_base,
            &span,
            overall_start,
        )
        .await;
    }

    // ── Steps 6–12: tools/call / resources/read ────────────────────────────────
    if matches!(method.as_str(), "tools/call" | "resources/read") {
        let tool_name = mcp_req
            .params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_owned();

        let arguments = mcp_req
            .params
            .as_ref()
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        // ── Step 6: validate server in trusted registry ───────────────────────
        let Some(server) = select_mcp_server(&state, &parts.headers, &mcp_req) else {
            return mcp_acl_block(&mcp_req, &trace_id, &dash_base);
        };

        let tool_call = McpToolCall {
            tool_name: tool_name.clone(),
            arguments: arguments.clone(),
            server_id: Some(server.id.clone()),
            call_id: None,
        };

        // ── Step 7: Run detection on tool arguments ───────────────────────────
        let detection_start = Instant::now();
        let inspection_input = revoc_core::traits::InspectionInput {
            request_id: trace_id.clone(),
            request_type: RequestType::McpToolCall,
            raw_body: bytes::Bytes::from(body_bytes.to_vec()),
            parsed_messages: None,
            mcp_call: Some(tool_call.clone()),
            caller: caller.clone(),
            governance_depth: depth,
        };
        let pipeline_result = state
            .pipeline
            .run(inspection_input)
            .instrument(span.clone())
            .await;
        if let Some(err) = &pipeline_result.detection_error {
            warn!(error = %err, "MCP argument detection incomplete");
            if state.fail_closed() {
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return mcp_error_resp(503, body, &trace_id, &dash_base);
            }
        }
        let findings = pipeline_result.findings;
        let detection_ms = detection_start.elapsed().as_secs_f64() * 1000.0;
        let was_normalized = findings.iter().any(|f| f.was_normalized);

        // ── Step 8: Evaluate policy ────────────────────────────────────────────
        let policy_input = PolicyInput {
            request_id: trace_id.clone(),
            request_type: RequestType::McpToolCall,
            caller: caller.clone(),
            findings: findings.clone(),
            model: None,
            provider: None,
            messages: None,
            tool_call: Some(tool_call.clone()),
            tool_result: None,
            token_usage: None,
            session_state: None,
            governance_depth: depth,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        let policy_start = Instant::now();
        let decision = match state
            .policy_engine
            .evaluate(&policy_input)
            .instrument(span.clone())
            .await
        {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Policy eval failed");
                if state.fail_closed() {
                    let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                    return mcp_error_resp(503, body, &trace_id, &dash_base);
                }
                revoc_core::PolicyDecision::allow()
            }
        };
        let policy_ms = policy_start.elapsed().as_secs_f64() * 1000.0;

        // ── Step 9: BLOCK — UPSTREAM NEVER RECEIVES THE REQUEST ────────────────
        if decision.effective_action.is_blocking() {
            let resp = mcp_block_response(&mcp_req, &decision, &trace_id, &dash_base);
            publish_mcp_event(
                &state,
                &trace_id,
                "block",
                &caller,
                None,
                &tool_name,
                depth,
                overall_start.elapsed().as_secs_f64() * 1000.0,
                &findings,
                was_normalized,
                &decision,
            );
            spawn_mcp_audit(
                &state,
                &trace_id,
                &request_id,
                &caller,
                &decision,
                &decision,
                "enforce",
                &tool_name,
                depth,
                detection_ms,
                policy_ms,
                overall_start.elapsed().as_secs_f64() * 1000.0,
                was_normalized,
            );
            return resp;
        }

        // ── Step 10: Forward to upstream MCP server (real) ────────────────────
        let upstream_start = Instant::now();
        let (status, result_bytes) = match forward_to_mcp_server(
            &state,
            server,
            bytes::Bytes::from(body_bytes.to_vec()),
            depth,
        )
        .instrument(span.clone())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "MCP tool forward failed");
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return mcp_error_resp(502, body, &trace_id, &dash_base);
            }
        };
        let upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;

        // ── Step 11: Bidirectional governance — detect + redact tool result ────
        let result_inspection = revoc_core::traits::InspectionInput {
            request_id: trace_id.clone(),
            request_type: RequestType::McpToolResult,
            raw_body: result_bytes.clone(),
            parsed_messages: None,
            mcp_call: Some(tool_call.clone()),
            caller: caller.clone(),
            governance_depth: depth,
        };
        let result_pipeline = state
            .pipeline
            .run(result_inspection)
            .instrument(span.clone())
            .await;
        if let Some(err) = &result_pipeline.detection_error {
            warn!(error = %err, "MCP result detection incomplete");
            if state.fail_closed() {
                let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                return mcp_error_resp(503, body, &trace_id, &dash_base);
            }
        }
        let result_findings = result_pipeline.findings;
        let result_was_normalized = result_findings.iter().any(|f| f.was_normalized);

        let result_value: serde_json::Value =
            serde_json::from_slice(&result_bytes).unwrap_or(serde_json::Value::Null);
        let result_policy_input = PolicyInput {
            request_id: trace_id.clone(),
            request_type: RequestType::McpToolResult,
            caller: caller.clone(),
            findings: result_findings.clone(),
            model: None,
            provider: None,
            messages: None,
            tool_call: Some(tool_call.clone()),
            tool_result: Some(result_value),
            token_usage: None,
            session_state: None,
            governance_depth: depth,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        let result_decision = match state
            .policy_engine
            .evaluate(&result_policy_input)
            .instrument(span.clone())
            .await
        {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Result policy eval failed");
                if state.fail_closed() {
                    let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                    return mcp_error_resp(503, body, &trace_id, &dash_base);
                }
                revoc_core::PolicyDecision::allow()
            }
        };

        let final_bytes =
            if result_decision.action.requires_redaction() || !result_findings.is_empty() {
                match state.redactor.redact_mcp_result(
                    &result_bytes,
                    &result_findings,
                    &result_decision,
                ) {
                    Ok((redacted, _)) => redacted,
                    Err(e) => {
                        // Fail closed: never return the unredacted tool result.
                        warn!(error = %e, "MCP result redaction failed");
                        if state.fail_closed() {
                            let body = RevocErrorResponse::internal_error(&trace_id, &dash_base);
                            return mcp_error_resp(503, body, &trace_id, &dash_base);
                        }
                        result_bytes.to_vec()
                    }
                }
            } else {
                result_bytes.to_vec()
            };

        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        let timing = format!(
            "detection={detection_ms:.1}ms,policy={policy_ms:.1}ms,redaction=0.0ms,upstream={upstream_ms:.1}ms,total={total_ms:.1}ms"
        );
        let decision_str = action_to_str(&result_decision.effective_action);
        let mut resp = Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
            .header("Content-Type", "application/json")
            .body(Body::from(final_bytes))
            .unwrap_or_default();
        let result_rules_str = result_decision.applicable_rules.join(",");
        set_revoc_headers(
            resp.headers_mut(),
            &trace_id,
            decision_str,
            &format!("{dash_base}/traces/{trace_id}"),
            &timing,
            if result_decision.applicable_rules.is_empty() {
                None
            } else {
                Some(&result_rules_str)
            },
        );

        // ── Step 12: audit, SSE, metrics ───────────────────────────────────────
        info!(parent: &span, trace_id, tool_name, decision = decision_str, duration_ms = total_ms, "MCP tool call processed");
        state
            .metrics
            .revoc_requests_total
            .with_label_values(&[
                &state.config.server.environment,
                "mcp",
                decision_str,
                "",
                "",
            ])
            .inc();
        let all_findings: Vec<revoc_core::Finding> = findings
            .iter()
            .cloned()
            .chain(result_findings.iter().cloned())
            .collect();
        publish_mcp_event(
            &state,
            &trace_id,
            decision_str,
            &caller,
            Some(server.id.clone()),
            &tool_name,
            depth,
            total_ms,
            &all_findings,
            was_normalized || result_was_normalized,
            &result_decision,
        );
        spawn_mcp_audit(
            &state,
            &trace_id,
            &request_id,
            &caller,
            &decision,
            &result_decision,
            "enforce",
            &tool_name,
            depth,
            detection_ms,
            policy_ms,
            total_ms,
            was_normalized || result_was_normalized,
        );

        return resp;
    }

    // Unknown method — return JSON-RPC method-not-found
    let err_resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": mcp_req.id,
        "error": {"code": -32601, "message": "Method not found"}
    });

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(err_resp.to_string()))
        .unwrap_or_default();

    set_revoc_headers(
        resp.headers_mut(),
        &trace_id,
        "allow",
        &format!("{dash_base}/traces/{trace_id}"),
        "detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream=0.0ms,total=0.0ms",
        None,
    );

    resp
}

// ── Step 5 helper: sampling/createMessage → LLM governance (depth+1) ──────────

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_sampling_create_message(
    state: &AppState,
    mcp_req: &McpRawRequest,
    caller: &CallerContext,
    depth: u8,
    trace_id: &str,
    request_id: &str,
    dash_base: &str,
    span: &tracing::Span,
    overall_start: Instant,
) -> Response {
    let next_depth = depth.saturating_add(1);
    if check_depth(next_depth).is_err() {
        let body = RevocErrorResponse::depth_exceeded(trace_id, next_depth, dash_base);
        return mcp_error_resp(503, body, trace_id, dash_base);
    }

    let params = mcp_req.params.clone().unwrap_or(serde_json::Value::Null);
    let default_model = state
        .upstream_router
        .default_provider()
        .map_or_else(|| "gpt-4o-mini".to_owned(), |p| p.name.clone());
    let chat_body = sampling_to_chat_body(&params, &default_model);
    let body_bytes = serde_json::to_vec(&chat_body).unwrap_or_default();

    let messages: Vec<ChatMessage> = chat_body
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .map(|m| ChatMessage {
                    role: m
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("user")
                        .to_owned(),
                    content: m
                        .get("content")
                        .cloned()
                        .unwrap_or(serde_json::Value::String(String::new())),
                    name: None,
                    tool_call_id: None,
                    tool_calls: None,
                })
                .collect()
        })
        .unwrap_or_default();

    let detection_start = Instant::now();
    let inspection_input = revoc_core::traits::InspectionInput {
        request_id: trace_id.to_owned(),
        request_type: RequestType::McpSampling,
        raw_body: bytes::Bytes::from(body_bytes.clone()),
        parsed_messages: Some(messages.clone()),
        mcp_call: None,
        caller: caller.clone(),
        governance_depth: depth,
    };
    let pipeline_result = state
        .pipeline
        .run(inspection_input)
        .instrument(span.clone())
        .await;
    if let Some(err) = &pipeline_result.detection_error {
        warn!(error = %err, "Sampling detection incomplete");
        if state.fail_closed() {
            let body = RevocErrorResponse::internal_error(trace_id, dash_base);
            return mcp_error_resp(503, body, trace_id, dash_base);
        }
    }
    let findings = pipeline_result.findings;
    let detection_ms = detection_start.elapsed().as_secs_f64() * 1000.0;

    let model_name = chat_body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(&default_model)
        .to_owned();
    let policy_input = PolicyInput {
        request_id: trace_id.to_owned(),
        request_type: RequestType::McpSampling,
        caller: caller.clone(),
        findings: findings.clone(),
        model: Some(model_name.clone()),
        provider: None,
        messages: Some(messages),
        tool_call: None,
        tool_result: None,
        token_usage: None,
        session_state: None,
        governance_depth: depth,
        timestamp: chrono::Utc::now().timestamp_millis(),
    };
    let policy_start = Instant::now();
    let decision = match state
        .policy_engine
        .evaluate(&policy_input)
        .instrument(span.clone())
        .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Sampling policy eval failed");
            if state.fail_closed() {
                let body = RevocErrorResponse::internal_error(trace_id, dash_base);
                return mcp_error_resp(503, body, trace_id, dash_base);
            }
            revoc_core::PolicyDecision::allow()
        }
    };
    let policy_ms = policy_start.elapsed().as_secs_f64() * 1000.0;

    if decision.effective_action.is_blocking() {
        let resp = mcp_block_response(mcp_req, &decision, trace_id, dash_base);
        spawn_mcp_audit(
            state,
            trace_id,
            request_id,
            caller,
            &decision,
            &decision,
            "enforce",
            "sampling/createMessage",
            depth,
            detection_ms,
            policy_ms,
            overall_start.elapsed().as_secs_f64() * 1000.0,
            findings.iter().any(|f| f.was_normalized),
        );
        return resp;
    }

    let Some(provider) = state.upstream_router.default_provider().cloned() else {
        let body = RevocErrorResponse::internal_error(trace_id, dash_base);
        return mcp_error_resp(503, body, trace_id, dash_base);
    };

    let upstream_start = Instant::now();
    let upstream_req = match state.upstream_router.build_upstream_request(
        state.upstream_client.inner(),
        http::Method::POST,
        "/v1/chat/completions",
        &provider,
        bytes::Bytes::from(body_bytes),
        next_depth,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Sampling upstream build failed (SSRF?)");
            let body = RevocErrorResponse::internal_error(trace_id, dash_base);
            return mcp_error_resp(503, body, trace_id, dash_base);
        }
    };
    let upstream_resp = match upstream_req.send().instrument(span.clone()).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Sampling upstream send failed");
            let body = RevocErrorResponse::internal_error(trace_id, dash_base);
            return mcp_error_resp(502, body, trace_id, dash_base);
        }
    };
    let status = upstream_resp.status().as_u16();
    let resp_bytes = match crate::upstream::body::read_response_limited(
        upstream_resp,
        state.config.server.max_response_body_bytes,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "Sampling upstream response unreadable or too large");
            let body = RevocErrorResponse::internal_error(trace_id, dash_base);
            return mcp_error_resp(502, body, trace_id, dash_base);
        }
    };
    let upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
    let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;

    let parsed: serde_json::Value =
        serde_json::from_slice(&resp_bytes).unwrap_or(serde_json::Value::Null);
    let text = parsed
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or_default()
        .to_owned();
    let model_used = parsed
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(&model_name)
        .to_owned();

    let sampling_result = serde_json::json!({
        "jsonrpc": "2.0",
        "id": mcp_req.id,
        "result": {
            "role": "assistant",
            "content": {"type": "text", "text": text},
            "model": model_used,
            "stopReason": "endTurn"
        }
    });

    let decision_str = action_to_str(&decision.effective_action);
    let timing = format!(
        "detection={detection_ms:.1}ms,policy={policy_ms:.1}ms,redaction=0.0ms,upstream={upstream_ms:.1}ms,total={total_ms:.1}ms"
    );
    let mut resp = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header("Content-Type", "application/json")
        .body(Body::from(sampling_result.to_string()))
        .unwrap_or_default();
    set_revoc_headers(
        resp.headers_mut(),
        trace_id,
        decision_str,
        &format!("{dash_base}/traces/{trace_id}"),
        &timing,
        None,
    );

    info!(parent: span, trace_id, decision = decision_str, duration_ms = total_ms, model = %model_used, "MCP sampling/createMessage processed");
    spawn_mcp_audit(
        state,
        trace_id,
        request_id,
        caller,
        &decision,
        &decision,
        "enforce",
        "sampling/createMessage",
        depth,
        detection_ms,
        policy_ms,
        total_ms,
        findings.iter().any(|f| f.was_normalized),
    );

    resp
}

/// Translate MCP `sampling/createMessage` params into an OpenAI-style chat
/// completion request body so the existing detection + policy + upstream
/// pipeline can govern it identically to a direct LLM call.
fn sampling_to_chat_body(params: &serde_json::Value, default_model: &str) -> serde_json::Value {
    let mut messages: Vec<serde_json::Value> = params
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .map(|m| {
                    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                    let text = m
                        .get("content")
                        .and_then(|c| {
                            c.get("text")
                                .and_then(|t| t.as_str())
                                .map(str::to_owned)
                                .or_else(|| c.as_str().map(str::to_owned))
                        })
                        .unwrap_or_default();
                    serde_json::json!({"role": role, "content": text})
                })
                .collect()
        })
        .unwrap_or_default();

    if let Some(system) = params.get("systemPrompt").and_then(|s| s.as_str()) {
        messages.insert(0, serde_json::json!({"role": "system", "content": system}));
    }

    let model = params
        .get("modelPreferences")
        .and_then(|mp| mp.get("hints"))
        .and_then(|h| h.as_array())
        .and_then(|arr| arr.first())
        .and_then(|hint| hint.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or(default_model);

    let mut body = serde_json::json!({"model": model, "messages": messages});
    if let Some(max_tokens) = params.get("maxTokens") {
        body["max_tokens"] = max_tokens.clone();
    }
    body
}

// ── MCP server selection / forwarding ──────────────────────────────────────────

/// Select the trusted MCP server to forward this request to.
///
/// Priority: `X-Revoc-Mcp-Server` header → `params.server_id`/`serverId` →
/// the sole configured server (single-server deployments). Returns `None`
/// when no trusted server matches — callers MUST treat that as a hard
/// failure (SPEC.md §17 — never derive upstream targets from request data
/// outside the configured allowlist).
fn select_mcp_server<'a>(
    state: &'a AppState,
    headers: &http::HeaderMap,
    mcp_req: &McpRawRequest,
) -> Option<&'a revoc_config::TrustedMcpServer> {
    let servers = &state.config.mcp.trusted_servers;
    if servers.is_empty() {
        return None;
    }
    if let Some(id) = headers
        .get("X-Revoc-Mcp-Server")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(s) = servers.iter().find(|s| s.id == id) {
            return Some(s);
        }
    }
    if let Some(id) = mcp_req
        .params
        .as_ref()
        .and_then(|p| p.get("server_id").or_else(|| p.get("serverId")))
        .and_then(|v| v.as_str())
    {
        if let Some(s) = servers.iter().find(|s| s.id == id) {
            return Some(s);
        }
    }
    if servers.len() == 1 {
        return servers.first();
    }
    None
}

/// Forward the raw JSON-RPC body to a trusted MCP server, setting
/// `X-Revoc-Depth` on the outgoing request (SPEC.md §23 Rule 27).
async fn forward_to_mcp_server(
    state: &AppState,
    server: &revoc_config::TrustedMcpServer,
    body: bytes::Bytes,
    current_depth: u8,
) -> Result<(u16, bytes::Bytes), revoc_core::RevocError> {
    let next_depth = current_depth.saturating_add(1);
    let resp = state
        .upstream_client
        .inner()
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            concat!("revoc-proxy/", env!("CARGO_PKG_VERSION")),
        )
        .header(crate::depth::REVOC_DEPTH_HEADER, next_depth.to_string())
        .body(body)
        .send()
        .await
        .map_err(|_e| revoc_core::RevocError::Upstream {
            status: 502,
            provider: server.id.clone(),
        })?;

    let status = resp.status().as_u16();
    let bytes = crate::upstream::body::read_response_limited(
        resp,
        state.config.server.max_response_body_bytes,
    )
    .await?;
    Ok((status, bytes))
}

/// Remove tools flagged by manifest analysis from a `tools/list` response
/// before it reaches the AI client (`mcp.auto_disable_dangerous_tools = true`).
fn remove_dangerous_tools(body: &[u8], findings: &[ManifestFinding]) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    let dangerous: std::collections::HashSet<&str> =
        findings.iter().map(|f| f.tool_name.as_str()).collect();

    let retain = |arr: &mut Vec<serde_json::Value>| {
        arr.retain(|t| {
            !t.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|name| dangerous.contains(name))
        });
    };

    if let Some(tools) = value.get_mut("tools").and_then(|t| t.as_array_mut()) {
        retain(tools);
    } else if let Some(arr) = value.as_array_mut() {
        retain(arr);
    }

    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

// ── Block / audit / SSE helpers ────────────────────────────────────────────────

fn mcp_acl_block(mcp_req: &McpRawRequest, trace_id: &str, dash_base: &str) -> Response {
    let decision = revoc_core::PolicyDecision::block(
        "No trusted MCP server is registered for this tool call",
        vec!["mcp_tool_acl_v1".to_owned()],
    );
    mcp_block_response(mcp_req, &decision, trace_id, dash_base)
}

fn mcp_block_response(
    mcp_req: &McpRawRequest,
    decision: &revoc_core::PolicyDecision,
    trace_id: &str,
    dash_base: &str,
) -> Response {
    let block_resp = McpBlockResponse::new(
        mcp_req.id.clone(),
        trace_id,
        decision.applicable_rules.clone(),
        &decision.reason,
        &format!("{dash_base}/traces/{trace_id}"),
    );

    let mut resp = Response::builder()
        .status(StatusCode::OK) // MCP blocks are HTTP 200 with JSON-RPC error
        .header("Content-Type", "application/json")
        .header("X-Revoc-Block", "true")
        .body(Body::from(
            serde_json::to_string(&block_resp).unwrap_or_default(),
        ))
        .unwrap_or_default();

    let block_rules_str = decision.applicable_rules.join(",");
    set_revoc_headers(
        resp.headers_mut(),
        trace_id,
        "block",
        &format!("{dash_base}/traces/{trace_id}"),
        "detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream=0.0ms,total=0.0ms",
        Some(&block_rules_str),
    );

    resp
}

#[allow(clippy::too_many_arguments)]
fn spawn_mcp_audit(
    state: &AppState,
    trace_id: &str,
    request_id: &str,
    caller: &CallerContext,
    raw_decision: &revoc_core::PolicyDecision,
    effective_decision: &revoc_core::PolicyDecision,
    enforcement_mode: &str,
    tool_name: &str,
    governance_depth: u8,
    detection_ms: f64,
    policy_ms: f64,
    total_ms: f64,
    was_normalized: bool,
) {
    let now = chrono::Utc::now();
    let rules: Vec<String> = raw_decision
        .applicable_rules
        .iter()
        .chain(effective_decision.applicable_rules.iter())
        .cloned()
        .collect();
    let event = revoc_dashboard::AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        org_id: Some(caller.org_id.clone()),
        request_id: request_id.to_owned(),
        timestamp: now.to_rfc3339(),
        caller_id: Some(caller.caller_id.clone()),
        caller_team: caller.team.clone(),
        environment: Some(state.config.server.environment.clone()),
        decision: action_to_str(&raw_decision.action).to_owned(),
        effective_action: action_to_str(&effective_decision.effective_action).to_owned(),
        enforcement_mode: enforcement_mode.to_owned(),
        violated_rules: if rules.is_empty() {
            None
        } else {
            Some(rules.join(","))
        },
        finding_types: None,
        model: None,
        provider: Some("mcp".to_owned()),
        tool_name: Some(tool_name.to_owned()),
        request_type: Some("McpToolCall".to_owned()),
        governance_depth: i64::from(governance_depth),
        prompt_tokens: None,
        completion_tokens: None,
        estimated_cost_usd: None,
        duration_ms: Some(total_ms),
        detection_ms: Some(detection_ms),
        policy_ms: Some(policy_ms),
        was_normalized,
        manifest_warnings: 0,
        trace_id: Some(trace_id.to_owned()),
        policy_engine: Some(format!("{:?}", effective_decision.policy_engine)),
        created_at: now.to_rfc3339(),
    };
    state.spawn_audit_write(event);
}

#[allow(clippy::too_many_arguments)]
fn publish_mcp_event(
    state: &AppState,
    trace_id: &str,
    decision_str: &str,
    caller: &CallerContext,
    mcp_server: Option<String>,
    tool_name: &str,
    governance_depth: u8,
    duration_ms: f64,
    findings: &[revoc_core::Finding],
    was_normalized: bool,
    decision: &revoc_core::PolicyDecision,
) {
    let pii_types: Vec<String> = findings
        .iter()
        .filter_map(|f| {
            f.pii_entity
                .as_ref()
                .map(revoc_core::PiiEntityType::to_string)
        })
        .collect();
    let mcp_tool =
        mcp_server.map_or_else(|| tool_name.to_owned(), |sid| format!("{sid}/{tool_name}"));
    state.feed_bus.publish(GovernanceEvent {
        trace_id: trace_id.to_owned(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        decision: decision_str.to_owned(),
        blocked_by: decision.applicable_rules.first().cloned(),
        caller_id: caller.caller_id.clone(),
        model: None,
        duration_ms,
        findings_count: findings.len(),
        pii_types,
        mcp_tool: Some(mcp_tool),
        request_type: "McpToolCall".to_owned(),
        governance_depth,
        was_normalized,
        manifest_warnings: 0,
    });
}

fn mcp_error_resp(
    status: u16,
    body: RevocErrorResponse,
    trace_id: &str,
    dash_base: &str,
) -> Response {
    use axum::response::IntoResponse;
    let mut resp = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body),
    )
        .into_response();
    set_revoc_headers(
        resp.headers_mut(),
        trace_id,
        "block",
        &format!("{dash_base}/traces/{trace_id}"),
        "detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream=0.0ms,total=0.0ms",
        None,
    );
    resp
}
