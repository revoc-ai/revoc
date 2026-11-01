//! Exit-path audit (SPEC.md §15): every authenticated request on a governed
//! route leaves at least one audit record, whichever way it ends.
//!
//! Handlers write a detailed event on their governed paths. Early exits
//! (kill switch, depth limit, malformed body, rate limit, upstream failure,
//! governance error) returned without one. This middleware runs each
//! request inside a task-local flag that [`mark_audited`] sets; when the
//! response comes back with the flag still clear, it writes a minimal event
//! built from the status and the `X-Revoc-*` headers. The body is never
//! read, so streams are untouched and nothing from the payload is stored.
//!
//! Unauthenticated (401) responses are counted in metrics but not audited:
//! recording them would let anyone without a key write to the audit store.

use std::cell::Cell;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

use revoc_core::{CallerContext, EnforcementMode};
use revoc_dashboard::AuditEvent;

use crate::app::AppState;
use crate::middleware::request_id::{GovernanceDepth, RequestId};

tokio::task_local! {
    static AUDITED: Cell<bool>;
}

/// Record that the current request has written an audit event. A no-op
/// outside a request (for example in a task spawned to finish a stream).
pub fn mark_audited() {
    // Outside a request scope there is nothing to mark.
    let _ = AUDITED.try_with(|flag| flag.set(true));
}

/// Middleware: write a fallback audit event for any response whose handler
/// did not write one.
pub async fn audit_exit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let caller = req.extensions().get::<CallerContext>().cloned();
    let request_id = req.extensions().get::<RequestId>().map(|r| r.0.clone());
    let depth = req.extensions().get::<GovernanceDepth>().map_or(0, |d| d.0);
    let request_type = request_type_for(req.uri().path());

    let (resp, audited) = AUDITED
        .scope(Cell::new(false), async {
            let resp = next.run(req).await;
            (resp, AUDITED.with(Cell::get))
        })
        .await;

    if !audited {
        if let Some(caller) = caller {
            let event = fallback_event(
                &state,
                &caller,
                request_id,
                depth,
                request_type,
                resp.status(),
                resp.headers(),
                start.elapsed().as_secs_f64() * 1000.0,
            );
            state.spawn_audit_write(event);
        }
    }
    resp
}

fn request_type_for(path: &str) -> &'static str {
    match path {
        "/v1/embeddings" => "LlmEmbeddings",
        "/mcp" => "McpToolCall",
        _ => "LlmRequest",
    }
}

/// Decision for an unaudited exit. A client or server error is classified
/// by status — `reject` for a client error, `error` for a server, upstream
/// or fail-closed governance failure — even when the error response carries
/// `X-Revoc-Decision: block`, so failures stay distinguishable from policy
/// blocks. Otherwise the handler's `X-Revoc-Decision` wins.
fn exit_decision(status: StatusCode, headers: &HeaderMap) -> String {
    if status == StatusCode::FORBIDDEN {
        return "block".to_owned();
    }
    if !status.is_client_error() && !status.is_server_error() {
        if let Some(d) = header(headers, "X-Revoc-Decision") {
            return d;
        }
    }
    if status.is_client_error() {
        "reject".to_owned()
    } else if status.is_server_error() {
        "error".to_owned()
    } else {
        "allow".to_owned()
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

#[allow(clippy::too_many_arguments)]
fn fallback_event(
    state: &AppState,
    caller: &CallerContext,
    request_id: Option<String>,
    depth: u8,
    request_type: &str,
    status: StatusCode,
    headers: &HeaderMap,
    duration_ms: f64,
) -> AuditEvent {
    let now = chrono::Utc::now();
    let decision = exit_decision(status, headers);
    AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        org_id: Some(caller.org_id.clone()),
        request_id: request_id.unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
        timestamp: now.to_rfc3339(),
        caller_id: Some(caller.caller_id.clone()),
        caller_team: caller.team.clone(),
        environment: Some(state.config.server.environment.clone()),
        effective_action: decision.clone(),
        decision,
        enforcement_mode: if caller.enforcement_mode == EnforcementMode::Shadow {
            "shadow".to_owned()
        } else {
            "enforce".to_owned()
        },
        violated_rules: header(headers, "X-Revoc-Rules"),
        finding_types: None,
        model: None,
        provider: None,
        tool_name: None,
        request_type: Some(request_type.to_owned()),
        governance_depth: i64::from(depth),
        prompt_tokens: None,
        completion_tokens: None,
        estimated_cost_usd: None,
        duration_ms: Some(duration_ms),
        detection_ms: None,
        policy_ms: None,
        was_normalized: false,
        manifest_warnings: 0,
        trace_id: header(headers, "X-Revoc-Trace-ID"),
        policy_engine: Some(format!("exit:{}", status.as_u16())),
        created_at: now.to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_prefers_handler_header() {
        let mut h = HeaderMap::new();
        h.insert("X-Revoc-Decision", "redact".parse().unwrap());
        assert_eq!(exit_decision(StatusCode::OK, &h), "redact");
    }

    #[test]
    fn decision_by_status_class() {
        let mut h = HeaderMap::new();
        h.insert("X-Revoc-Decision", "block".parse().unwrap());
        assert_eq!(exit_decision(StatusCode::FORBIDDEN, &h), "block");
        assert_eq!(exit_decision(StatusCode::TOO_MANY_REQUESTS, &h), "reject");
        assert_eq!(exit_decision(StatusCode::SERVICE_UNAVAILABLE, &h), "error");
        assert_eq!(exit_decision(StatusCode::BAD_GATEWAY, &h), "error");
    }

    #[tokio::test]
    async fn mark_outside_scope_is_noop() {
        mark_audited();
    }
}
