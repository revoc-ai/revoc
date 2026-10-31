//! Request metrics recording middleware.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::time::Instant;

use crate::app::AppState;

/// Middleware: record `revoc_requests_total` and `revoc_request_duration_ms` after response.
pub async fn metrics_recorder_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let resp = next.run(req).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let decision = resp
        .headers()
        .get("X-Revoc-Decision")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("allow")
        .to_owned();

    let provider = resp
        .headers()
        .get("X-Revoc-Upstream-Provider")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();

    // Record counters
    state
        .metrics
        .revoc_requests_total
        .with_label_values(&[
            &state.config.server.environment,
            &provider,
            &decision,
            "",
            "",
        ])
        .inc();

    state
        .metrics
        .revoc_request_duration_ms
        .with_label_values(&[&state.config.server.environment, &provider, &decision])
        .observe(elapsed_ms);

    resp
}
