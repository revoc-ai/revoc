//! Health, readiness, startup, metrics, and reload handlers.
//!
//! These endpoints ALWAYS bypass the kill-switch (SPEC.md §9 D11).

use axum::{extract::State, Json};
use serde_json::json;
use tracing::warn;

use revoc_dashboard::EventFilter;

use crate::app::AppState;

/// `GET /health` — always 200, even when kill-switch is active.
pub async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "revoc-proxy"
    }))
}

/// `GET /ready` — checks audit-store and policy-engine reachability with real
/// connectivity probes (a minimal `list_events` query against the configured
/// backend, and an `engine_type()`/config check for the policy engine), and
/// reports kill-switch state and store health.
pub async fn ready_handler(
    State(state): State<AppState>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let mut reasons = Vec::new();

    // Storage connectivity — issue a minimal real query against the audit store
    // (SQLite/Postgres) so a dead connection pool is detected before traffic.
    let filter = EventFilter {
        limit: Some(1),
        ..EventFilter::default()
    };
    if let Err(e) = state.audit_store.list_events(filter).await {
        warn!(error = %e, "Readiness check: audit store unreachable");
        reasons.push("audit_store_unreachable".to_owned());
    }

    // Policy engine reachability — sidecar mode requires a configured OPA URL;
    // native/wasm engines are in-process and always reachable once constructed.
    if state.config.policy.engine == "sidecar" && state.config.policy.opa_url.is_empty() {
        reasons.push("policy_engine_unavailable".to_owned());
    }

    // Kill-switch store: with fail_closed an unreadable store blocks all
    // traffic, so the instance is not ready; with local_only it serves on
    // its last known state and reports itself degraded.
    let kill_switch = state.kill_switch_service.status_json();
    if state.kill_switch.store_lockout() {
        reasons.push("kill_switch_store_unavailable".to_owned());
    }
    let degraded = !state.kill_switch_service.healthy();

    if reasons.is_empty() {
        (
            axum::http::StatusCode::OK,
            Json(json!({
                "status": if degraded { "degraded" } else { "ready" },
                "kill_switch": kill_switch,
            })),
        )
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready", "reasons": reasons, "kill_switch": kill_switch})),
        )
    }
}

/// `GET /startup` — probe used by Kubernetes startupProbe.
pub async fn startup_handler() -> Json<serde_json::Value> {
    Json(json!({"status": "started"}))
}

/// `GET /metrics` — Prometheus text format.
pub async fn metrics_handler() -> String {
    revoc_telemetry::RevocMetrics::prometheus_text()
}

/// `POST /internal/reload` — hot-reload the policy engine without restart.
///
/// Requires `X-Admin-Key`, like every other internal endpoint.
pub async fn reload_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    crate::handlers::emergency::require_admin(&headers, &state)?;
    state.policy_engine.reload_on_notification().await;
    Ok(Json(json!({"status": "reloaded"})))
}
