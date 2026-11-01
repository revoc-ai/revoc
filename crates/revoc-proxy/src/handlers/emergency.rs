//! Emergency kill-switch admin handlers (internal port 8081 ONLY).

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::{
    app::AppState,
    kill_switch::{KillSwitchEntry, KillSwitchScope},
    middleware::auth::derive_caller_id,
};

// ── Auth ──────────────────────────────────────────────────────────────────────

/// Minimum accepted admin key length; shorter keys are treated as unset.
pub const MIN_ADMIN_KEY_LEN: usize = 16;

/// The operator admin key: `REVOC_ADMIN_KEY`, else `auth.admin_key`.
/// `None` when unset or shorter than [`MIN_ADMIN_KEY_LEN`].
pub fn configured_admin_key(config: &revoc_config::Config) -> Option<String> {
    let key = std::env::var("REVOC_ADMIN_KEY").unwrap_or_else(|_| config.auth.admin_key.clone());
    (key.len() >= MIN_ADMIN_KEY_LEN).then_some(key)
}

/// Validate an admin key against [`configured_admin_key`] in constant time.
///
/// `REVOC_ADMIN_KEY` overrides `auth.admin_key` so operators can rotate the
/// key without a config change. Client API keys (`REVOC_API_KEYS`) are never
/// accepted — startup refuses an admin key equal to one. With no usable key
/// configured every request is rejected.
pub fn validate_admin_key(provided: &str, state: &AppState) -> bool {
    configured_admin_key(&state.config)
        .is_some_and(|expected| provided.as_bytes().ct_eq(expected.as_bytes()).into())
}

/// Extract `X-Admin-Key` and validate it; `Err(401)` when missing or wrong.
pub fn require_admin(headers: &axum::http::HeaderMap, state: &AppState) -> Result<(), StatusCode> {
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if validate_admin_key(provided, state) {
        Ok(())
    } else {
        warn!("Internal admin API: unauthorized request");
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActivateRequest {
    pub scope: String,
    pub reason: String,
    pub activated_by: String,
    pub target: Option<String>,
}

#[derive(Deserialize)]
pub struct DeactivateRequest {
    pub scope: String,
    pub target: Option<String>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

fn admin_key_header(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// `POST /internal/emergency/kill-switch/activate`
///
/// Traffic stops locally at once. `durable: false` in the response means the
/// store could not be written; the activation stays in force here and is
/// retried on every reconcile.
pub async fn activate_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_admin(&headers, &state)?;
    let scope = KillSwitchScope::parse(&req.scope, req.target.as_deref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if req.reason.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let outcome = state
        .kill_switch_service
        .activate(KillSwitchEntry {
            activated_by: req.activated_by.clone(),
            activated_at: chrono::Utc::now(),
            reason: req.reason.clone(),
            scope,
        })
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(serde_json::json!({
        "status": "activated",
        "scope": req.scope,
        "reason": req.reason,
        "durable": outcome.durable,
        "version": outcome.version,
    })))
}

/// `POST /internal/emergency/kill-switch/deactivate`
///
/// Lifted only once the change is in the durable store; otherwise 503 and
/// the switch stays active everywhere.
pub async fn deactivate_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).map_err(|s| (s, Json(serde_json::json!({}))))?;
    let scope = KillSwitchScope::parse(&req.scope, req.target.as_deref()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    // The request carries no actor; record the stable, non-reversible
    // identity derived from the admin key that authenticated it.
    let actor = derive_caller_id(admin_key_header(&headers));
    match state.kill_switch_service.deactivate(&scope, &actor).await {
        Ok(outcome) => Ok(Json(serde_json::json!({
            "status": "deactivated",
            "scope": req.scope,
            "durable": outcome.durable,
            "version": outcome.version,
        }))),
        Err(e) => {
            warn!(error = %e, "Kill-switch deactivation not persisted");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "still_active",
                    "error": "kill-switch store unavailable; nothing was lifted",
                })),
            ))
        }
    }
}

/// `GET /internal/emergency/kill-switch/status`
pub async fn status_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_admin(&headers, &state)?;
    let snap = state.kill_switch.status_snapshot();
    let mut body = state.kill_switch_service.status_json();
    body["by_org"] = serde_json::json!(snap.by_org.iter().map(|(k, _)| k).collect::<Vec<_>>());
    body["by_caller"] =
        serde_json::json!(snap.by_caller.iter().map(|(k, _)| k).collect::<Vec<_>>());
    Ok(Json(body))
}
