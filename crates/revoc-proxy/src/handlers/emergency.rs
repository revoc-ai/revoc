//! Emergency kill-switch admin handlers (internal port 8081 ONLY).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
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

/// Validate the `X-Admin-Key` header against the configured admin key.
///
/// `REVOC_ADMIN_KEY` overrides `auth.admin_key` so operators can rotate the
/// key without a config change. Client API keys (`REVOC_API_KEYS`) are never
/// accepted. With no key configured (or one shorter than
/// [`MIN_ADMIN_KEY_LEN`]) every request is rejected.
pub fn validate_admin_key(provided: &str, state: &AppState) -> bool {
    let expected =
        std::env::var("REVOC_ADMIN_KEY").unwrap_or_else(|_| state.config.auth.admin_key.clone());
    if expected.len() < MIN_ADMIN_KEY_LEN {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
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

#[derive(Serialize)]
#[allow(dead_code)]
pub struct StatusResponse {
    pub global: bool,
    pub by_org: Vec<String>,
    pub by_caller: Vec<String>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /internal/emergency/kill-switch/activate`
pub async fn activate_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let admin_key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !validate_admin_key(admin_key, &state) {
        warn!("Kill-switch activate: unauthorized attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let scope = parse_scope(&req.scope, req.target.as_deref()).ok_or(StatusCode::BAD_REQUEST)?;

    let entry = KillSwitchEntry {
        activated_by: req.activated_by.clone(),
        activated_at: chrono::Utc::now(),
        reason: req.reason.clone(),
        scope: scope.clone(),
    };

    state.kill_switch.activate(entry.clone());

    // Publish to Redis for cross-instance propagation (~50ms)
    crate::kill_switch::publish_kill_switch_message(
        &state.config,
        "activate",
        Some(entry.clone()),
        None,
    );

    // Persist to kill_switch_log (SPEC.md §23 Rule 26) — non-blocking failure.
    let (scope_str, scope_value) = scope_log_parts(&scope);
    if let Err(e) = state
        .kill_switch_log
        .log(
            scope_str,
            scope_value,
            "activate",
            &entry.activated_by,
            Some(&entry.reason),
        )
        .await
    {
        warn!(error = %e, "Failed to write kill_switch_log entry");
    }

    Ok(Json(serde_json::json!({
        "status": "activated",
        "scope": req.scope,
        "reason": req.reason
    })))
}

/// `POST /internal/emergency/kill-switch/deactivate`
pub async fn deactivate_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let admin_key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !validate_admin_key(admin_key, &state) {
        warn!("Kill-switch deactivate: unauthorized attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let scope = parse_scope(&req.scope, req.target.as_deref()).ok_or(StatusCode::BAD_REQUEST)?;

    state.kill_switch.deactivate(&scope);
    crate::kill_switch::publish_kill_switch_message(
        &state.config,
        "deactivate",
        None,
        Some(scope.clone()),
    );

    // Persist to kill_switch_log (SPEC.md §23 Rule 26) — non-blocking failure.
    // The deactivate request carries no `activated_by` field, so the actor is
    // derived from the admin key that authenticated this request — the same
    // stable, non-reversible derivation used for API-key callers.
    let actor = derive_caller_id(admin_key);
    let (scope_str, scope_value) = scope_log_parts(&scope);
    if let Err(e) = state
        .kill_switch_log
        .log(scope_str, scope_value, "deactivate", &actor, None)
        .await
    {
        warn!(error = %e, "Failed to write kill_switch_log entry");
    }

    Ok(Json(
        serde_json::json!({"status": "deactivated", "scope": req.scope}),
    ))
}

/// `GET /internal/emergency/kill-switch/status`
pub async fn status_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_admin(&headers, &state)?;
    let snap = state.kill_switch.status_snapshot();
    Ok(Json(serde_json::json!({
        "global": snap.global,
        "by_org": snap.by_org.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        "by_caller": snap.by_caller.iter().map(|(k, _)| k).collect::<Vec<_>>(),
    })))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Split a [`KillSwitchScope`] into the `(scope, scope_value)` pair stored in
/// the `kill_switch_log` table (SPEC.md §15).
fn scope_log_parts(scope: &KillSwitchScope) -> (&'static str, Option<&str>) {
    match scope {
        KillSwitchScope::Global => ("global", None),
        KillSwitchScope::Org(id) => ("org", Some(id.as_str())),
        KillSwitchScope::Caller(id) => ("caller", Some(id.as_str())),
    }
}

fn parse_scope(scope_str: &str, target: Option<&str>) -> Option<KillSwitchScope> {
    match scope_str {
        "global" => Some(KillSwitchScope::Global),
        "org" => target.map(|t| KillSwitchScope::Org(t.to_owned())),
        "caller" => target.map(|t| KillSwitchScope::Caller(t.to_owned())),
        _ => None,
    }
}
