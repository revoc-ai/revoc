//! Dashboard authentication middleware.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

/// Dashboard authentication configuration.
#[derive(Clone)]
pub struct DashboardAuth {
    /// Accepted API keys.
    pub api_keys: Vec<String>,
    /// Auth mode: `"none"` | `"shared"`.
    pub mode: String,
    /// Operator admin key required (in `X-Admin-Key`) to change the
    /// kill-switch. `None` disables kill-switch changes from the dashboard.
    pub admin_key: Option<String>,
}

impl DashboardAuth {
    /// Create a new auth configuration.
    pub fn new(mode: impl Into<String>, api_keys: Vec<String>) -> Self {
        Self {
            api_keys,
            mode: mode.into(),
            admin_key: None,
        }
    }

    /// Require `admin_key` for kill-switch changes.
    #[must_use]
    pub fn with_admin_key(mut self, admin_key: Option<String>) -> Self {
        self.admin_key = admin_key.filter(|k| !k.is_empty());
        self
    }

    /// Validate `X-Admin-Key` against the admin key in constant time.
    /// Independent of `mode`: even with dashboard auth off, the kill-switch
    /// can only be changed with the admin key.
    pub fn is_admin(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.admin_key else {
            return false;
        };
        headers
            .get("x-admin-key")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|k| k.as_bytes().ct_eq(expected.as_bytes()).into())
    }

    /// Validate the `Authorization` or `X-Api-Key` header using constant-time comparison.
    pub fn is_authorized(&self, headers: &HeaderMap) -> bool {
        if self.mode == "none" {
            return true;
        }

        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim_start_matches("Bearer ").trim())
            .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()));

        match provided {
            None => false,
            Some(key) => self
                .api_keys
                .iter()
                .any(|k| key.as_bytes().ct_eq(k.as_bytes()).into()),
        }
    }
}

/// Axum middleware that enforces dashboard authentication.
///
/// Returns HTTP 401 with a JSON body on failure.
/// Passes through immediately when `auth.mode == "none"`.
///
/// # Errors
/// Returns `(StatusCode::UNAUTHORIZED, JSON body)` when the key is missing or invalid.
pub async fn require_auth(
    axum::extract::State(auth): axum::extract::State<DashboardAuth>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    if auth.is_authorized(req.headers()) {
        Ok(next.run(req).await)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Valid API key required. Set Authorization: Bearer <key> or X-Api-Key: <key>."
            })),
        ))
    }
}

/// Axum middleware for the kill-switch mutation routes: requires the operator
/// admin key in `X-Admin-Key`, never a client API key.
///
/// # Errors
/// `(StatusCode::FORBIDDEN, JSON body)` when the admin key is missing,
/// wrong, or not configured.
pub async fn require_admin(
    axum::extract::State(auth): axum::extract::State<DashboardAuth>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<serde_json::Value>)> {
    if auth.is_admin(req.headers()) {
        Ok(next.run(req).await)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "Forbidden",
                "message": "Changing the kill-switch requires the admin key in X-Admin-Key."
            })),
        ))
    }
}
