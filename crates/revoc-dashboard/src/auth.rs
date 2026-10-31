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
}

impl DashboardAuth {
    /// Create a new auth configuration.
    pub fn new(mode: impl Into<String>, api_keys: Vec<String>) -> Self {
        Self {
            api_keys,
            mode: mode.into(),
        }
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
