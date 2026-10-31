//! Authentication middleware: apikey, jwt, none.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use subtle::ConstantTimeEq;
use tracing::warn;

use revoc_core::{CallerContext, RevocErrorResponse};

use crate::app::AppState;

#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    org: Option<String>,
}

/// Middleware: authenticate the request and insert a [`CallerContext`] extension.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let mode = state.config.auth.mode.as_str();

    let caller = match mode {
        "none" => {
            // Dev mode — unauthenticated, default caller
            CallerContext {
                org_id: "dev".into(),
                caller_id: "dev".into(),
                environment: state.config.server.environment.clone(),
                ..Default::default()
            }
        }
        "apikey" => {
            if let Some(ctx) = authenticate_apikey(&req, &state) {
                ctx
            } else {
                let trace_id = uuid::Uuid::now_v7().to_string();
                let body = RevocErrorResponse::internal_error(
                    &trace_id,
                    &state.config.server.dashboard_base_url,
                );
                return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            }
        }
        "jwt" => {
            if let Some(ctx) = authenticate_jwt(&req, &state) {
                ctx
            } else {
                let trace_id = uuid::Uuid::now_v7().to_string();
                let body = RevocErrorResponse::internal_error(
                    &trace_id,
                    &state.config.server.dashboard_base_url,
                );
                return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            }
        }
        other => {
            warn!(mode = other, "Unknown auth mode; defaulting to deny");
            let trace_id = uuid::Uuid::now_v7().to_string();
            let body = RevocErrorResponse::internal_error(
                &trace_id,
                &state.config.server.dashboard_base_url,
            );
            return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
        }
    };

    req.extensions_mut().insert(caller);
    next.run(req).await
}

fn authenticate_apikey(req: &Request, state: &AppState) -> Option<CallerContext> {
    let provided = extract_api_key(req)?;

    // Load keys from file first, then env
    let keys = load_api_keys(state);

    let matched = keys
        .iter()
        .any(|k| provided.as_bytes().ct_eq(k.as_bytes()).into());

    if !matched {
        return None;
    }

    // Derive stable caller_id = hex(sha256(key)[..8]) — never store raw key
    let caller_id = derive_caller_id(&provided);

    Some(CallerContext {
        org_id: "default".into(),
        caller_id,
        environment: state.config.server.environment.clone(),
        enforcement_mode: if state.config.policy.enforcement_mode == "shadow" {
            revoc_core::EnforcementMode::Shadow
        } else {
            revoc_core::EnforcementMode::Enforce
        },
        ..Default::default()
    })
}

fn authenticate_jwt(req: &Request, state: &AppState) -> Option<CallerContext> {
    use jsonwebtoken::{decode, DecodingKey, Validation};

    let token = extract_bearer_token(req)?;
    let secret = std::env::var(&state.config.auth.jwt_secret_env).ok()?;

    let data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?;

    Some(CallerContext {
        org_id: data.claims.org.unwrap_or_else(|| "unknown".into()),
        caller_id: data.claims.sub,
        environment: state.config.server.environment.clone(),
        ..Default::default()
    })
}

fn extract_api_key(req: &Request) -> Option<String> {
    // Check Authorization: Bearer <key>
    if let Some(v) = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(key) = v.strip_prefix("Bearer ") {
            return Some(key.trim().to_owned());
        }
    }
    // Check x-api-key
    req.headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn extract_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_owned())
}

pub(crate) fn load_api_keys(state: &AppState) -> Vec<String> {
    // File takes precedence over env
    if !state.config.auth.api_keys_file.is_empty() {
        if let Ok(content) = std::fs::read_to_string(&state.config.auth.api_keys_file) {
            return content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect();
        }
    }
    // Fall back to env
    std::env::var(&state.config.auth.api_keys_env)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Derive a stable, non-reversible caller ID from an API key.
pub fn derive_caller_id(key: &str) -> String {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(key.as_bytes());
    hex::encode(&hash[..8])
}
