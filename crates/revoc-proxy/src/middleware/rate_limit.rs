//! Per-caller rate limiting middleware.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use dashmap::DashMap;
use tokio::sync::Semaphore;

use revoc_core::{CallerContext, RevocErrorResponse};

use crate::app::AppState;

/// Shared per-caller concurrency semaphore map.
#[derive(Clone, Default)]
pub struct RateLimiter {
    semaphores: Arc<DashMap<String, Arc<Semaphore>>>,
    max_concurrent: usize,
}

impl RateLimiter {
    /// Create a limiter with `max_concurrent` requests per caller.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphores: Arc::new(DashMap::new()),
            max_concurrent,
        }
    }

    /// Try to acquire a permit for `caller_id`. Returns `None` if at limit.
    pub fn try_acquire(&self, caller_id: &str) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let sem = self
            .semaphores
            .entry(caller_id.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_concurrent)))
            .clone();
        sem.try_acquire_owned().ok()
    }
}

/// Middleware: apply per-caller rate limiting.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let caller_id = req
        .extensions()
        .get::<CallerContext>()
        .map_or_else(|| "anonymous".to_string(), |c| c.caller_id.clone());

    let Some(_permit) = state.rate_limiter.try_acquire(&caller_id) else {
        let trace_id = uuid::Uuid::now_v7().to_string();
        let body =
            RevocErrorResponse::rate_limit(&trace_id, 30, &state.config.server.dashboard_base_url);
        return (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    };

    next.run(req).await
    // _permit dropped here, releasing the slot
}
