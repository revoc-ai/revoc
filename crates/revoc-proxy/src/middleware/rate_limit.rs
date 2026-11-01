//! Concurrency limiting middleware: per caller, per org (tenant) and global.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use revoc_core::{CallerContext, RevocErrorResponse};

use crate::{app::AppState, handlers::llm::set_revoc_headers};

/// Which limit rejected a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// The caller's own in-flight limit.
    Caller,
    /// The caller's org (tenant) in-flight limit.
    Org,
    /// The process-wide in-flight limit.
    Global,
}

/// Permits held for the lifetime of one request; dropping releases them.
pub struct Permits {
    _caller: OwnedSemaphorePermit,
    _org: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

/// Concurrency limits keyed by caller and by org, plus one global limit.
///
/// One tenant can no longer exhaust the proxy by spreading load over many
/// API keys: every request also needs a permit from its org and from the
/// global pool.
#[derive(Clone)]
pub struct RateLimiter {
    callers: Arc<DashMap<String, Arc<Semaphore>>>,
    orgs: Arc<DashMap<String, Arc<Semaphore>>>,
    global: Arc<Semaphore>,
    per_caller: usize,
    per_org: usize,
}

impl RateLimiter {
    /// Create a limiter allowing `per_caller`, `per_org` and `global`
    /// requests in flight at once.
    pub fn new(per_caller: usize, per_org: usize, global: usize) -> Self {
        Self {
            callers: Arc::new(DashMap::new()),
            orgs: Arc::new(DashMap::new()),
            global: Arc::new(Semaphore::new(global)),
            per_caller,
            per_org,
        }
    }

    fn semaphore(map: &DashMap<String, Arc<Semaphore>>, key: &str, n: usize) -> Arc<Semaphore> {
        map.entry(key.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(n)))
            .clone()
    }

    /// Try to take a caller, org and global permit without waiting.
    ///
    /// # Errors
    /// The [`LimitScope`] that is full.
    pub fn try_acquire(&self, caller_id: &str, org_id: &str) -> Result<Permits, LimitScope> {
        let caller = Self::semaphore(&self.callers, caller_id, self.per_caller)
            .try_acquire_owned()
            .map_err(|_| LimitScope::Caller)?;
        let org = Self::semaphore(&self.orgs, org_id, self.per_org)
            .try_acquire_owned()
            .map_err(|_| LimitScope::Org)?;
        let global = Arc::clone(&self.global)
            .try_acquire_owned()
            .map_err(|_| LimitScope::Global)?;
        Ok(Permits {
            _caller: caller,
            _org: org,
            _global: global,
        })
    }
}

/// Middleware: reject with 429 when the caller, its org, or the proxy is at capacity.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let (caller_id, org_id) = req.extensions().get::<CallerContext>().map_or_else(
        || ("anonymous".to_string(), "anonymous".to_string()),
        |c| (c.caller_id.clone(), c.org_id.clone()),
    );

    let _permits = match state.rate_limiter.try_acquire(&caller_id, &org_id) {
        Ok(p) => p,
        Err(scope) => {
            tracing::warn!(?scope, caller_id, org_id, "Concurrency limit reached");
            let trace_id = uuid::Uuid::now_v7().to_string();
            let dash_base = &state.config.server.dashboard_base_url;
            let body = RevocErrorResponse::rate_limit(&trace_id, 1, dash_base);
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            set_revoc_headers(
                resp.headers_mut(),
                &trace_id,
                "block",
                &format!("{dash_base}/traces/{trace_id}"),
                "detection=0.0ms,policy=0.0ms,redaction=0.0ms,upstream=0.0ms,total=0.0ms",
                None,
            );
            resp.headers_mut()
                .insert("Retry-After", axum::http::HeaderValue::from_static("1"));
            return resp;
        }
    };

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_limit_applies_per_caller() {
        let rl = RateLimiter::new(1, 10, 10);
        let _a = rl.try_acquire("a", "org").expect("first");
        assert_eq!(rl.try_acquire("a", "org").err(), Some(LimitScope::Caller));
        assert!(rl.try_acquire("b", "org").is_ok());
    }

    #[test]
    fn org_limit_spans_callers() {
        let rl = RateLimiter::new(10, 2, 10);
        let _a = rl.try_acquire("a", "acme").expect("a");
        let _b = rl.try_acquire("b", "acme").expect("b");
        assert_eq!(rl.try_acquire("c", "acme").err(), Some(LimitScope::Org));
        assert!(rl.try_acquire("c", "other").is_ok());
    }

    #[test]
    fn global_limit_spans_orgs_and_permits_release_on_drop() {
        let rl = RateLimiter::new(10, 10, 1);
        let held = rl.try_acquire("a", "x").expect("a");
        assert_eq!(rl.try_acquire("b", "y").err(), Some(LimitScope::Global));
        drop(held);
        assert!(rl.try_acquire("b", "y").is_ok());
    }
}
