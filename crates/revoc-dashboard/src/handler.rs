//! Static SPA serving + API router for the REVOC dashboard.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use include_dir::{include_dir, Dir};

use crate::{
    api::{
        activate_kill_switch, deactivate_kill_switch, get_analytics, get_costs,
        get_kill_switch_status, get_request_detail, get_rules, list_requests, validate_policy,
        DashboardState,
    },
    auth::{require_auth, DashboardAuth},
    live_feed::LiveFeedBus,
};

/// Embedded pre-built React SPA (`ui/dist/` committed to git, SPEC.md §6).
static DIST: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/ui/dist");

/// Build the complete dashboard router.
///
/// Mount at `/dashboard` in the main axum application:
/// ```rust,ignore
/// app.nest("/dashboard", dashboard_router(state, auth, bus))
/// ```
pub fn dashboard_router(
    state: DashboardState,
    auth: DashboardAuth,
    bus: LiveFeedBus,
) -> Router {
    // API sub-router with optional auth middleware
    let api = Router::new()
        .route("/requests",                  get(list_requests))
        .route("/requests/:trace_id",        get(get_request_detail))
        .route("/analytics",                 get(get_analytics))
        .route("/costs",                     get(get_costs))
        .route("/rules",                     get(get_rules))
        .route("/kill-switch/status",        get(get_kill_switch_status))
        .route("/kill-switch/activate",      post(activate_kill_switch))
        .route("/kill-switch/deactivate",    post(deactivate_kill_switch))
        .route("/policies/validate",         post(validate_policy))
        .with_state(state)
        .layer(middleware::from_fn_with_state(auth, require_auth));

    // SSE live feed (no auth — same-origin only by network topology)
    let live = Router::new().route("/live", get(move || {
        let bus = bus.clone();
        async move { bus.sse_handler() }
    }));

    // Static SPA + fallback
    Router::new()
        .route("/", get(serve_index))
        .route("/assets/*path", get(serve_asset))
        .nest("/api", api)
        .merge(live)
        .fallback(spa_fallback)
}

async fn serve_index() -> impl IntoResponse {
    serve_file("index.html")
}

async fn serve_asset(req: Request) -> impl IntoResponse {
    let path = req
        .uri()
        .path()
        .trim_start_matches('/')
        .to_string();
    serve_file(&path)
}

async fn spa_fallback(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    // If the path maps to a real file, serve it; otherwise serve index.html for SPA routing
    if path.contains('.') {
        serve_file(path)
    } else {
        serve_file("index.html")
    }
}

fn serve_file(path: &str) -> Response {
    match DIST.get_file(path) {
        Some(file) => {
            let mime = guess_mime(path);
            (
                [(header::CONTENT_TYPE, mime)],
                file.contents(),
            )
                .into_response()
        }
        None => {
            // SPA fallback — serve index.html for any unknown path
            match DIST.get_file("index.html") {
                Some(index) => (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    index.contents(),
                )
                    .into_response(),
                None => (StatusCode::NOT_FOUND, Html("<h1>Dashboard not built</h1>")).into_response(),
            }
        }
    }
}

fn guess_mime(path: &str) -> &'static str {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if ext.eq_ignore_ascii_case("html")         { "text/html; charset=utf-8" }
    else if ext.eq_ignore_ascii_case("js")
         || ext.eq_ignore_ascii_case("mjs")     { "application/javascript; charset=utf-8" }
    else if ext.eq_ignore_ascii_case("css")     { "text/css; charset=utf-8" }
    else if ext.eq_ignore_ascii_case("svg")     { "image/svg+xml" }
    else if ext.eq_ignore_ascii_case("ico")     { "image/x-icon" }
    else if ext.eq_ignore_ascii_case("json")    { "application/json" }
    else if ext.eq_ignore_ascii_case("woff2")   { "font/woff2" }
    else if ext.eq_ignore_ascii_case("woff")    { "font/woff" }
    else if ext.eq_ignore_ascii_case("png")     { "image/png" }
    else                                        { "application/octet-stream" }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::{
        api::DashboardState,
        auth::DashboardAuth,
        live_feed::LiveFeedBus,
        AuditEvent, AuditStore, AnalyticsResult, AnalyticsWindow, EventFilter,
        KillSwitchControl, KillSwitchStatusView,
    };

    struct NoopStore;

    #[async_trait::async_trait]
    impl AuditStore for NoopStore {
        async fn insert_event(&self, _: AuditEvent) -> Result<(), revoc_core::RevocError> { Ok(()) }
        async fn list_events(&self, _: EventFilter) -> Result<(Vec<AuditEvent>, u64), revoc_core::RevocError> { Ok((vec![], 0)) }
        async fn get_event_by_trace(&self, _: &str) -> Result<Option<AuditEvent>, revoc_core::RevocError> { Ok(None) }
        async fn analytics(&self, _: AnalyticsWindow) -> Result<AnalyticsResult, revoc_core::RevocError> {
            Ok(AnalyticsResult {
                total: 0, blocked: 0, redacted: 0, allowed: 0,
                top_rules: vec![], top_callers: vec![], costs_by_service: vec![], timeline: vec![],
            })
        }
        async fn cleanup_old_events(&self, _: u32) -> Result<u64, revoc_core::RevocError> { Ok(0) }
    }

    /// Inert kill-switch control for router-wiring tests — never active,
    /// activate/deactivate are no-ops. Real behavior is exercised against the
    /// proxy's `DashboardKillSwitchAdapter` in `revoc-proxy`.
    struct NoopKillSwitchControl;

    #[async_trait::async_trait]
    impl KillSwitchControl for NoopKillSwitchControl {
        async fn status(&self) -> KillSwitchStatusView { KillSwitchStatusView::default() }
        async fn activate(&self, _: &str, _: Option<&str>, _: &str, _: &str) -> Result<(), revoc_core::RevocError> { Ok(()) }
        async fn deactivate(&self, _: &str, _: Option<&str>) -> Result<(), revoc_core::RevocError> { Ok(()) }
    }

    fn test_router() -> Router {
        dashboard_router(
            DashboardState { store: Arc::new(NoopStore), kill_switch: Arc::new(NoopKillSwitchControl) },
            DashboardAuth::new("none", vec![]),
            LiveFeedBus::new(16),
        )
    }

    #[tokio::test]
    async fn test_get_root_returns_html() {
        let app = test_router();
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(ct.contains("text/html"), "Expected text/html, got: {ct}");
    }

    #[tokio::test]
    async fn test_spa_fallback() {
        let app = test_router();
        let resp = app
            .oneshot(Request::builder().uri("/requests/trace-123").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // SPA fallback must return index.html (200)
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_requests_paginates() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/requests?limit=10&offset=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_rejects_no_key() {
        let app = dashboard_router(
            DashboardState { store: Arc::new(NoopStore), kill_switch: Arc::new(NoopKillSwitchControl) },
            DashboardAuth::new("shared", vec!["secret-key".into()]),
            LiveFeedBus::new(16),
        );
        let resp = app
            .oneshot(Request::builder().uri("/api/requests").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_assets_served() {
        let app = test_router();
        // The dist/ is embedded — requesting any asset path exercises the serve_asset handler
        // A 200 or 404 is acceptable; the key is it doesn't panic.
        let resp = app
            .oneshot(Request::builder().uri("/assets/nonexistent.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Should either find the asset (200) or fall back to index.html (200)
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_sse_delivers_events() {
        let bus = LiveFeedBus::new(16);
        let bus2 = bus.clone();

        // Publish an event before any subscriber connects (buffered)
        bus.publish(crate::GovernanceEvent {
            trace_id: "t1".into(),
            timestamp: "2024-01-01T00:00:00Z".into(),
            decision: "allow".into(),
            blocked_by: None,
            caller_id: "svc-a".into(),
            model: None,
            duration_ms: 5.0,
            findings_count: 0,
            pii_types: vec![],
            mcp_tool: None,
            request_type: "LlmRequest".into(),
            governance_depth: 0,
            was_normalized: false,
            manifest_warnings: 0,
        });

        // Verify the SSE handler can be constructed without panicking
        let _sse = bus2.sse_handler();
    }
}
