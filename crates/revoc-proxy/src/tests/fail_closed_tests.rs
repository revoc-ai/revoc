//! Fault-injection tests: every governance failure blocks (SPEC.md §3 P7),
//! and the internal admin API rejects requests without a valid admin key.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use revoc_config::Config;
use revoc_core::{DetectionStage, DetectionTier, Finding, InspectionInput, RevocError};
use revoc_detector::DetectionEngine;
use revoc_pipeline::Pipeline;
use tower::ServiceExt;
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

use crate::app::{build_app_state, build_routers, AppState};

const ADMIN_KEY: &str = "test-admin-key-0123456789";

#[derive(Debug)]
struct FailingStage;

#[async_trait]
impl DetectionStage for FailingStage {
    fn name(&self) -> &'static str {
        "failing"
    }
    fn tier(&self) -> DetectionTier {
        DetectionTier::HttpPlugin
    }
    async fn detect(&self, _input: &InspectionInput) -> Result<Vec<Finding>, RevocError> {
        Err(RevocError::Detection("injected failure".into()))
    }
}

fn base_config(mcp_url: Option<String>) -> Config {
    let mut cfg = Config::default();
    cfg.auth.mode = "none".into();
    cfg.auth.admin_key = ADMIN_KEY.into();
    cfg.server.environment = "development".into();
    cfg.server.dashboard_port = 0;
    cfg.upstream.mock_mode = true;
    cfg.storage.sqlite_path = ":memory:".into();
    cfg.policy.decision_cache_ttl_secs = 0;
    if let Some(url) = mcp_url {
        cfg.mcp.trusted_servers = vec![revoc_config::schema::TrustedMcpServer {
            id: "mock".into(),
            url,
            tls_verify: false,
        }];
    }
    cfg
}

async fn state_with_broken_detector(cfg: Config) -> AppState {
    let mut state = build_app_state(Arc::new(cfg)).await.expect("state");
    let engine = DetectionEngine::from_stages(vec![Arc::new(FailingStage)]);
    state.pipeline = Arc::new(Pipeline::new(Arc::new(engine), Duration::from_secs(1)));
    state
}

fn json_post(uri: &str, body: &serde_json::Value) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

#[tokio::test]
async fn llm_detection_failure_blocks() {
    let state = state_with_broken_detector(base_config(None)).await;
    let resp = build_routers(&state)
        .main
        .oneshot(json_post(
            "/v1/chat/completions",
            &serde_json::json!({"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().contains_key("x-revoc-dashboard"));
    assert!(resp.headers().contains_key("x-revoc-timing"));
}

#[tokio::test]
async fn mcp_detection_failure_blocks_and_never_reaches_tool_server() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(0)
        .mount(&server)
        .await;

    let state =
        state_with_broken_detector(base_config(Some(format!("{}/mcp", server.uri())))).await;
    let resp = build_routers(&state)
        .main
        .oneshot(json_post(
            "/mcp",
            &serde_json::json!({
                "jsonrpc":"2.0","id":"1","method":"tools/call",
                "params":{"name":"read_file","arguments":{"path":"README.md"}}
            }),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    server.verify().await;
}

#[tokio::test]
async fn fail_open_lets_request_through() {
    let mut cfg = base_config(None);
    cfg.policy.fail_open = true;
    let state = state_with_broken_detector(cfg).await;
    let resp = build_routers(&state)
        .main
        .oneshot(json_post(
            "/v1/chat/completions",
            &serde_json::json!({"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}),
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn internal(state: &AppState, req: Request<Body>) -> StatusCode {
    build_routers(state)
        .internal
        .oneshot(req)
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn admin_endpoints_require_admin_key() {
    let state = build_app_state(Arc::new(base_config(None)))
        .await
        .expect("state");

    let reload = || {
        Request::post("/internal/reload")
            .body(Body::empty())
            .expect("req")
    };
    let status = || {
        Request::get("/internal/emergency/kill-switch/status")
            .body(Body::empty())
            .expect("req")
    };

    assert_eq!(internal(&state, reload()).await, StatusCode::UNAUTHORIZED);
    assert_eq!(internal(&state, status()).await, StatusCode::UNAUTHORIZED);

    let mut ok = status();
    ok.headers_mut()
        .insert("x-admin-key", ADMIN_KEY.parse().expect("hdr"));
    assert_eq!(internal(&state, ok).await, StatusCode::OK);

    let mut wrong = reload();
    wrong.headers_mut().insert(
        "x-admin-key",
        "not-the-admin-key-at-all".parse().expect("hdr"),
    );
    assert_eq!(internal(&state, wrong).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unset_or_short_admin_key_disables_admin_api() {
    for key in ["", "short-key"] {
        let mut cfg = base_config(None);
        cfg.auth.admin_key = key.into();
        let state = build_app_state(Arc::new(cfg)).await.expect("state");
        let mut req = Request::get("/internal/emergency/kill-switch/status")
            .body(Body::empty())
            .expect("req");
        if !key.is_empty() {
            req.headers_mut()
                .insert("x-admin-key", key.parse().expect("hdr"));
        }
        assert_eq!(internal(&state, req).await, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn health_still_works_when_detection_is_broken() {
    let state = state_with_broken_detector(base_config(None)).await;
    let resp = build_routers(&state)
        .main
        .oneshot(Request::get("/health").body(Body::empty()).expect("req"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await;
}
