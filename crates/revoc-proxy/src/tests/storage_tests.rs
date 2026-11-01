//! Storage tests: exit-path audit, MCP session recording, and the Postgres
//! and Redis backends.
//!
//! The Postgres and Redis tests run against real servers when
//! `REVOC_TEST_POSTGRES_URL` / `REVOC_TEST_REDIS_URL` are set (CI provides
//! both) and are skipped otherwise.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use http::{Request, StatusCode};
use revoc_config::Config;
use revoc_dashboard::{AuditEvent, AuditStore, EventFilter};
use tower::ServiceExt;
use wiremock::{
    matchers::{body_string_contains, method},
    Mock, MockServer, ResponseTemplate,
};

use crate::app::{build_app_state, build_routers, AppState, SessionStore};

fn config(mcp_url: Option<String>) -> Config {
    let dir = std::env::temp_dir().join(format!("revoc-st-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("dir");
    let mut cfg = Config::default();
    cfg.auth.mode = "none".into();
    cfg.server.environment = "development".into();
    cfg.server.dashboard_port = 0;
    cfg.upstream.mock_mode = true;
    cfg.storage.sqlite_path = dir.join("revoc.db").display().to_string();
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

fn json_post(uri: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

/// Wait for queued audit writes, then return every stored event.
async fn events(state: &AppState) -> Vec<AuditEvent> {
    for _ in 0..200 {
        if state
            .pending_audit_writes
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let filter = EventFilter {
        limit: Some(100),
        ..EventFilter::default()
    };
    state.audit_store.list_events(filter).await.expect("list").0
}

// ── Exit-path audit ───────────────────────────────────────────────────────────

#[tokio::test]
async fn malformed_request_is_audited() {
    let state = build_app_state(Arc::new(config(None)))
        .await
        .expect("state");
    let resp = build_routers(&state)
        .main
        .oneshot(json_post("/v1/chat/completions", "{not json"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let all = events(&state).await;
    assert_eq!(all.len(), 1, "{all:?}");
    let e = &all[0];
    assert_eq!(e.decision, "reject");
    assert_eq!(e.policy_engine.as_deref(), Some("exit:400"));
    assert_eq!(e.caller_id.as_deref(), Some("dev"));
    assert_eq!(e.request_type.as_deref(), Some("LlmRequest"));
}

#[tokio::test]
async fn depth_limit_on_mcp_is_audited() {
    let state = build_app_state(Arc::new(config(None)))
        .await
        .expect("state");
    let mut req = json_post(
        "/mcp",
        r#"{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"t","arguments":{}}}"#,
    );
    req.headers_mut()
        .insert("X-Revoc-Depth", "10".parse().expect("header"));
    let resp = build_routers(&state)
        .main
        .oneshot(req)
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let all = events(&state).await;
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].decision, "error");
    assert_eq!(all[0].request_type.as_deref(), Some("McpToolCall"));
    assert_eq!(all[0].governance_depth, 10);
}

#[tokio::test]
async fn governed_request_gets_no_extra_fallback_event() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0", "id": "1",
            "result": {"content": [{"type": "text", "text": "ok"}]}
        })))
        .mount(&server)
        .await;
    let state = build_app_state(Arc::new(config(Some(format!("{}/mcp", server.uri())))))
        .await
        .expect("state");
    let (status, _) = mcp_call(&state, "read_file").await;
    assert_eq!(status, StatusCode::OK);

    let all = events(&state).await;
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].tool_name.as_deref(), Some("read_file"));
    assert!(
        !all[0]
            .policy_engine
            .as_deref()
            .unwrap_or("")
            .starts_with("exit:"),
        "{all:?}"
    );
}

#[tokio::test]
async fn mock_mode_response_is_audited() {
    let state = build_app_state(Arc::new(config(None)))
        .await
        .expect("state");
    let resp = build_routers(&state)
        .main
        .oneshot(json_post(
            "/v1/chat/completions",
            r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#,
        ))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let all = events(&state).await;
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].decision, "allow");
}

#[tokio::test]
async fn unauthenticated_requests_are_not_audited() {
    let mut cfg = config(None);
    cfg.auth.mode = "apikey".into();
    let state = build_app_state(Arc::new(cfg)).await.expect("state");
    let resp = build_routers(&state)
        .main
        .oneshot(json_post("/v1/chat/completions", "{}"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(events(&state).await.is_empty());
}

// ── MCP session recording ─────────────────────────────────────────────────────

async fn mcp_call(state: &AppState, tool: &str) -> (StatusCode, serde_json::Value) {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{{"name":"{tool}","arguments":{{}}}}}}"#
    );
    let resp = build_routers(state)
        .main
        .oneshot(json_post("/mcp", &body))
        .await
        .expect("response");
    let status = resp.status();
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn wait_for_session(
    state: &AppState,
    pred: impl Fn(&revoc_core::SessionState) -> bool,
) -> revoc_core::SessionState {
    for _ in 0..200 {
        if let Some(s) = state.session_store.get("dev:dev").await {
            if pred(&s) {
                return s;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("session never reached the expected state");
}

#[tokio::test]
async fn mcp_session_is_recorded_and_exfil_pattern_blocks_the_send() {
    let server = MockServer::start().await;
    let rows: Vec<serde_json::Value> = (0..600)
        .map(|i| serde_json::json!({"id": i, "owner": "alice@example.com"}))
        .collect();
    Mock::given(method("POST"))
        .and(body_string_contains("db_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0", "id": "1",
            "result": {
                "content": [{"type": "text", "text": "600 rows, contact alice@example.com"}],
                "structuredContent": {"rows": rows}
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("http_post"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(0)
        .mount(&server)
        .await;

    let state = build_app_state(Arc::new(config(Some(format!("{}/mcp", server.uri())))))
        .await
        .expect("state");

    let (status, _) = mcp_call(&state, "db_query").await;
    assert_eq!(status, StatusCode::OK);
    let session = wait_for_session(&state, |s| s.total_rows_read >= 600).await;
    assert_eq!(session.total_rows_read, 600);
    assert_eq!(session.tools_called.len(), 1);
    assert_eq!(session.tools_called[0].0, "db_query");
    assert!(!session.pii_entities_seen.is_empty(), "{session:?}");
    assert!(!session.external_send_attempted);

    // Rows read + PII seen + an external send: session_data_exfil_v1.
    let (_, body) = mcp_call(&state, "http_post").await;
    assert!(body.get("error").is_some(), "send was not blocked: {body}");
    let session = wait_for_session(&state, |s| s.external_send_attempted).await;
    assert_eq!(session.tools_called.len(), 2);
    server.verify().await;

    let all = events(&state).await;
    assert!(all.iter().any(|e| e.decision == "block"
        && e.violated_rules
            .as_deref()
            .unwrap_or("")
            .contains("session_data_exfil_v1")));
    // Only entity types are stored, never the address itself.
    assert!(!format!("{session:?}").contains("alice@example.com"));
}

// ── Redis session store ───────────────────────────────────────────────────────

#[tokio::test]
async fn redis_session_store_round_trip() {
    let Ok(url) = std::env::var("REVOC_TEST_REDIS_URL") else {
        eprintln!("skipped: REVOC_TEST_REDIS_URL not set");
        return;
    };
    let store = crate::storage::RedisSessionStore::new(&url).expect("client");
    let caller = revoc_core::CallerContext {
        org_id: "acme".into(),
        caller_id: format!("c-{}", uuid::Uuid::now_v7()),
        ..Default::default()
    };
    let sid = crate::storage::session::session_id(&caller);
    let s = crate::storage::session::record(
        None,
        &caller,
        &[],
        &crate::storage::session::SessionActivity {
            tool: Some("db_query"),
            rows_read: 42,
            external_send: false,
        },
    );
    store.set(&sid, s, 60).await.expect("set");
    let got = store.get(&sid).await.expect("stored");
    assert_eq!(got.total_rows_read, 42);
    assert_eq!(got.tools_called[0].0, "db_query");

    // A second store instance (another proxy) sees the same session.
    let other = crate::storage::RedisSessionStore::new(&url).expect("client");
    assert!(other.get(&sid).await.is_some());

    store.delete(&sid).await.expect("delete");
    assert!(other.get(&sid).await.is_none());
}

// ── Postgres audit store ──────────────────────────────────────────────────────

/// The Postgres tests share one database and clear its tables, so they run
/// one at a time.
static PG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn postgres_backend_requires_a_url() {
    let mut cfg = config(None);
    cfg.storage.backend = "postgres".into();
    cfg.storage.postgres_url_env = "REVOC_TEST_UNSET_DATABASE_URL".into();
    let Err(err) = build_app_state(Arc::new(cfg)).await else {
        panic!("started without a database URL");
    };
    assert!(
        err.to_string().contains("REVOC_TEST_UNSET_DATABASE_URL"),
        "{err}"
    );
}

#[tokio::test]
async fn unknown_storage_backend_is_rejected() {
    let mut cfg = config(None);
    cfg.storage.backend = "mongo".into();
    assert!(build_app_state(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn postgres_backend_audits_requests_end_to_end() {
    let (Ok(_), Ok(_)) = (
        std::env::var("REVOC_TEST_POSTGRES_URL"),
        std::env::var("REVOC_TEST_KILL_SWITCH_KEY"),
    ) else {
        eprintln!("skipped: REVOC_TEST_POSTGRES_URL / REVOC_TEST_KILL_SWITCH_KEY not set");
        return;
    };
    let _guard = PG_LOCK.lock().await;
    let mut cfg = config(None);
    cfg.storage.backend = "postgres".into();
    cfg.storage.postgres_url_env = "REVOC_TEST_POSTGRES_URL".into();
    cfg.kill_switch.signing_key_env = "REVOC_TEST_KILL_SWITCH_KEY".into();
    let state = build_app_state(Arc::new(cfg)).await.expect("state");
    assert!(state
        .kill_switch_service
        .status_json()
        .to_string()
        .contains("postgres"));

    let resp = build_routers(&state)
        .main
        .oneshot(json_post("/v1/chat/completions", "{not json"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let trace = resp
        .headers()
        .get("X-Revoc-Trace-ID")
        .and_then(|v| v.to_str().ok())
        .expect("trace header")
        .to_owned();
    events(&state).await;
    let e = state
        .audit_store
        .get_event_by_trace(&trace)
        .await
        .expect("query")
        .expect("event in postgres");
    assert_eq!(e.decision, "reject");
}

fn pg_event(trace: &str, decision: &str, rules: Option<&str>, created_at: &str) -> AuditEvent {
    AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        org_id: Some("acme".into()),
        request_id: uuid::Uuid::now_v7().to_string(),
        timestamp: created_at.to_owned(),
        caller_id: Some("agent-1".into()),
        caller_team: None,
        environment: Some("test".into()),
        decision: decision.to_owned(),
        effective_action: decision.to_owned(),
        enforcement_mode: "enforce".into(),
        violated_rules: rules.map(str::to_owned),
        finding_types: None,
        model: Some("gpt-4o-mini".into()),
        provider: Some("openai".into()),
        tool_name: None,
        request_type: Some("LlmRequest".into()),
        governance_depth: 1,
        prompt_tokens: Some(10),
        completion_tokens: Some(5),
        estimated_cost_usd: Some(0.25),
        duration_ms: Some(3.5),
        detection_ms: Some(1.0),
        policy_ms: Some(0.5),
        was_normalized: true,
        manifest_warnings: 2,
        trace_id: Some(trace.to_owned()),
        policy_engine: Some("Native".into()),
        created_at: created_at.to_owned(),
    }
}

#[tokio::test]
async fn postgres_audit_store_contract() {
    let Ok(url) = std::env::var("REVOC_TEST_POSTGRES_URL") else {
        eprintln!("skipped: REVOC_TEST_POSTGRES_URL not set");
        return;
    };
    let _guard = PG_LOCK.lock().await;
    let store = crate::storage::PostgresAuditStore::connect(&url, 4, true)
        .await
        .expect("connect");
    // Creating the schema twice is harmless (admin API may own it).
    let store2 = crate::storage::PostgresAuditStore::connect(&url, 4, true)
        .await
        .expect("connect again");
    sqlx::query("DELETE FROM audit_events")
        .execute(&store.pool())
        .await
        .expect("clean");

    let now = chrono::Utc::now();
    let trace = uuid::Uuid::now_v7().to_string();
    let first = pg_event(&trace, "allow", None, &now.to_rfc3339());
    let mut second = pg_event(
        &trace,
        "block",
        Some("pii_ssn_v1, secret_aws_v1"),
        &now.to_rfc3339(),
    );
    second.id = uuid::Uuid::now_v7().to_string();
    let old = pg_event(
        "old",
        "block",
        Some("pii_ssn_v1"),
        &(now - chrono::Duration::days(40)).to_rfc3339(),
    );
    for e in [&first, &second, &old] {
        store.insert_event(e.clone()).await.expect("insert");
    }
    // Re-inserting the same id updates instead of failing.
    store2.insert_event(first.clone()).await.expect("upsert");

    let (rows, total) = store
        .list_events(EventFilter::default())
        .await
        .expect("list");
    assert_eq!(total, 3);
    assert_eq!(rows.len(), 3);
    let got = rows.iter().find(|e| e.id == first.id).expect("first");
    assert!(got.was_normalized);
    assert_eq!(got.manifest_warnings, 2);
    assert_eq!(got.prompt_tokens, Some(10));
    assert!((got.estimated_cost_usd.unwrap_or_default() - 0.25).abs() < 1e-6);

    let latest = store
        .get_event_by_trace(&trace)
        .await
        .expect("trace")
        .expect("found");
    assert_eq!(latest.id, second.id);

    let a = store
        .analytics(revoc_dashboard::AnalyticsWindow::Hour24)
        .await
        .expect("analytics");
    assert_eq!((a.total, a.blocked, a.allowed), (2, 1, 1));
    assert_eq!(a.top_rules.len(), 2);
    assert_eq!(a.top_callers[0].count, 2);
    assert!((a.costs_by_service[0].cost_usd - 0.5).abs() < 1e-6);
    assert_eq!(a.timeline.len(), 1);
    assert!(a.timeline[0].ts.ends_with(":00:00Z"), "{:?}", a.timeline);
    let month = store
        .analytics(revoc_dashboard::AnalyticsWindow::Day30)
        .await
        .expect("analytics");
    assert_eq!(month.total, 2, "40-day-old event is outside 30d");

    assert_eq!(store.cleanup_old_events(30).await.expect("cleanup"), 1);

    crate::app::KillSwitchLogWriter::log(&store, "global", None, "activate", "test", None)
        .await
        .expect("kill-switch log");
}

#[tokio::test]
async fn postgres_kill_switch_store_compare_and_swap() {
    use crate::kill_switch::store::{KillSwitchStore, PostgresKillSwitchStore};
    let Ok(url) = std::env::var("REVOC_TEST_POSTGRES_URL") else {
        eprintln!("skipped: REVOC_TEST_POSTGRES_URL not set");
        return;
    };
    let _guard = PG_LOCK.lock().await;
    let audit = crate::storage::PostgresAuditStore::connect(&url, 2, true)
        .await
        .expect("connect");
    sqlx::query("DELETE FROM kill_switch_state")
        .execute(&audit.pool())
        .await
        .expect("clean");
    let a = PostgresKillSwitchStore::new(audit.pool());
    let b = PostgresKillSwitchStore::new(audit.pool());
    assert_eq!(a.load().await.expect("load"), None);
    assert!(a.compare_and_swap(0, 1, "v1").await.expect("cas"));
    // A second writer holding a stale version loses.
    assert!(!b.compare_and_swap(0, 1, "v1-other").await.expect("cas"));
    assert!(b.compare_and_swap(1, 2, "v2").await.expect("cas"));
    assert!(!a.compare_and_swap(1, 2, "v2-stale").await.expect("cas"));
    assert_eq!(a.load().await.expect("load").as_deref(), Some("v2"));
}

// ── Redis kill-switch store ───────────────────────────────────────────────────

#[tokio::test]
async fn redis_kill_switch_store_compare_and_swap() {
    use crate::kill_switch::store::{KillSwitchStore, RedisKillSwitchStore};
    let Ok(url) = std::env::var("REVOC_TEST_REDIS_URL") else {
        eprintln!("skipped: REVOC_TEST_REDIS_URL not set");
        return;
    };
    // The script reads the version from the stored document itself.
    let signed = |v: u64| {
        serde_json::json!({"doc": serde_json::json!({"version": v}).to_string(), "sig": "x"})
            .to_string()
    };
    let channel = format!("revoc:test:{}", uuid::Uuid::now_v7());
    let a = RedisKillSwitchStore::new(&url, &channel).expect("client");
    let b = RedisKillSwitchStore::new(&url, &channel).expect("client");
    assert_eq!(a.load().await.expect("load"), None);
    assert!(a.compare_and_swap(0, 1, &signed(1)).await.expect("cas"));
    assert!(!b.compare_and_swap(0, 1, &signed(1)).await.expect("cas"));
    assert!(b.compare_and_swap(1, 2, &signed(2)).await.expect("cas"));
    assert!(!a.compare_and_swap(1, 2, &signed(2)).await.expect("cas"));
    assert_eq!(a.load().await.expect("load"), Some(signed(2)));
}
