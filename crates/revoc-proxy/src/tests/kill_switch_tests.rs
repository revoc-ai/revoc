use std::sync::Arc;

use revoc_core::CallerContext;

use crate::kill_switch::{KillSwitchEntry, KillSwitchScope, KillSwitchState};

fn make_state() -> Arc<KillSwitchState> {
    Arc::new(KillSwitchState::new())
}

fn make_caller(org_id: &str, caller_id: &str) -> CallerContext {
    CallerContext {
        org_id: org_id.into(),
        caller_id: caller_id.into(),
        ..Default::default()
    }
}

fn entry(scope: KillSwitchScope) -> KillSwitchEntry {
    KillSwitchEntry {
        activated_by: "test".into(),
        activated_at: chrono::Utc::now(),
        reason: "test".into(),
        scope,
    }
}

#[test]
fn test_inactive_by_default() {
    let ks = make_state();
    let caller = make_caller("org1", "caller1");
    assert!(!ks.is_active_for(&caller));
}

#[test]
fn test_active_global_blocks_all_callers() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Global));
    assert!(ks.is_active_for(&make_caller("org-a", "caller-1")));
    assert!(ks.is_active_for(&make_caller("org-b", "caller-2")));
}

#[test]
fn test_org_scope_blocks_org_a_not_b() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Org("org-a".into())));
    assert!(ks.is_active_for(&make_caller("org-a", "any-caller")));
    assert!(!ks.is_active_for(&make_caller("org-b", "any-caller")));
}

#[test]
fn test_caller_scope_blocks_specific_caller() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Caller("bad-caller".into())));
    assert!(ks.is_active_for(&make_caller("org1", "bad-caller")));
    assert!(!ks.is_active_for(&make_caller("org1", "good-caller")));
}

#[test]
fn test_deactivate_restores_traffic() {
    let ks = make_state();
    let scope = KillSwitchScope::Global;
    ks.activate(entry(scope.clone()));
    assert!(ks.is_active_for(&make_caller("org1", "c1")));

    ks.deactivate(&scope);
    assert!(!ks.is_active_for(&make_caller("org1", "c1")));
}

#[test]
fn test_deactivate_org_scope() {
    let ks = make_state();
    let scope = KillSwitchScope::Org("org-x".into());
    ks.activate(entry(scope.clone()));
    assert!(ks.is_active_for(&make_caller("org-x", "any")));

    ks.deactivate(&scope);
    assert!(!ks.is_active_for(&make_caller("org-x", "any")));
}

#[test]
fn test_snapshot_reflects_state() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Global));
    ks.activate(entry(KillSwitchScope::Org("org-1".into())));

    let snap = ks.status_snapshot();
    assert!(snap.global);
    assert_eq!(snap.by_org.len(), 1);
    assert!(snap.by_caller.is_empty());
}

#[test]
fn test_multiple_org_scopes_independent() {
    let ks = make_state();
    ks.activate(entry(KillSwitchScope::Org("org-a".into())));
    ks.activate(entry(KillSwitchScope::Org("org-b".into())));

    assert!(ks.is_active_for(&make_caller("org-a", "c")));
    assert!(ks.is_active_for(&make_caller("org-b", "c")));

    ks.deactivate(&KillSwitchScope::Org("org-a".into()));
    assert!(!ks.is_active_for(&make_caller("org-a", "c")));
    assert!(ks.is_active_for(&make_caller("org-b", "c")));
}

// ── Durable, signed, reconciled service ───────────────────────────────────────

mod service {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use revoc_config::Config;
    use revoc_core::RevocError;
    use tower::ServiceExt as _;

    use super::{entry, make_caller};
    use crate::app::{build_app_state, build_routers, KillSwitchLogWriter};
    use crate::kill_switch::store::KillSwitchStore;
    use crate::kill_switch::{KillSwitchScope, KillSwitchService};

    const KEY_A: &[u8] = b"kill-switch-signing-key-aaaaaaaaaaaaaaaa";
    const KEY_B: &[u8] = b"kill-switch-signing-key-bbbbbbbbbbbbbbbb";

    /// In-memory store with a kill wire to simulate an outage.
    #[derive(Default)]
    struct MemStore {
        value: Mutex<Option<(u64, String)>>,
        down: AtomicBool,
    }

    impl MemStore {
        fn check(&self) -> Result<(), RevocError> {
            if self.down.load(Ordering::SeqCst) {
                Err(RevocError::Database("store down".into()))
            } else {
                Ok(())
            }
        }
        fn raw(&self) -> Option<String> {
            self.value
                .lock()
                .expect("lock")
                .as_ref()
                .map(|(_, s)| s.clone())
        }
        fn set_raw(&self, version: u64, s: &str) {
            *self.value.lock().expect("lock") = Some((version, s.to_owned()));
        }
    }

    #[async_trait]
    impl KillSwitchStore for MemStore {
        fn kind(&self) -> &'static str {
            "memory-test"
        }
        async fn load(&self) -> Result<Option<String>, RevocError> {
            self.check()?;
            Ok(self.raw())
        }
        async fn compare_and_swap(
            &self,
            expected: u64,
            new_version: u64,
            signed: &str,
        ) -> Result<bool, RevocError> {
            self.check()?;
            let mut v = self.value.lock().expect("lock");
            let current = v.as_ref().map_or(0, |(ver, _)| *ver);
            if current != expected {
                return Ok(false);
            }
            *v = Some((new_version, signed.to_owned()));
            Ok(true)
        }
    }

    #[derive(Default)]
    struct MemLog(Mutex<Vec<String>>);

    #[async_trait]
    impl KillSwitchLogWriter for MemLog {
        async fn log(
            &self,
            scope: &str,
            _scope_value: Option<&str>,
            action: &str,
            _activated_by: &str,
            _reason: Option<&str>,
        ) -> Result<(), RevocError> {
            self.0
                .lock()
                .expect("lock")
                .push(format!("{action}:{scope}"));
            Ok(())
        }
    }

    async fn service(
        store: &Arc<MemStore>,
        key: &[u8],
        fail_closed: bool,
    ) -> (Arc<KillSwitchService>, Arc<MemLog>) {
        let log = Arc::new(MemLog::default());
        let svc = KillSwitchService::with_store(
            store.clone(),
            Some(key.to_vec()),
            log.clone(),
            Duration::from_millis(50),
            fail_closed,
            None,
        )
        .await;
        (svc, log)
    }

    #[tokio::test]
    async fn activation_survives_restart() {
        let store = Arc::new(MemStore::default());
        let (a, log) = service(&store, KEY_A, false).await;
        let out = a
            .activate(entry(KillSwitchScope::Global))
            .await
            .expect("activate");
        assert!(out.durable);
        assert_eq!(out.version, 1);
        assert_eq!(log.0.lock().expect("lock").as_slice(), ["activate:global"]);

        // A new process reads the same store before serving traffic.
        let (b, _) = service(&store, KEY_A, false).await;
        assert!(b.state.is_active_for(&make_caller("o", "c")));
        assert_eq!(b.state.version(), 1);
    }

    #[tokio::test]
    async fn instances_converge_through_reconcile() {
        let store = Arc::new(MemStore::default());
        let (a, _) = service(&store, KEY_A, false).await;
        let (b, _) = service(&store, KEY_A, false).await;

        a.activate(entry(KillSwitchScope::Org("acme".into())))
            .await
            .expect("activate");
        assert!(!b.state.is_active_for(&make_caller("acme", "c")));
        b.sync_once().await.expect("sync");
        assert!(b.state.is_active_for(&make_caller("acme", "c")));

        a.deactivate(&KillSwitchScope::Org("acme".into()), "op")
            .await
            .expect("deactivate");
        b.sync_once().await.expect("sync");
        assert!(!b.state.is_active_for(&make_caller("acme", "c")));
        assert_eq!(b.state.version(), 2);
    }

    #[tokio::test]
    async fn concurrent_writers_do_not_lose_changes() {
        let store = Arc::new(MemStore::default());
        let (a, _) = service(&store, KEY_A, false).await;
        let (b, _) = service(&store, KEY_A, false).await;
        // b has not seen a's write; compare-and-swap makes it re-read.
        a.activate(entry(KillSwitchScope::Org("one".into())))
            .await
            .expect("a");
        b.activate(entry(KillSwitchScope::Org("two".into())))
            .await
            .expect("b");
        let (c, _) = service(&store, KEY_A, false).await;
        assert!(c.state.is_active_for(&make_caller("one", "x")));
        assert!(c.state.is_active_for(&make_caller("two", "x")));
        assert_eq!(c.state.version(), 2);
    }

    #[tokio::test]
    async fn document_signed_with_another_key_is_rejected() {
        let store = Arc::new(MemStore::default());
        let (a, _) = service(&store, KEY_A, false).await;
        a.activate(entry(KillSwitchScope::Global))
            .await
            .expect("activate");

        let (b, _) = service(&store, KEY_B, false).await;
        assert!(!b.state.is_active_for(&make_caller("o", "c")));
        assert!(b.sync_once().await.is_err());
    }

    #[tokio::test]
    async fn tampered_document_cannot_lift_the_switch() {
        let store = Arc::new(MemStore::default());
        let (a, _) = service(&store, KEY_A, false).await;
        a.activate(entry(KillSwitchScope::Global))
            .await
            .expect("activate");

        // Someone with Redis access writes "no entries" at a higher version.
        let raw = store.raw().expect("stored");
        let mut wire: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let mut doc: serde_json::Value =
            serde_json::from_str(wire["doc"].as_str().expect("doc")).expect("doc json");
        doc["version"] = 9.into();
        doc["entries"] = serde_json::json!([]);
        wire["doc"] = doc.to_string().into();
        store.set_raw(9, &wire.to_string());

        assert!(a.sync_once().await.is_err());
        assert!(a.state.is_active_for(&make_caller("o", "c")));
        assert!(a.deactivate(&KillSwitchScope::Global, "op").await.is_err());
        assert!(a.state.is_active_for(&make_caller("o", "c")));
    }

    #[tokio::test]
    async fn older_version_is_never_adopted() {
        let store = Arc::new(MemStore::default());
        let (a, _) = service(&store, KEY_A, false).await;
        a.activate(entry(KillSwitchScope::Global))
            .await
            .expect("v1");
        let v1 = store.raw().expect("v1");
        a.deactivate(&KillSwitchScope::Global, "op")
            .await
            .expect("v2");
        a.activate(entry(KillSwitchScope::Org("x".into())))
            .await
            .expect("v3");

        // Replay of a validly signed but older document.
        store.set_raw(1, &v1);
        a.sync_once().await.expect("sync");
        assert!(!a.state.global.load(Ordering::SeqCst));
        assert_eq!(a.state.version(), 3);
    }

    #[tokio::test]
    async fn activation_during_outage_is_local_then_persisted() {
        let store = Arc::new(MemStore::default());
        let (a, _) = service(&store, KEY_A, false).await;
        store.down.store(true, Ordering::SeqCst);

        let out = a
            .activate(entry(KillSwitchScope::Global))
            .await
            .expect("activate");
        assert!(!out.durable);
        assert!(a.state.is_active_for(&make_caller("o", "c")));
        assert!(a.sync_once().await.is_err());

        store.down.store(false, Ordering::SeqCst);
        a.sync_once().await.expect("sync");
        let (b, _) = service(&store, KEY_A, false).await;
        assert!(b.state.is_active_for(&make_caller("o", "c")));
        assert_eq!(a.status_json()["unpersisted_activations"], 0);
    }

    #[tokio::test]
    async fn deactivation_during_outage_lifts_nothing() {
        let store = Arc::new(MemStore::default());
        let (a, log) = service(&store, KEY_A, false).await;
        a.activate(entry(KillSwitchScope::Global))
            .await
            .expect("activate");
        store.down.store(true, Ordering::SeqCst);
        assert!(a.deactivate(&KillSwitchScope::Global, "op").await.is_err());
        assert!(a.state.is_active_for(&make_caller("o", "c")));
        assert_eq!(
            log.0.lock().expect("lock").len(),
            1,
            "failed deactivate is not logged"
        );
    }

    #[tokio::test]
    async fn fail_closed_blocks_traffic_while_store_is_unreadable() {
        let store = Arc::new(MemStore::default());
        store.down.store(true, Ordering::SeqCst);
        let (a, _) = service(&store, KEY_A, true).await;
        // Never synced: lockout from the start.
        assert!(a.state.is_active_for(&make_caller("o", "c")));
        assert!(!a.healthy());

        store.down.store(false, Ordering::SeqCst);
        a.sync_once().await.expect("sync");
        assert!(!a.state.is_active_for(&make_caller("o", "c")));
        assert!(a.healthy());
    }

    #[tokio::test]
    async fn local_only_keeps_last_state_while_store_is_unreadable() {
        let store = Arc::new(MemStore::default());
        store.down.store(true, Ordering::SeqCst);
        let (a, _) = service(&store, KEY_A, false).await;
        assert!(!a.state.is_active_for(&make_caller("o", "c")));
        assert!(!a.healthy());
        assert_eq!(a.status_json()["store_lockout"], false);
    }

    // ── Wiring through the app ───────────────────────────────────────────────

    const ADMIN_KEY: &str = "operator-admin-key-0123456789";

    fn config(db: &std::path::Path, keys_file: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.auth.mode = "none".into();
        cfg.auth.admin_key = ADMIN_KEY.into();
        cfg.auth.api_keys_file = keys_file.display().to_string();
        cfg.dashboard.auth_mode = "shared".into();
        cfg.server.environment = "development".into();
        cfg.server.dashboard_port = 3000;
        cfg.upstream.mock_mode = true;
        cfg.storage.sqlite_path = db.display().to_string();
        cfg
    }

    fn temp_paths() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("revoc-ks-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("dir");
        let keys = dir.join("keys.txt");
        std::fs::write(&keys, "client-key-0123456789\n").expect("keys");
        (dir.join("revoc.db"), keys)
    }

    fn post(uri: &str, headers: &[(&str, &str)], body: &serde_json::Value) -> Request<Body> {
        let mut req = Request::post(uri).header("content-type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.body(Body::from(body.to_string())).expect("request")
    }

    #[tokio::test]
    async fn sqlite_state_survives_restart_and_shows_on_ready() {
        let (db, keys) = temp_paths();
        let state = build_app_state(Arc::new(config(&db, &keys)))
            .await
            .expect("state");
        let resp = build_routers(&state)
            .internal
            .oneshot(post(
                "/internal/emergency/kill-switch/activate",
                &[("x-admin-key", ADMIN_KEY)],
                &serde_json::json!({"scope":"global","reason":"incident","activated_by":"test"}),
            ))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        // Restart: a fresh process on the same database starts blocked.
        let state = build_app_state(Arc::new(config(&db, &keys)))
            .await
            .expect("state");
        assert!(state.kill_switch.is_active_for(&make_caller("o", "c")));
        let ready = build_routers(&state)
            .main
            .oneshot(Request::get("/ready").body(Body::empty()).expect("req"))
            .await
            .expect("ready");
        assert_eq!(ready.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(ready.into_body())
            .await
            .expect("body")
            .to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(v["kill_switch"]["global"], true);
        assert_eq!(v["kill_switch"]["store"], "sqlite");
        assert_eq!(v["kill_switch"]["version"], 1);
    }

    #[tokio::test]
    async fn dashboard_kill_switch_changes_need_the_admin_key() {
        let (db, keys) = temp_paths();
        let state = build_app_state(Arc::new(config(&db, &keys)))
            .await
            .expect("state");
        let dashboard = build_routers(&state).dashboard.expect("dashboard");
        let body = serde_json::json!({"scope":"global","reason":"incident"});
        let client = ("authorization", "Bearer client-key-0123456789");

        // A client API key can read the dashboard but not change the switch.
        let resp = dashboard
            .clone()
            .oneshot(post("/api/kill-switch/activate", &[client], &body))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = dashboard
            .clone()
            .oneshot(post(
                "/api/kill-switch/activate",
                &[client, ("x-admin-key", "client-key-0123456789")],
                &body,
            ))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(!state.kill_switch.is_active_for(&make_caller("o", "c")));

        let resp = dashboard
            .oneshot(post(
                "/api/kill-switch/activate",
                &[client, ("x-admin-key", ADMIN_KEY)],
                &body,
            ))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert!(state.kill_switch.is_active_for(&make_caller("o", "c")));
    }
}
