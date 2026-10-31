//! D11 — Emergency kill-switch (SPEC.md §9 D11).
//!
//! Stops all AI traffic within ~50 ms across all instances via Redis pub/sub.
//! Health/readiness/metrics endpoints always bypass the kill-switch.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use revoc_core::CallerContext;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single kill-switch activation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchEntry {
    /// Identity of the operator who activated the switch.
    pub activated_by: String,
    /// Wall-clock time of activation.
    pub activated_at: DateTime<Utc>,
    /// Human-readable reason.
    pub reason: String,
    /// Scope of the activation.
    pub scope: KillSwitchScope,
}

/// Which traffic is affected by a kill-switch activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchScope {
    /// All traffic across all orgs and callers.
    Global,
    /// All traffic from a specific organisation.
    Org(String),
    /// All traffic from a specific caller.
    Caller(String),
}

// ── KillSwitchState ───────────────────────────────────────────────────────────

/// In-memory kill-switch state; shared via `Arc` across all handler tasks.
pub struct KillSwitchState {
    /// Global kill-switch flag — checked with `Relaxed` load for speed.
    pub global: AtomicBool,
    /// Per-organisation kill-switch entries.
    pub by_org: DashMap<String, KillSwitchEntry>,
    /// Per-caller kill-switch entries.
    pub by_caller: DashMap<String, KillSwitchEntry>,
}

impl KillSwitchState {
    /// Create a new, inactive kill-switch state.
    pub fn new() -> Self {
        Self {
            global: AtomicBool::new(false),
            by_org: DashMap::new(),
            by_caller: DashMap::new(),
        }
    }

    /// Returns `true` if the kill-switch is active for the given caller.
    pub fn is_active_for(&self, caller: &CallerContext) -> bool {
        if self.global.load(Ordering::Relaxed) {
            return true;
        }
        if self.by_org.contains_key(&caller.org_id) {
            return true;
        }
        self.by_caller.contains_key(&caller.caller_id)
    }

    /// Activate the kill-switch for the given scope.
    pub fn activate(&self, entry: KillSwitchEntry) {
        match &entry.scope {
            KillSwitchScope::Global => {
                self.global.store(true, Ordering::SeqCst);
                info!("Kill-switch ACTIVATED globally by '{}'", entry.activated_by);
            }
            KillSwitchScope::Org(id) => {
                info!(org_id = %id, "Kill-switch ACTIVATED for org");
                self.by_org.insert(id.clone(), entry);
            }
            KillSwitchScope::Caller(id) => {
                info!(caller_id = %id, "Kill-switch ACTIVATED for caller");
                self.by_caller.insert(id.clone(), entry);
            }
        }
    }

    /// Deactivate the kill-switch for the given scope.
    pub fn deactivate(&self, scope: &KillSwitchScope) {
        match scope {
            KillSwitchScope::Global => {
                self.global.store(false, Ordering::SeqCst);
                info!("Kill-switch DEACTIVATED globally");
            }
            KillSwitchScope::Org(id) => {
                self.by_org.remove(id);
                info!(org_id = %id, "Kill-switch DEACTIVATED for org");
            }
            KillSwitchScope::Caller(id) => {
                self.by_caller.remove(id);
                info!(caller_id = %id, "Kill-switch DEACTIVATED for caller");
            }
        }
    }

    /// Snapshot the current state for the status endpoint.
    pub fn status_snapshot(&self) -> KillSwitchSnapshot {
        KillSwitchSnapshot {
            global: self.global.load(Ordering::Relaxed),
            by_org: self
                .by_org
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
            by_caller: self
                .by_caller
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
        }
    }
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable snapshot of kill-switch state.
#[derive(Debug, Serialize)]
pub struct KillSwitchSnapshot {
    /// Whether the global kill-switch is active.
    pub global: bool,
    /// Active org-scoped entries.
    pub by_org: Vec<(String, KillSwitchEntry)>,
    /// Active caller-scoped entries.
    pub by_caller: Vec<(String, KillSwitchEntry)>,
}

// ── Redis pub/sub propagation ─────────────────────────────────────────────────

/// Redis message published on the `revoc:kill_switch` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchMessage {
    /// `"activate"` or `"deactivate"`.
    pub action: String,
    /// The kill-switch entry (only present for activate).
    pub entry: Option<KillSwitchEntry>,
    /// The scope to deactivate (only present for deactivate).
    pub scope: Option<KillSwitchScope>,
}

/// Publish a kill-switch activate/deactivate message to the
/// `revoc:kill_switch` Redis channel for cross-instance propagation
/// (~50ms — SPEC.md §9 D11). No-ops when the kill-switch is disabled in
/// config or no Redis URL is configured (`REDIS_URL` env, falling back to
/// `cache.redis_url_env`) — single-instance deployments remain functional
/// without Redis.
///
/// Shared by the internal admin handlers (`handlers::emergency`) and the
/// dashboard `KillSwitchControl` adapter so both paths propagate identically.
pub fn publish_kill_switch_message(
    config: &revoc_config::Config,
    action: &str,
    entry: Option<KillSwitchEntry>,
    scope: Option<KillSwitchScope>,
) {
    if !config.kill_switch.enabled {
        return;
    }
    let msg = KillSwitchMessage {
        action: action.to_owned(),
        entry,
        scope,
    };
    let Ok(payload) = serde_json::to_string(&msg) else {
        return;
    };

    let Ok(redis_url) =
        std::env::var("REDIS_URL").or_else(|_| std::env::var(&config.cache.redis_url_env))
    else {
        return;
    };

    tokio::spawn(async move {
        use redis::AsyncCommands;
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let _: Result<i64, _> = conn.publish("revoc:kill_switch", &payload).await;
            }
        }
    });
}

/// Subscribe to the Redis `revoc:kill_switch` channel and apply incoming
/// activate/deactivate messages to the local `KillSwitchState`.
///
/// Runs forever as a background task. On Redis failure the task logs a warning
/// and continues (local state remains valid).
pub async fn subscribe_kill_switch(state: Arc<KillSwitchState>, redis_url: &str) {
    loop {
        match try_subscribe(state.clone(), redis_url).await {
            Ok(()) => {}
            Err(e) => {
                warn!(error = %e, "Kill-switch Redis subscription lost — reconnecting in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn try_subscribe(
    state: Arc<KillSwitchState>,
    redis_url: &str,
) -> Result<(), redis::RedisError> {
    let mut pubsub = redis::Client::open(redis_url)?.get_async_pubsub().await?;
    pubsub.subscribe("revoc:kill_switch").await?;

    info!("Kill-switch Redis subscription active on revoc:kill_switch");

    let mut stream = pubsub.into_on_message();
    loop {
        use futures::StreamExt as _;
        match stream.next().await {
            Some(msg) => {
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "Kill-switch: bad payload");
                        continue;
                    }
                };
                match serde_json::from_str::<KillSwitchMessage>(&payload) {
                    Ok(ks_msg) => apply_message(&state, ks_msg),
                    Err(e) => warn!(error = %e, "Kill-switch: JSON parse error"),
                }
            }
            None => return Ok(()),
        }
    }
}

// ── Dashboard adapter ─────────────────────────────────────────────────────────

/// Concrete adapter giving `revoc-dashboard` real read/write access to the
/// proxy's shared [`KillSwitchState`] through the
/// [`revoc_dashboard::KillSwitchControl`] trait.
///
/// `revoc-dashboard` sits below `revoc-proxy` in the crate dependency order
/// (SPEC.md §4), so it cannot reference [`KillSwitchState`] directly — this
/// adapter is the inversion point, constructed once in
/// [`crate::app::build_routers`] and shared with the dashboard router.
pub struct DashboardKillSwitchAdapter {
    state: Arc<KillSwitchState>,
    config: Arc<revoc_config::Config>,
    log: Arc<dyn crate::app::KillSwitchLogWriter + Send + Sync>,
}

impl DashboardKillSwitchAdapter {
    /// Wrap the shared kill-switch state, config, and audit-log writer for
    /// dashboard use.
    pub fn new(
        state: Arc<KillSwitchState>,
        config: Arc<revoc_config::Config>,
        log: Arc<dyn crate::app::KillSwitchLogWriter + Send + Sync>,
    ) -> Self {
        Self { state, config, log }
    }
}

/// Split a [`KillSwitchScope`] into the `(scope, scope_value)` pair stored in
/// the `kill_switch_log` table (SPEC.md §15).
fn scope_log_parts(scope: &KillSwitchScope) -> (&'static str, Option<&str>) {
    match scope {
        KillSwitchScope::Global => ("global", None),
        KillSwitchScope::Org(id) => ("org", Some(id.as_str())),
        KillSwitchScope::Caller(id) => ("caller", Some(id.as_str())),
    }
}

#[async_trait::async_trait]
impl revoc_dashboard::KillSwitchControl for DashboardKillSwitchAdapter {
    async fn status(&self) -> revoc_dashboard::KillSwitchStatusView {
        let snap = self.state.status_snapshot();
        revoc_dashboard::KillSwitchStatusView {
            global: snap.global,
            by_org: snap
                .by_org
                .into_iter()
                .map(|(k, e)| (k, e.reason))
                .collect(),
            by_caller: snap
                .by_caller
                .into_iter()
                .map(|(k, e)| (k, e.reason))
                .collect(),
        }
    }

    async fn activate(
        &self,
        scope: &str,
        target: Option<&str>,
        reason: &str,
        activated_by: &str,
    ) -> Result<(), revoc_core::RevocError> {
        let scope = parse_scope(scope, target)?;
        let entry = KillSwitchEntry {
            activated_by: activated_by.to_owned(),
            activated_at: Utc::now(),
            reason: reason.to_owned(),
            scope: scope.clone(),
        };
        self.state.activate(entry.clone());
        publish_kill_switch_message(&self.config, "activate", Some(entry.clone()), None);
        let (scope_str, scope_value) = scope_log_parts(&entry.scope);
        if let Err(e) = self
            .log
            .log(
                scope_str,
                scope_value,
                "activate",
                activated_by,
                Some(reason),
            )
            .await
        {
            warn!(error = %e, "Failed to write kill_switch_log entry");
        }
        Ok(())
    }

    async fn deactivate(
        &self,
        scope: &str,
        target: Option<&str>,
    ) -> Result<(), revoc_core::RevocError> {
        let scope = parse_scope(scope, target)?;
        self.state.deactivate(&scope);
        publish_kill_switch_message(&self.config, "deactivate", None, Some(scope.clone()));
        let (scope_str, scope_value) = scope_log_parts(&scope);
        if let Err(e) = self
            .log
            .log(scope_str, scope_value, "deactivate", "dashboard", None)
            .await
        {
            warn!(error = %e, "Failed to write kill_switch_log entry");
        }
        Ok(())
    }
}

/// Parse a `(scope, target)` pair from the dashboard's request shape into a
/// [`KillSwitchScope`].
///
/// # Errors
/// Returns [`revoc_core::RevocError::RequestParse`] for an unknown scope name
/// or a missing `target` for `"org"`/`"caller"` scopes.
fn parse_scope(
    scope: &str,
    target: Option<&str>,
) -> Result<KillSwitchScope, revoc_core::RevocError> {
    match scope {
        "global" => Ok(KillSwitchScope::Global),
        "org" => target
            .map(|t| KillSwitchScope::Org(t.to_owned()))
            .ok_or_else(|| {
                revoc_core::RevocError::RequestParse("org scope requires a target".into())
            }),
        "caller" => target
            .map(|t| KillSwitchScope::Caller(t.to_owned()))
            .ok_or_else(|| {
                revoc_core::RevocError::RequestParse("caller scope requires a target".into())
            }),
        other => Err(revoc_core::RevocError::RequestParse(format!(
            "unknown kill-switch scope '{other}'"
        ))),
    }
}

fn apply_message(state: &KillSwitchState, msg: KillSwitchMessage) {
    match msg.action.as_str() {
        "activate" => {
            if let Some(entry) = msg.entry {
                state.activate(entry);
            }
        }
        "deactivate" => {
            if let Some(scope) = msg.scope {
                state.deactivate(&scope);
            }
        }
        other => warn!(action = other, "Kill-switch: unknown action"),
    }
}
