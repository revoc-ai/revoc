//! D11 — Emergency kill-switch (SPEC.md §9 D11).
//!
//! The in-memory [`KillSwitchState`] is what the hot path reads (Step 0 of
//! every handler). It is a cache of a versioned, signed document held in a
//! durable store — Redis when one is configured (shared by every instance),
//! otherwise the local `SQLite` database — so state survives restarts and
//! converges across instances (see [`service`]). Health/readiness/metrics
//! endpoints always bypass the kill-switch.

pub mod service;
pub mod store;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::info;

use revoc_core::CallerContext;

pub use service::KillSwitchService;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single kill-switch activation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchScope {
    /// All traffic across all orgs and callers.
    Global,
    /// All traffic from a specific organisation.
    Org(String),
    /// All traffic from a specific caller.
    Caller(String),
}

impl KillSwitchScope {
    /// Stable key used to order entries in the stored document.
    pub fn key(&self) -> String {
        match self {
            Self::Global => "global".to_owned(),
            Self::Org(id) => format!("org:{id}"),
            Self::Caller(id) => format!("caller:{id}"),
        }
    }

    /// Split into the `(scope, scope_value)` pair stored in `kill_switch_log`.
    pub fn log_parts(&self) -> (&'static str, Option<&str>) {
        match self {
            Self::Global => ("global", None),
            Self::Org(id) => ("org", Some(id.as_str())),
            Self::Caller(id) => ("caller", Some(id.as_str())),
        }
    }

    /// Parse the `(scope, target)` request shape used by the admin API and
    /// the dashboard.
    ///
    /// # Errors
    /// [`revoc_core::RevocError::RequestParse`] for an unknown scope or a
    /// missing `target` on an org/caller scope.
    pub fn parse(scope: &str, target: Option<&str>) -> Result<Self, revoc_core::RevocError> {
        let need = |what: &str| {
            revoc_core::RevocError::RequestParse(format!("{what} scope requires a target"))
        };
        match scope {
            "global" => Ok(Self::Global),
            "org" => target
                .filter(|t| !t.is_empty())
                .map(|t| Self::Org(t.to_owned()))
                .ok_or_else(|| need("org")),
            "caller" => target
                .filter(|t| !t.is_empty())
                .map(|t| Self::Caller(t.to_owned()))
                .ok_or_else(|| need("caller")),
            other => Err(revoc_core::RevocError::RequestParse(format!(
                "unknown kill-switch scope '{other}'"
            ))),
        }
    }
}

/// The durable, versioned kill-switch document. `version` increases by one
/// on every change; `entries` is sorted by [`KillSwitchScope::key`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchDoc {
    /// Monotonic version.
    pub version: u64,
    /// When this version was written.
    pub updated_at: DateTime<Utc>,
    /// Every active switch.
    pub entries: Vec<KillSwitchEntry>,
}

// ── KillSwitchState ───────────────────────────────────────────────────────────

/// In-memory kill-switch state; shared via `Arc` across all handler tasks.
pub struct KillSwitchState {
    /// Global kill-switch flag — checked with `Relaxed` load for speed.
    pub global: AtomicBool,
    global_entry: RwLock<Option<KillSwitchEntry>>,
    /// Per-organisation kill-switch entries.
    pub by_org: DashMap<String, KillSwitchEntry>,
    /// Per-caller kill-switch entries.
    pub by_caller: DashMap<String, KillSwitchEntry>,
    /// Version of the durable document this state reflects (0 = none yet).
    version: AtomicU64,
    /// Set when the durable store cannot be read and
    /// `kill_switch.on_redis_unavailable = "fail_closed"`: blocks all traffic.
    store_lockout: AtomicBool,
    /// Unix ms of the last successful sync with the store (0 = never).
    last_sync_ms: AtomicI64,
}

impl KillSwitchState {
    /// Create a new, inactive kill-switch state.
    pub fn new() -> Self {
        Self {
            global: AtomicBool::new(false),
            global_entry: RwLock::new(None),
            by_org: DashMap::new(),
            by_caller: DashMap::new(),
            version: AtomicU64::new(0),
            store_lockout: AtomicBool::new(false),
            last_sync_ms: AtomicI64::new(0),
        }
    }

    /// Returns `true` if the kill-switch is active for the given caller.
    pub fn is_active_for(&self, caller: &CallerContext) -> bool {
        if self.global.load(Ordering::Relaxed) || self.store_lockout.load(Ordering::Relaxed) {
            return true;
        }
        if self.by_org.contains_key(&caller.org_id) {
            return true;
        }
        self.by_caller.contains_key(&caller.caller_id)
    }

    /// Activate the kill-switch for the given scope (local state only).
    pub fn activate(&self, entry: KillSwitchEntry) {
        match &entry.scope {
            KillSwitchScope::Global => {
                self.global.store(true, Ordering::SeqCst);
                info!("Kill-switch ACTIVATED globally by '{}'", entry.activated_by);
                *self
                    .global_entry
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
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

    /// Deactivate the kill-switch for the given scope (local state only).
    pub fn deactivate(&self, scope: &KillSwitchScope) {
        match scope {
            KillSwitchScope::Global => {
                self.global.store(false, Ordering::SeqCst);
                *self
                    .global_entry
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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

    /// Replace local state with `doc`. New activations are applied before
    /// stale ones are removed, so traffic that should be stopped is never
    /// briefly let through.
    pub fn replace(&self, doc: &KillSwitchDoc) {
        let wanted: HashMap<String, &KillSwitchEntry> =
            doc.entries.iter().map(|e| (e.scope.key(), e)).collect();
        for e in &doc.entries {
            if !self.has(&e.scope) {
                self.activate(e.clone());
            }
        }
        for e in self.entries() {
            if !wanted.contains_key(&e.scope.key()) {
                self.deactivate(&e.scope);
            }
        }
        self.version.store(doc.version, Ordering::SeqCst);
    }

    fn has(&self, scope: &KillSwitchScope) -> bool {
        match scope {
            KillSwitchScope::Global => self.global.load(Ordering::SeqCst),
            KillSwitchScope::Org(id) => self.by_org.contains_key(id),
            KillSwitchScope::Caller(id) => self.by_caller.contains_key(id),
        }
    }

    /// Every active entry.
    pub fn entries(&self) -> Vec<KillSwitchEntry> {
        let mut out: Vec<KillSwitchEntry> = self
            .global_entry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        out.extend(self.by_org.iter().map(|e| e.value().clone()));
        out.extend(self.by_caller.iter().map(|e| e.value().clone()));
        out
    }

    /// Version of the durable document reflected locally.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Engage or release the store-unavailable lockout.
    pub fn set_store_lockout(&self, on: bool) {
        self.store_lockout.store(on, Ordering::SeqCst);
    }

    /// Whether traffic is blocked because the store is unreachable.
    pub fn store_lockout(&self) -> bool {
        self.store_lockout.load(Ordering::SeqCst)
    }

    /// Record a successful sync.
    pub fn mark_synced(&self) {
        self.last_sync_ms
            .store(Utc::now().timestamp_millis(), Ordering::SeqCst);
    }

    /// Milliseconds since the last successful sync, `None` if never synced.
    pub fn sync_age_ms(&self) -> Option<i64> {
        match self.last_sync_ms.load(Ordering::SeqCst) {
            0 => None,
            t => Some(Utc::now().timestamp_millis() - t),
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

// ── Dashboard adapter ─────────────────────────────────────────────────────────

/// Concrete adapter giving `revoc-dashboard` access to the kill-switch
/// through the [`revoc_dashboard::KillSwitchControl`] trait.
///
/// `revoc-dashboard` sits below `revoc-proxy` in the crate dependency order
/// (SPEC.md §4), so this adapter is the inversion point. The dashboard only
/// reaches the mutating methods after its admin-credential check.
pub struct DashboardKillSwitchAdapter {
    service: Arc<KillSwitchService>,
}

impl DashboardKillSwitchAdapter {
    /// Wrap the shared kill-switch service for dashboard use.
    pub fn new(service: Arc<KillSwitchService>) -> Self {
        Self { service }
    }
}

#[async_trait::async_trait]
impl revoc_dashboard::KillSwitchControl for DashboardKillSwitchAdapter {
    async fn status(&self) -> revoc_dashboard::KillSwitchStatusView {
        let snap = self.service.state.status_snapshot();
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
        let scope = KillSwitchScope::parse(scope, target)?;
        self.service
            .activate(KillSwitchEntry {
                activated_by: activated_by.to_owned(),
                activated_at: Utc::now(),
                reason: reason.to_owned(),
                scope,
            })
            .await
            .map(|_| ())
    }

    async fn deactivate(
        &self,
        scope: &str,
        target: Option<&str>,
    ) -> Result<(), revoc_core::RevocError> {
        let scope = KillSwitchScope::parse(scope, target)?;
        self.service
            .deactivate(&scope, "dashboard-operator")
            .await
            .map(|_| ())
    }
}
