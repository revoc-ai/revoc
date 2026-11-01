//! Durable, signed, reconciled kill-switch (SPEC.md §9 D11).
//!
//! - **Durable:** every change is written to the store as a new version of
//!   one signed [`KillSwitchDoc`] (compare-and-swap, retried on conflict).
//!   State is loaded from the store before the proxy serves traffic.
//! - **Signed:** the document is authenticated with HMAC-SHA256 under
//!   `kill_switch.signing_key_env`. A document or pub/sub message with a bad
//!   signature is ignored, so write access to Redis alone cannot switch
//!   traffic on or off. Redis-backed (shared) state requires a key.
//! - **Reconciled:** every `kill_switch.reconcile_interval_ms` (default 2 s)
//!   each instance re-reads the store and adopts any newer version; Redis
//!   pub/sub delivers changes sooner (~50 ms). Older versions are never
//!   adopted, so a replayed document cannot roll an instance back.
//! - **Store unavailable:** `on_redis_unavailable = "local_only"` keeps the
//!   last known state; `"fail_closed"` blocks all traffic until the store is
//!   readable again.
//!
//! Activation is applied locally first, so traffic stops at once even when
//! the store is down; an activation that could not be persisted is retried on
//! every reconcile. Deactivation is persisted first: if the store cannot be
//! written, nothing is lifted.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Notify;
use tracing::{info, warn};

use revoc_core::RevocError;

use super::store::{KillSwitchStore, RedisKillSwitchStore};
use super::{KillSwitchDoc, KillSwitchEntry, KillSwitchScope, KillSwitchState};
use crate::app::KillSwitchLogWriter;

/// Minimum signing-key length in bytes.
pub const MIN_SIGNING_KEY_LEN: usize = 32;

/// Compare-and-swap attempts before a write gives up.
const CAS_ATTEMPTS: usize = 5;

/// What the store holds and what is published: the document JSON exactly as
/// signed, plus its signature.
#[derive(Debug, Serialize, Deserialize)]
struct SignedDoc {
    doc: String,
    sig: String,
}

/// Result of an activate / deactivate call.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Outcome {
    /// `true` when the change reached the durable store.
    pub durable: bool,
    /// Store version after the change.
    pub version: u64,
}

enum Change {
    Activate(KillSwitchEntry),
    Deactivate(KillSwitchScope),
}

/// The kill-switch service shared by the admin API, the dashboard and the
/// background reconciler.
pub struct KillSwitchService {
    /// Hot-path state read by every handler.
    pub state: Arc<KillSwitchState>,
    store: Arc<dyn KillSwitchStore>,
    key: Option<Vec<u8>>,
    log: Arc<dyn KillSwitchLogWriter + Send + Sync>,
    interval: Duration,
    fail_closed: bool,
    redis: Option<(String, String)>,
    /// Activations applied locally but not yet persisted.
    pending: Mutex<Vec<KillSwitchEntry>>,
    failures: AtomicU32,
    wake: Notify,
}

impl KillSwitchService {
    /// Choose the store, validate settings and load the current state.
    ///
    /// Redis is used when `REDIS_URL` (or the `cache.redis_url_env`
    /// variable) is set; otherwise `audit_db`, the store over the audit
    /// database (`SQLite`, or Postgres shared by every instance).
    ///
    /// # Errors
    /// [`RevocError::Configuration`] for an unknown `on_redis_unavailable`
    /// value, or Redis without a signing key of at least
    /// [`MIN_SIGNING_KEY_LEN`] bytes.
    pub async fn build(
        cfg: &revoc_config::Config,
        log: Arc<dyn KillSwitchLogWriter + Send + Sync>,
        audit_db: Arc<dyn KillSwitchStore>,
    ) -> Result<Arc<Self>, RevocError> {
        let ks = &cfg.kill_switch;
        let fail_closed = match ks.on_redis_unavailable.as_str() {
            "local_only" => false,
            "fail_closed" | "fail" => true,
            other => {
                return Err(RevocError::Configuration(format!(
                    "kill_switch.on_redis_unavailable must be \"local_only\" or \"fail_closed\", got \"{other}\""
                )))
            }
        };
        let key = std::env::var(&ks.signing_key_env)
            .ok()
            .filter(|k| !k.is_empty())
            .map(String::into_bytes);
        if key.as_ref().is_some_and(|k| k.len() < MIN_SIGNING_KEY_LEN) {
            return Err(RevocError::Configuration(format!(
                "{} must be at least {MIN_SIGNING_KEY_LEN} bytes",
                ks.signing_key_env
            )));
        }
        let redis_url = std::env::var("REDIS_URL")
            .or_else(|_| std::env::var(&cfg.cache.redis_url_env))
            .ok()
            .filter(|u| !u.is_empty() && ks.enabled);

        let (store, redis): (Arc<dyn KillSwitchStore>, _) = if let Some(url) = redis_url {
            if key.is_none() {
                return Err(RevocError::Configuration(format!(
                    "kill-switch state is shared through Redis, so {} must be set \
                     (at least {MIN_SIGNING_KEY_LEN} bytes, same on every instance)",
                    ks.signing_key_env
                )));
            }
            (
                Arc::new(RedisKillSwitchStore::new(&url, &ks.redis_channel)?),
                Some((url, ks.redis_channel.clone())),
            )
        } else {
            if audit_db.kind() == "postgres" && key.is_none() {
                return Err(RevocError::Configuration(format!(
                    "kill-switch state is shared through Postgres, so {} must be set \
                     (at least {MIN_SIGNING_KEY_LEN} bytes, same on every instance)",
                    ks.signing_key_env
                )));
            }
            (audit_db, None)
        };

        let interval = Duration::from_millis(ks.reconcile_interval_ms.max(100));
        Ok(Self::with_store(store, key, log, interval, fail_closed, redis).await)
    }

    /// Assemble a service around `store` and load its state.
    pub(crate) async fn with_store(
        store: Arc<dyn KillSwitchStore>,
        key: Option<Vec<u8>>,
        log: Arc<dyn KillSwitchLogWriter + Send + Sync>,
        interval: Duration,
        fail_closed: bool,
        redis: Option<(String, String)>,
    ) -> Arc<Self> {
        let service = Arc::new(Self {
            state: Arc::new(KillSwitchState::new()),
            store,
            key,
            log,
            interval,
            fail_closed,
            redis,
            pending: Mutex::new(Vec::new()),
            failures: AtomicU32::new(0),
            wake: Notify::new(),
        });
        if let Err(e) = service.sync_once().await {
            warn!(error = %e, store = service.store.kind(), "Kill-switch state could not be loaded at startup");
        }
        service
    }

    /// Start the reconcile loop and, with Redis, the pub/sub listener.
    pub fn spawn_background(self: &Arc<Self>) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(me.interval) => {}
                    () = me.wake.notified() => {}
                }
                if let Err(e) = me.sync_once().await {
                    warn!(error = %e, "Kill-switch reconcile failed");
                }
            }
        });
        if let Some((url, channel)) = self.redis.clone() {
            let me = Arc::clone(self);
            tokio::spawn(async move { me.listen(&url, &channel).await });
        }
    }

    // ── Mutations ────────────────────────────────────────────────────────────

    /// Activate: applied locally at once, then persisted. When the store is
    /// unreachable the activation stays in force locally and is retried on
    /// every reconcile (`durable = false`).
    ///
    /// # Errors
    /// Never fails today; the `Result` keeps the call shape of
    /// [`Self::deactivate`].
    pub async fn activate(&self, entry: KillSwitchEntry) -> Result<Outcome, RevocError> {
        self.state.activate(entry.clone());
        self.write_log(
            &entry.scope,
            "activate",
            &entry.activated_by,
            Some(&entry.reason),
        )
        .await;
        match self.persist(Change::Activate(entry.clone())).await {
            Ok(version) => Ok(Outcome {
                durable: true,
                version,
            }),
            Err(e) => {
                warn!(error = %e, "Kill-switch activation not persisted; retrying on reconcile");
                self.lock_pending().push(entry);
                self.wake.notify_one();
                Ok(Outcome {
                    durable: false,
                    version: self.state.version(),
                })
            }
        }
    }

    /// Deactivate: persisted first, then applied.
    ///
    /// # Errors
    /// The store error when the change could not be persisted; the switch
    /// then stays active everywhere.
    pub async fn deactivate(
        &self,
        scope: &KillSwitchScope,
        actor: &str,
    ) -> Result<Outcome, RevocError> {
        self.lock_pending().retain(|e| &e.scope != scope);
        let version = self.persist(Change::Deactivate(scope.clone())).await?;
        self.state.deactivate(scope);
        self.write_log(scope, "deactivate", actor, None).await;
        Ok(Outcome {
            durable: true,
            version,
        })
    }

    async fn persist(&self, change: Change) -> Result<u64, RevocError> {
        for _ in 0..CAS_ATTEMPTS {
            let current = self.read_store().await?;
            let (expected, mut entries) =
                current.map_or((0, Vec::new()), |d| (d.version, d.entries));
            match &change {
                Change::Activate(e) => {
                    entries.retain(|x| x.scope != e.scope);
                    entries.push(e.clone());
                }
                Change::Deactivate(s) => entries.retain(|x| &x.scope != s),
            }
            entries.sort_by_key(|e| e.scope.key());
            let doc = KillSwitchDoc {
                version: expected + 1,
                updated_at: Utc::now(),
                entries,
            };
            let signed = self.sign(&doc)?;
            if self
                .store
                .compare_and_swap(expected, doc.version, &signed)
                .await?
            {
                self.adopt(&doc);
                self.state.mark_synced();
                return Ok(doc.version);
            }
        }
        Err(RevocError::Database(
            "kill-switch store kept changing; write not applied".into(),
        ))
    }

    // ── Sync ─────────────────────────────────────────────────────────────────

    /// Retry unpersisted activations, then adopt the store's document if it
    /// is newer than local state.
    ///
    /// # Errors
    /// The store or signature error; with `fail_closed` the lockout engages
    /// once the store has been unreadable for three intervals.
    pub async fn sync_once(&self) -> Result<(), RevocError> {
        let result = self.try_sync().await;
        match &result {
            Ok(()) => {
                self.failures.store(0, Ordering::SeqCst);
                self.state.mark_synced();
                if self.state.store_lockout() {
                    info!("Kill-switch store reachable again; lockout released");
                }
                self.state.set_store_lockout(false);
            }
            Err(e) => {
                let n = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
                let stale = self.state.sync_age_ms().is_none_or(|age| {
                    age > i64::try_from(self.interval.as_millis() * 3).unwrap_or(i64::MAX)
                });
                if self.fail_closed && stale && !self.state.store_lockout() {
                    warn!(error = %e, failures = n, "Kill-switch store unavailable — blocking all traffic (fail_closed)");
                    self.state.set_store_lockout(true);
                }
            }
        }
        result
    }

    async fn try_sync(&self) -> Result<(), RevocError> {
        let pending = std::mem::take(&mut *self.lock_pending());
        for (i, entry) in pending.iter().enumerate() {
            if let Err(e) = self.persist(Change::Activate(entry.clone())).await {
                self.lock_pending().extend(pending[i..].iter().cloned());
                return Err(e);
            }
        }
        if let Some(doc) = self.read_store().await? {
            self.adopt_if_newer(&doc);
        }
        Ok(())
    }

    /// Apply a document received over pub/sub.
    fn apply_published(&self, payload: &str) {
        match self.verify(payload) {
            Ok(doc) => self.adopt_if_newer(&doc),
            Err(e) => warn!(error = %e, "Kill-switch: rejected pub/sub message"),
        }
    }

    fn adopt_if_newer(&self, doc: &KillSwitchDoc) {
        let local = self.state.version();
        if doc.version > local {
            info!(
                version = doc.version,
                "Kill-switch state updated from store"
            );
            self.adopt(doc);
        } else if doc.version < local {
            warn!(
                stored = doc.version,
                local, "Kill-switch store holds an older version than this instance; ignored"
            );
        }
    }

    /// Replace local state with `doc`, keeping unpersisted activations.
    fn adopt(&self, doc: &KillSwitchDoc) {
        self.state.replace(doc);
        for e in self.lock_pending().iter() {
            self.state.activate(e.clone());
        }
    }

    async fn listen(&self, url: &str, channel: &str) {
        loop {
            if let Err(e) = self.listen_once(url, channel).await {
                warn!(error = %e, "Kill-switch Redis subscription lost — reconnecting in 5s");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn listen_once(&self, url: &str, channel: &str) -> Result<(), redis::RedisError> {
        use futures::StreamExt as _;
        let mut pubsub = redis::Client::open(url)?.get_async_pubsub().await?;
        pubsub.subscribe(channel).await?;
        info!(channel, "Kill-switch Redis subscription active");
        let mut stream = pubsub.into_on_message();
        while let Some(msg) = stream.next().await {
            match msg.get_payload::<String>() {
                Ok(p) => self.apply_published(&p),
                Err(e) => warn!(error = %e, "Kill-switch: unreadable pub/sub payload"),
            }
        }
        Ok(())
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    fn mac(&self, data: &[u8]) -> Option<String> {
        let key = self.key.as_ref()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
        mac.update(data);
        Some(hex::encode(mac.finalize().into_bytes()))
    }

    fn sign(&self, doc: &KillSwitchDoc) -> Result<String, RevocError> {
        let doc = serde_json::to_string(doc)
            .map_err(|e| RevocError::Configuration(format!("kill-switch doc: {e}")))?;
        let sig = self.mac(doc.as_bytes()).unwrap_or_default();
        serde_json::to_string(&SignedDoc { doc, sig })
            .map_err(|e| RevocError::Configuration(format!("kill-switch doc: {e}")))
    }

    fn verify(&self, signed: &str) -> Result<KillSwitchDoc, RevocError> {
        let bad = |m: &str| RevocError::Database(format!("kill-switch document {m}"));
        let wire: SignedDoc = serde_json::from_str(signed).map_err(|_| bad("is malformed"))?;
        match &self.key {
            Some(key) => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(key).map_err(|_| bad("key invalid"))?;
                mac.update(wire.doc.as_bytes());
                let sig = hex::decode(&wire.sig).map_err(|_| bad("signature malformed"))?;
                mac.verify_slice(&sig)
                    .map_err(|_| bad("signature does not verify"))?;
            }
            // Unsigned is only possible for the local `SQLite` store (Redis
            // requires a key); a signed document then cannot be checked.
            None if wire.sig.is_empty() => {}
            None => return Err(bad("is signed but no signing key is configured")),
        }
        serde_json::from_str(&wire.doc).map_err(|_| bad("body is malformed"))
    }

    async fn read_store(&self) -> Result<Option<KillSwitchDoc>, RevocError> {
        self.store
            .load()
            .await?
            .map(|s| self.verify(&s))
            .transpose()
    }

    // ── Misc ─────────────────────────────────────────────────────────────────

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, Vec<KillSwitchEntry>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn write_log(
        &self,
        scope: &KillSwitchScope,
        action: &str,
        actor: &str,
        reason: Option<&str>,
    ) {
        let (scope_str, value) = scope.log_parts();
        if let Err(e) = self.log.log(scope_str, value, action, actor, reason).await {
            warn!(error = %e, "Failed to write kill_switch_log entry");
        }
    }

    /// `true` when the store has been read successfully within three
    /// reconcile intervals.
    pub fn healthy(&self) -> bool {
        self.state.sync_age_ms().is_some_and(|age| {
            age <= i64::try_from(self.interval.as_millis() * 3).unwrap_or(i64::MAX)
        })
    }

    /// State summary for `/ready` and the admin status endpoint.
    pub fn status_json(&self) -> serde_json::Value {
        let snap = self.state.status_snapshot();
        serde_json::json!({
            "global": snap.global,
            "orgs": snap.by_org.len(),
            "callers": snap.by_caller.len(),
            "version": self.state.version(),
            "store": self.store.kind(),
            "signed": self.key.is_some(),
            "store_healthy": self.healthy(),
            "synced_ms_ago": self.state.sync_age_ms(),
            "store_lockout": self.state.store_lockout(),
            "unpersisted_activations": self.lock_pending().len(),
            "on_store_unavailable": if self.fail_closed { "fail_closed" } else { "local_only" },
        })
    }
}
