//! Batched, asynchronous audit writer (SPEC.md §23 Rule 25: "audit writes
//! are async and batched; they never block the request path").
//!
//! Handlers enqueue events on a bounded channel and return at once. One
//! writer task drains whatever is queued — up to `audit_write_batch_size`
//! events — and stores it in a single transaction, so write throughput
//! scales with load instead of opening one connection per event. A failed
//! batch is retried with a pause of `audit_write_interval_ms` doubling per
//! attempt; only after the last attempt are its events counted as dropped.
//!
//! Enqueueing never waits: if the queue is full the event is dropped and
//! counted, and `/ready` reports the count. A load test (`scripts/proof.sh`)
//! checks that none are dropped at the documented rate.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use revoc_dashboard::{AuditEvent, AuditStore};

/// Attempts per batch before its events are dropped.
const ATTEMPTS: u32 = 4;

/// Handle for enqueueing audit events; cheap to clone.
#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::Sender<AuditEvent>,
    pending: Arc<AtomicUsize>,
    stats: Arc<AuditStats>,
}

/// Counters reported on `/ready`.
#[derive(Debug, Default)]
pub struct AuditStats {
    /// Events stored.
    pub written: AtomicU64,
    /// Events lost: queue full, or every attempt failed.
    pub dropped: AtomicU64,
    /// Batches committed.
    pub batches: AtomicU64,
}

impl AuditWriter {
    /// Start the writer task over `store`.
    ///
    /// `pending` counts events queued or in flight, so graceful shutdown can
    /// wait for it to reach zero.
    pub fn spawn(
        store: Arc<dyn AuditStore + Send + Sync>,
        batch_size: usize,
        retry_interval: Duration,
        queue_capacity: usize,
        pending: Arc<AtomicUsize>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(queue_capacity.max(1));
        let stats = Arc::new(AuditStats::default());
        tokio::spawn(run(
            store,
            rx,
            batch_size.max(1),
            retry_interval,
            pending.clone(),
            stats.clone(),
        ));
        Self { tx, pending, stats }
    }

    /// Queue `event` without waiting. Returns `false` if it was dropped.
    pub fn enqueue(&self, event: AuditEvent) -> bool {
        self.pending.fetch_add(1, Ordering::SeqCst);
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(e) => {
                self.pending.fetch_sub(1, Ordering::SeqCst);
                let total = self.stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                let reason = match e {
                    mpsc::error::TrySendError::Full(_) => "queue full",
                    mpsc::error::TrySendError::Closed(_) => "writer stopped",
                };
                tracing::error!(reason, dropped_total = total, "Audit event dropped");
                false
            }
        }
    }

    /// Counters for `/ready`.
    pub fn status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "queued": self.pending.load(Ordering::SeqCst),
            "written": self.stats.written.load(Ordering::Relaxed),
            "dropped": self.stats.dropped.load(Ordering::Relaxed),
            "batches": self.stats.batches.load(Ordering::Relaxed),
        })
    }
}

async fn run(
    store: Arc<dyn AuditStore + Send + Sync>,
    mut rx: mpsc::Receiver<AuditEvent>,
    batch_size: usize,
    retry_interval: Duration,
    pending: Arc<AtomicUsize>,
    stats: Arc<AuditStats>,
) {
    let mut batch = Vec::with_capacity(batch_size);
    while rx.recv_many(&mut batch, batch_size).await > 0 {
        let n = batch.len();
        let mut delay = retry_interval;
        let mut stored = false;
        for attempt in 1..=ATTEMPTS {
            match store.insert_batch(batch.clone()).await {
                Ok(()) => {
                    stored = true;
                    break;
                }
                Err(e) if attempt < ATTEMPTS => {
                    tracing::warn!(error = %e, attempt, events = n, "Audit batch write failed; retrying");
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                }
                Err(e) => {
                    tracing::error!(error = %e, events = n, "Audit batch dropped after retries");
                }
            }
        }
        let counter = if stored {
            stats.batches.fetch_add(1, Ordering::Relaxed);
            &stats.written
        } else {
            &stats.dropped
        };
        counter.fetch_add(n as u64, Ordering::Relaxed);
        batch.clear();
        pending.fetch_sub(n, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use revoc_core::RevocError;
    use revoc_dashboard::{AnalyticsResult, AnalyticsWindow, EventFilter};

    /// Records batch sizes; fails the first `fail_first` batches.
    struct MemStore {
        batches: std::sync::Mutex<Vec<usize>>,
        fail_first: AtomicUsize,
        gate: tokio::sync::Semaphore,
    }

    #[async_trait]
    impl AuditStore for MemStore {
        async fn insert_event(&self, event: AuditEvent) -> Result<(), RevocError> {
            self.insert_batch(vec![event]).await
        }
        async fn insert_batch(&self, events: Vec<AuditEvent>) -> Result<(), RevocError> {
            let _permit = self.gate.acquire().await;
            if self.fail_first.load(Ordering::SeqCst) > 0 {
                self.fail_first.fetch_sub(1, Ordering::SeqCst);
                return Err(RevocError::Database("injected".into()));
            }
            self.batches.lock().expect("lock").push(events.len());
            Ok(())
        }
        async fn list_events(&self, _: EventFilter) -> Result<(Vec<AuditEvent>, u64), RevocError> {
            Ok((vec![], 0))
        }
        async fn get_event_by_trace(&self, _: &str) -> Result<Option<AuditEvent>, RevocError> {
            Ok(None)
        }
        async fn analytics(&self, _: AnalyticsWindow) -> Result<AnalyticsResult, RevocError> {
            Err(RevocError::Database("unused".into()))
        }
        async fn cleanup_old_events(&self, _: u32) -> Result<u64, RevocError> {
            Ok(0)
        }
    }

    fn event() -> AuditEvent {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::now_v7().to_string(), "org_id": null, "request_id": "r",
            "timestamp": "t", "caller_id": null, "caller_team": null, "environment": null,
            "decision": "allow", "effective_action": "allow", "enforcement_mode": "enforce",
            "violated_rules": null, "finding_types": null, "model": null, "provider": null,
            "tool_name": null, "request_type": null, "governance_depth": 0,
            "prompt_tokens": null, "completion_tokens": null, "estimated_cost_usd": null,
            "duration_ms": null, "detection_ms": null, "policy_ms": null,
            "was_normalized": false, "manifest_warnings": 0, "trace_id": null,
            "policy_engine": null, "created_at": "t"
        }))
        .expect("event")
    }

    async fn drained(pending: &AtomicUsize) {
        for _ in 0..500 {
            if pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("queue never drained");
    }

    fn store(permits: usize) -> Arc<MemStore> {
        Arc::new(MemStore {
            batches: std::sync::Mutex::default(),
            fail_first: AtomicUsize::new(0),
            gate: tokio::sync::Semaphore::new(permits),
        })
    }

    #[tokio::test]
    async fn queued_events_are_written_in_batches() {
        let s = store(0);
        let pending = Arc::new(AtomicUsize::new(0));
        let w = AuditWriter::spawn(
            s.clone(),
            50,
            Duration::from_millis(1),
            1000,
            pending.clone(),
        );
        // Hold the store so events pile up, then release it.
        for _ in 0..120 {
            assert!(w.enqueue(event()));
        }
        s.gate.add_permits(1000);
        drained(&pending).await;
        let batches = s.batches.lock().expect("lock").clone();
        assert_eq!(batches.iter().sum::<usize>(), 120);
        assert!(batches.iter().all(|&n| n <= 50), "{batches:?}");
        assert!(batches.len() < 120, "no batching happened: {batches:?}");
        assert_eq!(w.status_json()["dropped"], 0);
        assert_eq!(w.status_json()["written"], 120);
    }

    #[tokio::test]
    async fn failed_batches_are_retried() {
        let s = store(1000);
        s.fail_first.store(2, Ordering::SeqCst);
        let pending = Arc::new(AtomicUsize::new(0));
        let w = AuditWriter::spawn(
            s.clone(),
            10,
            Duration::from_millis(1),
            100,
            pending.clone(),
        );
        assert!(w.enqueue(event()));
        drained(&pending).await;
        assert_eq!(w.status_json()["written"], 1);
        assert_eq!(w.status_json()["dropped"], 0);
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_counts_without_waiting() {
        let s = store(0); // store never accepts
        let pending = Arc::new(AtomicUsize::new(0));
        let w = AuditWriter::spawn(s, 1, Duration::from_millis(1), 2, pending);
        let accepted = (0..10).filter(|_| w.enqueue(event())).count();
        assert!(accepted <= 3, "accepted {accepted}");
        assert_eq!(
            w.status_json()["dropped"].as_u64(),
            Some(10 - accepted as u64)
        );
    }
}
