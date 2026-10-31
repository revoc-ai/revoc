//! Policy decision cache — reduces policy engine load for repeated identical requests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sha2::{Digest, Sha256};

use revoc_core::{PolicyDecision, PolicyInput};

/// Thread-safe LRU-like decision cache backed by [`DashMap`].
pub struct DecisionCache {
    store: DashMap<String, (PolicyDecision, Instant)>,
    ttl: Duration,
    max_entries: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DecisionCache {
    /// Create a new cache with `ttl` per-entry lifetime and `max_entries` capacity.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            store: DashMap::new(),
            ttl,
            max_entries,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached decision by key.
    ///
    /// Returns `Some(decision)` with `cache_hit = true` when the key is found
    /// and the entry has not expired.
    pub fn get(&self, key: &str) -> Option<PolicyDecision> {
        if let Some(entry) = self.store.get(key) {
            let (decision, stored_at) = &*entry;
            if stored_at.elapsed() < self.ttl {
                self.hits.fetch_add(1, Ordering::Relaxed);
                let mut d = decision.clone();
                d.cache_hit = true;
                return Some(d);
            }
            // Expired — remove lazily
            drop(entry);
            self.store.remove(key);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Store a decision under `key`.
    ///
    /// When `max_entries` is reached, the oldest entry is evicted before inserting.
    pub fn set(&self, key: &str, decision: PolicyDecision) {
        if self.store.len() >= self.max_entries {
            // Evict the entry with the oldest timestamp
            if let Some(oldest_key) = self
                .store
                .iter()
                .min_by_key(|e| e.value().1)
                .map(|e| e.key().clone())
            {
                self.store.remove(&oldest_key);
            }
        }
        self.store
            .insert(key.to_owned(), (decision, Instant::now()));
    }

    /// Invalidate all cached entries (used on policy reload).
    pub fn invalidate_all(&self) {
        self.store.clear();
    }

    /// Return the current cache hit rate in `[0.0, 1.0]`.
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        #[allow(clippy::cast_precision_loss)]
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Compute a stable SHA-256 cache key from the policy-relevant fields of `input`.
    ///
    /// Intentionally excludes `request_id` and `timestamp` which differ per-request
    /// even when the governance-relevant content is identical.
    pub fn cache_key(input: &PolicyInput) -> String {
        let mut hasher = Sha256::new();

        // Request type
        hasher.update(format!("{:?}", input.request_type));

        // Caller identity
        hasher.update(&input.caller.environment);
        hasher.update(&input.caller.org_id);
        hasher.update(input.caller.team.as_deref().unwrap_or(""));
        hasher.update(&input.caller.caller_id);

        // Findings — sorted for stability (order of detection may vary)
        let mut finding_keys: Vec<String> = input
            .findings
            .iter()
            .map(|f| {
                // Include `pattern_name` metadata (set by regex_detector) so
                // findings that share a FindingType but stem from distinct
                // detection patterns (and thus distinct applicable_rules,
                // e.g. DdlMutation from "ddl_mutation" vs "delete_no_where"
                // vs "mass_delete") do not collide on the same cache key.
                let pattern_name = f
                    .metadata
                    .get("pattern_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                format!(
                    "{:?}:{}:{}",
                    f.finding_type,
                    f.pii_entity
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    pattern_name
                )
            })
            .collect();
        finding_keys.sort();
        for fk in &finding_keys {
            hasher.update(fk);
        }

        // Tool call name (if any)
        if let Some(call) = &input.tool_call {
            hasher.update(&call.tool_name);
        }

        // Model
        hasher.update(input.model.as_deref().unwrap_or(""));

        hex::encode(hasher.finalize())
    }
}
