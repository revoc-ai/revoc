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
    /// A zero TTL disables the cache: nothing is stored.
    pub fn set(&self, key: &str, decision: PolicyDecision) {
        if self.ttl.is_zero() {
            return;
        }
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

    /// Compute a SHA-256 cache key over the whole decision input.
    ///
    /// Hashes a canonical JSON form of `input` (object keys sorted
    /// recursively) with only the fields that change on every request
    /// removed: `request_id`, `timestamp`, and each finding's `id` and
    /// `detected_at`. Everything else — tool arguments, tool results,
    /// messages, findings (including `was_encoded`), depth, caller and
    /// session state — is part of the key, so two inputs share a key only
    /// when the policy sees identical data. Returns `None` if `input` cannot
    /// be serialised; callers then evaluate without caching.
    pub fn cache_key(input: &PolicyInput) -> Option<String> {
        let mut value = serde_json::to_value(input).ok()?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("request_id");
            obj.remove("timestamp");
            if let Some(findings) = obj.get_mut("findings").and_then(|f| f.as_array_mut()) {
                for f in findings.iter_mut().filter_map(|f| f.as_object_mut()) {
                    f.remove("id");
                    f.remove("detected_at");
                }
            }
        }
        let mut hasher = Sha256::new();
        write_canonical(&value, &mut hasher);
        Some(hex::encode(hasher.finalize()))
    }
}

/// Feed `v` into `hasher` as canonical JSON: object keys sorted, no whitespace.
fn write_canonical(v: &serde_json::Value, hasher: &mut Sha256) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            hasher.update(b"{");
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    hasher.update(b",");
                }
                hasher.update(Value::String(k.clone()).to_string().as_bytes());
                hasher.update(b":");
                write_canonical(&map[k], hasher);
            }
            hasher.update(b"}");
        }
        Value::Array(items) => {
            hasher.update(b"[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    hasher.update(b",");
                }
                write_canonical(item, hasher);
            }
            hasher.update(b"]");
        }
        other => hasher.update(other.to_string().as_bytes()),
    }
}
