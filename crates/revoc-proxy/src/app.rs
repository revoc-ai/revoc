//! Application state and router construction.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use tower_http::trace::TraceLayer;

use revoc_config::Config;
use revoc_core::{RevocError, SessionState};
use revoc_dashboard::LiveFeedBus;
use revoc_dashboard::{
    AnalyticsResult, AnalyticsWindow, AuditEvent, AuditStore, CallerCount, EventFilter, RuleCount,
    ServiceCost, TimelinePoint,
};
use revoc_pipeline::Pipeline;
use revoc_policy::RevocPolicyEngine;
use revoc_redaction::RevocRedactor;
use revoc_telemetry::RevocMetrics;

use crate::{
    handlers::{
        embeddings::embeddings_handler,
        emergency::{activate_handler, deactivate_handler, status_handler},
        health::{health_handler, metrics_handler, ready_handler, reload_handler, startup_handler},
        llm::{chat_completions_handler, completions_handler},
        mcp::mcp_handler,
    },
    kill_switch::{
        store::{KillSwitchStore, PostgresKillSwitchStore, SqliteKillSwitchStore},
        KillSwitchService, KillSwitchState,
    },
    middleware::{
        audit_exit::audit_exit_middleware,
        auth::{auth_middleware, load_api_keys},
        metrics_recorder::metrics_recorder_middleware,
        rate_limit::{rate_limit_middleware, RateLimiter},
        request_id::request_id_middleware,
        security::security_middleware,
    },
    storage::{AuditWriter, PostgresAuditStore, RedisSessionStore},
    upstream::{client::UpstreamClient, router::UpstreamRouter},
};

// ── SessionStore ──────────────────────────────────────────────────────────────

/// Async session state store (in-memory or Redis backed).
#[async_trait]
#[allow(dead_code)]
pub trait SessionStore: Send + Sync {
    /// Retrieve session state by session ID.
    async fn get(&self, session_id: &str) -> Option<SessionState>;
    /// Persist session state with a TTL.
    async fn set(
        &self,
        session_id: &str,
        state: SessionState,
        ttl_secs: u64,
    ) -> Result<(), RevocError>;
    /// Delete a session.
    async fn delete(&self, session_id: &str) -> Result<(), RevocError>;
}

/// In-memory session store (Tier 1 — no Redis required).
pub struct InMemorySessionStore {
    #[allow(dead_code)]
    store: DashMap<String, (SessionState, std::time::Instant)>,
    #[allow(dead_code)]
    ttl: Duration,
}

impl InMemorySessionStore {
    /// Create a new in-memory store with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            store: DashMap::new(),
            ttl,
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn get(&self, session_id: &str) -> Option<SessionState> {
        if let Some(entry) = self.store.get(session_id) {
            if entry.1.elapsed() < self.ttl {
                return Some(entry.0.clone());
            }
            drop(entry);
            self.store.remove(session_id);
        }
        None
    }

    async fn set(
        &self,
        session_id: &str,
        state: SessionState,
        _ttl_secs: u64,
    ) -> Result<(), RevocError> {
        self.store
            .insert(session_id.to_owned(), (state, std::time::Instant::now()));
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), RevocError> {
        self.store.remove(session_id);
        Ok(())
    }
}

// ── Kill-switch log ───────────────────────────────────────────────────────────

/// Persists kill-switch activate/deactivate events to the `` `kill_switch_log` ``
/// table (SPEC.md §23 Rule 26 — "Never activate kill-switch without writing
/// to `kill_switch_log` table").
#[async_trait]
pub trait KillSwitchLogWriter: Send + Sync {
    /// Record a kill-switch activate/deactivate action.
    async fn log(
        &self,
        scope: &str,
        scope_value: Option<&str>,
        action: &str,
        activated_by: &str,
        reason: Option<&str>,
    ) -> Result<(), RevocError>;
}

// ── Audit stores ──────────────────────────────────────────────────────────────

/// SQLite-backed audit store.
pub struct SqliteAuditStore {
    pool: sqlx::SqlitePool,
}

impl SqliteAuditStore {
    /// Open or create a `SQLite` database at `path`.
    pub async fn open(path: &str) -> Result<Self, anyhow::Error> {
        use std::str::FromStr as _;
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite:{path}"))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = sqlx::SqlitePool::connect_with(options).await?;
        // Ensure the audit table exists
        sqlx::query(include_str!("../sql/schema.sql"))
            .execute(&pool)
            .await
            .ok(); // Best-effort; table may already exist
        Ok(Self { pool })
    }

    /// The underlying connection pool (shared with the kill-switch store).
    pub fn pool(&self) -> sqlx::SqlitePool {
        self.pool.clone()
    }
}

/// The bound `INSERT` for one event, shared by single and batch writes.
fn sqlite_insert(
    event: &AuditEvent,
) -> sqlx::query::Query<'_, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'_>> {
    sqlx::query(
        "INSERT OR REPLACE INTO audit_events
         (id, org_id, request_id, timestamp, caller_id, caller_team, environment,
          decision, effective_action, enforcement_mode, violated_rules, finding_types,
          model, provider, tool_name, request_type, governance_depth, prompt_tokens,
          completion_tokens, estimated_cost_usd, duration_ms, detection_ms, policy_ms,
          was_normalized, manifest_warnings, trace_id, policy_engine, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&event.id)
    .bind(&event.org_id)
    .bind(&event.request_id)
    .bind(&event.timestamp)
    .bind(&event.caller_id)
    .bind(&event.caller_team)
    .bind(&event.environment)
    .bind(&event.decision)
    .bind(&event.effective_action)
    .bind(&event.enforcement_mode)
    .bind(&event.violated_rules)
    .bind(&event.finding_types)
    .bind(&event.model)
    .bind(&event.provider)
    .bind(&event.tool_name)
    .bind(&event.request_type)
    .bind(event.governance_depth)
    .bind(event.prompt_tokens)
    .bind(event.completion_tokens)
    .bind(event.estimated_cost_usd)
    .bind(event.duration_ms)
    .bind(event.detection_ms)
    .bind(event.policy_ms)
    .bind(event.was_normalized)
    .bind(event.manifest_warnings)
    .bind(&event.trace_id)
    .bind(&event.policy_engine)
    .bind(&event.created_at)
}

#[async_trait]
#[allow(clippy::too_many_lines)] // analytics runs five aggregate queries
impl AuditStore for SqliteAuditStore {
    async fn insert_event(&self, event: AuditEvent) -> Result<(), RevocError> {
        sqlite_insert(&event)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| RevocError::Database(e.to_string()))
    }

    async fn insert_batch(&self, events: Vec<AuditEvent>) -> Result<(), RevocError> {
        let db_err = |e: sqlx::Error| RevocError::Database(e.to_string());
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        for event in &events {
            sqlite_insert(event)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    async fn list_events(&self, filter: EventFilter) -> Result<(Vec<AuditEvent>, u64), RevocError> {
        let limit = i64::try_from(filter.limit.unwrap_or(25)).unwrap_or(i64::MAX);
        let offset = i64::try_from(filter.offset.unwrap_or(0)).unwrap_or(i64::MAX);
        let sql = "SELECT id, org_id, request_id, timestamp, caller_id, caller_team, \
                   environment, decision, effective_action, enforcement_mode, \
                   violated_rules, finding_types, model, provider, tool_name, \
                   request_type, governance_depth, prompt_tokens, completion_tokens, \
                   estimated_cost_usd, duration_ms, detection_ms, policy_ms, \
                   was_normalized, manifest_warnings, trace_id, policy_engine, created_at \
                   FROM audit_events ORDER BY timestamp DESC LIMIT ? OFFSET ?";
        let rows: Vec<AuditEvent> = sqlx::query_as::<_, AuditEvent>(sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| RevocError::Database(e.to_string()))?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RevocError::Database(e.to_string()))?;

        Ok((rows, total.unsigned_abs()))
    }

    /// A streamed request has a request-side and a response-side event; the
    /// latest one (ids are UUID v7, so time-ordered) is the trace's outcome.
    async fn get_event_by_trace(&self, trace_id: &str) -> Result<Option<AuditEvent>, RevocError> {
        let sql = "SELECT id, org_id, request_id, timestamp, caller_id, caller_team, \
                   environment, decision, effective_action, enforcement_mode, \
                   violated_rules, finding_types, model, provider, tool_name, \
                   request_type, governance_depth, prompt_tokens, completion_tokens, \
                   estimated_cost_usd, duration_ms, detection_ms, policy_ms, \
                   was_normalized, manifest_warnings, trace_id, policy_engine, created_at \
                   FROM audit_events WHERE trace_id = ? ORDER BY id DESC LIMIT 1";
        sqlx::query_as::<_, AuditEvent>(sql)
            .bind(trace_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RevocError::Database(e.to_string()))
    }

    async fn analytics(&self, window: AnalyticsWindow) -> Result<AnalyticsResult, RevocError> {
        let modifier = window.sqlite_modifier();
        let db_err = |e: sqlx::Error| RevocError::Database(e.to_string());

        // ── Aggregate decision counts for the window ─────────────────────
        let (total, blocked, redacted, allowed): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
                COUNT(*), \
                COALESCE(SUM(CASE WHEN decision = 'block'  THEN 1 ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN decision = 'redact' THEN 1 ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN decision = 'allow'  THEN 1 ELSE 0 END), 0) \
             FROM audit_events WHERE created_at >= datetime('now', ?)",
        )
        .bind(modifier)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        // ── Top violated rules — parsed from the comma-separated column ──
        // (ANSI SQL has no array type for `violated_rules`; aggregation is
        // performed in-process over the real rows in the window.)
        let rule_lists: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT violated_rules FROM audit_events \
             WHERE created_at >= datetime('now', ?) AND violated_rules IS NOT NULL \
               AND violated_rules <> ''",
        )
        .bind(modifier)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let mut rule_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        for (rules,) in &rule_lists {
            if let Some(rules) = rules {
                for r in rules.split(',') {
                    let r = r.trim();
                    if !r.is_empty() {
                        *rule_counts.entry(r.to_owned()).or_insert(0) += 1;
                    }
                }
            }
        }
        let mut top_rules: Vec<RuleCount> = rule_counts
            .into_iter()
            .map(|(rule_id, count)| RuleCount { rule_id, count })
            .collect();
        top_rules.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
        top_rules.truncate(10);

        // ── Top callers by event volume ───────────────────────────────────
        let caller_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT caller_id, COUNT(*) AS cnt FROM audit_events \
             WHERE created_at >= datetime('now', ?) AND caller_id IS NOT NULL AND caller_id <> '' \
             GROUP BY caller_id ORDER BY cnt DESC, caller_id ASC LIMIT 10",
        )
        .bind(modifier)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let top_callers = caller_rows
            .into_iter()
            .map(|(caller_id, count)| CallerCount {
                caller_id,
                count: count.unsigned_abs(),
            })
            .collect();

        // ── Estimated cost by service (provider, falling back to tool name) ─
        let cost_rows: Vec<(String, f64)> = sqlx::query_as(
            "SELECT COALESCE(NULLIF(provider, ''), NULLIF(tool_name, ''), 'unknown') AS service, \
                    COALESCE(SUM(estimated_cost_usd), 0.0) AS cost \
             FROM audit_events \
             WHERE created_at >= datetime('now', ?) AND estimated_cost_usd IS NOT NULL \
             GROUP BY service ORDER BY cost DESC LIMIT 10",
        )
        .bind(modifier)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let costs_by_service = cost_rows
            .into_iter()
            .map(|(service, cost_usd)| ServiceCost { service, cost_usd })
            .collect();

        // ── Timeline — bucketed by hour (short windows) or day (long) ────
        let bucket_fmt = window.bucket_strftime();
        let timeline_rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT strftime(?, created_at) AS bucket, \
                    COUNT(*) AS total, \
                    COALESCE(SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END), 0) AS blocked \
             FROM audit_events WHERE created_at >= datetime('now', ?) \
             GROUP BY bucket ORDER BY bucket ASC",
        )
        .bind(bucket_fmt)
        .bind(modifier)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let timeline = timeline_rows
            .into_iter()
            .map(|(ts, total, blocked)| TimelinePoint {
                ts,
                total: total.unsigned_abs(),
                blocked: blocked.unsigned_abs(),
            })
            .collect();

        Ok(AnalyticsResult {
            total: total.unsigned_abs(),
            blocked: blocked.unsigned_abs(),
            redacted: redacted.unsigned_abs(),
            allowed: allowed.unsigned_abs(),
            top_rules,
            top_callers,
            costs_by_service,
            timeline,
        })
    }

    async fn cleanup_old_events(&self, retention_days: u32) -> Result<u64, RevocError> {
        let res = sqlx::query("DELETE FROM audit_events WHERE created_at < datetime('now', ?)")
            .bind(format!("-{retention_days} days"))
            .execute(&self.pool)
            .await
            .map_err(|e| RevocError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }
}

#[async_trait]
impl KillSwitchLogWriter for SqliteAuditStore {
    async fn log(
        &self,
        scope: &str,
        scope_value: Option<&str>,
        action: &str,
        activated_by: &str,
        reason: Option<&str>,
    ) -> Result<(), RevocError> {
        sqlx::query(
            "INSERT INTO kill_switch_log (id, scope, scope_value, action, activated_by, reason)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(scope)
        .bind(scope_value)
        .bind(action)
        .bind(activated_by)
        .bind(reason)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| RevocError::Database(e.to_string()))
    }
}

// ── AppState ──────────────────────────────────────────────────────────────────

/// Shared application state — Clone-able (all fields are Arc or &'static).
#[derive(Clone)]
pub struct AppState {
    /// Full proxy configuration.
    pub config: Arc<Config>,
    /// Detection + deduplication pipeline.
    pub pipeline: Arc<Pipeline>,
    /// Policy engine (native / OPA sidecar / OPA WASM).
    pub policy_engine: Arc<RevocPolicyEngine>,
    /// Body redactor.
    pub redactor: Arc<RevocRedactor>,
    /// Upstream provider router.
    pub upstream_router: Arc<UpstreamRouter>,
    /// Shared upstream HTTP client.
    pub upstream_client: Arc<UpstreamClient>,
    /// Prometheus metrics singleton.
    pub metrics: &'static RevocMetrics,
    /// SSE live feed bus.
    pub feed_bus: Arc<LiveFeedBus>,
    /// Audit event store.
    pub audit_store: Arc<dyn AuditStore + Send + Sync>,
    /// Emergency kill-switch state (hot path; owned by `kill_switch_service`).
    pub kill_switch: Arc<KillSwitchState>,
    /// Durable, signed, reconciled kill-switch service.
    pub kill_switch_service: Arc<KillSwitchService>,
    /// Per-caller session state.
    #[allow(dead_code)]
    pub session_store: Arc<dyn SessionStore + Send + Sync>,
    /// Per-caller rate limiter.
    pub rate_limiter: RateLimiter,
    /// Count of queued or in-flight audit events — lets graceful shutdown
    /// drain the queue instead of dropping writes on the floor (Rule 25/26).
    pub pending_audit_writes: Arc<std::sync::atomic::AtomicUsize>,
    /// Batched audit writer (SPEC.md §23 Rule 25).
    pub audit_writer: AuditWriter,
}

impl AppState {
    /// `true` unless `policy.fail_open` is set. Every governance failure
    /// (detection incomplete, policy error, redaction error) blocks when this
    /// holds — an unchecked request is never forwarded (SPEC.md §3 P7).
    pub fn fail_closed(&self) -> bool {
        !self.config.policy.fail_open
    }

    /// Queue an audit event for the batched writer without blocking the
    /// request path (SPEC.md §23 Rule 25). Queued events are counted in
    /// `pending_audit_writes` so [`crate::shutdown::graceful_shutdown`] can
    /// wait for them to drain before the process exits.
    pub fn spawn_audit_write(&self, event: AuditEvent) {
        crate::middleware::audit_exit::mark_audited();
        self.audit_writer.enqueue(event);
    }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/// Build the complete `AppState` from a loaded configuration.
pub async fn build_app_state(cfg: Arc<Config>) -> Result<AppState, anyhow::Error> {
    use revoc_detector::DetectionEngine;

    let metrics = RevocMetrics::global();

    // Detection pipeline
    let engine = DetectionEngine::new(&cfg, metrics)?;
    let pipeline = Arc::new(Pipeline::new(
        std::sync::Arc::new(engine),
        Duration::from_secs(8),
    ));

    // Policy engine
    let policy_engine = Arc::new(RevocPolicyEngine::new(&cfg, metrics)?);

    // Redactor
    let redactor = Arc::new(RevocRedactor::new(metrics));

    // Upstream
    let upstream_client = Arc::new(UpstreamClient::new(&cfg)?);
    let upstream_router = Arc::new(UpstreamRouter::new(&cfg)?);

    // Live feed
    let feed_bus = Arc::new(LiveFeedBus::new(1024));

    // Audit store — also the kill-switch log writer and, without Redis, the
    // kill-switch state store, since all three live in the same database
    // (SPEC.md §15, §23 Rule 26).
    let (audit_store, kill_switch_log, kill_switch_db) = open_audit_db(&cfg).await?;

    // Kill-switch: state is loaded from the durable store before any traffic
    // is served (SPEC.md §9 D11).
    let kill_switch_service =
        KillSwitchService::build(&cfg, kill_switch_log, kill_switch_db).await?;
    let kill_switch = kill_switch_service.state.clone();

    // Session store — Redis when configured, so every instance sees the
    // same session (SPEC.md §11).
    let session_store: Arc<dyn SessionStore + Send + Sync> = match redis_url(&cfg) {
        Some(url) => Arc::new(RedisSessionStore::new(&url)?),
        None => Arc::new(InMemorySessionStore::new(Duration::from_secs(
            cfg.session.ttl_secs,
        ))),
    };

    // Concurrency limits: per caller, per org (tenant) and process-wide
    let rate_limiter = RateLimiter::new(
        cfg.server.max_concurrent_per_caller,
        cfg.server.max_concurrent_per_org,
        cfg.server.max_concurrent_total,
    );

    let pending_audit_writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let audit_cfg = &cfg.storage.audit;
    let audit_writer = AuditWriter::spawn(
        audit_store.clone(),
        audit_cfg.audit_write_batch_size,
        Duration::from_millis(audit_cfg.audit_write_interval_ms.max(1)),
        AUDIT_QUEUE_CAPACITY,
        pending_audit_writes.clone(),
    );

    Ok(AppState {
        config: cfg,
        pipeline,
        policy_engine,
        redactor,
        upstream_router,
        upstream_client,
        metrics,
        feed_bus,
        audit_store,
        kill_switch,
        kill_switch_service,
        session_store,
        rate_limiter,
        pending_audit_writes,
        audit_writer,
    })
}

/// Audit events that may wait for the writer before new ones are dropped —
/// about 10 s of backlog at 10k req/s.
const AUDIT_QUEUE_CAPACITY: usize = 100_000;

type AuditDb = (
    Arc<dyn AuditStore + Send + Sync>,
    Arc<dyn KillSwitchLogWriter + Send + Sync>,
    Arc<dyn KillSwitchStore>,
);

/// Open the audit database selected by `storage.backend`.
///
/// # Errors
/// An unknown backend, a missing Postgres URL, or a connection failure:
/// the proxy does not serve traffic it cannot audit.
async fn open_audit_db(cfg: &Config) -> Result<AuditDb, anyhow::Error> {
    match cfg.storage.backend.as_str() {
        "sqlite" => {
            let store = Arc::new(SqliteAuditStore::open(&cfg.storage.sqlite_path).await?);
            let ks = Arc::new(SqliteKillSwitchStore::new(store.pool()));
            Ok((store.clone(), store, ks))
        }
        "postgres" => {
            let env = &cfg.storage.postgres_url_env;
            let url = std::env::var(env)
                .ok()
                .filter(|u| !u.is_empty())
                .ok_or_else(|| {
                    RevocError::Configuration(format!(
                        "storage.backend is \"postgres\" but {env} is not set"
                    ))
                })?;
            let store = Arc::new(
                PostgresAuditStore::connect(
                    &url,
                    cfg.storage.pool_size,
                    cfg.storage.migrations_auto_run,
                )
                .await?,
            );
            let ks = Arc::new(PostgresKillSwitchStore::new(store.pool()));
            Ok((store.clone(), store, ks))
        }
        other => Err(RevocError::Configuration(format!(
            "storage.backend must be \"sqlite\" or \"postgres\", got \"{other}\""
        ))
        .into()),
    }
}

/// Redis URL from `REDIS_URL` or the `cache.redis_url_env` variable.
fn redis_url(cfg: &Config) -> Option<String> {
    std::env::var("REDIS_URL")
        .or_else(|_| std::env::var(&cfg.cache.redis_url_env))
        .ok()
        .filter(|u| !u.is_empty())
}

// ── Router ────────────────────────────────────────────────────────────────────

/// All routers returned by [`build_routers`].
pub struct AppRouters {
    /// Main proxy router (binds on `cfg.server.port`, default 8080).
    pub main: Router,
    /// Internal admin router (binds on `server.internal_host:internal_port`, loopback by default).
    pub internal: Router,
    /// Dashboard SPA router (binds on `cfg.server.dashboard_port`).
    pub dashboard: Option<Router>,
}

/// Build all three routers from the application state.
pub fn build_routers(state: &AppState) -> AppRouters {
    // ── Main proxy router (8080) ─────────────────────────────────────────────
    //
    // Health/readiness/startup/metrics probes are deliberately split into
    // their own sub-router WITHOUT the `auth` and `rate_limit` layers.
    // Orchestrators (Docker healthcheck, Kubernetes liveness/readiness/startup
    // probes, Prometheus scrapers) hit these endpoints unauthenticated — they
    // must never be gated behind `auth.mode = "apikey"`/`"jwt"`, mirroring the
    // kill-switch bypass guarantee that `/health`, `/ready`, `/startup`, and
    // `/metrics` are ALWAYS reachable (SPEC.md §9 D11 / §16).
    let governed = Router::new()
        .route("/v1/chat/completions", post(chat_completions_handler))
        .route("/v1/completions", post(completions_handler))
        .route("/v1/embeddings", post(embeddings_handler))
        .route("/mcp", post(mcp_handler))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        // Inside auth (needs the caller), outside rate limiting (so 429s
        // are audited): every authenticated exit leaves a record.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit_exit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let probes = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler).with_state(state.clone()))
        .route("/startup", get(startup_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state.clone());

    let main = governed
        .merge(probes)
        // Middleware in order (outermost first): RequestId → Trace → Metrics → Security
        // — applied uniformly to both governed and probe routes. Auth + RateLimit
        // are scoped to the governed sub-router only (see above).
        .layer(middleware::from_fn(security_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics_recorder_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(request_id_middleware));

    // ── Internal admin router (loopback by default) ───────────────────────────────────────────────────
    let internal = Router::new()
        .route("/internal/reload", post(reload_handler))
        .route(
            "/internal/emergency/kill-switch/activate",
            post(activate_handler),
        )
        .route(
            "/internal/emergency/kill-switch/deactivate",
            post(deactivate_handler),
        )
        .route(
            "/internal/emergency/kill-switch/status",
            get(status_handler),
        )
        .with_state(state.clone());

    // ── Dashboard router ─────────────────────────────────────────────────────
    let dashboard_router = if state.config.server.dashboard_port > 0 {
        // "shared" mode reuses the same operator-provisioned API keys as the
        // governed proxy (api_keys_file / api_keys_env) — a single shared
        // secret set for both planes, matching SPEC.md §13 [auth] config.
        // Changing the kill-switch additionally requires the admin key —
        // client API keys only ever grant read access to the dashboard.
        let dash_auth = revoc_dashboard::auth::DashboardAuth::new(
            state.config.dashboard.auth_mode.clone(),
            load_api_keys(state),
        )
        .with_admin_key(crate::handlers::emergency::configured_admin_key(
            &state.config,
        ));
        let dash_state = revoc_dashboard::api::DashboardState {
            store: state.audit_store.clone(),
            kill_switch: Arc::new(crate::kill_switch::DashboardKillSwitchAdapter::new(
                state.kill_switch_service.clone(),
            )),
        };
        Some(revoc_dashboard::handler::dashboard_router(
            dash_state,
            dash_auth,
            (*state.feed_bus).clone(),
        ))
    } else {
        None
    };

    AppRouters {
        main,
        internal,
        dashboard: dashboard_router,
    }
}
