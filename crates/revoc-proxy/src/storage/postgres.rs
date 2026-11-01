//! Postgres audit store (SPEC.md §15) — the multi-instance backend selected
//! by `storage.backend = "postgres"`.
//!
//! The table is shared with the admin API, whose alembic migration declares
//! every timestamp as RFC 3339 `TEXT` and the counters as `INTEGER`/`REAL`.
//! Reads therefore cast to the Rust types (`BIGINT`, `DOUBLE PRECISION`,
//! `BOOLEAN`), and time windows compare RFC 3339 strings, which sort
//! chronologically because every writer emits UTC with the same layout.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::{PgPool, PgPoolOptions};

use revoc_core::RevocError;
use revoc_dashboard::{
    AnalyticsResult, AnalyticsWindow, AuditEvent, AuditStore, CallerCount, EventFilter, RuleCount,
    ServiceCost, TimelinePoint,
};

use crate::app::KillSwitchLogWriter;

/// Advisory lock serialising schema creation across instances.
const SCHEMA_LOCK_ID: i64 = 0x5245_564f_4353_3731; // "REVOCS71"

/// Columns of `audit_events`, cast so they decode into [`AuditEvent`].
const SELECT_COLUMNS: &str = "id, org_id, request_id, timestamp, caller_id, caller_team, \
     environment, decision, effective_action, enforcement_mode, violated_rules, finding_types, \
     model, provider, tool_name, request_type, \
     COALESCE(governance_depth, 0)::BIGINT AS governance_depth, \
     prompt_tokens::BIGINT AS prompt_tokens, completion_tokens::BIGINT AS completion_tokens, \
     estimated_cost_usd::DOUBLE PRECISION AS estimated_cost_usd, \
     duration_ms::DOUBLE PRECISION AS duration_ms, \
     detection_ms::DOUBLE PRECISION AS detection_ms, \
     policy_ms::DOUBLE PRECISION AS policy_ms, \
     (COALESCE(was_normalized, 0) <> 0) AS was_normalized, \
     COALESCE(manifest_warnings, 0)::BIGINT AS manifest_warnings, \
     trace_id, policy_engine, created_at";

#[allow(clippy::needless_pass_by_value)] // used as `map_err(db_err)`
fn db_err(e: sqlx::Error) -> RevocError {
    RevocError::Database(e.to_string())
}

/// Postgres-backed audit store and kill-switch log.
pub struct PostgresAuditStore {
    pool: PgPool,
}

impl PostgresAuditStore {
    /// Connect to `url` with at most `pool_size` connections and, when
    /// `create_schema` is set, create the tables if they are missing.
    ///
    /// # Errors
    /// Connection or schema-creation failure. Startup aborts on either: a
    /// proxy that cannot record its decisions does not serve traffic.
    pub async fn connect(
        url: &str,
        pool_size: u32,
        create_schema: bool,
    ) -> Result<Self, RevocError> {
        let pool = PgPoolOptions::new()
            .max_connections(pool_size.max(1))
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await
            .map_err(db_err)?;
        if create_schema {
            // `CREATE TABLE IF NOT EXISTS` is not safe against a concurrent
            // create, so replicas starting together take turns.
            let mut tx = pool.begin().await.map_err(db_err)?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(SCHEMA_LOCK_ID)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            sqlx::raw_sql(include_str!("../../sql/schema_postgres.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
        }
        Ok(Self { pool })
    }

    /// The underlying connection pool (shared with the kill-switch store).
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }
}

/// RFC 3339 start of `window`, comparable with `created_at`.
fn window_start(window: AnalyticsWindow) -> String {
    (Utc::now() - window.duration()).to_rfc3339()
}

/// SQL expression truncating `created_at` to the window's timeline bucket,
/// in the same layout the `SQLite` store produces.
fn bucket_expr(window: AnalyticsWindow) -> &'static str {
    match window {
        AnalyticsWindow::Hour1 | AnalyticsWindow::Hour24 => "LEFT(created_at, 13) || ':00:00Z'",
        AnalyticsWindow::Day7 | AnalyticsWindow::Day30 => "LEFT(created_at, 10) || 'T00:00:00Z'",
    }
}

/// The bound `INSERT` for one event, shared by single and batch writes.
fn pg_insert(
    event: &AuditEvent,
) -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "INSERT INTO audit_events
         (id, org_id, request_id, timestamp, caller_id, caller_team, environment,
          decision, effective_action, enforcement_mode, violated_rules, finding_types,
          model, provider, tool_name, request_type, governance_depth, prompt_tokens,
          completion_tokens, estimated_cost_usd, duration_ms, detection_ms, policy_ms,
          was_normalized, manifest_warnings, trace_id, policy_engine, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
                 $20,$21,$22,$23,$24::INTEGER,$25,$26,$27,$28)
         ON CONFLICT (id) DO UPDATE SET
          decision = EXCLUDED.decision,
          effective_action = EXCLUDED.effective_action,
          violated_rules = EXCLUDED.violated_rules,
          finding_types = EXCLUDED.finding_types,
          prompt_tokens = EXCLUDED.prompt_tokens,
          completion_tokens = EXCLUDED.completion_tokens,
          estimated_cost_usd = EXCLUDED.estimated_cost_usd,
          duration_ms = EXCLUDED.duration_ms,
          detection_ms = EXCLUDED.detection_ms,
          policy_ms = EXCLUDED.policy_ms",
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
impl AuditStore for PostgresAuditStore {
    async fn insert_event(&self, event: AuditEvent) -> Result<(), RevocError> {
        pg_insert(&event)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn insert_batch(&self, events: Vec<AuditEvent>) -> Result<(), RevocError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        for event in &events {
            pg_insert(event).execute(&mut *tx).await.map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    async fn list_events(&self, filter: EventFilter) -> Result<(Vec<AuditEvent>, u64), RevocError> {
        let limit = i64::try_from(filter.limit.unwrap_or(25)).unwrap_or(i64::MAX);
        let offset = i64::try_from(filter.offset.unwrap_or(0)).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM audit_events \
             ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
        );
        let rows: Vec<AuditEvent> = sqlx::query_as::<_, AuditEvent>(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok((rows, total.unsigned_abs()))
    }

    /// The latest event (UUID v7 ids are time-ordered) is the trace's outcome.
    async fn get_event_by_trace(&self, trace_id: &str) -> Result<Option<AuditEvent>, RevocError> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM audit_events \
             WHERE trace_id = $1 ORDER BY id DESC LIMIT 1"
        );
        sqlx::query_as::<_, AuditEvent>(&sql)
            .bind(trace_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)
    }

    async fn analytics(&self, window: AnalyticsWindow) -> Result<AnalyticsResult, RevocError> {
        let since = window_start(window);

        let (total, blocked, redacted, allowed): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
                COUNT(*), \
                COUNT(*) FILTER (WHERE decision = 'block'), \
                COUNT(*) FILTER (WHERE decision = 'redact'), \
                COUNT(*) FILTER (WHERE decision = 'allow') \
             FROM audit_events WHERE created_at >= $1",
        )
        .bind(&since)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        let top_rules: Vec<(String, i64)> = sqlx::query_as(
            "SELECT TRIM(rule) AS rule_id, COUNT(*) AS cnt \
             FROM audit_events, UNNEST(STRING_TO_ARRAY(violated_rules, ',')) AS rule \
             WHERE created_at >= $1 AND TRIM(rule) <> '' \
             GROUP BY rule_id ORDER BY cnt DESC, rule_id ASC LIMIT 10",
        )
        .bind(&since)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let caller_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT caller_id, COUNT(*) AS cnt FROM audit_events \
             WHERE created_at >= $1 AND caller_id IS NOT NULL AND caller_id <> '' \
             GROUP BY caller_id ORDER BY cnt DESC, caller_id ASC LIMIT 10",
        )
        .bind(&since)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let cost_rows: Vec<(String, f64)> = sqlx::query_as(
            "SELECT COALESCE(NULLIF(provider, ''), NULLIF(tool_name, ''), 'unknown') AS service, \
                    COALESCE(SUM(estimated_cost_usd), 0)::DOUBLE PRECISION AS cost \
             FROM audit_events \
             WHERE created_at >= $1 AND estimated_cost_usd IS NOT NULL \
             GROUP BY service ORDER BY cost DESC LIMIT 10",
        )
        .bind(&since)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let timeline_sql = format!(
            "SELECT {bucket} AS bucket, COUNT(*) AS total, \
                    COUNT(*) FILTER (WHERE decision = 'block') AS blocked \
             FROM audit_events WHERE created_at >= $1 \
             GROUP BY bucket ORDER BY bucket ASC",
            bucket = bucket_expr(window)
        );
        let timeline_rows: Vec<(String, i64, i64)> = sqlx::query_as(&timeline_sql)
            .bind(&since)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;

        Ok(AnalyticsResult {
            total: total.unsigned_abs(),
            blocked: blocked.unsigned_abs(),
            redacted: redacted.unsigned_abs(),
            allowed: allowed.unsigned_abs(),
            top_rules: top_rules
                .into_iter()
                .map(|(rule_id, count)| RuleCount {
                    rule_id,
                    count: count.unsigned_abs(),
                })
                .collect(),
            top_callers: caller_rows
                .into_iter()
                .map(|(caller_id, count)| CallerCount {
                    caller_id,
                    count: count.unsigned_abs(),
                })
                .collect(),
            costs_by_service: cost_rows
                .into_iter()
                .map(|(service, cost_usd)| ServiceCost { service, cost_usd })
                .collect(),
            timeline: timeline_rows
                .into_iter()
                .map(|(ts, total, blocked)| TimelinePoint {
                    ts,
                    total: total.unsigned_abs(),
                    blocked: blocked.unsigned_abs(),
                })
                .collect(),
        })
    }

    async fn cleanup_old_events(&self, retention_days: u32) -> Result<u64, RevocError> {
        let cutoff = (Utc::now() - chrono::Duration::days(i64::from(retention_days))).to_rfc3339();
        let res = sqlx::query("DELETE FROM audit_events WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected())
    }
}

#[async_trait]
impl KillSwitchLogWriter for PostgresAuditStore {
    async fn log(
        &self,
        scope: &str,
        scope_value: Option<&str>,
        action: &str,
        activated_by: &str,
        reason: Option<&str>,
    ) -> Result<(), RevocError> {
        sqlx::query(
            "INSERT INTO kill_switch_log
             (id, scope, scope_value, action, activated_by, reason, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(scope)
        .bind(scope_value)
        .bind(action)
        .bind(activated_by)
        .bind(reason)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(db_err)
    }
}
