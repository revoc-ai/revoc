//! Durable backends for the signed kill-switch document.
//!
//! A store holds one value: the signed document as JSON
//! (`{"doc": "<KillSwitchDoc JSON>", "sig": "<hex HMAC>"}`). Writes are
//! compare-and-swap on the document version so two instances changing the
//! switch at once cannot overwrite each other.

use async_trait::async_trait;

use revoc_core::RevocError;

/// A durable home for the kill-switch document.
#[async_trait]
pub trait KillSwitchStore: Send + Sync {
    /// Short name reported on `/ready` (`"redis"` / `"sqlite"`).
    fn kind(&self) -> &'static str;

    /// Read the stored signed document, `None` if nothing was ever written.
    async fn load(&self) -> Result<Option<String>, RevocError>;

    /// Write `signed` (version `new_version`) only if the stored version is
    /// still `expected`. Returns `false` on a version conflict.
    async fn compare_and_swap(
        &self,
        expected: u64,
        new_version: u64,
        signed: &str,
    ) -> Result<bool, RevocError>;
}

// ── Redis ─────────────────────────────────────────────────────────────────────

/// Compare-and-swap plus publish in one atomic script: the stored version is
/// read from the signed document itself, so there is a single source of truth.
const CAS_SCRIPT: &str = r"
local cur = redis.call('GET', KEYS[1])
local v = 0
if cur then
  v = tonumber(cjson.decode(cjson.decode(cur).doc).version)
end
if v ~= tonumber(ARGV[1]) then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PUBLISH', KEYS[2], ARGV[2])
return 1
";

/// Shared state in Redis; every instance reads and writes the same key and
/// is notified of changes on the pub/sub channel. Connects lazily, so an
/// unreachable server at startup is a store error (handled by
/// `on_redis_unavailable`), not a crash.
pub struct RedisKillSwitchStore {
    client: redis::Client,
    conn: tokio::sync::Mutex<Option<redis::aio::ConnectionManager>>,
    state_key: String,
    channel: String,
}

impl RedisKillSwitchStore {
    /// The document lives at `<channel>:state`; changes are published on
    /// `channel`.
    ///
    /// # Errors
    /// [`RevocError::Configuration`] for a malformed URL.
    pub fn new(url: &str, channel: &str) -> Result<Self, RevocError> {
        let client = redis::Client::open(url)
            .map_err(|e| RevocError::Configuration(format!("kill-switch Redis URL: {e}")))?;
        Ok(Self {
            client,
            conn: tokio::sync::Mutex::new(None),
            state_key: format!("{channel}:state"),
            channel: channel.to_owned(),
        })
    }

    async fn conn(&self) -> Result<redis::aio::ConnectionManager, RevocError> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let c = redis::aio::ConnectionManager::new(self.client.clone())
            .await
            .map_err(|e| RevocError::Database(format!("kill-switch Redis connect: {e}")))?;
        *guard = Some(c.clone());
        Ok(c)
    }
}

#[async_trait]
impl KillSwitchStore for RedisKillSwitchStore {
    fn kind(&self) -> &'static str {
        "redis"
    }

    async fn load(&self) -> Result<Option<String>, RevocError> {
        let mut conn = self.conn().await?;
        redis::cmd("GET")
            .arg(&self.state_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| RevocError::Database(format!("kill-switch Redis GET: {e}")))
    }

    async fn compare_and_swap(
        &self,
        expected: u64,
        _new_version: u64,
        signed: &str,
    ) -> Result<bool, RevocError> {
        let mut conn = self.conn().await?;
        let applied: i64 = redis::Script::new(CAS_SCRIPT)
            .key(&self.state_key)
            .key(&self.channel)
            .arg(expected)
            .arg(signed)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| RevocError::Database(format!("kill-switch Redis CAS: {e}")))?;
        Ok(applied == 1)
    }
}

// ── SQLite ────────────────────────────────────────────────────────────────────

/// Single-instance durable state in the proxy's local database.
pub struct SqliteKillSwitchStore {
    pool: sqlx::SqlitePool,
}

impl SqliteKillSwitchStore {
    /// Use `pool`; the `kill_switch_state` table comes from `sql/schema.sql`.
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KillSwitchStore for SqliteKillSwitchStore {
    fn kind(&self) -> &'static str {
        "sqlite"
    }

    async fn load(&self) -> Result<Option<String>, RevocError> {
        sqlx::query_scalar::<_, String>("SELECT signed FROM kill_switch_state WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RevocError::Database(e.to_string()))
    }

    async fn compare_and_swap(
        &self,
        expected: u64,
        new_version: u64,
        signed: &str,
    ) -> Result<bool, RevocError> {
        let to_i64 = |v: u64| {
            i64::try_from(v)
                .map_err(|_| RevocError::Database("kill-switch version overflow".into()))
        };
        let result = if expected == 0 {
            sqlx::query(
                "INSERT INTO kill_switch_state (id, version, signed) VALUES (1, ?, ?)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(to_i64(new_version)?)
            .bind(signed)
            .execute(&self.pool)
            .await
        } else {
            sqlx::query(
                "UPDATE kill_switch_state SET version = ?, signed = ? WHERE id = 1 AND version = ?",
            )
            .bind(to_i64(new_version)?)
            .bind(signed)
            .bind(to_i64(expected)?)
            .execute(&self.pool)
            .await
        };
        result
            .map(|r| r.rows_affected() == 1)
            .map_err(|e| RevocError::Database(e.to_string()))
    }
}
