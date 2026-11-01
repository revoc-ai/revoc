//! Session state shared across instances (SPEC.md §11) and the recorder
//! that folds each governed LLM or MCP exchange into it.
//!
//! The session id is `<org_id>:<caller_id>` for both LLM and MCP traffic, so
//! the `session_data_exfil_v1` heuristic sees rows read through one tool and
//! an external send through another as the same session.

use async_trait::async_trait;
use redis::AsyncCommands;

use revoc_core::{CallerContext, Finding, RevocError, SessionState};

use crate::app::{AppState, SessionStore};

/// Upper bound on `tools_called` kept per session; older entries are
/// dropped so a long-lived session cannot grow without limit.
pub const MAX_TOOLS_TRACKED: usize = 256;

/// Session id shared by the LLM and MCP handlers.
pub fn session_id(caller: &CallerContext) -> String {
    format!("{}:{}", caller.org_id, caller.caller_id)
}

/// One governed exchange to fold into a session.
#[derive(Debug, Default)]
pub struct SessionActivity<'a> {
    /// Tool invoked, for MCP `tools/call`.
    pub tool: Option<&'a str>,
    /// Rows returned by a tool result.
    pub rows_read: u64,
    /// The exchange sent data out of the governed boundary.
    pub external_send: bool,
}

/// Fold `findings` and `activity` into the caller's session, creating it on
/// first contact. Only PII entity *types* are recorded, never values.
pub fn record(
    existing: Option<SessionState>,
    caller: &CallerContext,
    findings: &[Finding],
    activity: &SessionActivity<'_>,
) -> SessionState {
    let now = chrono::Utc::now();
    let mut session = existing.unwrap_or_else(|| SessionState {
        session_id: session_id(caller),
        org_id: caller.org_id.clone(),
        caller_id: caller.caller_id.clone(),
        tools_called: Vec::new(),
        total_rows_read: 0,
        pii_entities_seen: std::collections::HashSet::new(),
        external_send_attempted: false,
        started_at: now,
        last_active: now,
    });
    for finding in findings {
        if let Some(entity) = &finding.pii_entity {
            session.pii_entities_seen.insert(entity.to_string());
        }
    }
    if let Some(tool) = activity.tool {
        session.tools_called.push((tool.to_owned(), now));
        if session.tools_called.len() > MAX_TOOLS_TRACKED {
            let excess = session.tools_called.len() - MAX_TOOLS_TRACKED;
            session.tools_called.drain(..excess);
        }
    }
    session.total_rows_read = session.total_rows_read.saturating_add(activity.rows_read);
    if activity.external_send {
        session.external_send_attempted = true;
    }
    session.last_active = now;
    session
}

/// Tool names that move data out of the governed boundary (HTTP, mail,
/// chat, upload). Matched case-insensitively as substrings of the name.
const EXTERNAL_SEND_MARKERS: &[&str] = &[
    "http", "fetch", "request", "post", "send", "email", "mail", "upload", "webhook", "slack",
    "publish", "notify", "sms", "tweet",
];

/// Whether calling `tool` counts as an external send for the session.
pub fn is_external_send_tool(tool: &str) -> bool {
    let t = tool.to_ascii_lowercase();
    EXTERNAL_SEND_MARKERS.iter().any(|m| t.contains(m))
}

/// Persist `session` without blocking the request; failures are logged.
pub fn spawn_persist(state: &AppState, session: SessionState) {
    if !state.config.session.enabled {
        return;
    }
    let store = state.session_store.clone();
    let ttl = state.config.session.ttl_secs;
    tokio::spawn(async move {
        let sid = session.session_id.clone();
        if let Err(e) = store.set(&sid, session, ttl).await {
            tracing::warn!(error = %e, "Failed to persist session state");
        }
    });
}

/// Load the caller's session when session tracking is enabled.
pub async fn load(state: &AppState, caller: &CallerContext) -> Option<SessionState> {
    if !state.config.session.enabled {
        return None;
    }
    state.session_store.get(&session_id(caller)).await
}

/// Rows in an MCP tool result: the length of the largest array among
/// `structuredContent` (or a top-level `rows`/`data`/`results` array), or
/// the number of content items when no array is present.
pub fn rows_in_tool_result(result: &serde_json::Value) -> u64 {
    fn largest_array(v: &serde_json::Value, depth: u8) -> usize {
        match v {
            serde_json::Value::Array(a) => a.len(),
            serde_json::Value::Object(o) if depth > 0 => o
                .values()
                .map(|x| largest_array(x, depth - 1))
                .max()
                .unwrap_or(0),
            _ => 0,
        }
    }
    let structured = result
        .get("structuredContent")
        .map_or(0, |s| largest_array(s, 2));
    let top = ["rows", "data", "results"]
        .iter()
        .filter_map(|k| result.get(*k))
        .map(|v| largest_array(v, 0))
        .max()
        .unwrap_or(0);
    let rows = structured.max(top);
    let rows = if rows == 0 {
        result
            .get("content")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len)
    } else {
        rows
    };
    u64::try_from(rows).unwrap_or(u64::MAX)
}

/// Sessions in Redis under `revoc:session:<id>` as JSON with a TTL, so every
/// instance sees the same session. Connects lazily; while Redis is
/// unreachable reads return no session and writes fail (the caller logs).
pub struct RedisSessionStore {
    client: redis::Client,
    conn: tokio::sync::Mutex<Option<redis::aio::ConnectionManager>>,
}

impl RedisSessionStore {
    /// # Errors
    /// [`RevocError::Configuration`] for a malformed URL.
    pub fn new(url: &str) -> Result<Self, RevocError> {
        let client = redis::Client::open(url)
            .map_err(|e| RevocError::Configuration(format!("session Redis URL: {e}")))?;
        Ok(Self {
            client,
            conn: tokio::sync::Mutex::new(None),
        })
    }

    fn key(session_id: &str) -> String {
        format!("revoc:session:{session_id}")
    }

    async fn conn(&self) -> Result<redis::aio::ConnectionManager, RevocError> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let c = redis::aio::ConnectionManager::new(self.client.clone())
            .await
            .map_err(|e| RevocError::Database(format!("session Redis connect: {e}")))?;
        *guard = Some(c.clone());
        Ok(c)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn get(&self, session_id: &str) -> Option<SessionState> {
        let mut conn = match self.conn().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "session store unavailable");
                return None;
            }
        };
        let raw: Option<String> = match conn.get(Self::key(session_id)).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "session read failed");
                return None;
            }
        };
        raw.and_then(|s| serde_json::from_str(&s).ok())
    }

    async fn set(
        &self,
        session_id: &str,
        state: SessionState,
        ttl_secs: u64,
    ) -> Result<(), RevocError> {
        let json = serde_json::to_string(&state)?;
        let mut conn = self.conn().await?;
        conn.set_ex::<_, _, ()>(Self::key(session_id), json, ttl_secs.max(1))
            .await
            .map_err(|e| RevocError::Database(format!("session write: {e}")))
    }

    async fn delete(&self, session_id: &str) -> Result<(), RevocError> {
        let mut conn = self.conn().await?;
        conn.del::<_, ()>(Self::key(session_id))
            .await
            .map_err(|e| RevocError::Database(format!("session delete: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> CallerContext {
        CallerContext {
            org_id: "acme".into(),
            caller_id: "agent-1".into(),
            ..Default::default()
        }
    }

    #[test]
    fn record_accumulates_rows_tools_and_sends() {
        let a = record(
            None,
            &caller(),
            &[],
            &SessionActivity {
                tool: Some("db.query"),
                rows_read: 400,
                external_send: false,
            },
        );
        let b = record(
            Some(a),
            &caller(),
            &[],
            &SessionActivity {
                tool: Some("http.post"),
                rows_read: 200,
                external_send: true,
            },
        );
        assert_eq!(b.session_id, "acme:agent-1");
        assert_eq!(b.total_rows_read, 600);
        assert_eq!(b.tools_called.len(), 2);
        assert!(b.external_send_attempted);
    }

    #[test]
    fn tools_called_is_bounded() {
        let mut s = None;
        for _ in 0..(MAX_TOOLS_TRACKED + 10) {
            s = Some(record(
                s,
                &caller(),
                &[],
                &SessionActivity {
                    tool: Some("t"),
                    ..Default::default()
                },
            ));
        }
        assert_eq!(s.map(|s| s.tools_called.len()), Some(MAX_TOOLS_TRACKED));
    }

    #[test]
    fn send_tools_are_recognised() {
        assert!(is_external_send_tool("http_post"));
        assert!(is_external_send_tool("Slack.SendMessage"));
        assert!(!is_external_send_tool("db.query"));
    }

    #[test]
    fn rows_counted_from_structured_content() {
        let r = serde_json::json!({
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"rows": [1, 2, 3, 4]}
        });
        assert_eq!(rows_in_tool_result(&r), 4);
        let r = serde_json::json!({"content": [{"type": "text"}, {"type": "text"}]});
        assert_eq!(rows_in_tool_result(&r), 2);
    }
}
