//! SSE live governance event feed.

use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::warn;

/// A governance event published to the live SSE feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvent {
    /// Trace ID linking to X-Revoc-Dashboard.
    pub trace_id: String,
    /// ISO 8601 wall-clock timestamp.
    pub timestamp: String,
    /// Effective decision: allow/redact/block/audit.
    pub decision: String,
    /// First rule that caused a block, if any.
    pub blocked_by: Option<String>,
    /// Caller identifier.
    pub caller_id: String,
    /// LLM model, if known.
    pub model: Option<String>,
    /// Total proxy duration in milliseconds.
    pub duration_ms: f64,
    /// Number of findings produced by the detection engine.
    pub findings_count: usize,
    /// PII entity types seen (e.g. `["EMAIL_ADDRESS", "US_SSN"]`).
    pub pii_types: Vec<String>,
    /// MCP tool name, if this was an MCP call.
    pub mcp_tool: Option<String>,
    /// Request type (`LlmRequest`, `McpToolCall`, etc.).
    pub request_type: String,
    /// Governance nesting depth of this request.
    pub governance_depth: u8,
    /// Whether Unicode normalization changed the input (evasion indicator).
    pub was_normalized: bool,
    /// Number of tool manifest findings.
    pub manifest_warnings: u32,
}

// ── LiveFeedBus ───────────────────────────────────────────────────────────────

/// Broadcast bus for the SSE live feed.
///
/// Clone this and pass it to every handler that produces governance events.
/// Dashboard SSE connections subscribe to the broadcast channel.
#[derive(Clone)]
pub struct LiveFeedBus {
    sender: broadcast::Sender<GovernanceEvent>,
}

impl LiveFeedBus {
    /// Create a new bus with the given broadcast channel capacity.
    /// `capacity = 1024` is the recommended default.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish a governance event to all active SSE subscribers.
    ///
    /// Silently drops the event if there are no active receivers or the
    /// channel is full — never blocks.
    pub fn publish(&self, event: GovernanceEvent) {
        // try_send / send errors mean no receivers — safe to ignore
        let _ = self.sender.send(event);
    }

    /// Build an SSE response stream for a new dashboard connection.
    ///
    /// Sends a 15-second keep-alive ping to prevent proxy timeouts.
    pub fn sse_handler(&self) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
        let rx = self.sender.subscribe();

        let stream = stream::unfold(rx, |mut receiver| async move {
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        let data = serde_json::to_string(&event).unwrap_or_default();
                        return Some((Ok(Event::default().data(data)), receiver));
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "SSE subscriber lagged — skipping events");
                        // continue — try to receive the next available event
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Sender dropped — close the stream
                        return None;
                    }
                }
            }
        });

        Sse::new(stream).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        )
    }
}
