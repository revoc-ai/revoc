//! SSE (Server-Sent Events) parsing and formatting utilities.

use bytes::Bytes;

/// A single parsed SSE event.
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// Optional event type (`event:` field).
    #[allow(dead_code)]
    pub event_type: Option<String>,
    /// Data payload (`data:` field).
    pub data: String,
}

/// Parse raw SSE bytes into individual events.
///
/// An event is delimited by a blank line (`\n\n` or `\r\n\r\n`).
pub fn parse_sse_chunk(bytes: &[u8]) -> Vec<SseEvent> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return vec![];
    };

    let mut events = Vec::new();
    for block in text.split("\n\n") {
        let block = block.trim();
        if block.is_empty() || block == "[DONE]" {
            continue;
        }

        let mut event_type: Option<String> = None;
        let mut data_lines: Vec<&str> = Vec::new();

        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event_type = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim());
            }
        }

        if !data_lines.is_empty() {
            events.push(SseEvent {
                event_type,
                data: data_lines.join("\n"),
            });
        }
    }

    events
}

#[allow(dead_code)]
/// Extract the delta text from an OpenAI-format SSE event data string.
///
/// Returns `None` for `[DONE]` events, events with no choices, or parse errors.
pub fn extract_delta_text(event_data: &str) -> Option<String> {
    if event_data.trim() == "[DONE]" {
        return None;
    }

    let v: serde_json::Value = serde_json::from_str(event_data).ok()?;
    v.get("choices")?
        .get(0)?
        .get("delta")?
        .get("content")?
        .as_str()
        .map(str::to_owned)
}

/// Format a string as an SSE data line.
pub fn format_sse_event(data: &str) -> Bytes {
    Bytes::from(format!("data: {data}\n\n"))
}

/// The SSE termination sentinel.
pub const SSE_DONE: &[u8] = b"data: [DONE]\n\n";
