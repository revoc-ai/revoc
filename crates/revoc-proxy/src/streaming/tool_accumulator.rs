//! Tool call accumulator for streaming responses (SPEC.md §12).
//!
//! Collects `function.name` and `function.arguments` across SSE chunks.
//! When `finish_reason == "tool_calls"` the accumulated calls are submitted
//! to MCP governance. If blocked, a synthetic `content_filter` chunk is injected.

use std::collections::HashMap;

use revoc_core::McpToolCall;

/// Partial tool call being assembled from streaming chunks.
#[derive(Debug, Default, Clone)]
pub struct PartialToolCall {
    /// Tool / function name (accumulated across chunks).
    pub name: String,
    /// Raw JSON arguments string (accumulated across chunks).
    pub arguments: String,
}

/// Accumulates streaming tool call deltas across SSE chunks.
#[derive(Debug, Default)]
pub struct ToolCallAccumulator {
    calls: HashMap<u32, PartialToolCall>,
}

impl ToolCallAccumulator {
    /// Process a parsed SSE event JSON value.
    ///
    /// Extracts `tool_calls[].function.name` and `tool_calls[].function.arguments`
    /// from the first choice's delta and accumulates them by index.
    pub fn process_chunk(&mut self, event_json: &serde_json::Value) {
        let Some(delta) = event_json
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("delta"))
        else {
            return;
        };

        let Some(tool_calls) = delta.get("tool_calls").and_then(|t| t.as_array()) else {
            return;
        };

        for tc in tool_calls {
            let index = u32::try_from(
                tc.get("index")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            )
            .unwrap_or(0);
            let entry = self.calls.entry(index).or_default();

            if let Some(func) = tc.get("function") {
                if let Some(name) = func.get("name").and_then(|n| n.as_str()) {
                    entry.name.push_str(name);
                }
                if let Some(args) = func.get("arguments").and_then(|a| a.as_str()) {
                    entry.arguments.push_str(args);
                }
            }
        }
    }

    /// Returns `true` when the streaming response contains `finish_reason == "tool_calls"`.
    pub fn is_finish_tool_calls(event_json: &serde_json::Value) -> bool {
        event_json
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("finish_reason"))
            .and_then(|r| r.as_str())
            .is_some_and(|r| r == "tool_calls")
    }

    /// Parse all accumulated partial calls into [`McpToolCall`] objects.
    pub fn get_completed_calls(&self) -> Vec<McpToolCall> {
        let mut entries: Vec<(u32, &PartialToolCall)> =
            self.calls.iter().map(|(k, v)| (*k, v)).collect();
        entries.sort_by_key(|(idx, _)| *idx);

        entries
            .into_iter()
            .map(|(idx, partial)| {
                let arguments = serde_json::from_str(&partial.arguments)
                    .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                McpToolCall {
                    tool_name: partial.name.clone(),
                    arguments,
                    server_id: None,
                    call_id: Some(idx.to_string()),
                }
            })
            .collect()
    }

    /// Generate a synthetic SSE chunk that signals `finish_reason = "content_filter"`.
    ///
    /// Injected in the stream when a tool call is blocked by governance so the
    /// AI client receives a clean signal that the call was filtered.
    pub fn synthetic_content_filter_chunk() -> String {
        serde_json::json!({
            "id": format!("chatcmpl-revoc-{}", uuid::Uuid::now_v7()),
            "object": "chat.completion.chunk",
            "created": chrono::Utc::now().timestamp(),
            "model": "revoc-governance",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "content_filter"
            }]
        })
        .to_string()
    }
}
