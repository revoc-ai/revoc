//! Sliding window scanner for streaming governance (SPEC.md §12).

use std::collections::VecDeque;
use std::sync::Arc;

use revoc_core::traits::InspectionInput;
use revoc_core::{CallerContext, ChatMessage, Finding, RequestType};
use revoc_detector::DetectionEngine;

/// Result of processing a single SSE delta through the sliding window.
#[derive(Debug)]
pub struct ChunkResult {
    /// Bytes safe to forward to the client immediately.
    pub bytes_to_forward: bytes::Bytes,
    /// If `Some`, governance triggered a block — stop the stream.
    pub block_reason: Option<String>,
    /// Findings that triggered the block (or were otherwise notable).
    pub redacted_findings: Vec<Finding>,
}

/// Sliding window scanner for streaming LLM responses.
///
/// Maintains a rolling buffer of recent output to detect patterns that may
/// span multiple SSE chunks (e.g. a SSN split across two `delta.content` values).
pub struct SlidingWindowScanner {
    window: VecDeque<u8>,
    window_size: usize,
    detector: Arc<DetectionEngine>,
}

impl SlidingWindowScanner {
    /// Create a new scanner with the given window size and detection engine.
    pub fn new(window_size: usize, detector: Arc<DetectionEngine>) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size,
            detector,
        }
    }

    /// Process a new delta text chunk.
    ///
    /// Appends `delta` to the window, trims to `window_size`, runs the
    /// detection engine over the accumulated window content (so patterns
    /// spanning multiple chunks are still caught), and returns the bytes
    /// safe to forward plus any block decision.
    ///
    /// High/Critical severity findings (secrets, prompt injection, DDL
    /// mutation, SSRF, path traversal, system-prompt extraction, etc.)
    /// halt the stream immediately — SPEC.md §12 requires governance to
    /// run on streamed output, not just buffered responses.
    pub async fn process_chunk(
        &mut self,
        delta: &[u8],
        caller: &CallerContext,
        governance_depth: u8,
    ) -> ChunkResult {
        for &b in delta {
            self.window.push_back(b);
        }
        while self.window.len() > self.window_size {
            self.window.pop_front();
        }

        let window_bytes: Vec<u8> = self.window.iter().copied().collect();
        let window_text = String::from_utf8_lossy(&window_bytes).into_owned();

        let input = InspectionInput {
            request_id: uuid::Uuid::now_v7().to_string(),
            request_type: RequestType::LlmResponse,
            raw_body: bytes::Bytes::from(window_bytes),
            parsed_messages: Some(vec![ChatMessage {
                role: "assistant".to_owned(),
                content: serde_json::Value::String(window_text),
                name: None,
                tool_call_id: None,
                tool_calls: None,
            }]),
            mcp_call: None,
            caller: caller.clone(),
            governance_depth,
        };

        let findings = match self.detector.detect_default_timeout(&input).await {
            Ok(f) => f,
            Err(e) => {
                // Fail closed: an unscanned window is never forwarded.
                return ChunkResult {
                    bytes_to_forward: bytes::Bytes::new(),
                    block_reason: Some(format!("Stream governance unavailable: {e}")),
                    redacted_findings: Vec::new(),
                };
            }
        };
        let blocking: Vec<Finding> = findings
            .into_iter()
            .filter(Finding::is_high_severity)
            .collect();

        if let Some(first) = blocking.first() {
            return ChunkResult {
                bytes_to_forward: bytes::Bytes::new(),
                block_reason: Some(format!(
                    "{:?} detected in streamed output (severity={:?})",
                    first.finding_type, first.severity
                )),
                redacted_findings: blocking,
            };
        }

        ChunkResult {
            bytes_to_forward: bytes::Bytes::copy_from_slice(delta),
            block_reason: None,
            redacted_findings: vec![],
        }
    }

    /// Drain any remaining bytes from the window (call at end of stream).
    #[allow(dead_code)]
    pub fn drain(&mut self) -> bytes::Bytes {
        let v: Vec<u8> = self.window.drain(..).collect();
        bytes::Bytes::from(v)
    }
}
