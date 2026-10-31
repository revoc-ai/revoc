//! OpenAI-compatible wire types and REVOC error response envelopes.
//!
//! [`RevocErrorResponse`] is **only** used for errors that REVOC itself
//! originates. Upstream 4xx/5xx responses are **always** forwarded verbatim
//! and must never be wrapped in this type (SPEC.md §17, §23 Rule 8).

use serde::{Deserialize, Serialize};

// ── OpenAI request / response types ──────────────────────────────────────────

/// Inbound OpenAI-compatible chat completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    /// Model identifier (e.g. `"gpt-4o"`, `"claude-3-5-sonnet-20241022"`).
    pub model: String,
    /// Conversation messages.
    pub messages: Vec<serde_json::Value>,
    /// Whether to stream the response as SSE chunks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Maximum tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Tool definitions available to the model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<serde_json::Value>>,
    /// Tool selection mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
}

/// Outbound OpenAI-compatible chat completion response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    /// Unique completion identifier.
    pub id: String,
    /// Object type — always `"chat.completion"`.
    pub object: String,
    /// Unix timestamp of when the completion was created.
    pub created: i64,
    /// Model that produced the completion.
    pub model: String,
    /// One or more completion choices.
    pub choices: Vec<Choice>,
    /// Token usage statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageStats>,
}

/// A single completion choice within [`ChatCompletionResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Zero-based choice index.
    pub index: u32,
    /// Full message for non-streaming responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<serde_json::Value>,
    /// Incremental delta for streaming responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<serde_json::Value>,
    /// Reason the generation stopped (`"stop"`, `"tool_calls"`, `"length"`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

/// Token usage reported by the upstream provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageStats {
    /// Prompt (input) token count.
    pub prompt_tokens: u64,
    /// Completion (output) token count.
    pub completion_tokens: u64,
    /// Total token count.
    pub total_tokens: u64,
}

// ── RevocErrorResponse ────────────────────────────────────────────────────────

/// Top-level error envelope returned by REVOC for proxy-originated errors.
///
/// Follows the `OpenAI` error response shape so clients that already handle
/// `OpenAI` errors degrade gracefully.
///
/// **Never** wrap an upstream 4xx/5xx in this type — those must be forwarded
/// verbatim (SPEC.md §17, §23 Rule 8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocErrorResponse {
    /// The structured error detail.
    pub error: RevocErrorDetail,
}

/// Detail object within [`RevocErrorResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocErrorDetail {
    /// Machine-readable error code (e.g. `"REVOC_GOVERNANCE_BLOCK"`).
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Error category (e.g. `"governance_error"`, `"emergency_stop"`).
    pub r#type: String,
    /// The first rule ID that caused a block, if applicable.
    pub blocked_by: Option<String>,
    /// All rule IDs that contributed to a block.
    pub rules: Option<Vec<String>>,
    /// UUID v7 trace identifier for correlation with the dashboard.
    pub trace_id: String,
    /// Direct link to the governance trace in the REVOC dashboard.
    pub dashboard_url: String,
    /// Link to the relevant documentation page.
    pub documentation_url: Option<String>,
}

impl RevocErrorResponse {
    /// Governance block — one or more policy rules rejected this request.
    pub fn governance_block(
        trace_id: &str,
        reason: &str,
        rules: Vec<String>,
        dash_base: &str,
    ) -> Self {
        let first = rules.first().cloned();
        let doc = first
            .as_ref()
            .map(|r| format!("https://revoc.io/docs/policies/{r}"));
        Self {
            error: RevocErrorDetail {
                code: "REVOC_GOVERNANCE_BLOCK".into(),
                message: reason.to_string(),
                r#type: "governance_error".into(),
                blocked_by: first,
                rules: Some(rules),
                trace_id: trace_id.to_string(),
                dashboard_url: format!("{dash_base}/traces/{trace_id}"),
                documentation_url: doc,
            },
        }
    }

    /// Emergency kill-switch is active — all AI traffic is suspended.
    pub fn kill_switch_active(trace_id: &str, dash_base: &str) -> Self {
        Self {
            error: RevocErrorDetail {
                code: "REVOC_KILL_SWITCH_ACTIVE".into(),
                message: "All AI traffic suspended by emergency stop. \
                          Contact your AI platform team."
                    .into(),
                r#type: "emergency_stop".into(),
                blocked_by: None,
                rules: None,
                trace_id: trace_id.to_string(),
                dashboard_url: format!("{dash_base}/emergency"),
                documentation_url: Some(
                    "https://revoc.io/docs/operations/emergency-kill-switch".into(),
                ),
            },
        }
    }

    /// Governance depth limit reached — possible infinite agent loop detected.
    pub fn depth_exceeded(trace_id: &str, depth: u8, dash_base: &str) -> Self {
        Self {
            error: RevocErrorDetail {
                code: "REVOC_GOVERNANCE_DEPTH_EXCEEDED".into(),
                message: format!(
                    "Governance depth limit ({depth}/10) reached. \
                     Possible infinite agent loop."
                ),
                r#type: "depth_exceeded".into(),
                blocked_by: None,
                rules: None,
                trace_id: trace_id.to_string(),
                dashboard_url: format!("{dash_base}/traces/{trace_id}"),
                documentation_url: Some("https://revoc.io/docs/concepts/governance-depth".into()),
            },
        }
    }

    /// Per-caller rate limit exceeded.
    pub fn rate_limit(trace_id: &str, retry_after: u64, dash_base: &str) -> Self {
        Self {
            error: RevocErrorDetail {
                code: "REVOC_RATE_LIMIT_EXCEEDED".into(),
                message: format!("Rate limit exceeded. Retry after {retry_after} seconds."),
                r#type: "rate_limit_error".into(),
                blocked_by: None,
                rules: None,
                trace_id: trace_id.to_string(),
                dashboard_url: format!("{dash_base}/traces/{trace_id}"),
                documentation_url: None,
            },
        }
    }

    /// Unexpected internal error — the request may be retried.
    pub fn internal_error(trace_id: &str, dash_base: &str) -> Self {
        Self {
            error: RevocErrorDetail {
                code: "REVOC_INTERNAL_ERROR".into(),
                message: "An internal error occurred. Please retry.".into(),
                r#type: "internal_error".into(),
                blocked_by: None,
                rules: None,
                trace_id: trace_id.to_string(),
                dashboard_url: format!("{dash_base}/traces/{trace_id}"),
                documentation_url: None,
            },
        }
    }

    /// Request body could not be parsed as valid JSON (HTTP 400).
    pub fn request_parse_error(trace_id: &str, reason: &str, dash_base: &str) -> Self {
        Self {
            error: RevocErrorDetail {
                code: "REVOC_REQUEST_PARSE_ERROR".into(),
                message: format!("Request body is not valid JSON: {reason}"),
                r#type: "invalid_request_error".into(),
                blocked_by: None,
                rules: None,
                trace_id: trace_id.to_string(),
                dashboard_url: format!("{dash_base}/traces/{trace_id}"),
                documentation_url: None,
            },
        }
    }
}
