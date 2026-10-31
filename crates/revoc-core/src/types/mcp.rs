//! MCP (Model Context Protocol) wire types.
//!
//! Covers the JSON-RPC request/response envelope, tool call arguments,
//! the blocked-call response ([`McpBlockResponse`]), and tool manifest
//! findings produced by D10 manifest analysis.

use serde::{Deserialize, Serialize};

use super::finding::Severity;

// ── McpMethod ─────────────────────────────────────────────────────────────────

/// Recognised MCP JSON-RPC method names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpMethod {
    /// MCP session initialisation handshake.
    Initialize,
    /// Keepalive ping.
    Ping,
    /// List available tools.
    ToolsList,
    /// Invoke a tool.
    ToolsCall,
    /// List available resources.
    ResourcesList,
    /// Read a resource by URI.
    ResourcesRead,
    /// Subscribe to resource change notifications.
    ResourcesSubscribe,
    /// Retrieve a named prompt template.
    PromptsGet,
    /// List available prompt templates.
    PromptsList,
    /// Request the LLM to generate a completion (MCP sampling).
    SamplingCreateMessage,
    /// Configure the server's logging level.
    LoggingSetLevel,
    /// Auto-complete a partial input.
    Completion,
}

impl McpMethod {
    /// Returns `true` if this method requires full governance inspection of
    /// its request body before being forwarded to the MCP server.
    pub fn requires_governance(&self) -> bool {
        matches!(
            self,
            Self::ToolsCall | Self::ResourcesRead | Self::SamplingCreateMessage
        )
    }

    /// Returns `true` if the **response** to this method must also be inspected
    /// (bidirectional governance — SPEC.md Principle 4).
    pub fn response_requires_inspection(&self) -> bool {
        matches!(self, Self::ToolsCall | Self::ResourcesRead)
    }
}

// ── McpToolCall ───────────────────────────────────────────────────────────────

/// Parsed arguments from a `tools/call` JSON-RPC request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// Arguments object passed to the tool.
    pub arguments: serde_json::Value,
    /// MCP server identifier this call targets.
    pub server_id: Option<String>,
    /// JSON-RPC call identifier for correlation with the response.
    pub call_id: Option<String>,
}

// ── McpRawRequest ─────────────────────────────────────────────────────────────

/// Raw JSON-RPC 2.0 request envelope received from an MCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRawRequest {
    /// JSON-RPC version — always `"2.0"`.
    pub jsonrpc: String,
    /// Request identifier (string, number, or null).
    pub id: serde_json::Value,
    /// Method name (e.g. `"tools/call"`).
    pub method: String,
    /// Method parameters, if any.
    pub params: Option<serde_json::Value>,
}

// ── McpBlockResponse ──────────────────────────────────────────────────────────

/// JSON-RPC 2.0 error response returned to the AI client when a tool call is
/// blocked by governance (SPEC.md §7.4, §11 MCP Step 9).
///
/// **Important**: the upstream MCP tool server **never** receives a blocked
/// request. This response is synthesised entirely within the proxy.
///
/// The `dashboard_url` is embedded inside `error.data` so AI clients can
/// surface a human-readable link to the governance trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBlockResponse {
    /// JSON-RPC version — always `"2.0"`.
    pub jsonrpc: String,
    /// Echoed from the original request.
    pub id: serde_json::Value,
    /// The JSON-RPC error object.
    pub error: McpBlockError,
}

/// JSON-RPC error object within [`McpBlockResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBlockError {
    /// JSON-RPC error code. REVOC uses `-32603` (Internal Error) for blocks.
    pub code: i32,
    /// Human-readable reason for the block.
    pub message: String,
    /// Structured block metadata including the dashboard link.
    pub data: McpBlockData,
}

/// Structured data payload within the JSON-RPC error, carrying governance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBlockData {
    /// Machine-readable block code — always `"REVOC_GOVERNANCE_BLOCK"`.
    pub code: String,
    /// IDs of the rules that triggered the block.
    pub rules: Vec<String>,
    /// UUID v7 trace identifier for correlation with the audit log.
    pub trace_id: String,
    /// Direct link to the governance trace in the REVOC dashboard.
    pub dashboard_url: String,
}

impl McpBlockResponse {
    /// Construct a governance-block JSON-RPC error response.
    ///
    /// `dashboard_url` goes into `error.data` so the AI client can surface it.
    pub fn new(
        id: serde_json::Value,
        trace_id: &str,
        rules: Vec<String>,
        reason: &str,
        dashboard_url: &str,
    ) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            error: McpBlockError {
                code: -32603,
                message: reason.to_string(),
                data: McpBlockData {
                    code: "REVOC_GOVERNANCE_BLOCK".into(),
                    rules,
                    trace_id: trace_id.to_string(),
                    dashboard_url: dashboard_url.to_string(),
                },
            },
        }
    }
}

// ── ToolManifestFinding ───────────────────────────────────────────────────────

/// A single risk finding produced by D10 tool manifest analysis
/// (SPEC.md §9 D10, `manifest_analyzer.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifestFinding {
    /// Name of the tool containing the risky parameter or description.
    pub tool_name: String,
    /// Name of the parameter (or `"description"` for description-level risks).
    pub parameter_name: String,
    /// The keyword or pattern that triggered the finding.
    pub matched_keyword: String,
    /// Severity of the finding.
    pub severity: Severity,
}
