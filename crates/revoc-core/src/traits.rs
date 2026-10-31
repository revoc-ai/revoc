//! Core async traits implemented by the upper crates in the dependency graph.
//!
//! - [`DetectionStage`] — one step of the detection pipeline (regex, ONNX, plugin…)
//! - [`PolicyEngine`] — evaluates findings against governance rules
//! - [`Redactor`] — mutates request/response bodies to remove matched entities

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::RevocError;
use crate::types::decision::{CallerContext, PolicyDecision, PolicyEngineMode, PolicyInput, RequestType};
use crate::types::finding::{DetectionTier, Finding};
use crate::types::mcp::McpToolCall;

// ── InspectionInput ───────────────────────────────────────────────────────────

/// Everything a [`DetectionStage`] needs to analyse a single request or response.
#[derive(Debug, Clone)]
pub struct InspectionInput {
    /// UUID v7 request identifier for correlation with audit events.
    pub request_id: String,
    /// Direction and protocol of this governance event.
    pub request_type: RequestType,
    /// Raw body bytes as received from the client or upstream.
    pub raw_body: Bytes,
    /// Pre-parsed conversation messages (populated for LLM events).
    pub parsed_messages: Option<Vec<crate::types::decision::ChatMessage>>,
    /// Pre-parsed MCP tool call (populated for MCP tool events).
    pub mcp_call: Option<McpToolCall>,
    /// Caller identity and governance metadata.
    pub caller: CallerContext,
    /// Current governance nesting depth (checked at Step 1 in every handler).
    pub governance_depth: u8,
}

impl InspectionInput {
    /// Returns `true` when this input represents an MCP tool call.
    pub fn is_mcp_call(&self) -> bool {
        self.mcp_call.is_some()
    }
}

// ── DetectionStage ────────────────────────────────────────────────────────────

/// A single detection stage in the governance pipeline.
///
/// Stages are executed in order (normalization → encoding → regex → ONNX →
/// HTTP plugin → deduplication) by `revoc-pipeline`. Each stage returns the
/// findings it discovered; the pipeline merges and deduplicates them.
///
/// Implementors must be `Send + Sync` and must **not** call external HTTP
/// services from the hot path in Tier 1 or Tier 2 mode (SPEC.md Principle 3).
#[async_trait]
pub trait DetectionStage: Send + Sync + std::fmt::Debug {
    /// Short descriptive name used in tracing spans and timing headers.
    fn name(&self) -> &'static str;

    /// Which detection tier this stage belongs to.
    fn tier(&self) -> DetectionTier;

    /// Analyse `input` and return all findings discovered by this stage.
    ///
    /// This method must:
    /// - Call `normalization::normalize()` before any regex match (D8).
    /// - Set `Finding::was_normalized` when the normalised text differed.
    /// - Set `Finding::was_encoded` when a finding was in decoded content.
    /// - Never log or store matched text values (SPEC.md §23 Rule 2).
    async fn detect(&self, input: &InspectionInput) -> Result<Vec<Finding>, RevocError>;
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

/// Evaluates detection findings against governance rules and produces a
/// [`PolicyDecision`].
///
/// Three backends implement this trait (SPEC.md §7.6, §13):
/// - `revoc_policy::native::NativePolicyEngine` — pure Rust, Tier 1/2 default
/// - `revoc_policy::sidecar::OpaSidecarEngine` — OPA HTTP, Tier 3
/// - `revoc_policy::wasm::OpaWasmEngine` — OPA WASM via wasmtime, Tier 3
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluate the policy for a single governance event.
    ///
    /// When `fail_open = false` (non-negotiable in production) and the engine
    /// is unreachable, this must return `Err(RevocError::PolicyEngineUnreachable)`.
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, RevocError>;

    /// Hot-reload the policy bundle without restarting the process.
    async fn reload(&self) -> Result<(), RevocError>;

    /// Returns which backend produced this engine instance.
    fn engine_type(&self) -> PolicyEngineMode;
}

// ── Redactor ──────────────────────────────────────────────────────────────────

/// Mutates request or response bodies to remove or mask entities flagged by
/// the detection pipeline.
///
/// Implementors must be `Send + Sync`. All three redaction strategies
/// (remove, mask, hash) are provided by `revoc-redaction`.
///
/// **Privacy**: implementations must only use `Finding::span` position data;
/// they must **never** log `TextSpan::value` (SPEC.md §23 Rule 2).
pub trait Redactor: Send + Sync {
    /// Apply redaction to an LLM request/response body.
    ///
    /// Returns the mutated body bytes and the updated findings (with
    /// `redaction_applied = true` set on each mutated span).
    ///
    /// # Errors
    /// Returns [`RevocError::Redaction`] if the body cannot be mutated.
    fn redact_body(
        &self,
        body: &[u8],
        findings: &[Finding],
        decision: &PolicyDecision,
    ) -> Result<(Vec<u8>, Vec<Finding>), RevocError>;

    /// Apply redaction to an MCP tool result JSON payload.
    ///
    /// Returns the mutated result bytes and the updated findings.
    ///
    /// # Errors
    /// Returns [`RevocError::Redaction`] if the body cannot be mutated.
    fn redact_mcp_result(
        &self,
        result_json: &[u8],
        findings: &[Finding],
        decision: &PolicyDecision,
    ) -> Result<(Vec<u8>, Vec<Finding>), RevocError>;
}
