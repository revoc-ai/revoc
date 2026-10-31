//! Policy decision types: [`Action`], [`PolicyDecision`], [`CallerContext`],
//! [`SessionState`], [`PolicyInput`], and supporting enums.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::finding::Severity;

// ── Action ────────────────────────────────────────────────────────────────────

/// The governance action the policy engine has decided to take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Pass the request through unmodified.
    Allow,
    /// Mutate the request/response body to remove or mask matched entities.
    Redact,
    /// Reject the request with an appropriate error response.
    Block,
    /// Allow the request but record a full audit event (shadow or explicit).
    Audit,
}

impl Action {
    /// Returns `true` if this action stops the request from reaching upstream.
    pub fn is_blocking(&self) -> bool {
        matches!(self, Action::Block)
    }

    /// Returns `true` if this action requires the body to be mutated.
    pub fn requires_redaction(&self) -> bool {
        matches!(self, Action::Redact)
    }
}

// ── EnforcementMode ───────────────────────────────────────────────────────────

/// Controls whether governance decisions are enforced or merely observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Decisions are applied: blocks reject traffic, redactions mutate bodies.
    #[default]
    Enforce,
    /// Decisions are observed only; `effective_action` is always [`Action::Audit`].
    Shadow,
}

// ── PolicyRuleTier ────────────────────────────────────────────────────────────

/// Precedence tier for conflict resolution. Higher tier always wins.
///
/// When multiple rules match a request, conflict resolution applies this
/// ordering: `Emergency > Security > Profile > Custom > Default`.
/// A [`Security`](PolicyRuleTier::Security)-tier [`Action::Block`] can never
/// be overridden by a Custom or Profile allow rule (SPEC.md §9 D12).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleTier {
    /// Baseline allow — the lowest-priority default.
    Default = 0,
    /// Operator-defined custom rules.
    Custom = 1,
    /// Compliance profile rules (HIPAA, PCI-DSS, GDPR, SOC2, etc.).
    Profile = 2,
    /// Built-in security rules — cannot be overridden by Custom or Profile.
    Security = 3,
    /// Emergency kill-switch — highest precedence, overrides everything.
    Emergency = 4,
}

// ── PolicyEngineMode ──────────────────────────────────────────────────────────

/// Which policy engine backend produced this decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEngineMode {
    /// Pure Rust native engine (Tier 1/2 default).
    Native,
    /// External OPA HTTP sidecar (Tier 3).
    OpaHttp,
    /// In-process OPA WASM bundle via wasmtime (Tier 3 alternative).
    OpaWasm,
}

// ── RequestType ───────────────────────────────────────────────────────────────

/// Which direction and protocol this governance event covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestType {
    /// Outbound LLM chat completion request.
    LlmRequest,
    /// Inbound LLM chat completion response.
    LlmResponse,
    /// MCP `tools/call` request.
    McpToolCall,
    /// MCP `tools/call` result (bidirectional governance).
    McpToolResult,
    /// MCP `sampling/createMessage` request.
    McpSampling,
    /// Embeddings API request.
    LlmEmbeddings,
}

// ── CallerContext ─────────────────────────────────────────────────────────────

/// Identity and governance metadata extracted from the incoming request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallerContext {
    /// Organisation identifier (from API key or JWT claim).
    pub org_id: String,
    /// Individual caller identifier (service account, user, or agent ID).
    pub caller_id: String,
    /// Optional team or department label for reporting.
    pub team: Option<String>,
    /// Optional agent identifier for multi-agent orchestration tracking.
    pub agent_id: Option<String>,
    /// Service name reported by the caller (e.g. "my-coding-assistant").
    pub service_name: Option<String>,
    /// Deployment environment (production, staging, development).
    pub environment: String,
    /// Active compliance policy profile (hipaa, pci-dss, gdpr, etc.).
    pub policy_profile: Option<String>,
    /// Whether governance decisions should be enforced or observed only.
    pub enforcement_mode: EnforcementMode,
    /// Current nesting depth of governance calls (incremented per hop).
    pub governance_depth: u8,
    /// Arbitrary key-value attributes for custom policy rules.
    pub attributes: HashMap<String, String>,
}

impl CallerContext {
    /// Returns `true` when this caller is running in shadow (observe-only) mode.
    pub fn is_shadow_mode(&self) -> bool {
        matches!(self.enforcement_mode, EnforcementMode::Shadow)
    }
}

// ── TokenUsage ────────────────────────────────────────────────────────────────

/// Token consumption reported by the upstream provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Tokens in the prompt (input).
    pub prompt_tokens: u64,
    /// Tokens in the completion (output).
    pub completion_tokens: u64,
    /// Sum of prompt and completion tokens.
    pub total_tokens: u64,
    /// Estimated cost in USD, computed from the provider's pricing table.
    pub estimated_cost_usd: Option<f64>,
}

// ── ChatMessage ───────────────────────────────────────────────────────────────

/// A single message in an LLM conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Conversation role: "system", "user", "assistant", or "tool".
    pub role: String,
    /// Message content — may be a string or a structured content array.
    pub content: serde_json::Value,
    /// Optional name for multi-participant conversations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool call result ID linking this message to a prior `tool_calls` entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Tool call requests emitted by the assistant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<serde_json::Value>>,
}

// ── SessionState ──────────────────────────────────────────────────────────────

/// Per-session governance state tracked across multiple requests.
///
/// Used by the `session_data_exfil_v1` rule to detect data exfiltration
/// patterns: high row reads + PII exposure + external send attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier.
    pub session_id: String,
    /// Organisation this session belongs to.
    pub org_id: String,
    /// Caller within the organisation.
    pub caller_id: String,
    /// Ordered log of `(tool_name, timestamp)` pairs for tools called this session.
    pub tools_called: Vec<(String, DateTime<Utc>)>,
    /// Cumulative number of data rows read via MCP tool results.
    pub total_rows_read: u64,
    /// Set of PII entity type strings observed in this session.
    pub pii_entities_seen: HashSet<String>,
    /// Whether the session has attempted to send data to an external endpoint.
    pub external_send_attempted: bool,
    /// Wall-clock time the session was created.
    pub started_at: DateTime<Utc>,
    /// Wall-clock time of the most recent activity.
    pub last_active: DateTime<Utc>,
}

impl SessionState {
    /// Returns `true` when the heuristic data-exfiltration pattern is detected:
    /// more than 500 rows read AND PII entities seen AND an external send attempted.
    pub fn is_exfil_pattern_detected(&self) -> bool {
        self.total_rows_read > 500
            && !self.pii_entities_seen.is_empty()
            && self.external_send_attempted
    }
}

// ── PolicyDecision ────────────────────────────────────────────────────────────

/// The complete output of the policy engine for a single governance event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The raw action determined by the policy rules.
    pub action: Action,
    /// The action that will actually be applied, accounting for shadow mode.
    /// In shadow mode this is always [`Action::Audit`] regardless of `action`.
    pub effective_action: Action,
    /// Human-readable explanation of why this decision was reached.
    pub reason: String,
    /// IDs of the rules that contributed to this decision.
    pub applicable_rules: Vec<String>,
    /// Highest severity finding that influenced this decision.
    pub severity: Severity,
    /// Tier of the winning rule (determines conflict resolution priority).
    pub tier: PolicyRuleTier,
    /// Additional context from the policy engine (e.g. quota remaining).
    pub metadata: HashMap<String, serde_json::Value>,
    /// Wall-clock milliseconds spent evaluating the policy.
    pub eval_duration_ms: f64,
    /// Whether this decision was served from the decision cache.
    pub cache_hit: bool,
    /// Which policy engine backend produced this decision.
    pub policy_engine: PolicyEngineMode,
    /// Wall-clock time the decision was produced.
    pub evaluated_at: DateTime<Utc>,
}

impl PolicyDecision {
    /// Construct a default allow decision (all governance checks passed).
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            effective_action: Action::Allow,
            reason: "All governance checks passed.".into(),
            applicable_rules: vec![],
            severity: Severity::Info,
            tier: PolicyRuleTier::Default,
            metadata: HashMap::new(),
            eval_duration_ms: 0.0,
            cache_hit: false,
            policy_engine: PolicyEngineMode::Native,
            evaluated_at: Utc::now(),
        }
    }

    /// Construct a security-tier block decision.
    pub fn block(reason: impl Into<String>, rules: Vec<String>) -> Self {
        let mut d = Self::allow();
        d.action = Action::Block;
        d.effective_action = Action::Block;
        d.reason = reason.into();
        d.applicable_rules = rules;
        d.severity = Severity::Critical;
        d.tier = PolicyRuleTier::Security;
        d
    }

    /// Construct a profile-tier redact decision.
    pub fn redact(reason: impl Into<String>, rules: Vec<String>) -> Self {
        let mut d = Self::allow();
        d.action = Action::Redact;
        d.effective_action = Action::Redact;
        d.reason = reason.into();
        d.applicable_rules = rules;
        d.tier = PolicyRuleTier::Profile;
        d
    }

    /// Construct a default-tier audit decision.
    pub fn audit() -> Self {
        let mut d = Self::allow();
        d.action = Action::Audit;
        d.effective_action = Action::Audit;
        d
    }

    /// Apply shadow mode: keep `action` for recording, set `effective_action` to
    /// [`Action::Audit`] so no blocking or redaction is applied.
    #[must_use]
    pub fn apply_shadow(mut self) -> Self {
        self.effective_action = Action::Audit;
        self
    }
}

// ── PolicyInput ───────────────────────────────────────────────────────────────

/// Everything the policy engine needs to produce a [`PolicyDecision`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    /// UUID v7 request identifier for correlation.
    pub request_id: String,
    /// Direction and protocol of the governance event.
    pub request_type: RequestType,
    /// Caller identity and governance metadata.
    pub caller: CallerContext,
    /// All findings from the detection pipeline for this request.
    pub findings: Vec<super::finding::Finding>,
    /// LLM model name (e.g. "gpt-4o", "claude-3-5-sonnet-20241022").
    pub model: Option<String>,
    /// Upstream provider name (e.g. "openai", "anthropic").
    pub provider: Option<String>,
    /// Parsed conversation messages (for LLM request/response events).
    pub messages: Option<Vec<ChatMessage>>,
    /// The MCP tool call being evaluated (for MCP events).
    pub tool_call: Option<super::mcp::McpToolCall>,
    /// The raw MCP tool result (for bidirectional MCP governance).
    pub tool_result: Option<serde_json::Value>,
    /// Token usage reported by the upstream provider.
    pub token_usage: Option<TokenUsage>,
    /// Current session state for exfiltration heuristics.
    pub session_state: Option<SessionState>,
    /// Governance nesting depth of this request.
    pub governance_depth: u8,
    /// Unix millisecond timestamp of the original request.
    pub timestamp: i64,
}
