//! `OpenTelemetry` span attribute constants and helper constructors for REVOC.
//!
//! All REVOC-specific keys carry the `revoc.` prefix. `gen_ai.*` attributes
//! follow the `OpenTelemetry` `GenAI` semantic conventions.
//!
//! # Usage
//! ```rust,ignore
//! let attrs = governance_attrs(&decision, &input);
//! span.set_attributes(attrs);
//! ```

use opentelemetry::KeyValue;

use revoc_core::{McpToolCall, PolicyDecision, PolicyInput, TokenUsage};

// ── REVOC attribute key constants ─────────────────────────────────────────────

/// UUID v7 unique identifier for a single proxy request.
pub const REVOC_REQUEST_ID: &str = "revoc.request_id";

/// Governance decision taken: allow / redact / block / audit.
pub const REVOC_DECISION: &str = "revoc.decision";

/// Direct link to the governance trace in the REVOC dashboard.
pub const REVOC_DASHBOARD_URL: &str = "revoc.dashboard_url";

/// Detection stage wall-clock duration in milliseconds.
pub const REVOC_TIMING_DETECTION_MS: &str = "revoc.timing.detection_ms";

/// Policy evaluation wall-clock duration in milliseconds.
pub const REVOC_TIMING_POLICY_MS: &str = "revoc.timing.policy_ms";

/// Redaction wall-clock duration in milliseconds.
pub const REVOC_TIMING_REDACTION_MS: &str = "revoc.timing.redaction_ms";

/// Upstream provider round-trip duration in milliseconds.
pub const REVOC_TIMING_UPSTREAM_MS: &str = "revoc.timing.upstream_ms";

/// Total proxy overhead in milliseconds (detection + policy + redaction).
pub const REVOC_TIMING_TOTAL_MS: &str = "revoc.timing.total_ms";

/// Number of findings produced by the detection engine.
pub const REVOC_FINDINGS_COUNT: &str = "revoc.findings_count";

/// Comma-separated PII entity types found in this request.
pub const REVOC_PII_TYPES: &str = "revoc.pii_types";

/// Comma-separated IDs of the rules that triggered the governance decision.
pub const REVOC_VIOLATED_RULES: &str = "revoc.violated_rules";

/// Caller identifier extracted from the API key or JWT.
pub const REVOC_CALLER_ID: &str = "revoc.caller_id";

/// Organisation identifier extracted from the API key or JWT.
pub const REVOC_CALLER_ORG: &str = "revoc.caller_org";

/// Optional team label from the caller context.
pub const REVOC_CALLER_TEAM: &str = "revoc.caller_team";

/// Governance nesting depth of this request (0 = top-level).
pub const REVOC_GOVERNANCE_DEPTH: &str = "revoc.governance_depth";

/// Whether the emergency kill-switch was active for this request.
pub const REVOC_KILL_SWITCH_ACTIVE: &str = "revoc.kill_switch_active";

/// Whether Unicode normalisation changed the request text (D8).
pub const REVOC_NORMALIZATION_APPLIED: &str = "revoc.normalization_applied";

/// Number of tool manifest findings from D10 analysis.
pub const REVOC_MANIFEST_FINDINGS_COUNT: &str = "revoc.manifest_findings_count";

/// Winning policy tier from conflict resolution (D12).
pub const REVOC_POLICY_TIER: &str = "revoc.policy_tier";

/// Name of the MCP tool being called.
pub const REVOC_MCP_TOOL_NAME: &str = "revoc.mcp.tool_name";

/// Whether the MCP tool call was blocked by governance.
pub const REVOC_MCP_BLOCKED: &str = "revoc.mcp.blocked";

/// MCP server identifier that owns the tool.
pub const REVOC_MCP_SERVER_ID: &str = "revoc.mcp.server_id";

/// Upstream AI provider name (e.g. `"openai"`, `"anthropic"`).
pub const REVOC_UPSTREAM_PROVIDER: &str = "revoc.upstream.provider";

/// Upstream LLM model name (e.g. `"gpt-4o"`).
pub const REVOC_UPSTREAM_MODEL: &str = "revoc.upstream.model";

// ── GenAI semantic convention keys ───────────────────────────────────────────

/// `OTel` `GenAI` system attribute (e.g. `"openai"`, `"anthropic"`).
pub const GEN_AI_SYSTEM: &str = "gen_ai.system";

/// `OTel` `GenAI` requested model attribute.
pub const GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";

/// `OTel` `GenAI` total token usage attribute.
pub const GEN_AI_USAGE_TOTAL_TOKENS: &str = "gen_ai.usage.total_tokens";

// ── Helper constructors ───────────────────────────────────────────────────────

/// Build span attributes from a governance decision and its policy input.
///
/// Returns attributes with `revoc.*` keys only — no body content is included
/// (SPEC.md §23 Rule 2).
pub fn governance_attrs(decision: &PolicyDecision, input: &PolicyInput) -> Vec<KeyValue> {
    let rules = decision.applicable_rules.join(",");
    let pii_types: Vec<String> = input
        .findings
        .iter()
        .filter_map(|f| f.pii_entity.as_ref().map(ToString::to_string))
        .collect();

    let mut attrs = vec![
        KeyValue::new(REVOC_REQUEST_ID,       input.request_id.clone()),
        KeyValue::new(REVOC_DECISION,         format!("{:?}", decision.effective_action)),
        KeyValue::new(REVOC_FINDINGS_COUNT,   i64::try_from(input.findings.len()).unwrap_or(i64::MAX)),
        KeyValue::new(REVOC_VIOLATED_RULES,   rules),
        KeyValue::new(REVOC_PII_TYPES,        pii_types.join(",")),
        KeyValue::new(REVOC_CALLER_ID,        input.caller.caller_id.clone()),
        KeyValue::new(REVOC_CALLER_ORG,       input.caller.org_id.clone()),
        KeyValue::new(REVOC_GOVERNANCE_DEPTH, i64::from(input.governance_depth)),
        KeyValue::new(REVOC_POLICY_TIER,      format!("{:?}", decision.tier)),
    ];

    if let Some(team) = &input.caller.team {
        attrs.push(KeyValue::new(REVOC_CALLER_TEAM, team.clone()));
    }
    if let Some(provider) = &input.provider {
        attrs.push(KeyValue::new(REVOC_UPSTREAM_PROVIDER, provider.clone()));
    }
    if let Some(model) = &input.model {
        attrs.push(KeyValue::new(REVOC_UPSTREAM_MODEL, model.clone()));
    }

    attrs
}

/// Build span attributes for an upstream AI provider call.
pub fn gen_ai_attrs(model: &str, provider: &str, usage: Option<&TokenUsage>) -> Vec<KeyValue> {
    let mut attrs = vec![
        KeyValue::new(GEN_AI_SYSTEM,        provider.to_string()),
        KeyValue::new(GEN_AI_REQUEST_MODEL, model.to_string()),
    ];
    if let Some(u) = usage {
        attrs.push(KeyValue::new(GEN_AI_USAGE_TOTAL_TOKENS, i64::try_from(u.total_tokens).unwrap_or(i64::MAX)));
    }
    attrs
}

/// Build span attributes for a single MCP tool call.
pub fn mcp_attrs(call: &McpToolCall, blocked: bool) -> Vec<KeyValue> {
    let mut attrs = vec![
        KeyValue::new(REVOC_MCP_TOOL_NAME, call.tool_name.clone()),
        KeyValue::new(REVOC_MCP_BLOCKED,   blocked),
    ];
    if let Some(sid) = &call.server_id {
        attrs.push(KeyValue::new(REVOC_MCP_SERVER_ID, sid.clone()));
    }
    attrs
}

/// Build the four timing attributes included in every `X-Revoc-Timing` span.
///
/// Returns exactly 4 [`KeyValue`]s:
/// `detection_ms`, `policy_ms`, `redaction_ms`, `upstream_ms`.
pub fn timing_attrs(
    detection_ms: f64,
    policy_ms: f64,
    redaction_ms: f64,
    upstream_ms: f64,
) -> Vec<KeyValue> {
    vec![
        KeyValue::new(REVOC_TIMING_DETECTION_MS, detection_ms),
        KeyValue::new(REVOC_TIMING_POLICY_MS,    policy_ms),
        KeyValue::new(REVOC_TIMING_REDACTION_MS, redaction_ms),
        KeyValue::new(REVOC_TIMING_UPSTREAM_MS,  upstream_ms),
    ]
}
