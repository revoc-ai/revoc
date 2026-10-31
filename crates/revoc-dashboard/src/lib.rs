//! Embedded React dashboard for REVOC — SSE live feed, REST API, static SPA serving.
//!
//! The pre-built React SPA (`ui/dist/`) is embedded at compile time via
//! `include_dir!`. No Node.js is required at runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod auth;
pub mod handler;
pub mod live_feed;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use handler::dashboard_router;
pub use live_feed::{GovernanceEvent, LiveFeedBus};

// ── AuditEvent — mirrors SPEC.md §15 audit_events table ────────────────────

/// A single persisted audit event (matches the `audit_events` SQL schema).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEvent {
    /// Primary key UUID v7.
    pub id: String,
    /// Organisation identifier.
    pub org_id: Option<String>,
    /// UUID v7 request identifier.
    pub request_id: String,
    /// Wall-clock time of the event.
    pub timestamp: String,
    /// Caller service / user identifier.
    pub caller_id: Option<String>,
    /// Optional team label.
    pub caller_team: Option<String>,
    /// Deployment environment.
    pub environment: Option<String>,
    /// Raw policy decision (allow/redact/block/audit).
    pub decision: String,
    /// Effective action after shadow-mode override.
    pub effective_action: String,
    /// Enforcement mode (enforce/shadow).
    pub enforcement_mode: String,
    /// Comma-separated violated rule IDs.
    pub violated_rules: Option<String>,
    /// Comma-separated finding type labels.
    pub finding_types: Option<String>,
    /// LLM model name.
    pub model: Option<String>,
    /// Upstream provider name.
    pub provider: Option<String>,
    /// MCP tool name (if applicable).
    pub tool_name: Option<String>,
    /// Request/response direction.
    pub request_type: Option<String>,
    /// Governance nesting depth.
    pub governance_depth: i64,
    /// Prompt token count.
    pub prompt_tokens: Option<i64>,
    /// Completion token count.
    pub completion_tokens: Option<i64>,
    /// Estimated cost in USD.
    pub estimated_cost_usd: Option<f64>,
    /// Total proxy latency in milliseconds.
    pub duration_ms: Option<f64>,
    /// Detection stage latency.
    pub detection_ms: Option<f64>,
    /// Policy evaluation latency.
    pub policy_ms: Option<f64>,
    /// Whether Unicode normalization changed the input (evasion indicator).
    pub was_normalized: bool,
    /// Number of tool manifest findings.
    pub manifest_warnings: i64,
    /// Trace ID for correlation with X-Revoc-Dashboard header.
    pub trace_id: Option<String>,
    /// Policy engine backend used.
    pub policy_engine: Option<String>,
    /// Row creation time.
    pub created_at: String,
}

// ── EventFilter ───────────────────────────────────────────────────────────────

/// Filter parameters for querying audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Restrict to a single organisation.
    pub org_id: Option<String>,
    /// Restrict to a specific effective action.
    pub decision: Option<String>,
    /// Restrict to a specific caller.
    pub caller_id: Option<String>,
    /// Restrict to a specific team.
    pub team: Option<String>,
    /// Look up by exact trace ID.
    pub trace_id: Option<String>,
    /// Events at or after this time.
    pub start_time: Option<DateTime<Utc>>,
    /// Events at or before this time.
    pub end_time: Option<DateTime<Utc>>,
    /// Rule ID that must appear in `violated_rules`.
    pub rule_id: Option<String>,
    /// Maximum rows to return.
    pub limit: Option<usize>,
    /// Rows to skip (for pagination).
    pub offset: Option<usize>,
}

// ── AnalyticsWindow ───────────────────────────────────────────────────────────

/// Time window for analytics aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalyticsWindow {
    /// Last 1 hour.
    Hour1,
    /// Last 24 hours.
    Hour24,
    /// Last 7 days.
    Day7,
    /// Last 30 days.
    Day30,
}

impl AnalyticsWindow {
    /// Parse from a query-string value (`"1h"`, `"24h"`, `"7d"`, `"30d"`).
    pub fn parse_window(s: &str) -> Self {
        match s {
            "1h" => Self::Hour1,
            "7d" => Self::Day7,
            "30d" => Self::Day30,
            _ => Self::Hour24,
        }
    }

    /// `SQLite` `datetime('now', <modifier>)` modifier marking the start of
    /// this window — used to filter `audit_events.created_at >= ...`.
    pub fn sqlite_modifier(&self) -> &'static str {
        match self {
            Self::Hour1 => "-1 hours",
            Self::Hour24 => "-24 hours",
            Self::Day7 => "-7 days",
            Self::Day30 => "-30 days",
        }
    }

    /// `SQLite` `strftime` format used to bucket events for the timeline —
    /// hourly buckets for short (<= 24h) windows, daily buckets for longer
    /// (multi-day) windows so the series stays readable.
    pub fn bucket_strftime(&self) -> &'static str {
        match self {
            Self::Hour1 | Self::Hour24 => "%Y-%m-%dT%H:00:00Z",
            Self::Day7 | Self::Day30 => "%Y-%m-%dT00:00:00Z",
        }
    }
}

// ── AnalyticsResult ───────────────────────────────────────────────────────────

/// Aggregated analytics over a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsResult {
    /// Total requests in the window.
    pub total: u64,
    /// Blocked requests.
    pub blocked: u64,
    /// Redacted requests.
    pub redacted: u64,
    /// Allowed requests.
    pub allowed: u64,
    /// Top triggered rule IDs with counts.
    pub top_rules: Vec<RuleCount>,
    /// Top caller IDs with counts.
    pub top_callers: Vec<CallerCount>,
    /// Estimated cost broken down by service.
    pub costs_by_service: Vec<ServiceCost>,
    /// Time-series data for charting.
    pub timeline: Vec<TimelinePoint>,
}

/// Rule ID + hit count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCount {
    /// Rule identifier.
    pub rule_id: String,
    /// Number of times this rule triggered.
    pub count: u64,
}

/// Caller ID + request count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerCount {
    /// Caller identifier.
    pub caller_id: String,
    /// Number of requests from this caller.
    pub count: u64,
}

/// Service name + cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCost {
    /// Service / caller name.
    pub service: String,
    /// Estimated USD cost.
    pub cost_usd: f64,
}

/// A single point on the request timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    /// ISO 8601 timestamp bucket.
    pub ts: String,
    /// Total requests in this bucket.
    pub total: u64,
    /// Blocked requests in this bucket.
    pub blocked: u64,
}

// ── AuditStore trait ──────────────────────────────────────────────────────────

/// Async data-access trait for audit events.
///
/// Implemented by the `SQLite` and Postgres backends in `revoc-proxy`.
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Insert a new audit event.
    async fn insert_event(&self, event: AuditEvent) -> Result<(), revoc_core::RevocError>;

    /// List events matching the filter.
    async fn list_events(
        &self,
        filter: EventFilter,
    ) -> Result<(Vec<AuditEvent>, u64), revoc_core::RevocError>;

    /// Look up a single event by trace ID.
    async fn get_event_by_trace(
        &self,
        trace_id: &str,
    ) -> Result<Option<AuditEvent>, revoc_core::RevocError>;

    /// Compute aggregated analytics for the given window.
    async fn analytics(
        &self,
        window: AnalyticsWindow,
    ) -> Result<AnalyticsResult, revoc_core::RevocError>;

    /// Delete events older than `retention_days`.
    async fn cleanup_old_events(&self, retention_days: u32) -> Result<u64, revoc_core::RevocError>;
}

// ── KillSwitchControl ─────────────────────────────────────────────────────────

/// Read-only snapshot of kill-switch activation state across all scopes.
///
/// Mirrors `revoc_proxy::kill_switch::KillSwitchSnapshot` without requiring a
/// dependency on `revoc-proxy` (which itself depends on `revoc-dashboard`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KillSwitchStatusView {
    /// Whether the global kill-switch is active.
    pub global: bool,
    /// Active org-scoped activations: `org_id -> reason`.
    pub by_org: std::collections::HashMap<String, String>,
    /// Active caller-scoped activations: `caller_id -> reason`.
    pub by_caller: std::collections::HashMap<String, String>,
}

/// Abstraction over the proxy's emergency kill-switch (SPEC.md §9 D11).
///
/// `revoc-dashboard` is lower in the crate dependency order than `revoc-proxy`
/// (§4: `... -> revoc-dashboard -> revoc-proxy`), so it cannot reference
/// `KillSwitchState` directly. `revoc-proxy` supplies a concrete adapter over
/// its real, shared `KillSwitchState` when it constructs `DashboardState`,
/// giving the dashboard read/write access to the *actual* emergency-stop
/// state — never a fabricated snapshot.
#[async_trait]
pub trait KillSwitchControl: Send + Sync {
    /// Current activation status across all scopes.
    async fn status(&self) -> KillSwitchStatusView;

    /// Activate the kill-switch for `scope` (`"global" | "org" | "caller"`).
    ///
    /// `target` is required for `"org"`/`"caller"` scopes and ignored for
    /// `"global"`. Implementations must propagate the activation to all
    /// instances (e.g. via Redis pub/sub) and write to the `kill_switch_log`
    /// audit table (SPEC.md §23 Rule 26).
    ///
    /// # Errors
    /// Returns [`revoc_core::RevocError::RequestParse`] for an unknown scope
    /// or a missing `target` for a scoped activation.
    async fn activate(
        &self,
        scope: &str,
        target: Option<&str>,
        reason: &str,
        activated_by: &str,
    ) -> Result<(), revoc_core::RevocError>;

    /// Deactivate the kill-switch for `scope` (`"global" | "org" | "caller"`).
    ///
    /// # Errors
    /// Returns [`revoc_core::RevocError::RequestParse`] for an unknown scope
    /// or a missing `target` for a scoped deactivation.
    async fn deactivate(
        &self,
        scope: &str,
        target: Option<&str>,
    ) -> Result<(), revoc_core::RevocError>;
}
