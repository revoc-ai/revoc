//! Prometheus metrics registry for REVOC.
//!
//! All metrics are namespaced with the `revoc_` prefix. D8/D9/D10/D11/D12
//! properties each have dedicated counters for observability into the security
//! invariant machinery.

use std::sync::LazyLock;

use prometheus::{CounterVec, Encoder, HistogramVec, IntCounter, Opts, Registry, TextEncoder};

use revoc_core::RevocError;

// ── Request duration buckets (ms) ─────────────────────────────────────────────
const REQUEST_BUCKETS: &[f64] = &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0];

// ── Detection stage duration buckets (ms) ─────────────────────────────────────
const DETECTION_BUCKETS: &[f64] = &[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0];

// ── Upstream duration buckets (ms) ────────────────────────────────────────────
const UPSTREAM_BUCKETS: &[f64] =
    &[10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0];

// ── Global registry + metrics ─────────────────────────────────────────────────

static GLOBAL_REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// All metric names/help strings/bucket sets above are compile-time constants
// under our control, so registration cannot fail at runtime.
static GLOBAL_METRICS: LazyLock<RevocMetrics> = LazyLock::new(|| {
    RevocMetrics::new(&GLOBAL_REGISTRY).unwrap_or_else(|e| {
        eprintln!("FATAL: GLOBAL_METRICS init failed — metric definitions are static constants: {e}");
        std::process::exit(1)
    })
});

// ── Helper ────────────────────────────────────────────────────────────────────

fn make_counter_vec(
    registry: &Registry,
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<CounterVec, RevocError> {
    let m = CounterVec::new(Opts::new(name, help), labels)
        .map_err(|e| RevocError::Configuration(format!("Metric '{name}' create error: {e}")))?;
    registry
        .register(Box::new(m.clone()))
        .map_err(|e| RevocError::Configuration(format!("Metric '{name}' register error: {e}")))?;
    Ok(m)
}

fn make_histogram_vec(
    registry: &Registry,
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Vec<f64>,
) -> Result<HistogramVec, RevocError> {
    let opts = prometheus::HistogramOpts::new(name, help).buckets(buckets);
    let m = HistogramVec::new(opts, labels)
        .map_err(|e| RevocError::Configuration(format!("Histogram '{name}' create error: {e}")))?;
    registry
        .register(Box::new(m.clone()))
        .map_err(|e| RevocError::Configuration(format!("Histogram '{name}' register error: {e}")))?;
    Ok(m)
}

fn make_int_counter(
    registry: &Registry,
    name: &str,
    help: &str,
) -> Result<IntCounter, RevocError> {
    let m = IntCounter::new(name, help)
        .map_err(|e| RevocError::Configuration(format!("Counter '{name}' create error: {e}")))?;
    registry
        .register(Box::new(m.clone()))
        .map_err(|e| RevocError::Configuration(format!("Counter '{name}' register error: {e}")))?;
    Ok(m)
}

// ── RevocMetrics ──────────────────────────────────────────────────────────────

/// All Prometheus metrics for the REVOC proxy.
///
/// Obtain the process-wide singleton via [`RevocMetrics::global`].
#[derive(Debug)]
pub struct RevocMetrics {
    // ── Request counters ──────────────────────────────────────────────────────

    /// Total requests processed, labelled by outcome.
    pub revoc_requests_total: CounterVec,

    /// End-to-end proxy latency in milliseconds (including detection + policy).
    pub revoc_request_duration_ms: HistogramVec,

    // ── Detection stage metrics ───────────────────────────────────────────────

    /// Latency of each detection stage (regex, ONNX, plugin, etc.) in ms.
    pub revoc_detection_stage_ms: HistogramVec,

    /// Total findings produced, labelled by type and severity.
    pub revoc_findings_total: CounterVec,

    // ── Policy metrics ────────────────────────────────────────────────────────

    /// Policy decisions emitted by the engine.
    pub revoc_policy_decisions_total: CounterVec,

    // ── Upstream metrics ──────────────────────────────────────────────────────

    /// Upstream provider round-trip latency in milliseconds.
    pub revoc_upstream_duration_ms: HistogramVec,

    /// Upstream HTTP errors (4xx / 5xx), labelled by provider and status code.
    pub revoc_upstream_errors_total: CounterVec,

    // ── MCP metrics ───────────────────────────────────────────────────────────

    /// MCP tool calls governed.
    pub revoc_mcp_calls_total: CounterVec,

    // ── Token / cost metrics ──────────────────────────────────────────────────

    /// Cumulative tokens consumed per caller / model.
    pub revoc_tokens_used_total: CounterVec,

    /// Cumulative estimated cost in USD per caller / model.
    pub revoc_estimated_cost_usd: CounterVec,

    // ── Cache metrics ─────────────────────────────────────────────────────────

    /// Policy decision cache hits.
    pub revoc_cache_hits_total: CounterVec,

    /// Policy decision cache misses.
    pub revoc_cache_misses_total: CounterVec,

    // ── Security invariant metrics (D8/D9/D10/D11/D12) ───────────────────────

    /// Kill-switch activations, labelled by scope (global/org/caller). [D11]
    pub revoc_kill_switch_activations_total: CounterVec,

    /// Requests rejected for exceeding governance depth limit. [D9]
    pub revoc_depth_exceeded_total: IntCounter,

    /// Requests where Unicode normalisation changed the text. [D8]
    pub revoc_normalization_applied_total: IntCounter,

    /// Tool manifest findings produced by D10 analysis, labelled by severity. [D10]
    pub revoc_manifest_findings_total: CounterVec,

    /// Policy conflict resolutions, labelled by the winning tier. [D12]
    pub revoc_policy_conflict_resolved_total: CounterVec,
}

impl RevocMetrics {
    /// Create and register all metrics into `registry`.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] if any metric fails to register
    /// (typically only when the same name is registered twice).
    #[allow(clippy::too_many_lines)]
    pub fn new(registry: &Registry) -> Result<Self, RevocError> {
        Ok(Self {
            // ── Requests ──────────────────────────────────────────────────────
            revoc_requests_total: make_counter_vec(
                registry,
                "revoc_requests_total",
                "Total requests processed by the REVOC proxy",
                &["environment", "provider", "decision", "caller_team", "org_id"],
            )?,
            revoc_request_duration_ms: make_histogram_vec(
                registry,
                "revoc_request_duration_ms",
                "End-to-end proxy latency in milliseconds",
                &["environment", "provider", "decision"],
                REQUEST_BUCKETS.to_vec(),
            )?,

            // ── Detection ─────────────────────────────────────────────────────
            revoc_detection_stage_ms: make_histogram_vec(
                registry,
                "revoc_detection_stage_ms",
                "Latency of each detection stage in milliseconds",
                &["stage", "tier"],
                DETECTION_BUCKETS.to_vec(),
            )?,
            revoc_findings_total: make_counter_vec(
                registry,
                "revoc_findings_total",
                "Total findings produced by the detection engine",
                &["finding_type", "severity", "tier"],
            )?,

            // ── Policy ────────────────────────────────────────────────────────
            revoc_policy_decisions_total: make_counter_vec(
                registry,
                "revoc_policy_decisions_total",
                "Total policy decisions emitted by the engine",
                &["action", "rule_id", "engine", "tier"],
            )?,

            // ── Upstream ──────────────────────────────────────────────────────
            revoc_upstream_duration_ms: make_histogram_vec(
                registry,
                "revoc_upstream_duration_ms",
                "Upstream AI provider round-trip latency in milliseconds",
                &["provider", "model"],
                UPSTREAM_BUCKETS.to_vec(),
            )?,
            revoc_upstream_errors_total: make_counter_vec(
                registry,
                "revoc_upstream_errors_total",
                "Upstream HTTP errors forwarded verbatim to the client",
                &["provider", "status_code"],
            )?,

            // ── MCP ───────────────────────────────────────────────────────────
            revoc_mcp_calls_total: make_counter_vec(
                registry,
                "revoc_mcp_calls_total",
                "MCP tool calls governed by REVOC",
                &["tool_name", "decision", "server_id"],
            )?,

            // ── Tokens / cost ─────────────────────────────────────────────────
            revoc_tokens_used_total: make_counter_vec(
                registry,
                "revoc_tokens_used_total",
                "Cumulative tokens consumed per caller and model",
                &["caller_id", "org_id", "model", "provider"],
            )?,
            revoc_estimated_cost_usd: make_counter_vec(
                registry,
                "revoc_estimated_cost_usd",
                "Cumulative estimated cost in USD per caller and model",
                &["caller_id", "org_id", "model"],
            )?,

            // ── Cache ─────────────────────────────────────────────────────────
            revoc_cache_hits_total: make_counter_vec(
                registry,
                "revoc_cache_hits_total",
                "Policy decision cache hits",
                &["engine"],
            )?,
            revoc_cache_misses_total: make_counter_vec(
                registry,
                "revoc_cache_misses_total",
                "Policy decision cache misses",
                &["engine"],
            )?,

            // ── Security invariants ───────────────────────────────────────────
            revoc_kill_switch_activations_total: make_counter_vec(
                registry,
                "revoc_kill_switch_activations_total",
                "Emergency kill-switch activations (D11)",
                &["scope"],
            )?,
            revoc_depth_exceeded_total: make_int_counter(
                registry,
                "revoc_depth_exceeded_total",
                "Requests rejected for exceeding governance depth limit (D9)",
            )?,
            revoc_normalization_applied_total: make_int_counter(
                registry,
                "revoc_normalization_applied_total",
                "Requests where Unicode normalisation changed the input text (D8)",
            )?,
            revoc_manifest_findings_total: make_counter_vec(
                registry,
                "revoc_manifest_findings_total",
                "Tool manifest findings from D10 analysis",
                &["severity"],
            )?,
            revoc_policy_conflict_resolved_total: make_counter_vec(
                registry,
                "revoc_policy_conflict_resolved_total",
                "Policy conflict resolutions by winning tier (D12)",
                &["winning_tier"],
            )?,
        })
    }

    /// Return the process-wide singleton, initialised lazily on first access.
    pub fn global() -> &'static RevocMetrics {
        &GLOBAL_METRICS
    }

    /// Encode all metrics in the global registry as Prometheus text format.
    pub fn prometheus_text() -> String {
        let encoder = TextEncoder::new();
        let families = GLOBAL_REGISTRY.gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap_or_default();
        String::from_utf8(buf).unwrap_or_default()
    }
}
