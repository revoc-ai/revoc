//! `OpenTelemetry` tracing, Prometheus metrics, and structured logging for REVOC.
//!
//! Initialisation order:
//! 1. Call [`tracer::RevocTracer::init`] to install the global `OTel` provider.
//! 2. Call [`logger::init_logging`] to install the tracing subscriber with the
//!    `OTel` layer wired to that provider.
//! 3. Use [`metrics::RevocMetrics::global`] anywhere to record counters /
//!    histograms.
//!
//! # Security note (SPEC.md §17, §23 Rule 2)
//! **Never** log request or response body content. Log only metadata
//! (entity type, field name, byte offset, decision). This is enforced by
//! convention — no body-content fields appear in any log format here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attributes;
pub mod logger;
pub mod metrics;
pub mod tracer;

pub use logger::init_logging;
pub use metrics::RevocMetrics;
pub use tracer::RevocTracer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_init_no_panic_in_test() {
        // try_init() silently ignores "already initialized" — safe to call N times.
        let _ = logger::init_logging("info", "pretty");
        let _ = logger::init_logging("debug", "json");
        let _ = logger::init_logging("warn", "pretty");
    }

    #[test]
    fn test_metrics_new_without_error() {
        let registry = prometheus::Registry::new();
        let result = metrics::RevocMetrics::new(&registry);
        assert!(result.is_ok(), "RevocMetrics::new should succeed: {result:?}");
    }

    #[test]
    fn test_prometheus_text_non_empty() {
        use prometheus::Encoder;
        let registry = prometheus::Registry::new();
        let _metrics = metrics::RevocMetrics::new(&registry).expect("metrics init");
        let encoder = prometheus::TextEncoder::new();
        let families = registry.gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).expect("encode");
        let text = String::from_utf8(buf).expect("utf8");
        assert!(
            !text.is_empty(),
            "Prometheus text should be non-empty after metric registration"
        );
    }

    #[test]
    fn test_governance_attrs_all_revoc_prefix() {
        use revoc_core::{CallerContext, PolicyDecision, PolicyInput, RequestType};

        let decision = PolicyDecision::block(
            "test block",
            vec!["sec_ddl_mutation_v1".into()],
        );
        let input = PolicyInput {
            request_id: "req-123".into(),
            request_type: RequestType::LlmRequest,
            caller: CallerContext {
                org_id: "org1".into(),
                caller_id: "svc-a".into(),
                ..CallerContext::default()
            },
            findings: vec![],
            model: Some("gpt-4o".into()),
            provider: Some("openai".into()),
            messages: None,
            tool_call: None,
            tool_result: None,
            token_usage: None,
            session_state: None,
            governance_depth: 0,
            timestamp: 0,
        };

        let attrs = attributes::governance_attrs(&decision, &input);
        assert!(!attrs.is_empty(), "governance_attrs must return attributes");
        for kv in &attrs {
            let key = kv.key.as_str();
            assert!(
                key.starts_with("revoc.") || key.starts_with("gen_ai."),
                "Attribute key '{key}' does not start with 'revoc.' or 'gen_ai.'"
            );
        }
    }

    #[test]
    fn test_timing_attrs_all_4_fields() {
        let attrs = attributes::timing_attrs(2.5, 1.1, 0.3, 45.0);
        assert_eq!(attrs.len(), 4, "timing_attrs must return exactly 4 KeyValues");
    }
}
