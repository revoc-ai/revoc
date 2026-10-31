//! Structured logging initialisation.
//!
//! Supports two output formats:
//! - `"json"` — machine-readable JSON for production log aggregators.
//! - `"pretty"` — ANSI-coloured human-readable output for development.
//!
//! Uses [`tracing_subscriber::Registry::try_init`] so multiple calls in the
//! same process (e.g. during tests) are silently ignored rather than panicking.
//!
//! # Privacy rule (SPEC.md §23 Rule 2)
//! This module **never** logs request or response body content.
//! Only metadata fields (decision, timing, caller ID, entity type) may appear.

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use revoc_core::RevocError;

/// Initialise the global tracing subscriber.
///
/// The `OTel` layer is wired to whatever global tracer provider is active at
/// the time of the call. Call [`crate::tracer::RevocTracer::init`] before
/// this function to attach the OTLP exporter.
///
/// Safe to call more than once — subsequent calls are silently ignored,
/// making this test-friendly.
///
/// # Errors
/// Returns [`RevocError::Configuration`] only if the provided `level` string
/// is not a valid [`EnvFilter`] directive and the fallback also fails.
pub fn init_logging(level: &str, format: &str) -> Result<(), RevocError> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    // OTel span-correlation is added by RevocTracer::init() after the provider
    // is built. The logger sets up structured output only; BoxedTracer cannot
    // be used with with_tracer() directly (PreSampledTracer bound not satisfied).
    if format == "json" {
        let fmt_layer = fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_target(true)
            .with_file(false)
            .with_line_number(false)
            .with_timer(fmt::time::SystemTime);

        // try_init() swallows "global subscriber already set" — safe in tests.
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init();
    } else {
        // "pretty" and any unrecognised format use ANSI-coloured output.
        let fmt_layer = fmt::layer()
            .pretty()
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .with_timer(fmt::time::SystemTime);

        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init();
    }

    Ok(())
}
