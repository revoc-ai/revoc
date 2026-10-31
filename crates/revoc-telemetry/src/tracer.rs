//! `OpenTelemetry` tracer initialisation and lifecycle management.
//!
//! Handles two modes:
//! - **Disabled** (`otlp_endpoint` is empty): installs a no-op provider, logs an
//!   info message, and returns immediately.
//! - **`OTel` gRPC** (`otlp_endpoint` is set): installs a batched OTLP exporter
//!   with W3C `traceparent` propagation and configurable sampling.
//!
//! On connection failure to the `OTel` endpoint, the proxy falls back to the
//! no-op provider and logs a warning rather than crashing.

use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{BatchSpanProcessor, Config, Sampler, TracerProvider},
    Resource,
};
use tracing::{info, warn};

use revoc_config::TelemetryConfig;
use revoc_core::RevocError;

/// Handle to the active `OTel` tracer provider.
///
/// Call [`RevocTracer::shutdown`] on graceful process exit to flush all
/// in-flight spans to the collector.
pub struct RevocTracer {
    provider: Option<TracerProvider>,
}

impl RevocTracer {
    /// Initialise the global `OTel` tracer provider from [`TelemetryConfig`].
    ///
    /// Must be called before [`crate::logger::init_logging`] so the `OTel`
    /// layer in the subscriber picks up the real provider.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] only for unrecoverable
    /// configuration errors. OTLP connection failures are logged and
    /// fall back to no-op.
    pub fn init(cfg: &TelemetryConfig) -> Result<Self, RevocError> {
        // Install W3C traceparent/tracestate propagation regardless of mode.
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

        if cfg.otlp_endpoint.is_empty() {
            info!("OTel disabled. Set telemetry.otlp_endpoint to enable trace export.");
            // Install a minimal provider (no exporter) so global::tracer() never panics.
            let provider = TracerProvider::builder().build();
            opentelemetry::global::set_tracer_provider(provider.clone());
            return Ok(Self {
                provider: Some(provider),
            });
        }

        match Self::build_otlp_provider(cfg) {
            Ok(provider) => {
                opentelemetry::global::set_tracer_provider(provider.clone());
                info!(
                    endpoint = %cfg.otlp_endpoint,
                    sample_rate = cfg.sample_rate,
                    "OTel OTLP exporter initialised"
                );
                Ok(Self {
                    provider: Some(provider),
                })
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to connect to OTel endpoint; falling back to no-op provider"
                );
                let provider = TracerProvider::builder().build();
                opentelemetry::global::set_tracer_provider(provider.clone());
                Ok(Self {
                    provider: Some(provider),
                })
            }
        }
    }

    /// Flush all in-flight spans and shut down the OTLP exporter.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] if the provider shutdown fails.
    pub fn shutdown(&self) -> Result<(), RevocError> {
        if let Some(provider) = &self.provider {
            provider
                .shutdown()
                .map_err(|e| RevocError::Configuration(format!("OTel shutdown error: {e}")))?;
        }
        Ok(())
    }

    fn build_otlp_provider(cfg: &TelemetryConfig) -> Result<TracerProvider, RevocError> {
        use opentelemetry_otlp::WithExportConfig;

        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(&cfg.otlp_endpoint)
            .build_span_exporter()
            .map_err(|e| {
                RevocError::Configuration(format!("OTel OTLP exporter build error: {e}"))
            })?;

        let processor =
            BatchSpanProcessor::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

        let sampler = if cfg.sample_rate >= 1.0 {
            Sampler::AlwaysOn
        } else {
            Sampler::TraceIdRatioBased(cfg.sample_rate)
        };

        let resource = Resource::new(vec![
            KeyValue::new("service.name", cfg.service_name.clone()),
            KeyValue::new("service.version", cfg.service_version.clone()),
        ]);

        let provider = TracerProvider::builder()
            .with_span_processor(processor)
            .with_config(
                Config::default()
                    .with_sampler(sampler)
                    .with_resource(resource),
            )
            .build();

        Ok(provider)
    }
}
