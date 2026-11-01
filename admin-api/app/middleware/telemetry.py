from __future__ import annotations

from fastapi import FastAPI

from app.core.config import Settings


def setup_telemetry(app: FastAPI, settings: Settings) -> None:
    """Instrument the FastAPI app with OpenTelemetry if an OTLP endpoint is set.

    When no endpoint is configured (the default for Tier 1 / dev) this is a
    no-op so the service still starts without any OTel collector present.
    """
    # Only import heavy OTel machinery when actually needed
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return  # OTel packages not installed — silently skip

    # Determine OTLP endpoint from settings (stored in environment as
    # REVOC_ADMIN_OTLP_ENDPOINT; falls back to empty string → disabled).
    otlp_endpoint: str = getattr(settings, "otlp_endpoint", "")
    if not otlp_endpoint:
        return  # Not configured — skip

    resource = Resource.create(
        {
            "service.name": "revoc-admin-api",
            "service.version": "0.1.0-beta.1",
            "deployment.environment": settings.environment,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
