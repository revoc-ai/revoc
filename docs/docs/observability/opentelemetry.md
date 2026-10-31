# OpenTelemetry

REVOC exports traces, metrics, and logs via the OpenTelemetry Protocol (OTLP).
OTel export is disabled by default — set `otlp_endpoint` to enable it.

## Configuration

```toml
[telemetry]
otlp_endpoint = "http://otel-collector:4317"  # gRPC endpoint
service_name = "revoc-proxy"
service_version = "1.0.0"
sample_rate = 1.0   # 1.0 = 100% sampling, 0.1 = 10%
prometheus_port = 9090
log_level = "info"
log_format = "json"
```

```bash
REVOC_TELEMETRY__OTLP_ENDPOINT=http://otel-collector:4317
REVOC_TELEMETRY__SAMPLE_RATE=0.1   # 10% sampling for high-traffic environments
```

## Trace Structure

Each governed request produces a root span named `revoc.request` with child spans:

```
revoc.request
  ├── revoc.detection          detection pipeline duration
  │     ├── revoc.normalize    normalization step
  │     ├── revoc.regex        regex detection stage
  │     └── revoc.onnx         ONNX stage (if enabled)
  ├── revoc.policy             policy evaluation duration
  ├── revoc.redaction          redaction step (if redact action)
  └── revoc.upstream           upstream LLM call duration
```

## Trace Attributes

All spans carry these attributes:

| Attribute | Value |
|---|---|
| `revoc.request_id` | UUID v7 |
| `revoc.trace_id` | UUID v7 (same as `X-Revoc-Trace-ID`) |
| `revoc.org_id` | Caller's org ID |
| `revoc.caller_id` | Caller ID from authentication |
| `revoc.decision` | allow / redact / block / audit |
| `revoc.rules` | Comma-separated violated rule IDs |
| `revoc.governance_depth` | Nesting depth |
| `revoc.was_normalized` | true if Unicode evasion normalization fired |
| `revoc.model` | LLM model name |
| `revoc.provider` | Upstream provider name |

No PII values are included in trace attributes.

## W3C Trace Context Propagation

REVOC propagates W3C `traceparent` headers:

- Reads `traceparent` from incoming requests — if present, the REVOC span is a child
  of the caller's trace
- Sets `traceparent` on the outgoing upstream request — upstream spans are children
  of the REVOC span

This allows end-to-end traces from your application through REVOC to the upstream LLM.

## OpenTelemetry Collector Configuration

```yaml
# otel-collector.yml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024

exporters:
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true
  prometheus:
    endpoint: 0.0.0.0:8889

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus]
```

## Disabling OTel

Set `otlp_endpoint` to empty string (the default):

```toml
[telemetry]
otlp_endpoint = ""    # OTel disabled — no spans exported
```

Prometheus metrics on port 9090 remain active regardless of OTel configuration.
