# Telemetry Policy

**REVOC collects zero telemetry.**

The REVOC proxy process makes no outbound connections to revoc.io, any analytics
endpoint, any crash reporting service, or any metrics aggregation service.

## What REVOC Does Not Do

- Does not send usage statistics to revoc.io
- Does not send model names, token counts, or request counts to any third party
- Does not send error reports or crash dumps to any external service
- Does not check for updates by calling home
- Does not send API keys, prompt content, or finding data to any external party
- Does not embed any analytics SDK (Segment, Mixpanel, Amplitude, Datadog agent, etc.)

This applies to all three deployment tiers: single container, docker compose, and Helm.

## Complete List of Outbound Connections

The REVOC proxy process makes exactly these outbound connections at runtime:

| Destination | When | Purpose | Configurable |
|---|---|---|---|
| Upstream LLM provider (e.g., `api.openai.com`) | On every governed request | Forward the AI request | Yes — `[[upstream.providers]]` |
| Upstream MCP server (configured URLs) | On MCP tool calls | Forward tool calls | Yes — `[mcp].trusted_servers` |
| OPA sidecar (default: `http://localhost:8181`) | Tier 3 only, policy eval | Evaluate Rego policies | Yes — `[policy].opa_url` |
| Postgres (`DATABASE_URL`) | Tier 2/3 only | Audit log, policy storage | Yes — `[storage].backend` |
| Redis (`REDIS_URL`) | Tier 2/3 only | Kill-switch pub/sub, cache | Yes — `[cache].backend` |
| OTLP endpoint (`[telemetry].otlp_endpoint`) | Only if configured | Export traces and metrics | Yes — empty by default |
| Presidio (`[detection].presidio_url`) | Only if configured | PII enrichment | Yes — disabled by default |
| Webhook endpoints (`[[webhooks.endpoints]]`) | Only if configured | Governance event delivery | Yes — disabled by default |

All connections are to destinations you configure explicitly. There are no hardcoded
external URLs in the proxy binary other than upstream AI provider defaults.

## Verifying Zero Outbound Telemetry

You can verify this at runtime using network monitoring:

```bash
# Run REVOC in mock mode (no upstream LLM connections)
docker run -d \
  -p 8080:8080 -p 3000:3000 \
  -e REVOC_UPSTREAM__MOCK_MODE=true \
  -e REVOC_AUTH__MODE=none \
  --name revoc-audit \
  ghcr.io/revoc-ai/revoc:latest

# Monitor outbound connections from the container
docker exec revoc-audit ss -tnp | grep ESTABLISHED

# Send a request
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'

# Verify no unexpected outbound connections appeared
docker exec revoc-audit ss -tnp | grep ESTABLISHED
# Expected: empty (mock mode makes no upstream connections)
```

## Source Code Verification

The proxy binary is built from source with `#![forbid(unsafe_code)]` on all library crates.
You can audit the complete list of outbound HTTP calls:

```bash
# All reqwest client calls in the proxy
grep -rn "\.get\|\.post\|\.put\|\.delete\|client\.request" crates/revoc-proxy/src/
```

Every result is either:
- A call to a configured upstream provider URL
- A call to the configured OPA sidecar URL
- A call to a configured enricher URL (Presidio / Azure, disabled by default)

## Build Reproducibility

The proxy Docker image is built from the public `Dockerfile` at `crates/revoc-proxy/Dockerfile`.
You can build it yourself and verify the image digest matches the published image:

```bash
docker build -t revoc-local -f crates/revoc-proxy/Dockerfile .
docker inspect revoc-local --format '{{.Id}}'
```

## Data Residency

All data processed by REVOC (prompt content, findings, audit events) stays within your
infrastructure. Audit events are written to your configured SQLite or Postgres database.
No data is transmitted to revoc.io or any third party.
