# REVOC

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust 1.80](https://img.shields.io/badge/rust-1.80.0-orange.svg)](rust-toolchain.toml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Frevoc--ai%2Frevoc-blue)](https://ghcr.io/revoc-ai/revoc)
[![P95 Overhead](https://img.shields.io/badge/P95%20overhead-%3C10ms-brightgreen)](benches/)
[![Calls Home](https://img.shields.io/badge/calls%20home-never-brightgreen)](docs/docs/security/telemetry-policy.md)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](CHANGELOG.md)

**Runtime Execution Validation & Observability Control**

Govern every AI call your application makes. Zero code changes.

---

## Three-Step Quickstart

**Step 1 — Start the proxy:**

```bash
# One-liner:
docker run -d -p 8080:8080 -p 3000:3000 -e OPENAI_API_KEY=$OPENAI_API_KEY --name revoc ghcr.io/revoc-ai/revoc:latest
```

**Step 2 — Change one line (or zero lines):**

```python
# Before
client = OpenAI(api_key="sk-...")

# After — 30 rules active, dashboard at :3000, full audit
client = OpenAI(api_key="sk-...", base_url="http://localhost:8080")
```

Or zero code changes via environment variable:

```bash
export REVOC_BASE_URL=http://localhost:8080
# All existing code now governed. No source changes required.
export OPENAI_BASE_URL=http://localhost:8080  # standard OpenAI SDK env var also works
```

**Step 3 — Open the dashboard:**

```
http://localhost:3000
```

Or via environment variable — zero code changes:

```bash
export OPENAI_BASE_URL=http://localhost:8080
# All existing code now governed. No source changes.
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                          │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP (OpenAI-compatible)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                 REVOC Proxy  :8080                           │
│                                                             │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Normalize│→ │  Detect   │→ │  Policy  │→ │ Redact / │  │
│  │ (NFKC+  │  │ (Regex +  │  │  Engine  │  │  Block / │  │
│  │  ZW+BIDI)│  │  ONNX opt)│  │ (Native) │  │  Allow   │  │
│  └──────────┘  └───────────┘  └──────────┘  └──────────┘  │
│                                                             │
│  Kill-Switch :8081          Dashboard :3000                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              LLM / MCP Server (OpenAI, Anthropic, ...)
```

---

## Feature Table

| Feature | Status | Detail |
|---|---|---|
| PII detection (11 entity types) | ✅ | SSN, email, phone, credit card, IBAN, passport, MRN, DOB, IP, driver license, bank account |
| Secret blocking (10 types) | ✅ | AWS keys, GitHub tokens, OpenAI/Anthropic keys, private keys, JWTs, passwords |
| Prompt injection detection | ✅ | 15+ injection and jailbreak phrase patterns |
| SQL mutation blocking | ✅ | DROP, TRUNCATE, ALTER TABLE, DELETE without WHERE |
| SSRF protection | ✅ | Internal IP ranges blocked in HTTP tool args |
| Path traversal blocking | ✅ | `../` sequences in file tool args |
| Unicode evasion normalization | ✅ | NFKC + zero-width + RTLO/BIDI removal before every detection pass |
| Emergency kill-switch (50ms) | ✅ | Global, per-org, per-caller; Redis propagation to all instances |
| Governance depth guard | ✅ | Max depth 10; prevents infinite agent recursion |
| Tool manifest analysis | ✅ | Scans MCP `tools/list` for dangerous parameter names and suspicious descriptions |
| Bidirectional MCP governance | ✅ | Tool arguments AND tool results inspected |
| Shadow mode | ✅ | Observe without blocking; per-deployment or per-caller |
| HIPAA / PCI-DSS / GDPR profiles | ✅ | Pre-built compliance policy bundles |
| P95 proxy overhead | ✅ | < 10ms measured (criterion benchmarks) |
| Streaming governance | ✅ | Sliding window scanner + tool call accumulator |
| Calls home / telemetry | ❌ | REVOC makes zero outbound connections to revoc.io |

---

## PII Detection — Before and After

**Request sent by your application:**

```json
{
  "messages": [{
    "role": "user",
    "content": "My SSN is 123-45-6789 and email is alice@example.com. Help with my account."
  }]
}
```

**Request forwarded to the LLM (after REVOC redaction):**

```json
{
  "messages": [{
    "role": "user",
    "content": "My SSN is [REDACTED] and email is [EMAIL_ADDRESS]. Help with my account."
  }]
}
```

**Response headers set by REVOC:**

```
X-Revoc-Decision: redact
X-Revoc-Rules: pii_ssn_v1,pii_email_v1
X-Revoc-Dashboard: http://localhost:3000/traces/01932abc-...
X-Revoc-Timing: detection=2ms,policy=0ms,redaction=1ms,upstream=312ms,total=315ms
```

---

## MCP Tool Call Governance

**Tool call sent by the AI model:**

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "execute_sql",
    "arguments": {"query": "DROP TABLE users"}
  }
}
```

**REVOC response (HTTP 200, upstream never receives the request):**

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32603,
    "message": "Request blocked by governance policy.",
    "data": {
      "code": "REVOC_GOVERNANCE_BLOCK",
      "rules": ["sec_ddl_mutation_v1"],
      "dashboard_url": "http://localhost:3000/traces/01932abc-..."
    }
  }
}
```

---

## Performance

All benchmarks run with criterion on an `i7-13700K` at 5GHz, single container, no upstream.

| Benchmark | Result | Target |
|---|---|---|
| P95 proxy overhead (proxy-only) | 4.2ms | < 10ms ✅ |
| Regex detection — 4KB, no PII | 187K req/s | > 100K/s ✅ |
| Regex detection — 4KB, 3 PII findings | 73K req/s | > 50K/s ✅ |
| Full pipeline (regex + policy + redaction) | 58K req/s | > 40K/s ✅ |
| Policy cache hit | 4.1M ops/s | > 1M/s ✅ |
| Normalization overhead | 0.12ms | < 0.5ms ✅ |
| Manifest analysis (10 tools) | 0.31ms | < 1ms ✅ |

---

## Deployment Options

### Tier 1 — Single Container (zero dependencies)

```bash
docker run -d \
  -p 8080:8080 -p 3000:3000 -p 8081:8081 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc \
  ghcr.io/revoc-ai/revoc:latest
```

SQLite audit log stored in the container. Suitable for development and single-node production.

### Tier 2 — Team (docker compose with Postgres + Redis)

```bash
curl -O https://raw.githubusercontent.com/revoc-ai/revoc/main/docker-compose.yml
OPENAI_API_KEY=$OPENAI_API_KEY docker compose up -d
```

Adds persistent Postgres audit storage and Redis for kill-switch propagation and caching.

### Tier 3 — Enterprise (Helm)

```bash
helm repo add revoc https://charts.revoc.io
helm install revoc revoc/revoc \
  --set upstream.openai.apiKey=$OPENAI_API_KEY \
  --set global.environment=production
```

HA deployment with OPA sidecar, OTel export, autoscaling, and multi-instance kill-switch.

---

## Framework Integrations

| Framework | Integration | Example |
|---|---|---|
| OpenAI SDK (Python) | `base_url="http://localhost:8080"` | [python-quickstart/](examples/python-quickstart/) |
| LangChain | `openai_api_base="http://localhost:8080"` | [langchain_example.py](examples/framework-integrations/langchain_example.py) |
| LlamaIndex | `api_base="http://localhost:8080"` | [llamaindex_example.py](examples/framework-integrations/llamaindex_example.py) |
| AutoGen | `"base_url": "http://localhost:8080"` in config_list | [autogen_example.py](examples/framework-integrations/autogen_example.py) |
| CrewAI | `openai_api_base="http://localhost:8080"` | [crewai_example.py](examples/framework-integrations/crewai_example.py) |
| Any OpenAI-compatible client | Set `OPENAI_BASE_URL=http://localhost:8080` | Zero code changes |

---

## REVOC Does Not Call Home

REVOC makes zero outbound connections to revoc.io or any analytics endpoint.
All data processed by REVOC stays within your infrastructure.

See [Telemetry Policy](docs/docs/security/telemetry-policy.md) for the complete list
of outbound connections (all user-configured, all opt-in).

---

## Documentation

Full documentation: [https://revoc.io/docs](https://revoc.io/docs)

- [Quickstart](docs/docs/getting-started/quickstart.md)
- [Default Rules (all 30)](docs/docs/default-rules/overview.md)
- [Shadow Mode](docs/docs/shadow-mode/overview.md)
- [Emergency Kill-Switch](docs/docs/operations/emergency-kill-switch.md)
- [Unicode Normalization](docs/docs/concepts/normalization.md)
- [Governance Depth](docs/docs/concepts/governance-depth.md)
- [Telemetry Policy](docs/docs/security/telemetry-policy.md)

---

## License

Apache 2.0. See [LICENSE](LICENSE).
