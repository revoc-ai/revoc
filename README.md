# REVOC

[![Version](https://img.shields.io/badge/version-0.1.0--beta.1-orange.svg)](CHANGELOG.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust 1.80](https://img.shields.io/badge/rust-1.80.0-orange.svg)](rust-toolchain.toml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Frevoc--ai%2Frevoc-blue)](https://ghcr.io/revoc-ai/revoc)
[![Calls Home](https://img.shields.io/badge/calls%20home-never-brightgreen)](docs/docs/security/telemetry-policy.md)
[![Status](https://img.shields.io/badge/status-beta-orange.svg)](#project-status)

**Runtime Execution Validation & Observability Control**

Govern every AI call your application makes. Zero code changes.

> **Beta — not yet for production traffic.** REVOC 0.1 is ready for evaluation,
> development and shadow-mode trials. See [Project status](#project-status) for
> what is solid, what is partial, and what is still missing.

---

## Three-Step Quickstart

**Step 1 — Start the proxy:**

```bash
# One-liner:
docker run -d -p 8080:8080 -p 3000:3000 -e OPENAI_API_KEY=$OPENAI_API_KEY --name revoc ghcr.io/revoc-ai/revoc:beta
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

✅ implemented and tested · ⚠️ partial or experimental · ❌ not yet

| Feature | Status | Detail |
|---|---|---|
| PII detection (11 entity types) | ✅ | Regex + validators (Luhn, IBAN, ABA). Pattern-based: expect misses and false positives on free text |
| Secret blocking (10 types) | ✅ | AWS keys, GitHub tokens, OpenAI/Anthropic keys, private keys, JWTs, passwords |
| Prompt injection detection | ⚠️ | Phrase patterns only; paraphrased or translated injections are not caught |
| SQL mutation blocking | ✅ | DROP, TRUNCATE, ALTER TABLE, DELETE without WHERE (regex, not a SQL parser) |
| SSRF / path traversal | ⚠️ | Literal internal IPs and `../`; encoded or alternate IP forms are not canonicalised yet |
| Unicode evasion normalization | ✅ | NFKC + zero-width + RTLO/BIDI removal before every detection pass |
| Fail-closed governance | ✅ | Detection timeouts, detector errors, policy errors and redaction errors block the request |
| Emergency kill-switch | ⚠️ | Global, per-org, per-caller. State is in memory per instance; Redis pub/sub fan-out is best-effort and not persisted |
| Governance depth guard | ✅ | Max depth 10; prevents infinite agent recursion |
| Tool manifest analysis | ✅ | Scans MCP `tools/list` for dangerous parameter names and suspicious descriptions |
| Bidirectional MCP governance | ✅ | Tool arguments and tool results inspected (JSON-RPC over HTTP POST) |
| Shadow mode | ✅ | Observe without blocking |
| Streaming governance | ⚠️ | Sliding-window scanner and tool-call accumulator; experimental — use `stream.buffer_output = true` for strict inspection |
| Compliance profiles (HIPAA / PCI-DSS / GDPR) | ⚠️ | Example policy bundles only. REVOC is not certified for, and does not by itself make you compliant with, any framework |
| Postgres audit store / Redis shared state | ❌ | Audit events are written to SQLite today |
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

Targets (SPEC.md §19), checked with criterion micro-benchmarks in `benches/`:

| Benchmark | Target |
|---|---|
| P95 proxy overhead (proxy-only) | < 10ms |
| Regex detection — 4KB, no PII | > 100K req/s |
| Regex detection — 4KB, 3 PII findings | > 50K req/s |
| Full pipeline (regex + policy + redaction) | > 40K req/s |
| Policy cache hit | > 1M ops/s |
| Normalization overhead | < 0.5ms |
| Manifest analysis (10 tools) | < 1ms |

Run them on your own hardware with `cargo bench -p revoc-benches`. These are
in-process numbers; end-to-end HTTP latency (P50/P95/P99 under load) has not
been published yet.

---

## Deployment Options

### Tier 1 — Single Container (zero dependencies)

```bash
docker run -d \
  -p 8080:8080 -p 3000:3000 -p 127.0.0.1:8081:8081 \
  -e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 -e REVOC_ADMIN_KEY=$REVOC_ADMIN_KEY \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc \
  ghcr.io/revoc-ai/revoc:beta
```

SQLite audit log at `/data/revoc-audit.db` (mount a volume on `/data` to keep it). For development and evaluation.

### Tier 2 — Team (docker compose with Postgres + Redis)

```bash
git clone https://github.com/revoc-ai/revoc && cd revoc
cp .env.example .env    # set OPENAI_API_KEY and a strong REVOC_ADMIN_KEY
make up
```

Adds the admin API with Postgres, and Redis for kill-switch fan-out. The proxy's
own audit log is still SQLite in this release.

### Tier 3 — Kubernetes (Helm)

```bash
git clone https://github.com/revoc-ai/revoc && cd revoc
helm dependency build helm/revoc
helm install revoc helm/revoc \
  --set secrets.openaiApiKey=$OPENAI_API_KEY \
  --set secrets.adminKey=$(openssl rand -hex 24)
```

Multiple replicas with autoscaling and OTel export. The chart is beta: an OPA
sidecar and a published chart repository are not included yet.

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

## Project status

REVOC 0.1 is a **beta**. It is ready for evaluation, development, and
shadow-mode trials on real traffic. It has not had an external security review
and is not yet recommended as the only control in front of production systems.

Known gaps being worked on before 1.0:

- Streaming governance scans assembled SSE frames with a sliding window; a
  rebuilt per-choice parser with hold-back and in-stream redaction is planned.
- The policy decision cache key does not yet include tool arguments or session
  state; set `policy.decision_cache_ttl_secs = 0` for strict evaluation.
- Kill-switch state is per instance; there is no persisted, reconciled state.
- All API keys map to a single org; there is no tenant-scoped key registry yet.
- Audit storage is SQLite only on the proxy; Postgres is used by the admin API.
- Detection is pattern-based; there is no labelled evaluation corpus or
  published precision/recall yet.

Security issues: please use [private vulnerability reporting](SECURITY.md).

---

## License

Apache 2.0. See [LICENSE](LICENSE).
