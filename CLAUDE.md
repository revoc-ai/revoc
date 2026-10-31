# CLAUDE.md — Contributor & Coding-Agent Guide

REVOC (Runtime Execution Validation & Observability Control) is an out-of-band
governance proxy for LLM and MCP traffic. This file is the short guide for
humans and coding agents working in this repo.

- **[SPEC.md](SPEC.md)** — the full design specification (types, handler
  lifecycles, config schema, default rules). Code comments cite it as `SPEC.md §N`.
  Read the relevant section before changing behavior, and update it in the same PR.
- **<https://revoc.io>** — user and operator docs (source in `docs/`).

## Build & test

```bash
make build            # cargo build --workspace
make test             # cargo test --workspace
make lint             # cargo clippy --workspace -- -D warnings
make fmt-check
cargo audit && cargo deny check

cd admin-api && ruff check . && mypy app/ --strict && pytest tests/ --cov-fail-under=85
cd sdk/python && pytest
cd sdk/node && npm ci && npm test
opa check policies/ --strict && opa test policies/ -v
mkdocs build --strict -f docs/mkdocs.yml
make up / make down   # full docker compose stack
```

Toolchains: Rust stable (see `rust-toolchain.toml`), Python 3.12, Node 20+.

## Repository layout

```
crates/            Rust workspace (dependency order):
  revoc-core → revoc-config → revoc-telemetry → revoc-detector →
  revoc-pipeline → revoc-policy → revoc-redaction → revoc-dashboard → revoc-proxy
crates/revoc-dashboard/ui/        React SPA; ui/dist/ is pre-built and MUST stay committed
admin-api/         FastAPI admin service (package: revoc-gateway)
sdk/python/        revoc-sdk (PyPI)
sdk/node/          @revoc-io/sdk (npm)
policies/          Rego policies, compliance profiles, examples, schema
helm/revoc/        Helm chart
docker/            Compose stack + observability config
docs/              MkDocs site published to revoc.io
tests/ benches/ fuzz/   integration/e2e/load tests, criterion benches, cargo-fuzz targets
```

## Non-negotiable principles

Violating any of these is a bug, not a trade-off (SPEC.md §3).

1. Zero governance code in application code — the proxy is fully out-of-band.
2. P95 proxy overhead < 10ms, P99 < 25ms (benchmarked).
3. No external HTTP in the Tier 1/Tier 2 detection hot path.
4. Bidirectional governance — requests, responses, tool calls and tool results.
5. Normalize before detect — NFKC + zero-width/BIDI/control removal before every regex pass.
6. Max governance depth 10 (`X-Revoc-Depth`); at the limit return 503 immediately.
7. Fail-closed — `fail_open = false` in every committed config.
8. Upstream 4xx/5xx are forwarded verbatim, never wrapped in `RevocErrorResponse`.
9. No PII in logs or audit records — entity type, field and position only, never values.
10. Emergency kill-switch is Step 0 of every handler and stops traffic within ~50ms.
11. `X-Revoc-Dashboard` on every response.
12. `X-Revoc-Timing` on every response.
13. `tools/list` responses always go through manifest analysis.
14. Tier 3 security rules always win; custom allow rules cannot override them.
15. No unsafe code — `#![forbid(unsafe_code)]` on all library crates.

## Performance targets

| Benchmark | Target |
|---|---|
| P95 proxy overhead (no upstream) | < 10ms |
| Regex detection, 4KB body, no PII | > 100K req/s |
| Regex detection, 4KB body, 3 findings | > 50K req/s |
| Full pipeline (regex + policy + redaction) | > 40K req/s |
| Policy cache hit | > 1M ops/s |
| Native policy engine, empty findings | > 500K/s |
| Normalization overhead | < 0.5ms |
| Manifest analysis (10 tools) | < 1ms |
| MCP arg parse + detect | > 200K req/s |

Run with `cargo bench -p revoc-benches`.

## Coding rules

Summary of SPEC.md §23 ("What not to do"); the spec's numbering is what code cites.

1. No `.unwrap()` / `.expect()` outside `#[cfg(test)]`.
2. Never log or store raw PII or secret values.
3. No incomplete code: no TODO/FIXME/HACK, `todo!()`, `unimplemented!()`, stub or
   placeholder functions, or fabricated return values in non-test code.
4. LLM governance blocks return HTTP 403; MCP blocks return a JSON-RPC error (-32603)
   and the blocked request is never forwarded to the tool server.
5. `X-Revoc-Depth` goes on outgoing upstream requests, never on client responses.
6. API keys are compared with `subtle::ConstantTimeEq`, never `==`.
7. Upstream URLs come from the config allowlist only, never from request headers (SSRF).
8. Every response header value is sanitized (strip `\r`, `\n`, `\0`).
9. Streaming is never buffered unless `stream.buffer_output = true`; accumulated tool
   calls are governed before `finish_reason=tool_calls` is forwarded.
10. Audit writes are async and batched; they never block the request path.
11. Every kill-switch activation is written to `kill_switch_log`.
12. The proxy never calls home.
13. Never commit secrets, `.env`, databases, logs, build output or fuzz corpora.
