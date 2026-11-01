# Claims and evidence

Every claim REVOC makes about itself, with what backs it. A claim is listed
as **proven** only when a check that fails the build backs it. Everything
else says what it rests on.

| Status | Meaning |
|---|---|
| **Proven** | Gated in CI: the build fails if the claim stops being true |
| **Tested** | Covered by unit/integration tests, but not measured end-to-end |
| **Target** | A design goal with no gate yet |
| **Not claimed** | Something REVOC does not do, stated so it is not assumed |

The proof run is `scripts/proof.sh` (CI job **Proof / load + egress + PII**).
Each run uploads `report.md` / `report.json` as the `proof-report` artifact.

---

## Performance

| Claim | Status | Evidence |
|---|---|---|
| P95 proxy latency < 10 ms, P99 < 25 ms | **Proven** at 200 req/s per scenario | Proof run, latency phase. k6 thresholds per scenario fail the job |
| Measured under load: P50 / P95 / P99 | **Proven** (reported every run) | `report.md` latency table |
| No audit event lost under that load | **Proven** | Proof run, audit gate: `dropped == 0` and audit rows ≥ requests |
| Regex detection > 100K req/s, full pipeline > 40K req/s, policy cache > 1M ops/s, normalization < 0.5 ms, manifest analysis < 1 ms | **Target** | Criterion benches in `benches/` (`cargo bench -p revoc-benches`); not run in CI |

**How latency is measured.** k6 sends requests at a fixed arrival rate. Each
scenario runs on its own: clean chat, chat with PII (redacted or blocked),
MCP `tools/call`, and embeddings. The release proxy uses API-key auth, the
native policy engine and SQLite audit, in front of a stub upstream on
loopback (`benches/src/bin/stub_upstream.rs`).

The time is taken at the client, end to end: client → proxy → stub → proxy →
client. That makes it an **upper bound** on proxy overhead. It includes the
stub's own time and both loopback hops.

One local run, on 12 CPUs (i7-9750H, WSL2), at 200 req/s per scenario for 20 s
(17,004 requests, all audited):

| Scenario | P50 ms | P95 ms | P99 ms |
|---|---:|---:|---:|
| `llm_clean` | 1.61 | 2.20 | 4.85 |
| `llm_pii` | 1.32 | 1.68 | 3.51 |
| `mcp_tool` | 1.79 | 2.45 | 5.25 |
| `embeddings` | 1.39 | 1.95 | 4.08 |

CI runs the same thing on GitHub's runners. Each run's numbers are in the
job summary.

**What the latency figures do not cover:**
- Streaming responses.
- Real provider latency.
- Postgres audit.
- Redis-backed state.
- Rates beyond the one tested.
- The ONNX detector, which is off by default.

## Privacy and egress

| Claim | Status | Evidence |
|---|---|---|
| The proxy never calls home | **Proven** for the traffic in the proof run | Proof run, egress gate: strace records every `connect`/`sendto`/`sendmsg` of the proxy process tree, and every address must be loopback |
| No external HTTP in the detection hot path | **Proven** (same gate) | All detection runs while traced; the only network peer is the stub |
| No PII or secret values in logs | **Proven** at trace level | Proof run, PII gate: canary email, SSN, AWS key, the client API key and the upstream key, unique per run, must not appear in the proxy log at `trace` level |
| No PII in audit records | **Proven** | Same gate, over every table and column of the audit database |
| PII is redacted before it reaches the upstream | **Proven** for the canary set | Same gate, over every request body the stub upstream received |
| Session state stores entity types, never values | **Tested** | `storage_tests::mcp_session_is_recorded_and_exfil_pattern_blocks_the_send` |

**What the egress and PII checks do not cover:**
- **Configured features.** The egress gate covers the default configuration. OTLP export, an OPA sidecar, HTTP detection plugins, Postgres and Redis open connections to the endpoints *you* configure, by design.
- **Other entity types.** The canary set is three entity types plus two keys. Other entity types are covered by detector tests, not by this gate.

## Governance

| Claim | Status | Evidence |
|---|---|---|
| Every built-in rule and the action it takes | **Proven** | [Rule Catalog](docs/docs/default-rules/catalog.md) is generated from the detector's pattern tables, with each decision computed by the native policy engine; `rules_catalog::tests::committed_catalog_matches_the_code` fails if the page drifts |
| Fail-closed on detection, policy and redaction errors | **Tested** | `fail_closed_tests` |
| Blocked MCP calls never reach the tool server | **Tested** | `fail_closed_tests::mcp_detection_failure_blocks_and_never_reaches_tool_server`, `storage_tests::mcp_session_is_recorded_and_exfil_pattern_blocks_the_send` (mock server expects 0 calls) |
| Every authenticated request leaves an audit record | **Tested**, and **proven** under load | `storage_tests` exit-path tests, plus the proof run's audit gate |
| Kill switch stops traffic within ~50 ms across instances | **Tested** in-process | `kill_switch_tests`, plus a Redis compare-and-swap test against a real server. Cross-instance propagation time is not measured |
| Streaming governance (hold-back, in-stream redaction, tool calls held) | **Tested** | `streaming_tests`, plus the `fuzz_sse_parser` target |
| Normalization before detection (NFKC, zero-width, BIDI) | **Tested** | `check-normalization` CI job |
| Governance depth limit 10 | **Tested** | `depth_tests`, `storage_tests::depth_limit_on_mcp_is_audited` |
| Postgres audit store, Redis sessions | **Tested** against real servers | CI job **Rust / storage backends** |

## Not claimed

- **Detection accuracy.** There is no labelled evaluation corpus and no published precision/recall. Detection is pattern-based: paraphrased prompt injection, unusual PII formats and secrets without a known prefix are missed.
- **Compliance.** The profiles are examples. REVOC is not certified for, and does not by itself make you compliant with, any framework.
- **Security review.** The 0.1 beta has not had an external review.
- **Per-secret rule IDs.** Every secret finding is reported as `secret_block_v1`. The per-secret IDs on the secret-rules page appear only in the block reason (see the catalog).

---

To reproduce on Linux with k6, strace, curl and python3 installed:

```bash
bash scripts/proof.sh            # writes target/proof/report.md
RATE=500 DURATION=30 bash scripts/proof.sh
```
