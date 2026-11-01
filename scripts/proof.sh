#!/usr/bin/env bash
# Proof run: HTTP load test, audit completeness, no-egress and no-PII-in-logs
# checks against a release build. CLAIMS.md cites the report it writes.
#
# Two phases, each with a fresh proxy in front of the stub upstream
# (loopback only, API-key auth, SQLite audit):
#
#   latency   info-level logs, nothing attached. k6 drives clean chat, chat
#             with PII, MCP tools/call and embeddings at RATE req/s each;
#             gates P95/P99 per scenario and that every request was audited
#             with no events dropped.
#   evidence  the same traffic at EVIDENCE_RATE under strace (every connect /
#             send) with trace-level JSON logs; gates that every address the
#             proxy contacted is loopback and that no canary value (PII, the
#             client API key, the upstream key) appears in the logs, the audit
#             database, or the bodies the upstream received.
#
# Tracing and trace-level logging slow the proxy down, which is why latency
# is measured in a separate, untraced phase.
#
# Env: PROOF_OUT (default target/proof), RATE (200), DURATION (20),
#      EVIDENCE_RATE (50), EVIDENCE_DURATION (8), P95_MS (10), P99_MS (25),
#      PROXY_BIN / STUB_BIN (default <target>/release/...), STRACE (strace).
# Requires: k6, strace, curl, python3. Linux only.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${PROOF_OUT:-$ROOT/target/proof}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROXY_BIN="${PROXY_BIN:-$TARGET_DIR/release/revoc-proxy}"
STUB_BIN="${STUB_BIN:-$TARGET_DIR/release/stub-upstream}"
STRACE="${STRACE:-strace}"
PROXY_PORT=18080
STUB_PORT=18081
export RATE="${RATE:-200}" DURATION="${DURATION:-20}"
export EVIDENCE_RATE="${EVIDENCE_RATE:-50}" EVIDENCE_DURATION="${EVIDENCE_DURATION:-8}"
export P95_MS="${P95_MS:-10}" P99_MS="${P99_MS:-25}"

rm -rf "$OUT"
mkdir -p "$OUT/latency" "$OUT/evidence"

if [[ ! -x "$PROXY_BIN" || ! -x "$STUB_BIN" ]]; then
  (cd "$ROOT" && cargo build --release -p revoc-proxy -p revoc-benches \
    --bin revoc-proxy --bin stub-upstream)
fi
for tool in k6 curl python3 "$STRACE"; do
  command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 2; }
done

# Canary values, unique per run so a match can only come from this run.
eval "$(python3 "$ROOT/scripts/proof_check.py" canaries "$OUT/canaries.json")"
API_KEY="proof-$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
printf '%s\n' "$API_KEY" >"$OUT/api_keys.txt"

PIDS=()
stop_all() {
  # Under strace the proxy is strace's child: stop it first so it shuts
  # down gracefully (draining audit writes) while still traced.
  for p in "${PIDS[@]}"; do pkill -TERM -P "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  PIDS=()
}
trap stop_all EXIT

# run_phase <dir> <log-level> <rate> <duration> <p95> <p99> [wrapper...]
run_phase() {
  local dir="$1" level="$2" rate="$3" duration="$4" p95="$5" p99="$6"
  shift 6

  "$STUB_BIN" "$STUB_PORT" "$dir/upstream-bodies.jsonl" >"$dir/stub.log" 2>&1 &
  PIDS+=($!)

  env -i PATH="$PATH" HOME="$HOME" \
    REVOC_SERVER__HOST=127.0.0.1 \
    REVOC_SERVER__PORT=$PROXY_PORT \
    REVOC_SERVER__INTERNAL_PORT=18090 \
    REVOC_SERVER__DASHBOARD_PORT=0 \
    REVOC_SERVER__ENVIRONMENT=proof \
    REVOC_AUTH__MODE=apikey \
    REVOC_AUTH__API_KEYS_FILE="$OUT/api_keys.txt" \
    REVOC_STORAGE__BACKEND=sqlite \
    REVOC_STORAGE__SQLITE_PATH="$dir/audit.db" \
    REVOC_POLICY__ENGINE=native \
    REVOC_TELEMETRY__LOG_LEVEL="$level" \
    REVOC_TELEMETRY__LOG_FORMAT=json \
    REVOC_UPSTREAM__MOCK_MODE=false \
    REVOC_UPSTREAM__PROVIDERS__0__NAME=openai \
    REVOC_UPSTREAM__PROVIDERS__0__BASE_URL="http://127.0.0.1:$STUB_PORT" \
    REVOC_UPSTREAM__PROVIDERS__0__FORMAT=openai \
    REVOC_UPSTREAM__PROVIDERS__0__DEFAULT=true \
    REVOC_MCP__TRUSTED_SERVERS__0__ID=stub \
    REVOC_MCP__TRUSTED_SERVERS__0__URL="http://127.0.0.1:$STUB_PORT/mcp" \
    OPENAI_API_KEY=sk-proof-not-a-real-key \
    "$@" "$PROXY_BIN" serve >"$dir/proxy.log" 2>&1 &
  PIDS+=($!)

  for _ in $(seq 1 150); do
    curl -fsS "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
    sleep 0.2
  done
  curl -fsS "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
    echo "proxy did not start" >&2; tail -50 "$dir/proxy.log" >&2; exit 1; }

  set +e
  k6 run --quiet --no-usage-report \
    -e REVOC_BASE="http://127.0.0.1:$PROXY_PORT" -e API_KEY="$API_KEY" \
    -e RATE="$rate" -e DURATION="$duration" -e P95_MS="$p95" -e P99_MS="$p99" \
    -e CANARY_EMAIL="$CANARY_EMAIL" -e CANARY_SSN="$CANARY_SSN" -e CANARY_AWS="$CANARY_AWS" \
    -e SUMMARY="$dir/k6-summary.json" \
    "$ROOT/tests/load/k6/proxy_overhead.js" >"$dir/k6.log" 2>&1
  echo $? >"$dir/k6.exit"
  set -e

  # Wait for the audit queue to drain, then record the writer's counters.
  for _ in $(seq 1 100); do
    curl -fsS "http://127.0.0.1:$PROXY_PORT/ready" >"$dir/ready.json" 2>/dev/null || true
    python3 -c 'import json,sys;sys.exit(json.load(open(sys.argv[1]))["audit"]["queued"])' \
      "$dir/ready.json" 2>/dev/null && break
    sleep 0.1
  done
  stop_all
}

run_phase "$OUT/latency" info "$RATE" "$DURATION" "$P95_MS" "$P99_MS"
# Evidence phase: latency is not gated (thresholds set out of reach).
run_phase "$OUT/evidence" trace "$EVIDENCE_RATE" "$EVIDENCE_DURATION" 60000 60000 \
  "$STRACE" -f -qq -e trace=connect,sendto,sendmsg -o "$OUT/evidence/strace.log"
trap - EXIT

python3 "$ROOT/scripts/proof_check.py" report "$OUT"
