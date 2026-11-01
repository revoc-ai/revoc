#!/usr/bin/env bash
# REVOC v1.0.0 — Per-Phase Build & Smoke Validation
# Run from the repo root after each phase to verify incremental correctness.
# Requires: cargo, python3 (venv at admin-api/.venv), node/npm, docker, helm.
# Optional: opa, kubectl, cargo-fuzz (nightly).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ── Container lifecycle — EXIT trap for Phase 18b/18c containers ──────────────
# set -euo pipefail means any command failure exits the script immediately.
# The trap ensures containers are removed even when early exit occurs.
_E2E_CONTAINER_STARTED=0
_LOCUST_CONTAINER_STARTED=0
_cleanup_phase_containers() {
  [ "$_E2E_CONTAINER_STARTED"    = "1" ] && docker rm -f revoc-e2e    2>/dev/null || true
  [ "$_LOCUST_CONTAINER_STARTED" = "1" ] && docker rm -f revoc-locust 2>/dev/null || true
}
trap _cleanup_phase_containers EXIT

# ── Prerequisite: admin-api venv must exist ───────────────────────────────────
if [ ! -d "admin-api/.venv" ]; then
  echo "❌ admin-api/.venv not found. Create it first:"
  echo "   python3 -m venv admin-api/.venv"
  echo "   source admin-api/.venv/bin/activate"
  echo "   pip install -e 'admin-api/.[dev]'"
  exit 1
fi

# ── Phase 2: revoc-core ───────────────────────────────────────────────────────
cargo test -p revoc-core -- --nocapture 2>&1 | grep -E "test .* ok|FAILED"
cargo clippy -p revoc-core -- -D warnings
cargo doc -p revoc-core --no-deps

# Verify: PolicyRuleTier has 5 variants, CallerContext has governance_depth: u8
grep -q "governance_depth" crates/revoc-core/src/ -r \
  && echo "✅ governance_depth present" || echo "❌ governance_depth missing"

# ── Phase 3: revoc-config ─────────────────────────────────────────────────────
cargo test -p revoc-config -- --nocapture
cargo clippy -p revoc-config -- -D warnings

# ── Phase 4: revoc-telemetry ──────────────────────────────────────────────────
cargo test -p revoc-telemetry -- --nocapture
cargo clippy -p revoc-telemetry -- -D warnings

# ── Phase 5: revoc-detector ───────────────────────────────────────────────────
# Normalization MUST pass first — it is required before any regex detection
cargo test -p revoc-detector normalization -- --nocapture
# ALL normalization tests must pass: NFKC, zero-width, RTLO, idempotency
# Spot-check: "ＤＲＯＰTable" → DDL detected after normalization
cargo test -p revoc-detector manifest -- --nocapture
cargo test -p revoc-detector redos -- --nocapture
# ReDoS guard: all patterns < 10ms on 1KB of 'a'
cargo test -p revoc-detector -- --nocapture 2>&1 | grep -E "FAILED|ok" | tail -10
cargo clippy -p revoc-detector -- -D warnings

# ── Phase 6: revoc-pipeline ───────────────────────────────────────────────────
cargo test -p revoc-pipeline -- --nocapture
cargo clippy -p revoc-pipeline -- -D warnings

# ── Phase 7: revoc-policy ────────────────────────────────────────────────────
cargo build -p revoc-policy   # build.rs validates Rego stub files exist
cargo test -p revoc-policy conflict -- --nocapture
# Security rule must always win over custom allow (D12)
cargo test -p revoc-policy -- --nocapture
cargo clippy -p revoc-policy -- -D warnings

# ── Phase 8: revoc-redaction ──────────────────────────────────────────────────
cargo test -p revoc-redaction -- --nocapture
cargo clippy -p revoc-redaction -- -D warnings

# ── Phase 9: revoc-dashboard ──────────────────────────────────────────────────
cd crates/revoc-dashboard/ui
npm install
npm run build
ls dist/index.html   # Must exist and be non-empty
cd "$REPO_ROOT"
cargo build -p revoc-dashboard
cargo test -p revoc-dashboard -- --nocapture
cargo clippy -p revoc-dashboard -- -D warnings
# dist/ must be tracked in git (SPEC.md §6)
git ls-files crates/revoc-dashboard/ui/dist/index.html | grep -q "index.html" \
  && echo "✅ dist/index.html committed" || echo "❌ dist/index.html NOT in git"

# ── Phase 10: revoc-proxy ─────────────────────────────────────────────────────
cargo build --workspace --release
cargo test --workspace 2>&1 | tail -30
cargo clippy --workspace -- -D warnings
./target/release/revoc-proxy validate-config --config configs/revoc.dev.toml
./target/release/revoc-proxy version
# emergency status requires a live proxy on :8081; expected to fail here (no proxy running)
./target/release/revoc-proxy emergency status \
  && echo "✅ emergency status" \
  || echo "⚠️  emergency status (Connection refused — proxy not running, expected in CI)"
cargo test -p revoc-proxy kill_switch -- --nocapture   # All pass
cargo test -p revoc-proxy depth -- --nocapture         # All pass

# ── Phase 11: Rego policies ───────────────────────────────────────────────────
cargo build -p revoc-policy   # include_str! with real (non-stub) Rego content
if command -v opa >/dev/null 2>&1; then
  opa check policies/ --strict
  opa test policies/ -v --coverage
  # Target: 100% coverage for all policy packages
else
  echo "⚠️  opa not installed — Rego semantic check skipped"
fi

# ── Phase 12-14: Admin API ────────────────────────────────────────────────────
cd admin-api
source .venv/bin/activate
pip install -e ".[dev]"

# Verify locust is now installed (added in Phase 19 / dev deps)
locust --version && echo "✅ locust installed" || echo "❌ locust not found — check pyproject.toml"

python3 -c "from app.core.config import get_settings; print(get_settings().environment)"
python3 -c "
from app.core.security import hash_password, verify_password
h = hash_password('test')
print(verify_password('test', h))
"
ruff check app/core/ && mypy app/core/ --strict
ruff check app/ && mypy app/ --strict
python3 -c "from app.services.compiler_service import PolicyCompilerService; print('✅ compiler_service')"
python3 -c "from app.models.policy import PolicyBundle; print('✅ PolicyBundle model')"
alembic upgrade head
pytest tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=85
ruff check . && mypy app/ --strict

deactivate
cd "$REPO_ROOT"

# ── Phase 15: Python SDK ──────────────────────────────────────────────────────
cd sdk/python
source "$REPO_ROOT/admin-api/.venv/bin/activate"
pip install -e .
python3 -c "from revoc_sdk import RevocOpenAI; print('✅ RevocOpenAI importable')"
REVOC_BASE_URL=http://localhost:8080 python3 -c "
from revoc_sdk.patch import patch
patch()
import openai
c = openai.OpenAI(api_key='t')
print(c.base_url)
"
deactivate
cd "$REPO_ROOT"

# ── Phase 15: Node SDK ────────────────────────────────────────────────────────
cd sdk/node
npm install
npm run build
npm test
cd "$REPO_ROOT"

# ── Phase 16: Docker ──────────────────────────────────────────────────────────
cd docker
docker compose config
docker compose build
cd "$REPO_ROOT"

# Single-container smoke test
IMG=$(docker build -q -f crates/revoc-proxy/Dockerfile .)
docker run -d -p 8080:8080 -p 3000:3000 -p 8081:8081 \
  -e REVOC_AUTH__MODE=none -e REVOC_UPSTREAM__MOCK_MODE=true \
  --name revoc-sc "$IMG"
sleep 8
curl -sf http://localhost:8080/health | jq .
curl -s http://localhost:3000/ | head -2
docker rm -f revoc-sc

# Compose smoke (docker-compose.yml — dev/prod stack, no test wiremocks)
# /ready probes the audit store (real DB query) so the proxy may not be ready
# immediately after the container starts — postgres init + connection pool
# setup takes a few seconds.  Retry for up to 60s before declaring failure.
make up
_ready_ok=0
for _i in $(seq 1 30); do
  READY_STATUS=$(curl -sf http://localhost:8080/ready 2>/dev/null | jq -r '.status // empty' 2>/dev/null || true)
  if [ "$READY_STATUS" = "ready" ]; then
    _ready_ok=1
    break
  fi
  sleep 2
done
[ "$_ready_ok" = "1" ] \
  && echo "✅ /ready → ready (compose stack)" \
  || echo "❌ /ready failed or not 'ready' after 60s: $READY_STATUS"
make down

# Kill-switch smoke (D11)
IMG=$(docker build -q -f crates/revoc-proxy/Dockerfile .)
docker run -d -p 8080:8080 -p 3000:3000 -p 8081:8081 \
  -e REVOC_AUTH__MODE=none -e REVOC_UPSTREAM__MOCK_MODE=true \
  --name ks-test "$IMG"
sleep 8
curl -sf http://localhost:8080/health | jq .   # Expected: status=ok

# Activate kill-switch
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "X-Admin-Key: dev-admin-key" -H "Content-Type: application/json" \
  -d '{"scope":"global","reason":"test","activated_by":"test"}' | jq .

# Traffic must be blocked
KS_CODE=$(curl -s -X POST http://localhost:8080/v1/chat/completions \
  -d '{}' | jq -r '.error.code // empty')
[ "$KS_CODE" = "REVOC_KILL_SWITCH_ACTIVE" ] \
  && echo "✅ Kill-switch blocks traffic" \
  || echo "❌ Expected REVOC_KILL_SWITCH_ACTIVE, got: $KS_CODE"

# Health must still pass during kill-switch
H=$(curl -sf http://localhost:8080/health | jq -r '.status')
[ "$H" = "ok" ] && echo "✅ /health bypasses kill-switch" \
  || echo "❌ /health should not be blocked by kill-switch"

# Deactivate
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/deactivate \
  -H "X-Admin-Key: dev-admin-key" -H "Content-Type: application/json" \
  -d '{"scope":"global"}' | jq .

docker rm -f ks-test

# ── Phase 17: Helm ────────────────────────────────────────────────────────────
helm dependency build helm/revoc/ 2>/dev/null || true
helm lint helm/revoc/
helm template revoc helm/revoc/ --debug > /dev/null
if command -v kubectl >/dev/null 2>&1; then
  helm template revoc helm/revoc/ | kubectl apply --dry-run=client -f -
  helm template revoc helm/revoc/ -f helm/revoc/values.production.yaml \
    | kubectl apply --dry-run=client -f -
else
  echo "⚠️  kubectl not available — helm dry-run skipped"
fi

# ── Phase 18: Integration tests ───────────────────────────────────────────────
# The conftest fixture (docker_stack) manages the compose stack automatically.
# Do NOT run `make up` first — it uses docker-compose.yml on the same ports (8080/3000/8081)
# as docker-compose.test.yml and will cause a bind conflict.
source admin-api/.venv/bin/activate
pip install -e "admin-api/.[dev]" -q   # Ensures locust is present
pytest tests/integration/ -v --tb=short 2>&1 | tail -60
# 0 FAILED required
deactivate

# ── Phase 18b: E2E governance journey tests ───────────────────────────────────
# Full black-box test against a live single-container stack (mock_mode=true).
# Requires ghcr.io/revoc-ai/revoc:beta to be published. Skipped if unavailable.
# _cleanup_phase_containers EXIT trap (registered at script top) removes revoc-e2e.
docker rm -f revoc-e2e revoc-locust 2>/dev/null || true
if docker pull ghcr.io/revoc-ai/revoc:beta 2>/dev/null; then
  docker run -d --name revoc-e2e \
    -p 8080:8080 -p 3000:3000 -p 8081:8081 \
    -e REVOC_AUTH__MODE=none \
    -e REVOC_UPSTREAM__MOCK_MODE=true \
    -e REVOC_DASHBOARD__AUTH_MODE=none \
    -e REVOC_POLICY__DECISION_CACHE_TTL_SECS=0 \
    ghcr.io/revoc-ai/revoc:beta
  _E2E_CONTAINER_STARTED=1

  # Wait for readiness (up to 60s)
  for _i in $(seq 1 30); do
    curl -sf http://localhost:8080/health > /dev/null 2>&1 && break || sleep 2
  done
  curl -sf http://localhost:8080/health | jq -r '.status'   # Must print: ok

  source admin-api/.venv/bin/activate
  pip install -e "admin-api/.[dev]" -q
  pytest tests/e2e/ -v --tb=short 2>&1 | tail -40
  # 0 FAILED required
  deactivate

  docker rm -f revoc-e2e 2>/dev/null || true
  _E2E_CONTAINER_STARTED=0
else
  echo "⚠️  ghcr.io/revoc-ai/revoc:beta unavailable — Phase 18b E2E tests skipped (image not yet published)"
fi

# ── Phase 18c: Locust load test ───────────────────────────────────────────────
# End-to-end throughput signal. Proxy must be running with mock_mode=true.
# Requires ghcr.io/revoc-ai/revoc:beta to be published. Skipped if unavailable.
# _cleanup_phase_containers EXIT trap (registered at script top) removes revoc-locust.
# revoc-e2e was removed above so ports 8080/3000/8081 are free.
docker rm -f revoc-locust 2>/dev/null || true
if docker pull ghcr.io/revoc-ai/revoc:beta 2>/dev/null; then
  docker run -d --name revoc-locust \
    -p 8080:8080 -p 3000:3000 -p 8081:8081 \
    -e REVOC_AUTH__MODE=none \
    -e REVOC_UPSTREAM__MOCK_MODE=true \
    -e REVOC_DASHBOARD__AUTH_MODE=none \
    ghcr.io/revoc-ai/revoc:beta
  _LOCUST_CONTAINER_STARTED=1

  for _i in $(seq 1 30); do
    curl -sf http://localhost:8080/health > /dev/null 2>&1 && break || sleep 2
  done

  mkdir -p tests/load/results
  source admin-api/.venv/bin/activate
  pip install -e "admin-api/.[dev]" -q
  locust -f tests/load/locustfile.py \
    --headless \
    --host http://localhost:8080 \
    -u 50 -r 10 \
    --run-time 60s \
    --csv tests/load/results/phase18c \
    2>&1 | tail -20
  # Inspect results: grep "Aggregated" tests/load/results/phase18c_stats.csv
  deactivate

  docker rm -f revoc-locust 2>/dev/null || true
  _LOCUST_CONTAINER_STARTED=0
else
  echo "⚠️  ghcr.io/revoc-ai/revoc:beta unavailable — Phase 18c Locust tests skipped (image not yet published)"
fi

# ── Phase 19: Benchmarks + Fuzz ──────────────────────────────────────────────
cargo bench --workspace -- --test   # dry-run compile of all criterion benches

rustup toolchain install nightly --no-self-update 2>&1 | tail -1
if command -v cargo-fuzz >/dev/null 2>&1; then
  cargo +nightly fuzz build 2>&1 | tail -5
  cargo +nightly fuzz run fuzz_normalization -- -max_total_time=30
  cargo +nightly fuzz run fuzz_detector_input -- -max_total_time=30
else
  echo "⚠️  cargo-fuzz not installed — installing..."
  cargo +nightly install cargo-fuzz --locked 2>/dev/null || true
  for t in fuzz/fuzz_targets/*.rs; do
    name=$(basename "$t" .rs)
    cargo +nightly check --manifest-path fuzz/Cargo.toml --bin "$name" 2>&1 | tail -1 || true
  done
fi

# Load SLO pytest (proxy overhead via X-Revoc-Timing header — not wall-clock round-trip)
# Requires a proxy on :8080 with mock_mode=true.
# Phase 18c cleaned up revoc-locust; start a fresh one for this measurement.
docker rm -f revoc-slo 2>/dev/null || true
docker run -d --name revoc-slo \
  -p 8080:8080 -p 3000:3000 -p 8081:8081 \
  -e REVOC_AUTH__MODE=none \
  -e REVOC_UPSTREAM__MOCK_MODE=true \
  ghcr.io/revoc-ai/revoc:beta
for _i in $(seq 1 30); do
  curl -sf http://localhost:8080/health > /dev/null 2>&1 && break || sleep 2
done
source admin-api/.venv/bin/activate
pip install -e "admin-api/.[dev]" -q
pytest tests/load/test_latency_slo.py -v -s 2>&1 | tail -20; _SLO_STATUS=$?
deactivate
docker rm -f revoc-slo 2>/dev/null || true
[ "$_SLO_STATUS" -eq 0 ] && echo "✅ Load SLO tests passed" || echo "❌ Load SLO tests FAILED"

# ── Phase 20: MkDocs documentation ───────────────────────────────────────────
if command -v mkdocs >/dev/null 2>&1; then
  cd docs
  mkdocs build --strict
  ls site/index.html
  cd "$REPO_ROOT"
else
  echo "⚠️  mkdocs not installed — pip install mkdocs mkdocs-material"
fi
