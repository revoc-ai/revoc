# ─────────────────────────────────────────────────────────────────────────────
# REVOC — Runtime Execution Validation & Observability Control
# Apache 2.0 — https://revoc.io
# ─────────────────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
.PHONY: help build build-release test test-coverage lint fmt fmt-check \
        bench fuzz doc docker-build docker-build-ml docker-push \
        up up-dev up-obs down logs ps clean clean-all \
        opa-test helm-lint helm-package mkdocs-serve mkdocs-build \
        sdk-build-python sdk-build-node sdk-build-all \
        integration-test e2e-test load-slo locust-test migrate validate-config generate-key \
        emergency-activate emergency-deactivate emergency-status \
        release-patch release-minor release-major notice

# ─────────────────────────────────────────────────────────────────────────────
# Variables
# ─────────────────────────────────────────────────────────────────────────────
REGISTRY      ?= ghcr.io/revoc-ai
IMAGE_PROXY   := $(REGISTRY)/revoc
IMAGE_ML      := $(REGISTRY)/revoc:latest-ml
VERSION       ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0-dev")
COMMIT        := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
ADMIN_KEY     ?= dev-admin-key-local-only
REVOC_URL     ?= http://localhost:8080
INTERNAL_URL  ?= http://localhost:8081

## ─── Build ──────────────────────────────────────────────────────────────────

## Build all workspace crates in debug mode
build:
	cargo build --workspace

## Build all workspace crates in release mode
build-release:
	cargo build --workspace --release

## ─── Test ───────────────────────────────────────────────────────────────────

## Run all workspace tests (uses cargo-nextest if available, falls back to cargo test)
test:
	@if command -v cargo-nextest >/dev/null 2>&1 || cargo nextest --version >/dev/null 2>&1; then \
		cargo nextest run --workspace; \
	else \
		cargo test --workspace; \
	fi

## Run tests with coverage (requires cargo-llvm-cov)
test-coverage:
	cargo llvm-cov --workspace --lcov --output-path lcov.info
	cargo llvm-cov --workspace --open

## ─── Quality ────────────────────────────────────────────────────────────────

## Run Clippy across the workspace; treats warnings as errors
lint:
	cargo clippy --workspace -- -D warnings

## Format all Rust source files
fmt:
	cargo fmt --all

## Check formatting without modifying files (used in CI)
fmt-check:
	cargo fmt --all -- --check

## ─── Performance ────────────────────────────────────────────────────────────

## Run all criterion benchmarks and generate HTML reports
bench:
	cargo bench --workspace

## Run all fuzz targets for 60 seconds each (requires cargo-fuzz)
fuzz:
	@for target in $$(cargo fuzz list 2>/dev/null); do \
		echo "Fuzzing $$target for 60s..."; \
		cargo fuzz run $$target -- -max_total_time=60; \
	done

## ─── Documentation ──────────────────────────────────────────────────────────

## Build Rust API documentation and open in browser
doc:
	cargo doc --workspace --no-deps --open

## Serve MkDocs documentation site locally at http://localhost:8000
mkdocs-serve:
	mkdocs serve

## Build MkDocs documentation site for deployment
mkdocs-build:
	mkdocs build --strict

## ─── Docker ─────────────────────────────────────────────────────────────────

## Build the standard proxy Docker image
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE_PROXY):latest \
		-t $(IMAGE_PROXY):$(VERSION) \
		-f crates/revoc-proxy/Dockerfile .

## Build the ML-enabled proxy Docker image (includes ONNX runtime)
docker-build-ml:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg ML_ENABLED=true \
		-t $(IMAGE_ML) \
		-f crates/revoc-proxy/Dockerfile.ml .

## Push both proxy images to the container registry
docker-push:
	docker push $(IMAGE_PROXY):latest
	docker push $(IMAGE_PROXY):$(VERSION)
	docker push $(IMAGE_ML)

## ─── Compose ────────────────────────────────────────────────────────────────

## Start full stack (proxy + postgres + redis + dashboard) in detached mode
up:
	docker compose -f docker/docker-compose.yml up -d --build

## Start development stack (mock upstream, sqlite, pretty logs)
up-dev:
	docker compose -f docker/docker-compose.dev.yml up -d --build

## Start observability stack (adds Prometheus + Grafana + Tempo)
up-obs:
	docker compose -f docker/docker-compose.yml \
		-f docker/docker-compose.observability.yml up -d --build

## Stop and remove all containers from the current compose stack
down:
	docker compose -f docker/docker-compose.yml down

## Tail logs from all running compose services
logs:
	docker compose -f docker/docker-compose.yml logs -f

## Show status of all compose services
ps:
	docker compose -f docker/docker-compose.yml ps

## ─── Policy ─────────────────────────────────────────────────────────────────

## Run all OPA policy unit tests in policies/
opa-test:
	opa test policies/ -v --coverage

## ─── Helm ───────────────────────────────────────────────────────────────────

## Lint the Helm chart for template errors
helm-lint:
	helm lint helm/revoc/

## Package the Helm chart into a .tgz archive
helm-package:
	helm package helm/revoc/ --destination dist/

## ─── SDK ─────────────────────────────────────────────────────────────────────

## Build and install the Python SDK in editable mode
sdk-build-python:
	cd sdk/python && pip install -e ".[dev]"

## Build the Node.js SDK (TypeScript → JavaScript)
sdk-build-node:
	cd sdk/node && npm install && npm run build

## Build all SDKs
sdk-build-all: sdk-build-python sdk-build-node

## ─── Integration & Load Testing ─────────────────────────────────────────────

## Run integration tests. The test fixture manages its own docker-compose.test.yml stack
## automatically — do NOT run `make up` first (both stacks bind ports 8080/3000/8081).
integration-test:
	. admin-api/.venv/bin/activate && pip install -e "admin-api/.[dev]" -q && \
	pytest tests/integration/ -v --tb=short

## Run E2E governance journey tests against a live single-container stack.
## Starts ghcr.io/revoc-ai/revoc:beta in mock mode, runs tests, then removes it.
e2e-test:
	docker rm -f revoc-e2e 2>/dev/null || true
	docker run -d --name revoc-e2e \
		-p 8080:8080 -p 3000:3000 -p 127.0.0.1:8081:8081 -e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 -e REVOC_ADMIN_KEY=$(ADMIN_KEY) \
		-e REVOC_AUTH__MODE=none \
		-e REVOC_UPSTREAM__MOCK_MODE=true \
		-e REVOC_DASHBOARD__AUTH_MODE=none \
		-e REVOC_POLICY__DECISION_CACHE_TTL_SECS=0 \
		ghcr.io/revoc-ai/revoc:beta
	sleep 10
	. admin-api/.venv/bin/activate && pip install -e "admin-api/.[dev]" -q && \
	pytest tests/e2e/ -v --tb=short; \
	STATUS=$$?; docker rm -f revoc-e2e; exit $$STATUS

## Run proxy overhead SLO tests (pytest, measures via X-Revoc-Timing header).
## SPEC.md §3 Principle 2: P95 < 10ms, P99 < 25ms.
## Requires a proxy on :8080 with mock_mode=true (start with: make e2e-test or docker run).
load-slo:
	. admin-api/.venv/bin/activate && pip install -e "admin-api/.[dev]" -q && \
	pytest tests/load/test_latency_slo.py -v -s

## Run Locust load test (50 users, 10/s ramp, 60s, headless).
## Requires a proxy on :8080 with mock_mode=true (start with: make e2e-test or docker run).
locust-test:
	. admin-api/.venv/bin/activate && pip install -e "admin-api/.[dev]" -q && \
	locust -f tests/load/locustfile.py --headless --host http://localhost:8080 \
		-u 50 -r 10 --run-time 60s

## ─── Operations ──────────────────────────────────────────────────────────────

## Run database migrations (SQLite by default; set DATABASE_URL for Postgres)
migrate:
	cargo run --bin revoc-proxy -- migrate

## Validate the production config file
validate-config:
	cargo run --bin revoc-proxy -- validate-config --config configs/revoc.toml

## Generate a new API key with an optional LABEL (e.g. make generate-key LABEL=ci-runner)
generate-key:
	cargo run --bin revoc-proxy -- generate-key --label "$(LABEL)"

## Activate the emergency kill-switch (SCOPE: global|org|caller; REASON required)
## Example: make emergency-activate SCOPE=global REASON="active incident"
emergency-activate:
	curl -s -X POST $(INTERNAL_URL)/internal/emergency/kill-switch/activate \
		-H "X-Admin-Key: $(ADMIN_KEY)" \
		-H "Content-Type: application/json" \
		-d '{"scope":"$(SCOPE)","reason":"$(REASON)","activated_by":"operator"}' | jq .

## Deactivate the emergency kill-switch (SCOPE: global|org|caller)
## Example: make emergency-deactivate SCOPE=global
emergency-deactivate:
	curl -s -X POST $(INTERNAL_URL)/internal/emergency/kill-switch/deactivate \
		-H "X-Admin-Key: $(ADMIN_KEY)" \
		-H "Content-Type: application/json" \
		-d '{"scope":"$(SCOPE)"}' | jq .

## Show current kill-switch status across all scopes
emergency-status:
	curl -s -H "X-Admin-Key: $(ADMIN_KEY)" $(INTERNAL_URL)/internal/emergency/kill-switch/status | jq .

## ─── Release ─────────────────────────────────────────────────────────────────

## Bump patch version, tag, and generate CHANGELOG entry
release-patch:
	cargo release patch --execute

## Bump minor version, tag, and generate CHANGELOG entry
release-minor:
	cargo release minor --execute

## Bump major version, tag, and generate CHANGELOG entry
release-major:
	cargo release major --execute

## ─── Maintenance ─────────────────────────────────────────────────────────────

## Regenerate NOTICE file with full dependency attribution (requires cargo-about)
notice:
	cargo about generate about.hbs > NOTICE

## Remove Rust build artifacts (target/ directory)
clean:
	cargo clean

## Remove ALL generated artifacts: target/, dist/, site/, lcov.info, *.db
clean-all: clean
	rm -rf dist/ site/ lcov.info *.db htmlcov/ .coverage

## ─── Help ────────────────────────────────────────────────────────────────────

## Show this help message
help:
	@echo ""
	@echo "  REVOC — Runtime Execution Validation & Observability Control"
	@echo "  ──────────────────────────────────────────────────────────────"
	@awk '{ \
		if (/^## /) { desc=substr($$0,4) } \
		else if (/^[a-zA-Z_-]+:/ && desc) { \
			printf "  \033[36m%-25s\033[0m %s\n", $$1, desc; \
			desc="" \
		} \
	}' $(MAKEFILE_LIST)
	@echo ""
