# ── Stage 1: cargo-chef planner ───────────────────────────────────────────────
# Track the same `stable` channel declared in rust-toolchain.toml so the
# Docker build compiles with the identical toolchain as local/CI builds —
# avoids drift (and the `edition2024`-vs-pinned-Cargo mismatches that crop up
# when the image lags behind the project's actual toolchain).
FROM rust:slim-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: compute recipe ───────────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: build dependencies (cached layer) ───────────────────────────────
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build the actual binary
COPY . .
RUN cargo build --release --bin revoc-proxy

# ── Stage 4: distroless runtime ───────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="REVOC Proxy"
LABEL org.opencontainers.image.description="Runtime Execution Validation & Observability Control"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/revoc-ai/revoc"

# Copy the binary
COPY --from=builder /app/target/release/revoc-proxy /revoc-proxy

# Copy default policies (embedded at runtime)
COPY --from=builder /app/policies/default /policies/default

# Expose: proxy (8080), dashboard (3000), Prometheus metrics (9090)
EXPOSE 8080 3000 9090

# Run as non-root (distroless nonroot UID=65532)
USER nonroot

# Default to "development" so a bare `docker run` (single-container smoke
# test / Tier 1 quickstart) can run with auth.mode=none out of the box.
# docker-compose.yml overrides this to "production" via env_file — this
# default only takes effect when no explicit environment is supplied.
ENV REVOC_SERVER__ENVIRONMENT=development

# Development-only default admin key for the internal emergency/kill-switch
# API (port 8081) — lets the bare `docker run` smoke test exercise
# /internal/emergency/kill-switch/* without extra setup. Production deploys
# (docker-compose.yml / Helm) MUST override this via REVOC_AUTH__ADMIN_KEY
# (or REVOC_ADMIN_KEY) with a strong, randomly generated secret.
ENV REVOC_AUTH__ADMIN_KEY=dev-admin-key

ENTRYPOINT ["/revoc-proxy", "serve"]
