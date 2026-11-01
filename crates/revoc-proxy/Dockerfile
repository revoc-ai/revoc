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
# Writable data directory for the SQLite audit DB (distroless has no shell).
RUN mkdir -p /data

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

# SQLite audit DB lives in /data, owned by the nonroot user. Mount a volume
# here to keep audit history across container restarts.
COPY --from=builder --chown=65532:65532 /data /data
WORKDIR /data
ENV REVOC_STORAGE__SQLITE_PATH=/data/revoc-audit.db
VOLUME ["/data"]

# Expose: proxy (8080), dashboard (3000), Prometheus metrics (9090)
EXPOSE 8080 3000 9090

# Run as non-root (distroless nonroot UID=65532)
USER nonroot

# Default to "development" so a bare `docker run` (single-container smoke
# test / Tier 1 quickstart) can run with auth.mode=none out of the box.
# docker-compose.yml overrides this to "production" via env_file — this
# default only takes effect when no explicit environment is supplied.
ENV REVOC_SERVER__ENVIRONMENT=development

# No admin key is baked in: the internal API (port 8081, loopback-only by
# default) rejects every request until REVOC_ADMIN_KEY is set at run time.

ENTRYPOINT ["/revoc-proxy", "serve"]
