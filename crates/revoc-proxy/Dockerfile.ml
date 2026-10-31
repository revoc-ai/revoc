# ML-enabled image — adds ONNX Runtime for on-device NER inference.
#
# Differences from the base Dockerfile:
#   * Installs libgomp1 (OpenMP — required by ONNX Runtime shared library)
#   * Builds with ML_ENABLED=1 so the ort feature is compiled in
#   * Ships a Debian-slim runtime (instead of distroless) so libgomp1 is
#     available at run time; the ONNX Runtime .so is loaded dynamically via
#     the ort crate's load-dynamic feature
#   * Bundles the bundled ONNX Runtime shared library from the ort-sys crate
#
# Usage:
#   docker run -p 8080:8080 -p 3000:3000 \
#     -e REVOC_DETECTION__ONNX_ENABLED=true \
#     -e REVOC_DETECTION__ONNX_MODEL_PATH=/models/bert-base-ner.onnx \
#     -v $(pwd)/models:/models \
#     ghcr.io/revoc-ai/revoc:latest-ml

# ── Stage 1: cargo-chef planner ───────────────────────────────────────────────
FROM rust:slim-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libgomp1 && \
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

# Enable the onnx feature so ort is compiled in
ENV ML_ENABLED=1
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --bin revoc-proxy

# ── Stage 4: slim runtime with OpenMP support ────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r revoc && useradd -r -g revoc -u 65532 revoc

LABEL org.opencontainers.image.title="REVOC Proxy (ML)"
LABEL org.opencontainers.image.description="REVOC with ONNX Runtime for on-device NER inference"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/revoc-ai/revoc"

COPY --from=builder /app/target/release/revoc-proxy /usr/local/bin/revoc-proxy
COPY --from=builder /app/policies/default /policies/default

# models/ directory for mounting ONNX model and tokenizer
RUN mkdir -p /models && chown revoc:revoc /models

EXPOSE 8080 3000 9090

USER revoc

ENV REVOC_SERVER__ENVIRONMENT=development
ENV REVOC_AUTH__ADMIN_KEY=dev-admin-key
ENV REVOC_DETECTION__ONNX_ENABLED=false

ENTRYPOINT ["/usr/local/bin/revoc-proxy", "serve"]
