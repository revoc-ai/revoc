# ─────────────────────────────────────────────────────────────────────────────
# REVOC Admin API (revoc-gateway) — multi-stage Python 3.12 image.
#
# Stage 1 builds the wheel + resolves dependencies into a virtualenv;
# Stage 2 copies only the venv and source into a slim runtime image and
# drops privileges to the unprivileged `nobody` user before serving with
# uvicorn's FastAPI factory pattern (4 workers).
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# weasyprint (PDF report generation) needs Pango/Cairo at build AND run time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml ./
COPY app ./app
COPY alembic.ini ./
COPY alembic ./alembic

RUN pip install --upgrade pip && pip install .

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="REVOC Admin API"
LABEL org.opencontainers.image.description="Policy management, audit, and emergency controls for REVOC"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/revoc-ai/revoc"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/app ./app
COPY --from=builder /build/alembic.ini ./
COPY --from=builder /build/alembic ./alembic

# Run as the unprivileged `nobody` user (uid 65534) — no dedicated user
# creation needed since the base image already provides it.
RUN chown -R nobody:nogroup /app
USER nobody

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=20s \
    CMD curl -f http://localhost:8001/api/v1/health || exit 1

ENTRYPOINT ["uvicorn", "app.main:create_app", "--factory", \
            "--host", "0.0.0.0", "--port", "8001", "--workers", "4"]
