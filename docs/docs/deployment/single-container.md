# Single Container Deployment (Tier 1)

The single-container deployment runs the proxy, dashboard, and admin API in one
Docker container with SQLite for audit storage. No external dependencies.

## Quick Start

```bash
docker run -d \
  -p 8080:8080 \
  -p 3000:3000 \
  -p 127.0.0.1:8081:8081 \
  -e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 \
  -e REVOC_ADMIN_KEY=$REVOC_ADMIN_KEY \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -v revoc-data:/var/lib/revoc \
  --name revoc \
  ghcr.io/revoc-ai/revoc:beta
```

Verify:

```bash
curl -s http://localhost:8080/health | python3 -m json.tool
```

## Persistent Storage

Mount a volume for the SQLite database to survive container restarts:

```bash
docker run -d \
  -p 8080:8080 -p 3000:3000 -p 127.0.0.1:8081:8081 \
  -e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 -e REVOC_ADMIN_KEY=$REVOC_ADMIN_KEY \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -v /opt/revoc/data:/var/lib/revoc \
  --name revoc \
  ghcr.io/revoc-ai/revoc:beta
```

The SQLite database is written to `/var/lib/revoc/revoc-audit.db`.

## Environment Variables for Single Container

```bash
docker run -d \
  -p 8080:8080 -p 3000:3000 -p 127.0.0.1:8081:8081 \
  -e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 -e REVOC_ADMIN_KEY=$REVOC_ADMIN_KEY \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e REVOC_AUTH__MODE=apikey \
  -e REVOC_API_KEYS=revoc_k_mykey1,revoc_k_mykey2 \
  -e REVOC_TELEMETRY__LOG_LEVEL=info \
  -e REVOC_SERVER__ENVIRONMENT=production \
  -v revoc-data:/var/lib/revoc \
  --name revoc \
  ghcr.io/revoc-ai/revoc:beta
```

## Mock Mode (No API Key Required)

For development and testing:

```bash
docker run -d \
  -p 8080:8080 -p 3000:3000 -p 127.0.0.1:8081:8081 \
  -e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 -e REVOC_ADMIN_KEY=$REVOC_ADMIN_KEY \
  -e REVOC_UPSTREAM__MOCK_MODE=true \
  -e REVOC_AUTH__MODE=none \
  --name revoc-dev \
  ghcr.io/revoc-ai/revoc:beta
```

## Resource Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 1 core | 2 cores |
| Memory | 256 MB | 512 MB (2 GB with ONNX enabled) |
| Disk | 1 GB | 10 GB (for 90-day audit log at 10K req/day) |

## Upgrade

```bash
docker pull ghcr.io/revoc-ai/revoc:beta
docker stop revoc
docker rm revoc
docker run -d -p 8080:8080 -p 3000:3000 -p 127.0.0.1:8081:8081 \
-e REVOC_SERVER__INTERNAL_HOST=0.0.0.0 -e REVOC_ADMIN_KEY=$REVOC_ADMIN_KEY \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -v revoc-data:/var/lib/revoc \
  --name revoc \
  ghcr.io/revoc-ai/revoc:beta
```

Migrations run automatically on startup. Downtime is limited to the container
restart time (~2–5 seconds).

## Limitations

| Feature | Single Container | Tier 2/3 |
|---|---|---|
| Kill-switch multi-instance propagation | Local only | Redis pub/sub (~50ms) |
| Session tracking across restarts | Lost on restart | Redis (persisted) |
| Policy decision cache | In-process memory | Redis (shared) |
| Audit storage | SQLite (single file) | Postgres (HA) |
| Horizontal scaling | Not supported | Supported (Helm) |

Move to [Tier 2 (Docker Compose)](docker-compose.md) when you need persistent
Redis-backed session tracking or multi-instance deployments.
