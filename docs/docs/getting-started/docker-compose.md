# Team Deployment — Docker Compose

Docker Compose adds Postgres for persistent audit storage and Redis for kill-switch
propagation and policy caching. Use this for shared team environments or single-node
production with external database requirements.

## Prerequisites

- Docker Compose v2.20+ (`docker compose version`)
- An OpenAI API key (or set `REVOC_UPSTREAM__MOCK_MODE=true` for testing)

## Quick Start

```bash
curl -O https://raw.githubusercontent.com/revoc-ai/revoc/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/revoc-ai/revoc/main/.env.example
cp .env.example .env
# Edit .env: set OPENAI_API_KEY and REVOC_JWT_SECRET
docker compose up -d
```

Verify all services are healthy:

```bash
docker compose ps
```

Expected output:

```
NAME               IMAGE                           STATUS
revoc-proxy        ghcr.io/revoc-ai/revoc:beta   running (healthy)
revoc-postgres     postgres:16-alpine              running (healthy)
revoc-redis        redis:7-alpine                  running (healthy)
```

Check proxy health:

```bash
curl -s http://localhost:8080/health | python3 -m json.tool
```

## docker-compose.yml

```yaml
version: "3.9"

services:
  proxy:
    image: ghcr.io/revoc-ai/revoc:beta
    container_name: revoc-proxy
    ports:
      - "8080:8080"
      - "3000:3000"
      - "8081:8081"
    environment:
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
      DATABASE_URL: postgres://revoc:revoc@postgres:5432/revoc
      REDIS_URL: redis://redis:6379
      REVOC_STORAGE__BACKEND: postgres
      REVOC_CACHE__BACKEND: redis
      REVOC_AUTH__MODE: ${REVOC_AUTH_MODE:-apikey}
      REVOC_AUTH__JWT_SECRET_ENV: REVOC_JWT_SECRET
      REVOC_JWT_SECRET: ${REVOC_JWT_SECRET}
      REVOC_TELEMETRY__LOG_LEVEL: ${LOG_LEVEL:-info}
      REVOC_SERVER__ENVIRONMENT: ${ENVIRONMENT:-production}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 5

  postgres:
    image: postgres:16-alpine
    container_name: revoc-postgres
    environment:
      POSTGRES_USER: revoc
      POSTGRES_PASSWORD: revoc
      POSTGRES_DB: revoc
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U revoc"]
      interval: 5s
      timeout: 3s
      retries: 10

  redis:
    image: redis:7-alpine
    container_name: revoc-redis
    command: redis-server --save 60 1 --loglevel warning
    volumes:
      - redis_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  postgres_data:
  redis_data:
```

## .env.example

```bash
# Required
OPENAI_API_KEY=sk-your-key-here
REVOC_JWT_SECRET=change-this-to-a-random-64-char-string

# Optional
ANTHROPIC_API_KEY=
LOG_LEVEL=info
ENVIRONMENT=production
REVOC_AUTH_MODE=apikey
```

## Running Database Migrations

Migrations run automatically on startup (`migrations_auto_run = true` by default).
To run them manually:

```bash
docker compose exec proxy revoc-proxy migrate
```

## Stopping and Cleanup

```bash
# Stop without removing volumes (data preserved)
docker compose down

# Stop and remove all volumes (full reset)
docker compose down -v
```

## Scaling the Proxy

The kill-switch uses Redis pub/sub so all instances receive activation within ~50ms:

```bash
docker compose up -d --scale proxy=3
```

!!! warning
    Use a load balancer (nginx, Traefik) in front of multiple proxy instances.
    Each instance binds to the same ports — scaling requires port remapping.
