# Docker Compose Deployment (Tier 2)

See [Getting Started — Docker Compose](../getting-started/docker-compose.md) for the
complete `docker-compose.yml` and `.env.example`.

This page covers production-hardening, observability stack integration, and upgrade procedures.

## Production Hardening

### Restrict Admin Port

Port 8081 (admin API) must not be exposed to the internet. Use Docker's port binding
to restrict it to localhost or a management network:

```yaml
services:
  proxy:
    ports:
      - "8080:8080"
      - "3000:3000"
      - "127.0.0.1:8081:8081"    # Admin port: localhost only
```

### TLS Termination

Use Traefik or nginx for TLS termination in front of ports 8080 and 3000:

```yaml
services:
  traefik:
    image: traefik:v3
    ports:
      - "443:443"
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./certs:/certs

  proxy:
    labels:
      - "traefik.http.routers.revoc.rule=Host(`revoc.example.com`)"
      - "traefik.http.routers.revoc.entrypoints=websecure"
      - "traefik.http.routers.revoc.tls=true"
      - "traefik.http.services.revoc.loadbalancer.server.port=8080"
```

### Secrets Management

Use Docker Secrets instead of environment variables for API keys in production:

```yaml
services:
  proxy:
    secrets:
      - openai_api_key
    environment:
      OPENAI_API_KEY_FILE: /run/secrets/openai_api_key
      REVOC_UPSTREAM__API_KEY_FILE: /run/secrets/openai_api_key

secrets:
  openai_api_key:
    external: true
```

## Observability Stack

Add Prometheus + Grafana to the compose file:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD}
    volumes:
      - grafana-data:/var/lib/grafana
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: revoc
    static_configs:
      - targets: ["proxy:9090"]
```

## Upgrading

```bash
# Pull new image
docker compose pull proxy

# Rolling restart (brief downtime)
docker compose up -d proxy

# Verify new version
docker compose exec proxy revoc-proxy version
```

Migrations run automatically on startup. The old container handles requests until
the new one passes its healthcheck.

## Backup

```bash
# Backup Postgres audit database
docker compose exec postgres pg_dump -U revoc revoc > revoc-backup-$(date +%Y%m%d).sql

# Backup Redis state (optional — session data is transient)
docker compose exec redis redis-cli BGSAVE
docker compose cp redis:/data/dump.rdb ./redis-backup-$(date +%Y%m%d).rdb
```
