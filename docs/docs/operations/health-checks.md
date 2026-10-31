# Health Checks

REVOC exposes four health check endpoints on port 8080. All four endpoints bypass
the kill-switch — they always respond regardless of kill-switch state.

## Endpoints

| Endpoint | Purpose | Used by |
|---|---|---|
| `GET /health` | General liveness + system status | Humans, monitoring |
| `GET /ready` | Readiness — is REVOC accepting traffic? | Load balancer, Kubernetes readinessProbe |
| `GET /startup` | Startup — has REVOC finished initializing? | Kubernetes startupProbe |
| `GET /metrics` | Prometheus metrics | Prometheus scraper |

## `/health`

Returns detailed system status:

```bash
curl -s http://localhost:8080/health | python3 -m json.tool
```

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_secs": 3721,
  "environment": "production",
  "policy_engine": "native",
  "kill_switch_active": false,
  "storage_backend": "postgres",
  "cache_backend": "redis",
  "detection_stages": {
    "regex": true,
    "onnx": false,
    "http_plugin": false
  },
  "upstream_providers": ["openai", "anthropic"]
}
```

When the kill-switch is active: `"kill_switch_active": true`, `"status": "ok"`.
Health is always "ok" — kill-switch is a governance state, not a system failure.

## `/ready`

Returns 200 when REVOC is ready to accept governed traffic:

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ready
# 200 when ready, 503 during startup
```

Not-ready conditions:
- Database migrations still running
- Policy engine not yet initialized
- Upstream provider connection not yet verified

## `/startup`

Returns 200 once initial startup is complete:

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/startup
# 200 once started, 503 while starting
```

## Kubernetes Probe Configuration

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 3

startupProbe:
  httpGet:
    path: /startup
    port: 8080
  initialDelaySeconds: 2
  periodSeconds: 3
  failureThreshold: 20   # Allow up to 60s for startup
```

## Docker Compose Healthcheck

```yaml
healthcheck:
  test: ["CMD", "curl", "-sf", "http://localhost:8080/health"]
  interval: 10s
  timeout: 5s
  retries: 5
  start_period: 15s
```

## Kill-Switch and Health Checks

The kill-switch (emergency stop) does not affect health check responses.
This is intentional: when you activate the kill-switch, your load balancer
and container orchestrator must continue to see the proxy as healthy so it
does not restart instances during an intentional suspension.

```bash
# Activate kill-switch
curl -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{"scope":"global","reason":"test","activated_by":"ops"}'

# Health still returns 200
curl http://localhost:8080/health
# {"status": "ok", "kill_switch_active": true, ...}

# Governed traffic returns 503
curl -X POST http://localhost:8080/v1/chat/completions -d '{}'
# {"error": {"code": "REVOC_KILL_SWITCH_ACTIVE", ...}}
```
