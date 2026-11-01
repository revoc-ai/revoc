# Kubernetes / Helm Deployment (Tier 3)

The Helm chart deploys REVOC in high-availability mode with OPA sidecar support,
OTel export, horizontal pod autoscaling, and multi-instance kill-switch propagation.

## Prerequisites

- Kubernetes 1.27+
- Helm 3.12+
- An external Postgres instance or the Postgres sub-chart
- An external Redis instance or the Redis sub-chart

## Installation

```bash
git clone https://github.com/revoc-ai/revoc && cd revoc
helm dependency build helm/revoc

helm install revoc helm/revoc \
  --namespace revoc \
  --create-namespace \
  --set secrets.openaiApiKey=$OPENAI_API_KEY \
  --set secrets.adminKey=$(openssl rand -hex 24)
```

A published chart repository is planned; install from the repository for now.

## values.yaml Highlights

```yaml
global:
  environment: production
  image:
    repository: ghcr.io/revoc-ai/revoc
    tag: "0.1.0-beta.1"
    pullPolicy: IfNotPresent

replicaCount: 3

resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2"
    memory: "2Gi"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

proxy:
  port: 8080
  dashboardPort: 3000
  adminPort: 8081

policy:
  engine: native           # native | sidecar | wasm
  enforcementMode: enforce

upstream:
  openai:
    apiKey: ""             # set via --set or external Secret
    apiKeySecretName: ""   # or reference an existing Secret

storage:
  backend: postgres
  postgres:
    external:
      url: ""              # set via --set or external Secret

cache:
  backend: redis
  redis:
    external:
      url: ""

telemetry:
  otlpEndpoint: ""         # e.g. http://otel-collector:4317
  prometheusPort: 9090

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: revoc.example.com
      paths:
        - path: /
          pathType: Prefix
          port: 8080
  tls:
    - secretName: revoc-tls
      hosts:
        - revoc.example.com

# OPA sidecar (optional — only needed when policy.engine = "sidecar")
opa:
  enabled: false
  image: openpolicyagent/opa:latest-static
  bundleUrl: ""
```

## Production values.yaml

```bash
helm install revoc revoc/revoc \
  --namespace revoc \
  --create-namespace \
  -f values.production.yaml \
  --set upstream.openai.apiKeySecretName=openai-secret \
  --set storage.postgres.external.url=$DATABASE_URL \
  --set cache.redis.external.url=$REDIS_URL
```

## Multi-Instance Kill-Switch

With Redis configured, all replicas receive kill-switch activations via pub/sub.
Propagation latency is ~10–50ms depending on Redis RTT:

```bash
# Activate kill-switch — propagates to all replicas within 50ms
kubectl exec -n revoc deploy/revoc -- \
  curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d '{"scope":"global","reason":"incident","activated_by":"sre-on-call"}'
```

## Upgrading

```bash
helm repo update
helm upgrade revoc revoc/revoc \
  --namespace revoc \
  --reuse-values \
  --set global.image.tag=1.1.0
```

Helm performs a rolling update. Each new pod passes its startupProbe before the
old pod is terminated — zero-downtime upgrade.

## Uninstalling

```bash
helm uninstall revoc --namespace revoc
kubectl delete namespace revoc
```

This removes all REVOC resources but preserves the external Postgres and Redis data.
