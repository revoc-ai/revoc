# Metrics

REVOC exposes Prometheus metrics on port 9090 at `/metrics`.
All metrics use the `revoc_` prefix.

## Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: revoc
    static_configs:
      - targets: ["revoc:9090"]
    scrape_interval: 15s
```

## Request Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `revoc_requests_total` | Counter | `org_id`, `decision`, `request_type` | Total governed requests |
| `revoc_request_duration_ms` | Histogram | `request_type`, `decision` | End-to-end request duration |
| `revoc_upstream_duration_ms` | Histogram | `provider`, `model` | Upstream LLM latency only |
| `revoc_detection_duration_ms` | Histogram | `stages` | Detection pipeline duration |
| `revoc_policy_duration_ms` | Histogram | `engine`, `cache_hit` | Policy evaluation duration |

## Decision Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `revoc_decisions_total` | Counter | `action`, `org_id`, `rule_id` | Decisions by action and rule |
| `revoc_blocks_total` | Counter | `org_id`, `rule_id` | Blocked requests |
| `revoc_redactions_total` | Counter | `org_id`, `rule_id` | Redacted requests |

## Detection Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `revoc_findings_total` | Counter | `finding_type`, `org_id`, `was_normalized`, `was_encoded` | Findings by type |
| `revoc_pii_entities_total` | Counter | `entity_type`, `org_id` | PII entity type counts |
| `revoc_evasion_attempts_total` | Counter | `org_id`, `evasion_type` | Normalization/encoding evasion attempts caught |

## Token Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `revoc_tokens_total` | Counter | `org_id`, `provider`, `model`, `token_type` | Token usage (prompt/completion) |
| `revoc_cost_usd_total` | Counter | `org_id`, `provider`, `model` | Estimated cost in USD |

## System Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `revoc_kill_switch_active` | Gauge | `scope` | 1 if kill-switch is active, 0 if not |
| `revoc_policy_cache_hit_ratio` | Gauge | `engine` | Policy cache hit ratio (0.0–1.0) |
| `revoc_governance_depth_max` | Gauge | `org_id` | Maximum governance depth seen |
| `revoc_active_sessions` | Gauge | `org_id` | Active session count |
| `revoc_manifest_warnings_total` | Counter | `org_id` | tools/list responses with manifest warnings |

## Alerting Examples

```yaml
# alert-rules.yml
groups:
  - name: revoc
    rules:
      - alert: RevocKillSwitchActive
        expr: revoc_kill_switch_active{scope="global"} == 1
        for: 1m
        annotations:
          summary: "REVOC global kill-switch is active"

      - alert: RevocHighBlockRate
        expr: rate(revoc_blocks_total[5m]) > 100
        for: 2m
        annotations:
          summary: "REVOC blocking more than 100 req/min"

      - alert: RevocEvasionAttempts
        expr: rate(revoc_evasion_attempts_total[5m]) > 10
        for: 1m
        annotations:
          summary: "Unicode or encoding evasion attempts detected"

      - alert: RevocDetectionSlowdown
        expr: histogram_quantile(0.95, rate(revoc_detection_duration_ms_bucket[5m])) > 8000
        for: 2m
        annotations:
          summary: "Detection P95 > 8s — approaching timeout threshold"
```

## Grafana Dashboard

A pre-built Grafana dashboard JSON is available at:

```bash
curl -s http://localhost:8081/internal/grafana-dashboard \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" > revoc-dashboard.json
```

Import into Grafana via **Dashboards → Import → Upload JSON file**.
