# Shadow Mode

Shadow mode lets REVOC observe and audit every request without blocking or redacting anything.
All governance rules run at full fidelity — detection, policy evaluation, conflict resolution —
but the effective action is always `audit` regardless of what the policy engine decides.

## What Shadow Mode Does

- Detection engine runs: all findings are recorded
- Policy engine runs: the real decision (block/redact/allow) is computed and logged
- **Effective action is always `audit`**: traffic flows through unchanged
- Dashboard shows what _would_ have been blocked or redacted
- `X-Revoc-Decision: shadow-block` or `shadow-redact` headers reveal the counterfactual

## What Shadow Mode Does Not Do

- Does **not** block any request
- Does **not** modify any request or response body
- Does **not** generate a `403` or `503` to the client

## Enabling Shadow Mode

### Per-deployment (entire proxy in shadow mode)

```toml
# configs/revoc.toml
[policy]
enforcement_mode = "shadow"
```

Or via environment variable:

```bash
docker run -d \
  -p 8080:8080 -p 3000:3000 \
  -e REVOC_POLICY__ENFORCEMENT_MODE=shadow \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc-shadow \
  ghcr.io/revoc-ai/revoc:beta
```

### Per-caller (specific API keys in shadow mode)

```yaml
# In policy bundle
rules:
  - rule_id: caller_shadow_trial
    condition:
      caller_id: "agent-prod-7"
    enforcement_mode: shadow
```

## Reading Shadow Mode in the Dashboard

In the live feed, shadow mode events show:

- **Decision badge**: `shadow-block` (red outline) or `shadow-redact` (yellow outline)
- **Real decision column**: what would have fired in enforce mode
- **Rules column**: which rules triggered
- The request and response are unchanged — the badges are informational only

## The `X-Revoc-Decision` Header in Shadow Mode

| Enforce mode decision | Shadow mode `X-Revoc-Decision` value |
|---|---|
| `allow` | `allow` |
| `audit` | `audit` |
| `redact` | `shadow-redact` |
| `block` | `shadow-block` |

## 30-Day Trial Guide

Shadow mode is the recommended way to evaluate REVOC in production before enabling
enforcement. Here is a structured 30-day process:

### Days 1–7: Baseline

1. Deploy REVOC in shadow mode in front of your staging environment
2. Run your normal test suite and integration tests with all traffic through REVOC
3. Open the dashboard and review which rules would fire
4. Export audit events and calculate the false-positive rate

```bash
# Export last 7 days of shadow events
curl -s "http://localhost:8081/internal/audit/export?start=2026-01-01&end=2026-01-08&decision=shadow-block" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" > week1-shadow-blocks.json
```

### Days 8–14: Rule Tuning

1. Identify any rules generating false positives for your workload
2. Create a custom policy bundle that adjusts thresholds or disables non-applicable rules
3. Apply the bundle in shadow mode and rerun your test suite
4. Target: zero false positives on your known-good test suite

### Days 15–21: Production Shadow

1. Move shadow mode REVOC in front of your production environment
2. Monitor the dashboard for 7 days of real production traffic
3. Review `shadow-block` events — are they real threats or false positives?
4. Confirm your team understands the dashboard and can investigate events

### Days 22–28: Partial Enforcement

1. Enable `enforcement_mode = enforce` for a subset of callers (e.g., low-risk internal tools)
2. Keep high-risk or high-volume callers in shadow mode
3. Monitor for any operational impact (latency, unexpected blocks)
4. Verify the P95 proxy overhead is within the < 10ms budget

### Day 29–30: Full Enforcement

1. Switch the entire deployment to `enforcement_mode = enforce`
2. Keep the dashboard open for the first 48 hours
3. Verify `X-Revoc-Timing` headers show detection < 5ms, policy < 2ms
4. Document your governance ruleset and incident response process

## Shadow Mode Audit Records

Shadow mode events are stored in the `audit_events` table with:

- `enforcement_mode = 'shadow'`
- `decision = 'shadow-block'` or `'shadow-redact'` (the counterfactual)
- `effective_action = 'audit'` (what actually happened)

This lets you query: "How many requests would have been blocked last week if we were in enforce mode?"

```bash
curl -s "http://localhost:8081/internal/audit/stats?enforcement_mode=shadow&decision=shadow-block" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY"
```
