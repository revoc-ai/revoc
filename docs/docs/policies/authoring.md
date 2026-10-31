# Authoring Policies

REVOC policy bundles are YAML files that add, modify, or disable governance rules
for a specific organization and environment. Policy bundles are Custom tier (1) or
Profile tier (2). Security-tier rules cannot be modified via policy bundles.

## Policy Bundle Format

```yaml
name: my-custom-policy
version: "1.0"
environment: production          # production | staging | development
profile: null                    # null | hipaa | pci-dss | gdpr | soc2
description: >
  Custom policy for the ACME production environment.

rules:
  - rule_id: pii_email_v1
    action: remove               # remove | mask | block | audit
    enforcement_mode: enforce    # enforce | shadow

  - rule_id: pii_phone_v1
    enabled: false               # disable this rule for this org

  - rule_id: token_quota_v1
    action: block
    enforcement_mode: enforce
    parameters:
      max_tokens_per_hour: 1000000
      max_tokens_per_day: 10000000

audit_retention_days: 90
stream_buffer_output: false
```

## Actions

| Action | Effect |
|---|---|
| `allow` | Permit the request/response unchanged |
| `redact` | Remove or mask the detected entity |
| `block` | Reject the request with `REVOC_GOVERNANCE_BLOCK` |
| `audit` | Allow but record a finding in the audit log |

## Enforcement Modes

| Mode | Effect |
|---|---|
| `enforce` | Apply the action — block, redact, or audit |
| `shadow` | Observe only — record what *would* have happened; do not apply |

## Applying a Policy Bundle

Via the admin API:

```bash
curl -s -X POST http://localhost:8081/internal/policies \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  --data-binary @my-policy.yaml
```

Response:

```json
{
  "status": "activated",
  "policy_id": "01932abc-...",
  "org_id": "org-acme",
  "rules_loaded": 3,
  "effective_at": "2026-01-15T10:30:00Z"
}
```

## Listing Active Policy Bundles

```bash
curl -s http://localhost:8081/internal/policies \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" | python3 -m json.tool
```

## Versioning and Rollback

Every bundle activation is recorded in `policy_audit_log`. To roll back:

```bash
curl -s -X POST http://localhost:8081/internal/policies/{policy_id}/rollback \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY"
```

## Validation Before Applying

```bash
# Dry-run: validate and compile without activating
curl -s -X POST http://localhost:8081/internal/policies/validate \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  --data-binary @my-policy.yaml
```

Or using the CLI:

```bash
revoc-proxy check-policies --dir policies/
```

## Rules That Cannot Be Modified

Security-tier rules (`sec_*`, `secret_block_v1`, `session_data_exfil_v1`) are defined in
`revoc-policy/src/conflict.rs::SECURITY_RULE_IDS`. Attempts to modify them via a
policy bundle are rejected:

```json
{
  "error": "Cannot modify security-tier rule 'sec_ddl_mutation_v1' via policy bundle. Security rules are immutable."
}
```

## Custom Rules

Add rules beyond the 30 defaults using custom rule IDs:

```yaml
rules:
  - rule_id: custom_block_competitor_mention_v1
    finding_type: KEYWORD_MATCH
    keywords: ["CompetitorCo", "RivalAI"]
    action: audit
    enforcement_mode: enforce
    description: Audit requests mentioning competitor names.
```

Custom rule IDs must be unique within your org's policy bundle and must not
collide with the built-in rule IDs listed in [Default Rules](../default-rules/overview.md).
