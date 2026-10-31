# Default Rules

REVOC ships with 30 governance rules active from the first request with no configuration.
Rules are organized into four tiers. Higher tier always wins in conflict resolution.

## Tier Precedence

| Tier | Value | Description | Overridable? |
|---|---|---|---|
| Default | 0 | Baseline allow | Yes |
| Custom | 1 | Operator-defined rules | Yes |
| Profile | 2 | Compliance profile rules (HIPAA, PCI-DSS, GDPR) | By higher tier |
| Security | 3 | Built-in security rules | **Never** |
| Emergency | 4 | Kill-switch | **Never** |

Security-tier rules (Tier 3) cannot be overridden by any custom allow rule.
This is enforced in `conflict.rs::resolve()`: if any Security-tier Block fires,
it returns regardless of what other rules decided.

---

## PII Rules (Profile Tier — action: redact or remove)

These rules detect and redact personally identifiable information before it reaches
the upstream model or is returned to the client.

| Rule ID | Entity Detected | Action | Validator |
|---|---|---|---|
| `pii_ssn_v1` | US Social Security Number | Remove | Regex exclusions (no 000, 666, 9xx) |
| `pii_credit_card_v1` | Credit card number (Visa, MC, Amex, Discover) | Remove | Luhn checksum |
| `pii_iban_v1` | IBAN bank account number | Remove | Mod-97 checksum |
| `pii_bank_account_v1` | Bank account number (context-sensitive) | Remove | None |
| `pii_passport_v1` | US passport number | Remove | None |
| `pii_driver_license_v1` | US driver license (state-specific) | Mask | None |
| `pii_email_v1` | Email address | Mask | None |
| `pii_phone_v1` | US phone number (all formats) | Mask | None |
| `pii_ip_address_v1` | IPv4 and IPv6 addresses | Mask | None |
| `pii_mrn_v1` | Medical record number | Remove | None |
| `pii_dob_v1` | Date of birth (context-sensitive) | Mask | None |

**Remove** replaces the entity with `[REDACTED]`.
**Mask** replaces with type label: `[EMAIL_ADDRESS]`, `[PHONE_NUMBER]`, etc.

---

## Secret Rules (Security Tier — action: block or remove)

Secret rules are Security tier: they cannot be overridden. If a secret is detected
in a request, the entire request is blocked (not just the secret field).

| Rule ID | Entity Detected | Action |
|---|---|---|
| `secret_block_v1` | Any secret finding (umbrella rule) | Block |
| `secret_aws_key_v1` | AWS access key (`AKIA...`) | Remove from output |
| `secret_aws_secret_v1` | AWS secret key (40-char base64, context) | Remove |
| `secret_github_token_v1` | GitHub PAT (`ghp_...` or `github_pat_...`) | Remove |
| `secret_openai_key_v1` | OpenAI API key (`sk-...`) | Remove |
| `secret_anthropic_key_v1` | Anthropic API key (`sk-ant-...`) | Remove |
| `secret_generic_api_key_v1` | Generic API key (JSON field detection) | Remove |
| `secret_private_key_v1` | PEM private key (`-----BEGIN ... PRIVATE KEY-----`) | Remove |
| `secret_jwt_v1` | JWT token in content | Hash (SHA-256 prefix) |
| `secret_password_json_v1` | Password field in JSON body | Remove |

---

## Security Rules (Security Tier — action: block, cannot be overridden)

These rules block requests that represent active attack patterns or dangerous operations.
All are Tier 3. A custom allow rule at Tier 1 or Tier 2 cannot override them.

| Rule ID | Threat | Detection |
|---|---|---|
| `sec_prompt_injection_v1` | Prompt injection phrases | "ignore previous instructions", "disregard", "override all", jailbreak variants |
| `sec_sysextract_v1` | System prompt extraction | "reveal your system prompt", "what are your instructions", "print initial prompt" |
| `sec_ddl_mutation_v1` | DDL mutation in SQL tool args | `DROP TABLE`, `TRUNCATE TABLE`, `ALTER TABLE` |
| `sec_delete_no_where_v1` | Unsafe DELETE | `DELETE FROM` without `WHERE` clause |
| `sec_ssrf_v1` | Server-Side Request Forgery | Internal IPs in HTTP args: 127.x, 10.x, 192.168.x, 172.16–31.x, 169.254.x |
| `sec_path_traversal_v1` | Path traversal in file args | `../` or `..\` sequences |
| `sec_encoded_evasion_v1` | Encoded attack patterns | Above patterns found in base64 or URL-decoded content |
| `sec_mass_delete_v1` | Bulk delete operations | DELETE without WHERE on large tables |
| `session_data_exfil_v1` | Session-level exfiltration pattern | > 500 rows read + PII seen + external send attempted |
| `mcp_result_pii_v1` | PII in MCP tool result | PII found in tool result returned to AI client |

---

## Operational Rules (Custom Tier)

| Rule ID | Condition | Action |
|---|---|---|
| `mcp_tool_acl_v1` | MCP tool not in org's allowed tool list | Block |
| `token_quota_v1` | Token budget for org/caller exceeded | Block |

These rules are Custom tier and can be overridden or disabled via policy bundles.

---

## Viewing Active Rules in the Dashboard

Navigate to **Settings → Rules** in the dashboard at `:3000` to see:

- All 30 active rules with current status
- Per-rule trigger counts (last 24h / 7d / 30d)
- Any custom rules from loaded policy bundles
- Conflict resolution preview: "If rules X and Y both fire, which wins?"

## Disabling a Default Rule

Default rules can be disabled via a policy bundle (Custom tier). However, Security-tier
rules (`sec_*`, `secret_block_v1`, `session_data_exfil_v1`) cannot be disabled:

```yaml
# This will be REJECTED — sec_ddl_mutation_v1 is Security tier
rules:
  - rule_id: sec_ddl_mutation_v1
    enabled: false   # ERROR: security rules cannot be disabled
```

```yaml
# This is allowed — pii_email_v1 is Profile tier
rules:
  - rule_id: pii_email_v1
    enabled: false   # OK: profile-tier rules can be disabled by operator
```
