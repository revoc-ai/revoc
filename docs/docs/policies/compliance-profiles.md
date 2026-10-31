# Compliance Profiles

REVOC ships with six pre-built compliance profiles. Activating a profile applies
the full ruleset for that regulation as Profile-tier (2) rules. Profile-tier rules
are stronger than Custom-tier but weaker than Security-tier.

## Available Profiles

| Profile | Regulation | Key protections |
|---|---|---|
| `hipaa` | US Health Insurance Portability and Accountability Act | PHI removal, MRN, DOB, SSN, streaming buffer |
| `pci-dss` | Payment Card Industry Data Security Standard | Credit card, IBAN, secrets, 365-day audit |
| `gdpr` | EU General Data Protection Regulation | Personal identifiers, right-to-erasure retention |
| `soc2` | SOC 2 Type II | Secrets, access logging, quota enforcement |
| `financial-services` | Financial industry baseline | SWIFT, routing numbers, bank accounts, secrets |
| `internal-dev` | Internal developer tooling | PII in shadow mode, secrets enforced, generous quota |

## Activating a Profile

```bash
curl -s -X POST http://localhost:8081/internal/policies \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -d 'name: my-hipaa-policy
version: "1.0"
environment: production
profile: hipaa'
```

Or apply from the pre-built example files:

```bash
# HIPAA
curl -s -X POST http://localhost:8081/internal/policies \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  --data-binary @examples/policy-cookbook/hipaa-baseline.yaml

# PCI-DSS
curl -s -X POST http://localhost:8081/internal/policies \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  --data-binary @examples/policy-cookbook/pci-dss-baseline.yaml
```

## HIPAA Profile

Removes all 18 HIPAA identifiers before they reach the LLM:

- Medical record numbers (`pii_mrn_v1`)
- SSNs (`pii_ssn_v1`)
- Dates of birth (`pii_dob_v1`)
- Phone numbers (`pii_phone_v1`)
- Email addresses (`pii_email_v1`)
- IP addresses (`pii_ip_address_v1`)
- Credit card numbers (`pii_credit_card_v1`)
- IBAN codes (`pii_iban_v1`)
- Passport numbers (`pii_passport_v1`)
- Driver license numbers (`pii_driver_license_v1`)

Sets `stream_buffer_output = true` — full response buffering required to ensure
complete inspection before any PHI is returned to the application.

## PCI-DSS Profile

- Removes all credit card PANs (Luhn-validated)
- Blocks any request containing secrets (API keys, passwords, private keys)
- Sets `audit_retention_days = 365` (PCI-DSS Requirement 10.5)
- Enables `stream_buffer_output = true`

## GDPR Profile

- Masks email, phone, IP addresses (data minimization, Art. 5(1)(c))
- Removes SSNs, DOBs, passport numbers, credit cards
- Sets `audit_retention_days = 90` (storage limitation, Art. 5(1)(e))

## Combining Profile with Custom Rules

A profile can be extended with custom rules in the same bundle:

```yaml
name: hipaa-plus-custom
version: "1.0"
environment: production
profile: hipaa

rules:
  # Additional org-specific rule on top of HIPAA baseline
  - rule_id: custom_patient_id_v1
    finding_type: KEYWORD_MATCH
    keywords: ["PAT-", "PATIENT_"]
    action: remove
    enforcement_mode: enforce
```

Profile rules are applied at tier 2; custom rules at tier 1. Profile rules win
over custom rules in conflict resolution.
