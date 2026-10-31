# Compliance

REVOC provides controls applicable to several regulatory frameworks. This page
maps REVOC features to specific regulatory requirements.

## HIPAA (US Health Insurance Portability and Accountability Act)

### Applicability

HIPAA applies when REVOC governs AI workloads that process Protected Health
Information (PHI) on behalf of covered entities or business associates.

### Relevant Controls

| HIPAA Requirement | REVOC Control |
|---|---|
| § 164.312(a)(1) — Access control | API key authentication with per-caller identity; `mcp_tool_acl_v1` limits tool access per org |
| § 164.312(b) — Audit controls | `audit_events` table records every governed request; immutable audit log |
| § 164.312(c)(1) — Integrity | Bidirectional governance ensures PHI is not introduced into AI responses |
| § 164.312(e)(2)(ii) — Encryption in transit | Upstream connections use TLS (`rustls-tls`); configure HTTPS on the dashboard port |
| § 164.514 — De-identification | HIPAA profile removes all 18 Safe Harbor identifiers before LLM processing |

Apply the [HIPAA profile](../policies/compliance-profiles.md) for the full Safe Harbor de-identification ruleset.

---

## PCI-DSS (Payment Card Industry Data Security Standard)

### Applicability

PCI-DSS applies when REVOC governs AI workloads that may encounter or process
Primary Account Numbers (PANs) or other cardholder data.

### Relevant Controls

| PCI-DSS Requirement | REVOC Control |
|---|---|
| Req 3.4 — Do not store PANs in cleartext | `pii_credit_card_v1` removes Luhn-validated PANs before LLM processing |
| Req 3.2 — Do not store sensitive auth data | `secret_block_v1` blocks any request containing passwords, private keys, tokens |
| Req 7 — Restrict access | Per-caller API keys with policy profiles limit which models and tools each caller can use |
| Req 10.2 — Implement audit trails | Every governance decision is logged with caller identity, timestamp, and rule IDs |
| Req 10.5 — Secure audit logs | Audit log is append-only; no delete endpoint in the admin API |
| Req 10.7 — Retain for 12 months | Set `audit_retention_days = 365` in the PCI-DSS policy bundle |

Apply the [PCI-DSS profile](../policies/compliance-profiles.md) for the complete control set.

---

## GDPR (EU General Data Protection Regulation)

### Applicability

GDPR applies when REVOC governs AI workloads that process personal data of EU
data subjects, regardless of where the processing infrastructure is located.

### Relevant Controls

| GDPR Article | REVOC Control |
|---|---|
| Art. 5(1)(c) — Data minimization | GDPR profile masks/removes personal identifiers before LLM processing |
| Art. 5(1)(e) — Storage limitation | `audit_retention_days = 90` limits audit log retention |
| Art. 25 — Data protection by design | Governance runs before data reaches the LLM — privacy by design |
| Art. 30 — Records of processing | Audit log provides a record of when and how personal data was processed |
| Art. 32 — Security of processing | TLS in transit, no PII values in logs, constant-time key comparison |

Apply the [GDPR profile](../policies/compliance-profiles.md) for the full control set.

---

## SOC 2 Type II

### Applicability

SOC 2 Type II applies to service organizations using REVOC to demonstrate
security and availability controls for AI services.

### Relevant Trust Service Criteria

| Criterion | REVOC Control |
|---|---|
| CC6.1 — Logical access | API key authentication, per-caller identity, admin API on internal port only |
| CC6.6 — Threat detection | Detection pipeline, manifest analysis, session tracking |
| CC7.2 — Security incidents | Emergency kill-switch, audit log, dashboard alerts |
| CC7.3 — Recovery from incidents | Kill-switch deactivation, health checks always available |
| A1.1 — Availability | P95 overhead < 10ms; health check endpoints bypass kill-switch |

---

## Shared Responsibility

REVOC provides the governance layer. You are responsible for:

- Configuring appropriate compliance profiles for your workload
- Securing access to the admin API (port 8081)
- Encrypting the audit database at rest
- Configuring TLS termination for the proxy port if required
- Retaining audit logs for the required period
- Verifying that the upstream LLM provider's DPA/BAA meets your requirements
