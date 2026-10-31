# REVOC GDPR compliance profile.
# Package: revoc.governance.profile.gdpr
#
# Enforces GDPR Article 5 (data minimisation) and Article 25 (privacy by design):
#   - Email, phone, IP address, DoB → Mask before processing.
#   - SSN equivalents (national IDs) → Remove.
#   - Sending personal data to non-EU model providers → Audit (flag for DPO review).
#   - Data exfiltration patterns → Block.

package revoc.governance.profile.gdpr

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Personal data requiring masking under GDPR Art. 4(1).
gdpr_mask_entities := {
	"EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS_V4", "IP_ADDRESS_V6",
	"DATE_OF_BIRTH", "US_DRIVER_LICENSE",
}

# Special category data requiring removal under GDPR Art. 9.
gdpr_remove_entities := {
	"US_SSN", "MEDICAL_RECORD_NUMBER", "NPI_NUMBER",
	"CREDIT_CARD", "IBAN_CODE", "BANK_ACCOUNT",
}

# EU/EEA model providers (data transfer lawful by default).
eu_providers := {"azure", "azure-eu", "mistral"}

# ── Personal data must be masked ─────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in gdpr_mask_entities
	v := {
		"rule_id":  "gdpr_personal_data_mask_v1",
		"message":  sprintf("GDPR: personal data '%v' must be masked (Art. 5 data minimisation)", [f.pii_entity]),
		"severity": "MEDIUM",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── Special category data must be removed ────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in gdpr_remove_entities
	v := {
		"rule_id":  "gdpr_special_category_remove_v1",
		"message":  sprintf("GDPR: special category data '%v' must be removed (Art. 9)", [f.pii_entity]),
		"severity": "HIGH",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── Non-EU provider with personal data → Audit ────────────────────────────────
# Flags for DPO review; does not block (SCCs may be in place).

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	is_string(input.provider)
	not input.provider in eu_providers
	v := {
		"rule_id":  "gdpr_non_eu_transfer_v1",
		"message":  sprintf("GDPR: personal data sent to non-EU provider '%v' — review data transfer basis (Art. 46)", [input.provider]),
		"severity": "MEDIUM",
		"action":   "audit",
		"tier":     "profile",
	}
}

# ── Session exfiltration → block ─────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SESSION_ANOMALY"
	v := {
		"rule_id":  "gdpr_exfil_block_v1",
		"message":  "GDPR: data exfiltration pattern detected — blocked per Art. 25",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Secret exposure → block ───────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "gdpr_secret_block_v1",
		"message":  "GDPR: credential exposure blocked (security obligation Art. 32)",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}
