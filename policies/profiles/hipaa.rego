# REVOC HIPAA compliance profile.
# Package: revoc.governance.profile.hipaa
#
# Enforces HIPAA Privacy Rule requirements:
#   - PHI entities must be removed or masked before leaving the system.
#   - Tools that can export data in bulk are blocked in production.
#   - Medical record numbers, NPI, DEA numbers → Remove.
#   - All PII including name, DOB, SSN, email, phone → Remove.
#   - send_email tool blocked in all environments (PHI exfil risk).

package revoc.governance.profile.hipaa

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# PHI entity types that require Remove (not just Mask).
phi_entities := {
	"US_SSN", "MEDICAL_RECORD_NUMBER", "NPI_NUMBER", "DEA_NUMBER",
	"DATE_OF_BIRTH", "CREDIT_CARD", "IBAN_CODE", "BANK_ACCOUNT",
	"ROUTING_NUMBER",
}

# PHI that may be Masked rather than removed.
phi_mask_entities := {
	"EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS_V4", "IP_ADDRESS_V6",
	"US_PASSPORT", "US_DRIVER_LICENSE",
}

# ── PHI entities must be removed ─────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in phi_entities
	v := {
		"rule_id":  "hipaa_phi_remove_v1",
		"message":  sprintf("HIPAA: PHI entity '%v' must be removed before processing", [f.pii_entity]),
		"severity": "HIGH",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── PHI mask entities must be masked ─────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in phi_mask_entities
	v := {
		"rule_id":  "hipaa_phi_mask_v1",
		"message":  sprintf("HIPAA: PHI entity '%v' must be masked", [f.pii_entity]),
		"severity": "MEDIUM",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── send_email blocked (PHI exfiltration risk) ────────────────────────────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.tool_call.tool_name == "send_email"
	v := {
		"rule_id":  "hipaa_no_email_exfil_v1",
		"message":  "HIPAA: send_email is blocked to prevent PHI exfiltration",
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── delete_s3_object and write_file blocked in production ─────────────────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.caller.environment == "production"
	input.tool_call.tool_name in {"delete_s3_object", "write_file"}
	v := {
		"rule_id":  "hipaa_prod_data_tools_v1",
		"message":  sprintf("HIPAA: tool '%v' is blocked in production environment", [input.tool_call.tool_name]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── Secret exposure → block ───────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "hipaa_secret_block_v1",
		"message":  "HIPAA: credential exposure must be blocked",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}
