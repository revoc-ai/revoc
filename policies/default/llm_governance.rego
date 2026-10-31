# REVOC LLM governance violations.
# Package: revoc.governance.llm
#
# Produces violation objects for LLM request/response governance.
# Each violation: {rule_id, message, severity, action, tier}
#
# Violation actions:
#   block  — deny the request/response entirely
#   redact — strip or mask the identified content
#   audit  — allow but record for review
#
# Tier semantics (D12 — conflict resolution):
#   security → cannot be overridden by custom or profile allows
#   profile  → compliance-driven, overrides custom
#   custom   → operator-defined rules

package revoc.governance.llm

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ── PII redaction rules (Profile tier) ───────────────────────────────────────
# Any PII finding on an LLM request or response triggers redaction.

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	v := {
		"rule_id":  pii_rule_id(f.pii_entity),
		"message":  sprintf("PII entity detected: %v", [f.pii_entity]),
		"severity": "MEDIUM",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── Secret block rules (Security tier) ───────────────────────────────────────
# Credential/key exposure in any LLM direction is an immediate block.

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  secret_rule_id(f.pii_entity),
		"message":  sprintf("Secret credential detected: %v", [f.pii_entity]),
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Encoded evasion (Security tier) ──────────────────────────────────────────
# If a finding was detected only after base64/URL decoding, it is an evasion
# attempt — elevate to Security tier regardless of finding type.

violations contains v if {
	some f in input.findings
	f.was_encoded == true
	v := {
		"rule_id":  "sec_encoded_evasion_v1",
		"message":  "Security pattern detected in encoded (evasion) content",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Prompt injection (Security tier) ─────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PROMPT_INJECTION"
	v := {
		"rule_id":  "sec_prompt_injection_v1",
		"message":  "Prompt injection attempt detected in request",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── DDL mutation (Security tier) ──────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	f.metadata.pattern_name == "DDL_MUTATION"
	v := {
		"rule_id":  "sec_ddl_mutation_v1",
		"message":  "DDL mutation (DROP/TRUNCATE/ALTER) detected",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── DELETE without WHERE clause (Security tier) ───────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	f.metadata.pattern_name == "DELETE_NO_WHERE"
	v := {
		"rule_id":  "sec_delete_no_where_v1",
		"message":  "DELETE statement without a WHERE clause detected",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Mass delete operation (Security tier) ─────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	f.metadata.pattern_name == "MASS_DELETE"
	v := {
		"rule_id":  "sec_mass_delete_v1",
		"message":  "Mass delete operation detected",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── System prompt extraction (Security tier) ──────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SYSTEM_PROMPT_EXTRACTION"
	v := {
		"rule_id":  "sec_sysextract_v1",
		"message":  "System prompt extraction attempt detected",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Model ACL (Custom tier) ───────────────────────────────────────────────────
# Block requests to models not on the allowed list for this org.

violations contains v if {
	is_string(input.model)
	allowed := data.revoc.policies.model_restrictions["default"]
	not input.model in allowed
	v := {
		"rule_id":  "model_acl_v1",
		"message":  sprintf("Model '%v' is not in the approved model list", [input.model]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "custom",
	}
}

# ── Session data exfiltration (Security tier) ─────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SESSION_ANOMALY"
	v := {
		"rule_id":  "session_data_exfil_v1",
		"message":  "Session anomaly / data exfiltration pattern detected",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Helpers ───────────────────────────────────────────────────────────────────

pii_rule_id("US_SSN")               := "pii_ssn_v1"
pii_rule_id("CREDIT_CARD")          := "pii_credit_card_v1"
pii_rule_id("IBAN_CODE")            := "pii_iban_v1"
pii_rule_id("BANK_ACCOUNT")         := "pii_bank_account_v1"
pii_rule_id("ROUTING_NUMBER")       := "pii_bank_account_v1"
pii_rule_id("SWIFT_BIC")            := "pii_bank_account_v1"
pii_rule_id("US_PASSPORT")          := "pii_passport_v1"
pii_rule_id("US_DRIVER_LICENSE")    := "pii_driver_license_v1"
pii_rule_id("EMAIL_ADDRESS")        := "pii_email_v1"
pii_rule_id("PHONE_NUMBER")         := "pii_phone_v1"
pii_rule_id("IP_ADDRESS_V4")        := "pii_ip_address_v1"
pii_rule_id("IP_ADDRESS_V6")        := "pii_ip_address_v1"
pii_rule_id("MEDICAL_RECORD_NUMBER"):= "pii_mrn_v1"
pii_rule_id("NPI_NUMBER")           := "pii_mrn_v1"
pii_rule_id("DEA_NUMBER")           := "pii_mrn_v1"
pii_rule_id("DATE_OF_BIRTH")        := "pii_dob_v1"
default pii_rule_id(_)              := "pii_generic_v1"

secret_rule_id("AWS_ACCESS_KEY")    := "secret_aws_key_v1"
secret_rule_id("AWS_SECRET_KEY")    := "secret_aws_secret_v1"
secret_rule_id("GITHUB_TOKEN")      := "secret_github_token_v1"
secret_rule_id("OPENAI_KEY")        := "secret_openai_key_v1"
secret_rule_id("ANTHROPIC_KEY")     := "secret_anthropic_key_v1"
secret_rule_id("GENERIC_API_KEY")   := "secret_generic_api_key_v1"
secret_rule_id("PRIVATE_KEY")       := "secret_private_key_v1"
secret_rule_id("JWT_TOKEN")         := "secret_jwt_v1"
secret_rule_id("PASSWORD_IN_JSON")  := "secret_password_json_v1"
default secret_rule_id(_)           := "secret_block_v1"
