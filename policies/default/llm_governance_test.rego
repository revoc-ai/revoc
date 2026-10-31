package revoc.governance.llm_test

import future.keywords.if
import future.keywords.in

# ── Shared fixtures ───────────────────────────────────────────────────────────

clean_caller := {
	"org_id":           "org-test",
	"caller_id":        "caller-test",
	"team":             "engineering",
	"environment":      "development",
	"enforcement_mode": "enforce",
	"policy_profile":   null,
	"governance_depth": 0,
}

base_input := {
	"request_id":       "llm-test-001",
	"request_type":     "LlmRequest",
	"caller":           clean_caller,
	"findings":         [],
	"model":            "gpt-4o",
	"provider":         "openai",
	"token_usage":      null,
	"session_state":    null,
	"tool_call":        null,
	"governance_depth": 0,
	"timestamp":        1700000000,
}

mk_finding(ftype, severity, entity, encoded) := f if {
	f := mk_finding_meta(ftype, severity, entity, encoded, {})
}

mk_finding_meta(ftype, severity, entity, encoded, metadata) := f if {
	f := {
		"id":               "00000000-0000-0000-0000-000000000099",
		"finding_type":     ftype,
		"severity":         severity,
		"detection_tier":   "REGEX",
		"confidence":       1.0,
		"pii_entity":       entity,
		"was_encoded":      encoded,
		"was_normalized":   false,
		"redaction_applied":false,
		"detected_at":      "2024-01-01T00:00:00Z",
		"metadata":         metadata,
	}
}

# ── test_no_findings_no_violations ────────────────────────────────────────────

test_no_findings_no_violations if {
	result := data.revoc.governance.llm.violations with input as base_input
	count(result) == 0
}

# ── test_pii_email_triggers_redact ────────────────────────────────────────────

test_pii_email_triggers_redact if {
	f := mk_finding("PII", "MEDIUM", "EMAIL_ADDRESS", false)
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	count(result) > 0
	some v in result
	v.action == "redact"
	v.rule_id == "pii_email_v1"
	v.tier == "profile"
}

# ── test_secret_exposure_triggers_block ──────────────────────────────────────

test_secret_exposure_triggers_block if {
	f := mk_finding("SECRET_EXPOSURE", "CRITICAL", "OPENAI_KEY", false)
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "secret_openai_key_v1"
	v.tier == "security"
}

# ── test_prompt_injection_triggers_block ──────────────────────────────────────

test_prompt_injection_triggers_block if {
	f := mk_finding("PROMPT_INJECTION", "CRITICAL", null, false)
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "sec_prompt_injection_v1"
	v.tier == "security"
}

# ── test_ddl_mutation_triggers_block ──────────────────────────────────────────

test_ddl_mutation_triggers_block if {
	f := mk_finding_meta("DDL_MUTATION", "CRITICAL", null, false, {"pattern_name": "DDL_MUTATION"})
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "sec_ddl_mutation_v1"
	v.tier == "security"
}

# ── test_delete_no_where_triggers_block ───────────────────────────────────────

test_delete_no_where_triggers_block if {
	f := mk_finding_meta("DDL_MUTATION", "CRITICAL", null, false, {"pattern_name": "DELETE_NO_WHERE"})
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "sec_delete_no_where_v1"
	v.tier == "security"
}

# ── test_mass_delete_triggers_block ───────────────────────────────────────────

test_mass_delete_triggers_block if {
	f := mk_finding_meta("DDL_MUTATION", "CRITICAL", null, false, {"pattern_name": "MASS_DELETE"})
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "sec_mass_delete_v1"
	v.tier == "security"
}

# ── test_sys_extract_triggers_block ───────────────────────────────────────────

test_sys_extract_triggers_block if {
	f := mk_finding("SYSTEM_PROMPT_EXTRACTION", "CRITICAL", null, false)
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "sec_sysextract_v1"
	v.tier == "security"
}

# ── test_encoded_evasion_triggers_block ───────────────────────────────────────
# was_encoded=true on any finding → encoded evasion block fires.

test_encoded_evasion_triggers_block if {
	f := mk_finding("PII", "MEDIUM", "EMAIL_ADDRESS", true)
	inp := object.union(base_input, {"findings": [f]})
	result := data.revoc.governance.llm.violations with input as inp
	some v in result
	v.action == "block"
	v.rule_id == "sec_encoded_evasion_v1"
}

# ── test_disallowed_model_triggers_block ──────────────────────────────────────

test_disallowed_model_triggers_block if {
	inp := object.union(base_input, {"model": "gpt-3.5-turbo-instruct"})
	result := data.revoc.governance.llm.violations
		with input as inp
		with data.revoc.policies.model_restrictions as {
			"default": ["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet"],
		}
	some v in result
	v.action == "block"
	v.rule_id == "model_acl_v1"
	v.tier == "custom"
}

# ── test_allowed_model_no_acl_violation ───────────────────────────────────────

test_allowed_model_no_acl_violation if {
	inp := object.union(base_input, {"model": "gpt-4o-mini"})
	result := data.revoc.governance.llm.violations with input as inp
	# No model_acl violation expected
	count({v | v := result[_]; v.rule_id == "model_acl_v1"}) == 0
}
