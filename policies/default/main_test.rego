package revoc.governance.main_test

import future.keywords.if
import future.keywords.in

# ── Shared test helpers ───────────────────────────────────────────────────────

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
	"request_id":       "test-req-001",
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

pii_finding := {
	"id":               "00000000-0000-0000-0000-000000000001",
	"finding_type":     "PII",
	"severity":         "MEDIUM",
	"detection_tier":   "REGEX",
	"confidence":       0.99,
	"pii_entity":       "EMAIL_ADDRESS",
	"was_encoded":      false,
	"was_normalized":   false,
	"redaction_applied":false,
	"detected_at":      "2024-01-01T00:00:00Z",
	"metadata":         {},
}

injection_finding := {
	"id":               "00000000-0000-0000-0000-000000000002",
	"finding_type":     "PROMPT_INJECTION",
	"severity":         "CRITICAL",
	"detection_tier":   "REGEX",
	"confidence":       1.0,
	"pii_entity":       null,
	"was_encoded":      false,
	"was_normalized":   false,
	"redaction_applied":false,
	"detected_at":      "2024-01-01T00:00:00Z",
	"metadata":         {},
}

secret_finding := {
	"id":               "00000000-0000-0000-0000-000000000003",
	"finding_type":     "SECRET_EXPOSURE",
	"severity":         "CRITICAL",
	"detection_tier":   "REGEX",
	"confidence":       1.0,
	"pii_entity":       "OPENAI_KEY",
	"was_encoded":      false,
	"was_normalized":   false,
	"redaction_applied":false,
	"detected_at":      "2024-01-01T00:00:00Z",
	"metadata":         {},
}

# ── test_allow_clean ──────────────────────────────────────────────────────────
# No findings → decision must be allow.

test_allow_clean if {
	result := data.revoc.governance.main.decision with input as base_input
	result.action == "allow"
	result.effective_action == "allow"
	result.severity == "INFO"
	result.tier == "default"
}

# ── test_redact_pii ───────────────────────────────────────────────────────────
# PII finding → decision must be redact.

test_redact_pii if {
	inp := json.patch(base_input, [{"op": "add", "path": "/findings/-", "value": pii_finding}])
	result := data.revoc.governance.main.decision with input as inp
	result.action == "redact"
	result.tier == "profile"
}

# ── test_block_injection ──────────────────────────────────────────────────────
# Prompt injection → decision must be block at security tier.

test_block_injection if {
	inp := json.patch(base_input, [{"op": "add", "path": "/findings/-", "value": injection_finding}])
	result := data.revoc.governance.main.decision with input as inp
	result.action == "block"
	result.tier == "security"
	result.severity == "CRITICAL"
	"sec_prompt_injection_v1" in result.applicable_rules
}

# ── test_block_overrides_redact ───────────────────────────────────────────────
# Both PII (redact) and injection (block) → block must win.

test_block_overrides_redact if {
	findings := [pii_finding, injection_finding]
	inp := object.union(base_input, {"findings": findings})
	result := data.revoc.governance.main.decision with input as inp
	result.action == "block"
	result.tier == "security"
}

# ── test_security_block_not_blended_with_custom_block ─────────────────────────
# D12: when a Security-tier block (prompt injection) fires ALONGSIDE an
# unrelated Custom-tier block (disallowed model), the reported decision must
# reflect ONLY the Security-tier violation — its rule_id, message, severity,
# and tier — never a blend with the lower-tier rule that lost the conflict
# resolution outright (mirrors revoc-policy/src/conflict.rs::resolve()).

test_security_block_not_blended_with_custom_block if {
	findings := [injection_finding]
	inp := object.union(base_input, {
		"findings": findings,
		"model":    "not-an-approved-model",
	})
	result := data.revoc.governance.main.decision with input as inp

	# The custom-tier model_acl_v1 rule also fires (block) — but it must lose.
	result.action == "block"
	result.tier == "security"
	result.severity == "CRITICAL"
	result.applicable_rules == ["sec_prompt_injection_v1"]
	result.reason == "Prompt injection attempt detected in request"
	not "model_acl_v1" in result.applicable_rules
}

# ── test_security_rule_cannot_be_custom_allowed ───────────────────────────────
# Security-tier block wins regardless of tier ordering.
# (Shadow mode still records block internally, effective is audit.)

test_security_block_in_shadow_records_block if {
	findings := [injection_finding]
	shadow_caller := object.union(clean_caller, {"enforcement_mode": "shadow"})
	inp := object.union(base_input, {
		"findings": findings,
		"caller":   shadow_caller,
	})
	result := data.revoc.governance.main.decision with input as inp
	# action is the real decision (block)
	result.action == "block"
	# effective_action is downgraded to audit in shadow mode
	result.effective_action == "audit"
}

# ── test_shadow_mode_allows_become_audit ──────────────────────────────────────

test_shadow_mode_clean_is_audit if {
	shadow_caller := object.union(clean_caller, {"enforcement_mode": "shadow"})
	inp := object.union(base_input, {"caller": shadow_caller})
	result := data.revoc.governance.main.decision with input as inp
	result.action == "allow"
	result.effective_action == "audit"
}
