package revoc.governance.mcp_test

import future.keywords.if
import future.keywords.in

# ── Shared fixtures ───────────────────────────────────────────────────────────

allowed_caller := {
	"org_id":           "org-test",
	"caller_id":        "caller-test",
	"team":             "data-engineering",
	"environment":      "development",
	"enforcement_mode": "enforce",
	"policy_profile":   null,
	"governance_depth": 0,
}

blocked_env_caller := object.union(allowed_caller, {"environment": "production"})
wrong_team_caller  := object.union(allowed_caller, {"team": "marketing"})

tool_call_execute_sql := {
	"tool_name":  "execute_sql",
	"arguments":  {"query": "SELECT * FROM users LIMIT 10"},
	"server_id":  "db-server",
	"call_id":    "call-001",
}

base_mcp_input := {
	"request_id":       "mcp-test-001",
	"request_type":     "McpToolCall",
	"caller":           allowed_caller,
	"findings":         [],
	"model":            null,
	"provider":         null,
	"token_usage":      null,
	"session_state":    null,
	"tool_call":        tool_call_execute_sql,
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

# ── test_allowed_tool_call_no_violations ──────────────────────────────────────

test_allowed_tool_call_no_violations if {
	result := data.revoc.governance.mcp.violations with input as base_mcp_input
	count(result) == 0
}

# ── test_wrong_team_triggers_acl_block ────────────────────────────────────────

mock_mcp_tool_acl := {
	"execute_sql": {
		"allowed_teams":        ["data-engineering", "backend"],
		"blocked_environments": ["production"],
	},
}

test_wrong_team_triggers_acl_block if {
	inp := object.union(base_mcp_input, {"caller": wrong_team_caller})
	result := data.revoc.governance.mcp.violations
		with input as inp
		with data.revoc.policies.mcp_tool_acl as mock_mcp_tool_acl
	some v in result
	v.rule_id == "mcp_tool_acl_v1"
	v.action == "block"
	v.tier == "profile"
}

# ── test_blocked_env_triggers_env_block ───────────────────────────────────────

test_blocked_env_triggers_env_block if {
	inp := object.union(base_mcp_input, {"caller": blocked_env_caller})
	result := data.revoc.governance.mcp.violations
		with input as inp
		with data.revoc.policies.mcp_tool_acl as mock_mcp_tool_acl
	some v in result
	v.rule_id == "mcp_env_block_v1"
	v.action == "block"
}

# ── test_ddl_mutation_in_args_triggers_block ──────────────────────────────────

test_ddl_mutation_triggers_block if {
	f := mk_finding_meta("DDL_MUTATION", "CRITICAL", null, false, {"pattern_name": "DDL_MUTATION"})
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "sec_ddl_mutation_v1"
	v.tier == "security"
}

# ── test_delete_no_where_triggers_block ───────────────────────────────────────

test_delete_no_where_triggers_block if {
	f := mk_finding_meta("DDL_MUTATION", "CRITICAL", null, false, {"pattern_name": "DELETE_NO_WHERE"})
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "sec_delete_no_where_v1"
	v.tier == "security"
}

# ── test_mass_delete_triggers_block ───────────────────────────────────────────

test_mass_delete_triggers_block if {
	f := mk_finding_meta("DDL_MUTATION", "CRITICAL", null, false, {"pattern_name": "MASS_DELETE"})
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "sec_mass_delete_v1"
	v.tier == "security"
}

# ── test_ssrf_in_args_triggers_block ─────────────────────────────────────────

test_ssrf_triggers_block if {
	f := mk_finding("SSRF_ATTEMPT", "CRITICAL", null, false)
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "sec_ssrf_v1"
	v.tier == "security"
}

# ── test_path_traversal_triggers_block ───────────────────────────────────────

test_path_traversal_triggers_block if {
	f := mk_finding("PATH_TRAVERSAL", "CRITICAL", null, false)
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "sec_path_traversal_v1"
	v.tier == "security"
}

# ── test_encoded_evasion_triggers_block ───────────────────────────────────────

test_encoded_evasion_triggers_block if {
	f := mk_finding("DDL_MUTATION", "CRITICAL", null, true)
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "sec_encoded_evasion_v1"
	v.tier == "security"
}

# ── test_pii_in_tool_result_triggers_redact ───────────────────────────────────

test_mcp_result_pii_triggers_redact if {
	f := mk_finding("PII", "MEDIUM", "US_SSN", false)
	inp := object.union(base_mcp_input, {
		"request_type": "McpToolResult",
		"findings":     [f],
	})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "mcp_result_pii_v1"
	v.action == "redact"
	v.tier == "security"
}

# ── test_session_exfil_triggers_block ────────────────────────────────────────

test_session_exfil_triggers_block if {
	f := mk_finding("SESSION_ANOMALY", "CRITICAL", null, false)
	inp := object.union(base_mcp_input, {"findings": [f]})
	result := data.revoc.governance.mcp.violations with input as inp
	some v in result
	v.rule_id == "session_data_exfil_v1"
	v.tier == "security"
}
