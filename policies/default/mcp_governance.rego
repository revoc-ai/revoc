# REVOC MCP governance violations.
# Package: revoc.governance.mcp
#
# Covers bidirectional MCP governance:
#   - Outbound: tool call arguments (tool_acl, env_block, security patterns)
#   - Inbound:  tool results (PII redaction, exfil detection)

package revoc.governance.mcp

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ── Tool ACL (Profile tier) ───────────────────────────────────────────────────
# Block tool calls to tools not permitted for the caller's team.

violations contains v if {
	input.request_type == "McpToolCall"
	tool_name := input.tool_call.tool_name
	acl := data.revoc.policies.mcp_tool_acl[tool_name]
	caller_team := input.caller.team
	not caller_team in acl.allowed_teams
	v := {
		"rule_id":  "mcp_tool_acl_v1",
		"message":  sprintf("Tool '%v' is not allowed for team '%v'", [tool_name, caller_team]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── Environment block (Profile tier) ─────────────────────────────────────────
# Block tool calls that are explicitly blocked in the current environment.

violations contains v if {
	input.request_type == "McpToolCall"
	tool_name := input.tool_call.tool_name
	acl := data.revoc.policies.mcp_tool_acl[tool_name]
	env := input.caller.environment
	env in acl.blocked_environments
	v := {
		"rule_id":  "mcp_env_block_v1",
		"message":  sprintf("Tool '%v' is blocked in environment '%v'", [tool_name, env]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── DDL mutation in tool arguments (Security tier) ────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	f.metadata.pattern_name == "DDL_MUTATION"
	v := {
		"rule_id":  "sec_ddl_mutation_v1",
		"message":  "DDL mutation (DROP/TRUNCATE/ALTER) detected in tool argument",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── DELETE without WHERE clause in tool arguments (Security tier) ────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	f.metadata.pattern_name == "DELETE_NO_WHERE"
	v := {
		"rule_id":  "sec_delete_no_where_v1",
		"message":  "DELETE statement without a WHERE clause detected in tool argument",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Mass delete operation in tool arguments (Security tier) ──────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	f.metadata.pattern_name == "MASS_DELETE"
	v := {
		"rule_id":  "sec_mass_delete_v1",
		"message":  "Mass delete operation detected in tool argument",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── SSRF in tool arguments (Security tier) ────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SSRF_ATTEMPT"
	v := {
		"rule_id":  "sec_ssrf_v1",
		"message":  "SSRF: internal network address detected in tool argument",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Path traversal in tool arguments (Security tier) ──────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PATH_TRAVERSAL"
	v := {
		"rule_id":  "sec_path_traversal_v1",
		"message":  "Path traversal sequence detected in tool argument",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Prompt injection in sampling messages (Security tier) ─────────────────────

violations contains v if {
	input.request_type == "McpSampling"
	some f in input.findings
	f.finding_type == "PROMPT_INJECTION"
	v := {
		"rule_id":  "sec_prompt_injection_v1",
		"message":  "Prompt injection attempt detected in MCP sampling message",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Encoded evasion in any MCP direction (Security tier) ──────────────────────

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

# ── PII in MCP tool result (Security tier, bidirectional) ─────────────────────
# Results returning PII to the AI client must be redacted before forwarding.

violations contains v if {
	input.request_type == "McpToolResult"
	some f in input.findings
	f.finding_type == "PII"
	v := {
		"rule_id":  "mcp_result_pii_v1",
		"message":  sprintf("PII entity '%v' detected in MCP tool result", [f.pii_entity]),
		"severity": "HIGH",
		"action":   "redact",
		"tier":     "security",
	}
}

# ── Secret in MCP tool result (Security tier) ─────────────────────────────────

violations contains v if {
	input.request_type == "McpToolResult"
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "secret_block_v1",
		"message":  "Secret credential detected in MCP tool result",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Session data exfiltration (Security tier) ─────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SESSION_ANOMALY"
	v := {
		"rule_id":  "session_data_exfil_v1",
		"message":  "Session exfiltration pattern detected",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}
