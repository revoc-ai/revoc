# REVOC SOC 2 Type II compliance profile.
# Package: revoc.governance.profile.soc2
#
# Enforces SOC 2 Trust Service Criteria (Security, Availability, Confidentiality):
#   - All secrets → block (CC6.1 logical access controls).
#   - Admin tools in production → block (CC6.3 privileged access).
#   - DDL mutations → block (CC8.1 change management).
#   - SSRF / path traversal → block (CC7.1 threat detection).

package revoc.governance.profile.soc2

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Tools requiring admin/privileged access — blocked in production (CC6.3).
admin_tools := {"execute_shell", "create_user", "read_secrets", "delete_s3_object"}

# ── All secrets → block (CC6.1) ──────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "soc2_secret_block_v1",
		"message":  "SOC 2 CC6.1: credential exposure must be blocked (logical access control)",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Admin tools blocked in production (CC6.3) ─────────────────────────────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.caller.environment == "production"
	input.tool_call.tool_name in admin_tools
	v := {
		"rule_id":  "soc2_admin_tool_prod_block_v1",
		"message":  sprintf("SOC 2 CC6.3: admin tool '%v' is blocked in production (privileged access control)", [input.tool_call.tool_name]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── DDL mutations → block (CC8.1) ────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	v := {
		"rule_id":  "soc2_ddl_block_v1",
		"message":  "SOC 2 CC8.1: DDL schema change blocked — must go through change management",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── SSRF attempts → block (CC7.1) ────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SSRF_ATTEMPT"
	v := {
		"rule_id":  "soc2_ssrf_block_v1",
		"message":  "SOC 2 CC7.1: SSRF attempt detected — blocked by threat monitoring",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Path traversal → block (CC7.1) ───────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PATH_TRAVERSAL"
	v := {
		"rule_id":  "soc2_path_traversal_block_v1",
		"message":  "SOC 2 CC7.1: path traversal attempt blocked",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── PII in responses → redact (C1.1 confidentiality) ─────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	v := {
		"rule_id":  "soc2_pii_redact_v1",
		"message":  sprintf("SOC 2 C1.1: PII entity '%v' redacted (confidentiality commitment)", [f.pii_entity]),
		"severity": "MEDIUM",
		"action":   "redact",
		"tier":     "profile",
	}
}
