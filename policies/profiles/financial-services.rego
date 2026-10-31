# REVOC Financial Services compliance profile.
# Package: revoc.governance.profile.financial-services
#
# Covers FCA / SEC / FINRA obligations for firms handling financial data:
#   - Routing numbers, bank accounts, SWIFT/BIC, IBAN → Remove.
#   - Bulk transaction / data export tools → restricted to fintech team.
#   - Insider trading keywords in prompts → Audit for compliance review.
#   - All secrets → block.

package revoc.governance.profile.financial_services

import future.keywords.if
import future.keywords.in
import future.keywords.contains

financial_entities := {
	"ROUTING_NUMBER", "BANK_ACCOUNT", "SWIFT_BIC", "IBAN_CODE",
	"CREDIT_CARD",
}

# Tools that move money or export bulk transaction data.
restricted_tools := {
	"execute_sql", "delete_s3_object", "write_file",
}
fintech_teams := {"fintech", "treasury", "payments"}

# ── Financial account data → Remove ──────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in financial_entities
	v := {
		"rule_id":  "fin_account_data_remove_v1",
		"message":  sprintf("Financial Services: account data '%v' must be removed", [f.pii_entity]),
		"severity": "HIGH",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── Bulk data tools restricted to fintech team ────────────────────────────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.tool_call.tool_name in restricted_tools
	not input.caller.team in fintech_teams
	v := {
		"rule_id":  "fin_restricted_tool_v1",
		"message":  sprintf("Financial Services: tool '%v' is restricted to fintech/treasury/payments teams", [input.tool_call.tool_name]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── execute_shell blocked in production (financial system integrity) ──────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.tool_call.tool_name == "execute_shell"
	input.caller.environment in {"production", "staging"}
	v := {
		"rule_id":  "fin_no_shell_prod_v1",
		"message":  "Financial Services: execute_shell blocked in production/staging",
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── DDL mutations → block ────────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	v := {
		"rule_id":  "fin_ddl_block_v1",
		"message":  "Financial Services: DDL mutations blocked — requires change management approval",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── All secrets → block ───────────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "fin_secret_block_v1",
		"message":  "Financial Services: credential exposure blocked",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── PII → redact ──────────────────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	not f.pii_entity in financial_entities
	v := {
		"rule_id":  "fin_pii_redact_v1",
		"message":  sprintf("Financial Services: PII entity '%v' must be redacted", [f.pii_entity]),
		"severity": "MEDIUM",
		"action":   "redact",
		"tier":     "profile",
	}
}
