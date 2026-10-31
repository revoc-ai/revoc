# REVOC PCI-DSS compliance profile.
# Package: revoc.governance.profile.pci-dss
#
# Enforces PCI-DSS v4 requirements for cardholder data:
#   - Primary Account Numbers (credit cards), routing/account numbers → Remove.
#   - send_email to external addresses blocked (CHD exfil risk).
#   - Secrets in any direction → block.
#   - Logging of cardholder data is prohibited (redaction is the enforcement).

package revoc.governance.profile.pci_dss

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Cardholder Data Environment (CDE) entity types.
cde_entities := {
	"CREDIT_CARD", "ROUTING_NUMBER", "BANK_ACCOUNT", "IBAN_CODE", "SWIFT_BIC",
}

# ── CHD must be removed ───────────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in cde_entities
	v := {
		"rule_id":  "pci_chd_remove_v1",
		"message":  sprintf("PCI-DSS: cardholder data '%v' must be removed", [f.pii_entity]),
		"severity": "CRITICAL",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── SSN and passport also removed ────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	f.pii_entity in {"US_SSN", "US_PASSPORT"}
	v := {
		"rule_id":  "pci_sensitive_auth_remove_v1",
		"message":  sprintf("PCI-DSS: sensitive authentication data '%v' must be removed", [f.pii_entity]),
		"severity": "HIGH",
		"action":   "redact",
		"tier":     "profile",
	}
}

# ── send_email blocked (CHD exfiltration risk) ────────────────────────────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.tool_call.tool_name == "send_email"
	v := {
		"rule_id":  "pci_no_email_chd_v1",
		"message":  "PCI-DSS: send_email is blocked to prevent cardholder data exfiltration",
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── execute_shell blocked in production (system integrity) ────────────────────

violations contains v if {
	input.request_type == "McpToolCall"
	input.tool_call.tool_name == "execute_shell"
	input.caller.environment in {"production", "staging"}
	v := {
		"rule_id":  "pci_no_shell_prod_v1",
		"message":  "PCI-DSS: execute_shell is blocked in production/staging (system integrity requirement)",
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── All secrets → block ───────────────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "pci_secret_block_v1",
		"message":  "PCI-DSS: credential exposure is blocked per requirement 8",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── DDL mutations in CDE context → block ──────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	v := {
		"rule_id":  "pci_ddl_block_v1",
		"message":  "PCI-DSS: DDL mutations in CDE context are blocked",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}
