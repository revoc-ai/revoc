# REVOC quota governance violations.
# Package: revoc.governance.quota
#
# Enforces per-request token budgets.
# Lookup order: org-specific caller → org default → global default.

package revoc.governance.quota

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ── Token budget (Profile tier) ───────────────────────────────────────────────

violations contains v if {
	input.token_usage != null
	total := input.token_usage.total_tokens
	limit := effective_token_limit
	total > limit
	v := {
		"rule_id":  "token_quota_v1",
		"message":  sprintf("Token usage %v exceeds limit %v for caller '%v'", [total, limit, input.caller.caller_id]),
		"severity": "HIGH",
		"action":   "block",
		"tier":     "profile",
	}
}

# ── Quota lookup helpers ──────────────────────────────────────────────────────

# Try org-specific caller quota first, then org default, then global default.
effective_token_limit := limit if {
	limit := data.revoc.policies.quotas[input.caller.caller_id].tokens_per_request
} else := limit if {
	limit := data.revoc.policies.quotas[input.caller.org_id].tokens_per_request
} else := limit if {
	limit := data.revoc.policies.quotas["default"].tokens_per_request
} else := 100000
