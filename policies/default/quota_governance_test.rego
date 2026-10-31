package revoc.governance.quota_test

import future.keywords.if
import future.keywords.in

# ── Shared fixtures ───────────────────────────────────────────────────────────

base_caller := {
	"org_id":           "org-test",
	"caller_id":        "caller-test",
	"team":             "engineering",
	"environment":      "development",
	"enforcement_mode": "enforce",
	"policy_profile":   null,
	"governance_depth": 0,
}

base_input := {
	"request_id":       "quota-test-001",
	"request_type":     "LlmResponse",
	"caller":           base_caller,
	"findings":         [],
	"model":            "gpt-4o",
	"provider":         "openai",
	"session_state":    null,
	"tool_call":        null,
	"governance_depth": 0,
	"timestamp":        1700000000,
}

# ── test_within_global_default_no_violation ───────────────────────────────────

test_within_global_default if {
	inp := object.union(base_input, {
		"token_usage": {
			"prompt_tokens":      500,
			"completion_tokens":  500,
			"total_tokens":       1000,
			"estimated_cost_usd": 0.001,
		},
	})
	result := data.revoc.governance.quota.violations with input as inp
	count(result) == 0
}

# ── test_exceed_global_default_triggers_block ─────────────────────────────────
# Global default is 100 000 tokens; use 100 001.

test_exceed_global_default if {
	inp := object.union(base_input, {
		"token_usage": {
			"prompt_tokens":      50001,
			"completion_tokens":  50000,
			"total_tokens":       100001,
			"estimated_cost_usd": 0.1,
		},
	})
	result := data.revoc.governance.quota.violations with input as inp
	count(result) > 0
	some v in result
	v.rule_id == "token_quota_v1"
	v.action == "block"
}

# ── test_anonymous_caller_lower_limit ─────────────────────────────────────────
# Anonymous callers have a 10 000 token limit.

mock_quotas := {
	"default":   {"tokens_per_request": 100000, "tokens_per_minute": 500000, "requests_per_minute": 100},
	"anonymous": {"tokens_per_request": 10000,  "tokens_per_minute": 50000,  "requests_per_minute": 20},
}

test_anonymous_caller_lower_limit if {
	anon_caller := object.union(base_caller, {"caller_id": "anonymous"})
	inp := object.union(base_input, {
		"caller": anon_caller,
		"token_usage": {
			"prompt_tokens":      5001,
			"completion_tokens":  5000,
			"total_tokens":       10001,
			"estimated_cost_usd": 0.002,
		},
	})
	result := data.revoc.governance.quota.violations
		with input as inp
		with data.revoc.policies.quotas as mock_quotas
	count(result) > 0
	some v in result
	v.rule_id == "token_quota_v1"
}

# ── test_anonymous_within_limit_no_violation ──────────────────────────────────

test_anonymous_within_limit if {
	anon_caller := object.union(base_caller, {"caller_id": "anonymous"})
	inp := object.union(base_input, {
		"caller": anon_caller,
		"token_usage": {
			"prompt_tokens":      4000,
			"completion_tokens":  4000,
			"total_tokens":       8000,
			"estimated_cost_usd": 0.001,
		},
	})
	result := data.revoc.governance.quota.violations with input as inp
	count(result) == 0
}

# ── test_null_token_usage_no_violation ────────────────────────────────────────

test_null_token_usage_no_violation if {
	inp := object.union(base_input, {"token_usage": null})
	result := data.revoc.governance.quota.violations with input as inp
	count(result) == 0
}
