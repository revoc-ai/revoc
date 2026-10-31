# REVOC default governance — main decision entry point.
# Package: revoc.governance.main
# OPA eval URL: POST /v1/data/revoc/governance/main/decision
#
# Aggregates violations from llm, mcp, and quota sub-packages (plus any
# active compliance profile), then resolves them per D12 conflict rules:
#
#   Tier precedence:  emergency > security > profile > custom > default
#   Action priority:  block > redact > audit > allow
#   Invariant:        any Security-tier block wins regardless of other rules.

package revoc.governance.main

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ── Aggregate violations from core sub-packages ───────────────────────────────

all_violations contains v if { v := data.revoc.governance.llm.violations[_] }
all_violations contains v if { v := data.revoc.governance.mcp.violations[_] }
all_violations contains v if { v := data.revoc.governance.quota.violations[_] }

# ── Aggregate violations from the active compliance profile ───────────────────

all_violations contains v if {
	input.caller.policy_profile == "hipaa"
	v := data.revoc.governance.profile.hipaa.violations[_]
}

all_violations contains v if {
	input.caller.policy_profile == "pci-dss"
	v := data.revoc.governance.profile.pci_dss.violations[_]
}

all_violations contains v if {
	input.caller.policy_profile == "gdpr"
	v := data.revoc.governance.profile.gdpr.violations[_]
}

all_violations contains v if {
	input.caller.policy_profile == "soc2"
	v := data.revoc.governance.profile.soc2.violations[_]
}

all_violations contains v if {
	input.caller.policy_profile == "financial-services"
	v := data.revoc.governance.profile.financial_services.violations[_]
}

all_violations contains v if {
	input.caller.policy_profile == "internal-dev"
	v := data.revoc.governance.profile.internal_dev.violations[_]
}

# ── D12: Security-tier block always wins ─────────────────────────────────────
# SPEC.md §9 D12 / §23 Rule 15: "If ANY Security-tier block fires, return it
# regardless of other rules" — mirrors revoc-policy/src/conflict.rs::resolve(),
# which returns the matching Security-tier block verbatim, untouched by any
# Custom/Profile/Default-tier violation that may have fired alongside it.

security_blocks := [v |
	some v in all_violations
	v.tier == "security"
	v.action == "block"
]

has_security_block if count(security_blocks) > 0

# Deterministic single-winner pick when multiple Security-tier blocks fire —
# lowest rule_id wins, so the reported decision is stable across evaluations
# regardless of Rego's unordered set iteration.
winning_security_rule_id := min([v.rule_id | some v in security_blocks]) if has_security_block

winning_security_block := [v | some v in security_blocks; v.rule_id == winning_security_rule_id][0] if {
	has_security_block
}

# ── Final action: block > redact > audit > allow ──────────────────────────────

final_action := "block" if {
	some v in all_violations
	v.action == "block"
} else := "redact" if {
	some v in all_violations
	v.action == "redact"
} else := "audit" if {
	some v in all_violations
	v.action == "audit"
} else := "allow"

# ── Effective action (shadow mode always downgrades to audit) ─────────────────

effective_action := "audit" if {
	input.caller.enforcement_mode == "shadow"
} else := final_action

# ── Winning violation set ──────────────────────────────────────────────────────
# D12 invariant: when ANY Security-tier block fires, it alone determines the
# reported rules/reason/severity/tier — lower-tier violations that also matched
# the winning action ("block") are NOT blended in, since they lost the conflict
# resolution outright. Otherwise, all violations sharing the winning action are
# aggregated (this is the normal case — e.g. multiple PII findings → redact).

winning_violations := [winning_security_block] if {
	has_security_block
} else := [v |
	some v in all_violations
	v.action == final_action
]

# ── Collect applicable rule IDs and messages for the winning violation set ────

applicable_rules := [r | some v in winning_violations; r := v.rule_id]

winning_msgs := [v.message | some v in winning_violations]

first_reason := winning_msgs[0] if { count(winning_msgs) > 0 }
default first_reason := "All governance checks passed."

# ── Severity: take highest across winning violations ──────────────────────────

severity_order := {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
idx_to_severity := {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

winning_sev_idxs := [severity_order[v.severity] | some v in winning_violations]

max_sev_idx := max(winning_sev_idxs) if { count(winning_sev_idxs) > 0 }

final_severity := idx_to_severity[max_sev_idx] if { count(winning_sev_idxs) > 0 }
default final_severity := "INFO"

# ── Tier: take highest across winning violations ──────────────────────────────

tier_order := {"default": 0, "custom": 1, "profile": 2, "security": 3, "emergency": 4}
idx_to_tier := {0: "default", 1: "custom", 2: "profile", 3: "security", 4: "emergency"}

winning_tier_idxs := [tier_order[v.tier] | some v in winning_violations]

max_tier_idx := max(winning_tier_idxs) if { count(winning_tier_idxs) > 0 }

final_tier := idx_to_tier[max_tier_idx] if { count(winning_tier_idxs) > 0 }
default final_tier := "default"

# ── Evaluation timestamp ───────────────────────────────────────────────────────
# Computed from the real wall-clock at evaluation time (UTC, RFC3339) — never a
# fabricated constant. `eval_duration_ms` and `policy_engine` below are
# rewritten in-flight by the proxy's sidecar client
# (revoc-policy/src/sidecar.rs) once it measures the actual round-trip latency;
# `evaluated_at` receives no such rewrite, so it must already carry a real,
# computed timestamp when it leaves this policy.

now_ns := time.now_ns()

evaluated_at := sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", [
	time.date(now_ns)[0], time.date(now_ns)[1], time.date(now_ns)[2],
	time.clock(now_ns)[0], time.clock(now_ns)[1], time.clock(now_ns)[2],
])

# ── The decision object (PolicyDecision shape) ────────────────────────────────
# Deserialized by sidecar.rs into revoc_core::PolicyDecision.

decision := {
	"action":           final_action,
	"effective_action": effective_action,
	"reason":           first_reason,
	"applicable_rules": applicable_rules,
	"severity":         final_severity,
	"tier":             final_tier,
	"metadata":         {},
	"eval_duration_ms": 0.0,
	"cache_hit":        false,
	"policy_engine":    "opa_http",
	"evaluated_at":     evaluated_at,
}
