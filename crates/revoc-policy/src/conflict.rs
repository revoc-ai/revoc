//! D12 — Policy conflict resolution (SPEC.md §9 D12).
//!
//! Tier precedence: Emergency=4 > Security=3 > Profile=2 > Custom=1 > Default=0
//! Within a tier: Block > Redact > Audit > Allow
//! **Critical invariant**: if ANY Security-tier Block fires, it wins regardless of all
//! other rules. Security rules cannot be overridden by Custom or Profile allows.

use revoc_core::{Action, PolicyDecision, PolicyRuleTier};

/// The 10 built-in security rule IDs that operate at Tier 3 and cannot be
/// overridden by any Custom or Profile allow rule (SPEC.md §9 D12).
pub const SECURITY_RULE_IDS: &[&str] = &[
    "sec_ddl_mutation_v1",
    "sec_delete_no_where_v1",
    "sec_ssrf_v1",
    "sec_path_traversal_v1",
    "sec_prompt_injection_v1",
    "sec_sysextract_v1",
    "sec_encoded_evasion_v1",
    "sec_mass_delete_v1",
    "secret_block_v1",
    "session_data_exfil_v1",
    "mcp_result_pii_v1",
];

/// Returns `true` if `rule_id` is a built-in Security-tier rule.
pub fn is_security_rule(rule_id: &str) -> bool {
    SECURITY_RULE_IDS.contains(&rule_id)
}

/// Resolve a collection of policy violations into a single [`PolicyDecision`].
///
/// Algorithm (SPEC.md §9 D12):
/// 1. If **any** violation has `tier >= Security` AND `action == Block` → return it
///    immediately (Security tier always wins).
/// 2. Otherwise: pick the violation with the highest tier; ties broken by action
///    priority (`Block > Redact > Audit > Allow`).
/// 3. Empty violations → `PolicyDecision::allow()`.
pub fn resolve(violations: &[PolicyDecision]) -> PolicyDecision {
    // Step 1: Security-tier block always wins
    for v in violations {
        if v.tier >= PolicyRuleTier::Security && v.action.is_blocking() {
            return v.clone();
        }
    }

    // Step 2: max by tier, then action priority
    violations
        .iter()
        .max_by(|a, b| {
            a.tier
                .cmp(&b.tier)
                .then_with(|| action_priority(&a.action).cmp(&action_priority(&b.action)))
        })
        .cloned()
        .unwrap_or_else(PolicyDecision::allow)
}

/// Numeric priority for tie-breaking within a tier.
fn action_priority(a: &Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Audit => 1,
        Action::Redact => 2,
        Action::Block => 3,
    }
}
