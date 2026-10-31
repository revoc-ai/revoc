# Policy Conflict Resolution

When multiple governance rules fire on the same request, REVOC uses a deterministic
tier-based resolution algorithm to select the effective action.

## Tier Precedence

Higher tier always wins. Within the same tier, more restrictive action wins.

| Tier | Name | Value | Overridable |
|---|---|---|---|
| Emergency | Kill-switch | 4 | No |
| Security | Built-in security rules | 3 | No |
| Profile | Compliance profile rules | 2 | By Security/Emergency only |
| Custom | Operator-defined rules | 1 | By Profile/Security/Emergency |
| Default | Baseline allow | 0 | By any higher tier |

## Action Priority (within same tier)

```
Block (3) > Redact (2) > Audit (1) > Allow (0)
```

## Resolution Algorithm

```rust
pub fn resolve(violations: &[PolicyDecision]) -> PolicyDecision {
    // Step 1: Security-tier block always wins over everything
    for v in violations {
        if v.tier >= PolicyRuleTier::Security && v.action.is_blocking() {
            return v.clone();
        }
    }
    // Step 2: Max by tier, then by action priority
    violations.iter()
        .max_by(|a, b| {
            a.tier.cmp(&b.tier)
                .then(action_priority(&a.action).cmp(&action_priority(&b.action)))
        })
        .cloned()
        .unwrap_or_else(PolicyDecision::allow)
}
```

## Examples

### Example 1 — Custom allow cannot override security block

Rules that fire:
- `my_allow_sql_v1` (Custom tier, Allow) — operator allows SQL tool calls for this org
- `sec_ddl_mutation_v1` (Security tier, Block) — DROP TABLE detected

**Result:** Block. Security tier wins regardless of custom allow.

### Example 2 — Profile redact beats custom allow

Rules that fire:
- `my_allow_email_v1` (Custom tier, Allow) — operator explicitly allows email in prompts
- `pii_email_v1` (Profile tier, Mask) — HIPAA profile requires email masking

**Result:** Mask. Profile tier (2) beats Custom tier (1).

### Example 3 — Block beats redact within same tier

Rules that fire:
- `pii_email_v1` (Profile tier, Mask)
- `pii_credit_card_v1` (Profile tier, Remove)
- `secret_block_v1` (Security tier, Block)

**Result:** Block. Security tier wins in Step 1 of the algorithm.

### Example 4 — Multiple profile-tier rules, no security violations

Rules that fire:
- `pii_email_v1` (Profile tier 2, Mask)
- `pii_phone_v1` (Profile tier 2, Mask)

**Result:** Redact (both emails and phones masked). Both rules apply — redaction
handles multiple findings in a single pass.

## Shadow Mode and Conflict Resolution

In shadow mode, conflict resolution runs identically. The resolved action is
recorded as the `decision` in the audit log. The `effective_action` is always
`audit` in shadow mode, regardless of the resolved `action`.

```
shadow-block = resolved: block, effective: audit
shadow-redact = resolved: redact, effective: audit
```

## Security Rule IDs

The following rule IDs are always treated as Security tier:

```
sec_ddl_mutation_v1, sec_delete_no_where_v1, sec_ssrf_v1,
sec_path_traversal_v1, sec_prompt_injection_v1, sec_sysextract_v1,
sec_encoded_evasion_v1, secret_block_v1,
session_data_exfil_v1, mcp_result_pii_v1
```

These IDs are hardcoded in `revoc-policy/src/conflict.rs::SECURITY_RULE_IDS`
and cannot be added to or removed from via configuration.
