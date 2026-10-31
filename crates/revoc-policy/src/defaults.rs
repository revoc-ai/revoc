//! Embedded default policy files (loaded at compile time via `include_str!`).
//!
//! Compiled-in default Rego policy files embedded at build time for zero-config deployments.
//! The `build.rs` script asserts all five files exist before compilation.

/// Default main governance decision policy.
pub const MAIN_REGO: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/default/main.rego"));

/// LLM-specific governance violations policy.
pub const LLM_GOVERNANCE_REGO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policies/default/llm_governance.rego"
));

/// MCP-specific governance violations policy.
pub const MCP_GOVERNANCE_REGO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policies/default/mcp_governance.rego"
));

/// Quota governance violations policy.
pub const QUOTA_GOVERNANCE_REGO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policies/default/quota_governance.rego"
));

/// Policy data document (org quotas, ACL lists, etc.).
pub const DATA_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/default/data.json"));
