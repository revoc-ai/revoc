//! Policy engine for REVOC — native rules, OPA sidecar, OPA WASM,
//! D12 conflict resolution, and decision cache.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cache;
pub mod conflict;
pub mod defaults;
pub mod engine;
pub mod native;
pub mod sidecar;
pub mod wasm;

pub use cache::DecisionCache;
pub use conflict::{is_security_rule, resolve, SECURITY_RULE_IDS};
pub use engine::RevocPolicyEngine;
pub use native::NativePolicyEngine;
pub use sidecar::SidecarPolicyEngine;
pub use wasm::WasmPolicyEngine;

#[cfg(test)]
mod tests;
