//! D9 — Governance depth limiting (SPEC.md §9 D9).
//!
//! Every handler checks this BEFORE reading the body.
//! Requests at depth ≥ 10 are rejected with HTTP 503 immediately.

use revoc_core::RevocError;

/// Maximum permitted governance nesting depth (SPEC.md Principle 6).
pub const MAX_GOVERNANCE_DEPTH: u8 = 10;

/// The HTTP request/response header that carries the depth counter.
pub const REVOC_DEPTH_HEADER: &str = "X-Revoc-Depth";

/// Extract the governance depth from an incoming request's headers.
///
/// Returns `0` if the header is absent or unparseable (top-level request).
pub fn extract_depth(headers: &http::HeaderMap) -> u8 {
    headers
        .get(REVOC_DEPTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0)
}

/// Validate that `depth` is within the allowed limit.
///
/// # Errors
/// Returns [`RevocError::GovernanceDepthExceeded`] if `depth >= MAX_GOVERNANCE_DEPTH`.
pub fn check_depth(depth: u8) -> Result<(), RevocError> {
    if depth >= MAX_GOVERNANCE_DEPTH {
        Err(RevocError::GovernanceDepthExceeded { depth })
    } else {
        Ok(())
    }
}

/// Set `X-Revoc-Depth: {current + 1}` on outgoing upstream request headers.
///
/// Called at Step 14 in the LLM handler lifecycle and Step 10 in the MCP handler.
/// `X-Revoc-Depth` is set on **upstream** requests only — never on client responses
/// (SPEC.md §23 Rule 12).
#[allow(dead_code)]
pub fn set_outgoing_depth(headers: &mut http::HeaderMap, current: u8) {
    let next = current.saturating_add(1);
    if let Ok(v) = next.to_string().parse::<http::HeaderValue>() {
        headers.insert(REVOC_DEPTH_HEADER, v);
    }
}
