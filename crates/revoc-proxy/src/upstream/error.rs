//! Upstream error transparency (SPEC.md §17, §23 Rule 8).

/// Returns `true` when an upstream HTTP status should be forwarded verbatim.
///
/// When `true`: copy the upstream response body and headers as-is; add only
/// `X-Revoc-Trace-ID`. **Never** wrap the error body in [`RevocErrorResponse`].
pub fn should_forward_verbatim(status: u16) -> bool {
    status >= 400
}
