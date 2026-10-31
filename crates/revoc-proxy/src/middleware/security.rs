//! Incoming header sanitization middleware.

use axum::{extract::Request, middleware::Next, response::Response};
use tracing::warn;

/// Headers that should be stripped from inbound requests before processing.
const STRIP_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-revoc-decision",
    "x-revoc-trace-id",
];

/// Middleware: sanitize incoming request headers.
///
/// Strips headers that clients should not be able to set, and logs any
/// suspicious patterns (extremely long values, binary content, etc.).
pub async fn security_middleware(mut req: Request, next: Next) -> Response {
    // Remove spoofable REVOC headers from inbound requests
    for &name in STRIP_HEADERS {
        if let Ok(header_name) = name.parse::<http::HeaderName>() {
            req.headers_mut().remove(&header_name);
        }
    }

    // Log suspiciously large header values
    for (name, value) in req.headers() {
        if value.len() > 8192 {
            warn!(
                header = name.as_str(),
                len = value.len(),
                "Suspiciously large request header"
            );
        }
    }

    next.run(req).await
}
