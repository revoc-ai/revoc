//! Request ID and governance depth extraction middleware.

use axum::{extract::Request, middleware::Next, response::Response};
use uuid::Uuid;

/// Extension: the UUID v7 request identifier.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Extension: the governance depth extracted from `X-Revoc-Depth`.
#[derive(Clone, Copy, Debug, Default)]
pub struct GovernanceDepth(pub u8);

/// Middleware: generate / read `X-Revoc-Request-ID` and extract depth.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = req
        .headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| Uuid::now_v7().to_string(), str::to_owned);

    let depth = crate::depth::extract_depth(req.headers());

    req.extensions_mut().insert(RequestId(request_id.clone()));
    req.extensions_mut().insert(GovernanceDepth(depth));

    let mut resp = next.run(req).await;

    // Set X-Revoc-Request-ID on the response
    if let Ok(v) = request_id.parse() {
        resp.headers_mut().insert("X-Revoc-Request-ID", v);
    }

    resp
}
