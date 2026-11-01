//! Size-bounded body reading for client requests and upstream responses.

use axum::body::Body;
use http_body_util::{BodyExt, Limited};
use revoc_core::RevocError;

/// Read a client request body, stopping as soon as it exceeds `max_bytes`.
///
/// The limit is enforced while streaming, so an oversized body is never
/// buffered in full.
///
/// # Errors
/// [`RevocError::BodyTooLarge`] past the limit; [`RevocError::RequestParse`]
/// when the body stream itself fails.
pub async fn read_request_limited(
    body: Body,
    max_bytes: usize,
) -> Result<bytes::Bytes, RevocError> {
    match Limited::new(body, max_bytes).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e)
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            Err(RevocError::BodyTooLarge {
                size: max_bytes.saturating_add(1),
                max: max_bytes,
            })
        }
        Err(e) => Err(RevocError::RequestParse(e.to_string())),
    }
}

/// Read an upstream response body, failing once it exceeds `max_bytes`.
///
/// Rejects early on a declared `Content-Length` over the limit, then enforces
/// the limit chunk by chunk for bodies without one.
///
/// # Errors
/// [`RevocError::BodyTooLarge`] past the limit; [`RevocError::HttpClient`]
/// when reading from the upstream fails.
pub async fn read_response_limited(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<bytes::Bytes, RevocError> {
    if let Some(len) = resp.content_length() {
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > max_bytes {
            return Err(RevocError::BodyTooLarge {
                size: len,
                max: max_bytes,
            });
        }
    }
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > max_bytes {
            return Err(RevocError::BodyTooLarge {
                size: buf.len() + chunk.len(),
                max: max_bytes,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_within_limit_is_read() {
        let b = read_request_limited(Body::from("hello"), 5)
            .await
            .expect("ok");
        assert_eq!(&b[..], b"hello");
    }

    #[tokio::test]
    async fn request_over_limit_is_rejected() {
        let err = read_request_limited(Body::from("hello!"), 5)
            .await
            .unwrap_err();
        assert!(matches!(err, RevocError::BodyTooLarge { max: 5, .. }));
    }

    #[tokio::test]
    async fn response_over_limit_is_rejected() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("x".repeat(100)))
            .mount(&server)
            .await;
        let resp = reqwest::get(server.uri()).await.expect("resp");
        let err = read_response_limited(resp, 10).await.unwrap_err();
        assert!(matches!(err, RevocError::BodyTooLarge { max: 10, .. }));

        let resp = reqwest::get(server.uri()).await.expect("resp");
        assert_eq!(
            read_response_limited(resp, 100).await.expect("ok").len(),
            100
        );
    }
}
