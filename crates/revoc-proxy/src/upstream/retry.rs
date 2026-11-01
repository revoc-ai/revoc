//! Exponential backoff retry for upstream requests.

use std::time::Duration;

use tracing::warn;

use revoc_config::ProviderConfig;
use revoc_core::RevocError;

use super::router::UpstreamRouter;

/// Retry policy: which upstream status codes trigger a retry.
///
/// Only 429: the provider rejected the request without processing it.
/// 502/503/504 are not retried because completions are not idempotent — the
/// upstream may already have run (and billed) the request.
pub fn is_retryable_status(status: u16) -> bool {
    status == 429
}

/// Compute the delay for retry attempt `n` (0-indexed) with jitter.
/// Base: 200ms, max: 10s, jitter: ±25%.
pub fn backoff_delay(attempt: u32) -> Duration {
    let base_ms: u64 = 200 * (1u64 << attempt.min(5));
    let capped_ms = base_ms.min(10_000);
    // Simple jitter: use the attempt number as seed
    let jitter_ms = (capped_ms / 4) * (u64::from(attempt) % 3);
    Duration::from_millis(capped_ms + jitter_ms)
}

/// Parse a `Retry-After` header value expressed as a delay in seconds
/// (the numeric form; HTTP-date values are not produced by REVOC's
/// configured upstream providers and are treated as absent).
pub fn parse_retry_after(header: &str) -> Option<Duration> {
    header.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Execute `f` with up to `max_retries` retry attempts using exponential
/// backoff. Retries only on `Err`; the final attempt's error is returned
/// verbatim if every attempt fails.
pub async fn with_retry<F, Fut, T, E>(max_retries: u32, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt = 0;
    loop {
        if attempt > 0 {
            let delay = backoff_delay(attempt - 1);
            warn!(
                attempt,
                delay_ms = delay.as_millis(),
                "Retrying upstream request"
            );
            tokio::time::sleep(delay).await;
        }

        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt >= max_retries {
                    return Err(e);
                }
                attempt += 1;
            }
        }
    }
}

/// Send an upstream request with automatic retry on transient failures
/// (SPEC.md §23 — `RevocError::is_transient`, retryable HTTP status codes
/// 429/502/503/504, and `Retry-After`-aware backoff). The request is rebuilt
/// for each attempt since [`reqwest::RequestBuilder`] is consumed by `send`.
#[allow(clippy::too_many_arguments)]
pub async fn send_with_retries(
    router: &UpstreamRouter,
    client: &reqwest::Client,
    method: &http::Method,
    path: &str,
    provider: &ProviderConfig,
    body: &bytes::Bytes,
    governance_depth: u8,
    max_retries: u32,
) -> Result<reqwest::Response, RevocError> {
    let mut attempt: u32 = 0;
    loop {
        let request = router.build_upstream_request(
            client,
            method.clone(),
            path,
            provider,
            body.clone(),
            governance_depth,
        )?;

        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if attempt < max_retries && is_retryable_status(status) {
                    let delay = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_retry_after)
                        .unwrap_or_else(|| backoff_delay(attempt));
                    warn!(
                        attempt,
                        status,
                        delay_ms = delay.as_millis(),
                        "Retrying upstream request (retryable status)"
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                // Retry only when the connection was never established, so
                // the request cannot have reached the provider. A timeout may
                // fire after the body was sent, so it is not retried.
                let transient = e.is_connect();
                if attempt < max_retries && transient {
                    let delay = backoff_delay(attempt);
                    warn!(
                        attempt, error = %e, delay_ms = delay.as_millis(),
                        "Retrying upstream request (transport error)"
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(RevocError::HttpClient(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_429_is_retried() {
        assert!(is_retryable_status(429));
        for s in [500, 502, 503, 504, 400, 200] {
            assert!(!is_retryable_status(s), "{s} must not be retried");
        }
    }
}
