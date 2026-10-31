//! Upstream HTTP client with connection pooling, TLS (rustls), and HTTP/2.

use std::time::Duration;

use revoc_config::Config;
use revoc_core::RevocError;

/// Shared HTTP client for all upstream provider calls.
#[derive(Clone, Debug)]
pub struct UpstreamClient {
    inner: reqwest::Client,
}

impl UpstreamClient {
    /// Build a new client from the proxy configuration.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] if the client cannot be built.
    pub fn new(cfg: &Config) -> Result<Self, RevocError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.upstream.timeout_ms))
            .connect_timeout(Duration::from_millis(cfg.upstream.connect_timeout_ms))
            .pool_max_idle_per_host(cfg.upstream.max_idle_connections_per_host)
            .user_agent("revoc-proxy/1.0.0")
            .use_rustls_tls()
            .https_only(false) // Allow HTTP for mock/dev mode
            .build()
            .map_err(|e| RevocError::Configuration(format!("Upstream client build error: {e}")))?;
        Ok(Self { inner: client })
    }

    /// Access the inner `reqwest::Client`.
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}
