//! HTTP-based community detection plugin interface.
//!
//! Plugins are external HTTP services that receive the inspection input and
//! return findings. They are **optional** and **non-blocking**: any error
//! (timeout, connection refused, bad JSON) is logged as a warning and the
//! stage returns `Ok(vec![])`. Plugin failures never propagate to the request
//! path (SPEC.md Principle 3).

use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use revoc_core::{DetectionStage, DetectionTier, Finding, InspectionInput, RevocError};

/// An HTTP-based community detection plugin.
#[derive(Debug)]
pub struct HttpDetectionPlugin {
    client: reqwest::Client,
    /// Logical name for tracing/metrics.
    pub name: String,
    /// Endpoint to POST the inspection payload to.
    pub url: String,
    /// Per-request timeout in milliseconds.
    pub timeout_ms: u64,
}

impl HttpDetectionPlugin {
    /// Create a new plugin with the given endpoint and timeout.
    pub fn new(name: impl Into<String>, url: impl Into<String>, timeout_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_default();

        Self {
            client,
            name: name.into(),
            url: url.into(),
            timeout_ms,
        }
    }
}

/// Minimal payload sent to the plugin endpoint.
#[derive(serde::Serialize)]
struct PluginRequest<'a> {
    request_id: &'a str,
    raw_body: &'a str,
}

#[async_trait]
impl DetectionStage for HttpDetectionPlugin {
    fn name(&self) -> &'static str {
        // SAFETY: name is stored in self; returning 'static requires a leak or static str.
        // We return a constant since the plugin name is used only for tracing labels.
        "http_plugin"
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::HttpPlugin
    }

    async fn detect(&self, input: &InspectionInput) -> Result<Vec<Finding>, RevocError> {
        let Ok(body_str) = std::str::from_utf8(&input.raw_body) else {
            warn!(plugin = %self.name, "Non-UTF-8 body — skipping plugin");
            return Ok(vec![]);
        };

        let payload = PluginRequest {
            request_id: &input.request_id,
            raw_body: body_str,
        };

        let resp = match self.client.post(&self.url).json(&payload).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(plugin = %self.name, error = %e, "HTTP plugin request failed");
                return Ok(vec![]);
            }
        };

        let findings: Vec<Finding> = match resp.json().await {
            Ok(f) => f,
            Err(e) => {
                warn!(plugin = %self.name, error = %e, "HTTP plugin response parse failed");
                vec![]
            }
        };

        Ok(findings)
    }
}
