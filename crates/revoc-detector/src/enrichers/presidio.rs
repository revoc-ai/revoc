//! Microsoft Presidio enricher.
//!
//! Calls the Presidio Analyzer HTTP service for higher-recall NER.
//! Non-blocking: any error returns `vec![]` with a warning.

use std::time::Duration;

use tracing::warn;

/// Presidio Analyzer enricher.
#[derive(Debug, Clone)]
pub struct PresidioEnricher {
    client: reqwest::Client,
    /// Base URL of the Presidio analyzer service.
    pub url: String,
}

impl PresidioEnricher {
    /// Create a new enricher pointing at `url`.
    pub fn new(url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            url: url.into(),
        }
    }

    /// Analyze `text` and return raw Presidio analyzer results.
    ///
    /// Always returns `vec![]` on any error (timeout, connection, parse).
    pub async fn enrich(&self, text: &str) -> Vec<serde_json::Value> {
        let payload = serde_json::json!({
            "text": text,
            "language": "en"
        });

        let resp = match self
            .client
            .post(format!("{}/analyze", self.url))
            .json(&payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(enricher = "presidio", error = %e, "Request failed");
                return vec![];
            }
        };

        match resp.json::<Vec<serde_json::Value>>().await {
            Ok(results) => results,
            Err(e) => {
                warn!(enricher = "presidio", error = %e, "Response parse failed");
                vec![]
            }
        }
    }
}
