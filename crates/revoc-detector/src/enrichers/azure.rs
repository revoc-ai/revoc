//! Azure Content Safety enricher.
//!
//! Calls the Azure AI Content Safety API for additional classification.
//! Non-blocking: any error returns `vec![]` with a warning.

use std::time::Duration;

use tracing::warn;

/// Azure AI Content Safety enricher.
#[derive(Debug, Clone)]
pub struct AzureContentSafetyEnricher {
    client: reqwest::Client,
    /// Azure Content Safety endpoint URL.
    pub endpoint: String,
    /// API key (from environment).
    api_key: String,
}

impl AzureContentSafetyEnricher {
    /// Create a new enricher.
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            endpoint: endpoint.into(),
            api_key: api_key.into(),
        }
    }

    /// Analyze `text` and return raw Azure Content Safety results.
    ///
    /// Always returns `vec![]` on any error (timeout, connection, parse).
    pub async fn enrich(&self, text: &str) -> Vec<serde_json::Value> {
        let payload = serde_json::json!({
            "text": text
        });

        let resp = match self
            .client
            .post(format!(
                "{}/contentsafety/text:analyze?api-version=2023-10-01",
                self.endpoint
            ))
            .header("Ocp-Apim-Subscription-Key", &self.api_key)
            .json(&payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(enricher = "azure_content_safety", error = %e, "Request failed");
                return vec![];
            }
        };

        match resp.json::<serde_json::Value>().await {
            Ok(v) => v
                .get("categoriesAnalysis")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default(),
            Err(e) => {
                warn!(enricher = "azure_content_safety", error = %e, "Response parse failed");
                vec![]
            }
        }
    }
}
