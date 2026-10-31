//! Upstream provider routing and request translation.

use std::collections::HashMap;

use revoc_config::{Config, ProviderConfig};
use revoc_core::RevocError;


/// Routes requests to the configured upstream AI providers.
#[derive(Clone, Debug)]
pub struct UpstreamRouter {
    providers: HashMap<String, ProviderConfig>,
    default_name: String,
}

impl UpstreamRouter {
    /// Build from the proxy config.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] if no provider has `default = true`.
    pub fn new(cfg: &Config) -> Result<Self, RevocError> {
        let mut providers = HashMap::new();
        let mut default_name = String::new();

        for p in &cfg.upstream.providers {
            if p.default {
                default_name.clone_from(&p.name);
            }
            providers.insert(p.name.clone(), p.clone());
        }

        if default_name.is_empty() {
            return Err(RevocError::Configuration(
                "No upstream provider has default=true".into(),
            ));
        }

        Ok(Self { providers, default_name })
    }

    /// Select the provider for a request.
    ///
    /// Priority: `X-Revoc-Provider` header → default provider.
    pub fn route(&self, headers: &http::HeaderMap) -> Option<&ProviderConfig> {
        if let Some(name) = headers.get("X-Revoc-Provider").and_then(|v| v.to_str().ok()) {
            if let Some(p) = self.providers.get(name) {
                return Some(p);
            }
        }
        self.providers.get(&self.default_name)
    }

    /// Return the default provider config.
    #[allow(dead_code)]
    pub fn default_provider(&self) -> Option<&ProviderConfig> {
        self.providers.get(&self.default_name)
    }

    /// Return all providers.
    #[allow(dead_code)]
    pub fn providers(&self) -> &HashMap<String, ProviderConfig> {
        &self.providers
    }

    /// Build an upstream `reqwest::RequestBuilder` from an original request.
    ///
    /// Applies:
    /// - SSRF protection via [`validate_upstream_url`]
    /// - Format translation (Anthropic messages API)
    /// - `User-Agent: revoc-proxy/1.0.0`
    /// - `X-Revoc-Depth` on the outgoing request (D9, Step 14)
    pub fn build_upstream_request(
        &self,
        client: &reqwest::Client,
        method: http::Method,
        path: &str,
        provider: &ProviderConfig,
        body: bytes::Bytes,
        current_depth: u8,
    ) -> Result<reqwest::RequestBuilder, RevocError> {
        let url = format!("{}{}", provider.base_url.trim_end_matches('/'), path);

        // SSRF protection — always validate
        validate_upstream_url(&url, &self.providers)?;

        let api_key = provider.api_key().unwrap_or_default();

        let mut builder = client
            .request(method, &url)
            .header("User-Agent", "revoc-proxy/1.0.0");

        // Provider-specific auth and format
        builder = match provider.format.as_str() {
            "anthropic" => builder
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01"),
            "azure" => builder
                .header("api-key", &api_key),
            _ => builder
                .header("Authorization", format!("Bearer {api_key}")),
        };

        // D9: set outgoing depth header (Step 14 / Step 10)
        let next_depth = current_depth.saturating_add(1);
        builder = builder.header(crate::depth::REVOC_DEPTH_HEADER, next_depth.to_string());

        if !body.is_empty() {
            builder = builder
                .header("Content-Type", "application/json")
                .body(body);
        }

        Ok(builder)
    }
}

/// SSRF protection: verify the URL's origin is in the configured provider list.
///
/// # Errors
/// Returns [`RevocError::Security`] when the URL is not in the allowlist.
pub fn validate_upstream_url(
    url: &str,
    providers: &HashMap<String, ProviderConfig>,
) -> Result<(), RevocError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| RevocError::Security(format!("Invalid upstream URL '{url}': {e}")))?;

    let origin = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
    let port_suffix = parsed
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let full_origin = format!("{origin}{port_suffix}");

    let allowed = providers.values().any(|p| {
        p.base_url.starts_with(&origin)
            || p.base_url.starts_with(&full_origin)
            || p.base_url.starts_with(url)
    });

    if !allowed {
        return Err(RevocError::Security(format!(
            "SSRF: upstream URL origin '{full_origin}' is not in configured providers"
        )));
    }

    Ok(())
}
