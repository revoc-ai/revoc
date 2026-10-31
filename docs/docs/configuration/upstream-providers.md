# Upstream Providers

REVOC routes governed requests to one or more configured upstream AI providers.
The upstream URL is always taken from the provider configuration — never from
request headers (SSRF protection).

## Provider Configuration

```toml
[[upstream.providers]]
name = "openai"
base_url = "https://api.openai.com"
api_key_env = "OPENAI_API_KEY"   # env var name that holds the key
api_key_file = ""                 # alternative: read key from file
format = "openai"
default = true                    # used when no provider header is present
```

## Supported Formats

| Format | Provider | Base URL |
|---|---|---|
| `openai` | OpenAI, Together AI, Groq, Mistral, Ollama, vLLM | varies |
| `anthropic` | Anthropic | `https://api.anthropic.com` |
| `azure` | Azure OpenAI | `https://<deployment>.openai.azure.com` |

## OpenAI-Compatible Providers

Any provider that implements the OpenAI API format works with `format = "openai"`:

```toml
[[upstream.providers]]
name = "groq"
base_url = "https://api.groq.com/openai"
api_key_env = "GROQ_API_KEY"
format = "openai"
default = false

[[upstream.providers]]
name = "ollama"
base_url = "http://ollama:11434"
api_key_env = ""                  # Ollama doesn't require an API key
format = "openai"
default = false
```

## Provider Routing

REVOC selects the provider for each request based on:

1. `X-Revoc-Provider: <name>` request header — if present, use this provider
2. The `default = true` provider — if no header present
3. Model prefix matching — `claude-*` routes to Anthropic if an Anthropic provider is configured

## API Key Security

API keys are never logged, never included in audit events, and never forwarded
to the REVOC dashboard. The proxy injects the upstream API key into the outgoing
request at the last moment before forwarding.

API keys can be stored in:
- Environment variables (`api_key_env`) — simpler, suitable for container deployments
- Files (`api_key_file`) — preferred for production; use a secrets manager to write the file

## Format Translation

When the client uses OpenAI format and the upstream provider requires Anthropic format,
REVOC translates the request automatically:

```
OpenAI ChatCompletionRequest
  → messages[] → Anthropic messages[]
  → model name → Anthropic model ID
  → system message → Anthropic system field
  → tool_calls → Anthropic tool_use blocks
```

The response is translated back to OpenAI format before returning to the client.
The `X-Revoc-Trace-ID` and other governance headers are set on the translated response.

## Mock Mode

For development and testing without a real upstream:

```toml
[upstream]
mock_mode = true
mock_response = "Mock response. Governance pipeline ran."
```

The full detection and policy pipeline runs. Every request returns the configured
mock response with `finish_reason: stop`. Useful for testing governance rules without
incurring API costs.

## SSRF Protection

Upstream URLs are validated against the configured provider list before any
network connection is made:

```rust
fn validate_upstream_url(url: &Url, providers: &[ProviderConfig]) -> Result<(), RevocError> {
    let origin = url.origin().ascii_serialization();
    if !providers.iter().any(|p| p.base_url.starts_with(&origin)) {
        return Err(RevocError::Security("SSRF: URL not in allowed providers".into()));
    }
    Ok(())
}
```

Any attempt to route a request to an internal IP or an unlisted domain returns
HTTP 400 `REVOC_SECURITY_VIOLATION` and is logged as a security event.
