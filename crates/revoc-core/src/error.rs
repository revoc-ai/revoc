//! [`RevocError`] — the single error type for all REVOC failure modes.
//!
//! Every variant maps to an HTTP status code via [`RevocError::http_status`].
//! Upstream 4xx/5xx errors are **never** wrapped here — they are forwarded
//! verbatim (SPEC.md §17, §23 Rule 8).

/// All error conditions that can arise within the REVOC proxy.
#[derive(thiserror::Error, Debug)]
pub enum RevocError {
    /// Policy engine returned an error during rule evaluation.
    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluation(String),

    /// The OPA sidecar or WASM runtime could not be reached.
    #[error("Policy engine unreachable: {0}")]
    PolicyEngineUnreachable(String),

    /// Governance depth limit (10) was exceeded — possible infinite agent loop.
    #[error("Governance depth exceeded: {depth}/10")]
    GovernanceDepthExceeded {
        /// The depth value that triggered the limit.
        depth: u8,
    },

    /// Emergency kill-switch is active for the given scope.
    #[error("Kill-switch active: scope={scope}")]
    KillSwitchActive {
        /// The scope that is active (`global`, `org:<id>`, `caller:<id>`).
        scope: String,
    },

    /// ONNX model inference error.
    #[error("ONNX model error: {0}")]
    OnnxModel(String),

    /// Configuration file or field validation error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Authentication failed (invalid or missing API key / JWT).
    #[error("Authentication failed: {reason}")]
    Authentication {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Per-caller rate limit exceeded.
    #[error("Rate limit exceeded for caller '{caller_id}'")]
    RateLimitExceeded {
        /// The caller whose limit was exceeded.
        caller_id: String,
    },

    /// Upstream provider returned an HTTP error. The status is forwarded verbatim.
    #[error("Upstream error: HTTP {status} from {provider}")]
    Upstream {
        /// The HTTP status code returned by the upstream provider.
        status: u16,
        /// The provider name (e.g. "openai", "anthropic").
        provider: String,
    },

    /// Request body exceeded the configured `max_request_body_bytes` limit.
    #[error("Request body too large: {size} bytes (max: {max})")]
    BodyTooLarge {
        /// Actual body size in bytes.
        size: usize,
        /// Configured maximum in bytes.
        max: usize,
    },

    /// Request body could not be parsed into the expected format.
    #[error("Request parse error: {0}")]
    RequestParse(String),

    /// Redaction of a body field failed.
    #[error("Redaction failed: {0}")]
    Redaction(String),

    /// JSON serialization or deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Database query or migration error.
    #[error("Database error: {0}")]
    Database(String),

    /// I/O error (file, socket, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// HTTP client error from the upstream reqwest client.
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    /// A security invariant was violated (SSRF, header injection, etc.).
    #[error("Security violation: {0}")]
    Security(String),

    /// Detection did not complete (timeout or a failed stage). Callers fail
    /// closed: an incomplete scan is never treated as a clean one.
    #[error("Detection incomplete: {0}")]
    Detection(String),
}

impl RevocError {
    /// Returns `true` if this error is transient and the request may be retried.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::PolicyEngineUnreachable(_) | Self::Upstream { .. }
        )
    }

    /// Maps this error to the appropriate HTTP response status code.
    ///
    /// Upstream errors pass through their original status unchanged.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Authentication { .. } => 401,
            Self::RateLimitExceeded { .. } => 429,
            Self::BodyTooLarge { .. } => 413,
            Self::RequestParse(_) => 400,
            Self::PolicyEngineUnreachable(_)
            | Self::Detection(_)
            | Self::GovernanceDepthExceeded { .. }
            | Self::KillSwitchActive { .. } => 503,
            Self::Upstream { status, .. } => *status,
            _ => 500,
        }
    }
}
