//! Secret / credential detection patterns (SPEC.md §8.2).

use fancy_regex::Regex;

use revoc_core::{PiiEntityType, Severity};

// ── Compiled patterns ──────────────────────────────────────────────────────────

static AWS_ACCESS_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIPA|AROA|ASCA|ASIA)[A-Z0-9]{16}")
        .unwrap_or_else(|e| { eprintln!("FATAL: AWS_ACCESS_KEY_RE compile failed: {e}"); std::process::exit(1) })
});

static AWS_SECRET_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // 40-char base64-ish string near AWS context keywords
    Regex::new(r#"(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"#)
        .unwrap_or_else(|e| { eprintln!("FATAL: AWS_SECRET_KEY_RE compile failed: {e}"); std::process::exit(1) })
});

static GITHUB_TOKEN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})")
        .unwrap_or_else(|e| { eprintln!("FATAL: GITHUB_TOKEN_RE compile failed: {e}"); std::process::exit(1) })
});

static OPENAI_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_\-]{64,}")
        .unwrap_or_else(|e| { eprintln!("FATAL: OPENAI_KEY_RE compile failed: {e}"); std::process::exit(1) })
});

static ANTHROPIC_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"sk-ant-[a-zA-Z0-9\-_]{95}")
        .unwrap_or_else(|e| { eprintln!("FATAL: ANTHROPIC_KEY_RE compile failed: {e}"); std::process::exit(1) })
});

static GENERIC_API_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?i)"(?:api[_\-]?key|apikey)"\s*:\s*"([A-Za-z0-9\-_]{20,})""#)
        .unwrap_or_else(|e| { eprintln!("FATAL: GENERIC_API_KEY_RE compile failed: {e}"); std::process::exit(1) })
});

static PRIVATE_KEY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
        .unwrap_or_else(|e| { eprintln!("FATAL: PRIVATE_KEY_RE compile failed: {e}"); std::process::exit(1) })
});

static JWT_TOKEN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
        .unwrap_or_else(|e| { eprintln!("FATAL: JWT_TOKEN_RE compile failed: {e}"); std::process::exit(1) })
});

static PASSWORD_IN_JSON_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?i)"(?:password|passwd|secret)"\s*:\s*"([^"]{6,})""#)
        .unwrap_or_else(|e| { eprintln!("FATAL: PASSWORD_IN_JSON_RE compile failed: {e}"); std::process::exit(1) })
});

// ── Pattern catalogue ──────────────────────────────────────────────────────────

/// A compiled secret/credential detection pattern.
pub struct SecretPattern {
    /// Human-readable pattern name.
    pub name: &'static str,
    /// Compiled lazy regex.
    pub regex: &'static std::sync::LazyLock<Regex>,
    /// PII entity type (secrets reuse `PiiEntityType`).
    pub entity_type: PiiEntityType,
    /// Default severity (secrets are always Critical).
    pub severity: Severity,
    /// Detection confidence in [0.0, 1.0].
    pub confidence: f64,
}

static ALL_SECRETS: std::sync::LazyLock<Vec<SecretPattern>> = std::sync::LazyLock::new(|| {
    vec![
        SecretPattern {
            name: "AWS_ACCESS_KEY",
            regex: &AWS_ACCESS_KEY_RE,
            entity_type: PiiEntityType::AwsAccessKey,
            severity: Severity::Critical,
            confidence: 0.99,
        },
        SecretPattern {
            name: "AWS_SECRET_KEY",
            regex: &AWS_SECRET_KEY_RE,
            entity_type: PiiEntityType::AwsSecretKey,
            severity: Severity::Critical,
            confidence: 0.95,
        },
        SecretPattern {
            name: "GITHUB_TOKEN",
            regex: &GITHUB_TOKEN_RE,
            entity_type: PiiEntityType::GithubToken,
            severity: Severity::Critical,
            confidence: 0.99,
        },
        SecretPattern {
            name: "OPENAI_KEY",
            regex: &OPENAI_KEY_RE,
            entity_type: PiiEntityType::OpenaiKey,
            severity: Severity::Critical,
            confidence: 0.99,
        },
        SecretPattern {
            name: "ANTHROPIC_KEY",
            regex: &ANTHROPIC_KEY_RE,
            entity_type: PiiEntityType::AnthropicKey,
            severity: Severity::Critical,
            confidence: 0.99,
        },
        SecretPattern {
            name: "GENERIC_API_KEY",
            regex: &GENERIC_API_KEY_RE,
            entity_type: PiiEntityType::GenericApiKey,
            severity: Severity::High,
            confidence: 0.85,
        },
        SecretPattern {
            name: "PRIVATE_KEY",
            regex: &PRIVATE_KEY_RE,
            entity_type: PiiEntityType::PrivateKey,
            severity: Severity::Critical,
            confidence: 1.0,
        },
        SecretPattern {
            name: "JWT_TOKEN",
            regex: &JWT_TOKEN_RE,
            entity_type: PiiEntityType::JwtToken,
            severity: Severity::High,
            confidence: 0.95,
        },
        SecretPattern {
            name: "PASSWORD_IN_JSON",
            regex: &PASSWORD_IN_JSON_RE,
            entity_type: PiiEntityType::PasswordInJson,
            severity: Severity::Critical,
            confidence: 0.90,
        },
    ]
});

/// Return all secret patterns. Compiled lazily on first call.
pub fn all_secret_patterns() -> &'static [SecretPattern] {
    &ALL_SECRETS
}
