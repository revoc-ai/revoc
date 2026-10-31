//! Security threat detection patterns (SPEC.md §8.3).
//!
//! All security patterns fire at Tier 3 (`PolicyRuleTier::Security`) and
//! cannot be overridden by operator custom allow rules (SPEC.md D12).

use fancy_regex::Regex;

use revoc_core::{FindingType, Severity};

// ── Compiled patterns ──────────────────────────────────────────────────────────

static DDL_MUTATION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)\b(DROP|TRUNCATE|ALTER)\s+TABLE\b").unwrap_or_else(|e| {
        eprintln!("FATAL: DDL_MUTATION_RE compile failed: {e}");
        std::process::exit(1)
    })
});

/// Matches `DELETE FROM` without checking for `WHERE` — the `regex_detector` performs
/// the `WHERE` check post-match using `skip_if_after_contains`.
static DELETE_FROM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)\bDELETE\s+FROM\b").unwrap_or_else(|e| {
        eprintln!("FATAL: DELETE_FROM_RE compile failed: {e}");
        std::process::exit(1)
    })
});

static SSRF_INTERNAL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Single-line string — no backslash continuations (they are literal in raw strings).
    Regex::new(r"(?i)(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|[fF][dD][0-9a-fA-F]{2}:)")
        .unwrap_or_else(|e| { eprintln!("FATAL: SSRF_INTERNAL_RE compile failed: {e}"); std::process::exit(1) })
});

static PATH_TRAVERSAL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?:\.\./|\.\.\\)+").unwrap_or_else(|e| {
        eprintln!("FATAL: PATH_TRAVERSAL_RE compile failed: {e}");
        std::process::exit(1)
    })
});

static PROMPT_INJECTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Single-line string. \bjailbreak\b is a standalone alternative (fix 1).
    Regex::new(r"(?i)(?:\bjailbreak\b|ignore\s+(?:previous|prior|above|all\s+previous)\s+instructions?|disregard\s+(?:all\s+)?(?:previous\s+)?instructions?|do\s+anything\s+now|DAN\s+mode|you\s+are\s+now\s+(?:free|unlocked|unrestricted)|act\s+as\s+(?:if\s+you\s+have\s+no\s+restrictions?|DAN))")
        .unwrap_or_else(|e| { eprintln!("FATAL: PROMPT_INJECTION_RE compile failed: {e}"); std::process::exit(1) })
});

static SYS_EXTRACT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Single-line string. Covers "print your initial prompt", "what are your instructions", etc.
    Regex::new(r"(?i)(?:reveal\s+(?:your\s+)?system\s+prompt|what\s+are\s+your\s+(?:system\s+)?instructions?|print\s+(?:your\s+)?(?:initial\s+)?(?:system\s+)?prompt|show\s+(?:me\s+)?your\s+(?:system\s+)?instructions?|repeat\s+(?:your\s+)?system\s+prompt)")
        .unwrap_or_else(|e| { eprintln!("FATAL: SYS_EXTRACT_RE compile failed: {e}"); std::process::exit(1) })
});

static MASS_DELETE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // DELETE FROM <table> without WHERE, terminated by ; or end-of-string
    Regex::new(r"(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)").unwrap_or_else(|e| {
        eprintln!("FATAL: MASS_DELETE_RE compile failed: {e}");
        std::process::exit(1)
    })
});

// ── Pattern catalogue ──────────────────────────────────────────────────────────

/// A compiled security threat detection pattern.
pub struct SecurityPattern {
    /// Human-readable pattern name (matches rule ID prefix).
    pub name: &'static str,
    /// Compiled lazy regex.
    pub regex: &'static std::sync::LazyLock<Regex>,
    /// Finding type for findings produced by this pattern.
    pub finding_type: FindingType,
    /// Severity (security patterns default to `High` or `Critical`).
    pub severity: Severity,
    /// Detection confidence.
    pub confidence: f64,
    /// If `Some(s)`, a match is suppressed when the text immediately after the
    /// match (up to 512 bytes) contains `s` (case-insensitive).
    /// Used to implement `DELETE_NO_WHERE`: skip if `WHERE` appears after match.
    pub skip_if_after_contains: Option<&'static str>,
}

static ALL_SECURITY: std::sync::LazyLock<Vec<SecurityPattern>> = std::sync::LazyLock::new(|| {
    vec![
        SecurityPattern {
            name: "DDL_MUTATION",
            regex: &DDL_MUTATION_RE,
            finding_type: FindingType::DdlMutation,
            severity: Severity::Critical,
            confidence: 0.99,
            skip_if_after_contains: None,
        },
        SecurityPattern {
            name: "DELETE_NO_WHERE",
            regex: &DELETE_FROM_RE,
            finding_type: FindingType::DdlMutation,
            severity: Severity::High,
            confidence: 0.9,
            // Suppress if WHERE appears after the match (within 512 chars)
            skip_if_after_contains: Some("WHERE"),
        },
        SecurityPattern {
            name: "SSRF_INTERNAL",
            regex: &SSRF_INTERNAL_RE,
            finding_type: FindingType::SsrfAttempt,
            severity: Severity::Critical,
            confidence: 0.95,
            skip_if_after_contains: None,
        },
        SecurityPattern {
            name: "PATH_TRAVERSAL",
            regex: &PATH_TRAVERSAL_RE,
            finding_type: FindingType::PathTraversal,
            severity: Severity::High,
            confidence: 0.95,
            skip_if_after_contains: None,
        },
        SecurityPattern {
            name: "PROMPT_INJECTION",
            regex: &PROMPT_INJECTION_RE,
            finding_type: FindingType::PromptInjection,
            severity: Severity::Critical,
            confidence: 0.9,
            skip_if_after_contains: None,
        },
        SecurityPattern {
            name: "SYSTEM_PROMPT_EXTRACTION",
            regex: &SYS_EXTRACT_RE,
            finding_type: FindingType::SystemPromptExtraction,
            severity: Severity::High,
            confidence: 0.85,
            skip_if_after_contains: None,
        },
        SecurityPattern {
            name: "MASS_DELETE",
            regex: &MASS_DELETE_RE,
            finding_type: FindingType::DdlMutation,
            severity: Severity::Critical,
            confidence: 0.95,
            skip_if_after_contains: None,
        },
    ]
});

/// Return all security threat patterns. Compiled lazily on first call.
pub fn all_security_patterns() -> &'static [SecurityPattern] {
    &ALL_SECURITY
}
