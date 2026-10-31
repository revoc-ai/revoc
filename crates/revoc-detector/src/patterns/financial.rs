//! Financial data detection patterns (SPEC.md §8.4).

use fancy_regex::Regex;

use revoc_core::{PiiEntityType, Severity};

use super::pii::{aba_routing_check, PiiPattern};

// ── Compiled patterns ──────────────────────────────────────────────────────────

static SWIFT_BIC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // 6 alpha + 2 alphanumeric + optional 3 alphanumeric (location code)
    Regex::new(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap_or_else(|e| {
        eprintln!("FATAL: SWIFT_BIC_RE compile failed: {e}");
        std::process::exit(1)
    })
});

static ROUTING_NUMBER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // 9-digit ABA routing number — validated by aba_routing_check()
    Regex::new(r"\b\d{9}\b").unwrap_or_else(|e| {
        eprintln!("FATAL: ROUTING_NUMBER_RE compile failed: {e}");
        std::process::exit(1)
    })
});

static BANK_ACCOUNT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Account number near banking context keywords
    Regex::new(r"(?i)(?:account|acct)[\s_#]?[:#]?\s*\d{8,17}").unwrap_or_else(|e| {
        eprintln!("FATAL: BANK_ACCOUNT_RE compile failed: {e}");
        std::process::exit(1)
    })
});

// ── Pattern catalogue ──────────────────────────────────────────────────────────

static ALL_FINANCIAL: std::sync::LazyLock<Vec<PiiPattern>> = std::sync::LazyLock::new(|| {
    vec![
        PiiPattern {
            name: "SWIFT_BIC",
            regex: &SWIFT_BIC_RE,
            entity_type: PiiEntityType::SwiftBic,
            severity: Severity::High,
            confidence: 0.8,
            validator: None,
        },
        PiiPattern {
            name: "ROUTING_NUMBER",
            regex: &ROUTING_NUMBER_RE,
            entity_type: PiiEntityType::RoutingNumber,
            severity: Severity::High,
            confidence: 0.9,
            validator: Some(aba_routing_check),
        },
        PiiPattern {
            name: "BANK_ACCOUNT",
            regex: &BANK_ACCOUNT_RE,
            entity_type: PiiEntityType::BankAccount,
            severity: Severity::High,
            confidence: 0.8,
            validator: None,
        },
    ]
});

/// Return all financial patterns. Compiled lazily on first call.
pub fn all_financial_patterns() -> &'static [PiiPattern] {
    &ALL_FINANCIAL
}
