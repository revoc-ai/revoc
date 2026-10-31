//! PII detection patterns (SPEC.md §8.1).

use fancy_regex::Regex;

use revoc_core::{PiiEntityType, Severity};

// ── Compiled patterns ──────────────────────────────────────────────────────────

static SSN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: SSN_RE compile failed: {e}"); std::process::exit(1) })
});

static EMAIL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: EMAIL_RE compile failed: {e}"); std::process::exit(1) })
});

static PHONE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Anchored with `(?<!\d)` / `(?!\d)` so this does not match a 10-digit
    // substring embedded inside a longer run of digits (e.g. a 16-digit
    // credit card number, an 11-digit bank account, an IBAN, etc.). Without
    // these lookarounds, "4242424242424242" produces a spurious
    // PHONE_NUMBER finding in addition to the correct CREDIT_CARD finding,
    // and conflict resolution / deduplication can then surface
    // `pii_phone_v1` instead of `pii_credit_card_v1` for credit-card-only
    // content.
    //
    // Additionally, a bare unformatted run of 10-11 digits with no
    // separators, parens, or leading "+" (e.g. a generic bank account
    // number such as "12345678901") is NOT a recognizable phone-number
    // format and is therefore excluded: the pattern now requires either an
    // explicit "+" country-code prefix, OR at least one separator
    // (space/dot/dash/parens) somewhere in the match.
    Regex::new(
        r"(?<!\d)(?:\+1[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}|(?:1[\s.\-])?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]?\d{4}|\(\d{3}\)\d{3}[\s.\-]?\d{4})(?!\d)"
    )
        .unwrap_or_else(|e| { eprintln!("FATAL: PHONE_RE compile failed: {e}"); std::process::exit(1) })
});

static CREDIT_CARD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Visa (13/16), MasterCard (16), Amex (15), Discover (16)
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: CREDIT_CARD_RE compile failed: {e}"); std::process::exit(1) })
});

static IBAN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: IBAN_RE compile failed: {e}"); std::process::exit(1) })
});

static IPV4_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b",
    )
    .unwrap_or_else(|e| { eprintln!("FATAL: IPV4_RE compile failed: {e}"); std::process::exit(1) })
});

static IPV6_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Covers full, compressed, and loopback forms
    Regex::new(
        r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?::[0-9a-f]{1,4}){1,7}|::"
    )
    .unwrap_or_else(|e| { eprintln!("FATAL: IPV6_RE compile failed: {e}"); std::process::exit(1) })
});

static US_PASSPORT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b[A-Z]\d{8}\b").unwrap_or_else(|e| { eprintln!("FATAL: US_PASSPORT_RE compile failed: {e}"); std::process::exit(1) })
});

static US_DL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // Generic driver's license near keyword context
    Regex::new(r"(?i)\b(?:DL|D\.L\.|driver[\s_]?licen[sc]e)\s*[:#]?\s*([A-Z0-9]{5,20})\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: US_DL_RE compile failed: {e}"); std::process::exit(1) })
});

static DOB_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)(?:dob|date[\s_]of[\s_]birth|born|birthday)\s*[:#]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})")
        .unwrap_or_else(|e| { eprintln!("FATAL: DOB_RE compile failed: {e}"); std::process::exit(1) })
});

static MRN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:mrn|medical[\s_]record)\s*[:#]?\s*([A-Z0-9\-]{5,20})\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: MRN_RE compile failed: {e}"); std::process::exit(1) })
});

static NPI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:npi|national[\s_]provider)\s*[:#]?\s*(\d{10})\b")
        .unwrap_or_else(|e| { eprintln!("FATAL: NPI_RE compile failed: {e}"); std::process::exit(1) })
});

static DEA_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // DEA format: 2 alpha chars + 7 digits
    Regex::new(r"\b[A-Z]{2}\d{7}\b").unwrap_or_else(|e| { eprintln!("FATAL: DEA_RE compile failed: {e}"); std::process::exit(1) })
});

// ── Validators ─────────────────────────────────────────────────────────────────

/// Validate a credit/debit card number using the Luhn algorithm.
pub fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Validate an IBAN using the full mod-97 checksum algorithm.
pub fn iban_checksum_valid(s: &str) -> bool {
    let s = s.replace([' ', '-'], "");
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    // Country code must be 2 uppercase letters
    if !s[..2].chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Move first 4 chars to end, convert letters to digits
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let numeric: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let v = u32::from(c.to_ascii_uppercase()) - u32::from('A') + 10;
                v.to_string()
            } else {
                c.to_string()
            }
        })
        .collect();

    // Compute mod 97 in chunks to handle large integers
    let mut remainder: u64 = 0;
    for ch in numeric.chars() {
        if let Some(d) = ch.to_digit(10) {
            remainder = (remainder * 10 + u64::from(d)) % 97;
        }
    }
    remainder == 1
}

/// ABA routing number checksum weights (fix 8: moved to top of fn scope).
const ABA_WEIGHTS: [u32; 9] = [3, 7, 1, 3, 7, 1, 3, 7, 1];

/// Validate a 9-digit ABA routing number using the checksum algorithm.
pub fn aba_routing_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 9 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .zip(ABA_WEIGHTS.iter())
        .map(|(&d, &w)| d * w)
        .sum();

    sum.is_multiple_of(10)
}

// ── Pattern catalogue ──────────────────────────────────────────────────────────

/// A compiled PII detection pattern with metadata.
pub struct PiiPattern {
    /// Human-readable pattern name.
    pub name: &'static str,
    /// Compiled lazy regex.
    pub regex: &'static std::sync::LazyLock<Regex>,
    /// PII entity type for `Finding.pii_entity`.
    pub entity_type: PiiEntityType,
    /// Default severity.
    pub severity: Severity,
    /// Detection confidence in [0.0, 1.0].
    pub confidence: f64,
    /// Optional post-match validator (e.g. Luhn check).
    /// If `Some(f)`, the matched text is passed to `f`; matches returning
    /// `false` are discarded.
    pub validator: Option<fn(&str) -> bool>,
}

static ALL_PII: std::sync::LazyLock<Vec<PiiPattern>> = std::sync::LazyLock::new(|| {
    vec![
        PiiPattern {
            name: "US_SSN",
            regex: &SSN_RE,
            entity_type: PiiEntityType::UsSsn,
            severity: Severity::High,
            confidence: 0.95,
            validator: None,
        },
        PiiPattern {
            name: "EMAIL_ADDRESS",
            regex: &EMAIL_RE,
            entity_type: PiiEntityType::EmailAddress,
            severity: Severity::Medium,
            confidence: 0.9,
            validator: None,
        },
        PiiPattern {
            name: "PHONE_NUMBER",
            regex: &PHONE_RE,
            entity_type: PiiEntityType::PhoneNumber,
            severity: Severity::Low,
            confidence: 0.75,
            validator: None,
        },
        PiiPattern {
            name: "CREDIT_CARD",
            regex: &CREDIT_CARD_RE,
            entity_type: PiiEntityType::CreditCard,
            severity: Severity::High,
            confidence: 0.99,
            validator: Some(luhn_check),
        },
        PiiPattern {
            name: "IBAN_CODE",
            regex: &IBAN_RE,
            entity_type: PiiEntityType::IbanCode,
            severity: Severity::High,
            confidence: 0.99,
            validator: Some(iban_checksum_valid),
        },
        PiiPattern {
            name: "IP_ADDRESS_V4",
            regex: &IPV4_RE,
            entity_type: PiiEntityType::IpAddressV4,
            severity: Severity::Low,
            confidence: 0.95,
            validator: None,
        },
        PiiPattern {
            name: "IP_ADDRESS_V6",
            regex: &IPV6_RE,
            entity_type: PiiEntityType::IpAddressV6,
            severity: Severity::Low,
            confidence: 0.9,
            validator: None,
        },
        PiiPattern {
            name: "US_PASSPORT",
            regex: &US_PASSPORT_RE,
            entity_type: PiiEntityType::UsPassport,
            severity: Severity::High,
            confidence: 0.8,
            validator: None,
        },
        PiiPattern {
            name: "US_DRIVER_LICENSE",
            regex: &US_DL_RE,
            entity_type: PiiEntityType::UsDriverLicense,
            severity: Severity::Medium,
            confidence: 0.8,
            validator: None,
        },
        PiiPattern {
            name: "DATE_OF_BIRTH",
            regex: &DOB_RE,
            entity_type: PiiEntityType::DateOfBirth,
            severity: Severity::Medium,
            confidence: 0.85,
            validator: None,
        },
        PiiPattern {
            name: "MEDICAL_RECORD_NUMBER",
            regex: &MRN_RE,
            entity_type: PiiEntityType::MedicalRecordNumber,
            severity: Severity::High,
            confidence: 0.85,
            validator: None,
        },
        PiiPattern {
            name: "NPI_NUMBER",
            regex: &NPI_RE,
            entity_type: PiiEntityType::NpiNumber,
            severity: Severity::Medium,
            confidence: 0.85,
            validator: None,
        },
        PiiPattern {
            name: "DEA_NUMBER",
            regex: &DEA_RE,
            entity_type: PiiEntityType::DeaNumber,
            severity: Severity::High,
            confidence: 0.75,
            validator: None,
        },
    ]
});

/// Return all PII patterns. Compiled lazily on first call.
pub fn all_pii_patterns() -> &'static [PiiPattern] {
    &ALL_PII
}
