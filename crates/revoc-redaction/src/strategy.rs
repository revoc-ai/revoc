//! Redaction strategy selection and application.
//!
//! Strategies map to SPEC.md §14 actions:
//! - **Remove** — replaces span with empty string (PII that must not appear at all).
//! - **Hash** — replaces span with a short SHA-256 prefix for deduplication.
//! - **Mask** — replaces span with `[REDACTED-<entity>]` (less sensitive PII).

use sha2::Digest as _;

use revoc_core::{Finding, FindingType, PiiEntityType};

// ── RedactionStrategy ─────────────────────────────────────────────────────────

/// The action taken on a matched span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionStrategy {
    /// Replace the span with `[REDACTED-<entity>]`.
    Mask,
    /// Replace the span with `[hash:<first-4-bytes-hex>]` of the original value.
    Hash,
    /// Replace the span with an empty string.
    Remove,
}

impl RedactionStrategy {
    /// Apply the strategy to `original`, returning the replacement string.
    ///
    /// `original` is used only by [`RedactionStrategy::Hash`] to compute the
    /// digest. **It must never be logged.**
    pub fn apply(&self, original: &str, entity: &PiiEntityType) -> String {
        match self {
            Self::Mask => format!("[REDACTED-{entity}]"),
            Self::Hash => {
                let digest = sha2::Sha256::digest(original.as_bytes());
                format!("[hash:{}]", hex::encode(&digest[..4]))
            }
            Self::Remove => String::new(),
        }
    }
}

// ── strategy_for ──────────────────────────────────────────────────────────────

/// Select the appropriate [`RedactionStrategy`] for a given finding.
///
/// Rules (checked in order):
/// 1. Secret key/token types → [`RedactionStrategy::Hash`] (preserves dedup
///    signal without exposing the credential).
/// 2. High-sensitivity PII and fallback secret → [`RedactionStrategy::Remove`].
/// 3. Tool manifest risk → caller should skip (treated as audit-only).
/// 4. Everything else → [`RedactionStrategy::Mask`].
pub fn strategy_for(finding: &Finding) -> RedactionStrategy {
    // Hash: specific secret types where correlation may be useful
    if matches!(
        finding.pii_entity,
        Some(
            PiiEntityType::AwsAccessKey
                | PiiEntityType::AwsSecretKey
                | PiiEntityType::GithubToken
                | PiiEntityType::OpenaiKey
                | PiiEntityType::AnthropicKey
                | PiiEntityType::GenericApiKey
                | PiiEntityType::JwtToken
        )
    ) {
        return RedactionStrategy::Hash;
    }

    // Remove: high-sensitivity PII that must not appear in any form
    if matches!(
        finding.pii_entity,
        Some(
            PiiEntityType::UsSsn
                | PiiEntityType::CreditCard
                | PiiEntityType::IbanCode
                | PiiEntityType::RoutingNumber
                | PiiEntityType::BankAccount
                | PiiEntityType::UsPassport
                | PiiEntityType::MedicalRecordNumber
                | PiiEntityType::PrivateKey
                | PiiEntityType::PasswordInJson
        )
    ) {
        return RedactionStrategy::Remove;
    }

    // Remove: any secret exposure where pii_entity didn't match hash list above
    if finding.finding_type == FindingType::SecretExposure {
        return RedactionStrategy::Remove;
    }

    // ToolManifestRisk: caller must skip — return Mask as a safe default
    // (the redactor filters these out before calling strategy_for)
    if finding.finding_type == FindingType::ToolManifestRisk {
        return RedactionStrategy::Mask;
    }

    // Default: mask with entity label
    RedactionStrategy::Mask
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use revoc_core::{DetectionTier, Finding, FindingType, PiiEntityType, Severity};

    fn pii_finding(entity: PiiEntityType) -> Finding {
        Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
            .with_pii(entity)
    }

    fn secret_finding(entity: PiiEntityType) -> Finding {
        Finding::new(FindingType::SecretExposure, Severity::Critical, DetectionTier::Regex)
            .with_pii(entity)
    }

    #[test]
    fn test_strategy_ssn_is_remove() {
        let f = pii_finding(PiiEntityType::UsSsn);
        assert_eq!(strategy_for(&f), RedactionStrategy::Remove);
    }

    #[test]
    fn test_strategy_email_is_mask() {
        let f = pii_finding(PiiEntityType::EmailAddress);
        assert_eq!(strategy_for(&f), RedactionStrategy::Mask);
    }

    #[test]
    fn test_strategy_aws_key_is_hash() {
        let f = secret_finding(PiiEntityType::AwsAccessKey);
        assert_eq!(strategy_for(&f), RedactionStrategy::Hash);
    }

    #[test]
    fn test_strategy_private_key_is_remove() {
        let f = secret_finding(PiiEntityType::PrivateKey);
        assert_eq!(strategy_for(&f), RedactionStrategy::Remove);
    }

    #[test]
    fn test_strategy_generic_secret_is_remove() {
        // SecretExposure with no specific entity → Remove
        let f = Finding::new(FindingType::SecretExposure, Severity::Critical, DetectionTier::Regex);
        assert_eq!(strategy_for(&f), RedactionStrategy::Remove);
    }

    #[test]
    fn test_mask_apply_contains_entity_name() {
        let result = RedactionStrategy::Mask.apply("test@example.com", &PiiEntityType::EmailAddress);
        assert!(result.contains("EMAIL_ADDRESS"), "Mask must include entity type");
        assert!(!result.contains("test@"), "Mask must not include original value");
    }

    #[test]
    fn test_hash_apply_is_deterministic() {
        let a = RedactionStrategy::Hash.apply("sk-secret", &PiiEntityType::OpenaiKey);
        let b = RedactionStrategy::Hash.apply("sk-secret", &PiiEntityType::OpenaiKey);
        assert_eq!(a, b, "Hash must be deterministic");
        assert!(a.starts_with("[hash:"), "Hash output must start with [hash:");
    }

    #[test]
    fn test_remove_apply_is_empty() {
        let result = RedactionStrategy::Remove.apply("123-45-6789", &PiiEntityType::UsSsn);
        assert!(result.is_empty(), "Remove strategy must produce empty string");
    }
}
