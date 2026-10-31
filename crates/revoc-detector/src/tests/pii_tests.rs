use revoc_core::{FindingType, PiiEntityType};

use crate::{
    patterns::pii::{iban_checksum_valid, luhn_check},
    regex_detector::{make_test_input, RegexDetector},
};

fn detect(text: &str) -> Vec<revoc_core::Finding> {
    RegexDetector.detect_sync(&make_test_input(text))
}

fn has_pii(findings: &[revoc_core::Finding], entity: PiiEntityType) -> bool {
    findings
        .iter()
        .any(|f| f.pii_entity == Some(entity.clone()))
}

// ── SSN ────────────────────────────────────────────────────────────────────────

#[test]
fn test_ssn_matched() {
    let findings = detect("SSN: 123-45-6789");
    assert!(
        has_pii(&findings, PiiEntityType::UsSsn),
        "SSN must be detected"
    );
}

#[test]
fn test_ssn_no_false_positive_000() {
    // 000 area is invalid
    let findings = detect("000-45-6789");
    assert!(
        !has_pii(&findings, PiiEntityType::UsSsn),
        "000-xx-xxxx must not match"
    );
}

#[test]
fn test_ssn_no_false_positive_666() {
    // 666 area is invalid
    let findings = detect("666-12-3456");
    assert!(
        !has_pii(&findings, PiiEntityType::UsSsn),
        "666-xx-xxxx must not match"
    );
}

#[test]
fn test_ssn_no_false_positive_9xx() {
    // 9xx area is invalid
    let findings = detect("912-34-5678");
    assert!(
        !has_pii(&findings, PiiEntityType::UsSsn),
        "9xx-xx-xxxx must not match"
    );
}

// ── Email ──────────────────────────────────────────────────────────────────────

#[test]
fn test_email_matched() {
    let findings = detect("Contact us at admin@example.com for support");
    assert!(has_pii(&findings, PiiEntityType::EmailAddress));
}

#[test]
fn test_email_no_match_incomplete() {
    let findings = detect("not-an-email@");
    assert!(!has_pii(&findings, PiiEntityType::EmailAddress));
}

// ── Credit Card ────────────────────────────────────────────────────────────────

#[test]
fn test_credit_card_luhn_valid_matched() {
    // Valid Luhn: 4532015112830366
    let findings = detect("card: 4532015112830366");
    assert!(
        has_pii(&findings, PiiEntityType::CreditCard),
        "Valid Luhn card must be detected"
    );
}

#[test]
fn test_credit_card_luhn_invalid_not_matched() {
    // Invalid Luhn: 4532015112830367
    let findings = detect("card: 4532015112830367");
    assert!(
        !has_pii(&findings, PiiEntityType::CreditCard),
        "Invalid Luhn must not match"
    );
}

#[test]
fn test_luhn_check_known_valid() {
    assert!(luhn_check("4532015112830366"));
    assert!(luhn_check("4111111111111111"));
    assert!(luhn_check("378282246310005")); // Amex
}

#[test]
fn test_luhn_check_known_invalid() {
    assert!(!luhn_check("4532015112830367"));
    assert!(!luhn_check("1234567890123456"));
}

// ── IBAN ───────────────────────────────────────────────────────────────────────

#[test]
fn test_iban_valid_matched() {
    // GB82 WEST 1234 5698 7654 32 — valid mod-97
    let findings = detect("IBAN: GB82WEST12345698765432");
    assert!(
        has_pii(&findings, PiiEntityType::IbanCode),
        "Valid IBAN must be detected"
    );
}

#[test]
fn test_iban_invalid_checksum_not_matched() {
    // GB82 with wrong check digits
    let findings = detect("IBAN: GB99WEST12345698765432");
    assert!(
        !has_pii(&findings, PiiEntityType::IbanCode),
        "Invalid IBAN checksum must not match"
    );
}

#[test]
fn test_iban_checksum_valid_known() {
    assert!(iban_checksum_valid("GB82WEST12345698765432"));
    assert!(iban_checksum_valid("DE89370400440532013000"));
}

#[test]
fn test_iban_checksum_invalid_known() {
    assert!(!iban_checksum_valid("GB99WEST12345698765432"));
    assert!(!iban_checksum_valid("XX00000000000000000000"));
}

// ── IP Addresses ───────────────────────────────────────────────────────────────

#[test]
fn test_ip_v4_matched() {
    let findings = detect("server IP: 192.168.1.100");
    assert!(has_pii(&findings, PiiEntityType::IpAddressV4));
}

#[test]
fn test_ip_v4_no_false_positive_overflow() {
    let findings = detect("999.999.999.999");
    assert!(!has_pii(&findings, PiiEntityType::IpAddressV4));
}

#[test]
fn test_ip_v6_matched() {
    // Full-form IPv6
    let findings = detect("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert!(has_pii(&findings, PiiEntityType::IpAddressV6));
}

// ── Secrets ────────────────────────────────────────────────────────────────────

#[test]
fn test_aws_access_key_matched() {
    let findings = detect("key = AKIAIOSFODNN7EXAMPLE");
    assert!(
        findings
            .iter()
            .any(|f| f.finding_type == FindingType::SecretExposure
                && f.pii_entity == Some(PiiEntityType::AwsAccessKey)),
        "AWS access key must be detected"
    );
}

#[test]
fn test_github_token_matched() {
    let findings = detect("auth: ghp_1234567890123456789012345678901234567890");
    assert!(
        findings
            .iter()
            .any(|f| f.pii_entity == Some(PiiEntityType::GithubToken)),
        "GitHub token must be detected"
    );
}

#[test]
fn test_private_key_matched() {
    let findings = detect("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...");
    assert!(
        findings
            .iter()
            .any(|f| f.pii_entity == Some(PiiEntityType::PrivateKey)),
        "PEM private key must be detected"
    );
}

#[test]
fn test_jwt_matched() {
    let findings = detect("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456ghi");
    assert!(
        findings
            .iter()
            .any(|f| f.pii_entity == Some(PiiEntityType::JwtToken)),
        "JWT must be detected"
    );
}
