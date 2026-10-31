use base64::Engine as _;
use revoc_core::PiiEntityType;

use crate::{
    encoding::{prepare_scan_targets, try_decode_base64, try_decode_url},
    regex_detector::{make_test_input, RegexDetector},
};

fn detect(text: &str) -> Vec<revoc_core::Finding> {
    RegexDetector.detect_sync(&make_test_input(text))
}

// ── Base64 detection ───────────────────────────────────────────────────────────

#[test]
fn test_base64_ssn_detected_was_encoded_true() {
    // Encode an SSN in base64; the detector should decode and find it
    let ssn = "123-45-6789";
    let encoded = base64::engine::general_purpose::STANDARD.encode(ssn);
    let findings = detect(&encoded);
    let f = findings
        .iter()
        .find(|f| f.pii_entity == Some(PiiEntityType::UsSsn));
    assert!(f.is_some(), "SSN in base64 must be detected");
    assert!(
        f.unwrap().was_encoded,
        "Finding from base64 content must have was_encoded=true"
    );
}

#[test]
fn test_url_encoded_drop_table_detected() {
    // URL-encode a DDL injection attempt
    let encoded = "DROP%20TABLE%20users";
    let decoded = try_decode_url(encoded);
    assert!(decoded.is_some(), "URL decode must succeed");
    assert_eq!(decoded.unwrap(), "DROP TABLE users");

    let targets = prepare_scan_targets(encoded);
    assert_eq!(targets.len(), 2, "Original + decoded targets expected");
    assert!(!targets[0].1, "Original target must have was_encoded=false");
    assert!(targets[1].1, "Decoded target must have was_encoded=true");
}

#[test]
fn test_oversized_base64_not_decoded() {
    // Generate >64 KB of base64 data; try_decode_base64 must return None
    let large = vec![b'A'; 65_537];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&large);
    assert!(
        try_decode_base64(&encoded).is_none(),
        "Base64 decoding >64 KB must return None"
    );
}

#[test]
fn test_clean_text_only_original_target() {
    // Plain text with no base64 or % encoding → exactly one target
    let text = "Hello, world! This is plain text.";
    let targets = prepare_scan_targets(text);
    assert_eq!(
        targets.len(),
        1,
        "Plain text must produce exactly one scan target"
    );
    assert_eq!(targets[0].0, text);
    assert!(!targets[0].1, "Plain target must have was_encoded=false");
}

#[test]
fn test_try_decode_base64_valid() {
    let encoded = base64::engine::general_purpose::STANDARD.encode("hello world");
    let decoded = try_decode_base64(&encoded);
    assert_eq!(decoded, Some("hello world".into()));
}

#[test]
fn test_try_decode_base64_invalid() {
    // Not base64
    assert!(try_decode_base64("not base64 !!@#$").is_none());
}

#[test]
fn test_try_decode_url_with_percent() {
    let decoded = try_decode_url("hello%20world");
    assert_eq!(decoded, Some("hello world".into()));
}

#[test]
fn test_try_decode_url_no_percent() {
    // No percent sign → None
    assert!(try_decode_url("hello world").is_none());
}

#[test]
fn test_try_decode_url_unchanged_after_decode() {
    // Already-decoded URL that happens to not change → None
    // (percent chars that don't form valid escapes pass through unchanged)
    let result = try_decode_url("hello");
    assert!(result.is_none(), "String without % must return None");
}
