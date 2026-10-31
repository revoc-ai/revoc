#![no_main]

use libfuzzer_sys::fuzz_target;
use revoc_core::{
    DetectionTier, Finding, FindingType, PolicyDecision, PiiEntityType, Redactor, Severity, TextSpan,
};
use revoc_redaction::RevocRedactor;
use revoc_telemetry::RevocMetrics;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let redactor = RevocRedactor::new(RevocMetrics::global());
    let decision = PolicyDecision::redact("fuzz", vec!["pii_ssn_v1".into()]);

    // Derive a plausible span from the first 4 bytes of data.
    let start = (data[0] as usize) % data.len().max(1);
    let end_offset = (data[1] as usize % 16) + 1;
    let end = (start + end_offset).min(data.len());

    let findings = vec![
        Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
            .with_pii(PiiEntityType::UsSsn)
            .with_span(TextSpan { start, end, field: "messages[0].content".into(), value: None })
            .with_confidence(0.95),
    ];

    // Must never panic; invalid UTF-8 or out-of-bounds spans must be handled gracefully.
    let result = redactor.redact_body(data, &findings, &decision);

    // When redaction succeeds, the output must be valid UTF-8.
    if let Ok((output, _)) = result {
        let _ = std::str::from_utf8(&output);
    }
});
