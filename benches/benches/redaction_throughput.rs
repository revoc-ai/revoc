//! Redaction throughput benchmarks (SPEC.md §19 targets).

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use revoc_core::{
    DetectionTier, Finding, FindingType, PiiEntityType, PolicyDecision, Redactor, Severity,
    TextSpan,
};
use revoc_redaction::RevocRedactor;
use revoc_telemetry::RevocMetrics;
use serde_json::json;

// ── helpers ───────────────────────────────────────────────────────────────────

fn redactor() -> RevocRedactor {
    RevocRedactor::new(RevocMetrics::global())
}

fn redact_decision() -> PolicyDecision {
    PolicyDecision::redact("PII found", vec!["pii_ssn_v1".into()])
}

fn pii_finding_at(entity: PiiEntityType, field: &str, start: usize, end: usize) -> Finding {
    Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_pii(entity)
        .with_span(TextSpan {
            start,
            end,
            field: field.into(),
            value: None,
        })
        .with_confidence(0.99)
}

/// 4 KB LLM body with exactly 3 PII entities at known character positions.
fn body_3_findings_4kb() -> (Vec<u8>, Vec<Finding>) {
    let prefix = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"SSN: "#;
    let ssn = "123-45-6789";
    let middle = ", email: ";
    let email = "alice@example.com";
    let middle2 = ", cc: ";
    let cc = "4532015112830366";
    let suffix_len = 4096_usize.saturating_sub(
        prefix.len() + ssn.len() + middle.len() + email.len() + middle2.len() + cc.len() + 30,
    );
    let filler: String = "x".repeat(suffix_len);
    let body = format!(r#"{prefix}{ssn}{middle}{email}{middle2}{cc}{filler}"}}]}}"#);
    let body_bytes = body.into_bytes();

    let ssn_start = prefix.len();
    let email_start = ssn_start + ssn.len() + middle.len();
    let cc_start = email_start + email.len() + middle2.len();

    let findings = vec![
        pii_finding_at(
            PiiEntityType::UsSsn,
            "messages[0].content",
            ssn_start,
            ssn_start + ssn.len(),
        ),
        pii_finding_at(
            PiiEntityType::EmailAddress,
            "messages[0].content",
            email_start,
            email_start + email.len(),
        ),
        pii_finding_at(
            PiiEntityType::CreditCard,
            "messages[0].content",
            cc_start,
            cc_start + cc.len(),
        ),
    ];
    (body_bytes, findings)
}

/// 8 KB LLM body with 10 PII findings spread across the content.
fn body_10_findings_8kb() -> (Vec<u8>, Vec<Finding>) {
    let ssns: Vec<(&str, &str)> = vec![
        ("123-45-6789", "SSN_A"),
        ("234-56-7890", "SSN_B"),
        ("345-67-8901", "SSN_C"),
    ];
    let emails: Vec<&str> = vec![
        "alice@example.com",
        "bob@test.org",
        "carol@corp.net",
        "dave@mail.com",
    ];
    let ccs: Vec<&str> = vec![
        "4532015112830366",
        "5425233430109903",
        "374251018720955",
        "6011111111111117",
    ];

    let content = format!(
        "Users: {} {} {}. Contacts: {} {} {} {}. Cards: {} {} {} {}. {}",
        ssns[0].0,
        ssns[1].0,
        ssns[2].0,
        emails[0],
        emails[1],
        emails[2],
        emails[3],
        ccs[0],
        ccs[1],
        ccs[2],
        ccs[3],
        "More content here. ".repeat(200),
    );
    let body_json = json!({
        "model": "gpt-4o-mini",
        "messages": [{ "role": "user", "content": &content[..content.len().min(7800)] }]
    });
    let body_bytes = serde_json::to_vec(&body_json).unwrap_or_else(|e| {
        eprintln!("benchmark: failed to serialize fixture: {e}");
        std::process::exit(1)
    });

    let base_content_offset =
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":""#.len();
    let mut cursor = base_content_offset;
    let mut findings = Vec::new();

    for (ssn, _) in &ssns {
        findings.push(pii_finding_at(
            PiiEntityType::UsSsn,
            "messages[0].content",
            cursor,
            cursor + ssn.len(),
        ));
        cursor += ssn.len() + 1;
    }
    for email in &emails {
        findings.push(pii_finding_at(
            PiiEntityType::EmailAddress,
            "messages[0].content",
            cursor,
            cursor + email.len(),
        ));
        cursor += email.len() + 1;
    }
    for cc in &ccs {
        findings.push(pii_finding_at(
            PiiEntityType::CreditCard,
            "messages[0].content",
            cursor,
            cursor + cc.len(),
        ));
        cursor += cc.len() + 1;
    }

    (body_bytes, findings)
}

// ── benchmarks ────────────────────────────────────────────────────────────────

fn bench_redact_3_findings_4kb(c: &mut Criterion) {
    let r = redactor();
    let decision = redact_decision();
    let (body, findings) = body_3_findings_4kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("redaction_3_findings_4kb");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("redact_ssn_email_cc", |b| {
        b.iter(|| {
            let result = r.redact_body(
                criterion::black_box(&body),
                criterion::black_box(&findings),
                criterion::black_box(&decision),
            );
            let _ = criterion::black_box(result);
        });
    });
    g.finish();
}

fn bench_redact_10_findings_8kb(c: &mut Criterion) {
    let r = redactor();
    let decision = redact_decision();
    let (body, findings) = body_10_findings_8kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("redaction_10_findings_8kb");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("redact_3ssn_4email_4cc", |b| {
        b.iter(|| {
            let result = r.redact_body(
                criterion::black_box(&body),
                criterion::black_box(&findings),
                criterion::black_box(&decision),
            );
            let _ = criterion::black_box(result);
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_redact_3_findings_4kb,
    bench_redact_10_findings_8kb,
);
criterion_main!(benches);
