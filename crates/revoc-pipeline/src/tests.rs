use revoc_core::{
    DetectionTier, Finding, FindingType, PiiEntityType, Severity, TextSpan,
};

use crate::deduplication::deduplicate;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn span_finding(
    ft: FindingType,
    sev: Severity,
    entity: Option<PiiEntityType>,
    field: &str,
    start: usize,
    end: usize,
    confidence: f64,
) -> Finding {
    let mut f = Finding::new(ft, sev, DetectionTier::Regex);
    if let Some(e) = entity {
        f = f.with_pii(e);
    }
    f = f.with_confidence(confidence);
    f.span = Some(TextSpan { start, end, field: field.into(), value: None });
    f
}

fn simple(sev: Severity, field: &str, start: usize, end: usize) -> Finding {
    span_finding(FindingType::Pii, sev, Some(PiiEntityType::EmailAddress), field, start, end, 1.0)
}

// ── Empty / single-element passthrough ────────────────────────────────────────

#[test]
fn test_empty_input_returns_empty() {
    assert!(deduplicate(vec![]).is_empty());
}

#[test]
fn test_single_finding_passthrough() {
    let f = simple(Severity::High, "content", 0, 10);
    let result = deduplicate(vec![f]);
    assert_eq!(result.len(), 1);
}

// ── Exact duplicate — keep higher confidence ──────────────────────────────────

#[test]
fn test_exact_duplicate_keeps_higher_confidence() {
    let high_conf = span_finding(
        FindingType::Pii, Severity::High, Some(PiiEntityType::EmailAddress),
        "content", 0, 10, 0.95,
    );
    let low_conf = span_finding(
        FindingType::Pii, Severity::High, Some(PiiEntityType::EmailAddress),
        "content", 0, 10, 0.60,
    );
    let result = deduplicate(vec![low_conf, high_conf]);
    assert_eq!(result.len(), 1);
    assert!((result[0].confidence - 0.95).abs() < 1e-9, "Higher confidence must survive");
}

// ── Contained spans — inner wins ──────────────────────────────────────────────

#[test]
fn test_inner_span_beats_outer_same_severity() {
    // outer span [0, 20), inner span [5, 15) — same severity
    let outer = simple(Severity::High, "content", 0, 20);
    let inner = simple(Severity::High, "content", 5, 15);
    let result = deduplicate(vec![outer, inner]);
    assert_eq!(result.len(), 1);
    let s = result[0].span.as_ref().unwrap();
    assert_eq!((s.start, s.end), (5, 15), "Inner span must win");
}

// ── Severity precedence overrides span size ───────────────────────────────────

#[test]
fn test_higher_severity_wins_even_with_larger_span() {
    // A Critical DDL finding over a larger span beats a High PII finding on a smaller span.
    let critical_outer = span_finding(
        FindingType::DdlMutation, Severity::Critical, None,
        "content", 0, 30, 1.0,
    );
    let high_inner = span_finding(
        FindingType::Pii, Severity::High, Some(PiiEntityType::EmailAddress),
        "content", 5, 15, 1.0,
    );
    let result = deduplicate(vec![critical_outer, high_inner]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].finding_type, FindingType::DdlMutation, "Critical must survive");
    let s = result[0].span.as_ref().unwrap();
    assert_eq!((s.start, s.end), (0, 30));
}

// ── Partial overlap — smaller span wins ──────────────────────────────────────

#[test]
fn test_partial_overlap_smaller_span_wins_same_severity() {
    let bigger = simple(Severity::High, "content", 0, 20);
    let smaller = simple(Severity::High, "content", 5, 12);
    let result = deduplicate(vec![bigger, smaller]);
    assert_eq!(result.len(), 1);
    let s = result[0].span.as_ref().unwrap();
    assert_eq!((s.start, s.end), (5, 12));
}

// ── Non-overlapping spans — both survive ─────────────────────────────────────

#[test]
fn test_non_overlapping_spans_both_kept() {
    let f1 = simple(Severity::High, "content", 0, 10);
    let f2 = simple(Severity::High, "content", 20, 30);
    let result = deduplicate(vec![f1, f2]);
    assert_eq!(result.len(), 2);
}

// ── Different fields — both survive ──────────────────────────────────────────

#[test]
fn test_same_position_different_fields_both_kept() {
    let f1 = simple(Severity::High, "messages[0].content", 0, 10);
    let f2 = simple(Severity::High, "messages[1].content", 0, 10);
    let result = deduplicate(vec![f1, f2]);
    assert_eq!(result.len(), 2);
}

// ── Normalization flag preference ─────────────────────────────────────────────

#[test]
fn test_was_normalized_preferred_over_not_normalized() {
    let mut f_norm = simple(Severity::High, "content", 0, 10);
    f_norm.was_normalized = true;
    let mut f_raw = simple(Severity::High, "content", 0, 10);
    f_raw.was_normalized = false;
    let result = deduplicate(vec![f_raw, f_norm]);
    assert_eq!(result.len(), 1);
    assert!(result[0].was_normalized, "was_normalized=true must survive");
}

// ── Sort order: severity desc then confidence desc ────────────────────────────

#[test]
fn test_sort_severity_descending() {
    let low = span_finding(FindingType::Pii, Severity::Low, None, "a", 0, 5, 1.0);
    let crit = span_finding(FindingType::DdlMutation, Severity::Critical, None, "b", 0, 5, 1.0);
    let high = span_finding(FindingType::Pii, Severity::High, None, "c", 0, 5, 1.0);
    let result = deduplicate(vec![low, crit, high]);
    assert_eq!(result[0].severity, Severity::Critical);
    assert_eq!(result[1].severity, Severity::High);
    assert_eq!(result[2].severity, Severity::Low);
}

#[test]
fn test_sort_confidence_descending_within_same_severity() {
    let f1 = span_finding(FindingType::Pii, Severity::High, None, "a", 0, 5, 0.7);
    let f2 = span_finding(FindingType::Pii, Severity::High, None, "b", 0, 5, 0.99);
    let result = deduplicate(vec![f1, f2]);
    assert_eq!(result.len(), 2);
    assert!((result[0].confidence - 0.99).abs() < 1e-9, "Higher confidence must be first");
}

// ── Span-less findings dedup on entity + type ─────────────────────────────────

#[test]
fn test_no_span_exact_entity_match_deduped() {
    let f1 = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_pii(PiiEntityType::EmailAddress)
        .with_confidence(0.8);
    let f2 = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_pii(PiiEntityType::EmailAddress)
        .with_confidence(0.9);
    let result = deduplicate(vec![f1, f2]);
    assert_eq!(result.len(), 1);
    assert!((result[0].confidence - 0.9).abs() < 1e-9);
}

#[test]
fn test_no_span_different_entities_both_kept() {
    let f1 = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_pii(PiiEntityType::EmailAddress);
    let f2 = Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_pii(PiiEntityType::UsSsn);
    let result = deduplicate(vec![f1, f2]);
    assert_eq!(result.len(), 2);
}
