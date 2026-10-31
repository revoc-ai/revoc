//! Finding deduplication — removes redundant findings before policy evaluation.
//!
//! Rules applied in priority order:
//! 1. **Exact duplicate** `(field, start, end, pii_entity)` → keep higher confidence.
//! 2. **Overlapping spans** (same field) → keep the smaller (more specific) span.
//! 3. **Contained span** (same field) → keep the inner (more specific) span.
//! 4. **Same position, normalization flag differs** → prefer `was_normalized = true`.
//!
//! Final sort: severity descending, then confidence descending.

use revoc_core::Finding;

// ── Public API ─────────────────────────────────────────────────────────────────

/// Deduplicate and sort `findings`.
///
/// Removes findings that are dominated by another finding according to the four
/// rules described in the module doc. The returned list is sorted by severity
/// (highest first) then confidence (highest first).
pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() <= 1 {
        return sort_findings(findings);
    }

    // Winnowing pass: for each candidate, either add it to the keepers list
    // or replace an existing keeper that it dominates.
    let mut keepers: Vec<Finding> = Vec::with_capacity(findings.len());

    'candidate: for candidate in findings {
        let mut dominated_idx: Option<usize> = None;

        for (i, existing) in keepers.iter().enumerate() {
            match compare(&candidate, existing) {
                Dominance::CandidateWins => {
                    dominated_idx = Some(i);
                    break;
                }
                Dominance::ExistingWins => {
                    // Candidate is dominated — skip it entirely
                    continue 'candidate;
                }
                Dominance::NoRelation => {}
            }
        }

        if let Some(idx) = dominated_idx {
            keepers[idx] = candidate;
        } else {
            keepers.push(candidate);
        }
    }

    sort_findings(keepers)
}

// ── Internal ───────────────────────────────────────────────────────────────────

#[derive(PartialEq, Eq)]
enum Dominance {
    CandidateWins,
    ExistingWins,
    NoRelation,
}

/// Compare two findings and return which dominates, if either does.
fn compare(candidate: &Finding, existing: &Finding) -> Dominance {
    let cs = candidate.span.as_ref();
    let es = existing.span.as_ref();

    match (cs, es) {
        // Both have spans — apply span-based rules only within the same field
        (Some(cs), Some(es)) if cs.field == es.field => {
            // Rule 1: exact duplicate (same span + same entity type)
            if cs.start == es.start
                && cs.end == es.end
                && candidate.pii_entity == existing.pii_entity
                && candidate.finding_type == existing.finding_type
            {
                return exact_winner(candidate, existing);
            }

            // Rules 2 & 3: overlapping spans
            if spans_overlap(cs.start, cs.end, es.start, es.end) {
                // Severity precedence: a higher-severity finding (e.g. a
                // Critical security pattern like DDL_MUTATION) must never be
                // discarded in favor of a lower-severity finding (e.g. a
                // false-positive SWIFT_BIC PII match) just because the
                // lower-severity finding's span happens to be smaller or
                // contained. Containment/overlap rules below only decide
                // between findings of equal severity.
                if candidate.severity != existing.severity {
                    return if candidate.severity > existing.severity {
                        Dominance::CandidateWins
                    } else {
                        Dominance::ExistingWins
                    };
                }

                // Rule 3: contained → inner wins
                if is_contained(cs.start, cs.end, es.start, es.end) {
                    // candidate span is inside existing span → candidate wins
                    return Dominance::CandidateWins;
                }
                if is_contained(es.start, es.end, cs.start, cs.end) {
                    // existing span is inside candidate span → existing wins
                    return Dominance::ExistingWins;
                }
                // Rule 2: partial overlap → smaller span wins
                let cs_len = cs.end.saturating_sub(cs.start);
                let es_len = es.end.saturating_sub(es.start);
                return if cs_len < es_len {
                    Dominance::CandidateWins
                } else {
                    Dominance::ExistingWins
                };
            }

            // Rule 4: same position, different normalization flag
            if cs.start == es.start && cs.end == es.end {
                if candidate.was_normalized && !existing.was_normalized {
                    return Dominance::CandidateWins;
                }
                if existing.was_normalized && !candidate.was_normalized {
                    return Dominance::ExistingWins;
                }
            }

            Dominance::NoRelation
        }

        // Both lack spans: treat as exact duplicate if entity + type match
        (None, None)
            if candidate.pii_entity == existing.pii_entity
                && candidate.finding_type == existing.finding_type =>
        {
            exact_winner(candidate, existing)
        }

        _ => Dominance::NoRelation,
    }
}

/// Between two findings at the same position, pick the winner.
///
/// Priority: higher confidence → `was_normalized = true` → existing wins (stable).
fn exact_winner(candidate: &Finding, existing: &Finding) -> Dominance {
    use std::cmp::Ordering;
    match candidate
        .confidence
        .partial_cmp(&existing.confidence)
        .unwrap_or(Ordering::Equal)
    {
        Ordering::Greater => Dominance::CandidateWins,
        Ordering::Less => Dominance::ExistingWins,
        Ordering::Equal => {
            // Rule 4: same confidence — prefer was_normalized
            if candidate.was_normalized && !existing.was_normalized {
                Dominance::CandidateWins
            } else {
                Dominance::ExistingWins
            }
        }
    }
}

/// Returns `true` when `[a_start, a_end)` and `[b_start, b_end)` overlap.
fn spans_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// Returns `true` when `[inner_start, inner_end)` is strictly inside
/// `[outer_start, outer_end)`.
fn is_contained(
    inner_start: usize,
    inner_end: usize,
    outer_start: usize,
    outer_end: usize,
) -> bool {
    outer_start <= inner_start
        && inner_end <= outer_end
        && (inner_start != outer_start || inner_end != outer_end)
}

/// Sort by severity descending, then confidence descending.
fn sort_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    findings
}
