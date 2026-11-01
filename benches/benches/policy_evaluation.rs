//! Policy engine evaluation benchmarks (SPEC.md §19 targets).
//!
//! Targets:
//!   policy_cache   > 1_000_000 ops/s  (cache hit path)
//!   native_policy  > 500_000 ops/s    (cold evaluation, empty findings)

use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use revoc_core::{
    Action, CallerContext, DetectionTier, EnforcementMode, Finding, FindingType, PiiEntityType,
    PolicyDecision, PolicyEngine, PolicyInput, PolicyRuleTier, RequestType, Severity,
};
use revoc_policy::{cache::DecisionCache, conflict, native::NativePolicyEngine};
use uuid::Uuid;

// ── helpers ───────────────────────────────────────────────────────────────────

fn build_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("benchmark: failed to create Tokio runtime: {e}");
            std::process::exit(1)
        })
}

fn clean_caller() -> CallerContext {
    CallerContext {
        org_id: "bench-org".into(),
        caller_id: "bench-caller".into(),
        team: None,
        agent_id: None,
        service_name: None,
        environment: "bench".into(),
        policy_profile: None,
        enforcement_mode: EnforcementMode::Enforce,
        governance_depth: 0,
        attributes: Default::default(),
    }
}

fn empty_policy_input() -> PolicyInput {
    PolicyInput {
        request_id: Uuid::now_v7().to_string(),
        request_type: RequestType::LlmRequest,
        caller: clean_caller(),
        findings: vec![],
        model: Some("gpt-4o-mini".into()),
        provider: Some("openai".into()),
        messages: None,
        tool_call: None,
        tool_result: None,
        token_usage: None,
        session_state: None,
        governance_depth: 0,
        timestamp: chrono::Utc::now().timestamp_millis(),
    }
}

fn pii_finding(entity: PiiEntityType, field: &str) -> Finding {
    use revoc_core::TextSpan;
    Finding::new(FindingType::Pii, Severity::High, DetectionTier::Regex)
        .with_pii(entity)
        .with_span(TextSpan {
            start: 10,
            end: 21,
            field: field.into(),
            value: None,
        })
        .with_confidence(0.99)
}

fn policy_input_3_pii() -> PolicyInput {
    let mut input = empty_policy_input();
    input.findings = vec![
        pii_finding(PiiEntityType::UsSsn, "messages[0].content"),
        pii_finding(PiiEntityType::EmailAddress, "messages[0].content"),
        pii_finding(PiiEntityType::CreditCard, "messages[0].content"),
    ];
    input
}

fn native_engine_no_cache() -> Arc<NativePolicyEngine> {
    Arc::new(NativePolicyEngine::new(EnforcementMode::Enforce))
}

fn make_violation(tier: PolicyRuleTier, action: Action, rule: &str) -> PolicyDecision {
    let mut d = PolicyDecision::allow();
    d.action = action.clone();
    d.effective_action = action;
    d.tier = tier;
    d.applicable_rules = vec![rule.into()];
    d
}

// ── benchmarks ────────────────────────────────────────────────────────────────

/// policy_cache hit path (OPA sidecar cache). Target: > 1_000_000 ops/s.
/// Measures key computation plus lookup, which is what a hit costs.
fn bench_cache_hit(c: &mut Criterion) {
    let cache = DecisionCache::new(Duration::from_secs(60), 10_000);
    if let Some(key) = DecisionCache::cache_key(&empty_policy_input()) {
        cache.set(&key, PolicyDecision::allow());
    }

    let mut g = c.benchmark_group("policy_cache");
    g.throughput(Throughput::Elements(1));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("hit_target_1_000_000_ops", |b| {
        b.iter(|| {
            let input = criterion::black_box(empty_policy_input());
            let hit = DecisionCache::cache_key(&input).and_then(|k| cache.get(&k));
            criterion::black_box(hit);
        });
    });
    g.finish();
}

/// native_policy cold evaluation with empty findings. Target: > 500_000 ops/s.
fn bench_native_policy_empty(c: &mut Criterion) {
    let rt = build_rt();
    let engine = native_engine_no_cache();

    let mut g = c.benchmark_group("native_policy");
    g.throughput(Throughput::Elements(1));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    // Target: > 500_000 ops/s (cold path, empty findings)
    g.bench_function("empty_findings_target_500_000_ops", |b| {
        b.iter(|| {
            let input = criterion::black_box(empty_policy_input());
            let decision = rt
                .block_on(engine.evaluate(&input))
                .unwrap_or_else(|_| PolicyDecision::allow());
            criterion::black_box(decision);
        });
    });
    g.finish();
}

fn bench_native_3_pii(c: &mut Criterion) {
    let rt = build_rt();
    let engine = native_engine_no_cache();

    let mut g = c.benchmark_group("native_policy_3_pii");
    g.throughput(Throughput::Elements(1));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("ssn_email_cc_redact_decision", |b| {
        b.iter(|| {
            let input = criterion::black_box(policy_input_3_pii());
            let decision = rt
                .block_on(engine.evaluate(&input))
                .unwrap_or_else(|_| PolicyDecision::allow());
            criterion::black_box(decision);
        });
    });
    g.finish();
}

fn bench_conflict_5_violations(c: &mut Criterion) {
    let violations = vec![
        make_violation(PolicyRuleTier::Default, Action::Allow, "default_allow"),
        make_violation(PolicyRuleTier::Custom, Action::Audit, "custom_audit"),
        make_violation(PolicyRuleTier::Profile, Action::Redact, "pii_ssn_v1"),
        make_violation(
            PolicyRuleTier::Security,
            Action::Block,
            "sec_ddl_mutation_v1",
        ),
        make_violation(PolicyRuleTier::Emergency, Action::Block, "kill_switch"),
    ];

    let mut g = c.benchmark_group("policy_conflict_5_violations");
    g.throughput(Throughput::Elements(1));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("resolve_5_tier_violations", |b| {
        b.iter(|| {
            let result = conflict::resolve(criterion::black_box(&violations));
            criterion::black_box(result);
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_cache_hit,
    bench_native_policy_empty,
    bench_native_3_pii,
    bench_conflict_5_violations,
);
criterion_main!(benches);
