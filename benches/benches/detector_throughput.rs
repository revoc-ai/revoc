//! Detector throughput benchmarks (SPEC.md §19 targets).
//!
//! Targets:
//!   proxy_overhead       P95 < 10ms  (normalization + regex + policy decision, no upstream)
//!   regex_detection      > 100K req/s clean, > 50K req/s with 3 PII findings
//!   mcp_arg_parse        > 200K req/s
//!   manifest_analysis    < 1ms for 10 tools
//!   normalization        < 0.5ms added overhead

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use revoc_core::{CallerContext, EnforcementMode, InspectionInput, RequestType};
use revoc_detector::{analyze_tools_list, normalize, DetectionEngine};
use serde_json::json;
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

fn llm_input(body: Bytes) -> InspectionInput {
    InspectionInput {
        request_id: Uuid::now_v7().to_string(),
        request_type: RequestType::LlmRequest,
        raw_body: body,
        parsed_messages: None,
        mcp_call: None,
        caller: clean_caller(),
        governance_depth: 0,
    }
}

fn to_bytes(v: &serde_json::Value) -> Bytes {
    Bytes::from(serde_json::to_vec(v).unwrap_or_else(|e| {
        eprintln!("benchmark: failed to serialize fixture: {e}");
        std::process::exit(1)
    }))
}

/// 4 KB of clean prose — no PII.
fn clean_4kb() -> Bytes {
    let chunk = "The quick brown fox jumps over the lazy dog. \
                 All systems are nominal and no sensitive data is present. ";
    let text = chunk.repeat(4096 / chunk.len() + 1);
    to_bytes(&json!({
        "model": "gpt-4o-mini",
        "messages": [{ "role": "user", "content": &text[..4096] }]
    }))
}

/// 4 KB body containing 3 PII entities (SSN + email + credit card).
fn pii_4kb() -> Bytes {
    let text = format!(
        "User SSN is 123-45-6789, email alice@example.com, \
         card 4532015112830366. {}",
        "Lorem ipsum dolor sit amet consectetur adipiscing elit. ".repeat(60)
    );
    to_bytes(&json!({
        "model": "gpt-4o-mini",
        "messages": [{ "role": "user", "content": &text[..text.len().min(3800)] }]
    }))
}

/// 4 KB body with a base64-encoded SSN evasion attempt.
fn base64_ssn_4kb() -> Bytes {
    let encoded = base64_encode(b"My SSN is 123-45-6789");
    let text = format!(
        "Encoded data: {} {}",
        encoded,
        "padding content here. ".repeat(100)
    );
    to_bytes(&json!({
        "model": "gpt-4o-mini",
        "messages": [{ "role": "user", "content": &text[..text.len().min(3800)] }]
    }))
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// JSON body for an MCP tools/call — used by mcp_arg_parse benchmark.
fn mcp_arg_parse_body() -> Bytes {
    to_bytes(&json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "tools/call",
        "params": {
            "name": "query_database",
            "arguments": { "sql": "SELECT * FROM users WHERE active = 1", "limit": 10 }
        }
    }))
}

/// 4 KB body with fullwidth chars — used by normalization_overhead benchmark.
fn fullwidth_4kb() -> Bytes {
    let suspicious = "ＤＲＯＰTableusers\u{200B}DROP TABLE logs ";
    let filler = "The quick brown fox jumps. ".repeat(100);
    let text = format!("{suspicious}{filler}");
    to_bytes(&json!({
        "model": "gpt-4o-mini",
        "messages": [{ "role": "user", "content": &text[..text.len().min(3800)] }]
    }))
}

/// 10-tool manifest with 3 dangerous parameter names — used by manifest_analysis benchmark.
fn manifest_analysis_10_tools() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "tools": [
            { "name": "query_db", "description": "Run SQL query",
              "inputSchema": { "type": "object", "properties": { "sql": { "type": "string" } } } },
            { "name": "send_email", "description": "Send email",
              "inputSchema": { "type": "object", "properties": { "to": { "type": "string" }, "body": { "type": "string" } } } },
            { "name": "auth_user", "description": "Authenticate",
              "inputSchema": { "type": "object", "properties": { "password": { "type": "string" }, "token": { "type": "string" } } } },
            { "name": "list_files", "description": "List directory",
              "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } } },
            { "name": "exec_cmd", "description": "Run shell command",
              "inputSchema": { "type": "object", "properties": { "cmd": { "type": "string" } } } },
            { "name": "read_file", "description": "Read a file",
              "inputSchema": { "type": "object", "properties": { "filename": { "type": "string" } } } },
            { "name": "write_file", "description": "Write a file",
              "inputSchema": { "type": "object", "properties": { "content": { "type": "string" } } } },
            { "name": "admin_op", "description": "Admin operation",
              "inputSchema": { "type": "object", "properties": { "api_key": { "type": "string" }, "secret": { "type": "string" } } } },
            { "name": "search", "description": "Search data",
              "inputSchema": { "type": "object", "properties": { "query": { "type": "string" } } } },
            { "name": "get_user", "description": "Get user info",
              "inputSchema": { "type": "object", "properties": { "user_id": { "type": "string" } } } }
        ]
    })).unwrap_or_else(|e| {
        eprintln!("benchmark: failed to serialize manifest fixture: {e}");
        std::process::exit(1)
    })
}

// ── benchmarks ────────────────────────────────────────────────────────────────

/// proxy_overhead — full inline pipeline (normalize + regex_detection + policy decision)
/// on a clean 4 KB body with no upstream call. P95 target: < 10ms.
fn bench_proxy_overhead(c: &mut Criterion) {
    let rt = build_rt();
    let engine = DetectionEngine::new_for_testing();
    let body = clean_4kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("proxy_overhead");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    // P95 target: < 10ms  (normalization + regex_detection + policy resolution, no upstream)
    g.bench_function("clean_4kb_p95_lt_10ms", |b| {
        b.iter(|| {
            let input = llm_input(criterion::black_box(body.clone()));
            let findings = rt.block_on(engine.detect(&input));
            criterion::black_box(findings);
        });
    });
    g.finish();
}

fn bench_normalization_overhead(c: &mut Criterion) {
    let body = fullwidth_4kb();
    let len = body.len() as u64;
    let text = std::str::from_utf8(&body)
        .unwrap_or_else(|_| "")
        .to_string();

    let mut g = c.benchmark_group("normalization_overhead");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("normalize_4kb_fullwidth", |b| {
        b.iter(|| {
            let result = normalize(criterion::black_box(&text));
            criterion::black_box(result);
        });
    });
    g.finish();
}

/// regex_detection — clean 4 KB body, no PII. Target: > 100K req/s.
fn bench_regex_detection_clean_4kb(c: &mut Criterion) {
    let rt = build_rt();
    let engine = DetectionEngine::new_for_testing();
    let body = clean_4kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("regex_detection");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("clean_4kb_target_100k_rps", |b| {
        b.iter(|| {
            let input = llm_input(criterion::black_box(body.clone()));
            let findings = rt.block_on(engine.detect(&input));
            criterion::black_box(findings);
        });
    });
    g.finish();
}

/// regex_detection — 4 KB body with 3 PII findings. Target: > 50K req/s.
fn bench_regex_detection_3_pii(c: &mut Criterion) {
    let rt = build_rt();
    let engine = DetectionEngine::new_for_testing();
    let body = pii_4kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("regex_detection_3_pii");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("ssn_email_cc_target_50k_rps", |b| {
        b.iter(|| {
            let input = llm_input(criterion::black_box(body.clone()));
            let findings = rt.block_on(engine.detect(&input));
            criterion::black_box(findings);
        });
    });
    g.finish();
}

fn bench_encoding_base64_ssn(c: &mut Criterion) {
    let rt = build_rt();
    let engine = DetectionEngine::new_for_testing();
    let body = base64_ssn_4kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("encoding_base64_ssn");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("base64_evasion_target_40k_rps", |b| {
        b.iter(|| {
            let input = llm_input(criterion::black_box(body.clone()));
            let findings = rt.block_on(engine.detect(&input));
            criterion::black_box(findings);
        });
    });
    g.finish();
}

/// mcp_arg_parse — parse MCP tools/call body and run detection. Target: > 200K req/s.
fn bench_mcp_arg_parse(c: &mut Criterion) {
    let rt = build_rt();
    let engine = DetectionEngine::new_for_testing();
    let body = mcp_arg_parse_body();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("mcp_arg_parse");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("parse_detect_target_200k_rps", |b| {
        b.iter(|| {
            let input = InspectionInput {
                request_id: Uuid::now_v7().to_string(),
                request_type: RequestType::McpToolCall,
                raw_body: criterion::black_box(body.clone()),
                parsed_messages: None,
                mcp_call: None,
                caller: clean_caller(),
                governance_depth: 0,
            };
            let findings = rt.block_on(engine.detect(&input));
            criterion::black_box(findings);
        });
    });
    g.finish();
}

/// manifest_analysis — analyze 10-tool manifest (3 dangerous). Target: < 1ms.
fn bench_manifest_analysis(c: &mut Criterion) {
    let manifest = manifest_analysis_10_tools();
    let len = manifest.len() as u64;

    let mut g = c.benchmark_group("manifest_analysis");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("10_tools_3_dangerous_lt_1ms", |b| {
        b.iter(|| {
            let result = analyze_tools_list(criterion::black_box(&manifest));
            criterion::black_box(result);
        });
    });
    g.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let rt = build_rt();
    let engine = DetectionEngine::new_for_testing();
    let body = pii_4kb();
    let len = body.len() as u64;

    let mut g = c.benchmark_group("full_pipeline");
    g.throughput(Throughput::Bytes(len));
    g.warm_up_time(std::time::Duration::from_millis(500));
    g.measurement_time(std::time::Duration::from_secs(5));
    g.sample_size(500);

    g.bench_function("all_stages_4kb_target_40k_rps", |b| {
        b.iter(|| {
            let input = llm_input(criterion::black_box(body.clone()));
            let findings = rt.block_on(engine.detect(&input));
            criterion::black_box(findings);
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_proxy_overhead,
    bench_normalization_overhead,
    bench_regex_detection_clean_4kb,
    bench_regex_detection_3_pii,
    bench_encoding_base64_ssn,
    bench_mcp_arg_parse,
    bench_manifest_analysis,
    bench_full_pipeline,
);
criterion_main!(benches);
