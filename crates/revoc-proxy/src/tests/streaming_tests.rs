use serde_json::json;

use crate::streaming::tool_accumulator::ToolCallAccumulator;

// ── ToolCallAccumulator ───────────────────────────────────────────────────────

#[test]
fn test_accumulates_name_and_arguments_across_chunks() {
    let mut acc = ToolCallAccumulator::default();

    // Chunk 1: function name arrives
    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "execute_sql", "arguments": ""}}]}}]
    }));

    // Chunk 2: arguments start arriving in pieces
    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"quer"}}]}}]
    }));

    // Chunk 3: arguments complete
    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "y\": \"SELECT 1\"}"}}]}}]
    }));

    let calls = acc.get_completed_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool_name, "execute_sql");
    assert_eq!(calls[0].arguments["query"], "SELECT 1");
}

#[test]
fn test_multiple_parallel_tool_calls_by_index() {
    let mut acc = ToolCallAccumulator::default();

    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"name": "tool_a", "arguments": "{\"x\":1}"}},
            {"index": 1, "function": {"name": "tool_b", "arguments": "{\"y\":2}"}}
        ]}}]
    }));

    let calls = acc.get_completed_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].tool_name, "tool_a");
    assert_eq!(calls[1].tool_name, "tool_b");
}

#[test]
fn test_get_completed_calls_invalid_json_args_kept_as_string() {
    let mut acc = ToolCallAccumulator::default();
    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "bad_tool", "arguments": "not-valid-json"}}]}}]
    }));
    let calls = acc.get_completed_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool_name, "bad_tool");
    // Invalid JSON arguments are kept raw so governance still scans them
    assert_eq!(
        calls[0].arguments,
        serde_json::Value::String("not-valid-json".into())
    );
}

#[test]
fn test_process_chunk_no_tool_calls_field_noop() {
    let mut acc = ToolCallAccumulator::default();
    acc.process_chunk(&json!({
        "choices": [{"delta": {"content": "hello"}}]
    }));
    let calls = acc.get_completed_calls();
    assert!(calls.is_empty());
}

#[test]
fn test_process_chunk_no_choices_noop() {
    let mut acc = ToolCallAccumulator::default();
    acc.process_chunk(&json!({"model": "gpt-4o-mini"}));
    assert!(acc.get_completed_calls().is_empty());
}

#[test]
fn test_completed_calls_sorted_by_index() {
    let mut acc = ToolCallAccumulator::default();
    // Arrive out of order
    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [
            {"index": 2, "function": {"name": "tool_c", "arguments": "{}"}},
            {"index": 0, "function": {"name": "tool_a", "arguments": "{}"}},
            {"index": 1, "function": {"name": "tool_b", "arguments": "{}"}}
        ]}}]
    }));
    let calls = acc.get_completed_calls();
    assert_eq!(calls[0].tool_name, "tool_a");
    assert_eq!(calls[1].tool_name, "tool_b");
    assert_eq!(calls[2].tool_name, "tool_c");
}

// ── StreamGovernor ────────────────────────────────────────────────────────────

mod governor {
    use std::sync::Arc;

    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt as _;
    use revoc_config::Config;
    use revoc_core::CallerContext;
    use revoc_pipeline::sse::SseEvent;
    use serde_json::{json, Value};
    use tower::ServiceExt as _;
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

    use crate::app::{build_app_state, build_routers};
    use crate::streaming::governor::{StreamContext, StreamGovernor};

    const EMAIL: &str = "alice.smith@example.com";
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    fn config() -> Config {
        let mut cfg = Config::default();
        cfg.auth.mode = "none".into();
        cfg.server.environment = "development".into();
        cfg.server.dashboard_port = 0;
        cfg.storage.sqlite_path = ":memory:".into();
        cfg.policy.decision_cache_ttl_secs = 0;
        cfg
    }

    async fn governor(shadow: bool) -> StreamGovernor {
        let state = build_app_state(Arc::new(config())).await.expect("state");
        let ctx = StreamContext {
            trace_id: "trace".into(),
            request_id: "req".into(),
            model: "gpt-4o-mini".into(),
            provider: "openai".into(),
            caller: CallerContext::default(),
            shadow,
        };
        StreamGovernor::new(state, ctx, 128)
    }

    fn data(v: &Value) -> SseEvent {
        SseEvent {
            event: None,
            data: v.to_string(),
        }
    }

    fn text(choice: u64, content: &str) -> SseEvent {
        data(&json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk", "model": "gpt-4o-mini",
            "choices": [{"index": choice, "delta": {"content": content}, "finish_reason": null}]
        }))
    }

    fn finish(choice: u64, reason: &str) -> SseEvent {
        data(&json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk",
            "choices": [{"index": choice, "delta": {}, "finish_reason": reason}]
        }))
    }

    fn tool_delta(name: Option<&str>, args: &str) -> SseEvent {
        let mut function = json!({"arguments": args});
        if let Some(n) = name {
            function["name"] = json!(n);
        }
        data(&json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": function}]}, "finish_reason": null}]
        }))
    }

    fn done() -> SseEvent {
        SseEvent {
            event: None,
            data: "[DONE]".into(),
        }
    }

    async fn run(g: &mut StreamGovernor, events: Vec<SseEvent>) -> Vec<String> {
        let mut out = Vec::new();
        for ev in events {
            out.extend(g.on_event(ev).await);
        }
        out.extend(g.finish().await);
        out
    }

    /// Concatenate the visible text of every OpenAI content frame.
    fn visible_text(frames: &[String]) -> String {
        frames
            .iter()
            .filter_map(|f| f.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .filter_map(|v| {
                v.pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    }

    fn padding(n: usize) -> String {
        "lorem ipsum ".repeat(n)
    }

    #[tokio::test]
    async fn pii_split_across_chunks_is_redacted_in_stream() {
        let mut g = governor(false).await;
        let (a, b) = EMAIL.split_at(7);
        let frames = run(
            &mut g,
            vec![
                text(0, &format!("{}Contact {a}", padding(20))),
                text(0, b),
                text(0, &format!(" for details. {}", padding(20))),
                finish(0, "stop"),
                done(),
            ],
        )
        .await;
        let all = frames.concat();
        let visible = visible_text(&frames);
        assert!(!all.contains(EMAIL), "email leaked: {all}");
        assert!(!all.contains("alice.s"), "email prefix leaked");
        assert!(visible.contains("[REDACTED-"), "{visible}");
        assert!(visible.contains("Contact ") && visible.contains(" for details."));
        assert!(all.ends_with("data: [DONE]\n\n"));
        assert!(g.blocked().is_none());
        let audit = g.audit_event(1.0, None);
        assert_eq!(audit.decision, "redact");
        assert!(audit.finding_types.is_some_and(|t| t.contains("Pii")));
    }

    #[tokio::test]
    async fn secret_blocks_stream_before_any_of_it_is_released() {
        let mut g = governor(false).await;
        let (a, b) = AWS_KEY.split_at(6);
        let frames = run(
            &mut g,
            vec![
                text(0, &padding(30)),
                text(0, &format!("key: {a}")),
                text(0, b),
                text(0, &padding(30)),
                finish(0, "stop"),
                done(),
            ],
        )
        .await;
        let all = frames.concat();
        assert!(!all.contains("AKIAIO"), "secret prefix leaked: {all}");
        assert!(all.contains("content_filter"));
        assert!(g.blocked().is_some());
        assert_eq!(g.audit_event(1.0, None).effective_action, "block");
    }

    #[tokio::test]
    async fn short_text_is_held_until_the_choice_ends() {
        let mut g = governor(false).await;
        assert!(g.on_event(text(0, "Hello")).await.is_empty());
        let frames = g.on_event(finish(0, "stop")).await;
        assert_eq!(visible_text(&frames), "Hello");
        assert!(frames
            .last()
            .is_some_and(|f| f.contains("\"finish_reason\":\"stop\"")));
    }

    #[tokio::test]
    async fn tool_calls_are_held_until_governed_then_released_in_order() {
        let mut g = governor(false).await;
        assert!(g
            .on_event(tool_delta(Some("get_weather"), "{\"city\":"))
            .await
            .is_empty());
        assert!(g.on_event(tool_delta(None, "\"Paris\"}")).await.is_empty());
        let frames = g.on_event(finish(0, "tool_calls")).await;
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert!(frames[0].contains("get_weather"));
        assert!(frames[1].contains("Paris"));
        assert!(frames[2].contains("\"finish_reason\":\"tool_calls\""));
    }

    #[tokio::test]
    async fn dangerous_tool_call_is_never_forwarded() {
        let mut g = governor(false).await;
        let frames = run(
            &mut g,
            vec![
                tool_delta(Some("fetch_url"), "{\"url\":\"http://169.254."),
                tool_delta(None, "169.254/latest/meta-data\"}"),
                finish(0, "tool_calls"),
                done(),
            ],
        )
        .await;
        let all = frames.concat();
        assert!(
            !all.contains("fetch_url") && !all.contains("169.254"),
            "{all}"
        );
        assert!(all.contains("content_filter"));
        assert!(!all.contains("\"finish_reason\":\"tool_calls\""));
    }

    #[tokio::test]
    async fn invalid_tool_arguments_are_still_scanned() {
        let mut g = governor(false).await;
        let frames = run(
            &mut g,
            vec![
                tool_delta(Some("read_file"), "path=../../../../etc/passwd"),
                finish(0, "tool_calls"),
            ],
        )
        .await;
        assert!(frames.concat().contains("content_filter"));
    }

    #[tokio::test]
    async fn shadow_mode_records_but_never_blocks_or_rewrites() {
        let mut g = governor(true).await;
        let frames = run(
            &mut g,
            vec![
                text(0, &format!("key: {AWS_KEY} and {EMAIL}")),
                finish(0, "stop"),
                done(),
            ],
        )
        .await;
        let visible = visible_text(&frames);
        assert!(visible.contains(AWS_KEY) && visible.contains(EMAIL));
        assert!(g.blocked().is_none());
        let audit = g.audit_event(1.0, None);
        assert_eq!(audit.decision, "block");
        assert_eq!(audit.effective_action, "audit");
        assert_eq!(audit.enforcement_mode, "shadow");
    }

    #[tokio::test]
    async fn choices_are_governed_independently() {
        let mut g = governor(false).await;
        let frames = run(
            &mut g,
            vec![
                text(0, "First answer, "),
                text(1, "Second answer: "),
                text(0, "nothing sensitive."),
                text(1, EMAIL),
                finish(0, "stop"),
                finish(1, "stop"),
                done(),
            ],
        )
        .await;
        let mut by_choice = [String::new(), String::new()];
        for f in &frames {
            let Some(v) = f
                .strip_prefix("data: ")
                .and_then(|d| serde_json::from_str::<Value>(d.trim()).ok())
            else {
                continue;
            };
            let idx = v
                .pointer("/choices/0/index")
                .and_then(Value::as_u64)
                .unwrap_or(9);
            if let (Some(t), Some(slot)) = (
                v.pointer("/choices/0/delta/content")
                    .and_then(Value::as_str),
                by_choice.get_mut(usize::try_from(idx).unwrap_or(9)),
            ) {
                slot.push_str(t);
            }
        }
        assert_eq!(by_choice[0], "First answer, nothing sensitive.");
        assert!(
            by_choice[1].starts_with("Second answer: [REDACTED-"),
            "{by_choice:?}"
        );
        assert!(!frames.concat().contains(EMAIL));
    }

    #[tokio::test]
    async fn truncated_stream_gets_no_done_marker() {
        let mut g = governor(false).await;
        let frames = run(&mut g, vec![text(0, "partial answer")]).await;
        assert_eq!(visible_text(&frames), "partial answer");
        assert!(!frames.concat().contains("[DONE]"));
    }

    #[tokio::test]
    async fn anthropic_text_redacted_and_tool_use_blocked() {
        let mut g = governor(false).await;
        let ev = |name: &str, v: Value| SseEvent {
            event: Some(name.into()),
            data: v.to_string(),
        };
        let (a, b) = EMAIL.split_at(5);
        let frames = run(
            &mut g,
            vec![
                ev(
                    "message_start",
                    json!({"type":"message_start","message":{"usage":{"input_tokens":12}}}),
                ),
                ev(
                    "content_block_start",
                    json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
                ),
                ev(
                    "content_block_delta",
                    json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":format!("Mail {a}")}}),
                ),
                ev(
                    "content_block_delta",
                    json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":b}}),
                ),
                ev(
                    "content_block_stop",
                    json!({"type":"content_block_stop","index":0}),
                ),
                ev(
                    "content_block_start",
                    json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"read_file","input":{}}}),
                ),
                ev(
                    "content_block_delta",
                    json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"../../../../etc/"}}),
                ),
                ev(
                    "content_block_delta",
                    json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"passwd\"}"}}),
                ),
                ev(
                    "content_block_stop",
                    json!({"type":"content_block_stop","index":1}),
                ),
                ev(
                    "message_delta",
                    json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":30}}),
                ),
                ev("message_stop", json!({"type":"message_stop"})),
            ],
        )
        .await;
        let all = frames.concat();
        assert!(!all.contains(EMAIL) && all.contains("[REDACTED-"), "{all}");
        assert!(
            !all.contains("\"name\":\"read_file\"") && !all.contains("etc/passwd"),
            "{all}"
        );
        assert!(all.contains("event: error") && all.contains("revoc_governance_block"));
        assert!(!all.contains("message_stop"));
        assert_eq!(g.audit_event(1.0, None).prompt_tokens, Some(12));
    }

    // ── End to end through the router ────────────────────────────────────────

    fn sse_body(events: &[SseEvent]) -> String {
        events.iter().map(SseEvent::to_wire).collect()
    }

    async fn proxy_with_upstream(body: String, buffer_output: bool) -> (u16, String) {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        let mut cfg = config();
        cfg.upstream.mock_mode = false;
        cfg.upstream.providers = vec![serde_json::from_value(json!({
            "name": "openai", "base_url": server.uri(), "api_key_env": "REVOC_TEST_NO_KEY",
            "format": "openai", "default": true
        }))
        .expect("provider")];
        cfg.stream.buffer_output = buffer_output;
        let state = build_app_state(Arc::new(cfg)).await.expect("state");
        let req = Request::post("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]})
                    .to_string(),
            ))
            .expect("request");
        let resp = build_routers(&state)
            .main
            .oneshot(req)
            .await
            .expect("response");
        let status = resp.status().as_u16();
        assert!(resp.headers().contains_key("X-Revoc-Trace-ID"));
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn streamed_response_is_redacted_end_to_end() {
        let (a, b) = EMAIL.split_at(9);
        let body = sse_body(&[
            text(0, &format!("Reach {a}")),
            text(0, b),
            finish(0, "stop"),
            done(),
        ]);
        let (status, out) = proxy_with_upstream(body, false).await;
        assert_eq!(status, 200);
        assert!(!out.contains(EMAIL) && out.contains("[REDACTED-"), "{out}");
        assert!(out.ends_with("data: [DONE]\n\n"));
    }

    #[tokio::test]
    async fn buffered_mode_inspects_and_blocks_with_403() {
        let body = sse_body(&[
            text(0, &format!("key {AWS_KEY}")),
            finish(0, "stop"),
            done(),
        ]);
        let (status, out) = proxy_with_upstream(body, true).await;
        assert_eq!(status, 403);
        assert!(!out.contains(AWS_KEY));
    }

    #[tokio::test]
    async fn buffered_mode_redacts() {
        let body = sse_body(&[text(0, &format!("mail {EMAIL}")), finish(0, "stop"), done()]);
        let (status, out) = proxy_with_upstream(body, true).await;
        assert_eq!(status, 200);
        assert!(!out.contains(EMAIL) && out.contains("[REDACTED-"), "{out}");
    }
}
