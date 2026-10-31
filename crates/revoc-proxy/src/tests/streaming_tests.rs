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
fn test_is_finish_tool_calls_true() {
    let event = json!({
        "choices": [{"delta": {}, "finish_reason": "tool_calls"}]
    });
    assert!(ToolCallAccumulator::is_finish_tool_calls(&event));
}

#[test]
fn test_is_finish_tool_calls_false_for_stop() {
    let event = json!({
        "choices": [{"delta": {}, "finish_reason": "stop"}]
    });
    assert!(!ToolCallAccumulator::is_finish_tool_calls(&event));
}

#[test]
fn test_is_finish_tool_calls_false_for_null_reason() {
    let event = json!({
        "choices": [{"delta": {"content": "hello"}, "finish_reason": null}]
    });
    assert!(!ToolCallAccumulator::is_finish_tool_calls(&event));
}

#[test]
fn test_get_completed_calls_invalid_json_args_yields_empty_object() {
    let mut acc = ToolCallAccumulator::default();
    acc.process_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "bad_tool", "arguments": "not-valid-json"}}]}}]
    }));
    let calls = acc.get_completed_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool_name, "bad_tool");
    // Invalid JSON arguments fall back to an empty object
    assert_eq!(
        calls[0].arguments,
        serde_json::Value::Object(Default::default())
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
