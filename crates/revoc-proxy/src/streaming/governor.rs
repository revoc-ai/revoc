//! Governance of a streamed LLM response (SPEC.md §12).
//!
//! The governor sits between the SSE parser and the client. For every event
//! it decides what may be forwarded:
//!
//! - **Text** (`choices[i].delta.content`, Anthropic `text_delta` /
//!   `thinking_delta`) goes into a per-choice / per-block channel. The last
//!   `hold_back` characters of each channel are never released until more text
//!   arrives or the channel ends, so any pattern up to `hold_back` characters
//!   long is complete before any of it reaches the client. Each release is
//!   scanned together with the previously released tail, and spans that need
//!   redaction are rewritten in the text still held.
//! - **Tool calls** (`OpenAI` `delta.tool_calls`, Anthropic `tool_use` blocks)
//!   are held entirely and only released after the assembled calls pass
//!   governance — before `finish_reason` / `stop_reason` is forwarded
//!   (SPEC.md §23 Rule 22).
//! - **Unrecognised JSON events** are scanned whole; they are forwarded only
//!   when nothing in them needs blocking or redaction.
//!
//! In shadow mode nothing is blocked or rewritten: findings and the action
//! that would have been taken are recorded for the audit event only.

use std::collections::BTreeMap;

use serde_json::Value;
use tracing::warn;

use revoc_core::{
    traits::InspectionInput, Action, CallerContext, ChatMessage, Finding, FindingType, McpToolCall,
    PolicyEngine, PolicyInput, RequestType,
};
use revoc_detector::normalization::normalize;
use revoc_pipeline::sse::SseEvent;
use revoc_redaction::strategy_for;

use crate::app::AppState;
use crate::streaming::tool_accumulator::ToolCallAccumulator;

/// Wire format of the upstream stream, learned from the first event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    OpenAi,
    Anthropic,
}

/// Which JSON field of a text event carries the text.
#[derive(Debug, Clone, Copy)]
enum TextField {
    /// `choices[0].delta.content`
    OpenAiContent,
    /// `delta.text`
    AnthropicText,
    /// `delta.thinking`
    AnthropicThinking,
}

impl TextField {
    fn set(self, template: &Value, text: &str) -> Value {
        let mut v = template.clone();
        let slot = match self {
            Self::OpenAiContent => v.pointer_mut("/choices/0/delta/content"),
            Self::AnthropicText => v.pointer_mut("/delta/text"),
            Self::AnthropicThinking => v.pointer_mut("/delta/thinking"),
        };
        if let Some(s) = slot {
            *s = Value::String(text.to_owned());
        }
        v
    }
}

/// One stream of text (an `OpenAI` choice or an Anthropic content block).
struct TextChannel {
    /// Released text kept as left context for the next scan.
    context: String,
    /// Normalised text not yet released to the client.
    pending: String,
    /// Last event that carried text on this channel; releases are emitted as
    /// copies of it with the text replaced.
    template: Value,
    event_name: Option<String>,
    field: TextField,
}

/// Request-side facts the governor needs for policy input and audit.
#[derive(Debug, Clone)]
pub struct StreamContext {
    pub trace_id: String,
    pub request_id: String,
    pub model: String,
    pub provider: String,
    pub caller: CallerContext,
    pub shadow: bool,
}

/// Token usage reported inside the stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

/// Result of scanning one piece of text.
struct Verdict {
    findings: Vec<Finding>,
    action: Action,
    reason: String,
    rules: Vec<String>,
}

/// Upper bound on the left context kept per channel.
const MAX_CONTEXT_CHARS: usize = 4096;

/// Per-stream governance state machine.
pub struct StreamGovernor {
    state: AppState,
    ctx: StreamContext,
    hold_back: usize,
    format: Option<Format>,
    channels: BTreeMap<String, TextChannel>,
    openai_tools: BTreeMap<u64, ToolCallAccumulator>,
    anthropic_tools: BTreeMap<u64, (String, String)>,
    held_tool_frames: Vec<String>,
    findings: Vec<Finding>,
    rules: Vec<String>,
    blocked: Option<String>,
    would_block: Option<String>,
    redacted: bool,
    usage: StreamUsage,
    detection_ms: f64,
    policy_ms: f64,
}

impl StreamGovernor {
    /// `hold_back` is in characters; `usize::MAX` holds every channel until it
    /// ends (buffered mode).
    pub fn new(state: AppState, ctx: StreamContext, hold_back: usize) -> Self {
        Self {
            state,
            ctx,
            hold_back,
            format: None,
            channels: BTreeMap::new(),
            openai_tools: BTreeMap::new(),
            anthropic_tools: BTreeMap::new(),
            held_tool_frames: Vec::new(),
            findings: Vec::new(),
            rules: Vec::new(),
            blocked: None,
            would_block: None,
            redacted: false,
            usage: StreamUsage::default(),
            detection_ms: 0.0,
            policy_ms: 0.0,
        }
    }

    /// Reason the stream was stopped, if it was.
    pub fn blocked(&self) -> Option<&str> {
        self.blocked.as_deref()
    }

    /// Policy rules matched so far.
    pub fn rules(&self) -> &[String] {
        &self.rules
    }

    /// Process one upstream event; returns the frames to send, in order.
    pub async fn on_event(&mut self, ev: SseEvent) -> Vec<String> {
        if self.blocked.is_some() {
            return Vec::new();
        }
        if ev.data.trim() == "[DONE]" {
            let mut out = self.end_all().await;
            if self.blocked.is_none() {
                out.push(ev.to_wire());
            }
            return out;
        }
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else {
            return self.opaque(ev).await;
        };
        self.capture_usage(&v);
        if v.get("choices").is_some_and(Value::is_array) {
            self.format = Some(Format::OpenAi);
            self.openai(ev.event, v).await
        } else if let Some(t) = v.get("type").and_then(Value::as_str).map(str::to_owned) {
            self.format = Some(Format::Anthropic);
            self.anthropic(&t, ev, v).await
        } else {
            self.opaque(ev).await
        }
    }

    /// End of upstream stream: release whatever is still held after a final scan.
    pub async fn finish(&mut self) -> Vec<String> {
        if self.blocked.is_some() {
            return Vec::new();
        }
        self.end_all().await
    }

    /// Stop the stream for a reason other than a finding (size, read error).
    pub fn abort(&mut self, reason: &str) -> Vec<String> {
        self.block(reason)
    }

    // ── OpenAI chat.completion.chunk ─────────────────────────────────────────

    async fn openai(&mut self, event_name: Option<String>, v: Value) -> Vec<String> {
        let choices = v
            .get("choices")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if choices.is_empty() {
            // Usage-only chunk (stream_options.include_usage).
            return vec![wire(event_name.as_deref(), &v)];
        }
        let mut out = Vec::new();
        for (pos, choice) in choices.into_iter().enumerate() {
            let mut single = v.clone();
            single["choices"] = Value::Array(vec![choice]);
            out.extend(self.openai_choice(event_name.as_deref(), single, pos).await);
            if self.blocked.is_some() {
                break;
            }
        }
        out
    }

    async fn openai_choice(
        &mut self,
        event_name: Option<&str>,
        e: Value,
        pos: usize,
    ) -> Vec<String> {
        let idx = e
            .pointer("/choices/0/index")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| u64::try_from(pos).unwrap_or(u64::MAX));
        let key = format!("choice{idx}");
        let content = e
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let has_tools = e
            .pointer("/choices/0/delta/tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        let finish = e
            .pointer("/choices/0/finish_reason")
            .is_some_and(|f| !f.is_null());

        let mut out = Vec::new();
        if !content.is_empty() {
            let mut template = e.clone();
            if e.pointer("/choices/0/delta/role").is_some() {
                // Announce the role at once; held text follows without it.
                let mut role = e.clone();
                strip(&mut role, &["/choices/0/delta"], "tool_calls");
                set_null(&mut role, "/choices/0/finish_reason");
                if let Some(c) = role.pointer_mut("/choices/0/delta/content") {
                    *c = Value::String(String::new());
                }
                out.push(wire(event_name, &role));
                strip(&mut template, &["/choices/0/delta"], "role");
            }
            strip(&mut template, &["/choices/0/delta"], "tool_calls");
            set_null(&mut template, "/choices/0/finish_reason");
            out.extend(
                self.push_text(
                    &key,
                    TextField::OpenAiContent,
                    template,
                    event_name,
                    &content,
                )
                .await,
            );
            if self.blocked.is_some() {
                return out;
            }
        }
        if has_tools {
            self.openai_tools.entry(idx).or_default().process_chunk(&e);
            let mut held = e.clone();
            strip(&mut held, &["/choices/0/delta"], "content");
            set_null(&mut held, "/choices/0/finish_reason");
            self.held_tool_frames.push(wire(event_name, &held));
        }
        if finish {
            out.extend(self.end_channel(&key).await);
            out.extend(self.release_tools().await);
            if self.blocked.is_some() {
                return out;
            }
            let mut fin = e;
            strip(&mut fin, &["/choices/0/delta"], "content");
            strip(&mut fin, &["/choices/0/delta"], "tool_calls");
            out.push(wire(event_name, &fin));
        } else if content.is_empty() && !has_tools {
            // Role-only or empty delta.
            out.push(wire(event_name, &e));
        }
        out
    }

    // ── Anthropic Messages streaming ─────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    async fn anthropic(&mut self, t: &str, ev: SseEvent, v: Value) -> Vec<String> {
        let index = v.get("index").and_then(Value::as_u64).unwrap_or(0);
        let key = format!("block{index}");
        let name = ev.event.as_deref();
        match t {
            "content_block_start" => {
                let block_type = v
                    .pointer("/content_block/type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if block_type.ends_with("tool_use") {
                    let tool = v
                        .pointer("/content_block/name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    let input = v
                        .pointer("/content_block/input")
                        .filter(|i| i.as_object().is_some_and(|o| !o.is_empty()))
                        .map(Value::to_string)
                        .unwrap_or_default();
                    self.anthropic_tools.insert(index, (tool, input));
                    self.held_tool_frames.push(ev.to_wire());
                    return Vec::new();
                }
                let text = v
                    .pointer("/content_block/text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if text.is_empty() {
                    return vec![ev.to_wire()];
                }
                let mut start = v.clone();
                if let Some(s) = start.pointer_mut("/content_block/text") {
                    *s = Value::String(String::new());
                }
                let template = serde_json::json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {"type": "text_delta", "text": ""}
                });
                let mut out = vec![wire(name, &start)];
                out.extend(
                    self.push_text(
                        &key,
                        TextField::AnthropicText,
                        template,
                        Some("content_block_delta"),
                        &text,
                    )
                    .await,
                );
                out
            }
            "content_block_delta" => {
                let dtype = v
                    .pointer("/delta/type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match dtype {
                    "text_delta" | "thinking_delta" => {
                        let (field, ptr) = if dtype == "text_delta" {
                            (TextField::AnthropicText, "/delta/text")
                        } else {
                            (TextField::AnthropicThinking, "/delta/thinking")
                        };
                        let text = v
                            .pointer(ptr)
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        self.push_text(&key, field, v, name, &text).await
                    }
                    "input_json_delta" if self.anthropic_tools.contains_key(&index) => {
                        let part = v
                            .pointer("/delta/partial_json")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if let Some((_, args)) = self.anthropic_tools.get_mut(&index) {
                            args.push_str(part);
                        }
                        self.held_tool_frames.push(ev.to_wire());
                        Vec::new()
                    }
                    _ => self.opaque(ev).await,
                }
            }
            "content_block_stop" => {
                if self.anthropic_tools.contains_key(&index) {
                    self.held_tool_frames.push(ev.to_wire());
                    return Vec::new();
                }
                let mut out = self.end_channel(&key).await;
                if self.blocked.is_none() {
                    out.push(ev.to_wire());
                }
                out
            }
            "message_delta" | "message_stop" => {
                let mut out = self.end_all().await;
                if self.blocked.is_none() {
                    out.push(ev.to_wire());
                }
                out
            }
            "message_start" | "ping" | "error" => vec![ev.to_wire()],
            _ => self.opaque(ev).await,
        }
    }

    // ── Text channels ────────────────────────────────────────────────────────

    async fn push_text(
        &mut self,
        key: &str,
        field: TextField,
        template: Value,
        event_name: Option<&str>,
        text: &str,
    ) -> Vec<String> {
        let normalized = normalize(text).text;
        let ch = self
            .channels
            .entry(key.to_owned())
            .or_insert_with(|| TextChannel {
                context: String::new(),
                pending: String::new(),
                template: Value::Null,
                event_name: None,
                field,
            });
        ch.template = template;
        ch.event_name = event_name.map(str::to_owned);
        ch.field = field;
        ch.pending.push_str(&normalized);
        self.release(key, false).await
    }

    async fn end_channel(&mut self, key: &str) -> Vec<String> {
        self.release(key, true).await
    }

    async fn end_all(&mut self) -> Vec<String> {
        let keys: Vec<String> = self.channels.keys().cloned().collect();
        let mut out = Vec::new();
        for k in keys {
            out.extend(self.release(&k, true).await);
            if self.blocked.is_some() {
                return out;
            }
        }
        out.extend(self.release_tools().await);
        out
    }

    /// Scan a channel and release everything except the held-back tail
    /// (`final_` releases all of it).
    #[allow(clippy::too_many_lines)]
    async fn release(&mut self, key: &str, final_: bool) -> Vec<String> {
        let Some(ch) = self.channels.get(key) else {
            return Vec::new();
        };
        if ch.pending.is_empty() {
            return Vec::new();
        }
        let mut release_end = if final_ {
            ch.pending.len()
        } else {
            match tail_start(&ch.pending, self.hold_back) {
                0 => return Vec::new(),
                n => n,
            }
        };
        let ctx_len = ch.context.len();
        let scan_text = format!("{}{}", ch.context, ch.pending);
        let pending_len = ch.pending.len();

        let verdict = match self
            .evaluate(RequestType::LlmResponse, &scan_text, None)
            .await
        {
            Ok(v) => v,
            Err(reason) => return self.block(&reason),
        };

        if verdict.action.is_blocking() {
            if self.ctx.shadow {
                self.would_block.get_or_insert(verdict.reason.clone());
            } else {
                return self.block(&verdict.reason);
            }
        }

        let mut spans: Vec<(usize, usize, String)> = Vec::new();
        if !self.ctx.shadow {
            for f in &verdict.findings {
                if f.finding_type == FindingType::ToolManifestRisk
                    || !(verdict.action.requires_redaction() || f.is_high_severity())
                {
                    continue;
                }
                let Some(span) = f.span.as_ref().filter(|_| !f.was_encoded) else {
                    return self.block(&format!(
                        "{:?} in streamed output cannot be redacted in place",
                        f.finding_type
                    ));
                };
                if span.end <= ctx_len {
                    continue; // already handled when that text was released
                }
                let start = span.start.saturating_sub(ctx_len);
                let end = (span.end - ctx_len).min(pending_len);
                let Some(original) = scan_text.get(ctx_len + start..ctx_len + end) else {
                    return self.block("Stream redaction span off a character boundary");
                };
                let entity = f
                    .pii_entity
                    .clone()
                    .unwrap_or(revoc_core::PiiEntityType::Custom(format!(
                        "{:?}",
                        f.finding_type
                    )));
                spans.push((start, end, strategy_for(f).apply(original, &entity)));
                if !final_ && end > release_end {
                    release_end = end;
                }
            }
        }
        spans.sort_by_key(|s| s.0);

        // Record each finding once: when its start is released
        // (after redaction may have moved the release point).
        for f in &verdict.findings {
            let record = f.span.as_ref().map_or(final_, |s| {
                s.start >= ctx_len && s.start < ctx_len + release_end
            });
            if record {
                self.findings.push(f.clone());
            }
        }
        if !verdict.findings.is_empty() {
            self.note_rules(&verdict.rules);
        }

        let Some(ch) = self.channels.get_mut(key) else {
            return Vec::new();
        };
        let mut out_text = String::with_capacity(release_end);
        let mut cursor = 0;
        for (start, end, replacement) in &spans {
            if *start >= release_end || *end <= cursor {
                continue;
            }
            let start = (*start).max(cursor);
            out_text.push_str(&ch.pending[cursor..start]);
            out_text.push_str(replacement);
            cursor = *end;
            self.redacted = true;
        }
        if cursor < release_end {
            out_text.push_str(&ch.pending[cursor..release_end]);
        }
        let rest_start = release_end.max(cursor);
        ch.pending = ch.pending[rest_start..].to_owned();
        ch.context.push_str(&out_text);
        let keep = tail_start(&ch.context, self.hold_back.min(MAX_CONTEXT_CHARS));
        ch.context.drain(..keep);

        if out_text.is_empty() {
            return Vec::new();
        }
        let frame = ch.field.set(&ch.template, &out_text);
        vec![wire(ch.event_name.as_deref(), &frame)]
    }

    // ── Tool calls ───────────────────────────────────────────────────────────

    async fn release_tools(&mut self) -> Vec<String> {
        let mut calls: Vec<McpToolCall> = Vec::new();
        for acc in std::mem::take(&mut self.openai_tools).values() {
            calls.extend(acc.get_completed_calls());
        }
        for (idx, (name, args)) in std::mem::take(&mut self.anthropic_tools) {
            calls.push(McpToolCall {
                tool_name: name,
                arguments: ToolCallAccumulator::parse_arguments(&args),
                server_id: None,
                call_id: Some(idx.to_string()),
            });
        }
        let frames = std::mem::take(&mut self.held_tool_frames);
        for call in &calls {
            let text = call.arguments.to_string();
            let verdict = match self
                .evaluate(RequestType::McpToolCall, &text, Some(call.clone()))
                .await
            {
                Ok(v) => v,
                Err(reason) => return self.block(&reason),
            };
            self.findings.extend(verdict.findings.iter().cloned());
            self.note_rules(&verdict.rules);
            if verdict.action.is_blocking() || verdict.action.requires_redaction() {
                // Tool arguments cannot be rewritten mid-stream: anything
                // short of allow stops the call.
                let reason = format!("Tool call '{}': {}", call.tool_name, verdict.reason);
                if self.ctx.shadow {
                    self.would_block.get_or_insert(reason);
                } else {
                    return self.block(&reason);
                }
            }
        }
        frames
    }

    // ── Unrecognised events ──────────────────────────────────────────────────

    async fn opaque(&mut self, ev: SseEvent) -> Vec<String> {
        if serde_json::from_str::<Value>(&ev.data).is_err() && self.state.fail_closed() {
            return self.block("Unrecognised stream event");
        }
        let verdict = match self
            .evaluate(RequestType::LlmResponse, &ev.data, None)
            .await
        {
            Ok(v) => v,
            Err(reason) => return self.block(&reason),
        };
        self.findings.extend(verdict.findings.iter().cloned());
        self.note_rules(&verdict.rules);
        let needs_action = verdict.action.is_blocking()
            || verdict.action.requires_redaction()
            || verdict.findings.iter().any(Finding::is_high_severity);
        if needs_action {
            if self.ctx.shadow {
                self.would_block.get_or_insert(verdict.reason);
            } else {
                return self.block(&verdict.reason);
            }
        }
        vec![ev.to_wire()]
    }

    // ── Shared ───────────────────────────────────────────────────────────────

    async fn evaluate(
        &mut self,
        request_type: RequestType,
        text: &str,
        tool_call: Option<McpToolCall>,
    ) -> Result<Verdict, String> {
        let started = std::time::Instant::now();
        let input = InspectionInput {
            request_id: self.ctx.trace_id.clone(),
            request_type: request_type.clone(),
            raw_body: bytes::Bytes::from(text.as_bytes().to_vec()),
            parsed_messages: tool_call.is_none().then(|| {
                vec![ChatMessage {
                    role: "assistant".to_owned(),
                    content: Value::String(text.to_owned()),
                    name: None,
                    tool_call_id: None,
                    tool_calls: None,
                }]
            }),
            mcp_call: tool_call.clone(),
            caller: self.ctx.caller.clone(),
            governance_depth: self.ctx.caller.governance_depth,
        };
        let result = self.state.pipeline.run(input).await;
        self.detection_ms += started.elapsed().as_secs_f64() * 1000.0;
        if let Some(err) = result.detection_error {
            warn!(trace_id = %self.ctx.trace_id, error = %err, "Stream detection incomplete");
            if self.state.fail_closed() {
                return Err(format!("Stream governance unavailable: {err}"));
            }
        }
        let findings = result.findings;
        if findings.is_empty() {
            return Ok(Verdict {
                findings,
                action: Action::Allow,
                reason: String::new(),
                rules: Vec::new(),
            });
        }
        let policy_input = PolicyInput {
            request_id: self.ctx.trace_id.clone(),
            request_type,
            caller: self.ctx.caller.clone(),
            findings: findings.clone(),
            model: Some(self.ctx.model.clone()),
            provider: Some(self.ctx.provider.clone()),
            messages: None,
            tool_call,
            tool_result: None,
            token_usage: None,
            session_state: None,
            governance_depth: self.ctx.caller.governance_depth,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        let started = std::time::Instant::now();
        let decision = self.state.policy_engine.evaluate(&policy_input).await;
        self.policy_ms += started.elapsed().as_secs_f64() * 1000.0;
        match decision {
            Ok(d) => {
                // The engine's own shadow mode lowers effective_action; keep
                // what it would have done for the audit record.
                if d.action.is_blocking() && !d.effective_action.is_blocking() {
                    self.would_block.get_or_insert(d.reason.clone());
                }
                Ok(Verdict {
                    findings,
                    action: d.effective_action,
                    reason: d.reason,
                    rules: d.applicable_rules,
                })
            }
            Err(e) => {
                warn!(trace_id = %self.ctx.trace_id, error = %e, "Stream policy evaluation failed");
                if self.state.fail_closed() {
                    Err(format!("Stream policy evaluation failed: {e}"))
                } else {
                    Ok(Verdict {
                        findings,
                        action: Action::Allow,
                        reason: String::new(),
                        rules: Vec::new(),
                    })
                }
            }
        }
    }

    fn note_rules(&mut self, rules: &[String]) {
        for r in rules {
            if !self.rules.contains(r) {
                self.rules.push(r.clone());
            }
        }
    }

    fn block(&mut self, reason: &str) -> Vec<String> {
        warn!(trace_id = %self.ctx.trace_id, reason, "Stream stopped by governance");
        self.blocked = Some(reason.to_owned());
        self.channels.clear();
        self.held_tool_frames.clear();
        match self.format {
            Some(Format::Anthropic) => {
                let err = serde_json::json!({
                    "type": "error",
                    "error": {"type": "revoc_governance_block", "message": reason}
                });
                vec![wire(Some("error"), &err)]
            }
            _ => vec![
                wire(None, &content_filter_chunk()),
                "data: [DONE]\n\n".to_owned(),
            ],
        }
    }

    fn capture_usage(&mut self, v: &Value) {
        let u = v
            .get("usage")
            .or_else(|| v.pointer("/message/usage"))
            .filter(|u| u.is_object());
        let Some(u) = u else { return };
        if let Some(p) = u
            .get("prompt_tokens")
            .or_else(|| u.get("input_tokens"))
            .and_then(Value::as_u64)
        {
            self.usage.prompt_tokens = Some(p);
        }
        if let Some(c) = u
            .get("completion_tokens")
            .or_else(|| u.get("output_tokens"))
            .and_then(Value::as_u64)
        {
            self.usage.completion_tokens = Some(c);
        }
    }

    // ── Audit ────────────────────────────────────────────────────────────────

    /// Build the response-side audit event for this stream.
    pub fn audit_event(
        &self,
        duration_ms: f64,
        truncated: Option<&str>,
    ) -> revoc_dashboard::AuditEvent {
        let decision = if self.blocked.is_some() || self.would_block.is_some() {
            "block"
        } else if self.redacted {
            "redact"
        } else {
            "allow"
        };
        let effective = if self.blocked.is_some() {
            "block"
        } else if self.ctx.shadow && self.would_block.is_some() {
            "audit"
        } else {
            decision
        };
        let finding_types: Vec<String> = self
            .findings
            .iter()
            .map(|f| format!("{:?}", f.finding_type))
            .collect();
        let usage = match (self.usage.prompt_tokens, self.usage.completion_tokens) {
            (None, None) => None,
            (p, c) => Some(crate::handlers::llm::token_usage_for(
                p.unwrap_or(0),
                c.unwrap_or(0),
                &self.ctx.model,
            )),
        };
        let mut rules = self.rules.clone();
        if truncated.is_some() {
            rules.push("stream_truncated".to_owned());
        }
        let now = chrono::Utc::now();
        revoc_dashboard::AuditEvent {
            id: uuid::Uuid::now_v7().to_string(),
            org_id: Some(self.ctx.caller.org_id.clone()),
            request_id: self.ctx.request_id.clone(),
            timestamp: now.to_rfc3339(),
            caller_id: Some(self.ctx.caller.caller_id.clone()),
            caller_team: self.ctx.caller.team.clone(),
            environment: Some(self.state.config.server.environment.clone()),
            decision: decision.to_owned(),
            effective_action: effective.to_owned(),
            enforcement_mode: if self.ctx.shadow { "shadow" } else { "enforce" }.to_owned(),
            violated_rules: (!rules.is_empty()).then(|| rules.join(",")),
            finding_types: (!finding_types.is_empty()).then(|| finding_types.join(",")),
            model: Some(self.ctx.model.clone()),
            provider: Some(self.ctx.provider.clone()),
            tool_name: None,
            request_type: Some("LlmResponse".to_owned()),
            governance_depth: i64::from(self.ctx.caller.governance_depth),
            prompt_tokens: usage
                .as_ref()
                .map(|t| i64::try_from(t.prompt_tokens).unwrap_or(i64::MAX)),
            completion_tokens: usage
                .as_ref()
                .map(|t| i64::try_from(t.completion_tokens).unwrap_or(i64::MAX)),
            estimated_cost_usd: usage.as_ref().and_then(|t| t.estimated_cost_usd),
            duration_ms: Some(duration_ms),
            detection_ms: Some(self.detection_ms),
            policy_ms: Some(self.policy_ms),
            was_normalized: self.findings.iter().any(|f| f.was_normalized),
            manifest_warnings: 0,
            trace_id: Some(self.ctx.trace_id.clone()),
            policy_engine: None,
            created_at: now.to_rfc3339(),
        }
    }
}

/// Byte index where the last `n` characters of `s` begin (0 when `s` is
/// shorter than `n` characters).
fn tail_start(s: &str, n: usize) -> usize {
    if n == 0 {
        return s.len();
    }
    s.char_indices().rev().nth(n - 1).map_or(0, |(i, _)| i)
}

fn wire(event: Option<&str>, v: &Value) -> String {
    SseEvent {
        event: event.map(str::to_owned),
        data: v.to_string(),
    }
    .to_wire()
}

fn strip(v: &mut Value, parents: &[&str], key: &str) {
    for p in parents {
        if let Some(obj) = v.pointer_mut(p).and_then(Value::as_object_mut) {
            obj.remove(key);
        }
    }
}

fn set_null(v: &mut Value, ptr: &str) {
    if let Some(s) = v.pointer_mut(ptr) {
        *s = Value::Null;
    }
}

/// Synthetic `OpenAI` chunk that ends a stream stopped by governance.
pub fn content_filter_chunk() -> Value {
    serde_json::json!({
        "id": format!("chatcmpl-revoc-{}", uuid::Uuid::now_v7()),
        "object": "chat.completion.chunk",
        "created": chrono::Utc::now().timestamp(),
        "model": "revoc-governance",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "content_filter"}]
    })
}

#[cfg(test)]
mod tests {
    use super::tail_start;

    #[test]
    fn tail_start_counts_characters_not_bytes() {
        assert_eq!(tail_start("abcdef", 2), 4);
        assert_eq!(tail_start("ab", 5), 0);
        assert_eq!(tail_start("añé", 2), 1);
        assert_eq!(tail_start("abc", 0), 3);
    }
}
