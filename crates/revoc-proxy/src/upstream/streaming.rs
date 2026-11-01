//! Proxy an upstream SSE stream through the stream governor (SPEC.md §12).

use std::time::Instant;

use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt as _;
use tracing::warn;

use revoc_pipeline::sse::{parse_all, SseParser};

use crate::app::AppState;
use crate::streaming::governor::{StreamContext, StreamGovernor};

/// What the handler should send for a streamed request.
pub enum StreamOutcome {
    /// Send this response (a live stream, or a fully governed buffered body).
    Response(Response),
    /// Buffered mode only: governance blocked the response before any byte
    /// was sent, so the handler can still answer 403.
    Blocked {
        /// Why the response was blocked.
        reason: String,
        /// Rules that matched.
        rules: Vec<String>,
    },
    /// Buffered mode only: the upstream body could not be read within
    /// `server.max_response_body_bytes`.
    UpstreamUnreadable,
}

/// Proxy an upstream SSE response to the client under governance.
///
/// `stream.buffer_output = false` (default): events are forwarded as they are
/// governed, with per-choice hold-back. `true`: the whole body is read and
/// governed first; nothing is sent until it passes.
pub async fn proxy_sse_stream(
    upstream_resp: reqwest::Response,
    state: &AppState,
    ctx: StreamContext,
) -> StreamOutcome {
    let max_bytes = state.config.server.max_response_body_bytes;

    let mut builder = Response::builder()
        .status(upstream_resp.status())
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no");
    for (name, value) in upstream_resp.headers() {
        let n = name.as_str();
        if n.starts_with("x-") && !n.starts_with("x-revoc-") {
            builder = builder.header(name, value);
        }
    }

    if state.config.stream.buffer_output {
        return buffered(upstream_resp, state, ctx, builder, max_bytes).await;
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::convert::Infallible>>(128);
    let state = state.clone();
    let hold_back = state.config.stream.hold_back_chars;

    tokio::spawn(async move {
        let started = Instant::now();
        let mut gov = StreamGovernor::new(state.clone(), ctx, hold_back);
        let mut parser = SseParser::new(max_bytes);
        let mut upstream = upstream_resp.bytes_stream();
        let mut total = 0usize;
        let mut truncated: Option<&'static str> = None;

        loop {
            let (frames, last) = match upstream.next().await {
                None => {
                    let mut frames = Vec::new();
                    match parser.finish() {
                        Ok(Some(ev)) => frames.extend(gov.on_event(ev).await),
                        Ok(None) => {}
                        Err(e) => {
                            frames.extend(gov.abort(&format!("Malformed upstream stream: {e}")));
                        }
                    }
                    frames.extend(gov.finish().await);
                    (frames, true)
                }
                Some(Err(e)) => {
                    warn!(error = %e, "Upstream stream read error");
                    truncated = Some("upstream_read_error");
                    // Held text is released only after its final scan; no
                    // [DONE] is sent, so the client sees the truncation.
                    (gov.finish().await, true)
                }
                Some(Ok(chunk)) => {
                    total += chunk.len();
                    if total > max_bytes {
                        truncated = Some("response_too_large");
                        (
                            gov.abort("Stream exceeds server.max_response_body_bytes"),
                            true,
                        )
                    } else {
                        match parser.push(&chunk) {
                            Ok(events) => {
                                let mut frames = Vec::new();
                                for ev in events {
                                    frames.extend(gov.on_event(ev).await);
                                    if gov.blocked().is_some() {
                                        break;
                                    }
                                }
                                (frames, gov.blocked().is_some())
                            }
                            Err(e) => (gov.abort(&format!("Malformed upstream stream: {e}")), true),
                        }
                    }
                }
            };
            let mut client_gone = false;
            for frame in frames {
                if tx.send(Ok(Bytes::from(frame))).await.is_err() {
                    client_gone = true;
                    break;
                }
            }
            if client_gone {
                truncated = Some("client_disconnected");
                break;
            }
            if last {
                break;
            }
        }

        let ms = started.elapsed().as_secs_f64() * 1000.0;
        state.spawn_audit_write(gov.audit_event(ms, truncated));
    });

    let body = axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    StreamOutcome::Response(builder.body(body).unwrap_or_default())
}

async fn buffered(
    upstream_resp: reqwest::Response,
    state: &AppState,
    ctx: StreamContext,
    builder: axum::http::response::Builder,
    max_bytes: usize,
) -> StreamOutcome {
    let started = Instant::now();
    let body = match crate::upstream::body::read_response_limited(upstream_resp, max_bytes).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "Buffered stream unreadable or too large");
            return StreamOutcome::UpstreamUnreadable;
        }
    };
    let mut gov = StreamGovernor::new(state.clone(), ctx, usize::MAX);
    let mut out = String::with_capacity(body.len());
    match parse_all(&body, max_bytes) {
        Ok(events) => {
            for ev in events {
                out.extend(gov.on_event(ev).await);
            }
            out.extend(gov.finish().await);
        }
        Err(e) => {
            gov.abort(&format!("Malformed upstream stream: {e}"));
        }
    }
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    state.spawn_audit_write(gov.audit_event(ms, None));
    if let Some(reason) = gov.blocked() {
        return StreamOutcome::Blocked {
            reason: reason.to_owned(),
            rules: gov.rules().to_vec(),
        };
    }
    StreamOutcome::Response(
        builder
            .body(axum::body::Body::from(out))
            .unwrap_or_default(),
    )
}
