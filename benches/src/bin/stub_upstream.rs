//! Minimal upstream for the HTTP load test (`scripts/proof.sh`).
//!
//! Answers an `OpenAI` chat completion, an embeddings call and an MCP
//! `tools/call` with fixed bodies so the proxy's own overhead dominates
//! what the load test measures. Binds loopback only. When given a record
//! path it appends every request body it receives (one per line), so the
//! proof run can check what actually left the proxy.
//!
//! Usage: `stub-upstream [port] [record-path]` (default port 18081).

#![forbid(unsafe_code)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::{body::Bytes, extract::State, routing::post, Json, Router};
use serde_json::{json, Value};

#[derive(Clone, Default)]
struct Recorder(Option<Arc<Mutex<std::fs::File>>>);

impl Recorder {
    fn record(&self, body: &[u8]) -> Value {
        if let Some(file) = &self.0 {
            if let Ok(mut f) = file.lock() {
                let _ = f.write_all(body).and_then(|()| f.write_all(b"\n"));
            }
        }
        serde_json::from_slice(body).unwrap_or(Value::Null)
    }
}

async fn chat(State(rec): State<Recorder>, body: Bytes) -> Json<Value> {
    let req = rec.record(&body);
    let model = req
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("gpt-4o-mini")
        .to_owned();
    Json(json!({
        "id": "chatcmpl-stub",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "The quarterly summary is ready."},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 24, "completion_tokens": 7, "total_tokens": 31}
    }))
}

async fn embeddings(State(rec): State<Recorder>, body: Bytes) -> Json<Value> {
    rec.record(&body);
    Json(json!({
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.01, 0.02, 0.03]}],
        "model": "text-embedding-3-small",
        "usage": {"prompt_tokens": 5, "total_tokens": 5}
    }))
}

async fn mcp(State(rec): State<Recorder>, body: Bytes) -> Json<Value> {
    let req = rec.record(&body);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"content": [{"type": "text", "text": "3 open tickets"}]}
    }))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(18081);
    let recorder = match args.next() {
        Some(path) => Recorder(Some(Arc::new(Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        )))),
        None => Recorder::default(),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(chat))
        .route("/v1/embeddings", post(embeddings))
        .route("/mcp", post(mcp))
        .with_state(recorder);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    axum::serve(listener, app).await
}
