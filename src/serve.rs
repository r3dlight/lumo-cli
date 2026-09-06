// SPDX-License-Identifier: GPL-3.0-or-later
//! An OpenAI-compatible local HTTP server backed by Lumo.
//!
//! `lumo-cli serve` exposes `/v1/models` and `/v1/chat/completions` (streaming
//! and non-streaming) on localhost, translating each request to Lumo and doing
//! the U2L encryption in-process. This lets OpenAI-compatible tools (editors,
//! agents, MCP bridges) talk to Lumo through a single native binary.
//!
//! It binds to 127.0.0.1 by default. Because anything that reaches the port can
//! spend the Lumo quota, an optional bearer key (`--api-key`) gates every
//! request, and binding to a non-loopback address requires setting one.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::client::{LumoClient, StreamEvent, Turn};
use crate::protocol::{MODEL_APERTUS, MODEL_LITE, MODEL_MAX, Role};

/// Maximum request body accepted by the server (1 MiB).
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Upper bound on one generation, so a stalled upstream cannot hold the client
/// lock, and with it the whole server, indefinitely.
const GENERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Clone)]
struct AppState {
    client: Arc<Mutex<LumoClient>>,
    api_key: Option<String>,
    default_model: String,
}

pub struct ServeOptions {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
}

pub async fn run(client: LumoClient, opts: ServeOptions) -> Result<()> {
    let ip: IpAddr = opts
        .host
        .parse()
        .with_context(|| format!("invalid --host {}", opts.host))?;
    // Refuse to expose the quota on a public interface without a key.
    if !ip.is_loopback() && opts.api_key.is_none() {
        bail!("binding to a non-loopback address requires --api-key");
    }
    let default_model = client.model.clone();
    let state = AppState {
        client: Arc::new(Mutex::new(client)),
        api_key: opts.api_key,
        default_model,
    };
    let app = Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/health", get(|| async { "ok" }))
        // Bound request bodies so a hostile client cannot exhaust memory.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let addr = SocketAddr::new(ip, opts.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind {addr}"))?;
    eprintln!("lumo-cli: OpenAI-compatible endpoint on http://{addr}/v1");
    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}

/// Returns an error response when the request is not authorised, else `None`.
fn check_key(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let expected = state.api_key.as_ref()?;
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if constant_time_eq(got.as_bytes(), expected.as_bytes()) {
        None
    } else {
        Some(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or missing API key",
        ))
    }
}

/// Length-then-bytes comparison that does not short-circuit on the first
/// differing byte, so it does not leak the key through response timing. The
/// length is compared normally (its leak is negligible for a bearer token).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn error_response(code: StatusCode, message: &str) -> Response {
    (
        code,
        Json(json!({ "error": { "message": message, "type": "lumo_cli_error" } })),
    )
        .into_response()
}

async fn models(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(e) = check_key(&state, &headers) {
        return e;
    }
    let data: Vec<Value> = [MODEL_LITE, MODEL_MAX, MODEL_APERTUS]
        .iter()
        .map(|id| json!({ "id": id, "object": "model", "owned_by": "proton-lumo" }))
        .collect();
    Json(json!({ "object": "list", "data": data })).into_response()
}

// ---- chat completions ----

#[derive(Deserialize)]
struct ChatReq {
    #[serde(default)]
    model: Option<String>,
    messages: Vec<InMessage>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    reasoning_effort: Option<String>,
}

#[derive(Deserialize)]
struct InMessage {
    role: String,
    #[serde(default)]
    content: Value,
}

/// OpenAI allows content as a string or an array of parts; take the text.
fn content_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn to_turns(messages: &[InMessage]) -> Vec<Turn> {
    messages
        .iter()
        .filter_map(|m| {
            // Map to Lumo roles. A bare `tool` message (function-calling result)
            // has no place here (serve advertises no tools), and an orphaned
            // `tool` turn can be rejected by the server, so fold it into `user`.
            let role = match m.role.as_str() {
                "system" => Role::System,
                "assistant" => Role::Assistant,
                _ => Role::User,
            };
            let content = content_text(&m.content);
            if content.is_empty() && role != Role::User {
                None
            } else {
                Some(Turn { role, content })
            }
        })
        .collect()
}

fn resolve_model(req: &ChatReq, default: &str) -> String {
    match req.model.as_deref() {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => default.to_string(),
    }
}

#[derive(Serialize)]
struct OutChoiceMsg {
    role: &'static str,
    content: String,
}

async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChatReq>,
) -> Response {
    if let Some(e) = check_key(&state, &headers) {
        return e;
    }
    if req.messages.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "messages must not be empty");
    }
    let model = resolve_model(&req, &state.default_model);
    let reasoning = req.reasoning_effort.as_deref().is_some_and(|r| r == "high");
    let turns = to_turns(&req.messages);
    let id = format!("chatcmpl-{}", uuid::Uuid::new_v4());
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if req.stream {
        stream_completion(state, model, reasoning, turns, id, created).into_response()
    } else {
        buffered_completion(state, model, reasoning, turns, id, created).await
    }
}

/// Configure a locked client for one stateless request.
fn prepare(client: &mut LumoClient, model: &str, reasoning: bool, turns: Vec<Turn>) {
    client.model = model.to_string();
    client.reasoning = reasoning;
    client.client_tools.clear();
    client.history = turns;
}

async fn buffered_completion(
    state: AppState,
    model: String,
    reasoning: bool,
    turns: Vec<Turn>,
    id: String,
    created: u64,
) -> Response {
    let mut client = state.client.lock().await;
    prepare(&mut client, &model, reasoning, turns);
    let result = match tokio::time::timeout(GENERATION_TIMEOUT, client.generate(|_| {})).await {
        Ok(r) => r,
        Err(_) => {
            return error_response(StatusCode::GATEWAY_TIMEOUT, "lumo generation timed out");
        }
    };
    match result {
        Ok(resp) if resp.error.is_none() => {
            let usage = resp.usage_tokens.unwrap_or_default();
            Json(json!({
                "id": id,
                "object": "chat.completion",
                "created": created,
                "model": resp.served_model.unwrap_or(model),
                "choices": [{
                    "index": 0,
                    "message": OutChoiceMsg { role: "assistant", content: resp.message },
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": usage.prompt,
                    "completion_tokens": usage.completion,
                    "total_tokens": usage.total,
                },
            }))
            .into_response()
        }
        Ok(resp) => error_response(
            StatusCode::BAD_GATEWAY,
            &format!(
                "lumo ended the generation: {}",
                resp.error.unwrap_or_default()
            ),
        ),
        Err(e) => error_response(
            StatusCode::BAD_GATEWAY,
            &format!("lumo request failed: {e:#}"),
        ),
    }
}

/// A message from the generation task to the SSE writer.
enum Chunk {
    Token(String),
    Done,
    Error(String),
}

fn stream_completion(
    state: AppState,
    model: String,
    reasoning: bool,
    turns: Vec<Turn>,
    id: String,
    created: u64,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Chunk>();

    // Drive the generation in a task so tokens can be forwarded as they arrive.
    // Holding the client lock here serialises requests, which is fine for a
    // personal proxy.
    {
        let state = state.clone();
        let model = model.clone();
        tokio::spawn(async move {
            let mut client = state.client.lock().await;
            prepare(&mut client, &model, reasoning, turns);
            let tx2 = tx.clone();
            let gen_fut = client.generate(|ev| {
                if let StreamEvent::Token(t) = ev {
                    let _ = tx2.send(Chunk::Token(t.to_string()));
                }
            });
            match tokio::time::timeout(GENERATION_TIMEOUT, gen_fut).await {
                Ok(Ok(resp)) if resp.error.is_some() => {
                    let _ = tx.send(Chunk::Error(resp.error.unwrap_or_default()));
                }
                Ok(Ok(_)) => {
                    let _ = tx.send(Chunk::Done);
                }
                Ok(Err(e)) => {
                    let _ = tx.send(Chunk::Error(format!("{e:#}")));
                }
                Err(_) => {
                    let _ = tx.send(Chunk::Error("lumo generation timed out".into()));
                }
            }
        });
    }

    let model_for_stream = model;
    let stream = UnboundedReceiverStream::new(rx).map(move |chunk| {
        let event = match chunk {
            Chunk::Token(text) => Event::default().data(
                json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_for_stream,
                    "choices": [{ "index": 0, "delta": { "content": text }, "finish_reason": null }],
                })
                .to_string(),
            ),
            Chunk::Done => {
                // Final stop chunk, then the OpenAI sentinel.
                Event::default().data(
                    json!({
                        "id": id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model_for_stream,
                        "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
                    })
                    .to_string(),
                )
            }
            Chunk::Error(msg) => Event::default().data(
                json!({ "error": { "message": msg, "type": "lumo_cli_error" } }).to_string(),
            ),
        };
        Ok(event)
    });

    // Append the `[DONE]` sentinel after the stream ends.
    let done = tokio_stream::once(Ok(Event::default().data("[DONE]")));
    Sse::new(stream.chain(done))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn content_text_string_and_parts() {
        assert_eq!(content_text(&json!("hi")), "hi");
        let parts = json!([{"type":"text","text":"a"},{"type":"text","text":"b"}]);
        assert_eq!(content_text(&parts), "a\nb");
        assert_eq!(content_text(&json!(42)), "");
    }

    #[test]
    fn role_mapping() {
        let msgs: Vec<InMessage> = serde_json::from_value(json!([
            {"role":"system","content":"s"},
            {"role":"user","content":"u"},
            {"role":"assistant","content":"a"},
            {"role":"tool","content":"t"}
        ]))
        .unwrap();
        let turns = to_turns(&msgs);
        assert_eq!(turns.len(), 4);
        assert_eq!(turns[0].role, Role::System);
        assert_eq!(turns[1].role, Role::User);
        assert_eq!(turns[2].role, Role::Assistant);
        // A `tool` message is folded into `user` to avoid an orphaned tool turn.
        assert_eq!(turns[3].role, Role::User);
    }

    #[test]
    fn model_defaults() {
        let req: ChatReq = serde_json::from_value(json!({"messages":[]})).unwrap();
        assert_eq!(resolve_model(&req, "lumo-lite"), "lumo-lite");
        let req: ChatReq =
            serde_json::from_value(json!({"model":"lumo-max","messages":[]})).unwrap();
        assert_eq!(resolve_model(&req, "lumo-lite"), "lumo-max");
    }
}
