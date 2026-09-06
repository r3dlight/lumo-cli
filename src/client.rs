// SPDX-License-Identifier: GPL-3.0-or-later
//! Lumo chat client: encrypted chat-completions requests, SSE streaming.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use serde_json::Value;

use crate::auth::{self, Session};
use crate::crypto::RequestCrypto;
use crate::protocol::*;

/// One turn of local (cleartext) conversation history.
#[derive(Debug, Clone)]
pub struct Turn {
    pub role: Role,
    pub content: String,
}

/// A client tool call requested by the model.
#[derive(Debug, Clone)]
pub struct PendingToolCall {
    pub id: String,
    pub name: String,
    /// JSON-encoded arguments.
    pub arguments: String,
}

/// Events surfaced to the UI while streaming.
pub enum StreamEvent<'a> {
    Token(&'a str),
    Reasoning(&'a str),
    /// A server-side tool (web_search, …) ran remotely.
    ServerTool(&'a str),
}

/// Outcome of one streamed generation.
#[derive(Debug, Default)]
pub struct ChatResponse {
    pub message: String,
    pub reasoning: String,
    pub tool_calls: Vec<PendingToolCall>,
    /// Terminal status if the server ended abnormally
    /// ("timeout", "error", "rejected", "harmful", …).
    pub error: Option<String>,
    /// Machine-readable error code when present (e.g. "context_length_exceeded").
    pub error_code: Option<String>,
    /// Model reported by the server, e.g. "lumo-lite".
    pub served_model: Option<String>,
    pub usage: Option<Value>,
    /// Parsed token usage for this request, if the server reported it.
    pub usage_tokens: Option<Usage>,
}

pub struct LumoClient {
    http: reqwest::Client,
    pub session: Option<Session>,
    /// Lumo's PGP public key, parsed once; the per-request AES key is encrypted
    /// to it. Replaceable at startup from a file/override (see `keys`).
    lumo_key: pgp::composed::SignedPublicKey,
    /// Cleartext history, re-encrypted with a fresh key on every request.
    pub history: Vec<Turn>,
    /// Model to request: lumo-lite, lumo-max or apertus-15.
    pub model: String,
    /// Enable reasoning ("thinking") mode.
    pub reasoning: bool,
    /// Server-side tools to advertise (e.g. "web_search").
    pub server_tools: Vec<String>,
    /// Client function tools to advertise (OpenAI shape).
    pub client_tools: Vec<WireTool>,
    /// Max history turns sent per request (leading system turn always kept).
    pub max_turns: usize,
    /// Project instructions (from `.lumo-config/instructions.md`) to append to
    /// the system prompt, once approved by the user.
    pub project_instructions: Option<String>,
    /// Cumulative token usage this session (prompt, completion, total).
    session_tokens: (u64, u64, u64),
}

/// A parsed token-usage summary for one request.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    pub prompt: u64,
    pub completion: u64,
    pub total: u64,
}

impl Usage {
    fn from_value(v: &Value) -> Self {
        let g = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        let prompt = g("prompt_tokens");
        let completion = g("completion_tokens");
        let total = {
            let t = g("total_tokens");
            if t > 0 {
                t
            } else {
                prompt.saturating_add(completion)
            }
        };
        Usage {
            prompt,
            completion,
            total,
        }
    }
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in / {} out / {} total",
            self.prompt, self.completion, self.total
        )
    }
}

fn lumo_headers() -> reqwest::header::HeaderMap {
    use reqwest::header::HeaderValue;
    // All values are compile-time constants, so `from_static` is infallible and
    // there is no runtime panic path (ANSSI LANG: avoid unwrap on fallible calls).
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        "accept",
        HeaderValue::from_static("application/vnd.protonmail.v1+json"),
    );
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h.insert("origin", HeaderValue::from_static(LUMO_BASE_URL));
    h.insert("x-pm-appversion", HeaderValue::from_static("Other"));
    h.insert("x-pm-locale", HeaderValue::from_static("en_US"));
    h.insert("user-agent", HeaderValue::from_static("None"));
    h
}

/// Advance `idx` past any leading tool turns so a history slice never begins in
/// the middle of a `lumo_tool_call`/`tool` sequence (an orphaned `tool` result,
/// or a call cut from its result, which the server can reject). Lands on the
/// first User/Assistant/System turn.
fn snap_forward(history: &[Turn], mut idx: usize) -> usize {
    while let Some(t) = history.get(idx)
        && matches!(t.role, Role::ToolCall | Role::ToolResult)
    {
        idx = idx.saturating_add(1);
    }
    idx
}

#[derive(Default)]
struct ToolCallAccumulator {
    id: String,
    name: String,
    arguments: String,
}

impl LumoClient {
    pub fn new(session: Option<Session>) -> Result<Self> {
        use pgp::composed::{Deserializable, SignedPublicKey};
        let (lumo_key, _) = SignedPublicKey::from_string(LUMO_PGP_PUBLIC_KEY)
            .context("failed to parse embedded Lumo PGP key")?;
        Ok(Self {
            http: reqwest::Client::builder()
                .default_headers(lumo_headers())
                .connect_timeout(std::time::Duration::from_secs(20))
                .build()?,
            session,
            lumo_key,
            history: Vec::new(),
            model: MODEL_LITE.to_string(),
            reasoning: false,
            server_tools: Vec::new(),
            client_tools: Vec::new(),
            max_turns: 40,
            project_instructions: None,
            session_tokens: (0, 0, 0),
        })
    }

    /// Cumulative session usage (prompt, completion, total) tokens.
    pub fn session_usage(&self) -> Usage {
        Usage {
            prompt: self.session_tokens.0,
            completion: self.session_tokens.1,
            total: self.session_tokens.2,
        }
    }

    /// Replace the Lumo PGP key (e.g. from a file/override resolved at startup).
    pub fn set_lumo_key(&mut self, key: pgp::composed::SignedPublicKey) {
        self.lumo_key = key;
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Drop the oldest non-system turns (keeping any leading system turn and the
    /// most recent `keep_recent` turns). Returns true if anything was removed.
    /// Used to recover from a `context_length_exceeded` error. The cut is snapped
    /// to a safe boundary so a `lumo_tool_call`/`tool` pair is never split.
    pub fn trim_oldest(&mut self, keep_recent: usize) -> bool {
        let start = if self.history.first().map(|t| t.role) == Some(Role::System) {
            1
        } else {
            0
        };
        let removable = self.history.len().saturating_sub(start);
        if removable <= keep_recent {
            return false;
        }
        let mut cut = self.history.len().saturating_sub(keep_recent);
        cut = snap_forward(&self.history, cut);
        if cut <= start {
            return false;
        }
        self.history.drain(start..cut);
        true
    }

    /// Select which history turns to send: the leading system turn (if any)
    /// plus the most recent turns, cut on a safe boundary (never mid tool pair).
    fn turns_to_send(&self) -> Vec<&Turn> {
        let budget = self.max_turns;
        let has_system = self.history.first().map(|t| t.role) == Some(Role::System);
        let start = usize::from(has_system);
        let mut selected: Vec<&Turn> = Vec::new();
        if has_system
            && budget > 0
            && let Some(first) = self.history.first()
        {
            selected.push(first);
        }
        let remaining = budget.saturating_sub(selected.len());
        let tail = self.history.len().saturating_sub(remaining).max(start);
        let cut = snap_forward(&self.history, tail);
        selected.extend(self.history.get(cut..).unwrap_or_default());
        selected
    }

    fn build_request(&self) -> Result<(ChatCompletionsRequest, RequestCrypto, String)> {
        let crypto = RequestCrypto::new();
        let request_id = uuid::Uuid::new_v4().to_string();
        let aad = request_aad(&request_id);

        let mut messages = Vec::new();
        for turn in self.turns_to_send() {
            messages.push(WireMessage {
                role: turn.role.wire_name(),
                content: crypto.encrypt_turn(&aad, &turn.content)?,
                encrypted: true,
            });
        }
        // The official client always terminates the list with the (empty)
        // assistant turn that is being generated.
        messages.push(WireMessage {
            role: Role::Assistant.wire_name(),
            content: crypto.encrypt_turn(&aad, "")?,
            encrypted: true,
        });

        let mut tools: Vec<WireTool> = self
            .server_tools
            .iter()
            .map(|name| WireTool::Server { name: name.clone() })
            .collect();
        tools.extend(self.client_tools.iter().cloned());
        let tool_choice = if tools.is_empty() { None } else { Some("auto") };

        let request = ChatCompletionsRequest {
            model: self.model.clone(),
            messages,
            stream: true,
            stream_options: StreamOptions {
                include_usage: true,
            },
            reasoning_effort: if self.reasoning { "high" } else { "none" },
            tools,
            tool_choice,
            lumo: LumoExtension {
                client_type: "frontend",
                request_key: crypto.encrypted_request_key(&self.lumo_key)?,
                request_id: request_id.clone(),
            },
        };
        Ok((request, crypto, request_id))
    }

    async fn post_chat_once(&self, request: &ChatCompletionsRequest) -> Result<reqwest::Response> {
        let mut req = self
            .http
            .post(format!("{LUMO_BASE_URL}{LUMO_CHAT_ENDPOINT}"))
            .json(request);
        if let Some(s) = &self.session {
            req = req.header("x-pm-uid", &s.uid).bearer_auth(&s.access_token);
        }
        Ok(req.send().await?)
    }

    /// POST the chat request, retrying transient failures with exponential
    /// backoff: connection errors, timeouts, and 502/503/504. Auth (401) and
    /// quota/rate-limit (429) are NOT retried here: 401 is refreshed by the
    /// caller, and retrying a spent quota only wastes time.
    async fn post_chat(&self, request: &ChatCompletionsRequest) -> Result<reqwest::Response> {
        const MAX_ATTEMPTS: u32 = 4;
        let mut delay = std::time::Duration::from_millis(500);
        let mut attempt = 0u32;
        loop {
            attempt = attempt.saturating_add(1);
            match self.post_chat_once(request).await {
                Ok(resp) => {
                    let s = resp.status().as_u16();
                    if matches!(s, 502..=504) && attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(delay).await;
                        delay = delay
                            .saturating_mul(2)
                            .min(std::time::Duration::from_secs(8));
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let transient = e
                        .downcast_ref::<reqwest::Error>()
                        .map(|re| re.is_connect() || re.is_timeout() || re.is_request())
                        .unwrap_or(false);
                    if transient && attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(delay).await;
                        delay = delay
                            .saturating_mul(2)
                            .min(std::time::Duration::from_secs(8));
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Best-effort: the live Lumo web app version (from its version.json), or
    /// None if it can't be fetched. Used for a non-fatal startup warning when
    /// the deployed major version differs from what the protocol was tested on.
    pub async fn lumo_version(&self) -> Option<String> {
        let v: Value = self
            .http
            .get(format!("{LUMO_BASE_URL}/assets/version.json"))
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        v.get("version").and_then(Value::as_str).map(str::to_string)
    }

    /// GET /api/ai/v1/limits: remaining usage for the current session tier.
    pub async fn fetch_limits(&self) -> Result<Value> {
        let mut req = self
            .http
            .get(format!("{LUMO_BASE_URL}{LUMO_LIMITS_ENDPOINT}"));
        if let Some(s) = &self.session {
            req = req.header("x-pm-uid", &s.uid).bearer_auth(&s.access_token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body: Value = resp.json().await.context("limits: invalid JSON")?;
        if !status.is_success() {
            bail!("limits endpoint returned {status}: {body}");
        }
        Ok(body)
    }

    /// Send the current history and stream the reply. Does NOT modify history;
    /// callers append turns based on the response (see agent loop).
    pub async fn generate(
        &mut self,
        mut on_event: impl FnMut(StreamEvent<'_>),
    ) -> Result<ChatResponse> {
        let (request, crypto, request_id) = self.build_request()?;

        let mut response = self.post_chat(&request).await?;

        // On 401, refresh the token once and retry.
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let Some(session) = &self.session
        {
            let refreshed = auth::refresh(session)
                .await
                .context("access token expired and refresh failed; run `lumo login` again")?;
            self.session = Some(refreshed);
            response = self.post_chat(&request).await?;
        }

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("Error")
                        .or_else(|| v.pointer("/error/message"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or(body);
            bail!("Lumo API returned {status}: {detail}");
        }

        let aad = response_aad(&request_id);
        let mut result = ChatResponse::default();
        let mut tool_calls: BTreeMap<usize, ToolCallAccumulator> = BTreeMap::new();
        let mut buffer: Vec<u8> = Vec::new();
        let mut stream = response.bytes_stream();
        let mut done = false;

        'outer: while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("stream read error")?;
            buffer.extend_from_slice(&chunk);
            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buffer.drain(..=pos).collect();
                let line = String::from_utf8_lossy(&line);
                let line = line.trim();
                if line.is_empty() || line.starts_with(':') {
                    continue; // SSE comments: ": queued", ": ingesting"
                }
                let payload = match line.strip_prefix("data:") {
                    Some(rest) => rest.trim(),
                    None if line.starts_with('{') => line,
                    None => continue,
                };
                if payload == "[DONE]" {
                    done = true;
                    break 'outer;
                }
                let Ok(chunk) = serde_json::from_str::<SseChunk>(payload) else {
                    continue;
                };
                self.process_chunk(
                    chunk,
                    &crypto,
                    &aad,
                    &mut result,
                    &mut tool_calls,
                    &mut on_event,
                )?;
                if result.error.is_some() {
                    break 'outer;
                }
            }
        }
        let _ = done;

        // Finalize accumulated tool calls (complete JSON arguments only).
        for (index, acc) in tool_calls {
            if acc.name.is_empty() {
                continue;
            }
            let mut arguments = if acc.arguments.is_empty() {
                "{}".to_string()
            } else {
                acc.arguments
            };
            // Arguments may be U2L ciphertext (base64) instead of JSON.
            if serde_json::from_str::<Value>(&arguments).is_err() {
                match crypto.decrypt_chunk(&aad, arguments.trim()) {
                    Ok(clear) => arguments = clear,
                    Err(_) => continue, // incomplete or undecryptable: drop
                }
            }
            if serde_json::from_str::<Value>(&arguments).is_err() {
                continue;
            }
            let id = if acc.id.is_empty() {
                format!("call_{index}")
            } else {
                acc.id
            };
            // Collapse exact (name, arguments) duplicates. The same call can
            // surface on two channels (`delta.tool_calls` and a decrypted
            // `chat.tool_call`); this mirrors the official web client's
            // `mergePendingClientToolCalls`, which also drops exact dups. The
            // rare cost is that a model emitting two identical
            // calls in one turn runs it once, which is acceptable since identical
            // calls yield identical results.
            if result
                .tool_calls
                .iter()
                .any(|c| c.name == acc.name && c.arguments == arguments)
            {
                continue;
            }
            result.tool_calls.push(PendingToolCall {
                id,
                name: acc.name,
                arguments,
            });
        }

        // Parse and accumulate token usage for this request.
        if let Some(v) = &result.usage {
            let u = Usage::from_value(v);
            let t = &mut self.session_tokens;
            t.0 = t.0.saturating_add(u.prompt);
            t.1 = t.1.saturating_add(u.completion);
            t.2 = t.2.saturating_add(u.total);
            result.usage_tokens = Some(u);
        }

        Ok(result)
    }

    fn process_chunk(
        &self,
        chunk: SseChunk,
        crypto: &RequestCrypto,
        aad: &[u8],
        result: &mut ChatResponse,
        tool_calls: &mut BTreeMap<usize, ToolCallAccumulator>,
        on_event: &mut impl FnMut(StreamEvent<'_>),
    ) -> Result<()> {
        if let Some(model) = &chunk.model
            && !model.is_empty()
        {
            result.served_model = Some(model.clone());
        }
        if let Some(err) = &chunk.error {
            let code = err
                .code
                .as_ref()
                .map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            let msg = err
                .message
                .clone()
                .unwrap_or_else(|| "generation error".into());
            result.error = Some(if code.is_empty() {
                msg
            } else {
                format!("{msg} (code {code})")
            });
            result.error_code = (!code.is_empty()).then_some(code);
            return Ok(());
        }
        if let Some(usage) = chunk.usage {
            result.usage = Some(usage);
        }

        // Server tool activity chunks (chat.tool_call / chat.tool_result).
        match chunk.object.as_deref() {
            Some("chat.tool_call") => {
                if let Some(tc) = &chunk.tool_call {
                    let mut args = tc.arguments.clone().unwrap_or_default();
                    if tc.encrypted.unwrap_or(false)
                        && let Ok(clear) = crypto.decrypt_chunk(aad, args.trim())
                    {
                        args = clear;
                    }
                    // A `chat.tool_call` may describe a CLIENT tool call with
                    // decrypted arguments; register it so it merges with the
                    // delta.tool_calls channel.
                    if let Ok(parsed) =
                        serde_json::from_str::<Value>(if args.is_empty() { "{}" } else { &args })
                    {
                        let is_client_tool = self.client_tools.iter().any(|t| match t {
                            WireTool::Function(f) => f.function.name == tc.name,
                            _ => false,
                        });
                        if is_client_tool {
                            let index = tool_calls.len().saturating_add(10_000);
                            tool_calls.insert(
                                index,
                                ToolCallAccumulator {
                                    id: tc.id.clone(),
                                    name: tc.name.clone(),
                                    arguments: parsed.to_string(),
                                },
                            );
                        } else {
                            on_event(StreamEvent::ServerTool(&tc.name));
                        }
                    }
                }
                return Ok(());
            }
            Some("chat.tool_result") => {
                // Server tool finished; informational only.
                if chunk.tool_result.is_some() {
                    on_event(StreamEvent::ServerTool("result"));
                }
                return Ok(());
            }
            _ => {}
        }

        let Some(choice) = chunk.choices.into_iter().next() else {
            return Ok(());
        };
        if choice.finish_reason.as_deref() == Some("content_filter") {
            result.error = Some("content flagged as harmful".into());
            return Ok(());
        }
        let Some(delta) = choice.delta else {
            return Ok(());
        };

        let encrypted = delta.encrypted.unwrap_or(false);
        let target = delta.target.as_deref().unwrap_or("message");

        if let Some(content) = &delta.content
            && !content.is_empty()
        {
            let text = if encrypted {
                crypto.decrypt_chunk(aad, content)?
            } else {
                content.clone()
            };
            if target == "message" {
                on_event(StreamEvent::Token(&text));
                result.message.push_str(&text);
            }
        }

        let reasoning = delta
            .reasoning_content
            .as_ref()
            .or(delta.reasoning.as_ref());
        if let Some(reasoning) = reasoning
            && !reasoning.is_empty()
        {
            let text = if encrypted {
                crypto.decrypt_chunk(aad, reasoning)?
            } else {
                reasoning.clone()
            };
            on_event(StreamEvent::Reasoning(&text));
            result.reasoning.push_str(&text);
        }

        for tc in delta.tool_calls {
            let index = tc.index.unwrap_or(0);
            let acc = tool_calls.entry(index).or_default();
            if let Some(id) = tc.id {
                acc.id = id;
            }
            if let Some(f) = tc.function {
                if let Some(name) = f.name
                    && !name.is_empty()
                {
                    acc.name = name;
                }
                if let Some(args) = f.arguments {
                    acc.arguments.push_str(&args);
                }
            }
        }
        Ok(())
    }

    // ----- history helpers -----

    pub fn push_turn(&mut self, role: Role, content: impl Into<String>) {
        self.history.push(Turn {
            role,
            content: content.into(),
        });
    }

    /// Record an executed client tool call + its result, mirroring the
    /// official client: a `lumo_tool_call` turn with canonical JSON, then a
    /// `tool` turn with the result content.
    pub fn push_tool_exchange(&mut self, call: &PendingToolCall, result_content: &str) {
        let arguments: Value =
            serde_json::from_str(&call.arguments).unwrap_or(Value::String(call.arguments.clone()));
        let canonical = serde_json::json!({
            "id": call.id,
            "name": call.name,
            "arguments": arguments,
        });
        self.push_turn(Role::ToolCall, canonical.to_string());
        self.push_turn(Role::ToolResult, result_content.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(role: Role, s: &str) -> Turn {
        Turn {
            role,
            content: s.into(),
        }
    }

    #[test]
    fn keeps_system_turn_when_trimming() {
        let mut c = LumoClient::new(None).unwrap();
        c.max_turns = 4;
        c.history.push(turn(Role::System, "sys"));
        for i in 0..10 {
            c.history.push(turn(Role::User, &format!("u{i}")));
            c.history.push(turn(Role::Assistant, &format!("a{i}")));
        }
        let sel = c.turns_to_send();
        assert_eq!(sel.len(), 4);
        assert_eq!(sel[0].content, "sys");
        assert_eq!(sel[1].content, "a8");
        assert_eq!(sel[3].content, "a9");
    }

    #[test]
    fn request_shape() {
        let mut c = LumoClient::new(None).unwrap();
        c.model = MODEL_MAX.into();
        c.push_turn(Role::System, "sys");
        c.push_turn(Role::User, "hello");
        c.client_tools.push(function_tool(
            "read_file",
            "Read a file",
            serde_json::json!({"properties": {"path": {"type": "string"}}, "required": ["path"]}),
        ));
        c.server_tools.push("web_search".into());
        let (req, _, id) = c.build_request().unwrap();
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["model"], "lumo-max");
        assert_eq!(v["stream"], true);
        assert_eq!(v["reasoning_effort"], "none");
        assert_eq!(v["tool_choice"], "auto");
        assert_eq!(v["tools"][0]["name"], "web_search");
        assert_eq!(v["tools"][1]["type"], "function");
        assert_eq!(v["tools"][1]["function"]["name"], "read_file");
        assert_eq!(
            v["tools"][1]["function"]["parameters"]["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(v["lumo"]["client_type"], "frontend");
        assert_eq!(v["lumo"]["request_id"], id);
        // system + user + trailing empty assistant
        let msgs = v["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[2]["role"], "assistant");
        assert_eq!(msgs[2]["encrypted"], true);
    }

    #[test]
    fn tool_exchange_roles() {
        let mut c = LumoClient::new(None).unwrap();
        c.push_tool_exchange(
            &PendingToolCall {
                id: "call_1".into(),
                name: "read_file".into(),
                arguments: "{\"path\": \"a.rs\"}".into(),
            },
            "file contents",
        );
        assert_eq!(c.history.len(), 2);
        assert_eq!(c.history[0].role.wire_name(), "lumo_tool_call");
        let canon: Value = serde_json::from_str(&c.history[0].content).unwrap();
        assert_eq!(canon["name"], "read_file");
        assert_eq!(canon["arguments"]["path"], "a.rs");
        assert_eq!(c.history[1].role.wire_name(), "tool");
        assert_eq!(c.history[1].content, "file contents");
    }
}

#[cfg(test)]
mod trim_tests {
    use super::*;

    #[test]
    fn trim_keeps_system_and_recent() {
        let mut c = LumoClient::new(None).unwrap();
        c.push_turn(Role::System, "sys");
        for i in 0..20 {
            c.push_turn(Role::User, format!("u{i}"));
        }
        assert!(c.trim_oldest(6));
        assert_eq!(c.history.first().unwrap().role, Role::System);
        assert_eq!(c.history.len(), 1 + 6);
        assert_eq!(c.history.last().unwrap().content, "u19");
        // Nothing more to trim below the floor.
        assert!(!c.trim_oldest(6));
    }

    #[test]
    fn send_slice_never_starts_mid_tool_pair() {
        // system, user, assistant, then a tool_call/tool pair, then assistant.
        let mut c = LumoClient::new(None).unwrap();
        c.max_turns = 3; // force a tight cut that would land inside the pair
        c.push_turn(Role::System, "sys");
        c.push_turn(Role::User, "u");
        c.push_turn(Role::Assistant, "a");
        c.push_turn(Role::ToolCall, "{\"name\":\"read_file\"}");
        c.push_turn(Role::ToolResult, "contents");
        c.push_turn(Role::Assistant, "done");
        let sel = c.turns_to_send();
        // First turn is the system prompt; the next must NOT be an orphaned
        // tool result / dangling tool call.
        assert_eq!(sel[0].role, Role::System);
        assert!(!matches!(sel[1].role, Role::ToolResult));
    }

    #[test]
    fn trim_snaps_off_tool_boundary() {
        let mut c = LumoClient::new(None).unwrap();
        c.push_turn(Role::User, "u");
        c.push_turn(Role::Assistant, "a");
        c.push_turn(Role::ToolCall, "call");
        c.push_turn(Role::ToolResult, "res");
        c.push_turn(Role::Assistant, "done");
        // keep_recent=3 would cut at index 2 (a ToolCall); it must snap so the
        // remaining history does not begin with a tool turn.
        c.trim_oldest(3);
        assert!(!matches!(
            c.history.first().unwrap().role,
            Role::ToolCall | Role::ToolResult
        ));
    }
}
