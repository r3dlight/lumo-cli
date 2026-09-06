// SPDX-License-Identifier: GPL-3.0-or-later
//! Constants and wire types for the (unofficial) Lumo API, protocol v2.
//!
//! Reference: Proton's own open-source web client, `packages/lumo-api-client`
//! in <https://github.com/ProtonMail/WebClients>. The generation endpoint is
//! OpenAI-style chat completions with a Lumo extension for U2L encryption:
//! `POST /api/ai/v1/chat/completions` on lumo.proton.me.
//!
//! There is no officially supported public API; Proton may change this at any
//! time.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const LUMO_BASE_URL: &str = "https://lumo.proton.me";
pub const LUMO_CHAT_ENDPOINT: &str = "/api/ai/v1/chat/completions";
pub const LUMO_LIMITS_ENDPOINT: &str = "/api/ai/v1/limits";

/// Lumo web app version this client's protocol was written and tested against.
/// A different MAJOR version at runtime hints the wire format may have changed.
pub const TESTED_LUMO_VERSION: &str = "2.0.2.2";

pub const MODEL_LITE: &str = "lumo-lite";
pub const MODEL_MAX: &str = "lumo-max";
#[allow(dead_code)] // selectable via --model / /model
pub const MODEL_APERTUS: &str = "apertus-15";

/// Lumo's published PGP public key ("Prod Key 0002"), embedded in the official
/// clients. Per-request AES keys are encrypted to this key. If Proton rotates
/// the key, this constant must be updated.
pub const LUMO_PGP_PUBLIC_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEaA9k7RYJKwYBBAHaRw8BAQdABaPA24xROahXs66iuekwPmdOpJbPE1a8A69r
siWP8rfNL1Byb3RvbiBMdW1vIChQcm9kIEtleSAwMDAyKSA8c3VwcG9ydEBwcm90
b24ubWU+wpkEExYKAEEWIQTwMqEWnd/47aco5ZqadMPvYVFKKgUCaA9k7QIbAwUJ
B4TOAAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRCadMPvYVFKKqiVAQD7
JNeudEXTaNMoQMkYjcutNwNAalwbLr5qe6N5rPogDQD/bA5KBWmDlvxVz7If6SBS
7Xzcvk8VMHYkBLKfh+bfUQzOOARoD2TtEgorBgEEAZdVAQUBAQdAnBIJoFt6Pxnp
RAJMHwhdCXaE+lwQFbKgwb6LCUFWvHYDAQgHwn4EGBYKACYWIQTwMqEWnd/47aco
5ZqadMPvYVFKKgUCaA9k7QIbDAUJB4TOAAAKCRCadMPvYVFKKkuRAQChUthLyAcc
UD6UrJkroc6exHIMSR5Vlk4d4L8OeFUWWAEA3ugyE/b/pSQ4WO+fiTkHN2ZeKlyj
dZMbxO6yWPA5uQk=
=h/mc
-----END PGP PUBLIC KEY BLOCK-----";

/// AAD bound to every encrypted turn of a request.
pub fn request_aad(request_id: &str) -> Vec<u8> {
    format!("lumo.request.{request_id}.turn").into_bytes()
}

/// AAD bound to every encrypted response chunk.
pub fn response_aad(request_id: &str) -> Vec<u8> {
    format!("lumo.response.{request_id}.chunk").into_bytes()
}

/// Local conversation roles. On the wire, `ToolCall` becomes the non-standard
/// `lumo_tool_call` role (canonical `{"id","name","arguments"}` JSON in
/// `content`, so it can be U2L-encrypted) and `ToolResult` becomes `tool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    System,
    ToolCall,
    ToolResult,
}

impl Role {
    pub fn wire_name(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::System => "system",
            Role::ToolCall => "lumo_tool_call",
            Role::ToolResult => "tool",
        }
    }
}

/// One message of the chat-completions request.
#[derive(Debug, Serialize)]
pub struct WireMessage {
    pub role: &'static str,
    /// U2L-encrypted content: base64(iv\[12\] || ciphertext || gcm_tag\[16\]).
    pub content: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub encrypted: bool,
}

/// A tool entry: either a server-side tool (`{"name": "web_search"}`) or an
/// OpenAI-shaped client function tool.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum WireTool {
    Server { name: String },
    Function(FunctionTool),
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionTool {
    #[serde(rename = "type")]
    pub kind: &'static str, // "function"
    pub function: FunctionDef,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionDef {
    pub name: String,
    pub description: String,
    /// JSON schema; the official client normalizes in `type: "object"`,
    /// `properties` and a `$schema` of draft 2020-12.
    pub parameters: Value,
}

pub fn function_tool(name: &str, description: &str, mut parameters: Value) -> WireTool {
    if let Some(obj) = parameters.as_object_mut() {
        obj.entry("type").or_insert("object".into());
        obj.entry("$schema")
            .or_insert("https://json-schema.org/draft/2020-12/schema".into());
        obj.entry("properties")
            .or_insert(Value::Object(Default::default()));
    }
    WireTool::Function(FunctionTool {
        kind: "function",
        function: FunctionDef {
            name: name.to_string(),
            description: description.to_string(),
            parameters,
        },
    })
}

#[derive(Debug, Serialize)]
pub struct StreamOptions {
    pub include_usage: bool,
}

/// Lumo extension carrying the U2L encryption parameters.
#[derive(Debug, Serialize)]
pub struct LumoExtension {
    pub client_type: &'static str, // "frontend"
    pub request_key: String,
    pub request_id: String,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<WireMessage>,
    pub stream: bool,
    pub stream_options: StreamOptions,
    /// "none" or "high"
    pub reasoning_effort: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<WireTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<&'static str>, // "auto"
    pub lumo: LumoExtension,
}

// ---------- streaming response types ----------

#[derive(Debug, Deserialize)]
pub struct SseChunk {
    #[serde(default)]
    pub object: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub choices: Vec<SseChoice>,
    #[serde(default)]
    pub usage: Option<Value>,
    #[serde(default)]
    pub error: Option<SseError>,
    /// `chat.tool_call` chunks (server-executed tools, informational).
    #[serde(default)]
    pub tool_call: Option<ServerToolCall>,
    /// `chat.tool_result` chunks (server-executed tools, informational).
    #[serde(default)]
    pub tool_result: Option<ServerToolResult>,
}

#[derive(Debug, Deserialize)]
pub struct SseError {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub code: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct SseChoice {
    #[serde(default)]
    pub delta: Option<SseDelta>,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SseDelta {
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub reasoning_content: Option<String>,
    #[serde(default)]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub encrypted: Option<bool>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<SseToolCallDelta>,
}

#[derive(Debug, Deserialize)]
pub struct SseToolCallDelta {
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub function: Option<SseFunctionDelta>,
}

#[derive(Debug, Deserialize)]
pub struct SseFunctionDelta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServerToolCall {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub arguments: Option<String>,
    #[serde(default)]
    pub encrypted: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // parsed for completeness; currently informational only
pub struct ServerToolResult {
    pub call_id: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub encrypted: Option<bool>,
}
