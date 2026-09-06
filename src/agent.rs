// SPDX-License-Identifier: GPL-3.0-or-later
//! The agentic loop: system prompt, native tool calling, execute/feed-back.
//!
//! Lumo's chat-completions endpoint supports client function tools (this is
//! how Lumo Desktop's connectors work): the model emits `tool_calls`, the CLI
//! executes them locally and appends `lumo_tool_call` + `tool` turns, then
//! resumes generation. A text fallback also parses ```tool fenced blocks in
//! case a model emits the call as prose.

use anyhow::Result;

use crate::client::{LumoClient, PendingToolCall, StreamEvent};
use crate::protocol::{Role, WireTool, function_tool};
use crate::tools::{self, PendingAction, ToolCall};

pub const MAX_AGENT_ROUNDS: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Yes,
    /// Approve and stop asking for this kind of action for the session.
    YesAlways,
    No,
}

/// How the agent talks to the terminal UI.
pub trait Interaction {
    /// A streamed chunk of assistant text.
    fn on_token(&mut self, text: &str);
    /// A streamed chunk of reasoning ("thinking") text.
    fn on_reasoning(&mut self, text: &str);
    /// Called when a complete assistant message finished streaming.
    fn on_message_end(&mut self);
    /// Token usage reported for the request that just completed.
    fn on_usage(&mut self, usage: &crate::client::Usage);
    /// A server-side tool (web_search, …) is running remotely.
    fn on_server_tool(&mut self, name: &str);
    /// A client tool call is about to be evaluated.
    fn on_tool_start(&mut self, call: &ToolCall);
    /// Short summary after a tool ran (or failed).
    fn on_tool_result(&mut self, summary: &str, is_error: bool);
    /// Ask the user to approve a side-effecting action.
    fn approve(&mut self, action: &PendingAction) -> Result<Approval>;
}

/// The local tools advertised to the model.
pub fn client_tool_definitions() -> Vec<WireTool> {
    vec![
        function_tool(
            "list_dir",
            "List files and directories recursively (depth 3) under a path. \
             Use this first to discover the project layout.",
            serde_json::json!({
                "properties": {
                    "path": {"type": "string", "description": "Directory to list, default '.'"}
                },
                "required": []
            }),
        ),
        function_tool(
            "read_file",
            "Read a text file, returning numbered lines. Large files are paginated \
             with offset/limit.",
            serde_json::json!({
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "offset": {"type": "integer", "description": "First line to read (1-based), default 1"},
                    "limit": {"type": "integer", "description": "Max lines to return, default 400"}
                },
                "required": ["path"]
            }),
        ),
        function_tool(
            "search",
            "Regex search across files (ripgrep). Returns matching lines with file:line prefixes.",
            serde_json::json!({
                "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern"},
                    "path": {"type": "string", "description": "File or directory to search, default '.'"}
                },
                "required": ["pattern"]
            }),
        ),
        function_tool(
            "write_file",
            "Create or overwrite a file with the given content. Prefer edit_file for \
             modifying existing files.",
            serde_json::json!({
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string", "description": "Full file content"}
                },
                "required": ["path", "content"]
            }),
        ),
        function_tool(
            "edit_file",
            "Replace text in an existing file. `old` must match EXACTLY ONE location \
             in the file; include enough surrounding lines to make it unique. \
             Read the file first.",
            serde_json::json!({
                "properties": {
                    "path": {"type": "string"},
                    "old": {"type": "string", "description": "Exact text to replace (must be unique in the file)"},
                    "new": {"type": "string", "description": "Replacement text"}
                },
                "required": ["path", "old", "new"]
            }),
        ),
        function_tool(
            "bash",
            "Run a shell command in the working directory (sh -c, 120s timeout). \
             Returns stdout/stderr and exit code.",
            serde_json::json!({
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }),
        ),
    ]
}

pub fn system_prompt(agent_mode: bool, dry_run: bool, instructions: Option<&str>) -> String {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());
    let os = std::env::consts::OS;
    // Project instructions come from an approved .lumo-config/instructions.md.
    // They are user-approved guidance, not a channel to override these rules.
    let project = match instructions {
        Some(text) if !text.trim().is_empty() => format!(
            "\n\nProject instructions (from .lumo-config, approved by the user):\n{}",
            text.trim()
        ),
        _ => String::new(),
    };
    if !agent_mode {
        return format!(
            "You are Lumo, running inside a terminal chat client (lumo-cli) on {os}, \
             current directory {cwd}. Be concise; format answers as plain text or \
             markdown suitable for a terminal.{project}"
        );
    }
    let dry = if dry_run {
        "\n- DRY-RUN MODE: write_file, edit_file and bash do NOT run; their results say \
         \"[dry-run] ... not executed\". Treat those as not done. In your final summary, \
         describe what WOULD happen; never claim you created, changed, ran or deleted anything."
    } else {
        ""
    };
    format!(
        "You are Lumo Code, a coding agent running in the user's terminal (lumo-cli).\n\
         Environment: OS {os}, working directory {cwd}.\n\
         \n\
         You have function tools to inspect and modify the user's files and run shell \
         commands. Guidelines:\n\
         - Explore before acting: list_dir, search and read_file to understand the code.\n\
         - Always read a file before editing it. Prefer edit_file over write_file for \
           existing files.\n\
         - Tool results come back as tool messages; never fabricate them.\n\
         - Make focused, minimal changes; verify with bash (build/tests) when useful.\n\
         - When the task is complete or impossible, answer normally with a brief summary \
           in the language the user speaks. Keep answers terminal-friendly.{dry}{project}"
    )
}

/// Fallback: find a fenced code block (or whole-message JSON) that parses as a
/// `{\"tool\": ..., \"args\": ...}` call, for models that emit the call as text.
pub fn parse_text_tool_call(message: &str) -> Option<ToolCall> {
    let trimmed = message.trim();
    if trimmed.starts_with('{')
        && let Ok(call) = serde_json::from_str::<ToolCall>(trimmed)
    {
        return Some(call);
    }
    const FENCE: &str = "```";
    let mut search_from = 0usize;
    // Every index below comes from `find` on `message` itself, so it sits on a
    // char boundary; `get` turns any wrong index into a `None`, never a panic.
    // `search_from` strictly grows on every path, so the loop terminates.
    while let Some(rest) = message.get(search_from..)
        && let Some(rel) = rest.find(FENCE)
    {
        let after_fence = search_from.saturating_add(rel).saturating_add(FENCE.len());
        // A malformed fence (no newline, or no closing ```) must not abort the
        // whole scan: skip past this ``` and keep looking for later blocks.
        let Some(nl) = message.get(after_fence..).and_then(|s| s.find('\n')) else {
            search_from = after_fence;
            continue;
        };
        let body_start = after_fence.saturating_add(nl).saturating_add(1);
        let Some(body_len) = message.get(body_start..).and_then(|s| s.find(FENCE)) else {
            search_from = after_fence;
            continue;
        };
        let body_end = body_start.saturating_add(body_len);
        if let Some(body) = message.get(body_start..body_end)
            && let Ok(call) = serde_json::from_str::<ToolCall>(body.trim())
        {
            return Some(call);
        }
        search_from = body_end.saturating_add(FENCE.len());
    }
    None
}

fn to_tool_call(pending: &PendingToolCall) -> ToolCall {
    ToolCall {
        tool: pending.name.clone(),
        args: serde_json::from_str(&pending.arguments).unwrap_or(serde_json::Value::Null),
    }
}

/// Write one audit entry for a side-effecting action (read-only tools are not
/// recorded). The diff / command is the accountability payload.
fn audit_action(audit: &crate::audit::AuditLog, action: &PendingAction, ok: bool) {
    match action {
        PendingAction::ReadOnly => {}
        PendingAction::WriteFile { path, diff } => {
            audit.record("write", &path.display().to_string(), ok, diff)
        }
        PendingAction::Shell { command } => audit.record("bash", command, ok, ""),
    }
}

pub struct AgentOptions<'a> {
    /// Skip all approval prompts (dangerous).
    pub auto_approve: bool,
    /// Active Landlock sandbox for tool subprocesses and file confinement.
    pub sandbox: Option<&'a crate::sandbox::Sandbox>,
    /// Show side-effecting actions without executing them.
    pub dry_run: bool,
    /// Append-only audit trail of the actions performed.
    pub audit: Option<&'a crate::audit::AuditLog>,
}

/// Run one user request through the agent loop until the model stops calling
/// tools, the round cap is reached, or the user aborts.
pub async fn run_turn(
    client: &mut LumoClient,
    ui: &mut impl Interaction,
    user_input: &str,
    opts: &AgentOptions<'_>,
    always_approved: &mut AlwaysApproved,
) -> Result<()> {
    // Ensure the system prompt is the first turn and tools are advertised.
    if client.history.first().map(|t| t.role) != Some(Role::System) {
        let sys = system_prompt(true, opts.dry_run, client.project_instructions.as_deref());
        client.history.insert(
            0,
            crate::client::Turn {
                role: Role::System,
                content: sys,
            },
        );
    }
    if client.client_tools.is_empty() {
        client.client_tools = client_tool_definitions();
    }

    client.push_turn(Role::User, user_input);

    for round in 0..MAX_AGENT_ROUNDS {
        // Generate, retrying with a trimmed history if the server reports the
        // context is too long.
        let response = loop {
            let r = client
                .generate(|event| match event {
                    StreamEvent::Token(t) => ui.on_token(t),
                    StreamEvent::Reasoning(t) => ui.on_reasoning(t),
                    StreamEvent::ServerTool(name) => ui.on_server_tool(name),
                })
                .await?;
            if r.error_code.as_deref() == Some("context_length_exceeded") && client.trim_oldest(6) {
                ui.on_message_end();
                ui.on_tool_result("context too long; trimmed old turns, retrying", true);
                continue;
            }
            break r;
        };
        ui.on_message_end();
        if let Some(u) = &response.usage_tokens {
            ui.on_usage(u);
        }

        if let Some(err) = &response.error {
            ui.on_tool_result(&format!("generation ended abnormally: {err}"), true);
            // Keep the partial message in history so context isn't lost.
            if !response.message.is_empty() {
                client.push_turn(Role::Assistant, response.message.clone());
            }
            return Ok(());
        }

        if !response.message.trim().is_empty() {
            client.push_turn(Role::Assistant, response.message.clone());
        }

        // Native tool calls, or the text-protocol fallback.
        let mut calls: Vec<PendingToolCall> = response.tool_calls.clone();
        if calls.is_empty()
            && let Some(text_call) = parse_text_tool_call(&response.message)
        {
            let known = client.client_tools.iter().any(|t| match t {
                WireTool::Function(f) => f.function.name == text_call.tool,
                _ => false,
            });
            if known {
                calls.push(PendingToolCall {
                    id: format!("call_text_{round}"),
                    name: text_call.tool.clone(),
                    arguments: text_call.args.to_string(),
                });
            }
        }

        if calls.is_empty() {
            return Ok(()); // normal reply: turn finished
        }

        for pending in &calls {
            let call = to_tool_call(pending);
            ui.on_tool_start(&call);

            let result_content = match tools::plan(&call, opts.sandbox) {
                Err(e) => {
                    ui.on_tool_result(&format!("invalid tool call: {e}"), true);
                    format!("ERROR: invalid tool call: {e}")
                }
                Ok(planned) => {
                    // In dry-run nothing executes, so approval is moot.
                    let approved = if opts.dry_run
                        || opts.auto_approve
                        || matches!(planned.approval, PendingAction::ReadOnly)
                        || always_approved.covers(&planned.approval)
                    {
                        Approval::Yes
                    } else {
                        ui.approve(&planned.approval)?
                    };
                    match approved {
                        Approval::No => {
                            ui.on_tool_result("denied by user", true);
                            "DENIED: the user declined this action. Ask them how to \
                             proceed or try another approach."
                                .to_string()
                        }
                        yes => {
                            if yes == Approval::YesAlways {
                                always_approved.remember(&planned.approval);
                            }
                            let result = tools::execute(&planned, opts.sandbox, opts.dry_run).await;
                            // Record actually-executed side effects (not dry-run).
                            if let (Some(audit), false) = (opts.audit, opts.dry_run) {
                                audit_action(audit, &planned.approval, result.is_ok());
                            }
                            match result {
                                Ok(output) => {
                                    ui.on_tool_result(&summarize(&call, &output), false);
                                    output
                                }
                                Err(e) => {
                                    ui.on_tool_result(&format!("{e}"), true);
                                    format!("ERROR: {e}")
                                }
                            }
                        }
                    }
                }
            };
            client.push_tool_exchange(pending, &result_content);
        }

        if round.saturating_add(1) == MAX_AGENT_ROUNDS {
            ui.on_tool_result(
                &format!("stopped after {MAX_AGENT_ROUNDS} tool rounds (safety cap)"),
                true,
            );
        }
    }
    Ok(())
}

fn summarize(call: &ToolCall, output: &str) -> String {
    let lines = output.lines().count();
    match call.tool.as_str() {
        "read_file" | "list_dir" | "search" => format!("{} → {lines} lines", call.tool),
        _ => {
            let first = output.lines().next().unwrap_or("");
            let cut: String = first.chars().take(100).collect();
            format!("{} → {}", call.tool, cut)
        }
    }
}

/// Remembers "always allow" grants for the session.
#[derive(Default)]
pub struct AlwaysApproved {
    writes: bool,
    shell: bool,
}

impl AlwaysApproved {
    fn covers(&self, action: &PendingAction) -> bool {
        match action {
            PendingAction::ReadOnly => true,
            PendingAction::WriteFile { .. } => self.writes,
            PendingAction::Shell { .. } => self.shell,
        }
    }
    fn remember(&mut self, action: &PendingAction) {
        match action {
            PendingAction::ReadOnly => {}
            PendingAction::WriteFile { .. } => self.writes = true,
            PendingAction::Shell { .. } => self.shell = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tool_fence() {
        let msg = "I'll read the file.\n```tool\n{\"tool\": \"read_file\", \"args\": {\"path\": \"a.rs\"}}\n```";
        let call = parse_text_tool_call(msg).unwrap();
        assert_eq!(call.tool, "read_file");
    }

    #[test]
    fn parses_bare_json_message() {
        let msg = "{\"tool\": \"list_dir\", \"args\": {}}";
        assert_eq!(parse_text_tool_call(msg).unwrap().tool, "list_dir");
    }

    #[test]
    fn plain_text_has_no_call() {
        let msg = "Voilà, c'est terminé:\n```rust\nfn main() {}\n```";
        assert!(parse_text_tool_call(msg).is_none());
    }

    #[test]
    fn skips_non_tool_fence_then_finds_tool() {
        let msg = "```rust\nfn x() {}\n```\nok\n```tool\n{\"tool\": \"search\", \"args\": {\"pattern\": \"x\"}}\n```";
        assert_eq!(parse_text_tool_call(msg).unwrap().tool, "search");
    }

    #[test]
    fn malformed_fence_is_handled_gracefully() {
        // A fence opened but never closed must not panic or hang, only yield None.
        assert!(parse_text_tool_call("```tool\n{\"tool\": \"bash\"").is_none());
        // A ``` with no following newline at all must not abort the scan.
        assert!(parse_text_tool_call("no fence here ```").is_none());
        // An empty/non-tool fence before a valid tool fence: still found.
        let msg = "```\n\n```\n```tool\n{\"tool\": \"list_dir\", \"args\": {}}\n```";
        assert_eq!(parse_text_tool_call(msg).unwrap().tool, "list_dir");
    }

    #[test]
    fn tool_definitions_have_schemas() {
        let tools = client_tool_definitions();
        assert_eq!(tools.len(), 6);
        for t in &tools {
            let v = serde_json::to_value(t).unwrap();
            assert_eq!(v["type"], "function");
            assert_eq!(v["function"]["parameters"]["type"], "object");
        }
    }
}
