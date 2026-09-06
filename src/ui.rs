// SPDX-License-Identifier: GPL-3.0-or-later
//! Terminal UI: REPL, streaming rendering, approval prompts.

use std::io::Write as _;

use anyhow::Result;
use owo_colors::OwoColorize;

use crate::agent::{self, AgentOptions, AlwaysApproved, Approval, Interaction};
use crate::client::{LumoClient, StreamEvent};
use crate::protocol::Role;
use crate::tools::{PendingAction, ToolCall};

pub struct TermUi {
    streamed_anything: bool,
    in_reasoning: bool,
}

impl TermUi {
    pub fn new() -> Self {
        Self {
            streamed_anything: false,
            in_reasoning: false,
        }
    }
}

fn flush() {
    let _ = std::io::stdout().flush();
}

fn read_line_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

impl Interaction for TermUi {
    fn on_token(&mut self, text: &str) {
        if self.in_reasoning {
            println!();
            self.in_reasoning = false;
        }
        if !self.streamed_anything {
            println!();
            self.streamed_anything = true;
        }
        print!("{text}");
        flush();
    }

    fn on_reasoning(&mut self, text: &str) {
        if !self.streamed_anything {
            println!();
            self.streamed_anything = true;
        }
        self.in_reasoning = true;
        print!("{}", text.dimmed());
        flush();
    }

    fn on_message_end(&mut self) {
        if self.streamed_anything {
            println!();
        }
        self.streamed_anything = false;
        self.in_reasoning = false;
    }

    fn on_usage(&mut self, usage: &crate::client::Usage) {
        println!("{}", format!("· {usage} tokens").dimmed());
    }

    fn on_server_tool(&mut self, name: &str) {
        if name != "result" {
            println!(
                "{} {}",
                "🌐".yellow(),
                format!("server tool: {name}").dimmed()
            );
        }
    }

    fn on_tool_start(&mut self, call: &ToolCall) {
        // A curious cat pawing at the task.
        println!(
            "{} {}",
            "🐾".yellow(),
            format!(
                "{} {} {}",
                "=^.^=".yellow().bold(),
                call.tool,
                compact_args(call)
            )
            .dimmed()
        );
    }

    fn on_tool_result(&mut self, summary: &str, is_error: bool) {
        if is_error {
            // startled cat
            println!("{} {}", "🙀".red(), summary.red());
        } else {
            // happy cat
            println!("{} {}", "😺".green(), summary.dimmed());
        }
    }

    fn approve(&mut self, action: &PendingAction) -> Result<Approval> {
        match action {
            PendingAction::ReadOnly => return Ok(Approval::Yes),
            PendingAction::WriteFile { path, diff } => {
                println!();
                println!(
                    "{}",
                    format!("Proposed change to {}:", path.display()).bold()
                );
                for line in diff.lines() {
                    if line.starts_with('+') && !line.starts_with("+++") {
                        println!("{}", line.green());
                    } else if line.starts_with('-') && !line.starts_with("---") {
                        println!("{}", line.red());
                    } else if line.starts_with("@@") {
                        println!("{}", line.cyan());
                    } else {
                        println!("{}", line.dimmed());
                    }
                }
            }
            PendingAction::Shell { command } => {
                println!();
                println!("{}", "Proposed shell command:".bold());
                println!("  {}", command.yellow());
            }
        }
        loop {
            print!(
                "{}",
                "Allow? [y]es / [a]lways for this session / [n]o: ".bold()
            );
            flush();
            match read_line_stdin()?.to_lowercase().as_str() {
                "y" | "yes" => return Ok(Approval::Yes),
                "a" | "always" => return Ok(Approval::YesAlways),
                "n" | "no" | "" => return Ok(Approval::No),
                _ => continue,
            }
        }
    }
}

fn compact_args(call: &ToolCall) -> String {
    let s = call.args.to_string();
    let mut out: String = s.chars().take(120).collect();
    if out.chars().count() < s.chars().count() {
        out.push('…');
    }
    out
}

fn history_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("lumo-cli").join("history.txt"))
}

pub struct ReplConfig {
    pub agent_mode: bool,
    pub auto_approve: bool,
    pub dry_run: bool,
    pub commit: bool,
}

/// Commit the working tree in the project's git repo, if there is one and it has
/// changes. `instruction` seeds a conservative message. User-facing helper for
/// `--commit` and `/commit`.
pub fn maybe_commit(instruction: &str) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let Some(root) = crate::git::repo_root(&cwd) else {
        println!("{} not a git repository; skipping commit", "note:".dimmed());
        return;
    };
    match crate::git::has_changes(&root) {
        Ok(false) => println!("{} nothing to commit", "note:".dimmed()),
        Ok(true) => {
            let msg = crate::git::derive_message(instruction, &root);
            match crate::git::commit_all(&root, &msg) {
                Ok(summary) => println!("{} {summary}", "committed:".green().bold()),
                Err(e) => println!("{} {e:#}", "commit failed:".red()),
            }
        }
        Err(e) => println!("{} {e:#}", "git error:".red()),
    }
}

/// Plain chat exchange (no local tools): push turns and stream the reply.
pub async fn chat_send(client: &mut LumoClient, ui: &mut TermUi, input: &str) -> Result<()> {
    if client.history.first().map(|t| t.role) != Some(Role::System) {
        let sys = agent::system_prompt(false, false, client.project_instructions.as_deref());
        client.history.insert(
            0,
            crate::client::Turn {
                role: Role::System,
                content: sys,
            },
        );
    }
    client.push_turn(Role::User, input);
    let resp = client
        .generate(|event| match event {
            StreamEvent::Token(t) => ui.on_token(t),
            StreamEvent::Reasoning(t) => ui.on_reasoning(t),
            StreamEvent::ServerTool(name) => ui.on_server_tool(name),
        })
        .await?;
    ui.on_message_end();
    if let Some(u) = &resp.usage_tokens {
        ui.on_usage(u);
    }
    if !resp.message.trim().is_empty() {
        client.push_turn(Role::Assistant, resp.message.clone());
    }
    if let Some(err) = resp.error {
        println!(
            "{} {}",
            "✗".red().bold(),
            format!("server status: {err}").red()
        );
    }
    Ok(())
}

pub async fn run_repl(
    mut client: LumoClient,
    mut cfg: ReplConfig,
    sandbox: Option<crate::sandbox::Sandbox>,
    audit: Option<crate::audit::AuditLog>,
    mut pending_attach: Option<String>,
) -> Result<()> {
    print_banner(&client, &cfg, sandbox.as_ref());
    if pending_attach.is_some() {
        println!(
            "{}",
            "attachments loaded; they'll accompany your next message".dimmed()
        );
    }

    let mut rl = rustyline::DefaultEditor::new()?;
    if let Some(p) = history_path() {
        let _ = rl.load_history(&p);
    }

    let mut ui = TermUi::new();
    let mut always = AlwaysApproved::default();

    loop {
        let line = match rl.readline(&format!("{} ", "lumo ❯".magenta().bold())) {
            Ok(l) => l,
            Err(rustyline::error::ReadlineError::Interrupted) => continue,
            Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => return Err(e.into()),
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(input);

        if let Some(cmd) = input.strip_prefix('/') {
            match handle_slash(
                cmd,
                &mut client,
                &mut cfg,
                audit.as_ref(),
                &mut pending_attach,
            )
            .await?
            {
                SlashResult::Continue => continue,
                SlashResult::Quit => break,
            }
        }

        // Fold any pending attachments into this message, then consume them.
        // `input` stays the original text (used for the commit message); the
        // composed form (attachments + input) is what the model receives.
        let composed = crate::attach::prepend(&pending_attach, input);
        pending_attach = None;

        let result = if cfg.agent_mode {
            agent::run_turn(
                &mut client,
                &mut ui,
                composed.as_str(),
                &AgentOptions {
                    auto_approve: cfg.auto_approve,
                    sandbox: sandbox.as_ref(),
                    dry_run: cfg.dry_run,
                    audit: audit.as_ref(),
                },
                &mut always,
            )
            .await
        } else {
            chat_send(&mut client, &mut ui, composed.as_str()).await
        };
        if let Err(e) = result {
            println!("{} {e:#}", "error:".red().bold());
        } else if cfg.agent_mode && cfg.commit && !cfg.dry_run {
            maybe_commit(input);
        }
    }

    if let Some(p) = history_path() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = rl.save_history(&p);
    }
    println!("{}", "=^.^=  bye! *purr*".magenta());
    Ok(())
}

/// The lumo-cli mascot: a little cat (Lumo, "chat" in French).
const CAT: &str = r"
 /\_/\   lumo-cli
( o.o )  ~ your terminal cat ~
 > ^ <
";

fn print_banner(client: &LumoClient, cfg: &ReplConfig, sandbox: Option<&crate::sandbox::Sandbox>) {
    println!("{}", CAT.magenta());
    println!(
        "{}",
        "lumo-cli, an unofficial Lumo coding agent".magenta().bold()
    );
    match &client.session {
        Some(s) => println!(
            "  account: {}   mode: {}   model: {}",
            s.username.green(),
            if cfg.agent_mode { "agent" } else { "chat" },
            client.model
        ),
        None => println!(
            "  account: {}   mode: {}   model: {}",
            "none (run `lumo login`)".yellow(),
            if cfg.agent_mode { "agent" } else { "chat" },
            client.model
        ),
    }
    println!(
        "  cwd: {}",
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    );
    if client.model == crate::protocol::MODEL_MAX {
        println!(
            "  {}",
            "⚠ lumo-max is premium (daily quota); agent mode spends 1 request per tool step"
                .yellow()
        );
    }
    match sandbox {
        Some(sb) => println!(
            "  {} tool commands confined to project (Landlock, profile {})",
            "🔒 sandbox:".green(),
            sb.profile_name()
        ),
        None if cfg.agent_mode => {
            println!(
                "  {} tool commands run unconfined",
                "⚠ no sandbox:".yellow()
            )
        }
        None => {}
    }
    if cfg.dry_run {
        println!(
            "  {} writes and shell commands are shown but NOT executed",
            "🅳 dry-run:".cyan()
        );
    }
    println!("  type {} for commands, Ctrl-D to quit", "/help".bold());
    println!();
}

enum SlashResult {
    Continue,
    Quit,
}

async fn handle_slash(
    cmd: &str,
    client: &mut LumoClient,
    cfg: &mut ReplConfig,
    audit: Option<&crate::audit::AuditLog>,
    pending_attach: &mut Option<String>,
) -> Result<SlashResult> {
    let mut parts = cmd.split_whitespace();
    match parts.next().unwrap_or("") {
        "help" => {
            println!("  /clear           reset conversation history");
            println!("  /chat            toggle agent mode ↔ plain chat");
            println!(
                "  /model [name]    show or set model (lumo-lite = default; lumo-max = premium/quota; apertus-15)"
            );
            println!("  /think           toggle reasoning mode");
            println!("  /yolo            toggle auto-approve for writes & shell commands");
            println!("  /dry             toggle dry-run (show actions without executing)");
            println!(
                "  /commit [msg]    git add -A && commit the working tree in the project repo"
            );
            println!("  /attach <path>   attach a text file as context for your next message");
            println!("  /audit           show where this session's action log is written");
            println!(
                "  /tools [t]       toggle a Lumo server tool (web_search, weather, stock, cryptocurrency)"
            );
            println!("  /limits          show remaining usage for your plan");
            println!("  /status          show session / mode info");
            println!("  /quit            exit");
        }
        "commit" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            let cwd = std::env::current_dir().unwrap_or_default();
            match crate::git::repo_root(&cwd) {
                None => println!("  not a git repository"),
                Some(root) => {
                    let msg = if rest.trim().is_empty() {
                        crate::git::derive_message("update", &root)
                    } else {
                        rest
                    };
                    match crate::git::commit_all(&root, &msg) {
                        Ok(summary) => println!("  {} {summary}", "committed:".green().bold()),
                        Err(e) => println!("  {} {e:#}", "commit failed:".red()),
                    }
                }
            }
        }
        "audit" => match audit {
            Some(a) => println!("  action log: {}", a.path().display()),
            None => println!("  auditing is not active (agent mode only)"),
        },
        "attach" => {
            let files: Vec<String> = parts.map(str::to_string).collect();
            if files.is_empty() {
                println!("  usage: /attach <path> [path…]");
            } else {
                match crate::attach::build_block(&files) {
                    Ok(Some(block)) => {
                        // Merge with anything already pending.
                        *pending_attach = Some(match pending_attach.take() {
                            Some(prev) => format!("{prev}\n{block}"),
                            None => block,
                        });
                        println!("  attached {} file(s) for your next message", files.len());
                    }
                    Ok(None) => {}
                    Err(e) => println!("  {} {e:#}", "attach failed:".red()),
                }
            }
        }
        "clear" => {
            client.clear_history();
            println!("  history cleared");
        }
        "chat" => {
            cfg.agent_mode = !cfg.agent_mode;
            client.clear_history(); // system prompt differs between modes
            println!(
                "  mode: {} (history cleared)",
                if cfg.agent_mode { "agent" } else { "chat" }
            );
        }
        "model" => match parts.next() {
            None => println!("  model: {}", client.model),
            Some(m) => {
                client.model = m.to_string();
                println!("  model set to {m}");
            }
        },
        "think" => {
            client.reasoning = !client.reasoning;
            println!(
                "  reasoning: {}",
                if client.reasoning { "on" } else { "off" }
            );
        }
        "yolo" => {
            cfg.auto_approve = !cfg.auto_approve;
            println!(
                "  auto-approve: {}",
                if cfg.auto_approve {
                    "ON: writes and shell commands run without confirmation"
                        .red()
                        .to_string()
                } else {
                    "off".green().to_string()
                }
            );
        }
        "dry" | "dry-run" => {
            cfg.dry_run = !cfg.dry_run;
            println!(
                "  dry-run: {}",
                if cfg.dry_run {
                    "ON: writes and shell commands are shown but not executed"
                        .cyan()
                        .to_string()
                } else {
                    "off".green().to_string()
                }
            );
        }
        "tools" => match parts.next() {
            None => println!(
                "  enabled server tools: {}",
                if client.server_tools.is_empty() {
                    "(none)".to_string()
                } else {
                    client.server_tools.join(", ")
                }
            ),
            Some(t) => {
                let t = t.to_string();
                if let Some(pos) = client.server_tools.iter().position(|x| *x == t) {
                    client.server_tools.remove(pos);
                    println!("  disabled: {t}");
                } else {
                    client.server_tools.push(t.clone());
                    println!("  enabled: {t}");
                }
            }
        },
        "limits" => match client.fetch_limits().await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
            Err(e) => println!("  {} {e:#}", "error:".red()),
        },
        "status" => {
            match &client.session {
                Some(s) => println!(
                    "  logged in as {} (uid {}…)",
                    s.username,
                    s.uid.chars().take(8).collect::<String>()
                ),
                None => println!("  not logged in"),
            }
            println!("  mode: {}", if cfg.agent_mode { "agent" } else { "chat" });
            println!(
                "  model: {}   reasoning: {}",
                client.model, client.reasoning
            );
            println!("  history: {} turns", client.history.len());
            println!("  session usage: {} tokens", client.session_usage());
        }
        "quit" | "exit" | "q" => return Ok(SlashResult::Quit),
        other => println!("  unknown command: /{other} (try /help)"),
    }
    Ok(SlashResult::Continue)
}
