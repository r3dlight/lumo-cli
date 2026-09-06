// SPDX-License-Identifier: GPL-3.0-or-later
//! lumo-cli, an unofficial Claude Code-style terminal agent for Proton Lumo.

// ANSSI Rust guide (MEM/LANG): no `unsafe` anywhere in this crate.
#![forbid(unsafe_code)]
// The restriction lints below are enforced crate-wide from Cargo.toml
// (`[lints.clippy]`); tests may use them freely, since a failing test is the point.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::arithmetic_side_effects,
        clippy::panic
    )
)]

mod agent;
mod attach;
mod audit;
mod auth;
mod client;
mod crypto;
mod git;
mod keys;
mod projconfig;
mod protocol;
mod sandbox;
mod serve;
mod tools;
mod ui;

/// Default for `--max-turns`; also lets the project config's value apply only
/// when the user did not pass the flag.
const DEFAULT_MAX_TURNS: usize = 40;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;

use crate::client::LumoClient;
use crate::sandbox::Sandbox;

#[derive(Parser)]
#[command(
    name = "lumo",
    version,
    about = "Unofficial terminal coding agent for Proton Lumo (Claude Code style)",
    long_about = "Interactive terminal agent for Proton Lumo with end-to-end encrypted \
                  requests, local file editing and shell tools.\n\
                  Unofficial: built on the reverse-engineered Lumo web protocol."
)]
struct Cli {
    /// One-shot prompt: run a single request instead of the interactive REPL
    #[arg(short, long)]
    prompt: Option<String>,

    /// Plain chat mode (no local tools / agent loop)
    #[arg(long)]
    chat: bool,

    /// Auto-approve file writes and shell commands (dangerous)
    #[arg(long)]
    yolo: bool,

    /// Dry-run: show file writes and shell commands the agent proposes without executing them
    #[arg(long)]
    dry_run: bool,

    /// After each agent turn that changed files, commit them in the project's git repo
    #[arg(long)]
    commit: bool,

    /// Attach a text/document file as context (repeatable)
    #[arg(long)]
    attach: Vec<String>,

    /// Model: lumo-lite (default), lumo-max or apertus-15. NOTE: lumo-max is a premium
    /// model with a daily quota; agent mode spends one request per tool step, so it drains fast.
    #[arg(long)]
    model: Option<String>,

    /// Enable reasoning ("thinking") mode
    #[arg(long)]
    think: bool,

    /// Max conversation turns sent per request
    #[arg(long, default_value_t = DEFAULT_MAX_TURNS)]
    max_turns: usize,

    /// Lumo server-side tools to enable (comma separated: web_search,weather,stock,cryptocurrency)
    #[arg(long, value_delimiter = ',')]
    tools: Vec<String>,

    /// Require the Landlock sandbox for tool subprocesses (error if unavailable).
    /// Default: auto, that is sandbox when the kernel supports Landlock, otherwise warn and run unsandboxed.
    #[arg(long)]
    sandbox: bool,

    /// Disable the Landlock sandbox entirely.
    #[arg(long, conflicts_with = "sandbox")]
    no_sandbox: bool,

    /// Read-only project: the sandbox and the file tools refuse to modify it (code review)
    #[arg(long, global = true)]
    ro: bool,

    /// Deny execve of project files inside the sandbox (a speed bump)
    #[arg(long, global = true)]
    noexec: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to your Proton account (SRP; password never leaves this machine).
    ///
    /// If Proton demands a CAPTCHA (error 9001) that a CLI can't solve, import an
    /// existing session with --import-rclone or --paste instead.
    Login {
        /// Import a session from an rclone Proton Drive remote instead of an SRP login
        #[arg(long)]
        import_rclone: bool,
        /// Name of the rclone remote to import (default: first Proton remote found)
        #[arg(long)]
        remote: Option<String>,
        /// Path to rclone.conf (default: ~/.config/rclone/rclone.conf)
        #[arg(long)]
        rclone_config: Option<String>,
        /// Paste UID / access token / refresh token manually
        #[arg(long)]
        paste: bool,
        /// Human-verification token from a browser CAPTCHA (the
        /// `x-pm-human-verification-token` request header). Lets the SRP login
        /// proceed past error 9001 and create its own dedicated session.
        #[arg(long)]
        captcha_token: Option<String>,
    },
    /// Delete the stored session
    Logout,
    /// Verify the sandbox holds: run probes under Landlock and report
    /// what is denied (secrets, other dirs) and allowed (the project).
    CheckSandbox,
    /// Internal: confine this process with the policy from LUMO_SANDBOX_POLICY,
    /// then exec the given program. Used to launch every sandboxed tool command.
    #[command(hide = true)]
    SandboxExec {
        /// Program and arguments, after `--`
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Manage Lumo's PGP public key (the request-encryption trust anchor).
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Inspect or approve the project's .lumo-config directory.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run a local OpenAI-compatible HTTP server backed by Lumo.
    Serve {
        /// Address to bind (default 127.0.0.1; a non-loopback address requires --api-key)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// Require this bearer token on every request (Authorization: Bearer …)
        #[arg(long)]
        api_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show what .lumo-config would apply and whether it is approved
    Show,
    /// Approve the current .lumo-config content (non-interactive)
    Allow,
    /// Forget the approval for this project's .lumo-config
    Reset,
}

#[derive(Subcommand)]
enum KeyAction {
    /// Show the active key: source, fingerprint, user id, creation date
    Show,
    /// Compare the active key against Proton's canonical key and report rotation
    Check,
    /// Adopt a new key into the config override (asks for confirmation)
    Update {
        /// Read the key from a local file instead of the network
        #[arg(long)]
        file: Option<String>,
        /// Fetch the key from this URL (default: Proton's open-source repo)
        #[arg(long)]
        url: Option<String>,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Remove the config override and revert to the embedded default key
    Reset,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // The sandboxed-child entry point runs synchronously, before any runtime
    // thread exists: Landlock restricts the calling thread, and that same
    // thread must be the one that execs the program.
    if let Some(Command::SandboxExec { argv }) = &cli.command {
        return sandbox::exec_confined(argv);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting async runtime")?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Login {
            import_rclone,
            remote,
            rclone_config,
            paste,
            captcha_token,
        }) => {
            return if import_rclone {
                import_rclone_flow(remote.as_deref(), rclone_config.as_deref()).await
            } else if paste {
                paste_flow().await
            } else {
                login_flow(captcha_token.as_deref()).await
            };
        }
        Some(Command::Logout) => {
            if auth::Session::delete()? {
                println!("session deleted");
            } else {
                println!("no stored session");
            }
            return Ok(());
        }
        Some(Command::CheckSandbox) => {
            return check_sandbox(sandbox::Mode {
                ro: cli.ro,
                noexec: cli.noexec,
            })
            .await;
        }
        Some(Command::Key { action }) => return key_command(action).await,
        Some(Command::Config { action }) => {
            let cwd = std::env::current_dir().context("cannot determine working directory")?;
            return match action {
                ConfigAction::Show => projconfig::show(&cwd),
                ConfigAction::Allow => projconfig::allow(&cwd),
                ConfigAction::Reset => projconfig::reset(&cwd),
            };
        }
        Some(Command::Serve {
            host,
            port,
            api_key,
        }) => return serve_command(host, port, api_key).await,
        Some(Command::SandboxExec { .. }) => {
            anyhow::bail!("sandbox-exec is dispatched before the runtime starts")
        }
        None => {}
    }

    let session = auth::Session::load().unwrap_or_else(|e| {
        eprintln!("{} could not load session: {e:#}", "warning:".yellow());
        None
    });

    // Load the per-project config, if the user approves it. Its settings act as
    // defaults below; explicit CLI flags always win.
    let cwd = std::env::current_dir().unwrap_or_default();
    let proj = projconfig::load(&cwd).unwrap_or_else(|e| {
        eprintln!(
            "{} {e:#}; ignoring project config",
            "warning:".yellow().bold()
        );
        None
    });
    let pf = proj.as_ref().map(|p| &p.file);

    let agent_mode = !cli.chat;
    let mut client = LumoClient::new(session)?;
    load_active_lumo_key(&mut client);
    client.project_instructions = proj.as_ref().and_then(|p| p.instructions.clone());

    // Settings precedence: default < project config < explicit CLI flag.
    let cfg_max_turns = pf.and_then(|c| c.max_turns);
    client.max_turns = if cli.max_turns != DEFAULT_MAX_TURNS {
        cli.max_turns
    } else {
        cfg_max_turns.unwrap_or(DEFAULT_MAX_TURNS)
    }
    .max(4);
    // Default to lumo-lite everywhere. Agent mode issues one request PER tool
    // round, so defaulting to the premium lumo-max would silently burn the
    // daily premium quota in a single task. Opt into it with --model lumo-max.
    client.model = cli
        .model
        .clone()
        .or_else(|| pf.and_then(|c| c.model.clone()))
        .unwrap_or_else(|| protocol::MODEL_LITE.to_string());
    client.reasoning = cli.think || pf.and_then(|c| c.think).unwrap_or(false);
    for t in cli
        .tools
        .iter()
        .cloned()
        .chain(pf.and_then(|c| c.tools.clone()).unwrap_or_default())
    {
        if !client.server_tools.contains(&t) {
            client.server_tools.push(t);
        }
    }

    // Effective flags after folding in the (approved) config.
    let yolo = cli.yolo || pf.and_then(|c| c.yolo).unwrap_or(false);
    let dry_run = cli.dry_run;
    let commit = cli.commit || pf.and_then(|c| c.commit).unwrap_or(false);
    let no_sandbox = cli.no_sandbox || pf.and_then(|c| c.no_sandbox).unwrap_or(false);
    let ro = cli.ro || pf.and_then(|c| c.ro).unwrap_or(false);
    let noexec = cli.noexec || pf.and_then(|c| c.noexec).unwrap_or(false);

    // Non-fatal: warn if the deployed Lumo web app has a different major
    // version than the one this protocol was tested against.
    warn_on_api_version(&client).await;

    // Non-fatal, throttled (once/day): warn if Proton's canonical key no longer
    // matches the active one, i.e. the key has likely rotated.
    warn_on_key_rotation().await;

    // Set up the Landlock sandbox for tool subprocesses (agent mode only, as
    // chat mode has no local tools).
    let sandbox_mode = sandbox::Mode { ro, noexec };
    let sandbox = if agent_mode && !no_sandbox {
        setup_sandbox(cli.sandbox, sandbox_mode)?
    } else {
        None
    };

    // Audit trail of the agent's actions (agent mode only).
    let audit = if agent_mode {
        let log = audit::AuditLog::open(&cwd);
        if let Some(a) = &log {
            eprintln!(
                "{} actions logged to {}",
                "audit:".green(),
                a.path().display()
            );
        }
        log
    } else {
        None
    };

    // Read any attachments once (a bad file is a hard startup error).
    let attach_block = attach::build_block(&cli.attach)?;

    if let Some(prompt) = cli.prompt {
        let prompt = attach::prepend(&attach_block, &prompt);
        return one_shot(
            client,
            &prompt,
            agent_mode,
            yolo,
            dry_run,
            commit,
            sandbox.as_ref(),
            audit.as_ref(),
        )
        .await;
    }

    ui::run_repl(
        client,
        ui::ReplConfig {
            agent_mode,
            auto_approve: yolo,
            dry_run,
            commit,
        },
        sandbox,
        audit,
        attach_block,
    )
    .await
}

/// Compare the live Lumo web app version to [`protocol::TESTED_LUMO_VERSION`]
/// and warn (once, non-fatally) if the major version differs, a hint that the
/// reverse-engineered wire format may have shifted.
async fn warn_on_api_version(client: &LumoClient) {
    let Some(live) = client.lumo_version().await else {
        return;
    };
    let major = |v: &str| v.split('.').next().unwrap_or("").to_string();
    if major(&live) != major(protocol::TESTED_LUMO_VERSION) {
        eprintln!(
            "{} Lumo web app is v{live}, but lumo-cli was built against v{}; the API may have \
             changed; if requests fail, the protocol likely needs updating.",
            "warning:".yellow().bold(),
            protocol::TESTED_LUMO_VERSION
        );
    }
}

/// Build the sandbox for the current directory. `required` = the user passed
/// --sandbox (fail if unavailable); otherwise fall back to unsandboxed with a
/// warning so the tool still works on hosts without Landlock.
fn setup_sandbox(required: bool, mode: sandbox::Mode) -> Result<Option<Sandbox>> {
    let project = std::env::current_dir().context("cannot determine working directory")?;
    match Sandbox::setup(&project, mode) {
        Ok(sb) => {
            let envs = if sb.envs().is_empty() {
                "none".to_string()
            } else {
                sb.envs().join(", ")
            };
            let mut tags = Vec::new();
            if mode.ro {
                tags.push("read-only");
            }
            if mode.noexec {
                tags.push("noexec");
            }
            let mode_note = if tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", tags.join(", "))
            };
            eprintln!(
                "{} tool commands sandboxed (Landlock ABI {}) to {}; detected: {}{}",
                "sandbox:".green().bold(),
                sb.abi(),
                sb.project().display(),
                envs,
                mode_note
            );
            print_caveats(&sb);
            Ok(Some(sb))
        }
        Err(e) if required => Err(e),
        Err(e) => {
            eprintln!(
                "{} {e:#}\n         running WITHOUT a sandbox; tool commands are unconfined. \
                 Pass --sandbox to require it, or --no-sandbox to silence this.",
                "warning:".yellow().bold()
            );
            Ok(None)
        }
    }
}

/// Older kernels enforce less; say exactly what, every time.
fn print_caveats(sb: &Sandbox) {
    for c in sb.caveats() {
        eprintln!("{} sandbox: {c}", "warning:".yellow().bold());
    }
}

/// Run the sandbox self-check: probe denied and allowed operations under
/// Landlock and report PASS/FAIL for each.
async fn check_sandbox(mode: sandbox::Mode) -> Result<()> {
    let project = std::env::current_dir().context("cannot determine working directory")?;
    let sb = Sandbox::setup(&project, mode)?;
    println!(
        "{} profile {} for {} (Landlock ABI {})",
        "check:".bold(),
        sb.profile_name(),
        sb.project().display(),
        sb.abi()
    );
    print_caveats(&sb);

    // (label, sh command, expect_success): a denied op must fail, an allowed
    // op must succeed.
    let probe = project.join(".lumo-sandbox-probe");
    let probe_s = probe.to_string_lossy().to_string();
    let mut checks: Vec<(&str, String, bool)> = vec![
        (
            "deny: read ~/.ssh",
            "cat ~/.ssh/* >/dev/null 2>&1".into(),
            false,
        ),
        (
            "deny: list $HOME",
            "ls -1 \"$HOME\" >/dev/null 2>&1".into(),
            false,
        ),
        (
            "deny: read ~/.aws/credentials",
            "cat ~/.aws/credentials >/dev/null 2>&1".into(),
            false,
        ),
        (
            "allow: read /etc/hostname",
            "cat /etc/hostname >/dev/null 2>&1".into(),
            true,
        ),
    ];
    // Project write and execute depend on the mode.
    let write_probe = format!("echo ok > '{probe_s}' && rm -f '{probe_s}'");
    if mode.ro {
        checks.push(("deny: write inside the project (--ro)", write_probe, false));
    } else {
        checks.push(("allow: write inside the project", write_probe, true));
    }
    if !mode.noexec {
        checks.push(("allow: execute /usr/bin/true", "/usr/bin/true".into(), true));
    }
    let checks = checks;

    let mut all_ok = true;
    for (label, cmd, expect_ok) in &checks {
        let status = tokio::process::Command::from(sb.command("sh"))
            .arg("-c")
            .arg(cmd)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        let ok = status.map(|s| s.success()).unwrap_or(false);
        let pass = ok == *expect_ok;
        all_ok &= pass;
        println!(
            "  [{}] {}",
            if pass {
                "PASS".green().to_string()
            } else {
                "FAIL".red().to_string()
            },
            label
        );
    }
    if let Err(e) = std::fs::remove_file(&probe)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "{} could not remove {}: {e}",
            "warning:".yellow(),
            probe.display()
        );
    }
    if all_ok {
        println!(
            "{}",
            "result: OK, every probe behaved as required".green().bold()
        );
        Ok(())
    } else {
        anyhow::bail!("sandbox self-check failed; do not trust the confinement");
    }
}

/// Load the active Lumo PGP key (env/file/embedded) into the client. A broken
/// override is a hard warning but falls back to the embedded default so the
/// tool still works; expiry/rotation of the embedded default is caught
/// separately by [`warn_on_key_rotation`].
fn load_active_lumo_key(client: &mut LumoClient) {
    let (armored, source) = keys::active_key();
    if matches!(source, keys::KeySource::Embedded) {
        return; // client already parsed the embedded default in `new`
    }
    match keys::parse(&armored) {
        Ok((key, info)) => {
            client.set_lumo_key(key);
            eprintln!(
                "{} using Lumo key from {} (fp {})",
                "key:".green(),
                source,
                short_fp(&info.fingerprint)
            );
        }
        Err(e) => eprintln!(
            "{} {source} could not be parsed ({e:#}); using the embedded default key.",
            "warning:".yellow().bold()
        ),
    }
}

fn short_fp(fp: &str) -> String {
    // Group the last 8 hex chars for a quick eyeball check.
    fp.get(fp.len().saturating_sub(8)..)
        .unwrap_or(fp)
        .to_string()
}

fn key_check_stamp() -> Option<std::path::PathBuf> {
    dirs::cache_dir().map(|d| d.join("lumo-cli").join("last-key-check"))
}

/// Throttled best-effort rotation check: at most once per 24h, fetch Proton's
/// canonical key and compare fingerprints with the active one. Warns on
/// mismatch; silent on any error or when offline.
async fn warn_on_key_rotation() {
    // Throttle via a cache stamp.
    if let Some(stamp) = key_check_stamp()
        && let Ok(meta) = std::fs::metadata(&stamp)
        && let Ok(modified) = meta.modified()
        && modified
            .elapsed()
            .map(|d| d.as_secs() < 86_400)
            .unwrap_or(false)
    {
        return;
    }

    let (armored, _) = keys::active_key();
    let Ok((_, active)) = keys::parse(&armored) else {
        return;
    };
    let url = std::env::var("LUMO_PUBKEY_URL").unwrap_or_else(|_| keys::CANONICAL_KEY_URL.into());
    let Ok(canonical_armored) = keys::fetch_canonical(&url).await else {
        return; // offline or source unavailable: stay quiet
    };
    let Ok((_, canonical)) = keys::parse(&canonical_armored) else {
        return;
    };

    // Record that we checked (regardless of outcome) to honor the throttle.
    if let Some(stamp) = key_check_stamp() {
        if let Some(dir) = stamp.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&stamp, &canonical.fingerprint);
    }

    if canonical.fingerprint != active.fingerprint {
        eprintln!(
            "{} Lumo's PGP key appears to have ROTATED.\n         \
             active:    {} ({})\n         \
             canonical: {} ({})\n         \
             Requests may fail until you update. Review and run `lumo key update`.",
            "warning:".yellow().bold(),
            active.fingerprint,
            active.user_id,
            canonical.fingerprint,
            canonical.user_id
        );
    }
}

async fn serve_command(host: String, port: u16, api_key: Option<String>) -> Result<()> {
    let session = auth::Session::load().unwrap_or(None);
    if session.is_none() {
        eprintln!(
            "{} no stored session; serving in guest mode (stricter limits). Run `lumo login`.",
            "note:".yellow()
        );
    }
    let mut client = LumoClient::new(session)?;
    load_active_lumo_key(&mut client);
    client.model = protocol::MODEL_LITE.to_string();
    serve::run(
        client,
        serve::ServeOptions {
            host,
            port,
            api_key,
        },
    )
    .await
}

async fn key_command(action: KeyAction) -> Result<()> {
    match action {
        KeyAction::Show => {
            let (armored, source) = keys::active_key();
            let (_, info) = keys::parse(&armored).context("active key is invalid")?;
            println!("source:      {source}");
            println!("fingerprint: {}", info.fingerprint);
            println!("user id:     {}", info.user_id);
            println!("created:     {}", info.created);
            Ok(())
        }
        KeyAction::Check => {
            let (armored, _) = keys::active_key();
            let (_, active) = keys::parse(&armored).context("active key is invalid")?;
            let url =
                std::env::var("LUMO_PUBKEY_URL").unwrap_or_else(|_| keys::CANONICAL_KEY_URL.into());
            println!("active fingerprint:    {}", active.fingerprint);
            let canonical_armored = keys::fetch_canonical(&url).await?;
            let (_, canonical) = keys::parse(&canonical_armored)?;
            println!("canonical fingerprint: {}", canonical.fingerprint);
            if canonical.fingerprint == active.fingerprint {
                println!(
                    "{} the active key matches Proton's canonical key",
                    "✓ up to date:".green()
                );
            } else {
                println!(
                    "{} run `lumo key update` to adopt the canonical key ({})",
                    "⚠ rotated:".yellow(),
                    canonical.user_id
                );
            }
            Ok(())
        }
        KeyAction::Update { file, url, yes } => {
            let candidate = if let Some(path) = file {
                std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?
            } else {
                let url = url
                    .or_else(|| std::env::var("LUMO_PUBKEY_URL").ok())
                    .unwrap_or_else(|| keys::CANONICAL_KEY_URL.into());
                eprintln!("fetching candidate key from {url} …");
                keys::fetch_canonical(&url).await?
            };
            let (_, info) = keys::parse(&candidate).context("candidate is not a valid key")?;
            let (active_armored, _) = keys::active_key();
            let active_fp = keys::parse(&active_armored)
                .ok()
                .map(|(_, i)| i.fingerprint);

            println!("candidate key:");
            println!("  fingerprint: {}", info.fingerprint);
            println!("  user id:     {}", info.user_id);
            println!("  created:     {}", info.created);
            match &active_fp {
                Some(fp) if fp == &info.fingerprint => {
                    println!(
                        "{}",
                        "this is identical to the active key; nothing to do.".dimmed()
                    );
                    return Ok(());
                }
                Some(fp) => println!("  replaces active fingerprint {fp}"),
                None => {}
            }

            if !yes {
                use std::io::Write;
                print!(
                    "{}",
                    "Adopt this key? Verify the fingerprint against a trusted Proton \
                     source first. [y/N]: "
                        .bold()
                );
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
                    println!("aborted; no change.");
                    return Ok(());
                }
            }
            let path = keys::save_to_config(&candidate)?;
            println!("{} saved to {}", "✓".green().bold(), path.display());
            Ok(())
        }
        KeyAction::Reset => {
            if keys::clear_config()? {
                println!("config key override removed; reverting to the embedded default.");
            } else {
                println!("no config key override was set.");
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn one_shot(
    mut client: LumoClient,
    prompt: &str,
    agent_mode: bool,
    yolo: bool,
    dry_run: bool,
    commit: bool,
    sandbox: Option<&Sandbox>,
    audit: Option<&audit::AuditLog>,
) -> Result<()> {
    let mut term = ui::TermUi::new();
    if agent_mode {
        let mut always = agent::AlwaysApproved::default();
        agent::run_turn(
            &mut client,
            &mut term,
            prompt,
            &agent::AgentOptions {
                auto_approve: yolo,
                sandbox,
                dry_run,
                audit,
            },
            &mut always,
        )
        .await?;
        if commit && !dry_run {
            ui::maybe_commit(prompt);
        }
        Ok(())
    } else {
        ui::chat_send(&mut client, &mut term, prompt).await
    }
}

async fn login_flow(captcha_token: Option<&str>) -> Result<()> {
    println!("{}", "Proton login".bold());
    println!("Credentials are used locally for the SRP handshake; the password is never sent.");
    print!("email/username: ");
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();
    let mut password = rpassword::prompt_password("password: ")?;

    // Zeroize the password on every path (success or failure), not just Drop.
    let result = auth::login(&username, &password, captcha_token, || {
        rpassword::prompt_password("2FA code (TOTP): ").map_err(Into::into)
    })
    .await;
    zeroize::Zeroize::zeroize(&mut password);
    let session = result?;
    session.save()?;
    println!(
        "{} logged in as {}; session stored in {}",
        "✓".green().bold(),
        username.green(),
        auth::Session::path()?.display()
    );
    Ok(())
}

async fn import_rclone_flow(remote: Option<&str>, config: Option<&str>) -> Result<()> {
    let session = auth::import_from_rclone(remote, config)?;
    validate_and_save(session).await
}

async fn paste_flow() -> Result<()> {
    use std::io::Write;
    println!("{}", "Import a Proton session".bold());
    println!(
        "Paste the values from an authenticated Proton session (e.g. an rclone\n\
         protondrive remote in ~/.config/rclone/rclone.conf: client_uid,\n\
         client_access_token, client_refresh_token)."
    );
    let read = |label: &str| -> Result<String> {
        print!("{label}: ");
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        Ok(s.trim().to_string())
    };
    let uid = read("UID")?;
    let access_token = read("AccessToken")?;
    let refresh_token = read("RefreshToken")?;
    if uid.is_empty() || access_token.is_empty() || refresh_token.is_empty() {
        anyhow::bail!("UID, AccessToken and RefreshToken are all required");
    }
    validate_and_save(auth::Session {
        uid,
        access_token,
        refresh_token,
        username: "imported".to_string(),
    })
    .await
}

/// Confirm an imported session works against Lumo, then persist it.
async fn validate_and_save(mut session: auth::Session) -> Result<()> {
    let mut client = LumoClient::new(Some(session.clone()))?;

    // Access token may be expired even if the session is valid; refresh once.
    if client.fetch_limits().await.is_err() {
        match auth::refresh(&session).await {
            Ok(refreshed) => {
                session = refreshed;
                client = LumoClient::new(Some(session.clone()))?;
            }
            Err(e) => anyhow::bail!(
                "imported tokens were rejected by Lumo and could not be refreshed ({e:#}).\n\
                 The session is likely expired or lacks Lumo access. Re-authenticate the \
                 source (e.g. run an rclone op) and try again."
            ),
        }
    }

    client
        .fetch_limits()
        .await
        .context("session still rejected by Lumo after refresh")?;

    session.save()?;
    println!(
        "{} session imported and verified; stored in {}",
        "✓".green().bold(),
        auth::Session::path()?.display()
    );
    println!(
        "  {}",
        "note: lumo-cli now shares this Proton session; its own token refreshes may \
         eventually invalidate the source (e.g. rclone), which then signs in again."
            .dimmed()
    );
    Ok(())
}
