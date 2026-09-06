// SPDX-License-Identifier: GPL-3.0-or-later
//! Local tools the agent can invoke: file inspection, edits, shell commands.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::sandbox::Sandbox;

const MAX_TOOL_OUTPUT: usize = 12_000; // chars fed back to the model
const MAX_READ_BYTES: u64 = 256 * 1024;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    "dist",
];

/// A tool invocation parsed from the model's output.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    #[serde(default)]
    pub args: Value,
}

/// What the user must approve before the tool runs.
pub enum PendingAction {
    /// No side effects: runs without confirmation.
    ReadOnly,
    /// File creation/modification, with a rendered diff for review.
    WriteFile { path: PathBuf, diff: String },
    /// Arbitrary shell command.
    Shell { command: String },
}

/// A validated, ready-to-run operation. Built once by [`plan`] (which also reads
/// the file and computes the diff), then run by [`execute`], so the read/replace
/// logic lives in exactly one place and the approved bytes are the executed bytes.
enum Op {
    ListDir(PathBuf),
    ReadFile {
        path: PathBuf,
        offset: usize,
        limit: usize,
    },
    Search {
        pattern: String,
        path: String,
    },
    /// Final content to write (covers both write_file and edit_file).
    WriteFile {
        path: PathBuf,
        content: String,
    },
    Bash {
        command: String,
    },
}

/// The outcome of planning a tool call: what to show for approval, plus the
/// captured operation to run if approved.
pub struct Planned {
    pub approval: PendingAction,
    op: Op,
}

pub fn truncate_output(mut s: String) -> String {
    if s.chars().count() > MAX_TOOL_OUTPUT {
        let cut: String = s.chars().take(MAX_TOOL_OUTPUT).collect();
        s = format!("{cut}\n[... output truncated ...]");
    }
    s
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string argument `{key}`"))
}

fn resolve(path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}

/// Validate a tool call and capture what it will do. This is the single place
/// file contents are read and diffs are computed; [`execute`] just runs the
/// captured [`Op`]. When a sandbox is active, file paths are confined to the
/// project root. Returns an error if the call is malformed.
pub fn plan(call: &ToolCall, sandbox: Option<&Sandbox>) -> Result<Planned> {
    let confine = |p: &Path| -> Result<()> {
        match sandbox {
            Some(sb) => sb.confine(p),
            None => Ok(()),
        }
    };
    // In a read-only sandbox, lumo-cli's own file tools must not write either:
    // Landlock only confines subprocesses, not this process.
    let deny_if_ro = || -> Result<()> {
        if sandbox.map(|sb| sb.mode().ro).unwrap_or(false) {
            bail!("read-only sandbox (--ro): refusing to modify files");
        }
        Ok(())
    };
    let planned = match call.tool.as_str() {
        "list_dir" => {
            let path = call.args.get("path").and_then(Value::as_str).unwrap_or(".");
            let path = resolve(path);
            confine(&path)?;
            Planned {
                approval: PendingAction::ReadOnly,
                op: Op::ListDir(path),
            }
        }
        "read_file" => {
            let path = resolve(arg_str(&call.args, "path")?);
            confine(&path)?;
            // Model-supplied numbers: clamp instead of truncating.
            let to_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
            let offset = call
                .args
                .get("offset")
                .and_then(Value::as_u64)
                .map_or(1, to_usize)
                .max(1);
            let limit = call
                .args
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(400, to_usize);
            Planned {
                approval: PendingAction::ReadOnly,
                op: Op::ReadFile {
                    path,
                    offset,
                    limit,
                },
            }
        }
        "search" => {
            let pattern = arg_str(&call.args, "pattern")?.to_string();
            let path = call
                .args
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(".")
                .to_string();
            confine(&resolve(&path))?;
            Planned {
                approval: PendingAction::ReadOnly,
                op: Op::Search { pattern, path },
            }
        }
        "write_file" => {
            let path = resolve(arg_str(&call.args, "path")?);
            confine(&path)?;
            deny_if_ro()?;
            let content = arg_str(&call.args, "content")?.to_string();
            let old_content = std::fs::read_to_string(&path).unwrap_or_default();
            let diff = render_diff(&old_content, &content, &path);
            Planned {
                approval: PendingAction::WriteFile {
                    path: path.clone(),
                    diff,
                },
                op: Op::WriteFile { path, content },
            }
        }
        "edit_file" => {
            let path = resolve(arg_str(&call.args, "path")?);
            confine(&path)?;
            deny_if_ro()?;
            let old = arg_str(&call.args, "old")?;
            let new = arg_str(&call.args, "new")?;
            let current = std::fs::read_to_string(&path)
                .map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?;
            let count = current.matches(old).count();
            if count == 0 {
                bail!("`old` text not found in {}", path.display());
            }
            if count > 1 {
                bail!(
                    "`old` text found {count} times in {}; it must be unique",
                    path.display()
                );
            }
            let content = current.replacen(old, new, 1);
            let diff = render_diff(&current, &content, &path);
            Planned {
                approval: PendingAction::WriteFile {
                    path: path.clone(),
                    diff,
                },
                op: Op::WriteFile { path, content },
            }
        }
        "bash" => {
            let command = arg_str(&call.args, "command")?.to_string();
            Planned {
                approval: PendingAction::Shell {
                    command: command.clone(),
                },
                op: Op::Bash { command },
            }
        }
        other => bail!("unknown tool `{other}`"),
    };
    Ok(planned)
}

fn render_diff(old: &str, new: &str, path: &Path) -> String {
    let diff = similar::TextDiff::from_lines(old, new);
    let mut out = String::new();
    out.push_str(&format!(
        "--- {}\n+++ {} (proposed)\n",
        path.display(),
        path.display()
    ));
    for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
        out.push_str(&hunk.to_string());
    }
    out
}

/// Run a planned operation and return the output to feed the model. When a
/// sandbox is active, subprocess ops (search, bash) run under Landlock.
///
/// In `dry_run`, side-effecting ops (write_file, edit_file, bash) are NOT
/// performed; they report what they would do. Read-only ops still run so the
/// model can keep exploring.
pub async fn execute(
    planned: &Planned,
    sandbox: Option<&Sandbox>,
    dry_run: bool,
) -> Result<String> {
    let out = match &planned.op {
        Op::ListDir(path) => list_dir(path)?,
        Op::ReadFile {
            path,
            offset,
            limit,
        } => read_file(path, *offset, *limit)?,
        Op::Search { pattern, path } => search(pattern, path, sandbox).await?,
        Op::WriteFile { path, content } if dry_run => {
            format!(
                "[dry-run] would write {} bytes to {} (not executed)",
                content.len(),
                path.display()
            )
        }
        Op::WriteFile { path, content } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
            format!("wrote {} bytes to {}", content.len(), path.display())
        }
        Op::Bash { command } if dry_run => {
            format!("[dry-run] would run `{command}` (not executed)")
        }
        Op::Bash { command } => run_shell(command, sandbox).await?,
    };
    Ok(truncate_output(out))
}

fn list_dir(root: &Path) -> Result<String> {
    let mut out = String::new();
    let mut count = 0usize;
    walk(root, root, 0, &mut out, &mut count)?;
    if out.is_empty() {
        out = "(empty directory)".into();
    }
    Ok(out)
}

fn walk(root: &Path, dir: &Path, depth: usize, out: &mut String, count: &mut usize) -> Result<()> {
    if depth > 3 || *count > 500 {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        // Use symlink_metadata so we never follow a symlink into a directory,
        // which keeps a symlink cycle from turning into unbounded recursion.
        let ft = entry.file_type().ok();
        let is_symlink = ft.map(|t| t.is_symlink()).unwrap_or(false);
        let is_dir = !is_symlink && path.is_dir();
        if is_dir && (SKIP_DIRS.contains(&name.as_str()) || name.starts_with('.')) {
            continue;
        }
        *count = count.saturating_add(1);
        if *count > 500 {
            out.push_str("[... listing truncated ...]\n");
            return Ok(());
        }
        let rel = path.strip_prefix(root).unwrap_or(&path);
        if is_dir {
            out.push_str(&format!("{}/\n", rel.display()));
            walk(root, &path, depth.saturating_add(1), out, count)?;
        } else {
            out.push_str(&format!("{}\n", rel.display()));
        }
    }
    Ok(())
}

fn read_file(path: &Path, offset: usize, limit: usize) -> Result<String> {
    let meta =
        std::fs::metadata(path).map_err(|e| anyhow!("cannot access {}: {e}", path.display()))?;
    if meta.len() > MAX_READ_BYTES {
        bail!(
            "{} is {} bytes, too large to read whole; use `offset`/`limit` or `search`",
            path.display(),
            meta.len()
        );
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("cannot read {} as text: {e}", path.display()))?;
    let offset = offset.max(1);
    let skip = offset.saturating_sub(1);
    let numbered: Vec<String> = content
        .lines()
        .enumerate()
        .skip(skip)
        .take(limit)
        .map(|(i, l)| format!("{:>5}| {}", i.saturating_add(1), l))
        .collect();
    let total = content.lines().count();
    let mut out = numbered.join("\n");
    let shown_up_to = skip.saturating_add(limit).min(total);
    if shown_up_to < total {
        out.push_str(&format!(
            "\n[showing lines {offset}-{shown_up_to} of {total}; use offset to read more]"
        ));
    }
    Ok(out)
}

/// Build a `tokio::process::Command`, wrapping it in the sandbox when active.
/// `program` + `args` are what runs unsandboxed; under a sandbox they become
/// `lumo-cli sandbox-exec -- <program> <args...>` (see `sandbox.rs`).
fn tool_command(
    program: &str,
    args: &[&str],
    sandbox: Option<&Sandbox>,
) -> tokio::process::Command {
    match sandbox {
        Some(sb) => {
            let mut cmd = tokio::process::Command::from(sb.command(program));
            cmd.args(args);
            cmd
        }
        None => {
            let mut cmd = tokio::process::Command::new(program);
            cmd.args(args);
            cmd
        }
    }
}

async fn search(pattern: &str, path: &str, sandbox: Option<&Sandbox>) -> Result<String> {
    // Prefer ripgrep when available, fall back to grep.
    let rg = tool_command(
        "rg",
        &[
            "-n",
            "--no-heading",
            "--max-count",
            "60",
            "-e",
            pattern,
            path,
        ],
        sandbox,
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .await;
    let output = match rg {
        Ok(o) => o,
        Err(_) => {
            tool_command(
                "grep",
                &[
                    "-rn",
                    "-I",
                    "--exclude-dir=.git",
                    "--exclude-dir=node_modules",
                    "--exclude-dir=target",
                    "-e",
                    pattern,
                    path,
                ],
                sandbox,
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        Ok("(no matches)".into())
    } else {
        Ok(stdout.into_owned())
    }
}

async fn run_shell(command: &str, sandbox: Option<&Sandbox>) -> Result<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        tool_command("sh", &["-c", command], sandbox)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| anyhow!("command timed out after 120s"))??;

    let mut out = String::new();
    out.push_str(&String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        out.push_str("\n[stderr]\n");
        out.push_str(&stderr);
    }
    if !output.status.success() {
        out.push_str(&format!(
            "\n[exit code: {}]",
            output.status.code().unwrap_or(-1)
        ));
    }
    if out.trim().is_empty() {
        out = "(no output, command succeeded)".into();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call(tool: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            tool: tool.into(),
            args,
        }
    }

    #[test]
    fn plan_read_only_ops() {
        for t in ["list_dir", "read_file", "search"] {
            let args = match t {
                "read_file" => json!({"path": "Cargo.toml"}),
                "search" => json!({"pattern": "x"}),
                _ => json!({}),
            };
            let p = plan(&call(t, args), None).unwrap();
            assert!(matches!(p.approval, PendingAction::ReadOnly), "{t}");
        }
    }

    #[test]
    fn plan_edit_requires_unique_match() {
        let dir = std::env::temp_dir().join(format!("lumo_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f.txt");
        std::fs::write(&f, "a\nb\na\n").unwrap();
        let p = f.to_str().unwrap();
        // "a" appears twice -> error
        assert!(
            plan(
                &call("edit_file", json!({"path": p, "old": "a", "new": "z"})),
                None
            )
            .is_err()
        );
        // "b" is unique -> ok, and captures the final content in the Op
        let planned = plan(
            &call("edit_file", json!({"path": p, "old": "b", "new": "z"})),
            None,
        )
        .unwrap();
        match planned.op {
            Op::WriteFile { content, .. } => assert_eq!(content, "a\nz\na\n"),
            _ => panic!("expected WriteFile op"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn plan_write_captures_content() {
        let planned = plan(
            &call(
                "write_file",
                json!({"path": "/tmp/none.txt", "content": "hi"}),
            ),
            None,
        )
        .unwrap();
        assert!(matches!(planned.approval, PendingAction::WriteFile { .. }));
        match planned.op {
            Op::WriteFile { content, .. } => assert_eq!(content, "hi"),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn dry_run_does_not_write() {
        let dir = std::env::temp_dir().join(format!("lumo_dry_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("g.txt");
        let p = f.to_str().unwrap();
        let planned = plan(
            &call("write_file", json!({"path": p, "content": "data"})),
            None,
        )
        .unwrap();
        let out = execute(&planned, None, true).await.unwrap();
        assert!(out.contains("[dry-run]"), "got: {out}");
        assert!(!f.exists(), "dry-run must not create the file");
        // Without dry-run it writes.
        let planned = plan(
            &call("write_file", json!({"path": p, "content": "data"})),
            None,
        )
        .unwrap();
        execute(&planned, None, false).await.unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "data");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dry_run_skips_bash() {
        let marker = std::env::temp_dir().join(format!("lumo_dry_bash_{}", std::process::id()));
        std::fs::remove_file(&marker).ok();
        let cmd = format!("touch '{}'", marker.display());
        let planned = plan(&call("bash", json!({"command": cmd})), None).unwrap();
        let out = execute(&planned, None, true).await.unwrap();
        assert!(out.contains("[dry-run]"));
        assert!(!marker.exists(), "dry-run must not run the command");
    }

    #[test]
    fn plan_rejects_unknown_and_missing_args() {
        assert!(plan(&call("frobnicate", json!({})), None).is_err());
        assert!(plan(&call("bash", json!({})), None).is_err()); // missing command
    }
}
