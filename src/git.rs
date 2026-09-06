// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal, safe git helpers for committing the agent's changes.
//!
//! All invocations go through an argument vector (never a shell), operate only
//! inside the project's own repository, and never push or force. Commits are an
//! explicit user action (`/commit`, or the opt-in `--commit` after a turn).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

fn git(root: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .context("failed to run git (is it installed and on PATH?)")
}

/// The working tree root of the repository containing `dir`, or None.
pub fn repo_root(dir: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// True if the working tree has staged or unstaged changes (or untracked files).
pub fn has_changes(root: &Path) -> Result<bool> {
    let out = git(root, &["status", "--porcelain"])?;
    if !out.status.success() {
        bail!(
            "git status failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(!out.stdout.is_empty())
}

/// Paths with changes, for a commit body. Best-effort, capped.
pub fn changed_paths(root: &Path, cap: usize) -> Vec<String> {
    let Ok(out) = git(root, &["status", "--porcelain"]) else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.get(3..).map(str::to_string))
        .take(cap)
        .collect()
}

/// Stage everything and commit with `message`. Never pushes. Returns the short
/// commit summary (`git commit` stdout).
pub fn commit_all(root: &Path, message: &str) -> Result<String> {
    if message.trim().is_empty() {
        bail!("refusing to commit with an empty message");
    }
    if !has_changes(root)? {
        bail!("nothing to commit (working tree clean)");
    }
    let add = git(root, &["add", "-A"])?;
    if !add.status.success() {
        bail!("git add failed: {}", String::from_utf8_lossy(&add.stderr));
    }
    // `-m` with a single argument: the message is passed as one argv element,
    // so no shell interpretation and no injection surface.
    let commit = git(root, &["commit", "-m", message])?;
    if !commit.status.success() {
        bail!(
            "git commit failed: {}{}",
            String::from_utf8_lossy(&commit.stdout),
            String::from_utf8_lossy(&commit.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&commit.stdout).trim().to_string())
}

/// Build a conservative commit message from the user's instruction and the list
/// of changed files. Deterministic and free (no model call).
pub fn derive_message(instruction: &str, root: &Path) -> String {
    let subject = instruction.lines().next().unwrap_or("update").trim();
    let subject: String = subject.chars().take(72).collect();
    let subject = if subject.is_empty() {
        "update".into()
    } else {
        subject
    };
    let files = changed_paths(root, 20);
    let mut msg = subject;
    if !files.is_empty() {
        msg.push_str("\n\nChanged files:\n");
        for f in &files {
            msg.push_str(&format!("- {f}\n"));
        }
    }
    msg.push_str("\nCommitted by lumo-cli.\n");
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_message_uses_first_line_capped() {
        // A non-repo path: changed_paths returns empty, so only the subject +
        // trailer appear.
        let tmp = std::env::temp_dir();
        let long = "a".repeat(200);
        let msg = derive_message(&format!("{long}\nsecond line"), &tmp);
        let subject = msg.lines().next().unwrap();
        assert!(subject.chars().count() <= 72);
        assert!(msg.contains("Committed by lumo-cli"));
    }

    #[test]
    fn derive_message_defaults_when_empty() {
        let msg = derive_message("", &std::env::temp_dir());
        assert!(msg.starts_with("update"));
    }
}
