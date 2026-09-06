// SPDX-License-Identifier: GPL-3.0-or-later
//! Append-only audit trail of the actions the agent performed.
//!
//! Every side-effecting tool (write_file, edit_file, bash) is recorded so the
//! run is reviewable after the fact. The log lives in the XDG state directory,
//! keyed by project, and NOT inside the project on purpose, so it is never
//! committed by accident and stays outside the sandbox-writable tree. It stores
//! the action (path + diff for writes, command + exit status for shell) but not
//! a command's raw output, which could carry secrets.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

const MAX_DIFF: usize = 4000;

#[derive(Serialize)]
struct Entry<'a> {
    /// Unix seconds.
    ts: u64,
    /// Tool name (write_file, edit_file, bash, …).
    kind: &'a str,
    /// Target: a file path or the shell command.
    detail: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    note: &'a str,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Open (creating as needed) the audit log for `project`. Returns None if no
    /// suitable state directory exists.
    pub fn open(project: &Path) -> Option<Self> {
        let base = dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .or_else(dirs::cache_dir)?;
        let dir = base.join("lumo-cli").join("audit");
        if std::fs::create_dir_all(&dir).is_err() {
            return None;
        }
        harden_dir(&dir);
        let slug = slug(project);
        let session = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = dir.join(format!("{slug}-{session}.jsonl"));
        Some(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one action. Failures to write are swallowed: auditing must never
    /// break the agent, and the log is best-effort accountability, not a gate.
    pub fn record(&self, kind: &str, detail: &str, ok: bool, note: &str) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let note = truncate(note, MAX_DIFF);
        let entry = Entry {
            ts,
            kind,
            detail,
            ok,
            note: &note,
        };
        if let Ok(mut line) = serde_json::to_string(&entry) {
            line.push('\n');
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).append(true);
            // The log holds diffs and commands that may be sensitive: owner-only.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let _ = opts
                .open(&self.path)
                .and_then(|mut f| f.write_all(line.as_bytes()));
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}\n[... truncated ...]")
}

fn slug(project: &Path) -> String {
    project
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".into())
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(unix)]
fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn harden_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn audit_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("lumo_audit_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Force the log under our temp dir regardless of XDG.
        let log = AuditLog {
            path: tmp.join("a.jsonl"),
        };
        log.record("bash", "echo hi", true, "");
        let mode = std::fs::metadata(log.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log must be owner-only, got {mode:o}");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
