// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-project configuration under `.lumo-config/`, loaded only with the user's
//! consent.
//!
//! A repository can carry a `.lumo-config/` directory with:
//! - `instructions.md`: guidance injected into the agent's system prompt
//! - `config.toml`: default settings (model, tools, and, notably, some
//!   security-relevant switches)
//!
//! Because a cloned repository is not trusted, this config is never applied
//! automatically. On first sight (and after any edit) lumo-cli asks the user to
//! approve it, flagging any dangerous settings; the approval is remembered by a
//! SHA-256 of the content, so an edit forces re-approval. Outside a terminal we
//! fail closed and do not load it.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const CONFIG_DIR: &str = ".lumo-config";

/// Raw `config.toml`. Unknown keys are rejected so a typo cannot silently
/// disable a protection the user believes is on.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub model: Option<String>,
    pub tools: Option<Vec<String>>,
    pub think: Option<bool>,
    pub max_turns: Option<usize>,
    // Security-relevant switches (flagged on approval):
    pub yolo: Option<bool>,
    pub no_sandbox: Option<bool>,
    pub commit: Option<bool>,
    // More-restrictive switches (safe to enable):
    pub ro: Option<bool>,
    pub noexec: Option<bool>,
}

/// The loaded, approved project configuration.
#[derive(Debug, Default)]
pub struct ProjectConfig {
    pub instructions: Option<String>,
    pub file: FileConfig,
}

/// Locate `.lumo-config/` for `project`, returning its path if present.
pub fn locate(project: &Path) -> Option<PathBuf> {
    let dir = project.join(CONFIG_DIR);
    dir.is_dir().then_some(dir)
}

fn read_parts(dir: &Path) -> Result<(Option<String>, String, FileConfig)> {
    let instructions = std::fs::read_to_string(dir.join("instructions.md")).ok();
    let raw_toml = std::fs::read_to_string(dir.join("config.toml")).unwrap_or_default();
    let file: FileConfig = if raw_toml.trim().is_empty() {
        FileConfig::default()
    } else {
        toml::from_str(&raw_toml).context("invalid .lumo-config/config.toml")?
    };
    Ok((instructions, raw_toml, file))
}

fn content_hash(instructions: &Option<String>, raw_toml: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"instructions:");
    h.update(instructions.as_deref().unwrap_or("").as_bytes());
    h.update(b"config:");
    h.update(raw_toml.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// --- approval store: config-dir path -> approved content hash ---

fn approvals_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("lumo-cli").join("approved-configs.json"))
}

fn load_approvals() -> std::collections::HashMap<String, String> {
    approvals_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_approval(dir: &Path, hash: &str) -> Result<()> {
    let mut map = load_approvals();
    map.insert(dir.to_string_lossy().into_owned(), hash.to_string());
    if let Some(path) = approvals_path() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(&map)?)?;
    }
    Ok(())
}

fn is_approved(dir: &Path, hash: &str) -> bool {
    load_approvals()
        .get(&dir.to_string_lossy().into_owned())
        .map(|h| h == hash)
        .unwrap_or(false)
}

/// Dangerous settings the config would enable, for the approval prompt.
fn dangers(file: &FileConfig) -> Vec<&'static str> {
    let mut v = Vec::new();
    if file.yolo == Some(true) {
        v.push("--yolo: auto-approve file writes and shell commands (no confirmation)");
    }
    if file.no_sandbox == Some(true) {
        v.push("--no-sandbox: disable the Landlock sandbox for tool commands");
    }
    if file.commit == Some(true) {
        v.push("--commit: commit to the git repository after each turn");
    }
    v
}

/// Load the project config, asking for approval when needed. Returns None when
/// there is no config, when the user declines, or when running non-interactively
/// without a prior approval.
pub fn load(project: &Path) -> Result<Option<ProjectConfig>> {
    let Some(dir) = locate(project) else {
        return Ok(None);
    };
    let (instructions, raw_toml, file) = read_parts(&dir)?;
    if instructions.is_none() && raw_toml.trim().is_empty() {
        return Ok(None); // empty config dir
    }
    let hash = content_hash(&instructions, &raw_toml);

    if is_approved(&dir, &hash) {
        eprintln!(
            "{} loaded {} (previously approved)",
            "config:".green(),
            dir.display()
        );
        return Ok(Some(ProjectConfig { instructions, file }));
    }

    // Not approved: summarise and ask. Fail closed without a terminal.
    let danger = dangers(&file);
    eprintln!(
        "{} found a project config at {}",
        "config:".bold(),
        dir.display()
    );
    if let Some(text) = &instructions {
        eprintln!(
            "  - instructions.md ({} lines) will be added to the system prompt",
            text.lines().count()
        );
    }
    describe_settings(&file);
    if !danger.is_empty() {
        eprintln!(
            "  {}",
            "this config would enable dangerous behaviour:".red().bold()
        );
        for d in &danger {
            eprintln!("    {} {d}", "⚠".red());
        }
    }

    if !std::io::stdin().is_terminal() {
        eprintln!(
            "  {} not a terminal; skipping. Approve it once with `lumo config allow`.",
            "note:".yellow()
        );
        return Ok(None);
    }

    let prompt = if danger.is_empty() {
        "Load this project config? [y/N]: "
    } else {
        "Load this config, INCLUDING the dangerous settings above? [y/N]: "
    };
    eprint!("{}", prompt.bold());
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
        eprintln!("  skipped; running without the project config.");
        return Ok(None);
    }
    save_approval(&dir, &hash)?;
    eprintln!(
        "  {} approved and remembered (re-asked only if the file changes)",
        "✓".green()
    );
    Ok(Some(ProjectConfig { instructions, file }))
}

fn describe_settings(file: &FileConfig) {
    let mut bits = Vec::new();
    if let Some(m) = &file.model {
        bits.push(format!("model={m}"));
    }
    if let Some(t) = &file.tools {
        bits.push(format!("tools=[{}]", t.join(",")));
    }
    if file.think == Some(true) {
        bits.push("think".into());
    }
    if file.ro == Some(true) {
        bits.push("ro".into());
    }
    if file.noexec == Some(true) {
        bits.push("noexec".into());
    }
    if let Some(n) = file.max_turns {
        bits.push(format!("max_turns={n}"));
    }
    if !bits.is_empty() {
        eprintln!("  - settings: {}", bits.join(", "));
    }
}

/// `lumo config show`: print what the config would apply, without loading it.
pub fn show(project: &Path) -> Result<()> {
    let Some(dir) = locate(project) else {
        println!("no {CONFIG_DIR}/ in this project");
        return Ok(());
    };
    let (instructions, raw_toml, file) = read_parts(&dir)?;
    let hash = content_hash(&instructions, &raw_toml);
    println!("config dir: {}", dir.display());
    println!(
        "approved:   {}",
        if is_approved(&dir, &hash) {
            "yes"
        } else {
            "no"
        }
    );
    if let Some(text) = &instructions {
        println!("instructions.md: {} lines", text.lines().count());
    }
    describe_settings(&file);
    let danger = dangers(&file);
    if !danger.is_empty() {
        println!("dangerous settings:");
        for d in &danger {
            println!("  - {d}");
        }
    }
    Ok(())
}

/// `lumo config allow`: approve the current config non-interactively.
pub fn allow(project: &Path) -> Result<()> {
    let Some(dir) = locate(project) else {
        anyhow::bail!("no {CONFIG_DIR}/ in this project");
    };
    let (instructions, raw_toml, file) = read_parts(&dir)?;
    let hash = content_hash(&instructions, &raw_toml);
    let danger = dangers(&file);
    if !danger.is_empty() {
        println!("{}", "note: this config enables:".yellow());
        for d in &danger {
            println!("  - {d}");
        }
    }
    save_approval(&dir, &hash)?;
    println!("approved {}", dir.display());
    Ok(())
}

/// `lumo config reset`: forget the approval for this project's config.
pub fn reset(project: &Path) -> Result<()> {
    let Some(dir) = locate(project) else {
        println!("no {CONFIG_DIR}/ in this project");
        return Ok(());
    };
    let key = dir.to_string_lossy().into_owned();
    let mut map = load_approvals();
    if map.remove(&key).is_some() {
        if let Some(path) = approvals_path() {
            std::fs::write(&path, serde_json::to_string_pretty(&map)?)?;
        }
        println!("approval for {} removed", dir.display());
    } else {
        println!("no approval was stored for {}", dir.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_changes_with_content() {
        let a = content_hash(&Some("x".into()), "model='a'");
        let b = content_hash(&Some("x".into()), "model='b'");
        assert_ne!(a, b);
        let c = content_hash(&Some("x".into()), "model='a'");
        assert_eq!(a, c);
    }

    #[test]
    fn dangers_flagged() {
        let f = FileConfig {
            yolo: Some(true),
            no_sandbox: Some(true),
            ..Default::default()
        };
        let d = dangers(&f);
        assert_eq!(d.len(), 2);
        assert!(dangers(&FileConfig::default()).is_empty());
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(toml::from_str::<FileConfig>("surprise = true").is_err());
        assert!(toml::from_str::<FileConfig>("model = \"lumo-max\"").is_ok());
    }
}
