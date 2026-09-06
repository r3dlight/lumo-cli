// SPDX-License-Identifier: GPL-3.0-or-later
//! Lumo PGP public-key management: layered source, rotation detection, update.
//!
//! The request AES key is encrypted TO this key, so it is a trust anchor: a
//! substituted key would let a man-in-the-middle read your prompts. We never
//! blindly adopt a key fetched from the network: the embedded default is
//! pinned, a file override is an act of the user, and adopting a fetched key requires
//! explicit confirmation.
//!
//! Active key resolution (first that loads wins):
//!   1. `$LUMO_PUBKEY_PATH`, a file path
//!   2. `~/.config/lumo-cli/lumo-pubkey.asc`, the config override
//!   3. the embedded default ([`crate::protocol::LUMO_PGP_PUBLIC_KEY`])
//!
//! Rotation: Proton serves no runtime key endpoint (the web app embeds the key
//! at build time), so the canonical source we compare against is Proton's
//! open-source repo. `key check`/startup compares fingerprints and warns;
//! `key update` shows the candidate and, on confirmation, writes it to the
//! config override.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyDetails;

/// Canonical key source: Proton's official open-source web client. Overridable
/// with `$LUMO_PUBKEY_URL` or `key update --url`.
pub const CANONICAL_KEY_URL: &str =
    "https://raw.githubusercontent.com/ProtonMail/WebClients/main/packages/lumo-api-client/keys.ts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Embedded,
    Env(PathBuf),
    ConfigFile(PathBuf),
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::Embedded => write!(f, "embedded default"),
            KeySource::Env(p) => write!(f, "$LUMO_PUBKEY_PATH ({})", p.display()),
            KeySource::ConfigFile(p) => write!(f, "config file ({})", p.display()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub user_id: String,
    pub created: String,
}

pub fn config_key_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("lumo-cli").join("lumo-pubkey.asc"))
}

/// Resolve the active armored key and where it came from. Never fails: a broken
/// override falls back to the embedded default (with the returned source still
/// pointing at the override so the caller can warn).
pub fn active_key() -> (String, KeySource) {
    if let Ok(p) = std::env::var("LUMO_PUBKEY_PATH") {
        let path = PathBuf::from(&p);
        if let Ok(s) = std::fs::read_to_string(&path) {
            return (s, KeySource::Env(path));
        }
    }
    if let Some(path) = config_key_path()
        && let Ok(s) = std::fs::read_to_string(&path)
    {
        return (s, KeySource::ConfigFile(path));
    }
    (
        crate::protocol::LUMO_PGP_PUBLIC_KEY.to_string(),
        KeySource::Embedded,
    )
}

/// Parse an armored public key, returning the key and a human-readable summary.
pub fn parse(armored: &str) -> Result<(SignedPublicKey, KeyInfo)> {
    let (key, _headers) =
        SignedPublicKey::from_string(armored).context("not a valid armored OpenPGP public key")?;
    let info = info_of(&key);
    Ok((key, info))
}

fn info_of(key: &SignedPublicKey) -> KeyInfo {
    let fingerprint = format!("{:X}", key.fingerprint());
    let user_id = key
        .details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_else(|| "(no user id)".into());
    let created = ymd(key.primary_key.created_at().as_secs());
    KeyInfo {
        fingerprint,
        user_id,
        created,
    }
}

/// Format a Unix timestamp (seconds) as `YYYY-MM-DD` (UTC), no dependency.
/// Howard Hinnant's civil_from_days algorithm.
// Overflow is impossible: `secs` is a u32, so `days` <= 49_710 and every
// intermediate stays far below 2^40 in an i64 (ANSSI LANG-INTEGER-OVERFLOW).
#[allow(clippy::arithmetic_side_effects)]
fn ymd(secs: u32) -> String {
    let days = i64::from(secs / 86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Fetch the canonical key text and extract the first PGP public-key block.
pub async fn fetch_canonical(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let body = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("fetching {url}"))?
        .text()
        .await?;
    extract_pgp_block(&body).ok_or_else(|| anyhow!("no PGP public key block found at {url}"))
}

/// Pull the first `-----BEGIN PGP PUBLIC KEY BLOCK----- … END …` out of text
/// (the canonical source embeds it in a TypeScript string literal).
pub fn extract_pgp_block(text: &str) -> Option<String> {
    const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
    let rest = text.get(text.find(BEGIN)?..)?;
    let end = rest.find(END)?.saturating_add(END.len());
    Some(rest.get(..end)?.to_string())
}

/// Persist an armored key to the config override path.
pub fn save_to_config(armored: &str) -> Result<PathBuf> {
    let path = config_key_path().ok_or_else(|| anyhow!("cannot determine config directory"))?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("config key path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, armored)?;
    Ok(path)
}

/// Remove the config override, reverting to the embedded default.
pub fn clear_config() -> Result<bool> {
    let Some(path) = config_key_path() else {
        return Ok(false);
    };
    if path.exists() {
        std::fs::remove_file(&path)?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ymd_known_dates() {
        assert_eq!(ymd(0), "1970-01-01");
        // 2025-04-28 11:22:21 UTC = creation of the embedded Lumo key.
        assert_eq!(ymd(1_745_838_141), "2025-04-28");
    }

    #[test]
    fn embedded_key_parses_with_expected_uid() {
        let (_, info) = parse(crate::protocol::LUMO_PGP_PUBLIC_KEY).unwrap();
        assert!(info.user_id.contains("Proton Lumo"));
        assert_eq!(info.fingerprint, "F032A1169DDFF8EDA728E59A9A74C3EF61514A2A");
        assert_eq!(info.created, "2025-04-28");
    }

    #[test]
    fn extract_from_ts_literal() {
        let ts = "export const K = `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----`;";
        let block = extract_pgp_block(ts).unwrap();
        assert!(block.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(block.ends_with("-----END PGP PUBLIC KEY BLOCK-----"));
    }
}
