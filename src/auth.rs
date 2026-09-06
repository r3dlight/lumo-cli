// SPDX-License-Identifier: GPL-3.0-or-later
//! Proton account authentication (SRP) and session management.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use proton_srp::{SRPAuth, SRPProofB64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Persisted Proton session tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub username: String,
}

impl Session {
    pub fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("cannot determine config directory"))?
            .join("lumo-cli");
        Ok(dir.join("session.json"))
    }

    pub fn load() -> Result<Option<Session>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        Ok(Some(serde_json::from_str(&data)?))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let dir = path
            .parent()
            .ok_or_else(|| anyhow!("session path has no parent directory"))?;
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn delete() -> Result<bool> {
        let path = Self::path()?;
        if path.exists() {
            std::fs::remove_file(&path)?;
            return Ok(true);
        }
        Ok(false)
    }
}

/// Proton API base (same host the web app uses; supports the modern v4 flow).
const ACCOUNT_API: &str = "https://account.proton.me/api";

/// A realistic desktop-browser User-Agent. Proton's anti-abuse scoring treats
/// bot-like clients (empty UA, `appversion: Other`) far more aggressively; a
/// normal browser fingerprint plus the proper unauth-session flow is what keeps
/// a residential login from hitting the CAPTCHA.
const BROWSER_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

/// Fallback account web app version if the live one can't be fetched.
const ACCOUNT_APPVERSION_FALLBACK: &str = "web-account@5.0.413.0";

/// Fetch the current account web app version so `x-pm-appversion` matches a real
/// deploy (stale versions can be rejected with code 5003). Best-effort.
async fn account_appversion(client: &reqwest::Client) -> String {
    let fetched = async {
        let v: Value = client
            .get("https://account.proton.me/assets/version.json")
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        let ver = v.get("version").and_then(Value::as_str)?;
        Some(format!("web-account@{ver}"))
    }
    .await;
    fetched.unwrap_or_else(|| ACCOUNT_APPVERSION_FALLBACK.to_string())
}

/// Build a browser-like account client (cookie jar + realistic headers).
fn account_client(appversion: &str) -> Result<reqwest::Client> {
    use reqwest::header::HeaderValue;
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        "accept",
        HeaderValue::from_static("application/vnd.protonmail.v1+json"),
    );
    h.insert("content-type", HeaderValue::from_static("application/json"));
    // Only the app version is dynamic; reject a value with invalid header bytes
    // instead of panicking.
    h.insert(
        "x-pm-appversion",
        HeaderValue::from_str(appversion).context("invalid x-pm-appversion value")?,
    );
    h.insert("x-pm-locale", HeaderValue::from_static("en_US"));
    h.insert("x-enforce-unauthsession", HeaderValue::from_static("true"));
    h.insert(
        "origin",
        HeaderValue::from_static("https://account.proton.me"),
    );
    h.insert(
        "referer",
        HeaderValue::from_static("https://account.proton.me/"),
    );
    Ok(reqwest::Client::builder()
        .user_agent(BROWSER_UA)
        .default_headers(h)
        .cookie_store(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

/// An anonymous session, required before the SRP handshake in the v4 flow.
struct UnauthSession {
    uid: String,
    access_token: String,
    refresh_token: String,
}

async fn create_unauth_session(client: &reqwest::Client) -> Result<UnauthSession> {
    let resp: Value = client
        .post(format!("{ACCOUNT_API}/auth/v4/sessions"))
        .json(&json!({}))
        .send()
        .await?
        .json()
        .await
        .context("auth/v4/sessions: invalid response")?;
    let resp = check_proton(resp, "creating anonymous session")?;
    Ok(UnauthSession {
        uid: resp
            .get("UID")
            .and_then(Value::as_str)
            .context("missing UID")?
            .to_string(),
        access_token: resp
            .get("AccessToken")
            .and_then(Value::as_str)
            .context("missing AccessToken")?
            .to_string(),
        refresh_token: resp
            .get("RefreshToken")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

/// Check a Proton API JSON response `Code` field; return the body on success.
fn check_proton(body: Value, what: &str) -> Result<Value> {
    let code = body.get("Code").and_then(Value::as_i64).unwrap_or(0);
    if code == 1000 || code == 1001 {
        return Ok(body);
    }
    let err = body
        .get("Error")
        .and_then(Value::as_str)
        .unwrap_or("unknown error");
    // 9001 = human verification (CAPTCHA) required. Proton's CAPTCHA cannot be
    // solved from a third-party CLI (its verify page refuses to embed outside
    // *.proton.me), so guide the user to the workarounds instead.
    if code == 9001 {
        let methods = body
            .pointer("/Details/HumanVerificationMethods")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        bail!(
            "Proton asked for human verification (CAPTCHA) for this login (Code 9001, methods: {methods}).\n\
             This should be uncommon now that lumo-cli logs in like the web app. Try:\n\n\
               • Run `./lumo-cli login` again; the challenge is often transient.\n\
               • Log in once at https://account.proton.me in a browser on this network, then retry.\n\
               • Avoid VPN/Tor/datacenter IPs for the login (they get challenged far more).\n\n\
             If it still won't pass, reuse an already-authenticated session instead:\n\
               • `./lumo-cli login --import-rclone`   (if you use rclone with Proton Drive)\n\
               • `./lumo-cli login --paste`           (paste UID + tokens from a Proton session)\n\
             See `./lumo-cli login --help`."
        );
    }
    bail!("{what} failed (Code {code}): {err}");
}

/// Import a session from an rclone Proton Drive remote. rclone stores
/// `client_uid` / `client_access_token` / `client_refresh_token` in plaintext
/// in its config after a login that already passed the CAPTCHA.
pub fn import_from_rclone(remote: Option<&str>, config_path: Option<&str>) -> Result<Session> {
    let path = match config_path {
        Some(p) => PathBuf::from(p),
        None => dirs::config_dir()
            .ok_or_else(|| anyhow!("cannot determine config directory"))?
            .join("rclone")
            .join("rclone.conf"),
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read rclone config at {}", path.display()))?;

    let sections = parse_ini(&text);
    // Pick the requested remote, or the first one carrying Proton tokens.
    let (name, kv) = match remote {
        Some(r) => sections
            .iter()
            .find(|(n, _)| n == r)
            .ok_or_else(|| anyhow!("remote `{r}` not found in {}", path.display()))?,
        None => sections
            .iter()
            .find(|(_, kv)| kv.contains_key("client_uid") && kv.contains_key("client_access_token"))
            .ok_or_else(|| {
                anyhow!(
                    "no Proton remote with a saved session found in {}. \
                     Configure `rclone config` with a protondrive remote first.",
                    path.display()
                )
            })?,
    };

    let get = |k: &str| {
        kv.get(k)
            .map(String::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let uid = get("client_uid");
    let access_token = get("client_access_token");
    let refresh_token = get("client_refresh_token");
    if uid.is_empty() || access_token.is_empty() || refresh_token.is_empty() {
        bail!(
            "remote `{name}` has no saved Proton session tokens \
             (client_uid / client_access_token / client_refresh_token are empty). \
             Run an rclone operation on it once to populate them."
        );
    }
    Ok(Session {
        uid,
        access_token,
        refresh_token,
        username: kv
            .get("username")
            .cloned()
            .unwrap_or_else(|| format!("rclone:{name}")),
    })
}

/// Minimal INI parser: returns [(section, {key: value})]. Ignores comments.
fn parse_ini(text: &str) -> Vec<(String, std::collections::HashMap<String, String>)> {
    let mut out: Vec<(String, std::collections::HashMap<String, String>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                out.push((name.trim().to_string(), Default::default()));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && let Some((_, kv)) = out.last_mut()
        {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// Log in with SRP. `totp_provider` is invoked if the account has TOTP 2FA.
///
/// `captcha_token` is an optional human-verification token (obtained by solving
/// Proton's CAPTCHA in a browser and copying the `x-pm-human-verification-token`
/// request header); when set, it is attached so a login that would otherwise
/// return 9001 can proceed.
pub async fn login(
    username: &str,
    password: &str,
    captcha_token: Option<&str>,
    totp_provider: impl Fn() -> Result<String>,
) -> Result<Session> {
    // Build a browser-like client (realistic UA + current app version + cookie
    // jar). This, plus the unauth-session flow below, is what a normal web login
    // does, and what keeps a residential login from tripping the CAPTCHA.
    let bootstrap = reqwest::Client::builder()
        .user_agent(BROWSER_UA)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let appversion = account_appversion(&bootstrap).await;
    let client = account_client(&appversion)?;

    // Human-verification headers to attach to the SRP calls, if provided.
    let hv = |mut req: reqwest::RequestBuilder| {
        if let Some(token) = captcha_token {
            req = req
                .header("x-pm-human-verification-token", token)
                .header("x-pm-human-verification-token-type", "captcha");
        }
        req
    };

    // Step 0: anonymous session (required before the SRP handshake in v4).
    let unauth = create_unauth_session(&client).await?;
    let with_session = |req: reqwest::RequestBuilder| {
        req.header("x-pm-uid", &unauth.uid)
            .bearer_auth(&unauth.access_token)
    };

    // Step 1: fetch the SRP challenge.
    let info: Value = hv(with_session(
        client
            .post(format!("{ACCOUNT_API}/auth/v4/info"))
            .json(&json!({ "Username": username, "Intent": "Proton" })),
    ))
    .send()
    .await?
    .json()
    .await
    .context("auth/v4/info: invalid response")?;
    let info = check_proton(info, "auth/v4/info")?;

    let modulus = info
        .get("Modulus")
        .and_then(Value::as_str)
        .context("missing Modulus")?;
    let server_ephemeral = info
        .get("ServerEphemeral")
        .and_then(Value::as_str)
        .context("missing ServerEphemeral")?;
    let salt = info
        .get("Salt")
        .and_then(Value::as_str)
        .context("missing Salt")?;
    let srp_session = info
        .get("SRPSession")
        .and_then(Value::as_str)
        .context("missing SRPSession")?;
    let version_i64 = info
        .get("Version")
        .and_then(Value::as_i64)
        .context("missing Version")?;
    let version = u8::try_from(version_i64)
        .map_err(|_| anyhow!("unexpected SRP Version value: {version_i64}"))?;

    // Step 2: compute SRP proofs locally (the password never leaves the machine).
    let auth = SRPAuth::with_pgp(
        Some(username),
        password,
        version
            .try_into()
            .map_err(|e| anyhow!("unsupported SRP version {version}: {e:?}"))?,
        salt,
        modulus,
        server_ephemeral,
    )
    .map_err(|e| anyhow!("SRP setup failed: {e:?}"))?;
    let proofs: SRPProofB64 = auth
        .generate_proofs()
        .map_err(|e| anyhow!("SRP proof generation failed: {e:?}"))?
        .into();

    // Step 3: exchange proofs for tokens (upgrades the session in place).
    let auth_resp: Value = hv(with_session(
        client.post(format!("{ACCOUNT_API}/auth/v4")).json(&json!({
            "Username": username,
            "ClientEphemeral": proofs.client_ephemeral,
            "ClientProof": proofs.client_proof,
            "SRPSession": srp_session,
        })),
    ))
    .send()
    .await?
    .json()
    .await
    .context("auth/v4: invalid response")?;
    let auth_resp = check_proton(auth_resp, "authentication")?;

    // Verify the server knows the password too (mutual authentication).
    if let Some(server_proof) = auth_resp.get("ServerProof").and_then(Value::as_str)
        && !proofs.compare_server_proof(server_proof)
    {
        bail!("server proof mismatch: refusing to continue (possible MITM)");
    }

    // The authenticated tokens; fall back to the (now-upgraded) unauth session.
    let session = Session {
        uid: auth_resp
            .get("UID")
            .and_then(Value::as_str)
            .unwrap_or(&unauth.uid)
            .to_string(),
        access_token: auth_resp
            .get("AccessToken")
            .and_then(Value::as_str)
            .unwrap_or(&unauth.access_token)
            .to_string(),
        refresh_token: auth_resp
            .get("RefreshToken")
            .and_then(Value::as_str)
            .unwrap_or(&unauth.refresh_token)
            .to_string(),
        username: username.to_string(),
    };

    // Step 4: TOTP 2FA if enabled on the account.
    let twofa_enabled = auth_resp
        .pointer("/2FA/Enabled")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if twofa_enabled & 1 != 0 {
        let code = totp_provider()?;
        let resp: Value = client
            .post(format!("{ACCOUNT_API}/auth/v4/2fa"))
            .header("x-pm-uid", &session.uid)
            .bearer_auth(&session.access_token)
            .json(&json!({ "TwoFactorCode": code.trim() }))
            .send()
            .await?
            .json()
            .await
            .context("auth/v4/2fa: invalid response")?;
        check_proton(resp, "2FA verification")?;
    } else if twofa_enabled != 0 {
        bail!("this account requires FIDO2/U2F 2FA, which lumo-cli does not support yet");
    }

    Ok(session)
}

/// Refresh an expired access token. Returns the updated session (also persisted).
pub async fn refresh(session: &Session) -> Result<Session> {
    let client = account_client(ACCOUNT_APPVERSION_FALLBACK)?;

    let resp: Value = client
        .post(format!("{ACCOUNT_API}/auth/v4/refresh"))
        .header("x-pm-uid", &session.uid)
        .bearer_auth(&session.access_token)
        .json(&json!({
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": session.refresh_token,
            "RedirectURI": "https://account.proton.me",
        }))
        .send()
        .await?
        .json()
        .await
        .context("auth/v4/refresh: invalid response")?;
    let resp = check_proton(resp, "token refresh")?;

    let updated = Session {
        uid: resp
            .get("UID")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| session.uid.clone()),
        access_token: resp
            .get("AccessToken")
            .and_then(Value::as_str)
            .context("missing AccessToken in refresh response")?
            .to_string(),
        refresh_token: resp
            .get("RefreshToken")
            .and_then(Value::as_str)
            .context("missing RefreshToken in refresh response")?
            .to_string(),
        username: session.username.clone(),
    };
    updated.save()?;
    Ok(updated)
}
