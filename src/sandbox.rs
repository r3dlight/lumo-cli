// SPDX-License-Identifier: GPL-3.0-or-later
//! Landlock sandboxing for the agent's tool subprocesses.
//!
//! Every shell/search subprocess is launched through lumo-cli itself
//! (`lumo-cli sandbox-exec -- <program> <args…>`): that child applies a
//! Landlock ruleset to itself with the `landlock` crate (no `unsafe`, no
//! external binary) and then `exec`s the requested program. The kernel
//! (Landlock LSM) then confines it to the project (rw+exec), toolchain caches
//! and read-only system dirs (SSH keys, `~/.aws`, other projects and `$HOME`
//! itself stay invisible), with outbound TCP limited to 443/80/53. Secrets are
//! scrubbed from the child environment before launch, and the child gets a
//! private `TMPDIR` and private XDG directories so that nothing it writes
//! lands in the user's real configuration. Restrictions are inherited by all
//! descendants and cannot be lifted once applied.
//!
//! Kernel compatibility: the parent probes the running kernel once and pins
//! the policy to the highest Landlock ABI it supports (5.13 and newer). The
//! child then requires exactly that ABI, so it never silently enforces less
//! than what was announced. Features an older kernel lacks (TCP filtering
//! before 6.7, scoping before 6.12, and so on) are reported as explicit caveats.
//!
//! Two details keep a confined process from loosening the next command's
//! rules: the policy travels as JSON in the `LUMO_SANDBOX_POLICY` environment
//! variable, never through a file the sandbox could write to; and the child
//! is started from a file descriptor of this executable opened at setup, so
//! replacing the binary on disk (which a project or toolchain directory with
//! write access could allow) has no effect on later launches.
//!
//! lumo-cli's own file tools (read/write/edit) are not subprocesses, so Landlock
//! does not cover them; when the sandbox is active they are additionally kept
//! within the project root by [`Sandbox::confine`].

use std::fs::{DirBuilder, File};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, path_beneath_rules,
};
use serde::{Deserialize, Serialize};

/// Environment variable carrying the serialized [`Policy`] to the child.
pub const POLICY_ENV: &str = "LUMO_SANDBOX_POLICY";

/// Landlock ABIs that change what the policy can enforce, newest first. ABI 7
/// (audit flags) and 8 (`all_threads`) add nothing the policy uses, so a
/// kernel at those levels is pinned to ABI 6.
///
/// | ABI | Linux | what it adds for the policy |
/// |-----|-------|-----------------------------|
/// | 1 | 5.13 | file access rights |
/// | 2 | 5.19 | `refer` (rename/link across directories) |
/// | 3 | 6.2 | `truncate` |
/// | 4 | 6.7 | TCP bind/connect |
/// | 5 | 6.10 | device ioctls |
/// | 6 | 6.12 | scoping of signals and abstract UNIX sockets |
/// | 9 | 7.1 | pathname UNIX socket connections |
const ABI_LEVELS: &[ABI] = &[
    ABI::V9,
    ABI::V6,
    ABI::V5,
    ABI::V4,
    ABI::V3,
    ABI::V2,
    ABI::V1,
];

/// Outbound TCP ports the sandbox may connect to: HTTPS, HTTP, DNS. Nothing
/// may listen.
const TCP_CONNECT: &[u16] = &[443, 80, 53];

/// Highest ABI level of [`ABI_LEVELS`] the running kernel fully supports, or
/// `None` without Landlock (kernel before 5.13, or disabled at boot). Only
/// creates rulesets, never enforces one.
pub fn detect_abi() -> Option<ABI> {
    ABI_LEVELS
        .iter()
        .copied()
        .find(|abi| handled_ruleset(*abi).is_ok_and(|r| r.create().is_ok()))
}

/// A ruleset handling every access right of `abi`, as a hard requirement:
/// any bit the kernel does not know is an error, never a silent downgrade.
fn handled_ruleset(abi: ABI) -> Result<Ruleset> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .with_context(|| {
            format!(
                "Landlock: filesystem rights of ABI {} unsupported",
                abi as u8
            )
        })?;
    if abi >= ABI::V4 {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(abi))
            .context("Landlock: TCP restrictions unsupported by this kernel")?;
    }
    if abi >= ABI::V6 {
        ruleset = ruleset
            .scope(Scope::from_all(abi))
            .context("Landlock: scoping unsupported by this kernel")?;
    }
    Ok(ruleset)
}

/// What the policy cannot enforce at `abi`, for the user to know.
pub fn caveats(abi: ABI) -> Vec<&'static str> {
    let mut v = Vec::new();
    if abi < ABI::V2 {
        v.push("renaming or linking across directories is always denied (kernel < 5.19)");
    }
    if abi < ABI::V3 {
        v.push("truncate(2) of files outside the sandbox is not denied (kernel < 6.2)");
    }
    if abi < ABI::V4 {
        v.push("outbound TCP is not restricted (kernel < 6.7)");
    }
    if abi < ABI::V5 {
        v.push("device ioctls are not restricted (kernel < 6.10)");
    }
    if abi < ABI::V6 {
        v.push("signals and abstract UNIX sockets are not scoped (kernel < 6.12)");
    }
    v
}

fn abi_from_u8(n: u8) -> Option<ABI> {
    ABI_LEVELS.iter().copied().find(|abi| *abi as u8 == n)
}

/// Access granted beneath a path. Every handled access not listed is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsAccess {
    /// read_file + read_dir + execute: system hierarchies, toolchains.
    Rx,
    /// Everything except execute: caches, devices, workspaces.
    Rw,
    /// Everything: the project (default mode), toolchain trees.
    Rwx,
    /// read_file + read_dir only.
    Ro,
    /// read_file + read_dir + refer (`/etc`, to let tools link into it).
    RoRefer,
    /// read_file only (single files such as `~/.gitconfig`).
    File,
}

impl FsAccess {
    /// The rights for this level, limited to those `abi` handles (a rule may
    /// not grant a right the ruleset does not know).
    fn flags(self, abi: ABI) -> BitFlags<AccessFs> {
        let all = AccessFs::from_all(abi);
        let wanted = match self {
            FsAccess::Rx => AccessFs::from_read(abi),
            FsAccess::Rw => all & !AccessFs::Execute,
            FsAccess::Rwx => all,
            FsAccess::Ro => AccessFs::ReadFile | AccessFs::ReadDir,
            FsAccess::RoRefer => AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Refer,
            FsAccess::File => AccessFs::ReadFile.into(),
        };
        wanted & all
    }
}

/// One `path_beneath` rule: `access` beneath each of `paths`. Missing paths
/// are skipped (a toolchain cache that does not exist yet grants nothing).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FsRule {
    paths: Vec<PathBuf>,
    access: FsAccess,
}

/// The complete Landlock policy, built by the parent and enforced by the
/// re-executed child. Deny-by-default: every filesystem, TCP and scope access
/// known to `abi` is handled, and only these rules grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Policy {
    abi: u8,
    fs: Vec<FsRule>,
    tcp_connect: Vec<u16>,
}

impl Policy {
    fn abi(&self) -> Result<ABI> {
        abi_from_u8(self.abi)
            .ok_or_else(|| anyhow!("sandbox policy: unknown ABI level {}", self.abi))
    }

    /// Create the ruleset and add every rule, without enforcing it.
    fn build(&self) -> Result<RulesetCreated> {
        let abi = self.abi()?;
        let mut created = handled_ruleset(abi)?
            .create()
            .context("Landlock: cannot create ruleset")?;
        for rule in &self.fs {
            created = created
                .add_rules(path_beneath_rules(&rule.paths, rule.access.flags(abi)))
                .with_context(|| format!("Landlock: adding rule {rule:?}"))?;
        }
        if abi >= ABI::V4 {
            for port in &self.tcp_connect {
                created = created
                    .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                    .with_context(|| format!("Landlock: allowing TCP connect to port {port}"))?;
            }
        }
        Ok(created)
    }

    /// Enforce the policy on the calling thread. Fails closed: anything short
    /// of a fully enforced ruleset with `no_new_privs` is an error.
    fn enforce(&self) -> Result<()> {
        let status = self
            .build()?
            .restrict_self()
            .context("Landlock: landlock_restrict_self failed")?;
        if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
            bail!(
                "Landlock: sandbox not fully enforced (ruleset {:?}, no_new_privs {}); refusing to run",
                status.ruleset,
                status.no_new_privs
            );
        }
        Ok(())
    }
}

/// Entry point of the hidden `sandbox-exec` subcommand: read the policy from
/// [`POLICY_ENV`], confine this process, then replace it with `argv`. Must be
/// called on the thread that will `exec` (Landlock restricts the calling
/// thread; `execve` carries that thread's domain over to the new program).
/// Only returns on error.
pub fn exec_confined(argv: &[String]) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .filter(|(p, _)| !p.is_empty())
        .ok_or_else(|| anyhow!("sandbox-exec: no program given"))?;
    let raw = std::env::var(POLICY_ENV)
        .with_context(|| format!("sandbox-exec: {POLICY_ENV} not set (internal use only)"))?;
    let policy: Policy = serde_json::from_str(&raw).context("sandbox-exec: invalid policy")?;
    policy.enforce()?;
    // Everything below runs confined. `exec` only returns on failure.
    let err = Command::new(program)
        .args(args)
        .env_remove(POLICY_ENV)
        .exec();
    Err(err).with_context(|| format!("sandbox-exec: cannot execute {program}"))
}

/// Base system access, following claude-island's profile: system
/// hierarchies read/exec, safe devices and the terminal read/write,
/// configuration and introspection read-only. `/tmp` is left out on purpose:
/// the child gets its own private `TMPDIR` instead.
fn base_rules() -> Vec<FsRule> {
    vec![
        FsRule {
            paths: paths(&["/bin", "/lib", "/lib64", "/sbin", "/usr", "/opt"]),
            access: FsAccess::Rx,
        },
        FsRule {
            paths: paths(&[
                "/dev/full",
                "/dev/null",
                "/dev/random",
                "/dev/urandom",
                "/dev/zero",
                "/dev/tty",
                "/dev/ptmx",
                "/dev/pts",
            ]),
            access: FsAccess::Rw,
        },
        FsRule {
            paths: paths(&["/etc"]),
            access: FsAccess::RoRefer,
        },
        FsRule {
            paths: paths(&["/proc", "/sys", "/run/systemd/resolve"]),
            access: FsAccess::Ro,
        },
    ]
}

fn paths(p: &[&str]) -> Vec<PathBuf> {
    p.iter().map(PathBuf::from).collect()
}

/// A toolchain environment: detected by marker files at the project root,
/// it opens the toolchain's own directories (relative to `$HOME`).
struct Env {
    name: &'static str,
    markers: &'static [&'static str],
    rules: &'static [(&'static [&'static str], FsAccess)],
}

const ENVS: &[Env] = &[
    Env {
        name: "rust",
        markers: &["Cargo.toml"],
        rules: &[(&[".cargo", ".rustup"], FsAccess::Rwx)],
    },
    Env {
        name: "node",
        markers: &["package.json"],
        rules: &[
            (&[".npm", ".cache/yarn"], FsAccess::Rw),
            (&[".local/share/pnpm"], FsAccess::Rwx),
            (&[".nvm"], FsAccess::Rx),
        ],
    },
    Env {
        name: "python3",
        markers: &[
            "pyproject.toml",
            "requirements.txt",
            "setup.py",
            "Pipfile",
            "uv.lock",
        ],
        rules: &[
            (&[".cache/pip", ".cache/uv"], FsAccess::Rw),
            (&[".local/share/uv"], FsAccess::Rwx),
        ],
    },
    Env {
        name: "go",
        markers: &["go.mod"],
        rules: &[
            (&["go"], FsAccess::Rwx),
            (&[".cache/go-build"], FsAccess::Rw),
        ],
    },
    Env {
        name: "c",
        markers: &["Makefile", "CMakeLists.txt", "configure.ac"],
        rules: &[
            (&[".cache/ccache", ".ccache"], FsAccess::Rw),
            (&[".conan2"], FsAccess::Rwx),
        ],
    },
];

/// Environments whose marker files are present at the project root.
fn detect_envs(project: &Path) -> Vec<&'static Env> {
    ENVS.iter()
        .filter(|env| env.markers.iter().any(|m| project.join(m).exists()))
        .collect()
}

/// Env vars scrubbed from the child (Landlock does not filter the environment).
const SCRUB_ENV: &[&str] = &[
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
    "AWS_ACCESS_KEY_ID",
    "AWS_PROFILE",
    // Common secret-bearing names that carry no matching suffix.
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NETRC",
];
/// Fail-closed suffixes: any variable whose uppercased name ends with one of
/// these is dropped (better a missing var in the sandbox than a leaked secret).
const SCRUB_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_SECRET",
    "_KEY",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIALS",
    "_CREDENTIAL",
    "_AUTH",
    "_APIKEY",
    "_BEARER",
    "_PRIVATE",
    "_CERT",
];

/// Whether a variable name looks secret-bearing (suffix rule).
fn is_secret_name(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    SCRUB_SUFFIXES.iter().any(|s| up.ends_with(s))
}

/// Remove secret-bearing variables before spawning a sandboxed child.
pub fn scrub_env(cmd: &mut Command) {
    for v in SCRUB_ENV {
        cmd.env_remove(v);
    }
    for (k, _) in std::env::vars_os() {
        if is_secret_name(&k.to_string_lossy()) {
            cmd.env_remove(&k);
        }
    }
}

/// FNV-1a 64 folded to 32 bits: a stable profile name for a path.
fn hash8(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let folded = (h & 0xffff_ffff) ^ (h >> 32);
    format!("{folded:08x}")
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

/// Access restrictions applied to the project tree, on top of the boundary.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mode {
    /// Read-only project: deny writes (for code review).
    pub ro: bool,
    /// Deny execve of project files (a speed bump; interpreters bypass it).
    pub noexec: bool,
}

/// XDG base directories redirected into the profile workspace:
/// (variable, subdirectory).
const XDG_DIRS: &[(&str, &str)] = &[
    ("XDG_CONFIG_HOME", "config"),
    ("XDG_DATA_HOME", "data"),
    ("XDG_STATE_HOME", "state"),
    ("XDG_CACHE_HOME", "cache"),
];

/// Variables pointing at the private per-run temporary directory.
const TMP_VARS: &[&str] = &["TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR"];

pub struct Sandbox {
    profile: String,
    project: PathBuf,
    envs: Vec<&'static str>,
    mode: Mode,
    abi: ABI,
    policy_json: String,
    /// Persistent per-profile XDG workspace.
    workspace: PathBuf,
    /// Private, per-run `TMPDIR`, removed on drop.
    tmp: PathBuf,
    /// This executable, held open so that launches use the file as it was at
    /// setup even if the path is later replaced.
    exe: File,
}

impl Sandbox {
    /// Build the policy for `project`, create its workspace and check that
    /// the kernel can enforce it. Fails without Landlock (kernel before 5.13
    /// or disabled); the caller decides whether that is fatal.
    pub fn setup(project: &Path, mode: Mode) -> Result<Self> {
        let abi = detect_abi().ok_or_else(|| {
            anyhow!("Landlock is unavailable (kernel older than 5.13, or disabled at boot)")
        })?;
        let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
        let project = project
            .canonicalize()
            .with_context(|| format!("cannot resolve project dir {}", project.display()))?;
        let exe = File::open("/proc/self/exe").context("cannot open own executable")?;

        let sel = detect_envs(&project);
        let env_names: Vec<&'static str> = sel.iter().map(|env| env.name).collect();
        let env_tag = if env_names.is_empty() {
            String::new()
        } else {
            format!("-{}", env_names.join("-"))
        };
        // Encode the mode in the name so workspaces for different modes coexist.
        let mode_tag = format!(
            "{}{}",
            if mode.ro { "-ro" } else { "" },
            if mode.noexec { "-noexec" } else { "" }
        );
        let name = format!(
            "lumo-{}{}{}-{}",
            slug(&project),
            env_tag,
            mode_tag,
            hash8(&project.to_string_lossy())
        );

        // Persistent workspace: private XDG directories for the sandboxed
        // tools, outside the project and outside the user's real config.
        let workspace = dirs::cache_dir()
            .ok_or_else(|| anyhow!("cannot determine cache directory"))?
            .join("lumo-cli/sandbox")
            .join(&name);
        for (_, sub) in XDG_DIRS {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(workspace.join(sub))
                .with_context(|| format!("creating workspace {}", workspace.display()))?;
        }
        // Private TMPDIR for this run, created 0700 atomically.
        let tmp = std::env::temp_dir().join(format!(
            "lumo-sandbox-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;

        // Project access, following claude-island's matrix:
        //   default  -> read/write + execute (builds, tests, generated binaries)
        //   --ro     -> read + execute, no write (code review)
        //   --noexec -> read/write, no execve of project files
        //   both     -> read only
        let project_access = match (mode.ro, mode.noexec) {
            (false, false) => FsAccess::Rwx,
            (true, false) => FsAccess::Rx,
            (false, true) => FsAccess::Rw,
            (true, true) => FsAccess::Ro,
        };

        let mut fs = base_rules();
        // Git identity, read-only, so `git` works inside the sandbox.
        fs.push(FsRule {
            paths: vec![home.join(".gitconfig")],
            access: FsAccess::File,
        });
        fs.push(FsRule {
            paths: vec![project.clone()],
            access: project_access,
        });
        fs.push(FsRule {
            paths: vec![workspace.clone()],
            access: FsAccess::Rw,
        });
        fs.push(FsRule {
            paths: vec![tmp.clone()],
            access: FsAccess::Rwx,
        });
        for env in &sel {
            for (rel, access) in env.rules {
                fs.push(FsRule {
                    paths: rel.iter().map(|r| home.join(r)).collect(),
                    access: *access,
                });
            }
        }
        let policy = Policy {
            abi: abi as u8,
            fs,
            tcp_connect: TCP_CONNECT.to_vec(),
        };
        // Dry run: create the ruleset (without enforcing it) so a bad rule is
        // reported now, not at the first tool call.
        policy.build()?;
        let policy_json = serde_json::to_string(&policy).context("serializing sandbox policy")?;

        Ok(Sandbox {
            profile: name,
            project,
            envs: env_names,
            mode,
            abi,
            policy_json,
            workspace,
            tmp,
            exe,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn profile_name(&self) -> &str {
        &self.profile
    }

    pub fn project(&self) -> &Path {
        &self.project
    }

    pub fn envs(&self) -> &[&'static str] {
        &self.envs
    }

    /// The Landlock ABI level the policy is pinned to.
    pub fn abi(&self) -> u8 {
        self.abi as u8
    }

    /// What this kernel cannot enforce (empty on Linux 6.12 and newer).
    pub fn caveats(&self) -> Vec<&'static str> {
        caveats(self.abi)
    }

    /// Build `<self> sandbox-exec -- <program>` with the policy in the
    /// environment, secrets scrubbed, and private TMPDIR/XDG directories.
    /// The caller appends the program's arguments.
    ///
    /// The executable is named through the descriptor opened at setup
    /// (`/proc/self/fd/N`, resolved in the child before its close-on-exec
    /// descriptors are closed), so the launch does not depend on the path
    /// still holding the same binary.
    pub fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(format!("/proc/self/fd/{}", self.exe.as_raw_fd()));
        cmd.args(["sandbox-exec", "--", program]);
        scrub_env(&mut cmd);
        cmd.env(POLICY_ENV, &self.policy_json);
        for (var, sub) in XDG_DIRS {
            cmd.env(var, self.workspace.join(sub));
        }
        for var in TMP_VARS {
            cmd.env(var, &self.tmp);
        }
        cmd
    }

    /// Reject a file path that escapes the project root. This mirrors the Landlock
    /// project confinement for lumo-cli's own (non-subprocess) file tools.
    pub fn confine(&self, path: &Path) -> Result<()> {
        // Compare against the canonical project root; for a not-yet-existing
        // file, canonicalize the nearest existing ancestor.
        let mut probe = path.to_path_buf();
        let resolved = loop {
            if let Ok(c) = probe.canonicalize() {
                break c;
            }
            match probe.parent() {
                Some(p) if p != probe => probe = p.to_path_buf(),
                _ => break path.to_path_buf(),
            }
        };
        if resolved.starts_with(&self.project) {
            Ok(())
        } else {
            bail!(
                "sandbox: {} is outside the project ({}); refused",
                path.display(),
                self.project.display()
            )
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // The private TMPDIR is worthless after this run. A failure is not
        // fatal but must not go unnoticed: leftovers accumulate in /tmp.
        if let Err(e) = std::fs::remove_dir_all(&self.tmp)
            && e.kind() != ErrorKind::NotFound
        {
            eprintln!(
                "warning: could not remove sandbox tmp dir {}: {e}",
                self.tmp.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn abi_levels_roundtrip() {
        for abi in ABI_LEVELS {
            assert_eq!(abi_from_u8(*abi as u8), Some(*abi));
        }
        assert_eq!(abi_from_u8(0), None);
        assert_eq!(
            abi_from_u8(7),
            None,
            "ABI 7 adds nothing and is not a level"
        );
    }

    #[test]
    fn flags_never_exceed_the_handled_set() {
        for abi in ABI_LEVELS {
            let all = AccessFs::from_all(*abi);
            for access in [
                FsAccess::Rx,
                FsAccess::Rw,
                FsAccess::Rwx,
                FsAccess::Ro,
                FsAccess::RoRefer,
                FsAccess::File,
            ] {
                let f = access.flags(*abi);
                assert!(!f.is_empty());
                assert!(all.contains(f), "{access:?} at ABI {abi:?}");
            }
        }
        assert!(!FsAccess::RoRefer.flags(ABI::V1).contains(AccessFs::Refer));
        assert!(FsAccess::RoRefer.flags(ABI::V2).contains(AccessFs::Refer));
        assert!(FsAccess::Rw.flags(ABI::V6).contains(AccessFs::IoctlDev));
        assert!(!FsAccess::Rw.flags(ABI::V6).contains(AccessFs::Execute));
    }

    #[test]
    fn caveats_shrink_with_newer_abis() {
        assert_eq!(caveats(ABI::V1).len(), 5);
        assert_eq!(caveats(ABI::V4).len(), 2);
        assert!(caveats(ABI::V6).is_empty());
        assert!(caveats(ABI::V9).is_empty());
    }

    #[test]
    fn secret_names() {
        assert!(is_secret_name("MY_API_KEY"));
        assert!(is_secret_name("npm_token"));
        assert!(is_secret_name("X_BEARER"));
        assert!(!is_secret_name("PATH"));
        assert!(!is_secret_name("TOKENIZER"));
    }

    /// Requires a Landlock kernel; skipped otherwise.
    fn setup_or_skip(mode: Mode) -> Option<Sandbox> {
        if detect_abi().is_none() {
            eprintln!("skipping: no Landlock on this kernel");
            return None;
        }
        Some(Sandbox::setup(Path::new("."), mode).expect("sandbox setup"))
    }

    #[test]
    fn command_carries_policy_and_private_dirs() {
        let Some(sb) = setup_or_skip(Mode::default()) else {
            return;
        };
        let cmd = sb.command("sh");
        let envs: std::collections::HashMap<_, _> = cmd.get_envs().collect();
        let get = |k: &str| envs.get(OsStr::new(k)).copied().flatten();
        assert_eq!(get(POLICY_ENV), Some(OsStr::new(sb.policy_json.as_str())));
        assert_eq!(get("TMPDIR"), Some(sb.tmp.as_os_str()));
        assert_eq!(
            get("XDG_CONFIG_HOME"),
            Some(sb.workspace.join("config").as_os_str())
        );
        // Scrubbed: present in the map with no value.
        assert_eq!(envs.get(OsStr::new("SSH_AUTH_SOCK")), Some(&None));
        assert!(sb.tmp.is_dir());
        assert!(
            cmd.get_program()
                .to_string_lossy()
                .starts_with("/proc/self/fd/")
        );
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            ["sandbox-exec", "--", "sh"]
        );
    }

    #[test]
    fn tmpdir_removed_on_drop() {
        let Some(sb) = setup_or_skip(Mode::default()) else {
            return;
        };
        let tmp = sb.tmp.clone();
        drop(sb);
        assert!(!tmp.exists());
    }

    #[test]
    fn policy_roundtrips() {
        let Some(sb) = setup_or_skip(Mode {
            ro: true,
            noexec: true,
        }) else {
            return;
        };
        let p: Policy = serde_json::from_str(&sb.policy_json).expect("valid json");
        assert_eq!(p.abi, sb.abi());
        let project =
            p.fs.iter()
                .find(|r| r.paths == [sb.project.clone()])
                .expect("project rule");
        assert_eq!(project.access, FsAccess::Ro);
        assert_eq!(p.tcp_connect, TCP_CONNECT);
        assert!(p.build().is_ok());
    }
}
