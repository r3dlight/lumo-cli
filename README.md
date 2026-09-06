<img src="assets/logo.svg" alt="lumo-cli logo" width="96" align="left" hspace="12">

# lumo-cli

A terminal coding agent for Proton Lumo, written in Rust. It works the way Claude Code does: it
holds a conversation with Lumo, reads and edits the files of the current project, and runs
commands, with the same end-to-end encryption as the official web client.

<br clear="left">

> Unofficial. Proton does not (yet) publish a Lumo API. lumo-cli speaks the same protocol as their
> web client, which is open source at
> [ProtonMail/WebClients](https://github.com/ProtonMail/WebClients) (`packages/lumo-api-client`).
> That protocol may change without notice. Use it with your own account, and at your own risk.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage) · [REPL commands](#repl-commands) · [Options](#command-line-options)
- [Working on a project](#working-on-a-project)
- [Project configuration (`.lumo-config`)](#project-configuration-lumo-config)
- [Server mode](#server-mode)
- [Sign-in and the CAPTCHA (error 9001)](#sign-in-and-the-captcha-error-9001)
- [Sandbox (Landlock)](#sandbox-landlock)
- [Lumo's PGP key](#lumos-pgp-key-a-trust-anchor)
- [Architecture](#architecture) · [The Lumo v2 protocol](#the-lumo-v2-protocol-in-brief)
- [On-disk files](#on-disk-files)
- [Security](#security) · [References](#references)

## Features

- Agent mode (the default): Lumo reads and edits files and runs commands through the native
  function calling of `ai/v1/chat/completions`, the mechanism the Lumo Desktop connectors use.
  The read-only tools (`list_dir`, `read_file`, `search`) run directly; `write_file`, `edit_file`
  and `bash` require confirmation, with the diff or the command shown beforehand.
- End-to-end (user-to-Lumo) encryption, using the web client's scheme: a fresh AES-256-GCM key per
  request, itself encrypted to Lumo's PGP key, with associated data bound to the `request_id` to
  prevent replay. Responses arrive encrypted and their integrity is verified.
- Streamed responses, token by token, reasoning included (`/think`).
- Proton sign-in over SRP (the password never leaves the machine), TOTP, and automatic token
  refresh. It also works without an account, in guest mode, under stricter server limits.
- Models `lumo-lite` (default), `lumo-max` and `apertus-15`. `lumo-max` is a premium model with a
  daily quota, and agent mode spends one request per tool step; that is why `lumo-lite` is the
  default. Optional server-side tools: `web_search`, `weather`, `stock`, `cryptocurrency`.
- A kernel sandbox (Landlock) that confines the agent's commands to the project; a dry-run mode
  that previews actions without running them; exponential back-off on transient network errors;
  and a configurable PGP-key source with rotation detection.
- No `unsafe`, and a clean `clippy`. See [Security](#security).

## Installation

```sh
cargo build --release   # stable Rust 1.88 or newer (rust-toolchain.toml selects stable)
# binary: target/release/lumo-cli (symlink it, e.g. to ~/.local/bin/lumo)
```

The sandbox needs a Linux kernel with Landlock, that is 5.13 or newer. From 6.12 the whole policy
is enforced; older kernels enforce what they can and report what they cannot (see
[Sandbox](#sandbox-landlock)). No external binary is needed. The sandbox is optional and the tool
runs without it.

## Usage

```sh
lumo-cli login                 # Proton sign-in (SRP + 2FA); optional but recommended
lumo-cli login --import-rclone # or: reuse an already authenticated Proton session (see CAPTCHA)
lumo-cli login --paste         # or: paste UID + tokens by hand
lumo-cli                       # agent REPL in the current directory
lumo-cli --chat                # plain chat, without local tools
lumo-cli -p "fix the bug in src/main.rs"          # one-shot
lumo-cli --model lumo-lite --think                # model choice + reasoning
lumo-cli --tools web_search                       # enable server-side web search
lumo-cli --yolo                # auto-approve writes and commands (use with care)
lumo-cli --dry-run             # show proposed writes and commands without running them
lumo-cli check-sandbox         # prove the sandbox holds (see below)
lumo-cli logout
```

Before each file write or shell command, the diff or the command is shown for approval
(`[y]es / [a]lways / [n]o`), unless `--yolo` is set.

### REPL commands

| Command | Effect |
|---|---|
| `/help` | list the commands |
| `/clear` | reset the conversation history |
| `/chat` | toggle between agent mode and plain chat |
| `/model [name]` | show or change the model (`lumo-lite`, `lumo-max`, `apertus-15`) |
| `/think` | toggle reasoning mode |
| `/tools [t]` | enable or disable a server-side tool (`web_search`, `weather`, …) |
| `/yolo` | toggle auto-approval of writes and commands |
| `/dry` | toggle dry-run (show without executing) |
| `/commit [msg]` | stage and commit the working tree in the project repository |
| `/attach <path>` | attach a text file as context for the next message |
| `/audit` | show where this session's action log is written |
| `/limits` | show the remaining quota on your plan |
| `/status` | session, mode, model, and cumulative token usage |
| `/quit` | exit |

### Command-line options

| Option | Effect |
|---|---|
| `-p, --prompt <TXT>` | one-shot instead of the REPL |
| `--chat` | plain chat (no local tools) |
| `--model <NAME>` | `lumo-lite` (default), `lumo-max`, `apertus-15` |
| `--think` | reasoning mode |
| `--yolo` | auto-approve writes and commands (use with care) |
| `--dry-run` | show actions without running them |
| `--tools a,b` | Lumo server-side tools (`web_search`, …) |
| `--sandbox` / `--no-sandbox` | require or disable the Landlock sandbox |
| `--ro` | read-only project (the sandbox and file tools refuse to modify it) |
| `--noexec` | deny execve of project files inside the sandbox |
| `--commit` | commit the working tree after each turn that changed files |
| `--attach <path>` | attach a text/document file as context (repeatable) |
| `--max-turns <N>` | maximum turns sent per request (default 40) |

Generation requests retry transient failures (connection, timeout, 502/503/504) with exponential
back-off. A quota 429 is not retried, and a 401 is refreshed once. At startup, a non-blocking
warning appears when the deployed Lumo web app has a different major version from the one this
client was tested against (`TESTED_LUMO_VERSION`), a sign that the protocol may have shifted.
Dry-run (`--dry-run` / `/dry`) shows the writes and commands the agent proposes without carrying
them out; the read-only tools still run, so it can keep exploring.

## Working on a project

- Audit trail. In agent mode, every side-effecting action (file write, file edit, shell command)
  is appended to a per-session log in the state directory. The log sits outside the project on
  purpose, so it is never committed by accident and stays outside the tree the sandbox can write.
  It records the action (a file path and its diff, or a command and its exit status) but not a
  command's raw output, which could carry secrets. `/audit` prints its path.
- Git. `/commit [message]` stages the working tree and commits it in the project's repository; with
  `--commit`, a commit is made after each turn that changed files. A message is derived from your
  instruction and the changed files when you do not supply one. It never pushes and never forces,
  and every invocation goes through an argument vector rather than a shell.
- Token usage. Each request prints its token count (`· in / out / total tokens`), and `/status`
  shows the cumulative total for the session. This matters because agent mode spends one request
  per tool step, and `lumo-max` draws on a daily quota.
- Attachments. `--attach <path>` (repeatable) or `/attach <path>` reads a text or document file and
  supplies it to the model as context; each file is size-capped and rejected if it looks binary.
  Image attachments are not yet supported.
- Read-only review. `--ro` makes the project read-only: the sandbox denies writes, and lumo-cli's
  own file tools refuse to modify anything. This suits reviewing an unfamiliar or untrusted
  repository. `--noexec` additionally denies executing the project's own files inside the sandbox.

## Architecture

| Module | Responsibility |
|---|---|
| `main.rs` | CLI (clap), subcommands, and startup wiring (active key, version, sandbox) |
| `protocol.rs` | Constants and wire types (chat-completions request, the `lumo` extension, SSE chunks) |
| `crypto.rs` | Per-request AES-256-GCM and PGP encapsulation of the key (`rpgp`) |
| `keys.rs` | Lumo's PGP key: layered source, fingerprint/UID, rotation detection, `key update` |
| `auth.rs` | SRP via the official `proton-srp` crate, the v4 unauthenticated session, 2FA, refresh, import/CAPTCHA |
| `client.rs` | Building encrypted requests, SSE streaming, retries, tool-call accumulation |
| `agent.rs` | The agent loop: tool definitions (JSON Schema), approvals, `lumo_tool_call`/`tool` turns |
| `tools.rs` | Local tools (files, search, shell) with guard rails and project confinement |
| `sandbox.rs` | Landlock policy, self re-execution of confined subprocesses, secret scrubbing |
| `audit.rs` | Append-only audit trail of the agent's actions |
| `git.rs` | Safe git helpers for committing the agent's changes |
| `attach.rs` | Reading text/document attachments into prompt context |
| `projconfig.rs` | The `.lumo-config` project configuration, with approval gating |
| `serve.rs` | The OpenAI-compatible HTTP server (`serve`) |
| `ui.rs` | The REPL (rustyline), streaming rendering, diffs, and approval prompts |

### The Lumo v2 protocol in brief

`POST https://lumo.proton.me/api/ai/v1/chat/completions` (SSE):

```jsonc
{
  "model": "lumo-max",
  "messages": [ { "role": "user", "content": "<base64 iv‖ct‖tag>", "encrypted": true }, /* …, ending with an empty assistant turn */ ],
  "stream": true, "stream_options": { "include_usage": true },
  "reasoning_effort": "none",           // or "high"
  "tools": [ { "name": "web_search" }, { "type": "function", "function": { /* JSON Schema */ } } ],
  "tool_choice": "auto",
  "lumo": { "client_type": "frontend", "request_key": "<AES key encrypted to the PGP key>", "request_id": "<uuid>" }
}
```

The model's tool calls arrive in `delta.tool_calls` (their arguments possibly encrypted). Results
are sent back as two turns, `lumo_tool_call` (canonical `{"id","name","arguments"}` JSON) and then
`tool` (the result content), both encrypted.

## Project configuration (`.lumo-config`)

A repository may carry a `.lumo-config/` directory that tailors the agent to it:

- `instructions.md`: guidance added to the agent's system prompt (build and test commands,
  conventions, things to avoid), in the manner of a `CLAUDE.md` or `AGENTS.md`.
- `config.toml`: default settings: `model`, `tools`, `think`, `max_turns`, the more-restrictive
  `ro`/`noexec`, and the security-relevant `yolo`, `no_sandbox`, `commit`. Unknown keys are
  rejected, so a typo cannot silently disable a protection.

Because a cloned repository is not trusted, this config is never applied automatically. On first
sight, and again after any edit, lumo-cli shows what it would apply, flags any dangerous setting
(`yolo`, `no_sandbox`, `commit`) in red, and asks you to approve it. The approval is remembered by a
SHA-256 of the content, so an edit forces re-approval. Outside a terminal (a pipe, CI) it fails
closed and does not load. Settings from the config act as defaults, and an explicit command-line
flag always wins.

```sh
lumo-cli config show     # what it would apply, and whether it is approved
lumo-cli config allow    # approve the current content non-interactively
lumo-cli config reset    # forget the approval for this project
```

## Server mode

`lumo-cli serve` runs a local, OpenAI-compatible HTTP server backed by Lumo, so editors, agents and
other OpenAI clients can use Lumo through this one native binary. The U2L encryption happens
in-process.

```sh
lumo-cli serve                          # http://127.0.0.1:8787/v1
lumo-cli serve --port 9000 --api-key K  # require `Authorization: Bearer K`
```

It exposes `GET /v1/models` and `POST /v1/chat/completions` (streaming and non-streaming) and a
`GET /health`. It binds to loopback by default; binding to any other address requires `--api-key`,
since whatever reaches the port can spend your Lumo quota. The request `model` selects the Lumo tier
(`lumo-lite`, `lumo-max`, `apertus-15`); `reasoning_effort: "high"` turns on reasoning. Point a
client at it with `OPENAI_BASE_URL=http://127.0.0.1:8787/v1`. Function calling and image inputs are
not translated yet.

## Sign-in and the CAPTCHA (error 9001)

lumo-cli signs in the way the web client does: it creates an anonymous session
(`/auth/v4/sessions`), sends an `x-pm-appversion` matching the deployed version
(`web-account@x.y.z`, fetched at runtime) and a browser User-Agent, and keeps a cookie jar. This
is what Proton's scoring mostly looks at to tell a browser from a bot, and it avoids the CAPTCHA
in most cases.

If Proton still demands verification (error 9001, typically over a VPN, Tor, a datacenter
address, or a "cold" IP):

1. Run `lumo-cli login` again, as the challenge is often transient, and sign in once at
   <https://account.proton.me> from the same network, then retry.
2. Avoid VPN, Tor, and datacenter addresses for the sign-in; they are challenged far more often.
3. As a last resort, reuse a session that is already authenticated, without signing in again:
   - `lumo-cli login --import-rclone` reads `~/.config/rclone/rclone.conf` (`client_uid`,
     `client_access_token`, `client_refresh_token`) if you use rclone with Proton Drive. Options:
     `--remote <name>`, `--rclone-config <path>`.
   - `lumo-cli login --paste` accepts a UID, access token, and refresh token from a Proton session.
   - `lumo-cli login --captcha-token <token>` is for advanced use: the
     `x-pm-human-verification-token` from a CAPTCHA solved in a browser.

An imported session is validated against Lumo (the `/limits` endpoint) before it is stored.
lumo-cli then shares that Proton session; its own token refreshes may eventually invalidate the
source (rclone, for instance), which then signs in again on its own.

## Sandbox (Landlock)

In agent mode, every shell command and every search is confined by the kernel (the Landlock LSM),
with no external binary. lumo-cli builds a policy for the current project and launches each
subprocess as `lumo-cli sandbox-exec -- …`. That child applies the policy to itself through the
[`landlock`](https://crates.io/crates/landlock) crate (`landlock_restrict_self`, with
`no_new_privs`), and only then executes the requested program.

Two details keep a confined process from loosening the rules of the next command. The policy
reaches the child as JSON in an environment variable, never through a file the sandbox could write
to. And the child is started from a file descriptor of the lumo-cli executable opened at startup,
so replacing the binary on disk from inside the sandbox has no effect on later launches.

The access matrix follows [claude-island](https://github.com/landlock-lsm/island), as do the
private `TMPDIR` per run and the private XDG directories per project, which keep sandboxed tools
away from the user's real configuration. For the agent and everything it spawns:

| | Allowed | Denied |
|---|---|---|
| Files | the current project (rw + exec), detected toolchain caches, a private `TMPDIR`, `/usr` `/bin` … (read/exec), `/etc` `/proc` `/sys` (read) | everything else: `~/.ssh`, `~/.aws`, dotfiles, other projects, `/tmp`, `$HOME` itself |
| Network | outbound TCP on 443/80/53 | listening (bind), other ports |
| Processes | | signals to processes outside the sandbox, abstract UNIX sockets created outside it |
| Secrets | | `SSH_AUTH_SOCK`, `AWS_*`, `GH_TOKEN`, and any variable whose name ends in `_TOKEN`, `_SECRET`, `_KEY`, `_PASSWORD`, `_PASSWD`, `_CREDENTIAL(S)`, `_AUTH`, `_APIKEY`, `_BEARER`, `_PRIVATE` or `_CERT`, removed before launch |

Toolchains are detected from marker files (`Cargo.toml` → rust, `package.json` → node,
`pyproject.toml` → python3, `go.mod` → go, `Makefile`/`CMakeLists.txt` → c) and their caches
(`~/.cargo`, `~/.npm`, `~/.cache/go-build`, and so on) opened accordingly. lumo-cli's own file
tools (read/write/edit), which are not subprocesses, are additionally kept within the project root.

By default the sandbox is enabled when the kernel supports Landlock; otherwise the tool warns and
runs unconfined. At startup lumo-cli probes the kernel and pins the policy to the highest Landlock
ABI it supports. The child then requires exactly that ABI, and refuses to run the command if the
ruleset is not fully enforced. What an older kernel cannot enforce is printed as a warning at every
start:

| Kernel | Landlock ABI | Not enforced before it |
|---|---|---|
| 5.13 | 1 | (file access rights: the minimum) |
| 5.19 | 2 | renames and links across directories are always denied |
| 6.2 | 3 | `truncate(2)` of files outside the sandbox |
| 6.7 | 4 | outbound TCP restriction (443/80/53) |
| 6.10 | 5 | device ioctls |
| 6.12 | 6 | scoping of signals and abstract UNIX sockets |
| 7.1 | 9 | connections to pathname UNIX sockets outside the allowed trees (a bonus) |

`--sandbox` requires the sandbox and fails if it is unavailable; `--no-sandbox` disables it. Two
further modes tighten the project access: `--ro` drops write (read and execute remain), and
`--noexec` drops execution of the project's own files; they combine. To verify rather than trust,
run the self-check; its probes adapt to the mode:

```
$ lumo-cli check-sandbox
  [PASS] deny: read ~/.ssh
  [PASS] deny: list $HOME
  [PASS] deny: read ~/.aws/credentials
  [PASS] allow: read /etc/hostname
  [PASS] allow: write inside the project
  [PASS] allow: execute /usr/bin/true
result: OK, every probe behaved as required

$ lumo-cli check-sandbox --ro
  …
  [PASS] deny: write inside the project (--ro)
```

## Lumo's PGP key (a trust anchor)

Each request's AES key is encrypted to Lumo's public PGP key, which makes that key a trust anchor:
a substituted key would let an attacker read your prompts. For this reason lumo-cli never adopts a
key fetched from the network automatically. The embedded key is pinned, a file override is an act
of the user, and adopting a remote key requires explicit confirmation. (Proton serves no key over
a runtime API; the web client embeds it at build time.)

The active key is resolved in order, the first that loads winning:

1. `$LUMO_PUBKEY_PATH`, a file path
2. `~/.config/lumo-cli/lumo-pubkey.asc`, the configuration override
3. the embedded default

An unreadable or invalid override produces a warning and falls back to the embedded key, so the
tool keeps working.

If Proton rotates the key, a best-effort check at startup (throttled to once a day, silent when
offline) compares the active key's fingerprint against Proton's canonical key, the one in their
open-source `ProtonMail/WebClients` repository, and warns you when they differ. The commands are:

```sh
lumo-cli key show                 # source, fingerprint, user id, creation date
lumo-cli key check                # compare against Proton's canonical key; report any rotation
lumo-cli key update               # fetch the canonical key, show the fingerprint, confirm, store it
lumo-cli key update --file k.asc  # or from a local file
lumo-cli key update --url <URL>   # or from a URL (default: $LUMO_PUBKEY_URL, then the Proton repo)
lumo-cli key reset                # remove the override and revert to the embedded key
```

`key update` prints the candidate's fingerprint, user id, and creation date, and asks for
`[y/N]` (unless `--yes` is given): verify the fingerprint against a trusted Proton source before
adopting it.

## On-disk files

| Path | Contents |
|---|---|
| `~/.config/lumo-cli/session.json` | Proton session tokens (UID, access, refresh); mode 600 |
| `~/.config/lumo-cli/lumo-pubkey.asc` | PGP key override, when present |
| `~/.config/lumo-cli/history.txt` | REPL input history (rustyline) |
| `~/.config/lumo-cli/approved-configs.json` | approved `.lumo-config` hashes, per project |
| `~/.cache/lumo-cli/last-key-check` | timestamp of the last key-rotation check |
| `~/.local/state/lumo-cli/audit/*.jsonl` | per-session audit log of the agent's actions |
| `~/.cache/lumo-cli/sandbox/lumo-*` | private XDG directories of the sandboxed tools (one per project and mode) |

The conversation history itself lives only in memory: nothing is written, and leaving the REPL
discards it (there is no session resumption). This is a choice made for confidentiality.

## Security

- Conversations are encrypted between the client and the model: neither intermediaries nor Proton
  read them in transit, and response integrity is verified (GCM with associated data).
- Credentials serve only the SRP handshake, locally; only session tokens are stored, in a
  mode-600 file. The password is wiped from memory after use, and each request's AES key is wiped
  when the request ends.
- The agent neither writes nor executes anything without approval, except under `--yolo`. The
  audit log is written owner-only (mode 600) and records actions, not command output.
- The server (`serve`) binds to loopback unless given an `--api-key`, compares that key in constant
  time, bounds request bodies and generation time, and sets no CORS headers (so a web page cannot
  reach it).
- The code follows the [ANSSI Rust guide](https://anssi-fr.github.io/rust-guide/), and the rules
  that can be checked mechanically are enforced by the build:
  - `unsafe_code` is forbidden (`Cargo.toml` `[lints.rust]` and the crate root);
  - the Clippy lints `unwrap_used`, `expect_used`, `panic`, `unreachable`, `indexing_slicing`,
    `string_slice`, `arithmetic_side_effects`, `cast_possible_truncation` and `mem_forget` are
    set to `deny` in `Cargo.toml` (`[lints.clippy]`), so production code cannot panic on a
    runtime value, index without a check, or do unchecked arithmetic (tests are exempt);
  - release builds keep `overflow-checks = true`;
  - `rust-toolchain.toml` pins the stable channel (`rust-version = "1.88"`);
  - `Cargo.lock` is committed, `cargo fmt --check` and `clippy --all-targets -D warnings` are
    clean, and `cargo audit` reports no actionable advisory. The one acknowledged entry
    (`RUSTSEC-2023-0071`, a timing side-channel in RSA *decryption* reached transitively) is
    documented in `.cargo/audit.toml` as unreachable here, since lumo-cli performs no RSA
    decryption (Lumo's key is EdDSA + Curve25519);
  - every direct dependency is validated and recorded in [`DEPENDENCIES.md`](DEPENDENCIES.md),
    with the outdated-version exceptions justified there.

## References

- The official web client, and the source of the protocol:
  <https://github.com/ProtonMail/WebClients> (`packages/lumo-api-client`, `applications/lumo`)
- pyLumo (Mindgard), a Python client and an analysis of the U2L encryption (v1 protocol):
  <https://github.com/Mindgard/pyLumo>
- lumo-tamer, an OpenAI-compatible proxy for Lumo: <https://github.com/ZeroTricks/lumo-tamer>
