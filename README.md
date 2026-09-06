<img src="assets/logo.svg" alt="lumo-cli logo" width="96" align="left" hspace="12">

# lumo-cli

A terminal coding agent for Proton Lumo, written in Rust. It works the way Claude Code does: it
holds a conversation with Lumo, reads and edits the files of the current project, and runs
commands, with the same end-to-end encryption as the official web client.

<br clear="left">

> Unofficial. Proton does not publish a Lumo API. lumo-cli speaks the protocol of their open-source
> web client ([ProtonMail/WebClients](https://github.com/ProtonMail/WebClients),
> `packages/lumo-api-client`), which may change without notice. Use it with your own account, at
> your own risk.

## Contents

- [Features](#features) · [Installation](#installation) · [Usage](#usage)
- [Working on a project](#working-on-a-project) · [Project configuration](#project-configuration-lumo-config)
- [Server mode](#server-mode) · [Sign-in and the CAPTCHA](#sign-in-and-the-captcha-error-9001)
- [Sandbox (Landlock)](#sandbox-landlock) · [Lumo's PGP key](#lumos-pgp-key)
- [Architecture](#architecture) · [On-disk files](#on-disk-files) · [Security](#security)

## Features

- Agent mode (the default): Lumo reads and edits files and runs commands through the native
  function calling of `ai/v1/chat/completions`. The read-only tools (`list_dir`, `read_file`,
  `search`) run directly; `write_file`, `edit_file` and `bash` require confirmation, with the
  diff or the command shown beforehand.
- End-to-end encryption, as in the web client: a fresh AES-256-GCM key per request, encrypted to
  Lumo's PGP key, with associated data bound to the `request_id`. Responses are verified.
- Streamed responses, reasoning included (`/think`).
- Proton sign-in over SRP (the password never leaves the machine), TOTP, token refresh. Guest
  mode works without an account, under stricter limits.
- Models `lumo-lite` (default), `lumo-max` and `apertus-15`; server-side tools `web_search`,
  `weather`, `stock`, `cryptocurrency`. `lumo-max` has a daily quota and agent mode spends one
  request per tool step, hence the default.
- A Landlock sandbox around the agent's commands, a dry-run mode, retries with back-off, and a
  configurable PGP-key source with rotation detection.

## Installation

Prebuilt, statically linked binaries (x86_64 and aarch64, musl) are published by the release
workflow. The installer downloads the latest one, checks its SHA-256 against the release's
`SHA256SUMS`, and places it in `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/r3dlight/lumo-cli/main/install.sh | sh
```

`LUMO_INSTALL_DIR` changes the destination, `LUMO_VERSION` selects a tag and `LUMO_BASE_URL` points
at a mirror. Without the script, the same archive can be unpacked directly:

```sh
curl -fsSL https://github.com/r3dlight/lumo-cli/releases/latest/download/lumo-cli-x86_64-unknown-linux-musl.tar.gz | tar -xz -C ~/.local/bin
```

From source, with stable Rust 1.88 or newer (`rust-toolchain.toml` selects it) and a C compiler
for the TLS backend (`aws-lc-sys`):

```sh
cargo install --git https://github.com/r3dlight/lumo-cli --locked   # or: cargo build --release
```

At runtime the binary needs nothing beyond the kernel: `git` for `/commit`, and `rg` (falling back
to `grep`) for `search`, are optional. The sandbox needs Landlock (Linux 5.13 or newer; 6.12 for
the whole policy) and is optional as well.

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

Transient failures (connection, timeout, 502/503/504) are retried with exponential back-off; a
quota 429 is not, and a 401 is refreshed once. A warning appears at startup when the deployed Lumo
web app has a different major version from the one this client was tested against.

## Working on a project

- Audit trail. In agent mode, every file write, edit and shell command is appended to a
  per-session log in the state directory, outside the project so it is never committed and stays
  out of the sandbox's reach. It records the action (path and diff, or command and exit status),
  not command output, which could carry secrets. `/audit` prints its path.
- Git. `/commit [message]` stages and commits the working tree; `--commit` does so after each turn
  that changed files, deriving a message from your instruction when you give none. It never pushes
  or forces, and calls git through an argument vector, not a shell.
- Token usage. Each request prints its token count, and `/status` the session total.
- Attachments. `--attach <path>` (repeatable) or `/attach <path>` adds a text or document file as
  context; files are size-capped and rejected if binary. Images are not supported yet.
- Read-only review. `--ro` makes the project read-only for the sandbox and the file tools alike,
  which suits reviewing an untrusted repository. `--noexec` also denies executing project files.

## Project configuration (`.lumo-config`)

A repository may carry a `.lumo-config/` directory:

- `instructions.md`: guidance added to the system prompt (build and test commands, conventions),
  in the manner of a `CLAUDE.md`.
- `config.toml`: defaults for `model`, `tools`, `think`, `max_turns`, `ro`, `noexec`, and the
  security-relevant `yolo`, `no_sandbox`, `commit`. Unknown keys are rejected.

A cloned repository is not trusted, so this config is never applied on its own. On first sight, and
after any edit, lumo-cli shows what it would apply, flags the dangerous settings in red, and asks for
approval, remembered by a SHA-256 of the content. Outside a terminal it fails closed. Command-line
flags always win over the config.

```sh
lumo-cli config show     # what it would apply, and whether it is approved
lumo-cli config allow    # approve the current content non-interactively
lumo-cli config reset    # forget the approval for this project
```

## Server mode

`lumo-cli serve` runs a local, OpenAI-compatible HTTP server backed by Lumo, with the encryption
done in-process, so editors and other OpenAI clients can use Lumo through this one binary.

```sh
lumo-cli serve                          # http://127.0.0.1:8787/v1
lumo-cli serve --port 9000 --api-key K  # require `Authorization: Bearer K`
```

It exposes `GET /v1/models`, `POST /v1/chat/completions` (streaming or not) and `GET /health`. It
binds to loopback by default; any other address requires `--api-key`, since whatever reaches the
port can spend your quota. The request `model` selects the tier and `reasoning_effort: "high"`
turns on reasoning. Function calling and image inputs are not translated yet.

## Sign-in and the CAPTCHA (error 9001)

lumo-cli signs in the way the web client does (anonymous session, matching `x-pm-appversion`,
browser User-Agent, cookie jar), which avoids the CAPTCHA in most cases. If Proton still demands
verification, typically over a VPN, Tor or a datacenter address:

1. Run `lumo-cli login` again; the challenge is often transient. Signing in once at
   <https://account.proton.me> from the same network also helps.
2. Avoid VPN, Tor and datacenter addresses for the sign-in.
3. Reuse a session that is already authenticated: `lumo-cli login --import-rclone` reads
   `~/.config/rclone/rclone.conf` (options `--remote`, `--rclone-config`), `lumo-cli login --paste`
   takes a UID and tokens by hand, and `--captcha-token <token>` accepts the
   `x-pm-human-verification-token` of a CAPTCHA solved in a browser.

An imported session is validated against Lumo before it is stored. lumo-cli then shares it; its
token refreshes may later invalidate the source (rclone, for instance), which then signs in again.

## Sandbox (Landlock)

In agent mode, every shell command and search runs under the kernel's Landlock LSM, with no
external binary. lumo-cli builds a policy for the current project and launches each subprocess as
`lumo-cli sandbox-exec -- …`; that child restricts itself through the
[`landlock`](https://crates.io/crates/landlock) crate (`landlock_restrict_self`, `no_new_privs`),
then executes the program. The policy reaches the child through an environment variable, never a
file the sandbox could write, and the child is started from a file descriptor of the executable
opened at startup, so replacing the binary from inside the sandbox changes nothing. Each run gets a
private `TMPDIR`, and each project private XDG directories, following
[claude-island](https://github.com/landlock-lsm/island).

| | Allowed | Denied |
|---|---|---|
| Files | the current project (rw + exec), detected toolchain caches, a private `TMPDIR`, `/usr` `/bin` … (read/exec), `/etc` `/proc` `/sys` (read) | everything else: `~/.ssh`, `~/.aws`, dotfiles, other projects, `/tmp`, `$HOME` itself |
| Network | outbound TCP on 443/80/53 | listening (bind), other ports |
| Processes | | signals to processes outside the sandbox, abstract UNIX sockets created outside it |
| Secrets | | `SSH_AUTH_SOCK`, `AWS_*`, `GH_TOKEN`, and any variable whose name ends in `_TOKEN`, `_SECRET`, `_KEY`, `_PASSWORD`, `_PASSWD`, `_CREDENTIAL(S)`, `_AUTH`, `_APIKEY`, `_BEARER`, `_PRIVATE` or `_CERT`, removed before launch |

Toolchains are detected from marker files (`Cargo.toml`, `package.json`, `pyproject.toml`,
`go.mod`, `Makefile`/`CMakeLists.txt`) and their caches opened accordingly. lumo-cli's own file
tools, which are not subprocesses, are kept within the project root as well.

The sandbox is on whenever the kernel supports Landlock; otherwise the tool warns and runs
unconfined. `--sandbox` makes it mandatory, `--no-sandbox` turns it off; `--ro` and `--noexec`
tighten the project access. At startup lumo-cli pins the policy to the highest Landlock ABI the
kernel supports, the child requires exactly that ABI, and anything an older kernel cannot enforce
is printed as a warning:

| Kernel | Landlock ABI | Not enforced before it |
|---|---|---|
| 5.13 | 1 | (file access rights: the minimum) |
| 5.19 | 2 | renames and links across directories are always denied |
| 6.2 | 3 | `truncate(2)` of files outside the sandbox |
| 6.7 | 4 | outbound TCP restriction |
| 6.10 | 5 | device ioctls |
| 6.12 | 6 | scoping of signals and abstract UNIX sockets |
| 7.1 | 9 | connections to pathname UNIX sockets outside the allowed trees |

To verify rather than trust:

```
$ lumo-cli check-sandbox
  [PASS] deny: read ~/.ssh
  [PASS] deny: list $HOME
  [PASS] deny: read ~/.aws/credentials
  [PASS] allow: read /etc/hostname
  [PASS] allow: write inside the project
  [PASS] allow: execute /usr/bin/true
result: OK, every probe behaved as required
```

## Lumo's PGP key

Each request's AES key is encrypted to Lumo's public PGP key, so a substituted key would expose
your prompts. lumo-cli therefore never adopts a key from the network on its own: the embedded key
is pinned, and a new one is taken only from `$LUMO_PUBKEY_PATH`, from the override file
`~/.config/lumo-cli/lumo-pubkey.asc`, or after explicit confirmation. A daily, offline-tolerant
check compares the active key with the one in Proton's `WebClients` repository and warns on a
rotation.

```sh
lumo-cli key show                 # source, fingerprint, user id, creation date
lumo-cli key check                # compare against Proton's canonical key
lumo-cli key update               # fetch it, show the fingerprint, confirm, store it
lumo-cli key update --file k.asc  # or from a local file (or --url <URL>)
lumo-cli key reset                # revert to the embedded key
```

Verify the fingerprint against a trusted Proton source before confirming an update.

## Architecture

| Module | Responsibility |
|---|---|
| `main.rs` | CLI (clap), subcommands, startup wiring |
| `protocol.rs` | Wire types of the Lumo v2 chat-completions protocol |
| `crypto.rs` | Per-request AES-256-GCM and PGP encapsulation of the key |
| `keys.rs` | Lumo's PGP key: sources, rotation detection, `key update` |
| `auth.rs` | SRP sign-in (`proton-srp`), 2FA, refresh, session import |
| `client.rs` | Encrypted requests, SSE streaming, retries, tool-call accumulation |
| `agent.rs` | The agent loop: tool definitions, approvals, tool turns |
| `tools.rs` | Local tools (files, search, shell) and project confinement |
| `sandbox.rs` | Landlock policy and self re-execution of confined subprocesses |
| `audit.rs` | Append-only audit trail |
| `git.rs` | Committing the agent's changes |
| `attach.rs` | Text and document attachments |
| `projconfig.rs` | `.lumo-config` with approval gating |
| `serve.rs` | The OpenAI-compatible server |
| `ui.rs` | REPL, streaming rendering, diffs, prompts |

Requests go to `POST https://lumo.proton.me/api/ai/v1/chat/completions` (SSE) with each message
carrying `"encrypted": true` and a `lumo` object holding the PGP-encrypted request key and the
`request_id`. Tool results are sent back as a `lumo_tool_call` turn followed by a `tool` turn,
both encrypted.

## On-disk files

| Path | Contents |
|---|---|
| `~/.config/lumo-cli/session.json` | Proton session tokens; mode 600 |
| `~/.config/lumo-cli/lumo-pubkey.asc` | PGP key override, when present |
| `~/.config/lumo-cli/history.txt` | REPL input history |
| `~/.config/lumo-cli/approved-configs.json` | approved `.lumo-config` hashes |
| `~/.cache/lumo-cli/last-key-check` | timestamp of the last key-rotation check |
| `~/.local/state/lumo-cli/audit/*.jsonl` | per-session audit logs |
| `~/.cache/lumo-cli/sandbox/lumo-*` | private XDG directories of the sandboxed tools |

The conversation history lives only in memory and is discarded when the REPL exits.

## Security

- Conversations are encrypted between the client and the model, and response integrity is
  verified (GCM with associated data).
- The password serves only the local SRP handshake and is wiped afterwards; only session tokens are
  stored, in a mode-600 file. Each request's AES key is wiped when the request ends.
- Nothing is written or executed without approval, except under `--yolo`. The audit log is
  owner-only and holds no command output.
- `serve` binds to loopback unless given an `--api-key`, compares it in constant time, bounds
  request bodies and generation time, and sets no CORS headers.
- The code follows the [ANSSI Rust guide](https://anssi-fr.github.io/rust-guide/), with the
  mechanical rules enforced by the build: `unsafe_code` forbidden; the Clippy lints `unwrap_used`,
  `expect_used`, `panic`, `unreachable`, `indexing_slicing`, `string_slice`,
  `arithmetic_side_effects`, `cast_possible_truncation` and `mem_forget` set to `deny` in
  `Cargo.toml` (tests exempt); `overflow-checks` kept in release; the stable toolchain pinned;
  `cargo fmt`, `clippy -D warnings` and `cargo audit` clean. The one acknowledged advisory
  (`RUSTSEC-2023-0071`, RSA decryption, reached transitively) is documented in `.cargo/audit.toml`
  as unreachable, since lumo-cli performs no RSA decryption.
- Every direct dependency is validated and recorded in [`DEPENDENCIES.md`](DEPENDENCIES.md).
