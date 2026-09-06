# Dependency validation record

This file tracks the validation of every direct dependency, as the ANSSI Rust guide asks
(LIBS-DEPENDENCY-DIRECT). Transitive dependencies are covered by `cargo audit` (LIBS-AUDIT), whose
one acknowledged advisory is documented in `.cargo/audit.toml`. `cargo outdated --root-deps-only`
(LIBS-OUTDATED) is run at each release; the exceptions are listed at the end.

Validation criteria: a maintainer with a track record (an established organisation or a widely
depended-upon author), a public repository, a licence compatible with GPL-3.0-or-later, and an
API surface reviewed for what lumo-cli actually calls. Crates handling secrets or untrusted input
(marked *sensitive*) were read at the call sites listed.

| Crate | Version | Purpose in lumo-cli | Maintainer | Licence | Notes |
|---|---|---|---|---|---|
| `aes-gcm` | 0.11.1 | AES-256-GCM of every turn (*sensitive*: `crypto.rs`) | RustCrypto | Apache-2.0 OR MIT | Audited by NCC Group (2020); AEAD with associated data; nonce is 12 random bytes from the OS |
| `anyhow` | 1.0.104 | Error type and context chains | dtolnay | MIT OR Apache-2.0 | |
| `axum` | 0.8.9 | HTTP server for `serve` (*sensitive*: `serve.rs`) | tokio-rs | MIT | Default features off; only `http1`, `json`, `tokio`; body limit 1 MiB set in code |
| `base64` | 0.23.1 | Encoding of encrypted payloads | marshallpierce | MIT OR Apache-2.0 | Strict decoding (rejects trailing bits) |
| `clap` | 4.6.6 | Command-line parsing | clap-rs | MIT OR Apache-2.0 | `derive` feature only |
| `dirs` | 7.0.0 | XDG/home directory lookup | dirs-dev | MIT OR Apache-2.0 | No I/O beyond environment lookup |
| `futures-util` | 0.3.34 | Stream combinators for SSE | rust-lang | MIT OR Apache-2.0 | |
| `landlock` | 0.4.7 | Kernel sandbox for tool subprocesses (*sensitive*: `sandbox.rs`) | landlock-lsm (Landlock's kernel maintainers) | MIT OR Apache-2.0 | The only crate wrapping the Landlock syscalls; its `unsafe` is confined to those syscalls; used with `CompatLevel::HardRequirement` so nothing degrades silently |
| `owo-colors` | 4.4.0 | Terminal colours | jam1garner | MIT | Pure formatting |
| `pgp` | 0.20.0 | OpenPGP encryption of the request key to Lumo's public key (*sensitive*: `crypto.rs`, `keys.rs`) | rpgp | MIT OR Apache-2.0 | Audited (Radically Open Security, 2024); only public-key encryption and key parsing are used, never private-key operations |
| `proton-srp` | 0.8.2 | SRP login proofs (*sensitive*: `auth.rs`) | Proton AG (proton-crypto-rs) | Proton's licence file (see the crate) | Official Proton implementation of their SRP variant; the password is only ever passed to this crate, locally |
| `rand` | 0.8.8 | Randomness for AES keys and nonces, and the RNG handed to `pgp` (*sensitive*: `crypto.rs`) | rust-random | MIT OR Apache-2.0 | `OsRng` (kernel CSPRNG) for keys and nonces; `thread_rng` (ChaCha, OS-seeded) for OpenPGP session keys; see the version note below |
| `reqwest` | 0.13.4 | HTTPS client (*sensitive*: all network I/O) | seanmonstar | MIT OR Apache-2.0 | Default features off; `rustls` only (no OpenSSL), `http2`, `json`, `stream`, `cookies` |
| `rpassword` | 7.5.4 | Hidden password prompt (*sensitive*: `main.rs` login) | conradkleinespel | Apache-2.0 | The returned `String` is zeroized after use |
| `rustyline` | 18.0.1 | Line editing for the REPL | kkawakam | MIT | History file lives in the config dir |
| `serde` | 1.0.229 | Serialisation framework | serde-rs | MIT OR Apache-2.0 | `derive` feature |
| `serde_json` | 1.0.151 | JSON for the protocol, configs and the sandbox policy | serde-rs | MIT OR Apache-2.0 | Untrusted input is deserialised into typed structs or accessed with `get`, never indexed |
| `sha2` | 0.11.0 | SHA-256 of an approved `.lumo-config` (`projconfig.rs`) | RustCrypto | Apache-2.0 OR MIT | |
| `similar` | 3.2.0 | Diffs shown before file writes | mitsuhiko | Apache-2.0 | Display only |
| `tokio` | 1.53.1 | Async runtime, processes, timers | tokio-rs | MIT | `full` features |
| `tokio-stream` | 0.1.19 | Stream adapters | tokio-rs | MIT | |
| `toml` | 1.1.5 | `.lumo-config` parsing | toml-rs | MIT OR Apache-2.0 | Parsed into a typed struct with unknown keys rejected |
| `uuid` | 1.26.0 | Request ids and private tmp dir names | uuid-rs | Apache-2.0 OR MIT | `v4` (random) only |
| `zeroize` | 1.9.0 | Wiping keys and passwords from memory | RustCrypto | Apache-2.0 OR MIT | |

## Version exceptions

- `rand` stays on 0.8: `pgp` 0.20 and `proton-srp` 0.8 take `rand` 0.8 RNG types in their
  APIs, so the crate cannot move to 0.9 or 0.10 until they do. The only use is `OsRng`, whose
  behaviour is identical across these versions.

## Not used

- `cargo deny` is not part of the release checks yet; licences were checked by hand above.
