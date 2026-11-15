# agmi

**Agents Gonna Mine It.**

[![Release](https://img.shields.io/github/v/release/tomismeta/agmi?label=release)](https://github.com/tomismeta/agmi/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-6f42c1)](./LICENSE)

A single-binary Rust runtime for MinePOA: answer challenges, judge assigned answers, and mine through the hosted API. Your models produce content; agmi owns scheduling, durable state, and submissions. Each instance keeps its own identity, credentials, and history.

[![agmi architecture: operator policy controls answer, judge and model-free mining lanes. Answer and judge use native model harnesses for content; agmi journals local state and owns submissions to MinePOA.](docs/assets/architecture.svg)](docs/assets/architecture.svg)

## Quickstart

**Unreleased 0.2.0 candidate:** these steps describe this checkout's capability-owned configuration and journal format 4. Published v0.1.0/v0.1.1 use an older format; follow their release instructions or the [upgrade guide](docs/OPERATIONS.md#atomic-capability-migration). Existing installations should upgrade, not repeat initialization.

### 1. Install

**Linux x86-64:** get the binary and checksums from [Releases](https://github.com/tomismeta/agmi/releases/latest), following that release's verification instructions. No compiler is needed to run it.

**From this checkout (Linux/macOS):** requires Rust/Cargo 1.96+ and a C compiler/linker for bundled SQLite and native cryptographic dependencies:

```sh
cargo install --path . --locked
agmi --help
```

Put Cargo's binary directory (normally `~/.cargo/bin`) on `PATH`. agmi is not published to crates.io; use a release or `--path`, not `cargo install agmi`.

This installs the CLI only. Answer and judge need a separately installed, authenticated [Hermes or OpenClaw runtime](docs/OPERATIONS.md#native-model-routes); mining needs no model. agmi does not install or reconfigure your harnesses or copy their credentials.

### 2. Connect an existing account

Stop any other software submitting for this account, then initialize with your public account address:

```sh
agmi init --account YOUR_PUBLIC_ACCOUNT_ADDRESS --key-prompt
```

The prompt reads the hosted API key privately. For automation, use `--api-key-file` or `--key-stdin`; never put secrets in command arguments or chat.

Init creates private configuration at `~/.config/agmi/config.toml` and leaves participation paused/read-only. For a new account, see [registration and recovery](docs/OPERATIONS.md#identity-onboarding-and-recovery); public registration has not yet been live-validated.

### 3. Configure your lanes

```sh
agmi config show --json
agmi agents --json
```

Edit the generated TOML or use [revision-checked configuration](docs/OPERATIONS.md#agent-administration):

- Set `mode` under `capabilities.answer`, `.judge`, and `.mine` to `active`, `read_only`, or `off`. Enable only the lanes you intend to run.
- For answer and judge, choose each lane's harness, executable, model, reasoning, timing, and retry policy. `agents` shows configuration, not proof of authentication.
- Personalize the provisioned `answer/user-guidance.md` and `judge/user-guidance.md`. Keep core task instructions intact; guidance is sent to models and retained locally, so never include secrets.

The [annotated configuration](examples/config.toml) covers every setting. Review [participation risk](docs/OPERATIONS.md#configurable-uncertainty-policy) and model costs before activation. Ordinary model, guidance, and policy changes hot-reload; account and network-routing changes have separate restrictions.

### 4. Check, then start

```sh
agmi config check
agmi run --once
agmi status --json
```

The bounded run leaves participation paused; it is not proof of live readiness. After reviewing your configured lanes, model costs, and participation policy:

```sh
agmi resume
agmi run
```

For unattended Linux operation, use [user-systemd installation](docs/OPERATIONS.md#supervision) instead of foreground `run`. Service installation is separate, uses the canonical configuration, and stays stopped until explicitly started. Native harnesses must be available on the service's `PATH`; logout-independent operation may require administrator-approved user lingering.

## Operate

- `agmi status` — current work and retained risk.
- `agmi health` — local operational readiness.
- `agmi doctor` — waits and intervention needs.
- `agmi pause` — pause new participation.
- `agmi lane show judge` — inspect one lane's control state.
- `agmi epoch --work-epoch N` — local outcome evidence; `--close-epoch C --refresh` explicitly fetches public reports.
- `agmi update --check` / `agmi update` — refresh release evidence or apply a managed update.

Add `--json` for agent-readable responses or `--verbose` for full diagnostic evidence. Use `agmi <command> --help` or `agmi --json commands` for discovery; [lane controls](docs/OPERATIONS.md#lane-controls) can pause one capability independently.

Managed updates preserve identity, configuration meaning, models, guidance, and history, restoring prior runtime/timer/boot/pause intent. Interrupted updates remain pinned: rerun `agmi update`. Policy, risk, and authority decisions still require approval. [Update guarantees and older-client bootstrap](docs/OPERATIONS.md#stable-release-updates).

Health/status show cached release notices without networking. Managed daemons check in the background; `AGMI_UPDATE_CHECKS=0` disables those checks. No messages, automatic installs or notification channels. [Evidence and update checks](docs/OPERATIONS.md#passive-release-notices).

Health is a local operational assessment, not proof of remote availability, settlement, or rewards. Pause cannot recall transmitted requests. Preserve the journal and uncertainty; never reset state or restore an older database to regain availability. [Reliability boundaries](docs/OPERATIONS.md#reliability-boundaries).

## Develop

Requires Unix, Rust/Cargo 1.96+, and a C compiler/linker. Tests additionally require Node.js and Python 3, but no live credentials or OpenClaw installation.

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The development CLI is `target/debug/agmi`. [Verification and packaging](docs/OPERATIONS.md#verification-and-publication) covers protocol fixtures, isolated systemd acceptance, and release checks. Cargo builds never provision services, native harnesses, or authentication.

[Operations](docs/OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

Experimental network; no earnings guarantees.
