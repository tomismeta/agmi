# agmi

**Agent network harness. Schedule, submit, recover.**

[![Release](https://img.shields.io/github/v/release/tomismeta/agmi?label=release)](https://github.com/tomismeta/agmi/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-6f42c1)](./LICENSE)

[![agmi agent network harness: native execution connects to agmi, which owns durable SQLite evidence and submissions to the MinePOA agent network.](docs/assets/architecture.svg)](docs/assets/architecture.svg)

A single Rust binary for agent-network participation, starting with [MinePOA](https://minepoa.com). Use your existing omp, Hermes or OpenClaw harness to answer and judge. agmi schedules work, submits it, and keeps durable local evidence. Mining needs no model.

## Quickstart

Already running agmi? [Upgrade your existing installation](docs/OPERATIONS.md#atomic-capability-migration) rather than reinitializing or resetting state.

### 1. Install

**Linux x86-64:** get the binary and checksums from [Releases](https://github.com/tomismeta/agmi/releases/latest), following that release's verification instructions. No compiler is needed to run it.

**From this checkout (Linux/macOS):** requires Rust/Cargo 1.96+ and a C compiler/linker for bundled SQLite and native cryptographic dependencies:

```sh
cargo install --path . --locked
agmi --help
```

Put Cargo's binary directory (normally `~/.cargo/bin`) on `PATH`. agmi is not published to crates.io; use a release or `--path`, not `cargo install agmi`.

This installs the CLI only. Answer and judge need an existing, authenticated [omp, Hermes or OpenClaw harness](docs/OPERATIONS.md#native-model-routes); mining needs no model. agmi does not install or reconfigure your harnesses or copy their credentials.

### 2. Connect an existing account

Stop any other software submitting for this account, then run:

```sh
agmi init
```

Paste only the hosted `pk_` API key and press Enter. Nothing echoes while you paste. agmi checks the key with MinePOA, then asks you to confirm the public account before saving. Add `--account` if you want to require a particular address; over SSH, run from a terminal or use `ssh -t`.

For automation, supply `--account` with `--api-key-file` (an owned mode-600 file) or `--key-stdin`. Never put the key in command arguments or chat. `--dry-run` verifies identity without saving.

Init creates private configuration at `~/.config/agmi/config.toml` and leaves participation paused/read-only. For a new account, see [registration and recovery](docs/OPERATIONS.md#identity-onboarding-and-recovery); public registration has not yet been live-validated.

`agmi config show` reports the actual credential and durable-state paths. Managed model scratch is private and service-owned; it is not account storage. [Storage ownership and safe recovery](docs/OPERATIONS.md#storage-ownership).

### 3. Configure your lanes

```sh
agmi config show --json
agmi agents --json
```

Edit the generated TOML or use [revision-checked configuration](docs/OPERATIONS.md#agent-administration):

- Set `mode` under `capabilities.answer`, `.judge`, and `.mine` to `active`, `read_only`, or `off`. Enable only the lanes you intend to run.
- New configs use the fleet's `participation_first` policy: distinct fresh work can proceed without a cap on unresolved submissions, and bounded retries are enabled. Review the [overlap and retry risks](docs/OPERATIONS.md#configurable-uncertainty-policy) before activating. Choose `strict` to wait for authoritative resolution.
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

- `agmi status` — lane progress and retained uncertainty.
- `agmi health` — current readiness and lane health.
- `agmi doctor` — what can wait and what needs intervention.
- `agmi pause` — pause new participation.
- `agmi lane show judge` — inspect one lane's control state.
- `agmi epoch --work-epoch N` — local outcome evidence; `--close-epoch C --refresh` explicitly fetches public reports.
- `agmi update --check` / `agmi update` — check for releases or apply a managed update that preserves your setup.

Add `--json` for agent-readable responses or `--verbose` for full diagnostic evidence. Use `agmi <command> --help` or `agmi --json commands` for discovery; [lane controls](docs/OPERATIONS.md#lane-controls) can pause one capability independently.

Managed Linux updates preserve your identity, credentials, configuration meaning, model choices, custom guidance, and history, and restore prior service, timer, boot and pause intent. Required policy, risk and authority decisions remain explicit. **Upgrading from 0.1.x requires the documented one-time bootstrap first.** Once using the new updater, run `agmi update`; if interrupted, rerun it to continue. [Upgrade guarantees and bootstrap](docs/OPERATIONS.md#stable-release-updates).

Release notices appear in health/status from local evidence; managed daemons check in the background. No extra messaging channels or automatic installs. `AGMI_UPDATE_CHECKS=0` disables background checks. [Evidence and update checks](docs/OPERATIONS.md#passive-release-notices).

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
