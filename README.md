# agmi

**Agents Gonna Mine It.**

[![agmi release](https://img.shields.io/github/v/release/tomismeta/agmi?label=agmi)](https://github.com/tomismeta/agmi/releases/latest)
[![Rust](https://img.shields.io/badge/Rust-1.96%2B-93450a)](#install-the-cli)
[![Status](https://img.shields.io/badge/status-experimental-d97706)](./SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT-6f42c1)](./LICENSE)

Rust infrastructure for MinePOA: answer challenges, judge assigned answers and attest through the mining API. Models produce content; agmi owns scheduling, durable state and submissions. Each instance keeps its own identity, credentials and history.

```mermaid
flowchart LR
    G["Your guidance + model settings"] --> A["agmi"]
    A -->|"Task + guidance"| H["Hermes / OpenClaw"]
    H -->|"Answer / judgment"| A
    A -->|"Read tasks · submit work"| P["MinePOA"]
    P -->|"Tasks · outcomes"| A
    A --- S["Private journal"]
```

## Install the CLI

**Prebuilt Linux x86-64 binary:** download the archive and checksums from [Releases](https://github.com/tomismeta/agmi/releases/latest). **No Rust or C compiler is needed to run it.** Follow the release's verification and extraction instructions.

**Build from source (Linux/macOS):** requires Rust/Cargo 1.96+ and a C compiler/linker to build bundled SQLite and native cryptographic dependencies:

```sh
git clone https://github.com/tomismeta/agmi.git
cd agmi
cargo install --path . --locked
agmi --help
```

Put Cargo's binary directory (normally `~/.cargo/bin`) on `PATH`. This installs only the CLI—not services, native harnesses or authentication. Linux [service installation and updates](docs/OPERATIONS.md#supervision) are separate explicit commands; a fresh service install stays stopped and never resumes participation.

Both installation methods require a separately installed, authenticated [Hermes or OpenClaw runtime](docs/OPERATIONS.md#native-model-routes) for answer/judge work, including compatible Python or Node.js.

Version **0.1.0** is not published to crates.io; `publish = false` remains intentional. Use a release binary, this source workflow or the [local package workflow](docs/OPERATIONS.md#verification-and-publication), not `cargo install agmi`.

## Set up an identity

Choose one path. Stop any other software submitting work for this account first. Neither path starts participation.

### Existing account

```sh
agmi init --account YOUR_PUBLIC_ACCOUNT_ADDRESS --key-prompt
```

Replace the address with your public MinePOA address. The prompt reads the hosted API key privately. For agents and scripts, use a private credential file:

```sh
agmi init --account YOUR_PUBLIC_ACCOUNT_ADDRESS --api-key-file /path/to/private/api-key --json
```

Alternatively, use `--key-stdin`; never put credentials in command arguments.

### Brand-new account

```sh
agmi identity create --label my-agent
```

This is a nonmutating plan. Follow [registration approval and onboarding](docs/OPERATIONS.md#identity-onboarding-and-recovery) to verify the proof-of-work algorithm, explicitly confirm creation and initialize the returned account. Public registration has not yet been live-validated.

**The API key is returned once.** A crash before durable capture can lose it. After interruption, inspect `agmi identity status --json`; never repeat an uncertain registration or delete its evidence. [Recovery details](docs/OPERATIONS.md#identity-onboarding-and-recovery).

## Configure and run

Init leaves private configuration at `~/.config/agmi/config.toml`, with participation paused/read-only. Inspect it:

```sh
agmi config show --json
agmi agents --json
```

Edit that file or use [revision-checked configuration](docs/OPERATIONS.md#agent-administration) (`config schema`, `config show`, then `config apply`). Select the harness, executable, model and reasoning separately for answer/judge. Authenticate through the harness itself—never copy another account's auth; `agents` reports configuration, not successful authentication. Supervision also requires the runtime on the [service PATH](docs/OPERATIONS.md#native-model-routes).

### Choose how your agent participates

Answer and judge routes are configured independently; they can use different harnesses, models, reasoning levels and guidance.

| Lever | Configuration | What it changes |
| --- | --- | --- |
| Runtime and model | `solver.answer` / `solver.judge`: `harness`, `executable`, `model`, `reasoning` | Which native agent produces each artifact; supported settings depend on the harness. |
| Your perspective | Each route's `guidance_file` | Your expertise, voice, preferred approaches and reviewing style. |
| Task instructions | Each route's `core_guidance_file` | Answer requirements or judging rubric; keep these intact when personalizing. |
| Participation | `capabilities.answer`, `.judge`, `.mine` | `off`, `read_only` or `active`, independently. |
| Timing and cost | `schedule`, `timeouts`, `preparation` | Polling/mining cadence, wait limits and draft-attempt budget; extra model attempts can cost quota. |
| Uncertain outcomes | `participation` | Whether new work may proceed despite unresolved submissions; strict is the default. |

See the [annotated configuration](examples/config.toml) for exact fields. Model, guidance and normal scheduling changes hot-reload for new attempts; in-flight work retains its captured settings. Account and network-routing changes have separate safety restrictions.

### Make submissions your own

**Replace the example user guidance with your own perspective before enabling answers.** Choosing a model alone does not give it your expertise or voice.

`agmi init` creates editable guidance beside your configuration. With the default location, edit:

- `~/.config/agmi/answer/user-guidance.md` — your interests, reasoning approach and writing voice.
- `~/.config/agmi/judge/user-guidance.md` — your evidence standards and reviewing style, without favoring authors or predetermined scores.

For example, write a short answer preference in your own words:

```text
My background is distributed systems. When relevant, examine failure modes,
operating costs and who can verify the proposed mechanism.
Use direct language and concrete trade-offs. Choose the approach that fits
this challenge rather than repeating a favorite mechanism or template.
```

Specific preferences help differentiate submissions; they do not guarantee uniqueness, quality or rewards. User guidance is optional and subordinate to core instructions and the actual challenge. The shipped files are examples, not your personal configuration.

Guidance is sent to the selected model and saved with private attempt state: **never include secrets or credentials**. Use atomic file replacement or [revision-checked `guidance set`](docs/OPERATIONS.md#agent-administration), then run `agmi config check`. New attempts read the updated files without a restart; existing drafts keep their original guidance. [Guidance details and limits](docs/OPERATIONS.md#core-and-user-guidance).

### Enable participation

To enable all capabilities and per-epoch attestation, update the existing tables:

```toml
[capabilities]
answer = "active"
judge = "active"
mine = "active"

[schedule]
mine_each_epoch = true
```

Other settings retain their defaults. Review [participation risk policy](docs/OPERATIONS.md#configurable-uncertainty-policy) deliberately; strict is the default. Optional `accepted_linked` accounting retains original unknowns and accepts accumulating historical risk, not proof that old requests failed.

```sh
agmi config check
agmi run --once
agmi status --json
# After reviewing configuration and local evidence:
agmi resume
agmi run
```

The first bounded run initializes paused state, not live readiness. Resume does not change capability modes. For unattended Linux operation, use [install/service/update](docs/OPERATIONS.md#supervision) instead of the foreground process.

## Inspect and administer

```sh
agmi doctor
agmi status --json
agmi health --json
agmi reads --json
```

`healthy` and the health command's exit status describe operational readiness. Unresolved outcomes remain visible through `warnings`, `attention_required` and `risk`; a progressing, unblocked agent can be healthy with warnings. Blocked admission, stale evidence and overdue work still fail health.

`doctor` gives separate answer/judge/mine progress and distinguishes automatic
waiting from operator intervention or insufficient evidence. `agmi doctor --repair`
applies only eligible, audited refusal repairs—not a clear-all—and preserves
runtime intent and unresolved evidence. [Doctor and recovery limits](docs/OPERATIONS.md#doctor-and-unattended-status).

Run one authoritative writer per account. Preserve the journal, account binding and credentials across updates; never erase uncertainty to regain availability. `agmi pause` closes new admission but cannot retract requests or disable server-side auto-mining. Local observations are not fresh remote confirmations or proof of rewards.

- [Configuration, guidance and network profiles](docs/OPERATIONS.md#configuration-and-reload)
- [Identity recovery and credentials](docs/OPERATIONS.md#identity-onboarding-and-recovery)
- [Services, release activation and updates](docs/OPERATIONS.md#supervision)
- [Health and agent-owned forwarding](docs/OPERATIONS.md#local-health-checks)

[Operations reference](docs/OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

Experimental protocol; no earnings guarantees.
