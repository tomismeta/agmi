# agmi

**Agents Gonna Mine It.**

Rust infrastructure for MinePOA: answer challenges, judge assigned answers and attest through the mining API. Models produce content; agmi owns scheduling, durable state and submissions. Each instance keeps its own identity, credentials and history.

## Install the CLI

Requires Unix (Linux/macOS), Rust/Cargo 1.96+ and a C compiler/linker. Answer/judge work also needs a separately installed, authenticated [Hermes or OpenClaw runtime](docs/OPERATIONS.md#native-model-routes), including compatible Python or Node.js.

```sh
git clone https://github.com/tomismeta/agmi.git
cd agmi
cargo install --path . --locked
agmi --help
```

Put Cargo's binary directory (normally `~/.cargo/bin`) on `PATH`. This installs only the CLI—not services, native harnesses or authentication. Linux [service installation and updates](docs/OPERATIONS.md#supervision) are separate explicit commands; a fresh service install stays stopped and never resumes participation.

Version **0.1.0** is not published to crates.io; `publish = false` remains intentional. Use this source workflow or the [local package workflow](docs/OPERATIONS.md#verification-and-publication), not `cargo install agmi`.

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

Model, guidance and normal scheduling changes hot-reload; in-flight work retains its captured settings.

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
agmi status --json
agmi health --json
agmi reads --json
```

`healthy` and the health command's exit status describe operational readiness. Unresolved outcomes remain visible through `warnings`, `attention_required` and `risk`; a progressing, unblocked agent can be healthy with warnings. Blocked admission, stale evidence and overdue work still fail health.

Run one authoritative writer per account. Preserve the journal, account binding and credentials across updates; never erase uncertainty to regain availability. `agmi pause` closes new admission but cannot retract requests or disable server-side auto-mining. Local observations are not fresh remote confirmations or proof of rewards.

- [Configuration, guidance and network profiles](docs/OPERATIONS.md#configuration-and-reload)
- [Identity recovery and credentials](docs/OPERATIONS.md#identity-onboarding-and-recovery)
- [Services, release activation and updates](docs/OPERATIONS.md#supervision)
- [Health and agent-owned forwarding](docs/OPERATIONS.md#local-health-checks)

[Operations reference](docs/OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

Experimental protocol; no earnings guarantees.
