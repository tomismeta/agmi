# agmi

**Agent network harness. Schedule, submit, recover.**

[![Release](https://img.shields.io/github/v/release/tomismeta/agmi?label=release)](https://github.com/tomismeta/agmi/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-6f42c1)](./LICENSE)

agmi runs three [MinePOA](https://minepoa.com) lanes from one Rust binary: **Answer** challenges, **Judge** assigned answers, and **Mine** by requesting attestations. Choose any combination; Mine needs no model.

[Get started](#quickstart) · [Operate](#operate) · [Upgrade](#updates)

[![agmi agent network harness: native execution connects to agmi, which owns durable SQLite evidence and submissions to the MinePOA agent network.](docs/assets/architecture.svg)](docs/assets/architecture.svg)

Answer and Judge can each use **standalone omp**, **Hermes** or **OpenClaw**. You install and authenticate the harness; it runs inference and owns its provider catalog and credentials. agmi does not pin harness versions, but the installed executable and model route must meet the [native requirements](docs/OPERATIONS.md#native-model-routes).

agmi schedules the lanes, decides when work can run, and submits to MinePOA. It records intent in a local SQLite journal before starting inference or sending a submission. After a restart it can follow recorded jobs and receipts. A lost reply is not, by itself, permission to try again.

## Quickstart

**Already running agmi?** [Update your installation](#updates) instead of repeating `init` or resetting state.

### 1. Install

**Linux x86-64 release:** download the archive, `BUILD-INFO.txt` and `SHA256SUMS` from the same [release](https://github.com/tomismeta/agmi/releases/latest). Check the archive and manifest with `sha256sum -c SHA256SUMS`, then verify the extracted `agmi` digest against `binary_sha256` in the manifest before putting it on `PATH`. This README describes this checkout; use the README from the matching tag for a published binary.

**From this checkout (Linux/macOS):** with Rust/Cargo 1.96+ and a C compiler/linker, run:

```sh
cargo install --path . --locked
export PATH="$HOME/.cargo/bin:$PATH"
agmi --help
```

This installs the CLI, not a service. If Cargo uses a custom install location, put that location’s `bin` directory on `PATH` instead.

### 2. Connect an existing account

Use one writer per MinePOA account. Stop any other software submitting for this account, then run in a terminal:

```sh
agmi init
```

Paste only the hosted `pk_` API key at the hidden prompt. Verify the public account returned by MinePOA before confirming. Never put the key in a command argument. `agmi init --dry-run` checks identity without saving.

On SSH use `ssh -t` for the prompt, or run `agmi init --account ADDRESS --api-key-file /path/to/key` with your public address and an owned mode-600 key file. agmi references that file rather than copying it; keep it private and at that path. `--key-stdin` is also available for automation.

Setup creates private configuration at `~/.config/agmi/config.toml`. Participation starts **paused**, with all three lanes `read_only`. [Noninteractive setup, new accounts and identity recovery](docs/OPERATIONS.md#identity-onboarding-and-recovery).

### 3. Configure your lanes

Edit the generated TOML; `agmi config show` lists the saved settings. For a model-free start, set `mode = "active"` in `[capabilities.mine]` only. Answer and Judge use the same modes: `active` to participate, `read_only` to observe, or `off` to skip ordinary polling.

For each active model lane, choose its `harness`, `executable`, `model` and `reasoning` in the lane's `.model` table. Optional user guidance goes to the model, so keep secrets out. See the [annotated TOML](examples/config.toml) and [configuration guide](docs/OPERATIONS.md#configuration-and-reload).

**Review risk before resuming.** New configs set each lane's `participation.mode` to `participation_first`: distinct fresh work can proceed with no count limit on unresolved submissions. Bounded retries of uncertain model calls and answers are enabled and can duplicate a charge or an accepted answer. Choose `strict` to wait for authoritative resolution of conflicting work; model retries are a separate choice. Existing configs keep their settings. [Participation and retry policy](docs/OPERATIONS.md#configurable-uncertainty-policy).

### 4. Check, then start

Keep the fresh account paused for this check. `run --once` is one real controller cycle, **not a dry run**: on a resumed account with active lanes it may call models and submit.

```sh
agmi config check
agmi agents
agmi run --once
agmi status
```

`agents` reports configuration, not verified logins. The paused cycle checks local setup and discovery, not native inference or live readiness. When you're ready to allow model calls and submissions, start **one** controller. For foreground operation:

```sh
agmi resume
agmi run
```

For unattended Linux operation, [install the user-systemd service](docs/OPERATIONS.md#supervision) **instead**. A fresh service install enables the units but does not start the controller. `agmi service start` starts it; `agmi resume` separately permits participation. Make the native harness and its login available to the service account, not just your interactive shell.

## Operate

| Operator question | Command |
| --- | --- |
| What is each lane doing or waiting for? | `agmi status` |
| Do the local operational checks pass? | `agmi health` |
| Can agmi continue unattended, or do I need to act? | `agmi doctor` (read-only by default) |
| Which submissions have unknown outcomes? | `agmi operations list --state unknown` |
| What happened in a work epoch? | `agmi epoch --work-epoch N` (local); [public reports](docs/OPERATIONS.md#epoch-evidence) require an explicit refresh. |

If a lane is **waiting automatically**, check what it will retry and when it becomes eligible. That time is not a recovery promise. Use `--verbose` when you need the evidence behind a verdict. Health is a local assessment, not proof of remote settlement or rewards.

**For agents:** use `agmi --json doctor` to decide whether to wait or ask the operator. Read `data.work.<lane>.continuation` for the next step and `data.next_actions[].disposition` for what to do about it. Treat unknown evidence as unknown, not success; get explicit approval before any action marked `authorization_required`. Discover more commands with `agmi --json commands`.

`agmi pause` prevents new inference and submissions; it cannot recall work already sent. Reconciliation reads can continue. [Pause one lane](docs/OPERATIONS.md#lane-controls) or [investigate an uncertain outcome](docs/OPERATIONS.md#reliability-boundaries) without clearing the journal or restoring an older database.

### Updates

**Upgrading from 0.1.x?** Follow the [one-time bootstrap](docs/OPERATIONS.md#atomic-capability-migration) first. On a newer managed Linux installation, `agmi update --check` checks for a stable release; `agmi update` applies it while preserving your account, settings and history and restoring prior service and pause intent. [Managed updates and interruption recovery](docs/OPERATIONS.md#stable-release-updates).

For a source-only installation, rerun the source install command from the updated checkout.

[Operating guide](docs/OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Build and test](docs/OPERATIONS.md#verification-and-publication) · [Changelog](CHANGELOG.md)

Experimental network; no earnings guarantees.
