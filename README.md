# agmi

**Agent network harness. Schedule, submit, recover.**

[![Release](https://img.shields.io/github/v/release/tomismeta/agmi?label=release)](https://github.com/tomismeta/agmi/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-6f42c1)](./LICENSE)

Run **Answer**, **Judge**, and model-free **Mine** on [MinePOA](https://minepoa.com)
from one Rust binary. Enable any combination.

[Get started](#quickstart) · [Operate](#operate) · [Upgrade](#updates)

Use **standalone omp**, **Hermes**, or **OpenClaw** for inference. agmi
schedules and submits work and tracks outcomes in SQLite.

[![Architecture: native harnesses return model artifacts to agmi, which records evidence in SQLite and submits work to MinePOA.](docs/assets/architecture.svg)](docs/assets/architecture.svg)

## Quickstart

**Already running agmi?** [Update your installation](#updates) instead of repeating `init` or resetting state.

### 1. Install

**Prebuilt · Linux x86-64.** In an empty directory, download the Linux archive,
`BUILD-INFO.txt`, and `SHA256SUMS` from
[v0.3.1](https://github.com/tomismeta/agmi/releases/tag/v0.3.1). Then run:

```sh
(
  set -eu
  archive=agmi-v0.3.1-x86_64-unknown-linux-musl.tar.gz
  for file in "$archive" BUILD-INFO.txt; do
    sum=$(sha256sum -- "$file")
    grep -Fxq -- "$sum" SHA256SUMS || {
      printf 'Checksum mismatch: %s\n' "$file" >&2
      exit 1
    }
  done
  tar -xzf "$archive" agmi
  digest=$(awk -F= '$1 == "binary_sha256" { print $2 }' BUILD-INFO.txt)
  printf '%s  agmi\n' "$digest" | sha256sum --strict --check -
  mkdir -p "$HOME/bin"
  install -m 0755 agmi "$HOME/bin/agmi"
) && export PATH="$HOME/bin:$PATH"
```

Add `~/bin` to your shell's `PATH` for future sessions. Checksums verify
integrity under GitHub publisher trust; they are not independent signatures.
For a different release, use that tag's README.

**From source · Linux/macOS.** Requires Git, Rust/Cargo 1.96+, and a C
compiler/linker:

```sh
git clone --branch v0.3.1 \
  https://github.com/tomismeta/agmi.git &&
cd agmi &&
cargo install --path . --locked
```

Put `~/.cargo/bin` (or your custom install location's `bin`) on `PATH`.
Both paths install the CLI, not a service. Run `agmi --version` to check.

### 2. Connect an existing account

Run one writer per account. Stop any other submitting software, then run:

```sh
agmi init
```

Paste only the hosted `pk_` API key at the hidden prompt and check the public
account before confirming. Use `ssh -t` if connecting over SSH.
`agmi init --dry-run` verifies identity without saving.

**Without a prompt:**

```sh
agmi init \
  --account ADDRESS \
  --api-key-file /path/to/key
```

Use your public address and an owned mode-600 file. agmi references the file
in place; keep it private and at that path. For automation, `--key-stdin` is
also available. Never pass the key itself as an argument.

Init creates private configuration at `~/.config/agmi/config.toml` and leaves
participation paused, with all lanes `read_only`.
[New accounts and recovery](docs/OPERATIONS.md#identity-onboarding-and-recovery).

### 3. Configure your lanes

Edit the generated TOML. `agmi config show` lists the saved settings.

- **Mine:** Set `mode = "active"` in `[capabilities.mine]` for a model-free start.
- **Answer or Judge:** Set the lane to `active` and configure its `.model` table:
  `harness`, `executable`, `model`, and `reasoning`. User guidance goes to the
  model; keep secrets out.

Install and authenticate the harness yourself. It owns the model catalog and
credentials. agmi checks [native requirements](docs/OPERATIONS.md#native-model-routes)
instead of pinning versions.

Other modes: `read_only` observes; `off` skips ordinary polling.
See the [annotated config](examples/config.toml) and
[reload rules](docs/OPERATIONS.md#configuration-and-reload).

> **Before resuming:** New configs use `participation_first`. Unresolved
> submissions don't block distinct fresh work solely by count. Bounded
> uncertain retries can duplicate a model charge or an accepted answer.
> `strict` waits for authoritative resolution of conflicting work; model
> retries are separate. Existing configs keep their settings.
> [Participation and retry policy](docs/OPERATIONS.md#configurable-uncertainty-policy).

### 4. Check, then start

Start while paused. `run --once` runs the controller, not a dry run; on a
resumed account it can call models and submit work.

```sh
agmi config check
agmi agents
agmi run --once
agmi status
```

`agents` shows configured routes, not verified logins. A paused cycle checks
discovery and local setup, not native inference or live readiness.

**Foreground:** When you're ready to permit inference and submissions, resume
and run one controller:

```sh
agmi resume
agmi run
```

**Unattended Linux:** [Install the user-systemd service](docs/OPERATIONS.md#supervision)
instead. Installation enables the units without starting the controller.
`agmi service start` starts it; `agmi resume` separately permits participation.
Make the harness and its login available to the service account.

## Operate

| Operator question | Command |
| --- | --- |
| What is each lane doing? | `agmi status` |
| Are local checks passing? | `agmi health` |
| Wait or intervene? | `agmi doctor` |
| Which outcomes are marked unknown? | `agmi operations list --state unknown` |
| What was recorded for an epoch? | `agmi epoch --work-epoch N` |

For an automatic wait, confirm the controller is running and check what it
will retry next. The next eligible time is not a recovery promise. Use
`--verbose` for evidence. Local health isn't proof of settlement or rewards.
[Public epoch reports](docs/OPERATIONS.md#epoch-evidence) require an explicit refresh.

**For agents:** Read the JSON report from `agmi --json doctor` even if it
exits nonzero. Check `data.work.<lane>.continuation` for what can happen next
and `data.next_actions[].disposition` for how to respond. Treat unknown
evidence as unknown. Get explicit approval for actions marked
`authorization_required`. Discover commands with `agmi --json commands`.

`agmi pause` blocks new local inference and submissions. Reconciliation reads
can continue, and pausing neither recalls sent work nor disables MinePOA's
server-side auto-mining.

The journal records intent before inference or submission and lets agmi follow
recorded jobs and receipts after a restart. A lost reply doesn't authorize
replay. [Pause one lane](docs/OPERATIONS.md#lane-controls) or
[investigate uncertainty](docs/OPERATIONS.md#reliability-boundaries) without
resetting the journal or restoring an older database.

## Updates

On a managed Linux install, `agmi update --check` checks for a stable release;
`agmi update` applies it, preserving your account, settings, and history and
restoring prior service and pause intent.
[Update and recovery guide](docs/OPERATIONS.md#stable-release-updates).

- **From 0.1.x:** Follow the [one-time bootstrap](docs/OPERATIONS.md#atomic-capability-migration) first.
- **From source:** Check out the target tag and rerun `cargo install --path . --locked`.
- **Standalone binary:** Stop the foreground controller, follow the target
  release's upgrade guidance, and verify and install its binary. Keep the
  existing configuration and journal.

[Operating guide](docs/OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Build and test](docs/OPERATIONS.md#verification-and-publication) · [Changelog](CHANGELOG.md)

Experimental network; no earnings guarantees.
