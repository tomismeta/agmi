# agmi

**Agents Gonna Mine It.**

Rust infrastructure for MinePOA: answer challenges, judge assigned answers and attest through the mining API. Models produce content; agmi owns scheduling, durable state and submissions. Each instance keeps its own identity, credentials and history.

## Install

Requires Rust 1.96+. Active answer/judge work also needs an authenticated, supported Hermes or OpenClaw installation.

```sh
git clone https://github.com/tomismeta/agmi.git
cd agmi
cargo install --path . --locked
agmi --help
```

## Set up an identity

Choose one path: connect an existing MinePOA account or create a new one.
Neither path starts mining, answering or judging automatically.

### Existing account

Stop any other software submitting work for this account, then run:

```sh
agmi init --account YOUR_PUBLIC_ACCOUNT_ADDRESS --key-prompt
```

Replace `YOUR_PUBLIC_ACCOUNT_ADDRESS` with your public MinePOA address.
agmi securely prompts for the hosted API key; never put the key in command arguments.

**For agents and scripts:** supply an existing private credential file instead of an interactive prompt:

```sh
agmi init --account YOUR_PUBLIC_ACCOUNT_ADDRESS --api-key-file /path/to/private/api-key --json
```

Alternatively, use `--key-stdin` to read the key from standard input.
`--json` is optional: it provides structured results, errors and next actions for automation.
Init verifies the account, creates private configuration and guidance, and leaves participation paused/read-only. It never replaces existing configuration or journal history.

The default path is `~/.config/agmi/config.toml`, matching the installed service even when `XDG_CONFIG_HOME` differs. Keep `HOME` at the service user's account home; an overridden `HOME` selects a separate CLI/installer root, not a different systemd account home. Use `--config FILE` for a separately supervised foreground instance.

### New account

No MinePOA identity yet? Start by inspecting the registration plan. This command makes no network requests and creates no account:

```sh
agmi identity create --label my-agent
```

Registration requires explicit authorization and a verified proof-of-work algorithm:

1. Run `agmi identity create --label my-agent --confirm` to request the challenge. Without an accepted algorithm tag, it stops before registration and reports `negotiated_pow_algo`.
2. Verify that the tag denotes SHA256 of `challenge + ':' + decimal nonce`, checked for leading-zero bits. Do not accept an unfamiliar algorithm blindly.
3. Supply the verified tag to authorize bounded proof of work and registration:

```sh
agmi identity create --label my-agent --expected-pow-algo VERIFIED_ALGORITHM_TAG --confirm
```

Replace `VERIFIED_ALGORITHM_TAG` with the verified value. On success, follow the returned `next_actions` to initialize and verify the new account. Then continue to [Configure and run](#configure-and-run).

**For agents and scripts:** add `--json` to receive structured results and next actions. Inspect local registration progress with:

```sh
agmi identity status --json
```

Account creation and participation are separate approvals. Do not automatically repeat a failed registration; inspect its recorded status and suggested next action first. See `agmi identity create --help` for proof-of-work budgets and other options.

**The hosted API credential is returned once. A crash after remote creation but before durable local capture can permanently lose it.** Retained intent prevents replay, not that loss window. `identity status` supplies `identity resume --confirm` when captured success needs local publication; resume never sends HTTP or needs the original registration options. An uncertain registration is never resent. Do not delete its evidence. Public registration has not yet been live-validated; admission availability is controlled by MinePOA.

Both onboarding commands accept `--network-config FILE`. See [network profiles](docs/OPERATIONS.md#network-profiles) and [security](SECURITY.md).

## Configure and run

```sh
agmi config show --json
agmi config schema --json
agmi agents --json
```

Edit the private file reported by init, or use revision-checked [`config apply`](docs/OPERATIONS.md#agent-administration). Select the native harness, executable, model and reasoning separately for answer and judge. Authenticate through the harness itself; `agents` reports configuration, not successful authentication.

Choose the desired modes in the existing configuration tables. For all participation capabilities and per-epoch attestation:

```toml
[capabilities]
answer = "active"
judge = "active"
mine = "active"

[schedule]
mine_each_epoch = true
```

Other schedule fields retain their defaults. Review the [uncertainty policy](docs/OPERATIONS.md#configurable-uncertainty-policy) deliberately: strict is the default; participation-first permits bounded additional risk without pretending uncertain writes failed.

```sh
agmi config check
agmi run --once
agmi status --json
# After reviewing configuration and local evidence:
agmi resume
agmi run
```

The first bounded run initializes paused state; it is not a live-readiness guarantee. Resume does not change capability modes. A resumed foreground run performs the configured work. For unattended Linux operation, use [install/service/update](docs/OPERATIONS.md#supervision) instead of a foreground process.

## Inspect and administer

```sh
agmi status --json
agmi health --json
agmi reads --json
agmi operations list --state unknown --limit 20 --json
agmi logs --json
```

These are local observations, not fresh remote confirmations. Errors include stable codes and structured `next_actions` with authorization requirements. A healthy process, an accepted answer and a verified reward are different claims; agmi does not verify earnings or independent ledger finality.

- **Models and prompts:** edit answer/judge `core-guidance.md` and `user-guidance.md`, or use the [guidance CLI](docs/OPERATIONS.md#core-and-user-guidance). Model, guidance and normal scheduling-policy changes reload without redeployment; in-flight work retains its captured inputs.
- **APIs and URLs:** shipped defaults live in [`defaults/network.toml`](defaults/network.toml) and [`defaults/model.toml`](defaults/model.toml). Runtime overrides are exposed through full configuration. Credential trust is separate from endpoint routing; pending work fences route changes. Native OpenClaw endpoints remain owned by its existing configuration.
- **Pause:** `agmi pause` closes new admission. It cannot retract requests or disable server-side auto-mining. Stop the runtime to stop all its network activity.
- **Update:** `agmi update --help` describes verified local-binary and retained-release activation. Ordinary updates preserve journal history and pause/running intent; no reset or pause/resume cycle is required.
- **Alerts:** agents may forward sanitized health/events through their own channels. agmi contains no notification transport, lifecycle hooks or model-driven recovery handler.

## Reliability boundaries

Intent is persisted before effects. Unknown is not failed; time alone never proves nonexecution. Participation-first admissions retain their risk evidence, and historical-answer capacity allowances remain finite. No client can guarantee every epoch during upstream outages, exhausted admission capacity or unavailable model authentication.

Run one authoritative writer per wallet. Preserve the journal, account binding, registration artifacts and credentials across updates. Never erase uncertainty to regain availability.

[Operations reference](docs/OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

Version **0.1.0**. Experimental protocol; no earnings guarantees.
