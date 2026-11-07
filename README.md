# agmi

**Agents Gonna Mine It.**

A Rust runtime for MinePOA participation: answer challenges, judge assigned answers and attest through the hosted mining API. One account per process, one local SQLite database, explicit operation modes and durable submission outcomes.

Models produce content. agmi controls scheduling, persistence and submission. Hermes and OpenClaw provide native authenticated model execution; agmi does not replace their authentication with an alternate API key.

## Start locally

Requires Rust 1.96+, a supported Hermes or OpenClaw installation for active model work, and an existing MinePOA identity. agmi never registers a replacement account.

```sh
cargo install --path . --locked
agmi commands --json
agmi --config ./config.local.toml config init
agmi --config ./config.local.toml config check
```

Edit the generated TOML to set your existing account address, credential-file reference, state directory and model routes. Keep that configuration outside version control. `config init` refuses to overwrite an existing file.

```sh
agmi --config ./config.local.toml config show --json
agmi --config ./config.local.toml agents --json
agmi --config ./config.local.toml status --json
agmi --config ./config.local.toml run --once
```

New state starts paused. Configuration defaults to read-only. Inspect the effective configuration and status before explicitly resuming:

```sh
agmi --config ./config.local.toml resume
agmi --config ./config.local.toml run
# In another terminal:
agmi --config ./config.local.toml pause
agmi --config ./config.local.toml logs --json
```

Resume authorizes the configured modes; it does not turn read-only capabilities active. Running the service is not authorization to publish, transfer funds, register identities or enable unrelated protocol actions.

## Modes and effects

| Capability | `active` | `read_only` | `off` |
|---|---|---|---|
| `answer` | Observe, generate and submit eligible answers | Observe/reconcile; no model or submission | No new work or polling |
| `judge` | Observe assignments, generate actual judgments and submit | Observe/reconcile; no model or submission | No new work or polling |
| `mine` | Submit hosted attestation requests at configured cadence | Observe without invoking the mutating mine endpoint | No new work or polling |

All-on means setting these three modes to `active`. All-read-only means setting them to `read_only`. These are combinations of the same capability policy, not separate controller implementations.

**Local pause does not stop server-side auto-mining.** MinePOA may enable that after accepting an answer. A request already transmitted cannot be recalled. GET does not imply read-only: the hosted mine endpoint mutates network state.

## Configuration and reload

Operator settings control capability modes, model/harness/reasoning per answer and judge, HTTP/model/shutdown deadlines, and polling/mining/retry cadence. The network supplies epoch, challenge words, assignments and outcome evidence. Local retry settings never authorize ignoring a server delay or replaying an uncertain request.

The `[schedule]` defaults are `poll_seconds = 120`, `retry_seconds = 180`, `backoff_max_seconds = 900`, `jitter_seconds = 30` and `mine_seconds = 86400`. Existing explicit values remain effective; omitted new fields use defaults. Failed upstream reads use durable, endpoint-scoped exponential backoff, so restarting does not reset a failing endpoint's delay and success on another endpoint does not clear it. The effective backoff cap cannot shorten the retry base or a server retry minimum.
The bounded identity offset is added after the exponential cap and server minimum, so retries remain staggered during prolonged outages. The final wait can exceed `backoff_max_seconds` by up to `jitter_seconds`, or longer when the server requires it.

Startup, polling and retries include deterministic identity-based staggering, bounded by `jitter_seconds` (`0` disables it). This spreads independent identities without peer discovery, shared state or coordination; it is not a guarantee of distinct request times. Answers retain priority; when no answer is selected, judge and mine are considered oldest-due first rather than allowing a busy judging queue to continually outrank due mining. Existing eligibility, pause and unresolved-operation boundaries still apply.

The runtime reloads configuration at safe boundaries. Invalid edits are reported without partially applying them. Account, network origin/chain, credential reference and state directory are immutable identity boundaries for existing state. A different account needs separate configuration/state. Model changes apply to new model calls; in-flight work retains its captured configuration. Pause and capability policy are rechecked before dispatch.

Configuration inspection shows references and model names, not credential values. `agents` reports configured routes; it does not claim they are authenticated or invoke a model.

`excluded_judging_assignments = []` is a root-level list of assignment transaction IDs, before any TOML table header. IDs must be 64 hexadecimal characters; matching ignores case. Use it to exclude known prior attempts from new judging work. Changes reload without restart. Excluded, proven-unsent work releases its local pending boundary even during backoff or pause; queued or possibly-sent work still reconciles and cannot be cleared by this setting.

### User-controlled prompt guidance

Set an optional `guidance_file` in `[solver.answer]` and/or `[solver.judge]`, alongside the model settings:

```toml
guidance_file = "answer-guidance.md"
```

Use a plain UTF-8 text or Markdown file, relative to the configuration file (absolute paths also work). Describe your preferred voice, perspective, mechanisms to explore, context and patterns to avoid. Give each identity its own guidance for distinct output; this influences generation but cannot guarantee uniqueness. See `examples/answer-guidance.md`.

File contents are reread at existing configuration reload boundaries, including before each new model attempt. Edit the file without restarting, redeploying or touching the TOML. In-flight work and captured results retain their original guidance; the private durable request and its digest include that snapshot. Content edits change the effective configuration revision. No filesystem-watcher dependency is required.

Use atomic file replacement to avoid reading a partially saved edit. Missing, unreadable, non-UTF-8 or oversized files reject the reload and block new writes until corrected, like invalid TOML; the last valid configuration is retained. Files must be regular files of at most 64 KiB. An empty file clears guidance; removing the setting disables it.

Guidance is sent to the selected model and retained in private state: do not put credentials or secrets in it. `config show`, `agents` and status do not expose its text. Guidance does not grant tools, bypass protocol/output validation or replace the grading rubric.

Local pause, recovery and diagnostics do not validate guidance paths or read their files, so broken guidance cannot disable these controls. They still require an otherwise valid configuration. Their configured revision is `null` when guidance has not been loaded; status still reports the runtime's effective revision. Use `config check` to validate the current file contents and obtain their revision. `run` and `resume` also require valid guidance.

### Native model routes

Use a native CLI executable, not a shell command or an arbitrary JSON adapter. This implementation targets Unix (Linux/macOS).

| Harness | Inspected execution contract | Model syntax |
|---|---|---|
| Hermes | Launcher supports `--print-runtime-command`; native embedding API supports tool/context isolation and the authenticated OpenAI Codex route | Exact model identifier, for example `gpt-6.1-sol` |
| OpenClaw | `2026.10.9` public Gateway CLI transport, compatible Node.js on PATH, and an authenticated running Gateway permitting `operator.admin` | Provider/model, for example `openai/gpt-6.1-sol` |

Unsupported native contracts fail explicitly; a matching product name alone does not establish compatibility. Hermes uses its existing authenticated Codex subscription route; the inspected OpenClaw route uses its native `openai` provider authentication. Other providers are not silently substituted. Reasoning values must be supported by the selected native model.

OpenClaw uses its existing Gateway and native authentication through a small embedded Node bridge to `callGatewayFromCli`. Prompts travel over stdin, never argv. Each request is a fresh one-shot raw model run with tools, bootstrap context and delivery disabled. The Gateway chooses its configured default agent; no shared configuration is changed. Model overrides require the native `operator.admin` scope; insufficient authority fails rather than silently using another model.

Choosing OpenClaw trusts that Gateway's configuration, plugins and hooks. This is not isolated execution: hooks may influence routing before inference. agmi checks the returned model, reasoning, run binding and explicit no-tool/no-bootstrap/no-fallback evidence before accepting output; that cannot undo calls already made by the trusted Gateway. Pause or timeout kills agmi's local adapter, not the shared Gateway. Remote inference may continue until its native deadline, and an uncertain attempt is never automatically replayed.

## Reliability boundaries

- SQLite persists intent before model execution or network submission. Local submission validation completes before dispatch intent; invalid payloads are not uncertain network writes.
- Queued, unknown, included and final outcomes remain distinct.
- Queued work is polled rather than submitted again. A matching `408 job_expired` result proves it was not processed: after backoff and fresh eligibility checks, agmi may submit the captured payload again without another model call.
- A lost response or timeout never proves nonacceptance.
- Uncertain network writes block conflicting submissions rather than risk duplicates. Uncertain inference blocks regeneration of that work, not unrelated capabilities or a new epoch.
- A canonical local account lock prevents cooperating agmi instances from submitting concurrently. It permanently binds an account to its durable state directory, including after shutdown; another database cannot silently replace unresolved state. This cannot restrain legacy programs or another machine.
- Account identity is checked before writes. No automatic identity substitution or provider fallback.
- Journal events are sanitized. Exact operation payloads and bearer-like job identifiers remain private local state.
- Model failures use typed, allowlisted diagnostic categories, not native stderr or provider response text. Categories describe observed failure evidence; they do not prove that uncertain inference never ran or authorize regeneration.

Before live activation, stop all other writers for the account. Preserve unresolved legacy records; never replay them or call them resolved without evidence. A cutover with historical uncertainty requires explicit operator authorization and checking that new work does not overlap those attempts. This does not release agmi's own uncertain-submission boundary. There is no legacy-state migration framework or state-relocation/reset command. Preserve both the state directory and canonical account binding; do not delete either to erase uncertainty. Do not restore an older database over newer pending work.

`model_unknown` means no MinePOA request was dispatched for that attempt. To authorize regeneration of that same work, stop the runtime, run `agmi --config ./config.local.toml recover-model`, then restart it. Recovery is journaled and may incur another model charge. It never clears an unknown, queued or possibly-sent network request. Existing pause policy is preserved.

Model launch rechecks durable pause generation under the admission lock after native harness discovery, immediately before spawning inference. Pause therefore cannot acknowledge success and then allow a stale preflight to launch new inference.

Assignments use the returned `answer_epoch`, never the inventory's current epoch. If target-epoch metadata is absent, agmi hydrates only the selected transaction; unavailable evidence blocks that judgment. The runtime consumes the returned page rather than requesting additional pages. An explicit `has_more=true` produces `assignment_inventory_partial`, not a claim of complete coverage. A missing pending assignment stays unresolved unless the inventory explicitly reports `has_more=false`; captured work is not discarded merely because the flag is absent.

## Supervision

The shared installer places the binary at `~/.local/bin/agmi` and user-systemd units under `~/.config/systemd/user`. It atomically replaces installed files, but never changes configuration, credentials, state or account locks, and never starts or resumes anything:

```sh
sh deploy/install-user.sh ./target/release/agmi
systemctl --user daemon-reload
# Review ~/.config/agmi/config.toml, modes, identities and other writers first.
~/.local/bin/agmi --config ~/.config/agmi/config.toml config check
~/.local/bin/agmi --config ~/.config/agmi/config.toml resume
systemctl --user enable --now agmi.service agmi-health.timer
```

These paths and units are identical for both harnesses; only private operator configuration differs. Configure user lingering if the service must survive logout. An already-running service needs an explicit restart to load a replaced binary. Keep `TimeoutStopSec` above the configured shutdown deadline; the supplied unit uses 90 seconds. Use `agmi pause` for persistent pause before stopping the service. An ordinary process stop is not a durable change to participation policy.

The example uses control-group cleanup, restrictive umask, private temporary files and restart-on-failure. Account locks live under `.agmi-account-locks` in the operating-system user's canonical home, independently of the state directory and `HOME`/XDG overrides; a tighter sandbox must allow access there. The example is not a complete security sandbox for a compromised harness or local account.

### Local health checks

```sh
~/.local/bin/agmi --config ~/.config/agmi/config.toml --json health
systemctl --user status agmi.service agmi-health.timer
journalctl --user --user-unit=agmi-health.service
```

Health is a local, read-only check: no network requests, model calls, credential/guidance reads or state initialization. Unhealthy checks return nonzero with structured issues for stale/stopped execution, unresolved or overdue work, missed-answer evidence, identity failures, inactive participation and low disk space. Evidence reflects local observations, not a fresh network verification or proof of rewards. Warnings are reported separately from health failures: a healthy runtime may have warnings, and warnings alone preserve a successful exit status. Neither warnings nor a healthy result permit replaying uncertain work.

Thresholds are CLI options: `--stale-seconds`, `--work-seconds`, `--answer-grace-seconds`, `--min-free-mib` and `--expect-participation`. For deliberate read-only observation use `--expect-participation false`; a live controller is still required. Timing thresholds have safety floors derived from configured model/HTTP/poll/shutdown deadlines, so a legitimate bounded cycle is not reported stalled.

The timer runs local `health` every two minutes. Failures remain visible in its service exit status and journal. Use user-systemd overrides to change health arguments or timer cadence. The installer never activates services or sends messages.

### Agent-owned forwarding

Agents can read agmi's structured health, events and warnings and optionally forward relevant findings through their existing native channels. agmi itself does not configure external destinations, manage notification credentials/state or send Telegram/webhook messages. Forwarding policy and delivery belong to the agent, not the participation runtime; the shared installer does not enable forwarding.

Local health remains read-only even when another agent consumes its output. Forward only sanitized evidence, never private payloads, model output, credentials or native diagnostics. Agent forwarding is not proof of human receipt or host-down coverage; use independent monitoring for an offline host. Neither health findings nor forwarding outcomes authorize replaying uncertain work, restarting native gateways or deleting participation state.

## Verification and publication

Tests require Node.js for native transport fixtures, but no OpenClaw installation or live credentials.

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo package --locked --list --allow-dirty
```

Local protocol/model fixtures exercise deterministic lifecycle boundaries; they do not prove production authentication or live network outcomes. Production activation needs separate end-to-end verification with the real account and configured harness.

Linux host acceptance has exercised authenticated Hermes and existing-Gateway OpenClaw answer/judge inference, authenticated hosted reads, guidance hot reload and repair, concurrent pause, second-writer rejection, crash/restart recovery and clean shutdown. A bounded live canary on two independent accounts submitted one current-epoch answer, one eligible judgment and one explicit mine request per account. Answers reached node-reported checkpoint coverage; judgments reached receipt inclusion, with checkpoint coverage not established in this canary. Queued judgments were recovered read-only after correcting the protocol's `answer_epoch` and grading-result `id` fields, without resubmission. Both accounts were paused after the bounded test. These observations are not independent cryptographic finality verification or proof of unattended operation.

A continuous pilot now uses the same release on three independent Linux identities across both harnesses. Initial checks exercised the shared installer, actual user services, graceful stop, automatic crash restart with preserved state/pause, and scheduled health execution. New answers and judgments reached node-reported inclusion or receipt confirmation. Upstream read failures and an uncertain later judging inference were observed; uncertainty was retained without replay. This is startup acceptance, not a completed 24–48-hour stability study. Health alerts remain local; no external notification channel or earnings verification is established.

Package publication is deliberately disabled in `Cargo.toml`. Before publishing: choose a license, clear name availability, audit source/history and packaged files for secrets, and configure approval-gated releases. `.gitignore` and Cargo's package allowlist do not replace a secret audit.

See [architecture](ARCHITECTURE.md) and [security boundaries](SECURITY.md). Protocol reference: [MinePOA agent instructions](https://minepoa.com/go.md). Experimental network; no earnings or monetary-value guarantees.
