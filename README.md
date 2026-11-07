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
| `answer` | Observe, prepare and submit eligible answers | Observe/reconcile; no new model or submission | No new participation or ordinary polling; safety reconciliation continues |
| `judge` | Observe assignments, prepare judgments and submit | Observe/reconcile; no new model or submission | No new participation or ordinary polling; safety reconciliation continues |
| `mine` | Submit hosted attestation requests at configured cadence | Observe without invoking the mutating mine endpoint | No new participation or ordinary polling; safety reconciliation continues |

All-on means setting these three modes to `active`. All-read-only means setting them to `read_only`. These are combinations of the same capability policy, not separate controller implementations.

Off and pause do not abandon already possibly-sent work: allowlisted identity, job and receipt reads continue. Stop the runtime for strict no-network operation; local status/health remain offline. This safety-read contract replaces the earlier off=no-polling behavior.

**Local pause does not stop server-side auto-mining.** MinePOA may enable that after accepting an answer. A request already transmitted cannot be recalled. GET does not imply read-only: the hosted mine endpoint mutates network state.

## Configuration and reload

Operator settings control capability modes, model/harness/reasoning per answer and judge, HTTP/model/shutdown deadlines, and polling/mining/retry cadence. The network supplies epoch, challenge words, assignments and outcome evidence. Local retry settings never authorize ignoring a server delay or replaying an uncertain request.

The `[schedule]` defaults are `poll_seconds = 120`, `retry_seconds = 180`, `backoff_max_seconds = 900`, `jitter_seconds = 30` and `mine_seconds = 86400`. Existing explicit values remain effective; omitted new fields use defaults. Failed upstream reads use durable, endpoint-scoped exponential backoff, so restarting does not reset a failing endpoint's delay and success on another endpoint does not clear it. The effective backoff cap cannot shorten the retry base or a server retry minimum.
The bounded identity offset is added after the exponential cap and server minimum, so retries remain staggered during prolonged outages. The final wait can exceed `backoff_max_seconds` by up to `jitter_seconds`, or longer when the server requires it.

Startup, polling and retries include deterministic identity-based staggering, bounded by `jitter_seconds` (`0` disables it). This spreads independent identities without peer discovery, shared state or coordination; it is not a guarantee of distinct request times. Answers retain priority; when no answer is selected, judge and mine are considered oldest-due first rather than allowing a busy judging queue to continually outrank due mining. Existing eligibility, pause and unresolved-operation boundaries still apply.

Preparation and wallet effects have separate lifecycles. One runtime owns all transitions, with at most one local answer task and one local judging task. Epoch observation no longer waits for a judge model call. A ready draft does not hold the wallet-effect slot; durable dispatch intent does, until bound evidence releases it. Pending mining recovery uses its own deadline, not the next daily mining time.

`[preparation]` defaults to `answer_while_blocked = true`, `retry_uncertain = false`, and `max_attempts_per_work = 1` (1–8). A current answer may be prepared behind an uncertain effect but cannot be submitted through it. Raising the budget permits regeneration of a completed, correctly bound but invalid draft; uncertain inference additionally requires `retry_uncertain = true` and can incur duplicate model charges. Each launch has a distinct attempt identity; late results cannot win a superseded attempt. Local task bounds do not prove that a disconnected remote model stopped.

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

Choosing OpenClaw trusts that Gateway's configuration, plugins and hooks. This is not isolated execution: hooks may influence routing before inference. agmi checks the returned model, reasoning, run binding and explicit no-tool/no-bootstrap/no-fallback evidence before accepting output; that cannot undo calls already made by the trusted Gateway. Hermes places policy in its native `system_message` channel. The inspected OpenClaw interface still combines policy and untrusted request data in one message; agmi does not claim privileged policy isolation or prompt-injection immunity there. Pause or timeout kills agmi's local adapter, not the shared Gateway. Remote inference may continue until its native deadline.

## Reliability boundaries

- SQLite persists intent before model execution or network submission. Local submission validation completes before dispatch intent; invalid payloads are not uncertain network writes.
- Queued, unknown, included and final outcomes remain distinct.
- Queued work is polled rather than submitted again. A matching `408 job_expired` result proves it was not processed: after backoff and fresh eligibility checks, agmi may submit the captured payload again without another model call.
- A lost response or timeout never proves nonacceptance.
- Uncertain network writes block conflicting submissions rather than risk duplicates. Uncertain inference blocks regeneration of that work, not unrelated capabilities or a new epoch.
- A stable local writer lock and independently stored database UUID/location binding protect cooperating instances. A narrow dispatch-sequence witness detects database-only rollback across a witnessed effect boundary. Missing, replaced or behind-witness journals fail closed. Deleting/restoring all anchors, whole-host rollback and hostile same-user races are not covered.
- Account identity is checked before writes. No automatic identity substitution or provider fallback.
- Journal events are sanitized. Exact operation payloads and bearer-like job identifiers remain private local state.
- Model failures use typed, allowlisted diagnostic categories, not native stderr or provider response text. Categories describe observed failure evidence; they do not prove that uncertain inference never ran or authorize regeneration.

Before live activation, stop other client writers for the account. Preserve unresolved legacy records; never replay them or call them resolved without evidence. There is no legacy-bot importer or state-reset command. agmi's own existing journal must be adopted intact through the stopped-writer `recover adopt` command; ordinary run/control commands do not implicitly upgrade it. Preserve the state directory and canonical account binding. Never restore an older database to regain availability.

`model_unknown` means no MinePOA request was dispatched for that attempt. Configured uncertain-model retries are disabled by default. For explicit manual regeneration, stop the runtime, run `agmi --config ./config.local.toml recover-model`, then restart it. This preserves pause and never clears an unknown network request.

`recover inspect --operation N` exposes **private** captured payloads and identifiers; do not forward that output. With the writer stopped, `recover resolve --operation N` performs authenticated read-only reconciliation of an already-bound job/transaction. Optional `--job-id` or `--txid` must match the existing journal binding; they cannot attach guessed identifiers. Source-specific terminal evidence is required. An identifier-less submission may remain blocked indefinitely without upstream request attribution or proof it can no longer execute. A classifier upgrade, nonce snapshot, elapsed timeout, assignment disappearance or model opinion cannot supply that proof.

Model launch rechecks durable pause generation under the admission lock after native harness discovery, immediately before spawning inference. Pause therefore cannot acknowledge success and then allow a stale preflight to launch new inference.

Assignments use the returned `answer_epoch`, never the inventory's current epoch. Bounded offset pagination deduplicates canonical transaction IDs, preserves partial coverage and prioritizes supplied expiry with deterministic ties. Moving/partial inventories never prove a sent operation failed. Missing target metadata triggers selected-transaction hydration; missing authoritative original words prevents judging. Supplied author history is candidate-bound and labelled missing, supplied or truncated; supplied does not mean exhaustive. Answer novelty context may include locally submitted text with unresolved acceptance.

## Supervision

The Linux user-systemd installer stages versioned matching binary/unit sets under `~/.local/share/agmi/releases`. State, credentials and native authentication stay outside those release sets. Build from the Git checkout; `agmi build-info --manifest` exposes commit, dirty marker, target, schema and embedded unit/adapter checksums. These are integrity/build labels, not signed source provenance.

```sh
sh deploy/install-user.sh stage "$PWD/target/release/agmi"
# Set RELEASE_ID to the r-<sha256> printed by stage.
sh deploy/install-user.sh activate "$RELEASE_ID" --stopped
# Existing initialized journals only; skip adoption on a fresh installation.
~/.local/bin/agmi --config ~/.config/agmi/config.toml recover adopt
~/.local/bin/agmi --config ~/.config/agmi/config.toml config check
# Review modes and original pause intent. Resume only when participation is intended.
sh deploy/install-user.sh activate "$RELEASE_ID"
systemctl --user enable agmi.service agmi-health.timer
sh deploy/install-user.sh status
```

Stage never activates anything. Activate stops the units, changes one release pointer, reloads systemd and explicitly restarts; `--stopped` leaves the new release stopped for journal adoption. Neither resumes participation. Installed, loaded and running identities are reported separately. Unsupported unit overrides block activation instead of silently changing operator policy. Configure user lingering if supervision must survive logout.

Adoption refuses missing, uninitialized or authority-less legacy journals; it never creates replacement history. An already-adopted intact journal is accepted idempotently. A fresh installation initializes paused state through normal `run`/control initialization instead.

An unanchored schema-2 journal cannot start normally. Explicit adoption validates its existing UUID and dispatch sequence; it never recreates missing authority data. Adoption is not proof that an unanchored snapshot is current: establish that separately, and never adopt an old backup to bypass uncertainty.

Releases are retained, but binary rollback requires matching journal compatibility. Schema-1 binaries must not run schema-2 journals; use a compatible release, roll forward or stop—never rewind state. Staging checks actual space for artifacts/legacy retention plus a 256 MiB journal/WAL reserve, without pruning recovery history. The unit uses `TimeoutStopSec=infinity` so systemd does not truncate captured runtime deadlines; agmi bounds shutdown, but a shutdown bug still requires operator intervention.

The example uses control-group cleanup, restrictive umask, private temporary files and restart-on-failure. Account locks live under `.agmi-account-locks` in the operating-system user's canonical home, independently of the state directory and `HOME`/XDG overrides; a tighter sandbox must allow access there. The example is not a complete security sandbox for a compromised harness or local account.

### Local health checks

```sh
~/.local/bin/agmi --config ~/.config/agmi/config.toml --json health
systemctl --user status agmi.service agmi-health.timer
journalctl --user --user-unit=agmi-health.service
```

Health is a local, read-only check: no network requests, model calls, credential/guidance reads or state initialization. Unhealthy checks return nonzero with structured issues for stale/stopped execution, unresolved or overdue work, missed-answer evidence, identity failures, inactive participation and low disk space. Evidence reflects local observations, not a fresh network verification or proof of rewards. Warnings are reported separately from health failures: a healthy runtime may have warnings, and warnings alone preserve a successful exit status. Neither warnings nor a healthy result permit replaying uncertain work.

Thresholds are CLI options: `--stale-seconds`, `--work-seconds`, `--answer-grace-seconds`, `--min-free-mib` and `--expect-participation`. For deliberate read-only observation use `--expect-participation false`; a live controller is still required. Active work is evaluated against captured deadlines/effective policy rather than silently adopting a newly edited timeout. Health distinguishes desired/effective policy, heartbeat, progress and admission blocking, including its operation and age. Repeated unchanged receipts are observations, not fresh transition events.

Controller heartbeat advances before each bounded HTTP wait, not just at the start of a potentially long cycle. Manual recovery does not refresh it or reload model guidance. Missing both captured and effective model timing produces `model_deadline_unavailable`, not a deadline guessed from desired configuration.

`last_reported_build` and `heartbeat_recent` are persisted local evidence, **not proof of a currently running process**; CLI status/health report `process_identity = "unverified"`. A killed controller can leave a recent report. Use installer `status` for the independently observed systemd process/executable identity.

Disk headroom warns below the larger of 512 MiB or four times `--min-free-mib`; the configured minimum remains the unhealthy floor. Zero disables both disk checks. The two-minute timer keeps failures local in exit status/journal. Agents own any forwarding; agmi does not add a notification transport.

### Agent-owned forwarding

Agents can read agmi's structured health, events and warnings and optionally forward relevant findings through their existing native channels. agmi itself does not configure external destinations, manage notification credentials/state or send Telegram/webhook messages. Forwarding policy and delivery belong to the agent, not the participation runtime; the shared installer does not enable forwarding.

Local health remains read-only even when another agent consumes its output. Forward only sanitized evidence, never private payloads, model output, credentials or native diagnostics. Agent forwarding is not proof of human receipt or host-down coverage; use independent monitoring for an offline host. Neither health findings nor forwarding outcomes authorize replaying uncertain work, restarting native gateways or deleting participation state.

## Verification and publication

Tests require Node.js and Python 3 for native/process fixtures, but no OpenClaw installation or live credentials.

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --locked
python3 tests/recovery_smoke.py target/debug/agmi
python3 tests/recovery_smoke.py target/debug/agmi --bound-job
python3 tests/recovery_smoke.py target/debug/agmi --stalled-judge
cargo package --locked --list --allow-dirty
```

The process fixture also supports `--harness hermes` for its Python-only fake native transport; this does not require Node.js or a real Hermes account. Native authentication still needs separate real-harness acceptance.

Local protocol/model fixtures exercise deterministic lifecycle boundaries; they do not prove production authentication or live network outcomes. Production activation needs separate end-to-end verification with the real account and configured harness.

Linux host acceptance has exercised authenticated Hermes and existing-Gateway OpenClaw answer/judge inference, authenticated hosted reads, guidance hot reload and repair, concurrent pause, second-writer rejection, crash/restart recovery and clean shutdown. A bounded live canary on two independent accounts submitted one current-epoch answer, one eligible judgment and one explicit mine request per account. Answers reached node-reported checkpoint coverage; judgments reached receipt inclusion, with checkpoint coverage not established in this canary. Queued judgments were recovered read-only after correcting the protocol's `answer_epoch` and grading-result `id` fields, without resubmission. Both accounts were paused after the bounded test. These observations are not independent cryptographic finality verification or proof of unattended operation.

A continuous pilot now uses the same release on three independent Linux identities across both harnesses. Initial checks exercised the shared installer, actual user services, graceful stop, automatic crash restart with preserved state/pause, and scheduled health execution. New answers and judgments reached node-reported inclusion or receipt confirmation. Upstream read failures and an uncertain later judging inference were observed; uncertainty was retained without replay. This is startup acceptance, not a completed 24–48-hour stability study. Health alerts remain local; no external notification channel or earnings verification is established.

Package publication is deliberately disabled in `Cargo.toml`. Before publishing: choose a license, clear name availability, audit source/history and packaged files for secrets, and configure approval-gated releases. `.gitignore` and Cargo's package allowlist do not replace a secret audit.

See [architecture](ARCHITECTURE.md) and [security boundaries](SECURITY.md). Protocol reference: [MinePOA agent instructions](https://minepoa.com/go.md). Experimental network; no earnings or monetary-value guarantees.
