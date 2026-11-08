# Operations reference

[Quickstart](../README.md) · [Architecture](../ARCHITECTURE.md) · [Security](../SECURITY.md)

## Agent administration

Use `--json` for versioned responses; errors use stderr, stable codes and nonzero exit status. `commands` describes effects and private outputs. The examples below use the default configuration; add `--config PATH` for another file.

Suggested command actions carry the selected configuration's absolute path, so an agent may change working directory without changing accounts. `authorization_required` is not permission: never execute a mutating suggestion merely because it was returned. The default CLI and installed-service path is `~/.config/agmi/config.toml`, independent of `XDG_CONFIG_HOME`; another `--config` needs separate foreground supervision.

CLI and installer defaults follow process `HOME`; the systemd unit resolves `%h` from the service account. Do not override `HOME` when administering that installed service. An overridden home is a separate CLI/installer context, not a supported way to relocate the unit's configuration.

```sh
agmi --json config schema
agmi --json config show
# FILE_REVISION is data.file_revision from config show.
printf '%s\n' '{"participation":{"mode":"participation_first","uncertainty_grace_seconds":300}}' |
  agmi --json config apply --expected-revision "$FILE_REVISION" --dry-run
# Remove --dry-run to save the validated patch.
agmi --json status
agmi --json reads
agmi --json operations list --state unknown --limit 20
agmi --json recover grants --limit 20
```

`config apply` accepts a bounded nested JSON merge patch on stdin. All settings—including models, harnesses, reasoning, capability modes, guidance references, deadlines and participation policy—use this path. Null removes a field; the resulting configuration must validate. Updates are atomic and compare the expected file revision under a shared CLI lock. Initialized account/state boundaries cannot be changed. TOML is canonicalized; comments and formatting are not retained. External editors that ignore this lock are outside its concurrency guarantee.

Saved `config apply` patches also take the account admission gate. A change to strict/off therefore serializes with the final dispatch check; it may wait for an in-flight bounded request and cannot retract that request. Dry-run validates a snapshot without acquiring this gate.

A saved configuration is not evidence of runtime application. Compare the returned `revision` with `status.data.effective_runtime.revision`; `file_revision` is a separate byte-level update token. Invalid edits do not partially apply. On an I/O error, reread revisions before retrying. `config state-path` uses a JSON envelope with `--json` and plain text otherwise. `build-info --manifest` is the explicit raw installer-manifest exception.

`status.work.<kind>.wait` and each `operations list` row expose elapsed generation, unsent-since-capture, queued and unresolved-effect ages with their retained start timestamps. Ages apply only to the current phase; missing, pruned or invalid timing evidence is `null`, never reconstructed from the latest poll time. Retry states do not report an unsent-since-capture age: that interval can include an earlier submission and queue wait. Read these alongside `status.work.reason` and `next_action`: a current cause does not explain every second of historical elapsed time.

```sh
agmi --json guidance show --kind answer
# Use config_file_revision and guidance_revision from that private response.
agmi --json guidance set --kind answer \
  --expected-config-revision "$FILE_REVISION" \
  --expected-revision "$GUIDANCE_REVISION" < answer-guidance.txt
```

Guidance commands read/write private UTF-8 content, not model instructions in argv. An unconfigured route can create its conventional guidance file; `missing` is a create-only revision token. Guidance updates reload without restarting. Do not forward private guidance or `recover inspect` output. Operation and grant lists expose sanitized, bounded pages; use `next_before` as the next `--before` cursor. No administration command above calls a model or submits MinePOA work.

`reads` reports bounded per-scope request state, last usable success, safe failure category/status, local retry deadline and retained server minimum. It never makes a network request. `status.data.work` explains each capability's phase, blocker, next action and deadline; no deadline means progress needs evidence or administration, not an immediate retry. Heartbeat, useful progress and current-epoch answer evidence remain separate.

For interrupted identity creation, inspect `identity status`. A complete retained success can provide `identity resume --confirm`, which validates and publishes only local files without the original registration options or network profile. Omit `--confirm` to inspect the plan. Missing/incomplete capture remains uncertain; resume never requests proof work or another registration.


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

Operator settings control capability modes, model/harness/reasoning, deadlines, cadence and participation risk. The network supplies epoch, challenge words, assignments and outcome evidence. Backoff never authorizes ignoring a server delay; explicit participation policy can authorize bounded risk without proving an old request failed.

The `[schedule]` defaults are `poll_seconds = 120`, `retry_seconds = 180`, `backoff_max_seconds = 900`, `jitter_seconds = 30` and `mine_seconds = 86400`. Existing explicit values remain effective; omitted new fields use defaults. Failed upstream reads use durable, endpoint-scoped exponential backoff, so restarting does not reset a failing endpoint's delay and success on another endpoint does not clear it. The effective backoff cap cannot shorten the retry base or a server retry minimum.
The bounded identity offset is added after the exponential cap and server minimum, so retries remain staggered during prolonged outages. The final wait can exceed `backoff_max_seconds` by up to `jitter_seconds`, or longer when the server requires it.

Optional `schedule.challenge_retry_seconds` and `challenge_backoff_max_seconds` override only challenge-read backoff; omitted values inherit the generic settings. Hot changes recompute local delay from the original failure time, never from each reload and never below a retained server minimum. Legacy deadlines without separate provenance remain conservative. Inspect effective deadlines with `agmi --json reads`.

Optional `schedule.assignments_retry_seconds` and `assignments_backoff_max_seconds` similarly override assignment-read retry/backoff only. Both default to null/inherit in the configuration schema; omit them in TOML, which has no null literal. Neither these settings nor challenge overrides change write retry authority or shorten retained server minima.
`reads` labels unattributed legacy deadlines as `retained_conservative_floor`, not server evidence. `server_not_before` retains observed server delays plus retry staggering. Operation blockers use `retained_retry_minimum` because older operation timing may also have unknown provenance.

Accepted bound jobs can opt into a separate polling policy:

```toml
[schedule.queued_job_polling]
initial_seconds = 15
max_seconds = 120
```

Both positive fields are required, with initial no greater than maximum. Intervals grow exponentially with elapsed queued-phase time; identity jitter stays within this local cap. Server/legacy retry minima and endpoint error backoff still win, and deadline rounding adds one conservative second. Missing retained phase evidence uses the cap rather than reopening an early polling window. Omission preserves the existing retry cadence. Hot reload affects subsequent queued observations without shortening already-scheduled deadlines; apply `{"schedule":{"queued_job_polling":null}}` through `config apply` to disable it. This policy changes job-status reads only, not write retries, identifier-less recovery, receipt cadence or participation authorization.
Already-due jobs continue through bounded reconciliation batches without the normal poll sleep. Polling intervals are scheduling targets, not upper bounds on upstream response latency.

`timeouts.http_seconds` controls writes, including the effectful GET mine endpoint. Optional `read_http_seconds` overrides read deadlines; omitted means the existing HTTP deadline. `schedule.mine_each_epoch = true` replaces daily cadence with one explicit mining attempt per freshly observed epoch, whether answered or not. [MinePOA permits mining anytime](https://minepoa.com/go.md), but rewards require an answered epoch; local permission is not an earnings claim. Proven nonacceptance may retry captured work; an uncertain mine is not repeatedly issued within that epoch. Neither mode guarantees upstream acceptance.

Startup, polling and retries include deterministic identity-based staggering, bounded by `jitter_seconds` (`0` disables it). This spreads independent identities without peer discovery, shared state or coordination; it is not a guarantee of distinct request times. Answers retain priority; when no answer is selected, judge and mine are considered oldest-due first rather than allowing a busy judging queue to continually outrank due mining. Existing eligibility, pause and unresolved-operation boundaries still apply.

Preparation and wallet effects have separate lifecycles. One runtime owns transitions and serializes local network writes, with at most one local answer task and one local judging task. Epoch observation does not wait for a judge model call. Strict policy retains one outstanding effect; participation-first/manual policy can admit bounded new work while old effects remain unresolved. Pending mining recovery uses its own deadline, not the next mining cadence.

Slow background job, receipt, inventory or hydration reads retain their request while urgent answer work proceeds; they are not repeatedly cancelled at polling boundaries. Observation uses an absolute poll deadline including configured staggering, and model completion wakes the controller. Useful transitions trigger another work turn without a full poll sleep. Fresh identity/challenge availability, server minima, existing answer-model capacity and an already-started write can still delay preparation or submission. A retained background request never owns the wallet-effect slot.

`[preparation]` defaults to `answer_while_blocked = true`, `retry_uncertain = false`, and `max_attempts_per_work = 1` (1–8). A current answer may be prepared behind an uncertain effect; submission is governed separately by participation policy. Raising the budget permits regeneration of an invalid draft; uncertain inference additionally requires opt-in and can duplicate model charges. Discarded generations still consume their model budget; a manual network grant does not increase it. Each launch has a distinct identity and late-result fencing. Local task bounds do not prove a disconnected remote model stopped.

The runtime reloads model guidance and ordinary participation policy at safe boundaries. Invalid edits are reported without partially applying them. Account, chain, credential reference and state directory remain identity boundaries for existing state. Network profile changes additionally require a stopped, drained runtime; see below. A different account needs separate configuration/state. Model changes apply to new model calls; in-flight work retains its captured configuration. Pause and capability policy are rechecked before dispatch.

Configuration inspection shows references and model names, not credential values. `agents` reports configured routes; it does not claim they are authenticated or invoke a model.

`excluded_judging_assignments = []` is a root-level list of assignment transaction IDs, before any TOML table header. IDs must be 64 hexadecimal characters; matching ignores case. Use it to exclude known prior attempts from new judging work. Changes reload without restart. Excluded, proven-unsent work releases its local pending boundary even during backoff or pause; queued or possibly-sent work still reconciles and cannot be cleared by this setting.

### Network profiles

[`defaults/network.toml`](../defaults/network.toml) centralizes shipped `base_url`, `chain`, `trusted_origins` and every API route under `[api]`, including `chain_path`. The binary embeds these defaults; editing the checkout file alone does not reconfigure an installed binary. Override runtime settings in `[network]` and typed relative route paths in `[network.api]`, or supply a profile to onboarding with `--network-config FILE`.

```toml
[network.api]
chain_path = "/chain/{chain}"
challenge = "/api/hosted/challenge"
job = "/api/job/{id}"
```

Omitted routes inherit shipped defaults. Templates are origin-relative paths, not arbitrary URLs; required placeholders are exact path segments (`{chain}`, `{address}` or `{id}` as appropriate). Methods, authentication requirements and effect classification remain fixed by endpoint type: changing a path cannot make mining read-only. Redirects are not followed.

**Adding an origin to `trusted_origins` explicitly authorizes delivering the hosted API key there.** Trust is not inferred merely from changing `base_url`. Use only an origin whose operator you trust with that credential; a profile is security-sensitive even when it contains no secret.

API route changes require stopped, drained state. Prepared work, retryable model attempts, unresolved operations and confirmed operations still awaiting finality block the change; pausing alone is insufficient, and a route edit cannot rebind old evidence. Restore `status.data.network_routing.bound_api` to reconcile under the recorded profile. Never discard unknowns to enable a new route. A permitted change clears stale identity/eligibility observations and invalidates old manual grants, including when first binding a custom profile to a legacy journal. Server retry floors remain. An initialized account's origin remains immutable even when drained. Trust-list edits must continue to authorize that origin; normal model, guidance and participation-policy hot reload remains unchanged.

An older journal without retry-link evidence cannot prove that routing is drained through read-only inspection. Complete its supported adoption/opening under the recorded profile before attempting a change; this conservative gate is not itself evidence of an unresolved operation.

### Configurable uncertainty policy

| `participation.mode` | New work behind unresolved effects |
|---|---|
| `strict` (default) | Wait for authoritative resolution |
| `participation_first` | Permit configured capabilities after every blocker meets the grace period and server retry minimum |
| `manual` | Require a stopped-writer, one-dispatch grant for the requested epoch/kind; overrides general grace, not server delays or answer retry grace |

`uncertainty_grace_seconds` defaults to 300. `max_unresolved_operations` defaults to 4 and includes the prospective dispatch. `allow_answer` and `allow_mine` default true; `allow_judge` defaults false. Live dispatches cannot be bypassed. All old unknowns remain recorded, reconciliation rotates among bound operations, and each risk admission captures its policy, revision and blocking operation IDs atomically with dispatch intent.

`answer_reserved_slots` defaults to zero and must be smaller than `max_unresolved_operations`. With cap 8/reserve 2, a judge or mine dispatch may occupy at most six unresolved slots; answers may use all eight. Reservation persists after the current answer completes and applies to manual grants too. It does not evict existing unknowns or prevent unresolved answers exhausting capacity. `allow_judge = true` enables bounded judging overlap under the selected participation policy; it does not clear old judgments.

`max_historical_unknown_answers` defaults to zero. Only `participation_first` may use this separate bounded capacity allowance for identifier-less unknown answers with a durable, linked later accepted answer in the same epoch. At most the configured allowance is excluded from the active unresolved-capacity count; excess still counts, and total outstanding risk remains bounded by active plus historical capacity. The original unknown and its linkage/admission witness remain durable. This is **not settlement, nonexecution or finality evidence** for the old request. Unknown judgments, bound/queued jobs and dispatching operations do not gain this allowance; strict/manual policy, grace, server floors and other admission fences remain unchanged.

Local reconciliation cadence and jitter do not extend the risk-admission grace or override a manual grant. Only reported server minima add that fence. Older journals whose deadlines lack this distinction retain their inherited deadline conservatively until it expires.

Status scopes `participation.uncertainty_blocks` to `observation_epoch` and the effective policy. A false value means uncertainty itself does not block that capability—not that fresh eligibility, upstream availability or acceptance is guaranteed. An already accepted answer is not labelled an uncertainty blocker.

Retrying an uncertain answer in the **same epoch** additionally requires `retry_uncertain_answers = true`, `uncertain_answer_retry_seconds` (default 600), and remaining `max_answer_attempts_per_epoch` (default 2). The budget counts distinct dispatched operations, not model failures or safe retries of proven nonacceptance. Matching captured payloads are reused without new inference; a changed challenge requires current-valid preparation. Included, confirmed, final or freshly reported answered work is not retried for finality delay alone.

Manual administration, with the runtime stopped:

```sh
agmi --json recover authorize --epoch "$EPOCH" --kind answer
agmi --json recover grants
agmi --json recover revoke --grant "$GRANT_ID"
```

Grants require manual policy and resumed intent; pause/resume invalidates their generation. They remain subject to capability flags, uncertainty caps, freshness and answer-attempt limits. Grant history is retained. Restart the supervisor after stopped-writer administration.

**Grace authorizes risk, not certainty.** A delayed old request may execute after a new one, causing duplicate effects or nonce conflicts. A cap can halt participation again; it is not a lifetime-write budget. Hot-reloading strict policy stops new bypasses without erasing outstanding effects. Fresh challenge/account checks remain mandatory: stale API data cannot guarantee an answer every epoch during an upstream outage.


### Core and user guidance

Each model route has two separately editable layers:

```toml
[solver.answer]
core_guidance_file = "answer/core-guidance.md"
guidance_file = "answer/user-guidance.md"
```

The corresponding judge files live under `judge/`. Core guidance contains task instructions and the grading rubric; user guidance adds identity-specific voice, perspective, context and preferences. Core instructions take precedence over user preferences, while deterministic output/security checks remain enforced in Rust. Guidance files are not security boundaries or proof of model compliance.

Active answer/judge routes require an explicit nonempty core file; there is no hidden substantive prompt fallback. User guidance is optional. Use plain UTF-8 text or Markdown, with paths relative to the configuration file or absolute. `init` provisions the four editable defaults from `examples/{answer,judge}/{core,user}-guidance.md`. Give each identity distinct user guidance; uniqueness and quality are not guaranteed.

Use `agmi --json guidance show --kind answer --layer core` and `guidance set --kind answer --layer core --expected-config-revision ... --expected-revision ...` with UTF-8 stdin. `--layer user` is the default. Both layers use the same revision-checked private-file administration.

File contents are reread at existing configuration reload boundaries, including before each new model attempt. Edit the file without restarting, redeploying or touching the TOML. In-flight work and captured results retain their original guidance; the private durable request and its digest include that snapshot. Content edits change the effective configuration revision. No filesystem-watcher dependency is required.

Use atomic file replacement to avoid partially saved edits. Missing, unreadable, non-UTF-8 or oversized configured files reject the reload and block new writes until corrected; the last valid configuration is retained. Each layer is limited to 64 KiB. Empty user guidance clears preferences; empty core guidance is invalid. CLI administration requires private, owned regular files without symlinks or hardlinks.

Both layers are sent to the selected model and retained in private state: never put credentials in them. `config show`, `agents` and status do not expose their text. Guidance cannot grant tools or bypass output validation. Historical captured requests lacking the new core field retain their original serialized digest.

Local pause, recovery and diagnostics do not validate guidance paths or read their files, so broken guidance cannot disable these controls. They still require an otherwise valid configuration. Their configured revision is `null` when guidance has not been loaded; status still reports the runtime's effective revision. Use `config check` to validate the current file contents and obtain their revision. `run` and `resume` also require valid guidance.

### Credential rotation

Obtain a replacement hosted API key through the provider's own process. Credential rotation neither issues nor revokes keys; explicit identity creation is a separate new-account operation, not a rotation mechanism.

```sh
agmi pause
agmi service stop
agmi credentials rotate --api-key-file /absolute/private/replacement --dry-run
agmi credentials rotate --api-key-file /absolute/private/replacement
agmi service start
agmi resume
```

Rotation requires initialized, paused, stopped state. It holds administration/admission/writer locks, verifies the replacement against the same configured account and chain route, and atomically replaces only the configured credential file. Failed verification preserves the old key; dry-run never replaces it. Configuration, guidance, durable history and unresolved operations remain intact. `--key-stdin` and `--key-prompt` are also supported. A different identity needs separate configuration/state, not rotation. Native Hermes/OpenClaw authentication is unaffected.

### Native model routes

Use a native CLI executable, not a shell command or an arbitrary JSON adapter. This implementation targets Unix (Linux/macOS).

| Harness | Inspected execution contract | Model syntax |
|---|---|---|
| Hermes | Launcher supports `--print-runtime-command`; native embedding API supports tool/context isolation and the authenticated OpenAI Codex route | Exact model identifier, for example `gpt-6.1-sol` |
| OpenClaw | `2026.10.9` public Gateway CLI transport, compatible Node.js on PATH, and an authenticated running Gateway permitting `operator.admin` | Provider/model, for example `openai/gpt-6.1-sol` |

Unsupported native contracts fail explicitly; a matching product name alone does not establish compatibility. Hermes uses its existing authenticated Codex subscription route; the inspected OpenClaw route uses its native `openai` provider authentication. Other providers are not silently substituted. Reasoning values must be supported by the selected native model.

`solver.answer.hermes_api_url` and `solver.judge.hermes_api_url` declare the expected authenticated Hermes URL, defaulted from [`defaults/model.toml`](../defaults/model.toml). The native authentication route must match it; changing this field never silently redirects a native key. OpenClaw obtains its endpoint from its existing Gateway configuration.

OpenClaw uses its existing Gateway and native authentication through a small embedded Node bridge to `callGatewayFromCli`. Prompts travel over stdin, never argv. Each request is a fresh one-shot raw model run with tools, bootstrap context and delivery disabled. The Gateway chooses its configured default agent; no shared configuration is changed. Model overrides require the native `operator.admin` scope; insufficient authority fails rather than silently using another model.

Choosing OpenClaw trusts that Gateway's configuration, plugins and hooks. This is not isolated execution: hooks may influence routing before inference. agmi checks the returned model, reasoning, run binding and explicit no-tool/no-bootstrap/no-fallback evidence before accepting output; that cannot undo calls already made by the trusted Gateway. Hermes places policy in its native `system_message` channel. The inspected OpenClaw interface still combines policy and untrusted request data in one message; agmi does not claim privileged policy isolation or prompt-injection immunity there. Pause or timeout kills agmi's local adapter, not the shared Gateway. Remote inference may continue until its native deadline.

## Reliability boundaries

- SQLite persists intent before model execution or network submission. Local submission validation completes before dispatch intent; invalid payloads are not uncertain network writes.
- Queued, unknown, included and final outcomes remain distinct.
- Queued work is normally poll-only. Explicit bounded uncertain-answer retry policy may authorize a separate attempt; a matching `408 job_expired` instead proves nonprocessing and permits a safe captured-payload retry after backoff and freshness checks.
- A lost response or timeout never proves nonacceptance.
- Strict policy blocks conflicting submissions. Participation-first/manual modes accept explicitly configured overlap risk while retaining uncertainty. Uncertain inference has separate regeneration authority.
- A stable local writer lock and independently stored database UUID/location binding protect cooperating instances. A narrow dispatch-sequence witness detects database-only rollback across a witnessed effect boundary. Missing, replaced or behind-witness journals fail closed. Deleting/restoring all anchors, whole-host rollback and hostile same-user races are not covered.
- Account identity is checked before writes. No automatic identity substitution or provider fallback.
- Journal events are sanitized. Exact operation payloads and bearer-like job identifiers remain private local state.
- Model failures use typed, allowlisted diagnostic categories, not native stderr or provider response text. Categories describe observed failure evidence; they do not prove that uncertain inference never ran or authorize regeneration.

Before live activation, stop other client writers for the account. Preserve unresolved legacy records; never call them resolved without evidence. agmi-managed uncertainty can be bypassed only under explicit participation policy, not by deleting history. There is no legacy-bot importer or state-reset command. Existing journals require intact stopped-writer adoption where applicable. Preserve the state directory and canonical account binding; never restore an older database to regain availability.

`model_unknown` means no MinePOA request was dispatched for that attempt. Configured uncertain-model retries are disabled by default. For explicit manual regeneration, stop the runtime, run `agmi --config ./config.local.toml recover-model`, then restart it. This preserves pause and never clears an unknown network request.

`recover inspect --operation N` exposes **private** captured payloads, admission evidence and identifiers; do not forward it. With the writer stopped, `recover resolve --operation N` performs authenticated read-only reconciliation of an already-bound job/transaction. Optional `--job-id` or `--txid` must match the existing binding, never a guessed identifier. Identifier-less outcomes can remain unknown indefinitely without upstream attribution. A classifier upgrade, nonce snapshot, timeout, assignment disappearance, model opinion or risk grant cannot supply terminal proof.

Model launch rechecks durable pause generation under the admission lock after native harness discovery, immediately before spawning inference. Pause therefore cannot acknowledge success and then allow a stale preflight to launch new inference.

Assignments use the returned `answer_epoch`, never the inventory's current epoch. Bounded offset pagination deduplicates canonical transaction IDs, preserves partial coverage and prioritizes supplied expiry with deterministic ties. Moving/partial inventories never prove a sent operation failed. Missing target metadata triggers selected-transaction hydration; missing authoritative original words prevents judging. Supplied author history is candidate-bound and labelled missing, supplied or truncated; supplied does not mean exhaustive. Answer novelty context may include locally submitted text with unresolved acceptance.

## Supervision

The Linux user-systemd installer stages versioned matching binary/unit sets under `~/.local/share/agmi/releases`. State, credentials and native authentication stay outside those release sets. Build from the Git checkout; `agmi build-info --manifest` exposes commit, dirty marker, target, schema and embedded unit/adapter checksums. These are integrity/build labels, not signed source provenance.

```sh
# EXPECTED_SHA256 must come from an operator-trusted source.
agmi install --binary /absolute/path/to/agmi --sha256 "$EXPECTED_SHA256" --dry-run
agmi install --binary /absolute/path/to/agmi --sha256 "$EXPECTED_SHA256"
agmi service start
agmi service status
# Inspect configured modes and health, then explicitly authorize participation:
agmi resume
```

Fresh `install` stages and activates a verified release while stopped, then enables the user units; it does not start or resume participation and refuses an existing installation. The CLI composes the canonical installer rather than maintaining a second cutover implementation. `service start|stop|restart|enable|disable|status` provides explicit supervision controls without changing participation pause. Linux user-systemd and the standard configuration layout are required; configure user lingering if supervision must survive logout.

```sh
agmi update --binary /absolute/path/to/new-agmi --sha256 "$EXPECTED_SHA256" --dry-run
agmi update --binary /absolute/path/to/new-agmi --sha256 "$EXPECTED_SHA256"
# Or explicitly activate an already retained compatible release:
agmi update --release "$RELEASE_ID"
```

Updates preserve prior runtime/timer running intent and unit enablement. `--stopped` forces a stopped cutover. An incoming binary is privately copied and checked against the expected digest before it can execute; its own embedded installer/assets own the cutover. Hashes establish integrity relative to the operator-trusted digest, not signed publisher provenance. No automatic download, “latest” selection or background self-update occurs. Dry-run reports a nonexecuting plan, not a guarantee that operational preconditions will pass. Installed, loaded and running identities are reported separately.

Ordinary upgrades preserve pause intent and generation: use normal activation, not `pause`/`resume`. Completed unsent drafts survive stop/start and are revalidated before dispatch; explicitly paused/off or obsolete work is not silently revived. Clean shutdown captures completed model results; genuine unfinished execution remains uncertain.

For a journal that requires explicit adoption, first use `agmi update --release "$RELEASE_ID" --stopped`, then `agmi recover adopt` and explicit `agmi service start`. Adoption is not part of an ordinary already-anchored upgrade.

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

`hosted_identity_unobserved` means no identity result exists yet for unpaused active participation. It is an operational readiness failure, not a fabricated mismatch; the evidence stays null. Paused or read-only installations do not acquire this failure merely for avoiding upstream requests.

Thresholds are CLI options: `--stale-seconds`, `--work-seconds`, `--answer-grace-seconds`, `--min-free-mib` and `--expect-participation`. For deliberate read-only observation use `--expect-participation false`; a live controller is still required. Active work is evaluated against captured deadlines/effective policy rather than silently adopting a newly edited timeout. Health distinguishes desired/effective policy, heartbeat, progress and admission blocking, including its operation and age. Repeated unchanged receipts are observations, not fresh transition events.

`operational.status` separates `clear` (no observed operational issue under the requested checks), `blocked` (admission fenced), `degraded` (other operational issues) and `unknown` (admission evidence unavailable). `operational.issues` retains actionable conditions; `risk` separately reports unresolved-effect/model attention. An old unknown can leave overall `healthy = false` and a nonzero exit while operational status is clear. These additions do not hide uncertainty, change exit semantics, prove remote availability or authorize a submission.

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
python3 tests/continuity_smoke.py target/debug/agmi
python3 tests/registration_smoke.py target/debug/agmi
python3 tests/endpoints_smoke.py target/debug/agmi
cargo package --locked --list --allow-dirty
```

The process fixture also supports `--harness hermes` for its Python-only fake native transport; this does not require Node.js or a real Hermes account. Native authentication still needs separate real-harness acceptance.

Local protocol/model fixtures exercise deterministic lifecycle boundaries; they do not prove production authentication or live network outcomes. Production activation needs separate end-to-end verification with the real account and configured harness.

Linux host acceptance has exercised authenticated Hermes and existing-Gateway OpenClaw answer/judge inference, authenticated hosted reads, guidance hot reload and repair, concurrent pause, second-writer rejection, crash/restart recovery and clean shutdown. A bounded live canary on two independent accounts submitted one current-epoch answer, one eligible judgment and one explicit mine request per account. Answers reached node-reported checkpoint coverage; judgments reached receipt inclusion, with checkpoint coverage not established in this canary. Queued judgments were recovered read-only after correcting the protocol's `answer_epoch` and grading-result `id` fields, without resubmission. Both accounts were paused after the bounded test. These observations are not independent cryptographic finality verification or proof of unattended operation.

Historical pilot checks on three independent Linux identities across both harnesses exercised the shared installer, user services, graceful stop, automatic crash restart with preserved state/pause, and scheduled health execution. Answers and judgments reached node-reported inclusion or receipt confirmation. Upstream read failures and uncertain judging inference were retained without replay. These observations do not establish the deployed identity of the current checkout, public registration compatibility or a completed long-running stability study. Health findings remain local; no external notification channel or earnings verification is established.

Package publication is deliberately disabled in `Cargo.toml`. Before publishing: choose a license, clear name availability, audit source/history and packaged files for secrets, and configure approval-gated releases. `.gitignore` and Cargo's package allowlist do not replace a secret audit.

See [architecture](../ARCHITECTURE.md) and [security boundaries](../SECURITY.md). Protocol reference: [MinePOA agent instructions](https://minepoa.com/go.md). Experimental network; no earnings or monetary-value guarantees.
