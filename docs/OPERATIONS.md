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

`reads` and operation evidence expose bounded error categories, never raw provider
messages or credentials. HTTP status and transport/body failure remain separate
evidence: an interrupted 503 body may be labeled `timeout`, not a proven halt.

| Category | Next action |
| --- | --- |
| `halt_middleware`, `endpoint_halted`, `service_unavailable`, `bad_gateway`, `gateway_timeout`, `upstream_error` | Let scheduled read recovery proceed; inspect freshness and work deadlines. |
| `rate_limited`, `answer_global_ceiling`, `grade_queue_full` | Honor the retained retry floor; do not restart to bypass it. |
| `authentication_rejected`, `permission_denied` | Inspect credential configuration with `config check` and recorded endpoint evidence with `reads`; neither validates a credential remotely. Do not move credentials into a URL or register a replacement identity. A 403 alone does not prove an invalid key. |
| `redirect_refused`, `not_found`, `gone`, `request_rejected`, `upstream_rejected` | Inspect the configured network profile and operation evidence. A missing job or receipt is not proof a write failed. |
| `invalid_json`, `body_interrupted`, `response_too_large`, `timeout`, `connect` | Preserve uncertainty and let endpoint-scoped read backoff run; escalate if evidence becomes stale or work overdue. |

The longest parseable `Retry-After` header (seconds or HTTP-date) and JSON
`retry_after_seconds` wins. Displayed deadlines mean **retry no earlier than**,
not “the service will be restored at this time.” Free-form outage prose is not
parsed into a recovery timestamp. Unknown error bodies retain a safe HTTP or
transport category; they never silently become success.

For submissions, a complete, structurally valid JSON HTTP 429 refusal or a 503
with the exact halt middleware error on answer/judge submission permits retry
of retained work after backoff and fresh eligibility checks. This follows the upstream developer's pre-acceptance rejection contract;
it is not a general rule that all 4xx/5xx responses prove nonexecution.
Acceptance indicators or contradictory response fields prevent this shortcut.
Generic 503, 502/504, interrupted responses and timeouts remain uncertain.
Job/receipt lookup errors never establish rejection of the original submission.
Retained server minima still apply, including an earlier one-hour `Retry-After`;
maintenance prose or an expected server fix does not shorten them.

Accepted bound jobs can opt into a separate polling policy:

```toml
[schedule.queued_job_polling]
initial_seconds = 15
max_seconds = 120
```

Both positive fields are required, with initial no greater than maximum. Intervals grow exponentially with elapsed queued-phase time; identity jitter stays within this local cap. Server/legacy retry minima and endpoint error backoff still win, and deadline rounding adds one conservative second. Missing retained phase evidence uses the cap rather than reopening an early polling window. Omission preserves the existing retry cadence. Hot reload affects subsequent queued observations without shortening already-scheduled deadlines; apply `{"schedule":{"queued_job_polling":null}}` through `config apply` to disable it. This policy changes job-status reads only, not write retries, identifier-less recovery, receipt cadence or participation authorization.
Already-due jobs continue through bounded reconciliation batches without the normal poll sleep. Polling intervals are scheduling targets, not upper bounds on upstream response latency.

`timeouts.http_seconds` defaults to 90 seconds and controls writes, including the effectful GET mine endpoint. Optional `read_http_seconds` overrides read deadlines; omitted means reads inherit `http_seconds` (also 90 seconds by default). Explicit configured values remain authoritative. `schedule.mine_each_epoch = true` replaces daily cadence with one explicit mining attempt per freshly observed epoch, whether answered or not. [MinePOA permits mining anytime](https://minepoa.com/go.md), but rewards require an answered epoch; local permission is not an earnings claim. Proven nonacceptance may retry captured work; an uncertain mine is not repeatedly issued within that epoch. Neither mode guarantees upstream acceptance.

Startup, polling and retries include deterministic identity-based staggering, bounded by `jitter_seconds` (`0` disables it). This spreads independent identities without peer discovery, shared state or coordination; it is not a guarantee of distinct request times. Answers retain priority; when no answer is selected, judge and mine are considered oldest-due first rather than allowing a busy judging queue to continually outrank due mining. Existing eligibility, pause and unresolved-operation boundaries still apply.

Preparation and wallet effects have separate lifecycles. One runtime owns transitions and serializes local network writes, with at most one local answer task and one local judging task. Epoch observation does not wait for a judge model call. Strict policy retains one outstanding effect; participation-first/manual policy can admit bounded new work while old effects remain unresolved. Pending mining recovery uses its own deadline, not the next mining cadence.

Slow background job, receipt, inventory or hydration reads retain their request while urgent answer work proceeds; they are not repeatedly cancelled at polling boundaries. Observation uses an absolute poll deadline including configured staggering, and model completion wakes the controller. Useful transitions trigger another work turn without a full poll sleep. Fresh identity/challenge availability, server minima, existing answer-model capacity and an already-started write can still delay preparation or submission. A retained background request never owns the wallet-effect slot.

`[preparation]` defaults to `answer_while_blocked = true`, `retry_uncertain = false`, and `max_attempts_per_work = 2` (1–8). A current answer may be prepared behind an uncertain effect; submission is governed separately by participation policy. The default budget permits one additional model attempt after a completed, bound invalid draft, at additional model cost; uncertain inference still requires opt-in and can duplicate model charges. Discarded generations still consume their model budget; a manual network grant does not increase it. Each launch has a distinct identity and late-result fencing. Local task bounds do not prove a disconnected remote model stopped.

The runtime reloads model guidance and ordinary participation policy at safe boundaries. Invalid edits are reported without partially applying them. Account, chain, credential reference and state directory remain identity boundaries for existing state. Network profile changes additionally require a stopped, drained runtime; see below. A different account needs separate configuration/state. Model changes apply to new model calls; in-flight work retains its captured configuration. Pause and capability policy are rechecked before dispatch.

Configuration inspection shows references and model names, not credential values. `agents` reports configured routes; it does not claim they are authenticated or invoke a model.

`excluded_judging_assignments = []` is a root-level list of assignment transaction IDs, before any TOML table header. IDs must be 64 hexadecimal characters; matching ignores case. Use it to exclude known prior attempts from new judging work. Changes reload without restart. Exclusion is rechecked before local abstention so excluding an unjudgeable seat does not consume its attempt. Excluded, proven-unsent work releases its local pending boundary even during backoff or pause; queued or possibly-sent work still reconciles and cannot be cleared by this setting.

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

`uncertainty_grace_seconds` defaults to 300. `max_unresolved_operations` defaults to 4 and includes the prospective dispatch. `allow_answer` and `allow_mine` default true; `allow_judge` defaults false. Live dispatches cannot be bypassed. All old unknowns remain recorded, reconciliation rotates among bound operations, and each risk admission captures its policy, revision and applicable blocker/accounting evidence atomically with dispatch intent.

`answer_reserved_slots` defaults to zero and must be smaller than `max_unresolved_operations`. With cap 8/reserve 2, a judge or mine dispatch may occupy at most six unresolved slots; answers may use all eight. Reservation persists after the current answer completes and applies to manual grants too. It does not evict existing unknowns or prevent unresolved answers exhausting capacity. `allow_judge = true` enables bounded judging overlap under the selected participation policy; it does not clear old judgments.

`participation.historical_unknown_answer_capacity` defaults to `bounded`. In that mode, `max_historical_unknown_answers` (default zero) limits eligible historical answers excluded from active capacity; excess still counts. Active plus historical capacity bounds outstanding risk in this mode.

Only `participation_first` may opt into `accepted_linked`: **all** eligible historical answers are excluded from active capacity, regardless of the numeric historical allowance. Eligibility requires a dispatched, identifier-less unknown answer and a directly linked later retry in the same recorded epoch with a transaction ID and recorded `included_pending`, `confirmed` or `final` state. Unrelated accepted answers, transitive retry ancestors, age alone, judgments and mining never qualify. The original remains unknown: this is **not settlement, nonexecution or finality evidence** for that request.

`accepted_linked` explicitly accepts accumulating historical uncertainty without a lifetime historical-count bound. Active unresolved capacity and answer reservation remain finite; grace, server floors, pause, identity, control generation, capability permissions and per-epoch attempt limits still apply. Unlinked unknowns can still exhaust capacity. Strict remains the default and gains no bypass; manual mode gains no historical allowance.

For a queued or unknown answer with a retained payload but no transaction ID, `status.work.answer.retry` (also exposed by health) explains the separate retry-policy gate, even while a new attempt is being prepared. It reports `original_operation_id`, `policy_eligible`, `reason`, `next_action`, `next_at`, and `requires_fresh_eligibility`. Reasons distinguish retained retry minima, uncertainty grace, exhausted epoch attempts, unresolved capacity and unavailable fresh challenge evidence. Eligibility is not dispatch permission: a new attempt still requires fresh eligibility and all dispatch fences. The original operation remains uncertain; the retry projection does not replace its authoritative-recovery requirement. Expiry of a server floor never proves rejection or clears an unknown operation.

Discover fields with `agmi --json config schema` and obtain `data.file_revision` with `agmi --json config show`. To opt in using the supported nested patch interface (there is no `config set` command):

```sh
printf '%s\n' '{"participation":{"mode":"participation_first","historical_unknown_answer_capacity":"accepted_linked"}}' |
  agmi --json config apply --expected-revision "$FILE_REVISION" --dry-run
# Review the risk, then remove --dry-run to save.
```

This patch does not enable capabilities, resume participation or enable same-epoch uncertain-answer retries. Check saved versus effective revisions as described above. To return to bounded accounting, apply `"historical_unknown_answer_capacity":"bounded"` within the same `participation` patch; existing uncertainty is never erased.

Accepted-linked admissions retain active blocker IDs and a compact snapshot of accounting revision and total/eligible/exempt counts. Revisioned original-answer/accepted-retry links preserve the historical witness without copying every historical ID into every admission. Inspection reconstructs bounded examples at the captured revision and reports counts/truncation; status examples are limited to 20. This reduces repeated evidence growth, not journal retention: original operations and accounting history remain durable. Bounded-mode admissions retain their finite copied witness representation.

Local reconciliation cadence and jitter do not extend the risk-admission grace or override a manual grant. Only reported server minima add that fence. Older journals whose deadlines lack this distinction retain their inherited deadline conservatively until it expires.

Status scopes `participation.uncertainty_blocks` to `observation_epoch` and the effective policy. A false value means uncertainty itself does not block that capability—not that fresh eligibility, upstream availability or acceptance is guaranteed. An already accepted answer is not labelled an uncertainty blocker.

Retrying an uncertain answer in the **same epoch** additionally requires `retry_uncertain_answers = true`, `uncertain_answer_retry_seconds` (default 600), and remaining `max_answer_attempts_per_epoch` (default 2). The budget counts distinct dispatched operations, not model failures or safe retries of proven nonacceptance. Matching captured payloads are reused without new inference; a changed challenge requires current-valid preparation. Included, confirmed, final or freshly reported answered work is not retried for finality delay alone.

A due, authorized current-epoch uncertain-answer retry temporarily reserves **new effect admission**, not model preparation or reads. The reservation begins only after the original answer's retained retry floor and its own applicable grace/retry delay; it does not stop judging for the original long `Retry-After`. New judging/mining submissions then wait rather than continually moving the retry's eligibility window. Already-started effects and bound jobs continue settling, prepared judgments are retained, and every other operation's floor/grace, capacity limit, fresh challenge/identity check and attempt budget still applies.

This is derived priority, not another retry permission or resolution of the original. Both queued and unknown answers use the existing explicit uncertain-answer retry policy; known queued jobs keep their reconciliation. Strict mode never reserves for a risk retry; manual mode requires an unconsumed current-generation answer grant. The reservation ends when the answer is accepted/reported answered, the epoch changes, retry intent is disabled/paused, its dispatch budget is exhausted, or unsent preparation fails without a permitted model-retry transition. Discarding a stale draft or rejecting a dispatched retry does not end priority while another retry remains permitted. Upstream outages or unresolved capacity can still prolong the wait; no timer supplies fresh eligibility.

`status.work.answer.retry` identifies the original and, for floor/grace/live-effect waits, the blocking local operation (`blocking_operation_id`) and `next_at` deadline. `reservation_active` and `reservation_retry_not_before` describe the derived reservation. Prepared lower-priority work waiting for admission reports `answer_retry_reserved`; reads and preparation retain their own progress phases. The separate `admission_reservation` exposes `original_operation_id` and `retry_not_before`; that timestamp is the original's earliest retry point, **not** a promised dispatch time. These are local journal numbers, never bearer-like job identifiers or payloads.

A due, positively refused answer also reserves admission for retry of its same
captured operation, including when no earlier unknown answer exists. Reusing
that operation does not consume a new distinct-attempt slot; this never permits
a fresh third attempt beyond the budget. Its own delay must expire first.
Ordinary retries with no unresolved effects retain existing strict/manual
permission; overlapping uncertain effects still require the existing policy
and, in manual mode, an unused grant.
`admission_reservation` on each work kind exposes `active`, `same_operation`,
and `basis`; for a standalone refusal its `original_operation_id` identifies
the refused operation itself, not a fabricated uncertain predecessor.
Priority reservations are reported separately from `uncertainty_blocks`.
Health uses `answer_retry_reserved` for this admission wait without inventing
an unresolved effect.

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

Configuration failures include a bounded `details.reason` and, where known, a source-defined field or answer/judge guidance-layer selector. `config check` suggests a repair path rather than repeatedly recommending the same failing check. Parser contents, private values and native diagnostics are not printed.

### Identity onboarding and recovery

Run one authoritative writer per account; stop any other submitting software first. Existing accounts use `agmi init --account YOUR_PUBLIC_ACCOUNT_ADDRESS --key-prompt`, or `--api-key-file /path/to/private/api-key` / `--key-stdin` for automation. Never put credentials in command arguments. Init verifies the account read-only, provisions private configuration/guidance and leaves participation paused/read-only; it does not replace existing configuration or history.

An `initialization_invalid` error identifies a rejected initialization field before identity verification or onboarding writes. Follow its `init --help` / `config schema` actions, correct the init arguments or network profile, and repeat init—not `config check` against a configuration that was never created. Preserve any existing credentials and journal.

For a brand-new account, `agmi identity create --label my-agent` is a nonmutating plan. Registration requires separate explicit approval and a verified proof-of-work algorithm:

1. Run `agmi identity create --label my-agent --confirm` to request a challenge. An absent or mismatched algorithm approval stops before proof search, dispatch intent or registration POST with `registration_pow_algorithm_unbound`; `details.negotiated_pow_algo` contains the tag only when safe to display.
2. Verify that the tag denotes SHA256 of `challenge + ':' + decimal nonce`, checked for leading-zero bits. Never approve an unfamiliar algorithm blindly.
3. Authorize bounded proof of work and registration with the verified tag:

```sh
agmi identity create --label my-agent --expected-pow-algo VERIFIED_ALGORITHM_TAG --confirm
```

Follow the returned `next_actions` to initialize and verify the account; account creation never authorizes participation. `--json` provides structured evidence and actions, and `identity create --help` describes proof-of-work budgets. Both onboarding paths accept `--network-config FILE`; see [network profiles](#network-profiles).

The hosted API credential is returned once. A crash after remote creation but before durable capture can permanently lose it; retained intent prevents replay, not that loss. Inspect `agmi identity status --json` after any interruption instead of repeating registration. When captured success needs local publication, status supplies `identity resume --confirm`; resume is local-only and needs no original registration options. Uncertain registration is never resent. Preserve its evidence and never delete it to retry. Public registration has not yet been live-validated; admission remains controlled by MinePOA.

Derived credential, identity metadata and network-profile files are published individually from synced private temporary files using atomic no-replace rename. A crash between these publications leaves complete files that local `identity resume --confirm` can reuse and finish from the successful capture; different existing contents are never overwritten. This is not a multi-file transaction. Intent and response-capture fences deliberately retain incomplete writes; atomic derived publication does not repair an incomplete capture or close the remote lost-key window.

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

For identities created through agmi, `identity status` retains the original successful registration evidence after credential replacement. A different current credential is reported as unverified by that historical capture, not as failed registration or proof of authorized rotation. `identity resume` still refuses to overwrite a different credential.

### Native model routes

Use a native CLI executable, not a shell command or an arbitrary JSON adapter. This implementation targets Unix (Linux/macOS). The embedded Python and Node adapters remain thin native API bridges: provision the harness, its compatible Python/Node runtime and authentication yourself. Neither Cargo builds nor `agmi install`/`update` installs harnesses, authenticates providers or provisions accounts.

| Harness | Inspected execution contract | Model syntax |
|---|---|---|
| Hermes | Launcher supports `--print-runtime-command`; native embedding API supports tool/context isolation and the authenticated OpenAI Codex route | Exact model identifier, for example `gpt-6.1-sol` |
| OpenClaw | `2026.10.9` public Gateway CLI transport, compatible Node.js on PATH, and an authenticated running Gateway permitting `operator.admin` | Provider/model, for example `openai/gpt-6.1-sol` |

The user service sets `PATH` to `$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin`; it does not load shell startup files. Configure the native harness executable by absolute path and make OpenClaw's compatible `node` available on that service PATH. A working interactive `nvm`/`fnm` shell is not sufficient. Provision and authenticate the harness as the runtime OS account, then verify model execution under supervision before leaving it unattended.

Unsupported native contracts fail explicitly; a matching product name alone does not establish compatibility. Hermes uses its existing authenticated Codex subscription route; the inspected OpenClaw route uses its native `openai` provider authentication. Other providers are not silently substituted. Reasoning values must be supported by the selected native model.

`solver.answer.hermes_api_url` and `solver.judge.hermes_api_url` declare the expected authenticated Hermes URL, defaulted from [`defaults/model.toml`](../defaults/model.toml). The native authentication route must match it; changing this field never silently redirects a native key. OpenClaw obtains its endpoint from its existing Gateway configuration.

OpenClaw uses its existing Gateway and native authentication through a small embedded Node bridge to `callGatewayFromCli`. Prompts travel over stdin, never argv. Each request is a fresh one-shot raw model run with tools, bootstrap context and delivery disabled. The Gateway chooses its configured default agent; no shared configuration is changed. Model overrides require the native `operator.admin` scope; insufficient authority fails rather than silently using another model.

Choosing OpenClaw trusts that Gateway's configuration, plugins and hooks. This is not isolated execution: hooks may influence routing before inference. agmi checks the returned model, reasoning, run binding and explicit no-tool/no-bootstrap/no-fallback evidence before accepting output; that cannot undo calls already made by the trusted Gateway. Hermes places policy in its native `system_message` channel. The inspected OpenClaw interface still combines policy and untrusted request data in one message; agmi does not claim privileged policy isolation or prompt-injection immunity there. Pause closes new admission and fences pre-pause results; already-started inference may continue. Timeout or shutdown cancels agmi's local adapter, not the shared Gateway. Remote inference may continue until its native deadline.

Native authentication and OS privilege isolation remain deployment prerequisites, not fixes delivered by this release. Provision authentication through the native harness; never copy another account's auth material. Same-user hostile processes and privileged Gateway access are not isolated by these adapters. Stronger OS identity/auth/container isolation is explicitly deferred; see [security boundaries](../SECURITY.md).

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

Historical refusal recovery is a separate, local-only operator action with the
writer stopped:

```sh
agmi --json recover resolve --operation "$OPERATION_ID" --refusal --dry-run
# Review eligibility and evidence_limit, then use that preview's token.
agmi --json recover resolve --operation "$OPERATION_ID" --refusal --apply "$PREVIEW_TOKEN"
```

This retires an eligible operation as `refused`, not successful and not scheduled
for replay. Retained request, artifact, submission evidence, retry floors and
dispatch history remain intact; the resolution is audited. A changed preview
cannot authorize application, and repeating an applied token is idempotent.
Recovery requires positive retained refusal evidence and excludes bound or
contradictory acceptance evidence. Old generic `service_unavailable` or
`endpoint_halted` diagnostics do not establish the exact halt response and cannot
authorize historical 503 recovery. Missing original response details remain an
explicit evidence limitation, not reconstructed proof.
An unexpired server delay blocks retirement even if a crash interrupted the
normal retry-timing update after response capture.
For legacy 429s, approval applies the developer-reported pre-acceptance contract
to the retained status/category. Original response fields that were not retained
cannot be rechecked; this is an explicit recovery-policy decision, not newly
observed upstream execution evidence. Any retained acceptance or contradiction
evidence still excludes recovery.

Model launch rechecks durable pause generation under the admission lock after native harness discovery, immediately before spawning inference. Pause therefore cannot acknowledge success and then allow a stale preflight to launch new inference.

Assignments use the returned `answer_epoch`, never the inventory's current epoch. Bounded offset pagination deduplicates canonical transaction IDs, preserves partial coverage and prioritizes supplied expiry with deterministic ties. Moving/partial inventories never prove a sent operation failed. Missing target metadata triggers selected-transaction hydration; missing authoritative original words prevents judging. Supplied author history is candidate-bound and labelled missing, supplied or truncated; supplied does not mean exhaustive. Answer novelty context may include locally submitted text with unresolved acceptance.

## Doctor and unattended status

```sh
agmi doctor
agmi doctor --repair
```

`doctor` is local and read-only by default. It combines health, separate answer/
judge/mine progress, intervention requirements and eligible guarded repairs.
It does not contact MinePOA, invoke a model or read credentials. Add `--json`
for the same machine-readable assessment.

`status`, `health` and `doctor` share `work.{answer,judge,mine}.progress`
(`working`, `idle`, `complete`, `waiting`, `blocked`) and an `intervention`
object with reason, next action/time and evidence freshness:

| Intervention | Operator meaning |
| --- | --- |
| `none_required` | No intervention indicated for this lane; inspect progress and effective mode. |
| `automatic_recovery` | A configured automatic path exists. Wait for its next observation; success is not guaranteed. |
| `operator_required` | A known fence requires operator action; use the reported action, not a blind replay. |
| `undetermined` | Evidence is missing, stale or inconclusive. Inspect before assuming recovery or failure. |

Root `intervention.unattended` is `true` only when the observed controller is
ready, participation is resumed, at least one capability is active, and no lane
requires intervention or has undetermined progress. `false` also covers deliberate
pause/inactivity; `null` preserves insufficient evidence. A live process alone,
an old successful epoch or retained audit warnings do not establish this result.
Completion is scoped to fresh local epoch/inventory evidence, not rewards.

The existing `health` exit contract is unchanged: admission waits can still fail
health even when recovery is automatic. Agents should use `intervention`, not
`attention_required` or the exit code alone, to decide whether to ask a human.
`doctor` exits successfully only when `unattended` is true and its repair scan/
application has no failure. A repair can therefore be `applied` while the command
still exits nonzero because participation is paused or other blockers remain.

`--repair` explicitly authorizes token-fenced refusal recovery and local legacy
identity-evidence normalization. It discovers candidates and rechecks them under the configuration,
account and admission locks; no IDs or copied tokens are required. Human previews
show each candidate's classification and evidence limitation. Legacy 429 retirement
uses the developer-reported rejection policy: the original response body was not
retained, hidden contradictions cannot be ruled out, and no new upstream
verification is performed.

Older builds used the same identity flag for a timeout and an actual rejection.
Doctor can normalize an eligible legacy `false` flag into explicit
`legacy_unknown` evidence, preserving the original failure and an audit record.
It does not infer why that old check failed, mark identity verified, rotate
credentials or clear a classified authentication/account mismatch. Changed
evidence between preview and application is not overwritten; the repair reports
`skipped`, including through `update --repair`. Repeated repair is a no-op.
Backoff-only legacy journals can be normalized in the same invocation that upgrades
their local metadata. Retry deadlines, prepared work, uncertain submissions and
model attempts remain intact. A later successful runtime identity check is still required.

Only when eligible work exists, doctor can stop a validated matching canonical
Linux user-systemd runtime and restore its previous running state. A previously
stopped runtime stays stopped; pause, configuration, guidance, timer and enablement
are preserved. Normal graceful-shutdown uncertainty remains possible. A restored
runtime may resume its already-configured network/model work; doctor itself
does not replay submissions or authorize model abandonment/regeneration.

Noncanonical configurations, absent installations and unsupported hosts remain
caller-managed: repair requires their writer to be stopped. Failed integrity,
ownership, override or manager checks on an existing canonical installation
refuse automatic repair; correct the installation or use explicit stopped-writer
recovery. Doctor does not kill unmanaged processes.

`repairs` separates eligible, ineligible, applied and skipped records, failures
and restoration evidence. Partial progress is retained. Ambiguous writes,
generic historical 503s and model-only unknowns are not cleared. No history reset,
nonce change, capacity increase or policy relaxation occurs. Failed restoration
requires attention; a hard kill, process abort or host failure can prevent it.
A newly restored process without a fresh controller observation remains
`undetermined`, not a claim that participation has resumed.

## Supervision

The canonical Rust Linux user-systemd installer stages versioned matching binary/unit sets under `~/.local/share/agmi/releases`; no shell installer is shipped. State, credentials and native authentication stay outside those release sets. Build from this Git checkout or a Cargo package retaining `.cargo_vcs_info.json`; `agmi build-info --manifest` exposes commit, dirty marker, target, schema and embedded unit/adapter checksums. The installer requires known commit/dirty labels. Cargo package VCS labels are metadata, not signed source proof; an archive without either its own Git identity or valid Cargo VCS metadata remains unknown.

```sh
# EXPECTED_SHA256 must come from an operator-trusted source.
agmi install --binary /absolute/path/to/agmi --sha256 "$EXPECTED_SHA256" --dry-run
agmi install --binary /absolute/path/to/agmi --sha256 "$EXPECTED_SHA256"
agmi service start
agmi service status
# Inspect configured modes and health, then explicitly authorize participation:
agmi resume
```

Fresh `install` stages and activates a verified release while stopped, then enables the user units; it does not start or resume participation and refuses an existing installation. Rust owns filesystem changes, hashing, unit rendering and cutover control flow; only system integration invokes `systemctl`/`systemd-analyze`. `service start|stop|restart|enable|disable|status` provides explicit supervision controls without changing participation pause. Linux user-systemd and the standard configuration layout are required; configure user lingering if supervision must survive logout.

`cargo install` normally puts the administration CLI in `~/.cargo/bin`; service installation separately manages `~/.local/bin/agmi` through its release activation pointer. Updating the Cargo-installed CLI alone does not update a running service. `agmi update` updates the canonical managed service, not arbitrary executables on `PATH`; it inspects the selected managed release rather than assuming the invoking CLI is the installed version.

### Stable-release updates

```sh
agmi update --check
agmi update --dry-run
agmi update
agmi update --repair
```

The default source is the latest published stable GitHub release in
`tomismeta/agmi`, not the `main` branch. Discovery reads bounded release metadata,
checksums and build identity over HTTPS. Downloads are limited to the fixed
publisher and allowed GitHub release-asset redirects. Archive and extracted-binary
digests, target, embedded identity and journal compatibility are checked before
activation. Archives cannot supply arbitrary extraction paths or symlinks.
HTTPS trusts that publisher's release assets; checksums are integrity checks, not
independent signatures or protection against a compromised publisher.

`--check` and `--dry-run` do not activate or repair anything. A successful check
can report no compatible update or unverifiable source ordering; inspect its
availability/reason rather than treating exit zero as installability. Automatic
activation requires a compatible managed installation and conservative
version/commit ancestry evidence. Dirty, divergent or unproven source ordering is
not resolved by downgrading. Different commits with the same package version are
not treated as the same build. A selected-release fence is rechecked under the
installer lock, preventing a concurrent update from invalidating the download's
original decision. Explicit local sources below remain operator-selected.

Incoming published builds must advertise `update_protocol=1` in their verified
build manifest: this guarantees support for the lock-held selected-release fence.
Older builds without that protocol (including the original v0.1.0 artifact) and
unknown protocols are reported as incompatible during discovery, never offered
for automatic activation. Explicit local installation remains available; the
updater does not weaken its concurrency safeguard to accommodate older installers.

Downloads finish before the existing managed installer performs the cutover.
Configuration bytes, credentials, model/reasoning settings, core/user guidance,
pause intent and generation remain unchanged. No template is reapplied, account
is reinitialized, model is abandoned, or journal snapshot is restored. A service
that was running may resume its previously authorized participation after restart.

After a successful update/no-op, the selected executable runs read-only doctor.
`--repair` additionally authorizes its existing guarded refusal recovery, including
the disclosed legacy-429 policy limitation; it is not permission to replay
uncertain writes or clear history. Checks/dry runs never repair, and `--check`
cannot be combined with `--repair`. A failed update does not proceed to repair.

JSON `data.update`, `data.repair` and `data.readiness` are separate outcomes.
Update/repair failure exits nonzero without hiding a completed activation or
partial repair. An unhealthy doctor report does not undo a successful update;
readiness may be unavailable if the selected binary cannot provide that contract.
The report identifies that doctor executable's release and rechecks selection
afterward. Changed or unverifiable selection makes diagnosis `stale` and removes
readiness claims; completed repair effects remain reported. Guarded repair itself
retains the existing installer lock and runtime validation. This is a point-in-time
observation, not a guarantee that another operator cannot update afterward.
There is no background updater, release channel switch or automatic rollback.

Explicit pinned/offline paths remain available:

```sh
agmi update --binary /absolute/path/to/new-agmi --sha256 "$EXPECTED_SHA256" --dry-run
agmi update --binary /absolute/path/to/new-agmi --sha256 "$EXPECTED_SHA256"
# Or stage without activation, then activate the returned release ID:
agmi install --stage-only --binary /absolute/path/to/new-agmi --sha256 "$EXPECTED_SHA256"
# Also accepts an already retained compatible release:
agmi update --release "$RELEASE_ID"
```

Updates preserve prior runtime/timer running intent and unit enablement. `--stopped` forces a stopped cutover. An incoming binary is privately copied and checked against the expected digest before it can execute; its own embedded installer/assets own the cutover. Explicit local sources use the operator-supplied digest and make no release-discovery requests. Dry-run reports a nonexecuting plan, not a guarantee that operational preconditions will pass. Installed, loaded and running identities are reported separately.

Release staging and activation use synced artifacts and atomic publication/pointer replacement. A failure during cutover stops the runtime/timer and reports failure; it never automatically reverts the activation pointer or journal. If the delegating parent is interrupted after the incoming installer completed, it reports `interrupted` while preserving the child's completed activation/service evidence—not claiming that services stopped or selection was undone. Inspect that evidence before another lifecycle action.

Before manager-facing actions, agmi requires the OS account's canonical home, matching manager unit-search paths and loaded-unit file ownership. `manager_context_mismatch` requires correcting HOME/session selection or resolving conflicting units; `service_state_unavailable` requires readable, stable runtime/timer state before retrying. Stage-only does not contact the manager. Retained rendered units are checked against their binary's embedded template hashes, not just mutable checksum files.

Installer failures include a finite `failure_code` and relevant repair guidance without forwarding raw subprocess output. Installation needs an executable temporary filesystem for its private candidate copy; use an appropriate `TMPDIR` when the default temporary directory is mounted `noexec`. Do not disable host protections globally to install a release.

Ordinary upgrades preserve pause intent and generation: use normal activation, not `pause`/`resume`. Completed unsent drafts survive stop/start and are revalidated before dispatch; explicitly paused/off or obsolete work is not silently revived. Clean shutdown captures completed model results; genuine unfinished execution remains uncertain.

For a journal that requires explicit adoption, first use `agmi update --release "$RELEASE_ID" --stopped`, then `agmi recover adopt` and explicit `agmi service start`. Adoption is not part of an ordinary already-anchored upgrade.

Adoption refuses missing, uninitialized or authority-less legacy journals; it never creates replacement history. An already-adopted intact journal is accepted idempotently. A fresh installation initializes paused state through normal `run`/control initialization instead.

An unanchored schema-2 journal cannot start normally. Explicit adoption validates its existing UUID and dispatch sequence; it never recreates missing authority data. Adoption is not proof that an unanchored snapshot is current: establish that separately, and never adopt an old backup to bypass uncertainty.

Releases are retained, but binary rollback requires matching journal compatibility. Schema-1 binaries must not run schema-2 journals; use a compatible release, roll forward or stop—never rewind state. Staging checks actual space for artifacts/legacy retention plus a 256 MiB journal/WAL reserve, without pruning recovery history. The unit uses `TimeoutStopSec=infinity` so systemd does not truncate captured runtime deadlines; agmi bounds shutdown, but a shutdown bug still requires operator intervention.

The example uses control-group cleanup, restrictive umask, private temporary files and restart-on-failure. Account locks live under `.agmi-account-locks` in the operating-system user's canonical home, independently of the state directory and `HOME`/XDG overrides; a tighter sandbox must allow access there. The example is not a complete security sandbox for a compromised harness or local account.

### Help, completions and following logs

`agmi --help` lists everyday workflows; command-specific help explains examples
and side effects. `agmi --json commands` describes effects and output contracts
without loading configuration. Shell completions come from the same command
definitions, not a separately maintained command list:

```sh
agmi completions bash
agmi completions zsh
agmi completions fish
agmi logs --follow --limit 50
agmi --json logs --follow
```

Completion output is a script on stdout, or a normal `{shell, script}` data
envelope with `--json`. Printing it never installs shell files.

Snapshot `logs` is unchanged. Following first emits the selected retained tail
oldest-first, then newly recorded event IDs. JSON mode emits one `agmi.cli.v1`
`log_event` envelope per line with only `id`, `at`, `event` and `kind`. It does not
read private payloads, credentials or guidance, initialize state, or call an API.
Ctrl-C/SIGTERM and a closed output pipe stop following cleanly.

The journal normally retains only the newest 2,000 events. Following uses bounded
pages and short read snapshots; it does not pin the WAL while waiting. A retention
gap, regressed cursor or replaced journal stops with a specific error instead of
silently skipping or replaying records. Restart following explicitly after
inspection; it cannot recover already-pruned history.

### Local health checks

```sh
~/.local/bin/agmi --config ~/.config/agmi/config.toml --json health
systemctl --user status agmi.service agmi-health.timer
journalctl --user --user-unit=agmi-health.service
```

Health is a local, read-only check: no network requests, model calls, credential/guidance reads or state initialization. Unhealthy checks return nonzero with structured issues for stale/stopped execution, blocked or unobserved admission, overdue work, missed-answer evidence, identity failures, inactive participation and low disk space. Evidence reflects local observations, not a fresh network verification or proof of rewards. Warnings are reported separately from health failures: a healthy runtime may have warnings, and warnings alone preserve a successful exit status. Neither warnings nor a healthy result permit replaying uncertain work.

`hosted_identity_unobserved` means no identity result exists yet for unpaused active participation. It is an operational readiness failure, not a fabricated mismatch; the evidence stays null. Paused or read-only installations do not acquire this failure merely for avoiding upstream requests.

`hosted_identity` separates the latest verification outcome from availability:
timeouts, disconnected reads, rate limits and temporary server errors do not prove
bad credentials. Automatic recovery requires an identity read in flight or
scheduled pending/observably eligible work that can retry verification. A retained
backoff deadline alone is only a not-before floor, not a scheduled identity job;
without a demonstrated recovery path the result stays undetermined.
Completed answers/mines and an idle judge keep
their progress labels; they do not erase identity uncertainty or independent
operator-required blockers. The existing bounded read backoff remains in force,
including server minimums. Identity outcomes, completed-read evidence and their
retry state are committed together.

Explicit authentication rejection or a confirmed account/chain mismatch requires
operator attention. Later timeouts or malformed replies cannot erase that
rejection; only matching verification clears it. A 403 is a reason to inspect
access policy, not proof that rotating a key will help. Missing or malformed
identity data stays unverified. `hosted_identity_verified` is a derived nullable
summary, not permission to submit: every submission retains the fresh identity
guard. Legacy unknown evidence and successful doctor cleanup are not verification.

Thresholds are CLI options: `--stale-seconds`, `--work-seconds`, `--answer-grace-seconds`, `--min-free-mib` and `--expect-participation`. For deliberate read-only observation use `--expect-participation false`; a live controller is still required. Active work is evaluated against captured deadlines/effective policy rather than silently adopting a newly edited timeout. Health distinguishes desired/effective policy, heartbeat, progress and admission blocking. Repeated unchanged receipts are observations, not fresh transition events.

Missing captured timing policy yields `effective_policy_unavailable`, unknown controller/capability readiness and a failed health check—not freshness borrowed from desired configuration. `thresholds.timing_source` distinguishes effective evidence from unavailable timing; unknown effective timing and epoch freshness are null. Run a compatible controller normally to publish its loaded policy; never manufacture it by editing the journal.

`operational.status` separates `clear` (no observed operational issue under the requested checks), `blocked` (admission fenced), `degraded` (other operational issues) and `unknown` (required policy or admission evidence unavailable). Top-level `healthy` and the exit status reflect these operational conditions. Retained unknown outcomes are warnings (`pending_outcome_uncertain`), not operational failures by themselves: healthy participation can report `attention_required = true` and `risk.attention_required = true`. Actual admission blocks still fail health, as do stale observations, overdue work and other operational faults. This classification never changes journal outcomes, risk counts, admission limits or replay safeguards.

`contract_version = 1` adds one component contract under `components`: `controller`,
`answer`, `judge`, `mine`, and `api.{challenge,identity,assignments,assignment_evidence,job,receipt}`.
Each entry has `state`, bounded `reasons`, nullable `observed_at`/`age_seconds`
and structured `next_actions`. Capability entries also report their effective `mode`.

| State | Meaning |
| --- | --- |
| `ok` | Recent local evidence supports current operation or a legitimate idle/read-only state. |
| `degraded` | Observed work or a relevant API dependency needs attention. |
| `blocked` | A known controller or capability fence prevents participation. |
| `unknown` | Evidence is missing, stale, inconsistent or future-dated. |
| `disabled` | The effective capability mode is `off`. |

Agents may render `ok` green, `degraded` yellow and `blocked` red, but must retain
distinct unknown/disabled states rather than inventing success. No new health
field changes admission, risk accounting or the existing exit-status contract.
In particular, a degraded or unknown API component need not make overall health
fail when no current work depends on it.

API components describe **last recorded usable reads**, never fresh probes or
write-endpoint availability. HTTP 200 alone is not usable-success evidence.
Old success/failure becomes `unknown` after `--stale-seconds`; an in-flight read
does not refresh the previous result. `last_http_status_observed_at` uses an
independent HTTP-success timestamp for 2xx statuses; it is null for other statuses
because existing journals do not independently date them. Cancellation/recovery
must not make an old status appear newly observed. `retry_at` is a retained
scheduling deadline, not a recovery prediction. Component actions never authorize replay.

Fresh complete judging inventory with no eligible work is `ok`, even when it
contains ineligible entries, unless overdue work or recent hydration failure
needs attention. Partial coverage is not proof of an empty work queue.
Retained unknown effects remain in `risk`/warnings independently of component state.
Completed current work never hides another overdue operation in that capability.
Deliberate read-only observation does not require write-identity verification;
a known identity mismatch still matters. A recent assignment-evidence failure
degrades active judging while selection is missing or nonempty but ineligible,
unless a usable selection/preparation supersedes it. This reports recent failure,
not proof that every remaining candidate needs that endpoint. A fresh empty
inventory or stale failure does not acquire that degradation.

Health checks every entry in `pending_work`, not only the representative oldest `pending` operation, so an old unknown cannot hide later overdue queued, dispatching or model work. Missing admission evidence is reported as `admission_blocked = null` with `admission_unobserved`, never as an open admission boundary.

`oldest_unresolved_operation` and `oldest_unresolved_since` identify historical uncertainty; health also reports `oldest_unresolved_age_seconds`. They do not identify the current cause or duration of an admission block. Use `admission_blocked`, `affected_capabilities` and each `work` entry's reason/deadline for current policy waits.

`work.judge.selection` records selection time, observed candidate count, inventory completeness and whether that observation contained eligible work. Eligibility requires a usable parsed assignment, not merely a selectable identifier. `no_eligible_in_observed_inventory` is an idle-selection reason, not a claim that no assignments exist globally. Partial inventories remain explicitly partial; new observations and policy changes invalidate stale selection evidence. Inventory retains its starting control generation, so a response spanning pause/resume cannot become current selection evidence. Read backoff, active preparation and capacity constraints take precedence.

Controller heartbeat advances before each bounded HTTP wait, not just at the start of a potentially long cycle. Manual recovery does not refresh it or reload model guidance. Missing both captured and effective model timing produces `model_deadline_unavailable`, not a deadline guessed from desired configuration.

`last_reported_build` and `heartbeat_recent` are persisted local evidence, **not proof of a currently running process**; CLI status/health report `process_identity = "unverified"`. A killed controller can leave a recent report. Use installer `status` for the independently observed systemd process/executable identity.

Disk headroom warns below the larger of 512 MiB or four times `--min-free-mib`; the configured minimum remains the unhealthy floor. Zero disables both disk checks. The two-minute timer keeps failures local in exit status/journal. Agents own any forwarding; agmi does not add a notification transport.

### Agent-owned forwarding

Agents can read agmi's structured health, events and warnings and optionally forward relevant findings through their existing native channels. agmi itself does not configure external destinations, manage notification credentials/state or send Telegram/webhook messages. Forwarding policy and delivery belong to the agent, not the participation runtime; the shared installer does not enable forwarding.
Forward `work` progress and `intervention` for each action. Distinguish automatic
waits, operator-required blockers and insufficient evidence; historical warnings
alone are not a request for a restart or model abandonment.

Local health remains read-only even when another agent consumes its output. Forward only sanitized evidence, never private payloads, model output, credentials or native diagnostics. Agent forwarding is not proof of human receipt or host-down coverage; use independent monitoring for an offline host. Neither health findings nor forwarding outcomes authorize replaying uncertain work, restarting native gateways or deleting participation state.

## Verification and publication

Source/package builds require Unix, Rust/Cargo 1.96+ and a C compiler/linker. Tests additionally require Node.js and Python 3 for native/process fixtures, but no OpenClaw installation or live credentials. A source install is `cargo install --path . --locked`; it installs only the CLI, not systemd services or native harnesses.

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
python3 tests/installer_smoke.py target/debug/agmi
```

Build and inspect the local distributable, then install its extracted sources independently of the checkout:

```sh
cargo package --locked --list --allow-dirty
cargo package --locked --allow-dirty
package_root="$(mktemp -d)"
tar -xzf target/package/agmi-0.1.1.crate -C "$package_root"
cargo install --path "$package_root/agmi-0.1.1" --locked --root "$package_root/install"
"$package_root/install/bin/agmi" build-info --manifest
```

`cargo package` verifies the packaged build; the separate temporary install checks the extracted source workflow without replacing the normal CLI. Keep `.cargo_vcs_info.json` with the extracted sources. `--allow-dirty` records dirty source rather than certifying a clean release; omit it for a clean release candidate. `build.rs` only derives labels and hashes embedded assets: it never installs, authenticates or provisions. It uses the package's own Git checkout, or Cargo's JSON VCS metadata when outside that checkout, and never an enclosing repository's identity. Neither source labels nor packaged files are signed provenance.

The explicit package allowlist includes Rust sources, both native adapters, defaults, guidance, unit templates and public documentation. Shell installers, tests, private inputs and generated artifacts are not shipped. Inspect the actual list and archive as part of the secret audit.

The process fixture also supports `--harness hermes` for its Python-only fake native transport; this does not require Node.js or a real Hermes account. Native authentication still needs separate real-harness acceptance.

`python3 tests/native_bridge_smoke.py` executes the actual embedded Python and Node bridges against isolated native API substitutes. It covers authentication-route checks, isolation settings, policy delivery, failure cleanup and encoded input limits without live credentials. This is separate from the scheduler fixtures' fake inference transports.

CI also runs `tests/systemd_smoke.py` inside the disposable image defined by `tests/systemd_fixture.Dockerfile`. The container owns its user manager, home and units; it has no external network or host home/bus/cgroup mounts. This exercises real install/update/retained-release activation and post-switch failure cleanup. Do not run this fixture against a production user's services.

Local protocol/model fixtures exercise deterministic lifecycle boundaries; they do not prove production authentication or live network outcomes. Production activation needs separate end-to-end verification with the real account and configured harness.

Linux host acceptance has exercised authenticated Hermes and existing-Gateway OpenClaw answer/judge inference, authenticated hosted reads, guidance hot reload and repair, concurrent pause, second-writer rejection, crash/restart recovery and clean shutdown. A bounded live canary on two independent accounts submitted one current-epoch answer, one eligible judgment and one explicit mine request per account. Answers reached node-reported checkpoint coverage; judgments reached receipt inclusion, with checkpoint coverage not established in this canary. Queued judgments were recovered read-only after correcting the protocol's `answer_epoch` and grading-result `id` fields, without resubmission. Both accounts were paused after the bounded test. These observations are not independent cryptographic finality verification or proof of unattended operation.

Historical pilot checks on three independent Linux identities across both harnesses exercised the shared installer, user services, graceful stop, automatic crash restart with preserved state/pause, and scheduled health execution. Answers and judgments reached node-reported inclusion or receipt confirmation. Upstream read failures and uncertain judging inference were retained without replay. These observations do not establish the deployed identity of the current checkout, public registration compatibility or a completed long-running stability study. Health findings remain local; no external notification channel or earnings verification is established.

agmi is [MIT-licensed](../LICENSE). Package publication is deliberately disabled in `Cargo.toml`. Before publishing: clear registry name availability if publishing to crates.io, review third-party license obligations, audit source/history and packaged files for secrets, and require explicit release approval. `.gitignore` and Cargo's package allowlist do not replace a secret audit.

See [architecture](../ARCHITECTURE.md) and [security boundaries](../SECURITY.md). Protocol reference: [MinePOA agent instructions](https://minepoa.com/go.md). Experimental network; no earnings or monetary-value guarantees.
