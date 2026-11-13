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
printf '%s\n' '{"capabilities":{"answer":{"participation":{"mode":"participation_first","uncertainty_grace_seconds":300}}}}' |
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

`reads` reports current identity, lane discovery, assignment and operation-binding read state without making requests. The view is bounded to 256 rows with `reads_truncated`; identity/discovery are prioritized, and retired binding history remains durable but is not presented as current. Local retry clocks, same-resource minima and `shared_not_before` remain distinct. `status.data.work` explains each lane's phase, canonical admission decision and next action; a deadline is not permission or a recovery promise. Heartbeat, useful progress and current-epoch answer evidence remain separate.

For interrupted identity creation, inspect `identity status`. A complete retained success can provide `identity resume --confirm`, which validates and publishes only local files without the original registration options or network profile. Omit `--confirm` to inspect the plan. Missing/incomplete capture remains uncertain; resume never requests proof work or another registration.


## Modes and effects

| Capability | `active` | `read_only` | `off` |
|---|---|---|---|
| `answer` | Observe, prepare and submit eligible answers | Observe/reconcile; no new model or submission | No new participation or ordinary polling; safety reconciliation continues |
| `judge` | Observe assignments, prepare judgments and submit | Observe/reconcile; no new model or submission | No new participation or ordinary polling; safety reconciliation continues |
| `mine` | Submit hosted attestation requests at configured cadence | Observe without invoking the mutating mine endpoint | No new participation or ordinary polling; safety reconciliation continues |

Set `capabilities.<lane>.mode` to choose each mode. Each lane has its own native controller; modes do not create additional runtimes or journal writers.

Off and pause do not abandon already possibly-sent work: allowlisted identity, job and receipt reads continue. Stop the runtime for strict no-network operation; local status/health remain offline. This safety-read contract replaces the earlier off=no-polling behavior.

**Local pause does not stop server-side auto-mining.** MinePOA may enable that after accepting an answer. A request already transmitted cannot be recalled. GET does not imply read-only: the hosted mine endpoint mutates network state.

## Configuration and reload

This source tree accepts one current configuration shape, without `schema_version`. Released v0.1.1 configuration and earlier per-lane files carrying that marker are not accepted by the normal reader; use [explicit migration](#atomic-capability-migration). Each `capabilities.answer`, `.judge` and `.mine` table owns `mode`, `timeouts`, `schedule` and `participation`. Answer/judge additionally own `model` and `preparation`; mining is model-free. Only shared identity read policy (`identity`) and shutdown policy (`runtime.shutdown_seconds`) remain outside the lanes.

Each lane's schedule defaults to 120-second polling, 180-second retry, a 900-second exponential-backoff cap and 30-second deterministic staggering. Mining additionally has `interval_seconds = 86400` and `each_epoch = false`. These are independent values, not references to a global schedule. Optional `discovery_retry_seconds` and `discovery_backoff_max_seconds` inherit that lane's retry/base-cap settings.

`schedule.observation_max_age_seconds` independently limits usable discovery evidence (default 120 seconds). It is not the HTTP request timeout. Successful discovery schedules its next refresh after the smaller of configured polling plus stagger and half this age (minimum one second). Server restrictions and failure backoff still take precedence; an outage can therefore leave evidence stale without silently extending its validity. Each page retains its original completion time and expiry.

The mining interval starts with a new operation's first durable dispatch intent, not preparation. A draft discarded during fresh challenge validation does not consume the interval; a possibly-sent request does, including an unknown outcome. This local cadence survives restart, while safe retries of that same operation do not restart it. `each_epoch = true` instead limits new mining attempts to one per observed epoch; neither mode bypasses server-imposed request minima.

The latest completed mining operation remains visible in `status.work.mine` during the current epoch's scheduled wait. Health requires fresh matching epoch evidence; completion does not hide newer failed work or pending/uncertain work, or satisfy a new epoch or an already-due interval. For interval mining, `completion_valid_until` carries the deadline and health rechecks it at report time.

Failures belong to identity, one lane's discovery, one assignment, or an operation's exact job/receipt binding revision. A slow or missing job does not impose local backoff on another job or lane. Rebinding retires the old read key; late completions cannot update the replacement binding's clocks or state. Genuine account/route/resource restrictions still constrain every applicable request.

Hot changes recompute local delay from the original failure time, never from reload time. They cannot shorten a retained server minimum or conservative legacy floor. Deterministic identity staggering is added after the local exponential cap; final waits can exceed the cap when staggering or a genuine restriction requires it. `0` disables staggering.
`reads` and operation evidence expose bounded error categories, never raw provider
messages or credentials. HTTP status and transport/body failure remain separate
evidence: an interrupted 503 body may be labeled `timeout`, not a proven halt.

| Category | Next action |
| --- | --- |
| `halt_middleware`, `endpoint_halted`, `service_unavailable`, `bad_gateway`, `gateway_timeout`, `upstream_error` | Let scheduled read recovery proceed; inspect freshness and work deadlines. |
| `rate_limited`, `answer_global_ceiling`, `grade_queue_full` | Honor the retained retry floor; do not restart to bypass it. |
| `authentication_rejected`, `permission_denied` | Inspect credential configuration with `config check` and recorded endpoint evidence with `reads`; neither validates a credential remotely. Do not move credentials into a URL or register a replacement identity. A 403 alone does not prove an invalid key. |
| `redirect_refused`, `not_found`, `gone`, `request_rejected`, `upstream_rejected` | Inspect the configured network profile and operation evidence. A missing job or receipt is not proof a write failed. |
| `invalid_json`, `body_interrupted`, `response_too_large`, `timeout`, `connect` | Preserve uncertainty and let the owning read's backoff run; escalate if evidence becomes stale or work overdue. |

The longest parseable `Retry-After` header (seconds or HTTP-date) and JSON `retry_after_seconds` wins. Headers are retained privately until the body completes or its deadline expires; classification then determines scope. A valid queued 202 minimum is resource-local, not a global pause. Malformed or interrupted bodies retain conservative header evidence. Restrictions are ingested before stale local-completion checks, so an obsolete binding cannot erase a genuine shared limit.

A bare 429 without a valid minimum uses a fixed, versioned 30-second local cooldown anchored to the original observation—not a server-supplied duration or another lane's exponential backoff. Displayed deadlines mean **retry no earlier than**, not “the service will recover then.” Free-form outage prose never supplies a recovery timestamp.

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
[capabilities.answer.schedule.queued_job_polling]
initial_seconds = 15
max_seconds = 120
```

Configure this separately for each lane. Both positive fields are required, with initial no greater than maximum. Intervals grow with queued-phase age; jitter stays within the local cap. Same-resource/server/legacy minima still win, and conversion to integer timestamps adds one conservative second. Missing phase evidence uses the cap. Omission preserves normal retry cadence. To disable answer's override, apply `{"capabilities":{"answer":{"schedule":{"queued_job_polling":null}}}}`. This affects bound-job reads, not write retries, receipt cadence or participation authorization.
Already-due jobs continue through bounded reconciliation batches without the normal poll sleep. Polling intervals are scheduling targets, not upper bounds on upstream response latency.

Each lane has independent `timeouts.http_seconds` and `read_http_seconds`, both defaulting to 90; neither inherits the other's value. Effectful mining GET uses the effect deadline. Answer/judge independently default `model_seconds` to 300. `capabilities.mine.schedule.each_epoch = true` replaces interval cadence with one explicit mining attempt per freshly observed epoch, whether answered or not. [MinePOA permits mining anytime](https://minepoa.com/go.md), but rewards require an answered epoch; local permission is not an earnings claim. Proven nonacceptance can retry captured work; uncertain mining is not repeatedly issued within that epoch.

Startup, polling and retries use deterministic identity-based staggering without peer coordination. Ready effects use the [served-in-round fairness policy](#configurable-uncertainty-policy), not fixed answer priority or a reservation for future work. Its successful-opportunity bound is not a wall-clock or upstream-availability guarantee.

One runtime and journal owner collect results. Each lane has one discovery/freshness pipeline and two reconciliation slots with its own due cursor. Answer and judge each have one independent native model task. Shared identity verification and account-effect admission each have one slot. Slow retained reads do not own the effect slot or consume another lane's reconciliation slots.

The selected effect retains account and lane admission guards through response bookkeeping. Gate-dependent preparation, abstention and native launch defer without inventing failures or another attempt; result collection and safety recovery remain live. Global pause can wait for an in-flight bounded effect; lane pause waits for its own lane, not a sibling's effect. After acknowledgement, new starts require current authorization. Neither acknowledgement nor local shutdown recalls transmitted requests.

Answer/judge `preparation` defaults to `retry_uncertain = false`, `max_attempts_per_work = 2` (finite values 1–8), and `max_uncertain_replacements_per_work = 1` (0–8). `while_blocked` defaults true for answer and false for judge. Explicit `max_attempts_per_work = "unbounded"` authorizes paced recurring attempts after conclusively finished unusable output while work remains eligible; it is not a monetary budget. Possibly-running same-work inference remains separately limited to the original unresolved launch plus the configured replacement allowance, and requires `retry_uncertain`. Proven nonexecution does not consume an inference attempt; age, restart and manual abandonment do not refund possible execution. Existing retry schedules remain binding. Preparing behind uncertainty never authorizes submission. Preflight and pending admission/revalidation waits consume the same original execution deadline and cannot renew it.

`run --once` takes a finite entry-time plan: at most two entry-due recovery reads per lane, one model attempt per model lane and one effect per lane, with bounded discovery/freshness. It drains owned handles but does not wait for future grace/cadence deadlines, discover later grants or replenish completed work indefinitely. Ordinary `run` continues scheduling.

The runtime reloads model guidance and ordinary participation policy at safe boundaries. Invalid edits are reported without partially applying them. Account, chain, credential reference and state directory remain identity boundaries for existing state. Network profile changes additionally require a stopped, drained runtime; see below. A different account needs separate configuration/state. Model changes apply to new model calls; in-flight work retains its captured configuration. Pause and capability policy are rechecked before dispatch.

Valid lane-only reloads do not invalidate shared identity authority or another lane's observations. Diagnostics use captured effective lane revisions; they do not read guidance to reconstruct them or borrow desired settings when evidence is missing.

Configuration inspection shows references and model names, not credential values. `agents` reports configured routes; it does not claim they are authenticated or invoke a model.

`capabilities.judge.excluded_assignments = []` lists assignment transaction IDs. IDs must be 64 hexadecimal characters; matching ignores case. Exclusions reload and are checked before selection, abstention and admission. Only proven-unsent work is released; queued or possibly-sent work continues reconciling. A cooled or in-flight hydration candidate does not monopolize selection when another eligible assignment is available.

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

Each lane has its own `capabilities.<lane>.participation` policy:

| `mode` | New work behind account-wide unresolved effects |
|---|---|
| `strict` (default) | Wait for authoritative resolution |
| `participation_first` | With a numeric exposure cap, permit overlap after applicable uncertainty grace; with explicit `"unbounded"`, admit distinct fresh work without a historical-count ceiling or blanket grace |
| `manual` | Require a stopped-writer, epoch/lane/account-generation/lane-control-revision-bound one-dispatch grant; never bypass capacity, server minima or answer retry grace |

`manual` governs overlap with unresolved effects, not approval of every submission: otherwise-safe first work can dispatch without a grant. It is not a model-only execution mode. Use lane controls to stop participation, and isolate protocol endpoints when testing real model execution.

`max_unresolved_operations` defaults to 4 **per lane**, including the prospective dispatch. Another lane cannot consume or borrow a numeric allowance. There is no shared capacity pool, answer reserve or `allow_*` alias. `uncertainty_grace_seconds` defaults to 300 for bounded participation-first overlap. Strict/manual retain their independent account-uncertainty controls.

Explicit `mode = "participation_first"` plus `max_unresolved_operations = "unbounded"` accepts potentially growing remote exposure and retained history so missing old outcomes cannot indefinitely stop distinct fresh work. It removes neither same-work/epoch fences nor active local-effect, identity, pause, freshness or scoped server restrictions. The count ceiling and blanket uncertainty grace no longer govern that lane's new-work admission. Existing numeric files stay bounded; omission does not silently select unbounded behavior.

`work.<lane>.admission` uses the canonical dispatch policy, with current counts/limits, scope, reason and next timing evidence. An unbounded limit is not zero capacity. Historical counts omitted from the admission fast path are explicitly unevaluated, not proof of no uncertainty. Diagnostic snapshots may still compute exact retained totals. An allowed local projection is not fresh identity/eligibility proof or a reusable dispatch permit.

For a reviewed judge-only exposure change:

```sh
printf '%s\n' '{"capabilities":{"judge":{"participation":{"mode":"participation_first","max_unresolved_operations":"unbounded"}}}}' |
  agmi --json config apply --expected-revision "$FILE_REVISION" --dry-run
```

Remove `--dry-run` only after approving the exposure change. Recurring model spending is a separate decision: set the model lane's `preparation.max_attempts_per_work` to `"unbounded"` explicitly if desired. Neither patch activates an inactive lane or resumes participation.

These opt-ins require a binary that understands them. Older numeric-only parsers reject `"unbounded"` and do not understand the new uncertain-replacement field; matching journal formats alone does not make such a configuration backward-compatible. Never restore an older journal to undo a policy choice.
The same rule applies to `schedule.observation_max_age_seconds`: earlier binaries reject this field. A same-journal-format binary rollback requires restoring a configuration accepted by that binary, including its prior finite policy where necessary. Preserve the pre-update configuration separately; never restore an older database or clear uncertain outcomes to make rollback succeed.

Only answer owns historical capacity settings. `historical_unknown_answer_capacity = "bounded"` and `max_historical_unknown_answers = 0` are defaults. An explicit finite historical allowance excludes qualifying originals from answer's own active capacity. Participation-first may instead select `accepted_linked`, excluding all qualifying originals without a lifetime historical-count bound.

Eligibility requires a dispatched, identifier-less unknown answer and a directly linked later retry in the same recorded epoch with a transaction ID and recorded `included_pending`, `confirmed` or `final` state. Unrelated acceptance, transitive ancestry, age, judging and mining never qualify. Originals remain unknown. This is **not settlement, nonexecution or finality evidence**.

Historical exemptions affect finite answer capacity only; they never become judge/mine capacity or erase account-wide uncertainty. Witness revocation can recharge original answers. Strict/manual gain no historical allowance. Accepted-linked accounting accepts accumulating historical risk but grants no same-epoch replay. Unbounded participation-first does not need an exemption to proceed with distinct work; the original outcome and any witness history remain intact.

For an explicit answer-only policy patch:

```sh
printf '%s\n' '{"capabilities":{"answer":{"participation":{"mode":"participation_first","historical_unknown_answer_capacity":"accepted_linked"}}}}' |
  agmi --json config apply --expected-revision "$FILE_REVISION" --dry-run
# Review the risk, then remove --dry-run to save.
```

This does not enable capability modes, resume participation, change judge/mine risk policy or enable uncertain-answer retries. Return to bounded accounting by setting `historical_unknown_answer_capacity` to `bounded` in the same answer policy. Existing uncertainty is never erased.

Same-epoch uncertain-answer retries additionally require answer's `retry_uncertain_answers = true`, its `uncertain_answer_retry_seconds` (default 600) and remaining `max_answer_attempts_per_epoch` (default 2). Distinct dispatched operations consume that budget; model failures and safe retries of positively refused work do not create new distinct dispatch attempts. Matching captured payloads are reused; changed challenges require valid fresh preparation. Included, confirmed, final or freshly reported answered work is not retried merely because finality is slow.

`work.answer.retry` distinguishes policy permission, original operation, retained floors, fresh-evidence waits and exhausted answer-attempt limits. It is not resolution or dispatch authority. Ready effects use served-in-round fairness and earliest local observation-freshness deadlines, with due-time/stable-lane ties. A continuously eligible lane waits at most `2N−1` successful dispatch opportunities for `N` registered lanes, not a wall-clock bound. No lane reserves future capacity. Every dispatch retains its captured policy and evaluated authorization evidence; omitted historical scans are marked unevaluated rather than empty.

Manual administration, with the runtime stopped:

```sh
agmi --json recover authorize --epoch "$EPOCH" --kind answer
agmi --json recover grants
agmi --json recover revoke --grant "$GRANT_ID"
```

The selected lane must be active with manual policy and resumed intent. Account pause/resume changes the shared generation; lane pause/resume changes only that lane's control revision. Either invalidates the corresponding grant authority without deleting history. Grants remain subject to lane quota, fresh evidence and answer-attempt limits. Legacy conversion revokes old grants; source-3 conversion preserves records without inventing a missing lane-control binding.

**Grace authorizes risk, not certainty.** A delayed old request can execute after a new one, causing duplicate effects or nonce conflicts. Lowering a cap can stop new dispatches but never clears existing work. A cap is not a lifetime-write budget. Fresh identity and eligibility remain mandatory; no timer guarantees participation during an upstream outage.

Reconciliation is separately paced per lane with bounded read slots, fair service for recent/ordinary bound work and sparse service for repeatedly missing jobs. Fresh discovery remains independent. Repeated 404s can reduce polling urgency but never establish failure or permit a duplicate POST. A bound `408 job_expired` is different: it supplies positive nonprocessing evidence. Upstream finished-job retention is not a local retirement timer measured from submission. Identifierless uncertainty has no job to poll.

Capacity/scheduling changes need not discard valid unsent model output: reuse requires unchanged producer/input provenance, nonrevoked authority and fresh dispatch checks. Genuine model/guidance changes and insufficient historical provenance remain fences. The immutable producer record is not retagged with the new dispatch policy.

### Lane controls

Pause one capability without changing modes or sibling controls. With `jq` available:

```sh
CONTROL_TOKEN="$(agmi --json lane show judge | jq -r '.data.desired.control_token')"
agmi --json lane pause judge --expected-control "$CONTROL_TOKEN" --wait-seconds 30
# When ready, read the current token again before removing this override:
CONTROL_TOKEN="$(agmi --json lane show judge | jq -r '.data.desired.control_token')"
agmi --json lane resume judge --expected-control "$CONTROL_TOKEN"
```

The opaque token is not a config-file or loaded-content revision. Stale-token changes conflict; a current-token no-op does not churn revision/events. Controls load metadata without requiring unrelated guidance or harness executables. `--wait-seconds` bounds local lock acquisition attempts, not stalled OS I/O.

A pause ACK fences new selected-lane preflight, inference and effect admission. It does not stop already-started inference, settle a committed dispatch intent or cancel remote work. Unsettled dispatch and unresolved-sent counts remain explicit. Sibling lanes retain their own controls and can progress; ordinary shared identity, uncertainty and server restrictions still apply. Lane resume removes only the override, grants no retry right and never proves admission open. Global `pause`/`resume` remains account-wide and does not erase lane overrides.

`lane show` and `status.lane_controls` separate desired control, authoritative closure and last runtime observation. Stopped, stale or unverifiable observations report unknown admission rather than an open permit. Config/guidance saves are not fence acknowledgements. Stop the controller, rather than pausing a lane, when no agmi network activity is required.


### Core and user guidance

Each model route has two separately editable layers:

```toml
[capabilities.answer.model]
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

### Atomic capability migration

The proposed current contract uses unversioned per-lane configuration and journal format 4. Published **v0.1.0 and v0.1.1 use global-shaped configuration and journal format 2**; the unreleased implementation below is not a package publication or proof of a deployed format. Inspect actual configuration, journal, authority and migration seal rather than inferring compatibility from a version label. This is a permanent explicit cutover, not a legacy-bot importer. Preserve private backups for investigation; never restore older state to regain availability.

Ordinary `update` does not convert or pause an incompatible installation. `update --migrate` explicitly authorizes stopped maintenance: verify/stage the incoming release, disable service/timer boot activation, stop and verify the writer, durably pause when necessary, then select the incoming release stopped. A pause can change generation and invalidate grants/captures. Preparation is disruptive and mutating, **not a dry run**. Nothing automatically re-enables, starts or resumes participation.

**One-time published-client bootstrap:** v0.1.0 has no latest-stable updater; v0.1.1 online discovery requires journal format 2 before downloading and cannot fetch a journal-4 candidate. Old CLIs do not learn the new migration flags. Acquire the correct candidate through the publisher/operator trust path; verify origin, archive checksum, extracted executable checksum, and published manifest/build identity **before executing it**. Checksums under publisher trust are not independent signatures. Invoke that verified new executable directly; do not overwrite the managed binary by hand or install an intermediate bridge release:

```sh
# NEW_AGMI is the verified new executable; EXPECTED_SHA256 is operator-trusted.
umask 077
"$NEW_AGMI" --json update --binary "$NEW_AGMI" --sha256 "$EXPECTED_SHA256" \
  --migrate --proposal proposal.json > migration-preview.json
```

Prepare `proposal.json` privately with explicit positive `caps` for `answer`, `judge` and `mine`, or a complete `candidate_toml`. Caps are policy decisions, never automatically copied or divided global capacity. Canonical strict/no-allow legacy configuration may use `{}` only when preservation is proven. Missing necessary choices refuse before maintenance. No default modes, models, quotas or authority adoption are invented. Inspect `config migrate preview --help` for the canonical input shape.

`--proposal FILE` accepts one JSON object of at most 64 KiB; only explicit `--proposal -` reads stdin. Proposal JSON never travels in child argv: handoff uses an owned mode-0600 temporary file until the installer finishes. Preview/request/config/guidance/routing details are private; do not publish or log them. Preparation reports `migration_prepared`, not `updated`, and returns a private canonical `data.preview`, exact request, token and selected release ID. With `jq` available:

```sh
TOKEN="$(jq -r '.data.migration.token' migration-preview.json)"
RELEASE_ID="$(jq -r '.data.migration.release_id' migration-preview.json)"
jq '.data.preview.request' migration-preview.json > request.json
# Review candidate, backlog, exposure, model routes/budgets and authority first.
"$NEW_AGMI" --json update --release "$RELEASE_ID" --migrate \
  --proposal request.json --expected-token "$TOKEN"
# Add --accept-risk-change "$TOKEN" only when required and explicitly approved.
```

Use the preview's exact returned `request`, never a reconstructed proposal. The approval tuple is **selected release ID + exact request + migration token**. Continuation requires an explicit `--release` equal to the currently selected verified candidate and never re-resolves latest or selects a different candidate incidentally. Source/config/guidance/journal/authority or selection changes require refusal and a fresh explicit review, not automatic reapproval. Risk acknowledgment must equal the expected token. Changed/unproven effect exposure, answer-attempt or uncertain-retry allowances, model spending and historical backlog are assessed independently; strict mode alone is not proof. `--migrate` conflicts with `--repair` and `--migration-only`.

For per-lane `schema_version = 2` configuration already on journal format 4, plain update reports migration required. Explicit `update --migrate` uses the canonical exact `{}` marker-only preview/token/apply internally; it needs no external approval token and cannot change lane policy. Existing controls, account authority, operations, charges and retry floors remain. The necessary pause may change generation; configuration/lane/producer revisions change, and formatting/comments may be reserialized. Historical captures retain their original facts and charges, never automatic replay or budget reset. The result is `migration_complete_stopped`, not readiness.

Per-lane journal-3 conversion also uses unchanged-policy `{}`, but requires the returned token and explicit pinned continuation. Global-layout conversion requires explicit policy choices as above. Ordinary already-compatible updates retain their existing runtime/timer intent and config/pause/generation behavior, including when `--migrate` finds no conversion necessary.

The lower-level `--stopped --migration-only` explicit-source bootstrap remains available for supported 2/3-to-4 installation selection without conversion. It disables boot activation and never starts or repairs participation; use canonical standalone preview/apply with caller-managed stopping for noncanonical foreground installations. Partial bootstrap failures retain bounded `bootstrap_recovery` evidence for disable, definition restoration and manager reload; inspect actual selected release and manager state before retrying, never automatically enable/start.

Eligible initial unbound schema-1 authority additionally requires `adopt_legacy: true`. Preview returns the proposed initial database ID in `request`; reuse it. Conversion and initial authority sealing share one durable transaction. Missing or conflicting established schema-2 authority is never recreated.

If interrupted, inspect the sealed migration without starting participation:

```sh
"$NEW_AGMI" --config "$CONFIG" --json config migrate status --state-dir "$STATE_DIR"
"$NEW_AGMI" --config "$CONFIG" --json config migrate export \
  --state-dir "$STATE_DIR" --expected-token "$TOKEN" > private-sealed-migration.json
"$NEW_AGMI" --config "$CONFIG" --json config migrate resume \
  --state-dir "$STATE_DIR" --expected-token "$TOKEN"
```

**`config migrate resume` finishes conversion; it does not resume participation.** Use the token from migration status. Exact old bytes can be replaced by the sealed candidate; exact new bytes can be verified and finished. Different configuration/guidance or authority is a conflict, never permission to overwrite. Keep stopped, inspect the private export and restore approved inputs deliberately; do not edit journal or authority records.

Integrated `update --migrate --release "$RELEASE_ID" --expected-token "$TOKEN"` may finish the same canonical pending seal only when the selected release and exact token match. Use the verified incoming/retained executable, not an arbitrary stale CLI on PATH. A pending seal is recovery, not permission to generate a new proposal, retarget historical approval, repeat pause or adopt authority. After the first committed conversion seal (or config publication for config-only conversion), do not restart the old writer. If incoming selection succeeded before conversion or a later installer step failed, inspect migration and installation phases independently: failure never means rollback. Boot-disable/stopped maintenance intent is not automatically restored after interruption or cold restart.

Integrated recovery reports `pending` separately from further work. Only a pending
seal gets an old-token continuation. A completed target-3 seal gets a fresh,
separate current-format preparation, never reuse of its old approval. A completed
pre-gate seal exposes the bounded `authority_adoption` prerequisite: keep every
controller/native task stopped, inspect admission authority and separately approve
canonical `recover adopt`. Neither prerequisite authorizes service activation.

A recognized historical seal without an explicit target resumes only its exact original target-3 conversion, retaining its token and archived seal. It then needs a separate explicit 3-to-current preview/apply. Never relabel that seal or run the intermediate journal with the current binary. New conversion approvals authenticate both permanent writer and account-admission inodes without resetting database identity or witness. Authentic earlier explicit-4 approvals finish their unchanged writer-only destination; stopped `recover adopt` separately establishes the missing account-gate anchor before ordinary use. Completed migration resume only acknowledges completion, never retrofits anchors. Missing or contradictory established authority is a refusal, not a repair opportunity.

Pending migration fences ordinary mutators. Migration status/private export remain available even if the installed configuration conflicts. With no journal and no bound authority, conversion changes configuration only and creates neither journal nor authority. Retained legacy floors remain absolute and are never renewed by restart.

After completion, run `config check` and inspect local status. For a managed installation, explicitly run `agmi service enable` and `agmi service start`; migration does not restore either boot activation or running intent. Participation remains paused: review fresh readiness before a separate `agmi resume`. Neither bootstrap nor migration authorizes a fleet rollout or fleet risk-policy changes by itself.

#### Offline rehearsal is not a relocated database restore

A consistent SQLite backup is useful evidence, but is not a complete migration replica. Configuration, guidance, journal identity, canonical paths and the independent dispatch witness must agree. Existing writer/account anchors and sealed approvals also bind filesystem identities. Copying files changes inodes; capturing a newer witness beside an older database can correctly produce a refusal. Never edit those identities, lower a witness, delete anchors or re-adopt established authority to make a rehearsal pass.

An unsealed format-2 source without existing inode anchors can be rehearsed from a coherent live backup plus its unchanged binding/writer marker and exact private inputs, at the required canonical paths inside isolation. Production inode preservation and a preexisting global pause are not prerequisites on that path; conversion pauses the isolated copy and revokes unused manual grants. Do not generalize this exception to anchored or sealed sources. Capture provenance and stable config/guidance/binding evidence are still required; the sequence comparison alone does not prove a coherent capture.

Use only an explicitly authorized coherent capture in an isolated environment that demonstrably preserves the required identities. Deny network access externally, exclude credentials/provider sessions and production mounts, and expose no native execution or production service-manager path. Changing `HOME` or XDG directories is not isolation: account gates use the effective user's canonical passwd home. A snapshot alone does not prove these conditions.

Preview acquires locks and may create local lock artifacts; it is not a zero-write filesystem inspection. For per-lane source-3 or current-format configuration, use `{}`; caps/adoption inputs are not accepted on that path. Policy stays unchanged while obsolete configuration markers are removed. Apply/resume require the original authority checks and a durable pause on these paths, whereas the isolated unsealed source-2 path above does not require a preexisting pause. Without an eligible capture, report the rehearsal as blocked or an expected refusal—not a successful conversion.

Offline rehearsal ends with local migration/evidence inspection. Do not run participation, enable/start services, install/update, invoke credentials commands or return copied state to production. The activation instructions above apply only to a separately approved live cutover.

#### Fleet release gate

1. Record each host's observed executable/build, journal format, selected configuration, service/timer intent and current uncertainty. Do not infer deployed versions from an earlier review or a release label alone.
2. Review each candidate lane's explicit mode, quota, schedule and deadlines; answer/judge model, harness, reasoning and guidance; and uncertain-model/network retry policies. Old global capacity/reservation is not equivalent to three lane quotas. Existing participation-first or accepted-linked policies must not silently become strict—or vice versa.
3. Require the complete CI pipeline, extracted-package library-test compilation and binary writer/account-authority continuity coverage. Synthetic migration and native fixtures are not a real-journal rehearsal or authenticated-provider proof.
4. Separately authorize bounded native-provider validation with a designated test identity, exact harness/model route and inference budget. A pass requires successful inference, a valid bound artifact and sufficiently complete native-reported provenance matching the authorized route. Failed calls, mismatches or missing required facts are failed/unavailable proof and block that route's activation. Exercise cancellation separately without treating client exit as remote nonexecution. Do not patch installed harnesses or copy authentication material; ordinary native session/cache/auth-refresh writes may still occur when invoked.
5. Authorize one account's maintenance window and cutover, never a fleet-wide conversion. Verify effective lane modes after conversion, then separately approve service activation and participation. A format-incompatible old binary is not a rollback path; stop and roll forward without restoring older journal state.
6. Before expansion, observe at least two complete epoch transitions and one controlled restart. Require observed eligible answer/judge/mine progress, independent lane pause/resume, retained work/retry floors/uncertainty, and diagnostics that agree with observed state. Correctly explained blockers prove diagnostic behavior, not lane readiness. Any lane without demonstrated eligible progress remains failed or untested and blocks expansion, including when no judging opportunity arose. Record CPU, memory and journal growth against agreed limits; remote acceptance/finality require remote evidence.

Before deploying marker removal, inspect external monitoring/automation for reliance on health `contract_version` or the retired config schema identifier. They are no longer emitted; select the required evidence fields instead. No external-consumer compatibility is established by an in-repository search.

Historical target-3 and pre-gate recovery remain supported pending a deployment inventory: include stopped/offline hosts, selected/installed builds, journal formats, migration phases/targets, predecessor records and admission anchors. Unknown hosts are not proof of no obligations. Remove historical execution paths only after affected transitions complete or an explicitly supported recovery executable/procedure is verified. Keep retained approval/evidence export readable and unknown seals fail-closed; never delete journal history to simplify cleanup.

Keep financial reporting separate: local status supplies participation and health, not balances, spendable/locked funds or seats. Use authorized remote account/explorer sources for those fields, retaining their source and observation time; unavailable data is not zero.

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

Use a native CLI executable, not a shell command or an arbitrary JSON adapter. This implementation targets Unix (Linux/macOS). Provision each harness and its native authentication yourself. Hermes/OpenClaw additionally require their compatible Python/Node runtime; omp's standalone binary supplies its own runtime and bundled SDK. Neither Cargo builds nor `agmi install`/`update` installs harnesses, authenticates providers or provisions accounts. The omp executable/SDK are not vendored in agmi; only agmi's small native bridge is embedded.

| Harness | Inspected execution contract | Model syntax |
|---|---|---|
| Hermes | Launcher supports `--print-runtime-command`; native embedding API supports tool/context isolation and the authenticated OpenAI Codex route | Exact model identifier, for example `gpt-6.1-sol` |
| OpenClaw | `2026.10.9` public Gateway CLI transport, compatible Node.js on PATH, and an authenticated running Gateway permitting `operator.admin` | Provider/model, for example `openai/gpt-6.1-sol` |
| omp | Official standalone `18.19.0` binary; invocation-loaded public SDK bridge, independent direct inference and native authentication | Exact provider/model, including model IDs containing slashes |

The user service sets `PATH` to `$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin`; it does not load shell startup files. Configure the native harness executable by absolute path and make OpenClaw's compatible `node` available on that service PATH. A working interactive `nvm`/`fnm` shell is not sufficient. Provision and authenticate the harness as the runtime OS account, then verify model execution under supervision before leaving it unattended.

Unsupported native contracts fail explicitly; a matching product name alone does not establish compatibility. Hermes uses its existing authenticated Codex subscription route; the inspected OpenClaw route uses its native `openai` provider authentication. Other providers are not silently substituted. Reasoning values must be supported by the selected native model.

`capabilities.answer.model.hermes_api_url` and `capabilities.judge.model.hermes_api_url` independently declare the expected authenticated Hermes URL, defaulted from [`defaults/model.toml`](../defaults/model.toml). It must match the native authentication route; changing it never silently redirects a native key. OpenClaw resolves its endpoint through its existing Gateway configuration.

For omp, install the official binary separately with `curl -fsSL https://omp.sh/install | sh`, then run `~/.local/bin/omp` and authenticate through omp as the service OS account. No source checkout, npm SDK, external Bun/Node runtime or permanent plugin installation is required. Other omp versions fail qualification rather than silently changing the adapter contract.

Either model lane can independently use:

```toml
[capabilities.answer.model]
harness = "omp"
executable = "omp"
model = "openai-codex/gpt-6.1-sol" # Choose an exact ID from your native catalog.
reasoning = "high" # Must be supported; never silently clamped.
core_guidance_file = "answer/core-guidance.md"
guidance_file = "answer/user-guidance.md"

# Optional; omitted means native default profile, HOME-based provider discovery.
[capabilities.answer.model.omp]
# profile = "work"
# agent_dir = "./native-agent" # Explicit native agent directory instead of a named profile.
# provider_discovery_cwd = "./project" # Explicitly authorize project provider discovery.
env = [] # Native environment variable NAMES to inherit, never credential values.
```

Native paths are config-relative; native profile/auth/cache ownership stays with omp. Choose either `profile` or `agent_dir`, never both. Profiles use canonical native names: at most 64 lowercase ASCII letters/digits/dots/underscores/hyphens, beginning with a letter/digit; trailing dots and reserved device names are rejected before launch. Service-only environment inheritance is explicit: shell startup files are not read. HOME/PATH/LANG, private temporary/config controls and all native profile/root selectors (`OMP_PROFILE`, `PI_PROFILE`, `PI_CONFIG_DIR`, `PI_CODING_AGENT_DIR`) cannot be replaced through `env`. Native broker, proxy or provider environment variables must be named deliberately. Omp does not use `hermes_api_url`.

The omp adapter performs version-only preflight, waits for final admission, then owns one fresh native process and temporary extension per attempt. The extension also checks its actual bundled SDK version before projecting providers, so replacement during admission waiting cannot silently select an unqualified SDK. A fixed local command calls the public SDK directly with agmi's privileged policy and both captured guidance layers; native conversation, project instructions and tool hooks are not inherited into inference. Normal factory-time native providers are projected without attaching their tools/handlers. Providers registered only during live session lifecycle are not projected.

Native profile/provider factories remain trusted executable code, and the outer shell can initialize native facilities: this is tool-free direct inference, not a sandbox against startup side effects or opaque remote agent/tool behavior. Native endpoint-routing settings are passed explicitly; tools and configured fallback chains are not requested, returned tool calls fail, and unsupported exact reasoning-off fails closed. Host invocation/effort evidence is labeled adapter-owned, not provider-issued attestation. Native auth refresh/retries/cache writes remain native behavior; one logical attempt is not a hard HTTP-call or monetary cap. Killing the owned process does not prove remote cancellation, and possible execution remains charged.

Known agent/workflow transports `cursor-agent` and `gitlab-duo-agent` are refused before streaming: an empty supplied tool list does not disable their built-in workflow/tool capabilities. This is an API-capability fence, not a provider-name blacklist; ordinary direct-inference APIs and the supported Factory Droid controls remain independent.

Run `python3 tests/omp_native_smoke.py --omp /absolute/path/to/omp` for isolated default-binary/loopback acceptance. It uses temporary profiles and fixture credentials, not the operator's native login. Real authenticated provider acceptance remains separate.

OpenClaw uses its existing Gateway and native authentication through a small embedded Node bridge to `callGatewayFromCli`. Prompts travel over stdin, never argv. Each request is a fresh one-shot raw model run with tools, bootstrap context and delivery disabled. The Gateway chooses its configured default agent; no shared configuration is changed. Model overrides require the native `operator.admin` scope; insufficient authority fails rather than silently using another model.

Choosing OpenClaw trusts that Gateway's configuration, plugins and hooks. This is not isolated execution: hooks may influence routing before inference. agmi checks the returned model, reasoning, run binding and explicit no-tool/no-bootstrap/no-fallback evidence before accepting output; that cannot undo calls already made by the trusted Gateway. Hermes places policy in its native `system_message` channel. The inspected OpenClaw interface still combines policy and untrusted request data in one message; agmi does not claim privileged policy isolation or prompt-injection immunity there. Pause closes new admission and fences pre-pause results; already-started inference may continue. Timeout or shutdown cancels agmi's local adapter, not the shared Gateway. Remote inference may continue until its native deadline.

`operations list` and private `recover inspect` expose separate model-attempt producer, launch and completion evidence. Requested harness/model/effort are not native-reported facts. Completion retains safely parsed reports even on invalid artifacts or provenance mismatch; missing provider, effort, fallback or run facts stay unknown. Launch permission is not proof inference started, and crash recovery never invents a completion.

Native authentication and OS privilege isolation remain deployment prerequisites, not fixes delivered by this release. Provision authentication through the native harness; never copy another account's auth material. Same-user hostile processes and privileged Gateway access are not isolated by these adapters. Stronger OS identity/auth/container isolation is explicitly deferred; see [security boundaries](../SECURITY.md).

## Reliability boundaries

- SQLite persists intent before model execution or network submission. Local submission validation completes before dispatch intent; invalid payloads are not uncertain network writes.
- Queued, unknown, included and final outcomes remain distinct.
- Queued work is normally poll-only. Explicit bounded uncertain-answer retry policy may authorize a separate attempt; a matching `408 job_expired` instead proves nonprocessing and permits a safe captured-payload retry after backoff and freshness checks.
- A lost response or timeout never proves nonacceptance.
- HTTP status alone is not nonacceptance proof. The [published protocol guide](https://minepoa.com/go.md) explicitly documents `503 epoch_closing` and `429 accept queue full`; it does not establish an arbitrary “Chain indexing” 503 contract. Broader refusal handling requires sanitized captured route/status/body/header evidence plus an authoritative guarantee that no effect was accepted. Missing job/transaction IDs alone do not authorize replay.
- Strict policy blocks conflicting submissions. Participation-first/manual modes accept explicitly configured overlap risk while retaining uncertainty. Uncertain inference has separate regeneration authority.
- A stable local writer lock and independently stored database UUID/location binding protect cooperating instances. A narrow dispatch-sequence witness detects database-only rollback across a witnessed effect boundary. Missing, replaced or behind-witness journals fail closed. Deleting/restoring all anchors, whole-host rollback and hostile same-user races are not covered.
- Account identity is checked before writes. No automatic identity substitution or provider fallback.
- Journal events are sanitized. Exact operation payloads and bearer-like job identifiers remain private local state.
- Model failures use typed, allowlisted diagnostic categories, not native stderr or provider response text. Categories describe observed failure evidence; they do not prove that uncertain inference never ran or authorize regeneration.

Before live activation, stop other client writers for the account. Preserve unresolved legacy records; never call them resolved without evidence. agmi-managed uncertainty can be bypassed only under explicit participation policy, not by deleting history. There is no legacy-bot importer or state-reset command. Existing journals require intact stopped-writer adoption where applicable. Preserve the state directory and canonical account binding; never restore an older database to regain availability.

`model_unknown` means no MinePOA request was dispatched for that attempt. Configured uncertain-model retries are disabled by default. With the runtime stopped, `agmi --config ./config.local.toml recover-model` can abandon uncertain local preparation so policy may reconsider it; this is not proof that native inference stopped. It preserves pause, never clears an unknown network request, and does not refund the attempt or uncertain-replacement allowance. Current policy may still prohibit regeneration. Inspect model evidence and deliberately change the relevant policy rather than repeatedly abandoning attempts to bypass spending limits.

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

Preflight and inference start synchronously under account and selected-lane gates. Pending work retains its original deadline; waiting across pause, revalidation or SQLite contention consumes that budget rather than renewing it. Owning-lane revalidation must match unchanged task/config inputs and fresh observations. Store rechecks freshness after acquiring its transaction, and the host checks final bounds and continuity before native spawn. A pause ACK therefore fences subsequent starts, without claiming that already-started remote inference stopped.

Models return only task payloads: an answer, or a score and reasoning. agmi generates the native invocation identity outside the prompt and validates the returned native run against it. Hermes additionally binds the session, task, turn and exact current user/terminal assistant boundary; OpenClaw must return the invocation's native run ID. Unsupported native APIs fail preflight; mismatched completion evidence remains unknown and charged, not a valid artifact or permission to submit. Historical binding failures are not repaired by this cutover. Existing harness installations and authentication are untouched.

Assignments use the returned `answer_epoch`, never the inventory's current epoch. Bounded offset pagination deduplicates canonical transaction IDs, preserves partial coverage and prioritizes supplied expiry with deterministic ties. Moving/partial inventories never prove a sent operation failed. Missing target metadata triggers selected-transaction hydration; missing authoritative original words prevents judging. Supplied author history is candidate-bound and labelled missing, supplied or truncated; supplied does not mean exhaustive. Answer novelty context may include locally submitted text with unresolved acceptance.

Discovery persists its offset after validated pages, continuing bounded four-page windows across restart rather than repeatedly visiting only the first 400 assignments. Offsets above 10,000 remain traversable. Partial, duplicate-heavy or nonzero-start windows never establish complete absence; prepared targets retain their own bounded freshness lookup. Permanently obsolete unsent preparations retire without waiting for admission, while temporary backoff or capacity blockage preserves reusable work.

## Doctor and unattended status

```sh
agmi doctor
agmi doctor --repair
```

`doctor` is local and read-only by default. It combines health, separate answer/
judge/mine progress, intervention requirements and eligible guarded repairs.
It does not contact MinePOA, invoke a model or read credentials. Add `--json`
for the same machine-readable assessment.

Human diagnostics share a compact Core/answer/judge/mine view, separate retained
risk and actionable next steps. `status` is a snapshot using default diagnostic
thresholds, not a full health check. `health` names the selected readiness scope;
`doctor` additionally reports repair eligibility/outcome. Default output retains
operational essentials rather than duplicating full evidence trees; use
`agmi --json status --verbose` (or `health --verbose` / `doctor --verbose`) for detailed evidence.
Nonblocking historical uncertainty is still reported as risk, not as a current
new-work blocker, under finite as well as unbounded policy. Current actions take
precedence over background reconciliation. Shell-rendered actions preserve the selected configuration path.
Accepted/included work awaiting finality is also background follow-up when the canonical policy permits fresh participation. Its age alone does not make an open lane unhealthy. Same-work uncertainty, unavailable fresh evidence and actual admission fences still do. Model-failure diagnostics come from immutable model completion, not a later receipt or protocol error.
Exit codes retain distinct purposes: `status` succeeds when its snapshot is read;
`health` succeeds when its selected operational checks pass; `doctor` succeeds
when an unattended path exists and repair did not fail. A scheduled automatic
retry can coexist with degraded health. None is proof of remote finality.
`status.assessment_scope` makes its local snapshot scope explicit; it does not
probe filesystem headroom. `health`/`doctor` include their configured disk check.
Each `work.<lane>.operational` describes current lane health;
`work.<lane>.background_recovery` separately describes retained outcome follow-up
and inspection actions, not retry authority or a requirement to clear history.
`lane show`, `lane pause` and `lane resume` report control/admission evidence;
they do not certify operational health.

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
account and admission locks; no IDs or copied tokens are required. It never clears
blanket unknowns, replays uncertain work, raises budgets, or guarantees every
retained outcome will resolve. Human previews
show each candidate's classification and evidence limitation. Legacy 429 retirement
uses the developer-reported rejection policy: the original response body was not
retained, hidden contradictions cannot be ruled out, and no new upstream
verification is performed. This proves no independent finality.

Older builds used the same identity flag for a timeout and an actual rejection.
Doctor can normalize an eligible legacy `false` flag into explicit
`legacy_unknown` evidence, preserving the original failure and an audit record.
It does not infer why that old check failed, mark identity verified, rotate
credentials or clear a classified authentication/account mismatch. Changed
evidence between preview and application is not overwritten; the repair reports
`skipped`, including through `update --repair`. Repeated repair is a no-op.
Legacy identity flags can be normalized within a supported current journal; doctor does not perform a schema conversion. Use explicit migration for older journals. Retry deadlines, prepared work, uncertain submissions and model attempts remain intact; normalization is not verification.

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

Disabling boot activation preserves the exact unit-definition symlink targets,
including relative targets, so a later `service enable` remains possible without
reinstallation. Unexpected replacement definitions are not overwritten or reported
as successfully restored. Disable/enable does not start services or change pause.

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

`--check` and `--dry-run` never execute incoming code, activate, repair or convert.
They report operational compatibility as `not_assessed`, not installability; this
also applies with `--migrate`. A successful publication check may report no
compatible update or unverifiable source ordering. Inspect availability/reason.
Automatic activation requires verified host/build compatibility, protocol fencing
and conservative version/commit ancestry evidence. Dirty, divergent or unproven
source ordering is not resolved by downgrading. Different commits with the same
package version are not the same build. The selected-release fence is rechecked
under the installer lock. Explicit local sources remain operator-selected.

Incoming published builds must advertise `update_protocol=1` in their verified
build manifest: this guarantees support for the lock-held selected-release fence.
Older builds without that protocol (including the original v0.1.0 artifact) and
unknown protocols are reported as incompatible during discovery, never offered
for automatic activation. Explicit local installation remains available; the
updater does not weaken its concurrency safeguard to accommodate older installers.

Protocol 1 guarantees that fence, not universal configuration/journal compatibility.
Future ordinary compatible releases can use the existing verified incoming public-CLI
handoff without a bridge release or update-protocol bump. Older delegating parents
may discard unfamiliar child migration fields or report generic failure; the
one-time verified-new-CLI path above remains the honest escape hatch.

For ordinary compatible updates, downloads finish before managed installer cutover.
Configuration bytes, credentials, model/reasoning settings, core/user guidance,
pause intent and generation remain unchanged. No template is reapplied, account
is reinitialized, model is abandoned, or journal snapshot is restored. A service
that was running may resume its previously authorized participation after restart.

After a successful ordinary compatible update/no-op, the selected executable runs read-only doctor.
`--repair` additionally authorizes its existing guarded refusal recovery, including
the disclosed legacy-429 policy limitation; it is not permission to replay
uncertain writes or clear history. Checks/dry runs never repair, and `--check`
cannot be combined with `--repair`. A failed update does not proceed to repair.

JSON `data.update`, `data.installation`, `data.compatibility`, `data.migration`,
`data.repair` and `data.readiness` are separate outcomes. Finite migration outcomes
are `migration_required`, `migration_prepared`, `migration_complete_stopped` and
`recovery_required`; preparation can exit zero only as preparation. Migration
refusal/preparation/completion/recovery never runs doctor or automatic repair/resume.
Update/repair failure exits nonzero without hiding completed activation, conversion
or partial repair. Unhealthy doctor evidence does not undo an ordinary update;
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

Before manager-facing actions, agmi requires the OS account's canonical home, matching manager unit-search paths and loaded-unit file ownership. `manager_context_mismatch` requires correcting HOME/session selection or resolving conflicting units; `service_state_unavailable` requires readable, stable runtime/timer state before retrying. Stage-only writes the release tree without creating binary-link/user-unit directories or contacting the manager. Retained rendered units are checked against their binary's embedded template hashes, not just mutable checksum files.

Installer failures include a finite `failure_code` and relevant repair guidance without forwarding raw subprocess output. Installation needs an executable temporary filesystem for its private candidate copy; use an appropriate `TMPDIR` when the default temporary directory is mounted `noexec`. Do not disable host protections globally to install a release.

Ordinary upgrades preserve pause intent and generation: use normal activation, not `pause`/`resume`. Completed unsent drafts survive stop/start and are revalidated before dispatch; explicitly paused/off or obsolete work is not silently revived. Clean shutdown captures completed model results; genuine unfinished execution remains uncertain.

Older configuration/journals require [explicit stopped migration](#atomic-capability-migration), not `recover adopt` as an implicit conversion. Initial legacy adoption is an explicit migration approval. Current-format first anchoring requires intact writer, account gate, binding/UUID/witness and required lane evidence. Stop every controller and native task first: an unanchored gate cannot prove that an older detached gate has no owner. Writer-only anchoring is not complete account authority. Persisted inode continuity is not proof of a live process; inspect reported authority prerequisites before resuming. Missing established authority is never recreated, and adoption is not proof that an old snapshot is current.

Missing or unsafe unanchored lock evidence reports `authority_incomplete`, not an adoptable first-anchor state. Do not delete or recreate locks to make adoption pass.

Retained binaries are rollback candidates only when journal compatibility matches. Older binaries must not write current format-4 journals; roll forward or stop, never rewind state. Staging checks artifact/retention space plus a 256 MiB journal/WAL reserve without pruning history. `TimeoutStopSec=infinity` prevents systemd truncating captured deadlines; agmi bounds shutdown, but a shutdown bug still needs operator intervention.

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

Health is a local, read-only check: no network requests, model calls, credential/guidance reads or state initialization. Unhealthy checks return nonzero with structured issues for stale/stopped execution, blocked or unobserved admission, overdue work, missed-answer evidence, identity failures, inactive participation and low disk space. Evidence reflects local observations, not a fresh network verification or proof of rewards. Warnings are reported separately from health failures: a healthy runtime may have warnings, and warnings alone preserve a successful exit status. Healthy with warnings still reports attention required. Historical unknowns alone never fail a lane with a genuinely open fresh path, under finite as well as explicitly unbounded policy; this never turns age, missing jobs, or unrelated acceptance into terminal evidence. Neither warnings nor a healthy result permit replaying uncertain work.

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

Participation opt-out waives intentional pause/mode/reload expectations, not
intrinsic controller faults, captured-work deadlines, current bound-read failures
or active-lane accounting. Superseded, wrong-binding and unrelated discovery
failures do not become current-operation dependencies.
`participation.lanes.<lane>.pre_intent_blocker` retains the canonical blocker before
intent overlays: explicit null means none; unavailable evidence is unknown.
Strict uncertainty, manual authorization, quotas and server restrictions therefore
remain visible beneath a pause. This diagnostic field is never a permit.
Disk findings affect the core only and take precedence over start/resume/wait
recommendations. Verified doctor restoration supersedes stale stopped evidence,
not independent faults or the need for a new runtime observation.

Missing or incomplete captured policy, including any lane revision, yields `effective_policy_unavailable`, unknown controller/capability readiness and a failed health check—not defaults or freshness borrowed from desired configuration. An assessment marked stale by its projected authority/control/config stamp cannot establish current work even when its timestamps are recent. `thresholds.timing_source` distinguishes effective evidence from unavailable timing; unknown effective timing and epoch freshness are null. Run a compatible controller normally to publish its loaded policy; never manufacture it by editing the journal.

`operational.status` separates `clear` (no observed operational issue under the requested checks), `blocked` (admission fenced), `degraded` (other operational issues) and `unknown` (required policy or admission evidence unavailable). Top-level `healthy` and the exit status reflect these operational conditions. Retained unknown outcomes are warnings (`pending_outcome_uncertain`), not operational failures by themselves: healthy participation can report `attention_required = true` and `risk.attention_required = true`. Actual admission blocks still fail health, as do stale or missing observations, overdue work, exhausted finite capacity, strict-policy uncertainty gates and other operational faults. Background-resource failure never poisons a healthy sibling lane. This classification never changes journal outcomes, risk counts, admission limits or replay safeguards, and never guarantees every retained outcome will resolve or proves independent finality.

Health exposes `components.controller`, `.answer`, `.judge`, `.mine` and `api.identity`, `api.lanes.{answer,judge,mine}`, plus per-binding `api.resources`. Each health entry has `state`, bounded `reasons`, nullable observation/age and structured next actions; lane entries include effective mode. Resource entries identify owner, purpose, local operation and binding revision—not raw bearer identifiers.

`api.resources_truncated` discloses bounded read presentation; missing coverage is unknown, not proof of automatic recovery. Health still evaluates every `pending_work` operation independently of this presentation cap. Effective timing thresholds are lane-owned under `thresholds.lanes`; no lane borrows another's desired timeout.

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

Fresh complete judging inventory with no eligible work is `ok` under any participation policy, even when it
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

Awaiting inference admission uses the captured original pending deadline, not a renewed budget or an absent launch timestamp. Expiry is a prelaunch failure condition; a missing historical bound is unknown. A future-dated judge assessment makes clock evidence unverifiable and fails aggregate health, even when the controller heartbeat itself is current.

`oldest_unresolved_operation` and `oldest_unresolved_since` identify historical uncertainty; health also reports `oldest_unresolved_age_seconds`. They do not identify the current cause or duration of an admission block. Use `admission_blocked`, `affected_capabilities` and each `work` entry's reason/deadline for current policy waits.

`work.judge.assessment` and `lane_participation.{answer,judge}` expose sourced opportunity assessments with original `observed_at`, finite `valid_until`, coverage, candidate/exclusion counts and explicit unobserved outcomes. Judge eligibility requires usable parsed input, not merely an identifier. Read-only assessment may hydrate evidence but creates no operations, grants, model calls or submissions. Partial inventory never proves global absence. Account generation, lane-control revision, loaded lane configuration and runtime authority fence stale snapshots; stopped/stale assessments remain visible but cannot claim current eligibility. Model attempts and operation outcomes are separate counts, not proof of correctness, payment or finality.

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

Automated-update acceptance also exercised checksum-verified published v0.1.0 and
v0.1.1 journal-2 clients through the documented verified-new-CLI bootstrap,
unchanged-policy source-3 conversion with sealed interruption/public pinned recovery,
and journal-4 marker removal from a running old writer. These synthetic, loopback-only
accounts retained authority and approved policy and finished paused, stopped and
boot-disabled. Compatible updates preserved independent runtime/timer intent.
Use a release-profile executable for the resource-capped fixture; debug builds are
not production performance evidence. These updater runs did not include a fresh
kernel reboot or production/native-provider authentication.

Local protocol/model fixtures exercise deterministic lifecycle boundaries; they do not prove production authentication or live network outcomes. Production activation needs separate end-to-end verification with the real account and configured harness.

Linux host acceptance has exercised authenticated Hermes and existing-Gateway OpenClaw answer/judge inference, authenticated hosted reads, guidance hot reload and repair, concurrent pause, second-writer rejection, crash/restart recovery and clean shutdown. A bounded live canary on two independent accounts submitted one current-epoch answer, one eligible judgment and one explicit mine request per account. Answers reached node-reported checkpoint coverage; judgments reached receipt inclusion, with checkpoint coverage not established in this canary. Queued judgments were recovered read-only after correcting the protocol's `answer_epoch` and grading-result `id` fields, without resubmission. Both accounts were paused after the bounded test. These observations are not independent cryptographic finality verification or proof of unattended operation.

Historical pilot checks on three independent Linux identities across both harnesses exercised the shared installer, user services, graceful stop, automatic crash restart with preserved state/pause, and scheduled health execution. Answers and judgments reached node-reported inclusion or receipt confirmation. Upstream read failures and uncertain judging inference were retained without replay. These observations do not establish the deployed identity of the current checkout, public registration compatibility or a completed long-running stability study. Health findings remain local; no external notification channel or earnings verification is established.

The unreleased atomic-capability completion has local macOS proof for independent lane pause/resume, read-only answer/judge assessment, deadline classification, authority replacement refusal and authentic pre-change migration/refusal. Authorized isolated Linux checks additionally exercised real systemd install/update/retained activation, cutover cancellation, post-switch cleanup, sealed conversion interruption/recovery, old-binary refusal and automatic crash restart with preserved work and pause intent. Actual preflight/inference handoffs retained their account gate under injected `execve` delay; replacement/unlink could not produce a pause acknowledgment. An authentic pre-gate executable generated an approval whose exact token, seal and writer-only destination survived recovery, followed by separate stopped gate adoption. A genuine dedicated-host kernel reboot preserved disabled boot intent, journal/evidence, authority inodes, configuration, guidance and credentials in the retained isolated environment. Historical executables were built from hash-verified preserved source, not represented as published releases. Native/provider and protocol endpoints in those checks were substitutes; they did not prove installed-provider behavior.

Subsequent bounded acceptance exercised authenticated Hermes and existing-Gateway OpenClaw answer/grade execution using the native adapters from `c3640a3`, with synthetic loopback protocol identities and no MinePOA requests. Both harnesses returned valid bound artifacts with matching native-envelope provider/model/reasoning evidence: Hermes `gpt-6.1-sol` at max/high, OpenClaw `gpt-6.1-sol` at ultra/high. A 60-second Hermes answer probe timed out; a separately authorized attempt within the deployed 600-second limit succeeded. Timeout and explicit OpenClaw interruption retained unknown execution/stop evidence, not proof of remote cancellation or stopped billing. Manual uncertainty policy did not prevent first synthetic submissions; loopback isolation—not that policy—contained protocol effects. Protected copies of three real format-2 journals also converted offline with original operation fields, database identity and dispatch witness preserved, leaving copies paused. These checks do not establish live fleet participation, sustained stability, earnings or a rollout approval.

agmi is [MIT-licensed](../LICENSE). Package publication is deliberately disabled in `Cargo.toml`. Before publishing: clear registry name availability if publishing to crates.io, review third-party license obligations, audit source/history and packaged files for secrets, and require explicit release approval. `.gitignore` and Cargo's package allowlist do not replace a secret audit.

See [architecture](../ARCHITECTURE.md) and [security boundaries](../SECURITY.md). Protocol reference: [MinePOA agent instructions](https://minepoa.com/go.md). Experimental network; no earnings or monetary-value guarantees.
