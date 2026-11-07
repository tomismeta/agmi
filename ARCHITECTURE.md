# agmi

**Agents Gonna Mine It.** A small Rust runtime for MinePOA participation.

## Product contract

- One Cargo package, one binary, one durable state authority per identity.
- Existing accounts and credentials remain local. Shared code does not mean shared identity, answers or state.
- Fresh installation. No legacy-state importer or migration framework. Prior writers must be stopped. Historical uncertainty remains recorded, not replayed or silently declared resolved; proceeding with checked, non-overlapping new work requires explicit operator authorization. This never clears agmi's own uncertain operations.
- Public source contains no operator identities, machine paths, credentials or private answer histories.
- No transfers, swaps, registration or governance automation. All-on means the implemented participation capabilities, not every protocol action.

## Boundaries

`config` owns validated operator policy. `protocol` owns MinePOA routes, payload decoding and effect classification. `solver` owns authenticated Hermes/OpenClaw model execution. `store` owns durable state. `runtime` owns scheduling and submission authority. `health` owns local read-only evidence. The CLI is a thin adapter to these same modules.

Models generate answers and judgments; they never own mining credentials, schedule work or submit transactions. Deterministic orchestration means the same recorded inputs produce the same state decisions, not that model output or the remote network is deterministic.

## Configuration

Answer, judge and mine each have `active`, `read_only` and `off` modes. Read-only permits safe observations/reconciliation but no model calls or submissions. Off performs no new work or polling for that capability. Durable local status remains available.

Operator settings include model, reasoning setting and harness independently for answer/judge; request/model/shutdown deadlines; polling, mining and retry cadence. Protocol observations provide epoch, challenge words/constraints, assignments, eligibility and receipt state. Server retry delays constrain local scheduling. Safety invariants are not override knobs.

Schedule defaults are 120-second polling, 180-second retry base, 900-second exponential-backoff cap, 30-second deterministic staggering and unchanged 86400-second mining cadence. Existing explicit settings remain effective; omitted new fields take defaults. Failed reads retain endpoint-scoped backoff durably across restart; unrelated endpoint success does not reset that history. The effective cap cannot shorten the retry base or a server minimum.
The bounded identity offset is added after the exponential cap and server minimum; it is not clipped away at the cap. Final waits may exceed the configured cap by the offset or an authoritative server minimum.

Identity-derived startup/poll/retry offsets require no peer communication or shared scheduling authority. Each identity remains independent. Answers have priority; judge and mine are ordered oldest-due first after answer selection, subject to existing modes, eligibility and mutation boundaries. Fair ordering does not override uncertainty or guarantee upstream availability.

Reload validates the whole configuration before swapping it. Invalid edits retain the previous valid configuration and surface an event. Identity, chain, origin and credential reference are fixed for existing state; the canonical account binding also fixes its state directory across process lifetimes. Each model call records its chosen configuration; changed modes and pause state are rechecked before submission. No silent provider/model fallback.

Assignment exclusions are hot-reloaded admission policy, shared by every harness. They filter new judging selection and discard only proven-unsent captured work before backoff/activity gates. They never erase or release possibly-sent operations.

Answer/judge can each reference a bounded UTF-8 guidance file. File contents participate in the configuration revision and are snapshotted into the private model request; editing a file alone triggers existing reload boundaries. Local safety controls and diagnostics load configuration metadata without requiring guidance to be readable; they do not claim a loaded revision when guidance is uninspected.

## Durable effects

SQLite on local storage uses WAL and FULL synchronization. Private files and directories use restrictive permissions. Database transactions do not span HTTP or model waits. A canonical account lock is independent of the selected database directory and durably binds the account to that directory. Initial binding is committed only after the identity-checked database opens successfully, under the admission gate and before network effects. Stopping the writer does not authorize replacing its database. Legacy/manual writers must also be excluded.

An intent is committed before model launch or HTTP mutation. Protocol submission preconditions are checked synchronously before dispatch intent; a local rejection cannot become an uncertain write. Accepted model output is retained rather than regenerated after transport failure. A crash after dispatch intent but before recording the response leaves an unknown operation. Unknown is not failed, and cannot be replayed automatically.

Queued jobs, ledger inclusion and checkpoint claims are separate observations. A successful poll is interpreted through the original submission classifier. A bound `408 job_expired` is authoritative nonprocessing: clear the expired job binding, wait, recheck eligibility and make a fresh hosted submission using the captured content. Missing jobs, receipt 404s and unrelated nonce movement do not prove nonacceptance. Retry headers survive malformed response bodies. A timeout changes local waiting, not remote truth.

Hosted assignments supply their target `answer_epoch`; the inventory epoch is not the answer epoch. Those chain-scoped protocol observations bind the candidate and words used for judging. Missing target-epoch metadata requires selected-transaction hydration. Grading success returns the transaction identifier as `id`; it is journaled before a separate receipt lookup establishes inclusion. These are node-reported observations, not independently verified ledger proofs.

Only matching authoritative terminal rejection or inclusion evidence releases a conflicting mutation boundary. Ambiguous explicit mining also blocks account mutation until its effects are known. If the protocol cannot resolve ambiguity, report the blocker; do not manufacture progress. Local serialization does not establish upstream serialization with server-side auto-mining.

Pause is a durable control command, not an incidental process stop. It closes new admission; existing remote effects cannot be recalled. Model inference reacquires the admission gate after native discovery and rechecks durable control generation immediately before spawn. Active account ownership binds control commands to the writer's state and identity configuration. New databases start paused. Explicit resume does not change configured capability modes. Local pause does not claim to stop server-side auto-mining.

Health reads a consistent local SQLite snapshot without opening auxiliary database descriptors, initializing state, contacting services or invoking a harness. A bounded singleton evidence row preserves the latest hosted identity result and current epoch's first observation/answered state independently of pruned diagnostic events. Repeated polls cannot reset the answer grace clock. Missing legacy evidence stays unknown until observed; read-only inspection never upgrades a database. Warnings are distinct from unhealthy issues and do not alone change the successful health exit status.

Shared user-systemd units own process supervision and two-minute local `health` execution. The installer replaces binary/unit files without activating them or touching operator state. Health failures remain local exit/journal signals.

Agents may consume structured health, events and warnings and forward sanitized findings through existing native channels. Forwarding policy, credentials and delivery are agent-owned, outside agmi; the runtime contains no external notification transport or notification state. Local health stays read-only and grants no permission to replay uncertain model or protocol work. Agent forwarding does not establish host-down monitoring or human receipt.

## Harness adapters

Reuse native authenticated Hermes and OpenClaw interfaces, not copied OAuth credentials or alternate paid API routes. Hermes embeds its native isolated runtime. OpenClaw uses its public Gateway CLI transport through a small Node bridge and trusts the existing Gateway configuration/hooks. Requests select the model/reasoning, one-shot raw mode, no tools/bootstrap/delivery and a unique idempotency key; returned native run identity and execution evidence must match. Prompt data stays on stdin. Native admin authority is required for per-call model overrides; no shared configuration is mutated. Clearing environment variables alone is not filesystem isolation.

Local adapters are bounded and cancellable; a shared OpenClaw Gateway is not an owned descendant and may continue inference until its native deadline after the client exits. Lost launch acknowledgment remains unknown unless the native backend proves nonexecution. The same uncertain model work is not automatically regenerated, but it does not hold the account's network-mutation boundary. `recover-model` requires a stopped writer and explicitly abandons model-only uncertainty with no dispatch artifact, allowing regeneration at possible additional model cost. Network uncertainty is never cleared by that command. Unsupported versions or routes are explicit errors, not fake success.

Model diagnostics cross the adapter boundary as typed, allowlisted categories. Native stderr, provider bodies, prompts and credential-bearing text are not diagnostic payloads. A diagnostic category never turns an unknown model attempt into proven nonexecution; failure presentation and retry authority remain separate.

## Delivery plan

1. Implement strict configuration, protocol-derived capability semantics and public CLI discovery.
2. Implement native authenticated harness adapters with configurable model routes.
3. Implement durable answer/judge/mine execution, receipt reconciliation, hot reload, pause and local status.
4. Exercise the actual binary against local protocol fixtures: queued receipt, unknown write, restart, no-resend, read-only, mode reload, malformed config and pause.
5. Review security/lifecycle boundaries; document exact verification limits and unresolved upstream constraints.
6. After separate authorization, activate one host, prove actual authenticated participation, then expand the same release. GitHub publication and destructive legacy cleanup are separate approvals.

## Engineering principles

One core; explicit effects; typed protocol boundaries; stable JSON discovery; conservative mutation retries; private state; no secrets in output; small dependency surface; no unnecessary frameworks. Publish only what is exercised, distinguishing local tests from real harness and network proof.

Reference protocol: https://minepoa.com/go.md and https://minepoa.com/openapi.yaml. Prose, schemas and real responses may diverge; classify conservatively and document the evidence instead of inventing capabilities.
