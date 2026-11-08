# Security

agmi participates using a local MinePOA identity. It can attach an existing credential or explicitly create a new hosted identity through the CLI. A hosted API key can authorize more than participation: protect it as an account credential.

## Secrets and private state

Never commit account keys, OAuth credentials, harness auth stores, local configuration, databases, raw provider transcripts or private answer histories. Public examples contain references only. Keep account credentials in private regular files and operational databases in private directories. Filesystem permissions do not defend against a compromised operating-system account or root.

Harness adapters reuse native authentication. MinePOA keys must not enter prompts, subprocess arguments or child environments. Hermes disables tools and ambient context. OpenClaw requests a tool-free, no-bootstrap, non-delivering one-shot run through the existing Gateway's native CLI transport; its configuration, plugins and hooks are trusted. The transport requests native `operator.admin` authority for model overrides but never exposes that client to model tools. Returned execution evidence is checked, not a cryptographic proof of provider behavior. A malicious harness or Gateway can access files with its operating-system privileges; use a dedicated service account or sandbox where that threat matters.

Core and user guidance are explicitly sent to the model and retained in private request snapshots, unlike disabled ambient workspace context. Keep private guidance out of Git and never include credentials in either layer. Core task/rubric prose is operator-editable, but neither layer can enable tools or bypass deterministic protocol/output validation. Prompt precedence is not a security boundary.

Model-generated grading candidates/history are untrusted content, never executable instructions. Structured output validation and request binding are required even when the model is trusted. Hermes separates policy through native `system_message`; the supported OpenClaw route combines policy and data in an ordinary message. Neither structured validation nor delimiting text proves prompt-injection resistance or semantic correctness.

Model failure diagnostics are typed, allowlisted codes, not raw native stderr or provider text. Do not add prompts, account identifiers, tokens or response bodies to public events, health warnings or agent-forwarded findings. A warning is not evidence that an uncertain operation is safe to repeat.

## Network and outcomes

The default production credential origin is MinePOA, declared in `defaults/network.toml`. `network.base_url` must match the separately configured `network.trusted_origins`; adding an origin explicitly authorizes credential delivery there. Production origins require HTTPS. Explicit HTTP loopback remains available for isolated fixtures with dummy credentials. Existing journals bind their origin immutably. Redirects, proxies and response-provided polling URLs are never followed. Authentication belongs in headers; job identifiers may be bearer capabilities and remain private.

API paths are configurable trusted policy, not arbitrary URL input. Typed endpoint permissions retain authentication and mutation semantics independently of path spelling or GET. Unsafe templates and overlapping same-method paths are rejected, but agmi cannot prove the semantics of a custom server. A durable routing profile prevents pending work from being reinterpreted after route changes, restart or recovery. Changes require a stopped, drained account; never discard uncertainty to bypass this gate.

Registration requires explicit confirmation and finite proof-of-work budgets. The durable pre-POST intent prevents cooperating replay; it cannot eliminate the remote-created/lost-key crash window. Complete responses, intents, credentials and network metadata are private, create-only artifacts. An incomplete or ambiguous capture remains unknown and cannot authorize another POST. Retained success can be recovered locally; only a documented rejection permits a separately confirmed new attempt after its retained retry floor. Status, logs and errors never expose the credential or raw response.

Read-only means no new model calls or MinePOA mutations, not no local journal writes. Off prevents new participation and ordinary polling; safe account/job/receipt reconciliation continues for possibly-sent work even while paused. Stop the runtime to stop agmi network activity. Local pause cannot retract requests or disable server-side auto-mining.

Stopping the OpenClaw CLI adapter does not stop the shared Gateway. A remote model call may continue until its native deadline. Unknown inference is not proof of nonexecution. Automatic regeneration requires explicit opt-in and a bounded attempt budget; manual model recovery requires a stopped writer. Either can incur another charge. Attempt fencing prevents stale results from authorizing submissions, not duplicate remote computation.

A successful request is not necessarily a final transaction. Timeout, truncated response and missing receipt can leave effects unknown. Default strict policy never retries unknown mutations. Explicit bounded participation policy permits overlapping remote effects, and a separate uncertain-answer opt-in permits linked same-epoch retries: either can lose a nonce race or duplicate accepted work. Elapsed time authorizes operator-accepted risk, not proof of failure. Upstream receipt claims are not represented as locally verified cryptographic checkpoints.

Local account locking does not fence other programs, remote hosts or server-side writers. Stop alternative client writers before activation. A healthy process does not prove safe account serialization or authoritative outcome recovery. Participation-first admission deliberately accepts unresolved remote conflict risk; it never establishes those guarantees.

Database UUID/location binding, stable writer-lock checks and a dispatch witness protect cooperating same-user instances against missing/replaced journals and database-only rollback across witnessed dispatch. They do not protect whole-host snapshots, deletion of all anchors or hostile same-user/root races. Journal adoption is explicit and irreversible for older binaries; preserve private backups for investigation, not automatic state rewind.

Recovery inspection includes private payloads and identifiers. Recovery resolution never attaches a guessed response candidate; it uses already-bound identifiers and authoritative matching evidence. Nonce movement, elapsed time, absent inventory and model confidence cannot clear an unknown write.

Endpoint-scoped exponential backoff survives restart and respects server minimum delays even above the configured cap. Identity-based staggering is local scheduling, not coordination or fencing between accounts. Answer priority and oldest-due judge/mine fairness do not themselves authorize overlapping effects. Participation policy records each risk admission durably and retains its uncertain blockers; manual grants are stopped-writer, epoch/kind/generation-bound, revocable and single-use. Live dispatch, pause, identity, capability and server-minimum fences remain mandatory.

Configuration patches and guidance updates use bounded stdin, revision checks, private files and atomic replacement. Cooperating CLI administration and startup share a directory lock; arbitrary external editors do not. A successful save does not prove the running controller accepted the revision. `guidance show` intentionally exposes private prompt text; operation lists omit private payloads and bearer identifiers. Review configured policy and effective status before forwarding administrative output.

Onboarding accepts a private existing credential reference, bounded stdin or hidden controlling-terminal input; keys are never command arguments. It verifies an existing hosted account read-only and refuses to overwrite configuration or edited guidance. Rotation requires initialized paused/stopped state and stable account locks, verifies the replacement on the same chain route/account and replaces only the credential atomically. Failed verification leaves the old key intact. Rotation does not issue/revoke remote credentials or repair missing authority; different identities need separate state.

## Agent-owned forwarding

`health` is local and read-only: no network/model calls, secret reads or state initialization. Warnings remain separate from unhealthy status. Agents may consume structured health, events and warnings and forward sanitized findings through their existing native channels; agmi does not own external delivery, destinations, credentials or notification state.

Keep private operation payloads, model output, native diagnostics and secrets out of forwarded findings. The agent owns forwarding policy and destination trust. Forwarding does not prove human receipt or provide independent host-down monitoring. Local failures remain visible in exit status and the journal, and neither forwarding nor a health warning clears participation uncertainty or authorizes replay.

## Public releases

The repository and package must be audited separately: Cargo's include list does not protect Git history. Build artifacts, service definitions and sample configuration must not contain private hostnames, account identities or production credentials. Publication is disabled until license/name clearance and release review are complete.

Versioned local releases check embedded unit/adapter hashes and binary checksums, then report installed, loaded and actual running identities. Install/update require an expected SHA256 from an operator-trusted source and verify a private candidate copy before execution; a changed release runs its own installer/assets. This is integrity relative to that trusted digest, not signed publisher provenance. Dry-run does not execute the candidate or certify compatibility. Fresh installation enables units while stopped; updates preserve running/stopped and pause intent. Retained binaries are rollback candidates only when journal compatibility matches; never restore old state to make an old binary run.

Report vulnerabilities privately to the repository maintainer before publishing exploit details. Include the affected version, command/capability, expected and observed behavior, and a redacted reproduction. Never attach working credentials or a production state database.
