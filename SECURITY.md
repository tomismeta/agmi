# Security

agmi participates using an existing MinePOA identity. A hosted API key can authorize more than the participation operations agmi exposes: protect it as an account credential.

## Secrets and private state

Never commit account keys, OAuth credentials, harness auth stores, local configuration, databases, raw provider transcripts or private answer histories. Public examples contain references only. Keep account credentials in private regular files and operational databases in private directories. Filesystem permissions do not defend against a compromised operating-system account or root.

Harness adapters reuse native authentication. MinePOA keys must not enter prompts, subprocess arguments or child environments. Hermes disables tools and ambient context. OpenClaw requests a tool-free, no-bootstrap, non-delivering one-shot run through the existing Gateway's native CLI transport; its configuration, plugins and hooks are trusted. The transport requests native `operator.admin` authority for model overrides but never exposes that client to model tools. Returned execution evidence is checked, not a cryptographic proof of provider behavior. A malicious harness or Gateway can access files with its operating-system privileges; use a dedicated service account or sandbox where that threat matters.

Explicit operator guidance is sent to the model and retained in the private request journal, unlike disabled ambient workspace context. Keep private guidance out of Git and never include credentials in it. Guidance cannot enable tools or bypass protocol/output validation.

Model-generated grading candidates/history are untrusted content, never executable instructions. Structured output validation and request binding are required even when the model is trusted.

Model failure diagnostics are typed, allowlisted codes, not raw native stderr or provider text. Do not add prompts, account identifiers, tokens or response bodies to public events, health warnings or agent-forwarded findings. A warning is not evidence that an uncertain operation is safe to repeat.

## Network and outcomes

Production API origins require HTTPS; loopback HTTP exists for local development fixtures. Redirects and arbitrary polling destinations are not authorized. Authentication belongs in headers, not query strings. Job identifiers may act as bearer capabilities and must remain private.

Read-only means no model calls or MinePOA mutations. It does not mean no local journal writes. Off means no new capability work/polling. Local pause does not retract transmitted requests or disable MinePOA server-side auto-mining.

Stopping the OpenClaw CLI adapter does not stop the shared Gateway. A remote model call may continue until its configured native deadline. Do not interpret a disconnect or local process kill as proof that inference never started; unknown model work requires explicit recovery and may incur another model charge.

A successful request is not necessarily a final transaction. Timeout, truncated response and missing receipt can leave effects unknown. agmi must not retry an unknown mutation automatically. Upstream receipt claims are not represented as locally verified cryptographic checkpoints.

Local account locking does not fence other programs, remote hosts or server-side writers. Stop alternative client writers before activation. If safe account serialization or authoritative outcome recovery cannot be established, do not enable writes merely because the process starts successfully.

Endpoint-scoped exponential backoff survives restart and respects server minimum delays even above the configured cap. Identity-based staggering is local scheduling, not coordination or fencing between accounts. Answer priority and oldest-due judge/mine fairness never relax uncertainty boundaries or permit blind replay.

## Agent-owned forwarding

`health` is local and read-only: no network/model calls, secret reads or state initialization. Warnings remain separate from unhealthy status. Agents may consume structured health, events and warnings and forward sanitized findings through their existing native channels; agmi does not own external delivery, destinations, credentials or notification state.

Keep private operation payloads, model output, native diagnostics and secrets out of forwarded findings. The agent owns forwarding policy and destination trust. Forwarding does not prove human receipt or provide independent host-down monitoring. Local failures remain visible in exit status and the journal, and neither forwarding nor a health warning clears participation uncertainty or authorizes replay.

## Public releases

The repository and package must be audited separately: Cargo's include list does not protect Git history. Build artifacts, service definitions and sample configuration must not contain private hostnames, account identities or production credentials. Publication is disabled until license/name clearance and release review are complete.

Report vulnerabilities privately to the repository maintainer before publishing exploit details. Include the affected version, command/capability, expected and observed behavior, and a redacted reproduction. Never attach working credentials or a production state database.
