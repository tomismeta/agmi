use crate::capability::LaneId;
use crate::config::{Config, Mode};
use crate::endpoints::Endpoint;
use crate::protocol::{
    Assignment, Challenge, EffectDeadline, HostedResponse, Outcome, Protocol, ReadDeadline,
    RequestMeta, Response, ResponseSource, classify_source, has_required_words, parse_challenge,
    response_evidence, transport_failure, valid_grade_reasoning,
};
use crate::solver::{SolverRequest, SolverResult};
use crate::store::{
    AccountAdmissionGuard, AccountLock, AdmissionCutoff, Control, DiscoverySource,
    HostedIdentityOutcome, Operation, ReadKey, Store, digest, not_before, now,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Notify, oneshot, watch};

use super::*;
#[path = "coordinator.rs"]
mod coordinator;
#[path = "driver.rs"]
mod driver;
#[path = "io.rs"]
mod io;
#[path = "model.rs"]
mod model;
#[path = "ports.rs"]
mod ports;
pub(super) use coordinator::ReadyEffect;
use coordinator::{EffectInFlight, IdentityPermit, IdentityRead};
use driver::OncePlan;
pub(super) use io::ReadFlight;
use io::Recovery;
pub(super) use model::{AnswerModelSlot, GradeModelSlot};

pub fn build_info() -> Value {
    json!({"commit":env!("AGMI_BUILD_COMMIT"),"source_dirty":env!("AGMI_BUILD_DIRTY"),
        "target":env!("AGMI_BUILD_TARGET"),"profile":env!("AGMI_BUILD_PROFILE"),
        "journal_schema":env!("AGMI_JOURNAL_SCHEMA"),"version":env!("CARGO_PKG_VERSION")})
}

pub fn recovery_inspect(config: &Config, operation: i64) -> Result<Value> {
    Store::read_only(config)?
        .context("journal not initialized")?
        .inspect(operation)
}

pub fn recovery_adopt(config: &Config) -> Result<()> {
    let (_account, mut store) = AccountLock::adopt(config)?;
    let _gate = AccountAdmissionGuard::acquire(config)?;
    store.recover()
}

pub fn recovery_authorize(config: &Config, epoch: u64, kind: LaneId) -> Result<Value> {
    Store::read_only(config)?.context("journal not initialized")?;
    let (_account, mut store) = AccountLock::acquire(config)?;
    let _gate = AccountAdmissionGuard::acquire(config)?;
    store.authorize(config, epoch, kind)
}

pub async fn recovery_resolve(
    config_path: &Path,
    operation: i64,
    job_id: Option<&str>,
    txid: Option<&str>,
) -> Result<Value> {
    use crate::protocol::{RecoveryIdentifier, verify_recovery_identifier};
    let config_guard = crate::admin::lock_config_directory(config_path)?;
    let config = Config::load_metadata(config_path)?;
    let (_account, mut store) = AccountLock::acquire(&config)?;
    drop(config_guard);
    {
        let _gate = AccountAdmissionGuard::acquire(&config)?;
        store.recover()?;
    }
    let op = store.operation(operation)?.context("operation not found")?;
    if !matches!(op.state.as_str(), "unknown" | "queued" | "included_pending") {
        bail!("operation has no unresolved wallet effect");
    }
    if let Some(candidate) = job_id {
        verify_recovery_identifier(op.job_id.as_deref(), candidate, RecoveryIdentifier::Job)?;
    }
    if let Some(candidate) = txid {
        verify_recovery_identifier(
            op.txid.as_deref(),
            candidate,
            RecoveryIdentifier::Transaction,
        )?;
    }
    if op.job_id.is_none() && op.txid.is_none() {
        bail!(
            "recovery blocked: no authoritative request attribution; upstream terminal single-request binding is required"
        );
    }
    let protocol = Arc::new(
        Protocol::new(&config)
            .map_err(|_| anyhow::anyhow!("cannot initialize recovery protocol"))?,
    );
    let (_sender, stop) = watch::channel(false);
    let mut runtime =
        HostAccess::new(config_path.to_owned(), config, protocol, store, stop, false)?;
    runtime.start_identity(op.kind)?;
    while runtime.identity.is_some() {
        runtime.wake.notified().await;
        runtime.collect_identity()?;
    }
    if !runtime.permit_current()? {
        bail!("recovery identity unverified");
    }
    let mut seen = Vec::new();
    for _ in 0..2 {
        let mut op = runtime
            .store
            .operation(operation)?
            .context("operation missing")?;
        if op.next_at > now() {
            break;
        }
        let Some(key) = Store::operation_read_key(&op) else {
            break;
        };
        if seen.contains(&key) {
            break;
        }
        let (endpoint, resource) = if let Some(txid) = op.txid.as_deref() {
            (Endpoint::Receipt, txid)
        } else if let Some(job) = op.job_id.as_deref() {
            (Endpoint::Job, job)
        } else {
            break;
        };
        let Some(mut flight) =
            runtime.launch_read(op.kind, key.clone(), endpoint, Some(resource), None)?
        else {
            break;
        };
        seen.push(key.clone());
        let result = loop {
            if let Some(result) = flight.take() {
                break result;
            }
            runtime.wake.notified().await;
        };
        if let Some(response) = runtime.finish_read(&flight, result)? {
            runtime.recovery_response(&mut op, &key, &response)?;
        }
    }
    let op = runtime
        .store
        .operation(operation)?
        .context("operation missing")?;
    let resolved = !matches!(
        op.state.as_str(),
        "unknown" | "queued" | "included_pending" | "dispatching"
    );
    Ok(
        json!({"operation_id":op.id,"state":op.state,"resolved":resolved,
        "network_requests_reset":false,"evidence":"authenticated_bound_request","finality":"node_reported_only"}),
    )
}
pub(crate) fn status_evidence(config: &Config) -> Result<Value> {
    Ok(match Store::read_only(config)? {
        Some(store) => store.status(config)?,
        None => json!({"initialized":false,"paused":true,"generation":0,
            "configured_revision":config.optional_revision()?,"effective_runtime":null,
            "hosted_identity_verified":null,"pending":null,"operations":[],
            "hosted_identity":{"status":"unobserved","observed_at":null,
                "last_verified_at":null,"rejection":null,"legacy_failure":false},
            "capabilities":config.capabilities,"observations":{},"legacy_observation":null,
            "reads":[],"reads_truncated":false,"work":{},
            "participation":{"policy_source":"unavailable","unresolved_count":0,
                "risk_admissions":0,"lanes":null}}),
    })
}

pub fn status(config: &Config) -> Result<Value> {
    let mut status = status_evidence(config)?;
    crate::health::enrich_status(&mut status, crate::health::Options::default(), now());
    Ok(status)
}

/// Local metadata only: never initializes a journal or contacts the network.
pub fn reads(config: &Config) -> Result<Value> {
    match Store::read_only(config)? {
        Some(store) => store.reads_projection(),
        None => Ok(json!({"reads":[],"reads_truncated":false})),
    }
}

pub fn operations_list(
    config: &Config,
    kind: Option<LaneId>,
    state: Option<&str>,
    before: Option<i64>,
    limit: usize,
) -> Result<Value> {
    crate::store::validate_page(before, limit)?;
    match Store::read_only(config)? {
        Some(store) => store.operations_list(kind, state, before, limit),
        None => Ok(json!({"operations":[],"next_before":null})),
    }
}

pub fn recovery_grants(config: &Config, before: Option<i64>, limit: usize) -> Result<Value> {
    crate::store::validate_page(before, limit)?;
    match Store::read_only(config)? {
        Some(store) => store.grants(before, limit),
        None => Ok(json!({"grants":[],"next_before":null})),
    }
}

pub fn recovery_revoke(config: &Config, grant_id: i64) -> Result<Value> {
    Store::read_only(config)?.context("journal not initialized")?;
    let (_account, mut store) = AccountLock::acquire(config)?;
    let _gate = AccountAdmissionGuard::acquire(config)?;
    store.revoke_grant(grant_id)
}
pub fn events(config: &Config, limit: usize) -> Result<Value> {
    match Store::read_only(config)? {
        Some(store) => store.events(limit),
        None => Ok(json!([])),
    }
}
pub fn pause(config: &Config) -> Result<()> {
    let gate = AccountAdmissionGuard::for_control(config)?;
    AccountLock::control_store(config, &gate)?.set_paused(true, &gate)
}
pub fn resume(config: &Config) -> Result<()> {
    config.validate()?;
    if config.network.address.is_empty() || config.network.credential_file.as_os_str().is_empty() {
        bail!("resume requires a configured account and credential file");
    }
    let gate = AccountAdmissionGuard::for_control(config)?;
    AccountLock::control_store(config, &gate)?.set_paused(false, &gate)
}

/// Explicitly release model-only uncertainty while the writer is stopped.
/// A possibly-sent protocol request is never eligible.
pub fn recover_model(config: &Config) -> Result<usize> {
    let (_account, mut store) = AccountLock::acquire(config)?;
    let _gate = AccountAdmissionGuard::acquire(config)?;
    store.recover()?;
    store.abandon_models()
}

fn same_identity(a: &Config, b: &Config) -> bool {
    a.network.base_url == b.network.base_url
        && a.network.api == b.network.api
        && a.network.chain == b.network.chain
        && a.network.address == b.network.address
        && a.network.credential_file == b.network.credential_file
        && a.state_dir == b.state_dir
}
fn stagger(config: &Config, bound: u64, phase: &str) -> u64 {
    if bound == 0 {
        return 0;
    }
    let mut hash = Sha256::new();
    for part in [
        config.network.chain.as_bytes(),
        config.network.address.as_bytes(),
        phase.as_bytes(),
    ] {
        hash.update(part);
        hash.update(b"\0");
    }
    let bytes = hash.finalize();
    let value = u64::from_be_bytes(bytes[..8].try_into().expect("SHA-256 prefix"));
    if bound == u64::MAX {
        value
    } else {
        value % (bound + 1)
    }
}

fn queued_poll_interval(initial: u64, cap: u64, mut elapsed: u64) -> u64 {
    let mut interval = initial;
    // Cumulative boundaries (initial, 3*initial, 7*initial, ...) retain
    // progression from the durable queued transition, not process uptime.
    while interval < cap && elapsed >= interval {
        elapsed -= interval;
        interval = interval.saturating_mul(2).min(cap);
    }
    interval
}

pub(super) struct HostAccess {
    config_path: PathBuf,
    config: Config,
    protocol: Arc<Protocol>,
    store: Store,
    stop: watch::Receiver<bool>,
    controller: bool,
    reload_blocked: bool,
    authority: String,
    authority_instance: String,
    authority_epoch: u64,
    sequence: u64,
    wake: Arc<Notify>,
    lanes: Vec<NativeLane>,
    recovery: Vec<Recovery>,
    identity: Option<IdentityRead>,
    permit: Option<IdentityPermit>,
    effect: Option<EffectInFlight>,
    once: Option<OncePlan>,
    identity_nonblocking: bool,
}

fn authority_fingerprint(config: &Config, protocol: &Protocol) -> Result<String> {
    let origin = reqwest::Url::parse(&config.network.base_url)?
        .origin()
        .ascii_serialization();
    let mut trusted = config
        .network
        .trusted_origins
        .iter()
        .map(|origin| reqwest::Url::parse(origin).map(|url| url.origin().ascii_serialization()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    trusted.sort_unstable();
    trusted.dedup();
    Ok(digest(serde_json::to_vec(
        &json!({"origin":origin,"chain":config.network.chain,
        "address":config.network.address,"state":std::fs::canonicalize(&config.state_dir)?,
        "credential_reference":config.network.credential_file,"credential_instance":protocol.credential_instance(),
        "api":config.network.api,"trusted_origins":trusted,"identity":config.identity}),
    )?))
}

fn identity_read_failure(failure: crate::protocol::ReadFailure) -> HostedIdentityOutcome {
    use crate::protocol::ReadFailure;
    match failure {
        ReadFailure::Timeout
        | ReadFailure::Connect
        | ReadFailure::Request
        | ReadFailure::BodyInterrupted => HostedIdentityOutcome::Unavailable,
        ReadFailure::ResponseTooLarge
        | ReadFailure::InvalidJson
        | ReadFailure::CredentialEchoRedacted => HostedIdentityOutcome::InvalidResponse,
    }
}

fn classify_hosted_identity(config: &Config, response: &Response) -> HostedIdentityOutcome {
    if matches!(response.status, 401 | 403) {
        return HostedIdentityOutcome::AuthenticationFailed;
    }
    if matches!(response.status, 408 | 429) || (500..600).contains(&response.status) {
        return HostedIdentityOutcome::Unavailable;
    }
    if let Some(failure) = response.read_failure {
        return identity_read_failure(failure);
    }
    if !(200..300).contains(&response.status)
        || ["ok", "success"].iter().any(|field| {
            response
                .body
                .get(field)
                .is_some_and(|value| value.as_bool() != Some(true))
        })
    {
        return HostedIdentityOutcome::InvalidResponse;
    }
    let Some(address) = response
        .body
        .get("address")
        .and_then(Value::as_str)
        .filter(|address| crate::config::valid_address(address))
    else {
        return HostedIdentityOutcome::InvalidResponse;
    };
    // The hosted API may omit chain_id; malformed values are not mismatch proof.
    let chain = match response.body.get("chain_id") {
        Some(value) => match value
            .as_str()
            .filter(|chain| crate::config::safe_segment(chain, 64))
        {
            Some(chain) => Some(chain),
            None => return HostedIdentityOutcome::InvalidResponse,
        },
        None => None,
    };
    if address != config.network.address || chain.is_some_and(|chain| chain != config.network.chain)
    {
        HostedIdentityOutcome::IdentityMismatch
    } else {
        HostedIdentityOutcome::Verified
    }
}
/// A single runtime owns the account lock even when paused or read-only. The
/// admission lock is separate so local control commands can close admission.
pub async fn run(config_path: &Path, once: bool) -> Result<()> {
    let config_guard = crate::admin::lock_config_directory(config_path)?;
    let config = Config::load(config_path)?;
    config.validate()?;
    let protocol = Arc::new(Protocol::new(&config).map_err(|_| {
        anyhow::anyhow!(
            "cannot initialize protocol client; check local identity and credential permissions"
        )
    })?);
    let (_account, mut store) = AccountLock::acquire(&config)?;
    drop(config_guard);
    {
        let _gate = AccountAdmissionGuard::acquire(&config)?;
        store.recover()?;
        store.runtime_state(&config, false)?;
    }
    let (stop_tx, stop) = watch::channel(false);
    let signal = tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop_tx.send(true);
    });
    let mut runtime = HostAccess::new(config_path.to_owned(), config, protocol, store, stop, true)?;
    let result = runtime.run_loop(once).await;
    signal.abort();
    result
}
#[cfg(test)]
use crate::runtime::judge::assignment_matches;
fn payload(request: &SolverRequest, result: &SolverResult) -> Result<Value> {
    match request.kind {
        LaneId::Answer => {
            let answer = result.answer.as_deref().context("missing model answer")?;
            let length = answer.encode_utf16().count();
            if length < request.min_chars || length > request.max_chars || answer.trim().is_empty()
            {
                bail!("answer outside challenge bounds");
            }
            if !has_required_words(answer, &request.words) {
                bail!("missing challenge word");
            }
            Ok(json!({"answer":answer}))
        }
        LaneId::Judge => {
            let score = result.score.context("missing judgment score")?;
            let reasoning = result
                .reasoning
                .as_deref()
                .context("missing judgment reasoning")?;
            if score > 3 || !valid_grade_reasoning(reasoning) {
                bail!("invalid judgment");
            }
            Ok(
                json!({"assignment":request.assignment.as_deref().context("missing assignment")?,"score":score,"reasoning":reasoning}),
            )
        }
        LaneId::Mine => Ok(json!({})),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Receipt {
    Final,
    Included,
    Rejected,
    Unresolved,
}
fn receipt(response: &Response, txid: &str, address: &str) -> Receipt {
    if response.status != 200
        || ["ok", "success"].iter().any(|field| {
            response
                .body
                .get(field)
                .is_some_and(|value| value.as_bool() != Some(true))
        })
    {
        return Receipt::Unresolved;
    }
    let body = &response.body;
    if body.get("txid").is_some_and(|value| {
        !value
            .as_str()
            .is_some_and(|id| id.eq_ignore_ascii_case(txid))
    }) || ["address", "sender"].iter().any(|field| {
        body.get(field)
            .is_some_and(|value| value.as_str() != Some(address))
    }) {
        return Receipt::Unresolved;
    }
    match body.get("status").and_then(Value::as_str) {
        Some("rejected")
            if body
                .get("next_nonce")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0) =>
        {
            Receipt::Rejected
        }
        Some("included")
            if body
                .get("next_nonce")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0) =>
        {
            if body.get("checkpoint_covered").and_then(Value::as_bool) == Some(true) {
                Receipt::Final
            } else if body.get("valid_in_open_window").and_then(Value::as_bool) == Some(true) {
                Receipt::Included
            } else {
                Receipt::Unresolved
            }
        }
        _ => Receipt::Unresolved,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
