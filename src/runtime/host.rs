use crate::capability::LaneId;
use crate::config::{Config, Mode};
use crate::endpoints::Endpoint;
use crate::protocol::{
    Assignment, Challenge, EffectDeadline, HostedIdentityBody, HostedResponse, Outcome, Protocol,
    ReadDeadline, RequestMeta, Response, ResponseSource, classify_source, has_required_words,
    parse_challenge, response_evidence, transport_failure, valid_grade_reasoning,
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
pub(super) use driver::FreshTarget;
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
    let _managed_control = crate::lifecycle::guard_managed_recovery_mutation(config_path)?;
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
        runtime.collect_identity()?;
        if runtime.identity.is_none() {
            break;
        }
        tokio::select! {
            _ = runtime.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            _ = tokio::signal::ctrl_c() => {
                if let Some(mut read) = runtime.identity.take() {
                    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
                    read.flight.abort(deadline).await;
                    if let Some(res) = read.flight.take() {
                        let _ = runtime.finish_read(&read.flight, res);
                    } else {
                        let _ = runtime.store.cancel_read(&read.flight.key);
                    }
                }
                bail!("recovery interrupted");
            }
        }
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
            tokio::select! {
                _ = runtime.wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                _ = tokio::signal::ctrl_c() => {
                    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
                    flight.abort(deadline).await;
                    if let Some(res) = flight.take() {
                        let _ = runtime.finish_read(&flight, res);
                    } else {
                        let _ = runtime.store.cancel_reconciliation_read(
                            &flight.key,
                            flight.authority_epoch,
                            flight.sequence,
                        );
                    }
                    bail!("recovery interrupted");
                }
            }
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

pub fn status(config_path: &Path, config: &Config) -> Result<Value> {
    let mut status = crate::health::local_status(config_path, config, now())?;
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
        Some(store) => store.operations_list(config, kind, state, before, limit),
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

pub(crate) fn restore_update_pause(
    config: &Config,
    database_id: &str,
    expected_generation: i64,
    expected_paused: bool,
    desired_paused: bool,
) -> Result<Value> {
    if !desired_paused {
        config.validate()?;
        if config.network.address.is_empty()
            || config.network.credential_file.as_os_str().is_empty()
        {
            bail!("resume requires a configured account and credential file");
        }
    }
    // Restoration requires existing anchored authority; unlike ordinary initial
    // control, this must never create a journal, account witness or admission gate.
    let gate = AccountAdmissionGuard::acquire(config)?;
    AccountLock::control_store(config, &gate)?.restore_update_pause(
        database_id,
        expected_generation,
        expected_paused,
        desired_paused,
        &gate,
    )
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

#[derive(Clone, PartialEq, Eq)]
pub(super) struct RuntimeStateKey {
    pub(super) revision: String,
    pub(super) reload_blocked: bool,
    pub(super) once: bool,
    pub(super) account_generation: i64,
    pub(super) authority_epoch: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AdmissionObservationKey {
    pub(super) stamp: crate::store::AdmissionStampSnapshot,
    pub(super) state: &'static str,
    pub(super) reasons: Vec<&'static str>,
    pub(super) valid_until: Option<i64>,
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
    lanes: NativeLanes,
    recovery: Vec<Recovery>,
    reconciliation_pass: crate::store::ReconciliationPass,
    identity: Option<IdentityRead>,
    permit: Option<IdentityPermit>,
    effect: Option<EffectInFlight>,
    once: Option<OncePlan>,
    identity_nonblocking: bool,
    last_runtime_state: Option<(RuntimeStateKey, Instant)>,
    last_admission_observations: [Option<(AdmissionObservationKey, Instant)>; LaneId::COUNT],
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
        | ReadFailure::CredentialEchoRedacted
        | ReadFailure::BoundJobExpiryConflict => HostedIdentityOutcome::InvalidResponse,
    }
}

fn classify_hosted_identity(config: &Config, response: &Response) -> HostedIdentityOutcome {
    // Either HTTP refusal still fences effects, independently of the
    // distinction between authentication and permission in read diagnostics.
    if matches!(response.status, 401 | 403) {
        return HostedIdentityOutcome::AuthenticationFailed;
    }
    if matches!(response.status, 408 | 429) || (500..600).contains(&response.status) {
        return HostedIdentityOutcome::Unavailable;
    }
    if let Some(failure) = response.read_failure {
        return identity_read_failure(failure);
    }
    if !(200..300).contains(&response.status) {
        return HostedIdentityOutcome::InvalidResponse;
    }
    match response.hosted_identity_body(Some(&config.network.address), &config.network.chain) {
        HostedIdentityBody::Verified(_) => HostedIdentityOutcome::Verified,
        HostedIdentityBody::Invalid => HostedIdentityOutcome::InvalidResponse,
        HostedIdentityBody::Mismatch => HostedIdentityOutcome::IdentityMismatch,
    }
}
/// A single runtime owns the account lock even when paused or read-only. The
/// admission lock is separate so local control commands can close admission.
pub async fn run(config_path: &Path, once: bool) -> Result<()> {
    crate::lifecycle::guard_managed_run(config_path)?;
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
        store.runtime_state_with_mode(&config, false, once)?;
    }
    let (stop_tx, stop) = watch::channel(false);
    let mut runtime = HostAccess::new(config_path.to_owned(), config, protocol, store, stop, true)?;
    let signal_stop = stop_tx.clone();
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
        let _ = signal_stop.send(true);
    });
    let advisory = if !once && crate::update::advisory::background_policy()["enabled"] == true {
        Some(tokio::spawn(crate::update::advisory::run(
            config_path.to_owned(),
            runtime.stop.clone(),
        )))
    } else {
        None
    };
    let result = runtime.run_loop(once).await;
    // Signals already stop advisory HTTP alongside effect draining. Internal
    // exits must also stop it, then allow only local leased finalization.
    let _ = stop_tx.send(true);
    if let Some(task) = advisory {
        crate::update::advisory::finish_background(task).await;
    }
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
pub(in crate::runtime) mod tests;
