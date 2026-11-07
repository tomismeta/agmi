use crate::config::{Config, Mode, Participation, ParticipationMode, WorkKind};
use crate::protocol::{
    Assignment, Challenge, Outcome, Protocol, ReadFailure, Response, ResponseSource,
    assignment_ids, assignment_needs_hydration, classify_source, has_required_words,
    parse_challenge, parse_selected_assignment, response_evidence, transport_failure,
    valid_grade_reasoning,
};
use crate::solver::{
    SolverRequest, SolverResult, completed_artifact_invalid, execution_may_have_started,
    failure_code, solve,
};
use crate::store::{
    AccountLock, AdmissionGuard, Control, Operation, ReadScope, Store, digest, not_before, now,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, oneshot, watch};

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
    store.recover()
}

pub fn recovery_authorize(config: &Config, epoch: u64, kind: WorkKind) -> Result<Value> {
    Store::read_only(config)?.context("journal not initialized")?;
    let (_account, mut store) = AccountLock::acquire(config)?;
    let _gate = AdmissionGuard::acquire(config)?;
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
    store.recover()?;
    let mut op = store.operation(operation)?.context("operation not found")?;
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
    let mut runtime = Runtime {
        config_path: config_path.to_owned(),
        config,
        protocol,
        store,
        stop,
        reload_blocked: false,
        preparations: Vec::new(),
        controller: false,
        model_wake: Arc::new(Notify::new()),
        urgent_context: false,
    };
    if !runtime.identity_matches(op.kind).await? {
        bail!("recovery identity unverified");
    }
    runtime.reconcile(&mut op).await?;
    if op.state == "included_pending" {
        runtime.reconcile(&mut op).await?;
    }
    let resolved = !matches!(
        op.state.as_str(),
        "unknown" | "queued" | "included_pending" | "dispatching"
    );
    Ok(
        json!({"operation_id":op.id,"state":op.state,"resolved":resolved,
        "network_requests_reset":false,"evidence":"authenticated_bound_request",
        "finality":"node_reported_only"}),
    )
}
pub fn status(config: &Config) -> Result<Value> {
    match Store::read_only(config)? {
        Some(store) => store.status(config),
        None => Ok(json!({"initialized":false,"paused":true,"generation":0,
            "configured_revision":config.optional_revision()?,"effective_runtime":null,
            "hosted_identity_verified":null,"pending":null,"operations":[],
            "reads":[],"work":{},
            "participation":{"policy":Participation::default(),"policy_source":"unavailable",
                "unresolved_count":0,"risk_admissions":0,
                "uncertainty_blocks":{"answer":false,"judge":false,"mine":false}}})),
    }
}

/// Local metadata only: never initializes a journal or contacts the network.
pub fn reads(config: &Config) -> Result<Value> {
    match Store::read_only(config)? {
        Some(store) => store.reads(),
        None => Ok(json!([])),
    }
}

pub fn operations_list(
    config: &Config,
    kind: Option<WorkKind>,
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
    let _gate = AdmissionGuard::acquire(config)?;
    store.revoke_grant(grant_id)
}
pub fn events(config: &Config, limit: usize) -> Result<Value> {
    match Store::read_only(config)? {
        Some(store) => store.events(limit),
        None => Ok(json!([])),
    }
}
pub fn pause(config: &Config) -> Result<()> {
    let _gate = AdmissionGuard::acquire(config)?;
    AccountLock::control_store(config)?.set_paused(true)
}
pub fn resume(config: &Config) -> Result<()> {
    config.validate()?;
    if config.network.address.is_empty() || config.network.credential_file.as_os_str().is_empty() {
        bail!("resume requires a configured account and credential file");
    }
    let _gate = AdmissionGuard::acquire(config)?;
    AccountLock::control_store(config)?.set_paused(false)
}

/// Explicitly release model-only uncertainty while the writer is stopped.
/// A possibly-sent protocol request is never eligible.
pub fn recover_model(config: &Config) -> Result<usize> {
    let (_account, mut store) = AccountLock::acquire(config)?;
    store.recover()?;
    store.abandon_models()
}

fn same_identity(a: &Config, b: &Config) -> bool {
    a.network.base_url == b.network.base_url
        && a.network.chain == b.network.chain
        && a.network.address == b.network.address
        && a.network.credential_file == b.network.credential_file
        && a.state_dir == b.state_dir
}

fn stagger(config: &Config, phase: &str) -> u64 {
    let bound = config.schedule.jitter_seconds;
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

#[derive(Serialize, Deserialize)]
struct Input {
    solver: SolverRequest,
    challenge_fingerprint: Option<String>,
}

enum ModelAttempt {
    Captured(SolverResult),
    NotStarted(&'static str),
    Invalid(&'static str),
    Unknown(&'static str),
}

/// A bounded HTTP task owns only its request/result, never journal state.
/// Dropping a controller read also cancels its still-running transport.
struct ReadTaskGuard(tokio::task::AbortHandle);
impl Drop for ReadTaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Preparation {
    operation: Operation,
    input: Arc<Input>,
    control: Control,
    task: tokio::task::JoinHandle<()>,
    completion: oneshot::Receiver<ModelAttempt>,
}

struct Inventory {
    response: Response,
    // Earlier usable pages cannot supersede a later page's failure or delay.
    pages_usable: bool,
}

struct Runtime {
    config_path: PathBuf,
    config: Config,
    protocol: Arc<Protocol>,
    store: Store,
    stop: watch::Receiver<bool>,
    reload_blocked: bool,
    controller: bool,
    model_wake: Arc<Notify>,
    urgent_context: bool,
    preparations: Vec<Preparation>,
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
    store.recover()?;
    store.runtime_state(&config, false)?;
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
    let mut runtime = Runtime {
        config_path: config_path.to_path_buf(),
        config,
        protocol,
        store,
        stop,
        reload_blocked: false,
        preparations: Vec::new(),
        controller: true,
        model_wake: Arc::new(Notify::new()),
        urgent_context: false,
    };
    let result = runtime.run_loop(once).await;
    signal.abort();
    result
}

impl Runtime {
    fn stopping(&self) -> bool {
        *self.stop.borrow()
    }

    fn heartbeat(&self) -> Result<()> {
        // Stopped-writer recovery reads must not impersonate a live controller.
        if self.controller {
            self.store.heartbeat()?;
        }
        Ok(())
    }

    fn reload(&mut self) -> Result<()> {
        if !self.controller {
            return Ok(());
        }
        let was_blocked = self.reload_blocked;
        let mut changed = false;
        let candidate = Config::load(&self.config_path).and_then(|config| {
            config.validate()?;
            Ok(config)
        });
        let update = match candidate {
            Ok(config) if same_identity(&self.config, &config) => {
                if config.revision()? == self.config.revision()? {
                    Some((config, None))
                } else {
                    Protocol::new(&config)
                        .ok()
                        .map(|protocol| (config, Some(Arc::new(protocol))))
                }
            }
            _ => None,
        };
        match update {
            Some((config, protocol)) => {
                if let Some(protocol) = protocol {
                    self.config = config;
                    self.protocol = protocol;
                    changed = true;
                    self.store.event("config_reloaded", None)?;
                }
                if self.reload_blocked {
                    self.store.event("config_reload_recovered", None)?;
                }
                self.reload_blocked = false;
            }
            None => {
                if !self.reload_blocked {
                    self.store.event("config_reload_rejected", None)?;
                }
                self.reload_blocked = true;
            }
        }
        if changed || was_blocked != self.reload_blocked {
            self.store
                .runtime_state(&self.config, self.reload_blocked)?;
            let (base, cap) = self.read_policy(ReadScope::Challenge);
            self.store.reschedule_read(
                ReadScope::Challenge,
                base,
                cap,
                stagger(&self.config, "retry"),
            )?;
        }
        Ok(())
    }

    fn poll_delay(&self) -> u64 {
        self.config
            .schedule
            .poll_seconds
            .saturating_add(stagger(&self.config, "poll"))
    }

    fn retry_delay(&self, server_minimum: Option<u64>) -> u64 {
        self.config
            .schedule
            .retry_seconds
            .max(server_minimum.unwrap_or(0))
            .saturating_add(stagger(&self.config, "retry"))
    }

    fn read_policy(&self, scope: ReadScope) -> (u64, u64) {
        let schedule = &self.config.schedule;
        if scope == ReadScope::Challenge {
            (
                schedule
                    .challenge_retry_seconds
                    .unwrap_or(schedule.retry_seconds),
                schedule
                    .challenge_backoff_max_seconds
                    .unwrap_or(schedule.backoff_max_seconds),
            )
        } else {
            (schedule.retry_seconds, schedule.backoff_max_seconds)
        }
    }

    fn urgent_delay(&self) -> Result<Duration> {
        if self.config.mode(WorkKind::Answer) == Mode::Off {
            return Ok(Duration::from_secs(self.poll_delay()));
        }
        let deadline = self
            .store
            .next_at(WorkKind::Answer)?
            .max(self.store.read_backoff(ReadScope::Challenge)?.next_at);
        Ok(Duration::from_secs(
            deadline.saturating_sub(now()).max(0) as u64
        ))
    }
    async fn wait_delay(&mut self, seconds: u64) {
        if seconds == 0 || self.stopping() {
            return;
        }
        // No admission gate is held: pause remains immediately available.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(seconds)) => {},
            _ = self.stop.changed() => {},
            _ = self.model_wake.notified() => {},
        }
    }

    async fn run_loop(&mut self, once: bool) -> Result<()> {
        let (base, cap) = self.read_policy(ReadScope::Challenge);
        self.store.reschedule_read(
            ReadScope::Challenge,
            base,
            cap,
            stagger(&self.config, "retry"),
        )?;
        if !once {
            self.wait_delay(stagger(&self.config, "startup")).await;
        }
        loop {
            self.store.continuity()?;
            self.reload()?;
            self.store
                .runtime_state(&self.config, self.reload_blocked)?;
            if self.stopping() {
                break;
            }
            let before = self.store.work_revision()?;
            self.cycle().await?;
            if once {
                while !self.preparations.is_empty() && !self.stopping() {
                    self.wait_delay(self.poll_delay()).await;
                    self.reload()?;
                    self.collect_models().await?;
                    self.store
                        .runtime_state(&self.config, self.reload_blocked)?;
                    self.observe_enabled().await?;
                }
                for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
                    if let Some(mut op) = self.store.preparation(kind)?
                        && op.state != "generating"
                    {
                        self.dispatch(&mut op).await?;
                    }
                }
            }
            if once || self.stopping() {
                break;
            }
            if self.store.work_revision()? == before {
                let delay = self.store.wake_delay(&self.config, self.poll_delay())?;
                self.wait_delay(delay).await;
            }
        }
        // Give already-ready solver results priority over cancellation, then
        // retain their artifacts without granting permission to dispatch.
        let shutdown =
            tokio::time::sleep(Duration::from_secs(self.config.timeouts.shutdown_seconds));
        tokio::pin!(shutdown);
        loop {
            self.collect_models().await?;
            if self.preparations.is_empty() {
                break;
            }
            tokio::select! {
                _ = self.model_wake.notified() => {},
                _ = &mut shutdown => break,
            }
        }
        for preparation in &self.preparations {
            preparation.task.abort();
        }
        for preparation in &mut self.preparations {
            let _ = (&mut preparation.task).await;
        }
        // A result sent just as the shutdown deadline fired still belongs in
        // the journal. Joining closes only genuinely unfinished result channels.
        self.collect_models().await?;
        self.store.event("runtime_stopped", None)?;
        Ok(())
    }

    async fn get(
        &mut self,
        kind: WorkKind,
        scope: ReadScope,
        path: &str,
    ) -> Result<Option<Response>> {
        self.get_page(kind, scope, path, None).await
    }

    async fn get_page(
        &mut self,
        kind: WorkKind,
        scope: ReadScope,
        path: &str,
        offset: Option<u64>,
    ) -> Result<Option<Response>> {
        self.reload()?;
        if self.stopping()
            || (self.config.mode(kind) == Mode::Off
                && !matches!(
                    scope,
                    ReadScope::Job | ReadScope::Receipt | ReadScope::Identity
                ))
        {
            return Ok(None);
        }
        let backoff = self.store.read_backoff(scope)?;
        if backoff.next_at > now() {
            return Ok(None);
        }
        self.heartbeat()?;
        self.store.read_started(scope)?;
        let protocol = Arc::clone(&self.protocol);
        // Reqwest bounds the complete read, including its body. An equal outer
        // timeout would race that result and lose already-received Retry-After.
        let path = path.to_owned();
        let mut request = tokio::spawn(async move {
            if let Some(offset) = offset {
                protocol.assignment_page(offset, 100).await
            } else {
                protocol.get(&path).await
            }
        });
        let _request_guard = ReadTaskGuard(request.abort_handle());
        // Exactly one retained background request. Nested urgent reads use
        // their own lane, never a generic slot occupied by this request.
        let background = self.controller
            && !self.urgent_context
            && !matches!(scope, ReadScope::Challenge | ReadScope::Identity);
        let result = loop {
            if self.stopping() {
                self.store.read_finished(scope, None, None)?;
                return Ok(None);
            }
            let urgent_delay = if background {
                self.urgent_delay()?
            } else {
                Duration::from_secs(self.poll_delay())
            };
            let wake = Arc::clone(&self.model_wake);
            tokio::select! {
                biased;
                result = &mut request => break result,
                _ = self.stop.changed() => {
                    self.store.read_finished(scope, None, None)?;
                    return Ok(None);
                },
                _ = wake.notified() => {
                    self.collect_models().await?;
                    if background { Box::pin(self.service_urgent(true)).await?; }
                },
                _ = tokio::time::sleep(urgent_delay), if background => {
                    Box::pin(self.service_urgent(true)).await?;
                },
            }
        };
        match result {
            Ok(Ok(response)) => {
                self.store.read_finished(
                    scope,
                    Some(response.status),
                    response.read_failure.map(ReadFailure::as_str),
                )?;
                // The documented 408 job-expired result is authoritative, not
                // a transport timeout. Preserve its existing bound-job retry rule.
                let expired_job = response.status == 408
                    && matches!(scope, ReadScope::Job)
                    && matches!(
                        classify_source(kind, &response, ResponseSource::BoundJob),
                        Outcome::Expired
                    );
                if (response.status == 408 && !expired_job)
                    || response.status == 429
                    || (500..600).contains(&response.status)
                    || response.body.is_null()
                {
                    self.store.read_finished(
                        scope,
                        Some(response.status),
                        Some(
                            response
                                .read_failure
                                .map(ReadFailure::as_str)
                                .unwrap_or("http_status"),
                        ),
                    )?;
                    self.read_failed(scope, response.retry_after_seconds)?;
                    if let Some(minimum) = response.retry_after_seconds {
                        self.store.record_scope_retry_minimum(scope, minimum)?;
                    }
                    self.store.event("read_backoff", Some(kind))?;
                    return Ok(None);
                }
                Ok(Some(response))
            }
            failure => {
                let category = match failure {
                    Ok(Err(error)) => transport_failure(&error),
                    Err(_) => ReadFailure::Request,
                    Ok(Ok(_)) => unreachable!(),
                };
                self.store
                    .read_finished(scope, None, Some(category.as_str()))?;
                self.read_failed(scope, None)?;
                self.store.event("upstream_read_failed", Some(kind))?;
                Ok(None)
            }
        }
    }

    fn read_failed(&self, scope: ReadScope, server_minimum: Option<u64>) -> Result<()> {
        let (base, cap) = self.read_policy(scope);
        self.store.fail_read(
            scope,
            base,
            cap,
            stagger(&self.config, "retry"),
            server_minimum,
        )?;
        if scope == ReadScope::Challenge {
            let deadline = self.store.read_backoff(scope)?.next_at;
            self.store.defer_until(WorkKind::Answer, deadline)?;
        }
        Ok(())
    }

    fn read_evaluated(&self, scope: ReadScope, valid: bool, minimum: Option<u64>) -> Result<()> {
        if valid {
            self.store.reset_read(scope)
        } else {
            self.read_failed(scope, minimum)
        }
    }

    async fn challenge(&mut self, kind: WorkKind) -> Result<Option<Challenge>> {
        let Some(response) = self
            .get(kind, ReadScope::Challenge, "/api/hosted/challenge")
            .await?
        else {
            return Ok(None);
        };
        match parse_challenge(&response) {
            Ok(challenge) => {
                self.read_evaluated(ReadScope::Challenge, true, None)?;
                self.store.observe(challenge.epoch, challenge.answered)?;
                Ok(Some(challenge))
            }
            Err(_) => {
                self.read_failed(ReadScope::Challenge, response.retry_after_seconds)?;
                self.store.event("challenge_unavailable", Some(kind))?;
                Ok(None)
            }
        }
    }

    async fn assignment_inventory(&mut self) -> Result<Option<Inventory>> {
        let Some(mut response) = self
            .get(
                WorkKind::Judge,
                ReadScope::Assignments,
                "/api/hosted/assignments",
            )
            .await?
        else {
            return Ok(None);
        };
        let ids = assignment_ids(&response);
        if ids.is_err() {
            self.read_evaluated(ReadScope::Assignments, false, response.retry_after_seconds)?;
            self.store
                .event("assignments_unavailable", Some(WorkKind::Judge))?;
            self.store.defer(
                WorkKind::Judge,
                self.retry_delay(response.retry_after_seconds),
            )?;
            return Ok(None);
        }
        let mut seen: std::collections::HashSet<String> =
            ids.as_ref().unwrap().iter().cloned().collect();
        let mut offset = response.body["assignments"].as_array().map_or(0, Vec::len) as u64;
        let mut rows = response.body["assignments"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut complete = response.body["has_more"].as_bool() == Some(false);
        let mut pages_usable = true;
        // Offset inventories can move between pages: bounded deduplication is
        // useful selection evidence, never proof that an absent sent request failed.
        for _ in 1..4 {
            if response.body["has_more"].as_bool() != Some(true) || offset == 0 {
                break;
            }
            let Some(page) = self
                .get_page(
                    WorkKind::Judge,
                    ReadScope::Assignments,
                    "/api/hosted/assignments",
                    Some(offset),
                )
                .await?
            else {
                pages_usable = false;
                break;
            };
            let Ok(page_ids) = assignment_ids(&page) else {
                pages_usable = false;
                self.read_evaluated(ReadScope::Assignments, false, page.retry_after_seconds)?;
                break;
            };
            let page_rows = page.body["assignments"]
                .as_array()
                .context("assignment rows missing")?;
            let prior_len = rows.len();
            for (id, row) in page_ids.into_iter().zip(page_rows) {
                if seen.insert(id) {
                    rows.push(row.clone());
                }
            }
            offset += page_rows.len() as u64;
            complete = page.body["has_more"].as_bool() == Some(false);
            response.body["has_more"] = page.body["has_more"].clone();
            if complete || rows.len() == prior_len {
                break;
            }
        }
        response.body["assignments"] = json!(rows);
        response.body["has_more"] = json!(!complete);
        // Active selection validates the selected payload before clearing this scope.
        if pages_usable
            && (ids.as_ref().is_ok_and(|ids| ids.is_empty())
                || self.config.mode(WorkKind::Judge) == Mode::ReadOnly)
        {
            self.read_evaluated(ReadScope::Assignments, true, None)?;
        }
        if response.body.get("has_more") == Some(&Value::Bool(true)) {
            self.store
                .event("assignment_inventory_partial", Some(WorkKind::Judge))?;
        }
        Ok(Some(Inventory {
            response,
            pages_usable,
        }))
    }

    fn next_judging_assignment(&self, inventory: &Response) -> Result<Option<String>> {
        let ids = assignment_ids(inventory)?;
        let rows = inventory.body["assignments"]
            .as_array()
            .context("assignment rows missing")?;
        let mut ranked: Vec<_> = ids
            .into_iter()
            .zip(rows)
            .filter_map(|(id, row)| {
                (!self.config.judging_assignment_excluded(&id)).then(|| {
                    (
                        row["pending_meta"]["expires_at_epoch"]
                            .as_u64()
                            .unwrap_or(u64::MAX),
                        id,
                    )
                })
            })
            .collect();
        ranked.sort_unstable();
        for (_, id) in ranked {
            if !self.store.attempted(WorkKind::Judge, &id)?
                && self.store.model_budget_used(WorkKind::Judge, &id)?
                    < self.config.preparation.max_attempts_per_work
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    async fn assignment(&mut self, snapshot: &Inventory, id: &str) -> Result<Option<Assignment>> {
        let inventory = &snapshot.response;
        self.reload()?;
        if self.stopping() || self.config.mode(WorkKind::Judge) == Mode::Off {
            return Ok(None);
        }
        let hydrated = match assignment_needs_hydration(inventory, id) {
            Ok(true) => {
                let Some(response) = self
                    .get(
                        WorkKind::Judge,
                        ReadScope::AssignmentEvidence,
                        &format!("/api/explorer/tx/{id}"),
                    )
                    .await?
                else {
                    return Ok(None);
                };
                Some(response)
            }
            Ok(false) => None,
            Err(_) => {
                if snapshot.pages_usable {
                    self.read_evaluated(
                        ReadScope::Assignments,
                        false,
                        inventory.retry_after_seconds,
                    )?;
                }
                self.store
                    .event("assignment_evidence_unavailable", Some(WorkKind::Judge))?;
                self.store.defer(
                    WorkKind::Judge,
                    self.retry_delay(inventory.retry_after_seconds),
                )?;
                return Ok(None);
            }
        };
        let minimum = hydrated
            .as_ref()
            .and_then(|r| r.retry_after_seconds)
            .max(inventory.retry_after_seconds);
        let scope = if hydrated.is_some() {
            ReadScope::AssignmentEvidence
        } else {
            ReadScope::Assignments
        };
        match parse_selected_assignment(inventory, id, hydrated.as_ref()) {
            Ok(assignment) => {
                if hydrated.is_some() {
                    self.read_evaluated(ReadScope::AssignmentEvidence, true, None)?;
                }
                if snapshot.pages_usable {
                    self.read_evaluated(ReadScope::Assignments, true, None)?;
                }
                Ok(Some(assignment))
            }
            Err(_) => {
                if scope != ReadScope::Assignments || snapshot.pages_usable {
                    self.read_evaluated(scope, false, minimum)?;
                }
                self.store
                    .event("assignment_evidence_unavailable", Some(WorkKind::Judge))?;
                self.store
                    .defer(WorkKind::Judge, self.retry_delay(minimum))?;
                if self.active(WorkKind::Judge)?
                    && self.store.preparation(WorkKind::Judge)?.is_none()
                    && !self.store.attempted(WorkKind::Judge, id)?
                {
                    let _gate = AdmissionGuard::acquire(&self.config)?;
                    let control = self.store.control()?;
                    if !control.paused {
                        let mut skipped = self.store.begin(WorkKind::Judge,id,"prepared",
                            &json!({"assignment":id,"local_abstention":"required_evidence_unavailable"}),
                            control,&self.config.revision()?)?;
                        skipped.state = "abstained".into();
                        self.store
                            .save(&skipped, "assignment_evidence_insufficient")?;
                    }
                }
                Ok(None)
            }
        }
    }

    async fn identity_matches(&mut self, kind: WorkKind) -> Result<bool> {
        let Some(response) = self
            .get(kind, ReadScope::Identity, "/api/hosted/me")
            .await?
        else {
            self.store.record_hosted_identity(false)?;
            return Ok(false);
        };
        let matched = (200..300).contains(&response.status)
            && ["ok", "success"].iter().all(|field| {
                response
                    .body
                    .get(field)
                    .is_none_or(|value| value.as_bool() == Some(true))
            })
            && response
                .body
                .get("address")
                .and_then(Value::as_str)
                .is_some_and(|address| address == self.config.network.address)
            && response
                .body
                .get("chain_id")
                .is_none_or(|chain| chain.as_str() == Some(self.config.network.chain.as_str()));
        self.store.record_hosted_identity(matched)?;
        self.read_evaluated(ReadScope::Identity, matched, response.retry_after_seconds)?;
        if !matched {
            self.store.event("identity_unverified", Some(kind))?;
            self.store
                .defer(kind, self.retry_delay(response.retry_after_seconds))?;
        }
        Ok(matched)
    }

    fn active(&self, kind: WorkKind) -> Result<bool> {
        Ok(self.controller
            && !self.stopping()
            && !self.reload_blocked
            && self.config.mode(kind) == Mode::Active
            && !self.store.control()?.paused)
    }

    async fn advance_preparation(&mut self, kind: WorkKind) -> Result<()> {
        let Some(mut op) = self.store.preparation(kind)? else {
            return Ok(());
        };
        if op.state == "generating" || self.discard_excluded_judgment(&mut op)? {
            return Ok(());
        }
        if self.config.mode(kind) == Mode::Off || op.generation != self.store.control()?.generation
        {
            op.state = "discarded".into();
            self.store.save(&op, "unsent_admission_closed")?;
        } else if !self.store.admission_allowed(&self.config, &op)? {
            if matches!(kind, WorkKind::Answer | WorkKind::Mine)
                && self.store.next_at(kind)? <= now()
            {
                let input: Input = serde_json::from_value(op.request.clone())?;
                if self.fresh(&op, &input).await? == Some(false) {
                    op.state = "discarded".into();
                    self.store.save(&op, "request_no_longer_current")?;
                }
            }
        } else if self.active(kind)? {
            self.dispatch(&mut op).await?;
        }
        Ok(())
    }

    async fn service_urgent(&mut self, admission_available: bool) -> Result<()> {
        let previous = self.urgent_context;
        self.urgent_context = true;
        let result = self.answer_work(admission_available).await;
        self.urgent_context = previous;
        result
    }

    async fn answer_work(&mut self, admission_available: bool) -> Result<()> {
        self.reload()?;
        self.collect_models().await?;
        let kind = WorkKind::Answer;
        if self.stopping() {
            return Ok(());
        }
        // An effect holds the admission guard. Never reacquire it, even
        // synchronously for an otherwise eligible local model launch.
        if admission_available {
            self.advance_preparation(kind).await?;
        }
        if self.config.mode(kind) == Mode::Off || self.store.next_at(kind)? > now() {
            return Ok(());
        }
        self.store.defer(kind, self.poll_delay())?;
        let Some(challenge) = self.challenge(kind).await? else {
            return Ok(());
        };
        if !admission_available
            || self.store.preparation(kind)?.is_some()
            || challenge.answered
            || !self.active(kind)?
        {
            return Ok(());
        }
        let key = format!("{}:{}", challenge.epoch, challenge.fingerprint);
        let retry = if self.store.answer_epoch_attempted(challenge.epoch)? {
            let Some(original) = self.store.uncertain_answer(challenge.epoch)? else {
                return Ok(());
            };
            if !self.store.answer_retry_allowed(&self.config, &original)? {
                return Ok(());
            }
            Some(original)
        } else {
            None
        };
        if !self.identity_matches(kind).await? {
            return Ok(());
        }
        let input = Input {
            solver: self.request(kind, &challenge, None)?,
            challenge_fingerprint: Some(challenge.fingerprint),
        };
        if let Some(original) = retry {
            if original.key == key {
                let gate = AdmissionGuard::acquire(&self.config)?;
                self.reload()?;
                if !self.active(kind)?
                    || !self.store.answer_retry_allowed(&self.config, &original)?
                {
                    return Ok(());
                }
                let mut op = self.store.begin_linked(
                    kind,
                    &key,
                    ("prepared", &original.request),
                    self.store.control()?,
                    &self.config.revision()?,
                    Some((&original, true)),
                )?;
                drop(gate);
                self.dispatch(&mut op).await?;
            } else {
                self.generate_linked(kind, &key, input, Some(&original))
                    .await?;
            }
        } else {
            self.generate(kind, &key, input).await?;
        }
        Ok(())
    }

    async fn cycle(&mut self) -> Result<()> {
        self.collect_models().await?;
        self.store.retry_models(&self.config)?;
        let before_answer = self.store.work_revision()?;
        self.service_urgent(true).await?;
        if self.store.work_revision()? != before_answer {
            return Ok(());
        }
        for mut op in self.store.reconciliation_batch()? {
            self.reconcile(&mut op).await?;
        }
        for kind in [WorkKind::Judge, WorkKind::Mine] {
            self.advance_preparation(kind).await?;
        }
        self.follow_finality().await?;
        // Answer always goes first. Older eligible lower-priority work wins;
        // judge wins stable ties, but its poll deferral gives overdue mining a turn.
        let judge_at = self.store.next_at(WorkKind::Judge)?;
        let mine_at = self.store.next_at(WorkKind::Mine)?;
        let lower = if mine_at < judge_at {
            [WorkKind::Mine, WorkKind::Judge]
        } else {
            [WorkKind::Judge, WorkKind::Mine]
        };
        for kind in lower {
            if self.stopping() {
                break;
            }
            if self.config.mode(kind) == Mode::Off
                || (self.store.next_at(kind)? > now()
                    && !(kind == WorkKind::Mine && self.config.schedule.mine_each_epoch))
            {
                continue;
            }
            self.store.defer(kind, self.poll_delay())?;
            if self.store.preparation(kind)?.is_some() {
                continue;
            }
            if self.store.effect()?.is_some()
                && (self.config.participation.mode == ParticipationMode::Strict
                    || !self.config.participation.allows(kind))
                && (kind != WorkKind::Answer || !self.config.preparation.answer_while_blocked)
            {
                if kind == WorkKind::Judge {
                    let _ = self.assignment_inventory().await?;
                }
                continue;
            }
            match kind {
                WorkKind::Answer => unreachable!("answer uses the urgent lane"),
                WorkKind::Judge => {
                    let Some(inventory) = self.assignment_inventory().await? else {
                        continue;
                    };
                    if !self.active(kind)? {
                        continue;
                    }
                    let Some(key) = self.next_judging_assignment(&inventory.response)? else {
                        continue;
                    };
                    let Some(assignment) = self.assignment(&inventory, &key).await? else {
                        continue;
                    };
                    if !self.identity_matches(kind).await? {
                        continue;
                    }
                    let request = SolverRequest {
                        id: self.request_id(kind, &key)?,
                        kind,
                        epoch: assignment.epoch,
                        words: assignment.words,
                        min_chars: 0,
                        max_chars: 0,
                        assignment: Some(assignment.id),
                        candidate: Some(assignment.answer),
                        history: Vec::new(),
                        guidance: String::new(),
                        author_history: Some(assignment.author_prior),
                        candidate_author: assignment.author,
                    };
                    self.generate(
                        kind,
                        &key,
                        Input {
                            solver: request,
                            challenge_fingerprint: None,
                        },
                    )
                    .await?;
                    return Ok(());
                }
                WorkKind::Mine => {
                    let Some(challenge) = self.challenge(kind).await? else {
                        continue;
                    };
                    if !self.active(kind)?
                        || (self.config.schedule.mine_each_epoch
                            && self.store.mine_epoch_attempted(challenge.epoch)?)
                        || !self.identity_matches(kind).await?
                    {
                        continue;
                    }
                    let key = format!("{}:{}", challenge.epoch, now());
                    let input = Input {
                        solver: self.request(kind, &challenge, None)?,
                        challenge_fingerprint: Some(challenge.fingerprint),
                    };
                    self.reload()?;
                    if !self.active(kind)? {
                        continue;
                    }
                    let gate = AdmissionGuard::acquire(&self.config)?;
                    let control = self.store.control()?;
                    if control.paused {
                        continue;
                    }
                    let mut op = self.store.begin(
                        kind,
                        &key,
                        "prepared",
                        &serde_json::to_value(input)?,
                        control,
                        &self.config.revision()?,
                    )?;
                    if !self.config.schedule.mine_each_epoch {
                        self.store.defer(kind, self.config.schedule.mine_seconds)?;
                    }
                    drop(gate);
                    self.dispatch(&mut op).await?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn observe_enabled(&mut self) -> Result<()> {
        for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
            if self.stopping()
                || self.config.mode(kind) == Mode::Off
                || self.store.next_at(kind)? > now()
            {
                continue;
            }
            self.store.defer(kind, self.poll_delay())?;
            match kind {
                WorkKind::Judge => {
                    let _ = self.assignment_inventory().await?;
                }
                _ => {
                    let _ = self.challenge(kind).await?;
                }
            }
        }
        Ok(())
    }

    async fn follow_finality(&mut self) -> Result<()> {
        for kind in [WorkKind::Answer, WorkKind::Judge] {
            if self.stopping() {
                continue;
            }
            if let Some(mut op) = self.store.awaiting_finality(kind)? {
                self.reconcile(&mut op).await?;
            }
        }
        Ok(())
    }

    fn request_id(&self, kind: WorkKind, key: &str) -> Result<String> {
        Ok(digest(format!(
            "{}\n{}\n{}\n{}\n{}",
            self.config.network.chain,
            self.config.network.address,
            kind.as_str(),
            key,
            self.store.control()?.generation
        )))
    }
    fn request(
        &self,
        kind: WorkKind,
        challenge: &Challenge,
        candidate: Option<String>,
    ) -> Result<SolverRequest> {
        Ok(SolverRequest {
            id: self.request_id(kind, &challenge.fingerprint)?,
            kind,
            epoch: challenge.epoch,
            words: challenge.words.clone(),
            min_chars: challenge.min_chars,
            max_chars: challenge.max_chars,
            assignment: None,
            candidate,
            history: self.store.history()?,
            guidance: String::new(),
            author_history: None,
            candidate_author: None,
        })
    }

    async fn generate(&mut self, kind: WorkKind, key: &str, input: Input) -> Result<()> {
        self.generate_linked(kind, key, input, None).await
    }

    async fn generate_linked(
        &mut self,
        kind: WorkKind,
        key: &str,
        mut input: Input,
        retry: Option<&Operation>,
    ) -> Result<()> {
        self.reload()?;
        if !self.active(kind)?
            || self.store.preparation(kind)?.is_some()
            || (retry.is_none() && self.store.attempted(kind, key)?)
            || (kind == WorkKind::Judge && self.config.judging_assignment_excluded(key))
        {
            return Ok(());
        }
        if self.store.effect()?.is_some()
            && (self.config.participation.mode == ParticipationMode::Strict
                || !self.config.participation.allows(kind))
            && (kind != WorkKind::Answer || !self.config.preparation.answer_while_blocked)
        {
            return Ok(());
        }
        if let Some(original) = retry
            && !self.store.answer_retry_allowed(&self.config, original)?
        {
            return Ok(());
        }
        let count = self.store.attempt_count(kind, key)?;
        if self.store.model_budget_used(kind, key)? >= self.config.preparation.max_attempts_per_work
        {
            return Ok(());
        }
        let gate = AdmissionGuard::acquire(&self.config)?;
        let control = self.store.control()?;
        if control.paused {
            return Ok(());
        }
        let model = match kind {
            WorkKind::Answer => self.config.solver.answer.clone(),
            WorkKind::Judge => self.config.solver.judge.clone(),
            WorkKind::Mine => bail!("mine does not use a model"),
        };
        input.solver.guidance = model.guidance.to_string();
        input.solver.id = digest(format!("{}:attempt:{}", input.solver.id, count + 1));
        let op = self.store.begin_linked(
            kind,
            key,
            ("generating", &serde_json::to_value(&input)?),
            control,
            &self.config.revision()?,
            retry.map(|original| (original, false)),
        )?;
        let timeout = self.config.timeouts.model_seconds;
        self.store.capture_policy(op.id, &json!({"model":model,
            "model_seconds":timeout,"attempt":count+1,"retry_uncertain":self.config.preparation.retry_uncertain,
            "max_attempts_per_work":self.config.preparation.max_attempts_per_work}), Some(timeout), None)?;
        drop(gate);
        let expected = self.config.clone();
        let config_path = self.config_path.clone();
        let key = key.to_owned();
        let input = Arc::new(input);
        let task_input = Arc::clone(&input);
        let mut stop = self.stop.clone();
        let wake = Arc::clone(&self.model_wake);
        let (completed, completion) = oneshot::channel();
        let task = tokio::spawn(async move {
            let future = solve(&model, &task_input.solver, timeout, move || {
                let gate = AdmissionGuard::try_acquire(&expected)?;
                let current = Config::load(&config_path)?;
                if !same_identity(&expected, &current)
                    || current.mode(kind) != Mode::Active
                    || (kind == WorkKind::Judge && current.judging_assignment_excluded(&key))
                {
                    bail!("model admission changed");
                }
                let store =
                    Store::read_only(&expected)?.context("model admission state missing")?;
                if store.control()? != control || control.paused {
                    bail!("model admission closed");
                }
                Ok(gate)
            });
            let attempt = tokio::select! {
                biased;
                result = tokio::time::timeout(Duration::from_secs(timeout), future) => match result {
                    Ok(Ok(result)) => ModelAttempt::Captured(result),
                    Ok(Err(error)) if completed_artifact_invalid(&error) => ModelAttempt::Invalid(failure_code(&error)),
                    Ok(Err(error)) if !execution_may_have_started(&error) => ModelAttempt::NotStarted(failure_code(&error)),
                    Ok(Err(error)) => ModelAttempt::Unknown(failure_code(&error)),
                    Err(_) => ModelAttempt::Unknown("model_launch_unknown"),
                },
                _ = stop.changed() => ModelAttempt::Unknown("model_launch_unknown"),
            };
            let _ = completed.send(attempt);
            wake.notify_one();
        });
        self.preparations.push(Preparation {
            operation: op,
            input,
            control,
            task,
            completion,
        });
        Ok(())
    }

    async fn collect_models(&mut self) -> Result<()> {
        let mut index = 0;
        while index < self.preparations.len() {
            let result = match self.preparations[index].completion.try_recv() {
                Ok(result) => result,
                Err(oneshot::error::TryRecvError::Empty) => {
                    index += 1;
                    continue;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    ModelAttempt::Unknown("model_launch_unknown")
                }
            };
            let Preparation {
                operation: mut op,
                input,
                control,
                ..
            } = self.preparations.swap_remove(index);
            // A captured attempt can never overwrite a superseding durable state.
            if self
                .store
                .operation(op.id)?
                .is_none_or(|current| current.state != "generating")
            {
                continue;
            }
            match result {
                ModelAttempt::Captured(result) => {
                    op.result = Some(serde_json::to_value(&result)?);
                    if self.store.control()? != control
                        || self.config.mode(op.kind) == Mode::Off
                        || (op.kind == WorkKind::Judge
                            && self.config.judging_assignment_excluded(&op.key))
                    {
                        // The completed artifact is retained privately, but never
                        // promoted after pause/resume changes its generation.
                        op.state = "discarded".into();
                        self.store.save(&op, "late_model_result_discarded")?;
                    } else {
                        match payload(&input.solver, &result) {
                            Ok(payload) => {
                                op.payload = Some(payload);
                                op.state = "generated".into();
                                self.store.save(&op, "model_result_captured")?;
                            }
                            Err(_) => {
                                op.state = "rejected".into();
                                self.store.save(&op, "model_result_invalid")?;
                            }
                        }
                    }
                }
                ModelAttempt::Invalid(code) => {
                    self.store.record_evidence(op.id,&json!({"stage":"model","route":op.kind,"reason":code,"execution":"completed_invalid"}))?;
                    op.state = "rejected".into();
                    self.store.save(&op, code)?;
                    self.store.defer(op.kind, self.retry_delay(None))?;
                }
                ModelAttempt::NotStarted(code) => {
                    self.store.record_evidence(op.id,&json!({"stage":"model","route":op.kind,"reason":code,"execution":"not_started"}))?;
                    op.state = "prelaunch_failed".into();
                    self.store.save(&op, code)?;
                    self.store.defer(op.kind, self.retry_delay(None))?;
                }
                ModelAttempt::Unknown(code) => {
                    self.store.record_evidence(op.id,&json!({"stage":"model","route":op.kind,"reason":code,"execution":"unknown"}))?;
                    op.state = "model_unknown".into();
                    self.store.save(&op, code)?;
                }
            }
        }
        Ok(())
    }

    async fn fresh(&mut self, op: &Operation, input: &Input) -> Result<Option<bool>> {
        match op.kind {
            WorkKind::Answer | WorkKind::Mine => {
                let Some(challenge) = self.challenge(op.kind).await? else {
                    return Ok(None);
                };
                Ok(Some(
                    challenge.epoch == input.solver.epoch
                        && input.challenge_fingerprint.as_deref()
                            == Some(challenge.fingerprint.as_str())
                        && challenge.words == input.solver.words
                        && challenge.min_chars == input.solver.min_chars
                        && challenge.max_chars == input.solver.max_chars
                        && (op.kind == WorkKind::Mine || !challenge.answered),
                ))
            }
            WorkKind::Judge => {
                let Some(inventory) = self.assignment_inventory().await? else {
                    return Ok(None);
                };
                let ids = assignment_ids(&inventory.response)?;
                if !ids.contains(&op.key) {
                    if inventory
                        .response
                        .body
                        .get("has_more")
                        .and_then(Value::as_bool)
                        == Some(false)
                    {
                        return Ok(Some(false));
                    }
                    self.store
                        .event("assignment_eligibility_unresolved", Some(WorkKind::Judge))?;
                    return Ok(None);
                }
                let Some(assignment) = self.assignment(&inventory, &op.key).await? else {
                    return Ok(None);
                };
                Ok(Some(assignment_matches(&assignment, &input.solver)))
            }
        }
    }

    fn discard_excluded_judgment(&mut self, op: &mut Operation) -> Result<bool> {
        // Only unsent or authoritatively retryable work can be discarded.
        // Possibly-sent operations must retain their receipt/job reconciliation.
        if op.kind == WorkKind::Judge
            && matches!(op.state.as_str(), "generated" | "prepared" | "retry")
            && self.config.judging_assignment_excluded(&op.key)
        {
            op.state = "discarded".into();
            self.store.save(op, "judging_assignment_excluded")?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn dispatch(&mut self, op: &mut Operation) -> Result<()> {
        self.reload()?;
        if self.discard_excluded_judgment(op)? {
            return Ok(());
        }
        if !self.active(op.kind)?
            || !self.store.admission_allowed(&self.config, op)?
            || self.store.read_backoff(ReadScope::Identity)?.next_at > now()
        {
            return Ok(());
        }
        let expected_control = self.store.control()?;
        let input: Input =
            serde_json::from_value(op.request.clone()).context("invalid durable request")?;
        match self.fresh(op, &input).await? {
            Some(true) => {}
            Some(false) => {
                op.state = "discarded".into();
                self.store.save(op, "request_no_longer_current")?;
                return Ok(());
            }
            None => return Ok(()),
        }
        if !self.identity_matches(op.kind).await? {
            return Ok(());
        }
        let gate = AdmissionGuard::acquire(&self.config)?;
        self.reload()?;
        if self.discard_excluded_judgment(op)? || !self.active(op.kind)? {
            return Ok(());
        }
        let control = self.store.control()?;
        if control.paused || control != expected_control || self.stopping() {
            return Ok(());
        }
        let payload = op
            .payload
            .clone()
            .context("prepared operation has no payload")?;
        let protocol = Arc::clone(&self.protocol);
        let prepared = match protocol.prepare_submission(op.kind, &payload) {
            Ok(prepared) => prepared,
            Err(_) => {
                op.state = "locally_rejected".into();
                self.store.save(op, "submission_preflight_rejected")?;
                return Ok(());
            }
        };
        self.heartbeat()?;
        if !self.store.dispatch_intent(op, &self.config)? {
            return Ok(());
        }
        let request = tokio::time::timeout(
            Duration::from_secs(self.config.timeouts.http_seconds),
            prepared,
        );
        tokio::pin!(request);
        let result = loop {
            if self.stopping() {
                match tokio::time::timeout(
                    Duration::from_secs(self.config.timeouts.shutdown_seconds),
                    &mut request,
                )
                .await
                {
                    Ok(result) => break result,
                    Err(_) => {
                        self.store.record_evidence(
                            op.id,
                            &serde_json::to_value(response_evidence(
                                op.kind,
                                ResponseSource::Submit,
                                None,
                            ))?,
                        )?;
                        op.next_at = not_before(self.retry_delay(None));
                        op.state = "unknown".into();
                        self.store.save(op, "dispatch_outcome_unknown")?;
                        drop(gate);
                        return Ok(());
                    }
                }
            }
            let wake = Arc::clone(&self.model_wake);
            let delay = self.urgent_delay()?;
            tokio::select! {
                biased;
                result = &mut request => break result,
                _ = self.stop.changed() => continue,
                _ = wake.notified() => self.collect_models().await?,
                _ = tokio::time::sleep(delay) => {
                    // Poll the effect while observing too: receiving an urgent
                    // read must not hide an already-completed write response.
                    let mut observation = Box::pin(self.service_urgent(false));
                    tokio::select! {
                        biased;
                        result = &mut request => {
                            observation.await?;
                            break result;
                        },
                        observed = &mut observation => observed?,
                    }
                },
            }
        };
        match result {
            Ok(Ok(response)) => {
                self.store.record_candidates(
                    op.id,
                    &serde_json::to_value(crate::protocol::response_candidates(&response))?,
                )?;
                self.store.record_evidence(
                    op.id,
                    &serde_json::to_value(response_evidence(
                        op.kind,
                        ResponseSource::Submit,
                        Some(&response),
                    ))?,
                )?;
                self.outcome(
                    op,
                    classify_source(op.kind, &response, ResponseSource::Submit),
                    true,
                    response.retry_after_seconds,
                )?;
            }
            _ => {
                self.store.record_evidence(
                    op.id,
                    &serde_json::to_value(response_evidence(
                        op.kind,
                        ResponseSource::Submit,
                        None,
                    ))?,
                )?;
                op.state = "unknown".into();
                op.next_at = not_before(self.retry_delay(None));
                self.store.save(op, "dispatch_outcome_unknown")?;
            }
        }
        drop(gate);
        Ok(())
    }

    fn outcome(
        &mut self,
        op: &mut Operation,
        outcome: Outcome,
        submitted: bool,
        retry_after: Option<u64>,
    ) -> Result<()> {
        if let Some(minimum) = retry_after {
            self.store.record_retry_minimum(op.id, minimum)?;
        }
        let event = match outcome {
            Outcome::Queued { job_id } => {
                op.next_at = not_before(self.retry_delay(retry_after));
                if !submitted && op.job_id.as_ref().is_some_and(|known| known != &job_id) {
                    op.state = "unknown".into();
                    "job_binding_mismatch"
                } else {
                    op.job_id = Some(job_id);
                    op.state = "queued".into();
                    "submission_queued"
                }
            }
            Outcome::Included { txid } => {
                op.txid = Some(txid);
                op.state = "included_pending".into();
                op.next_at = 0;
                "transaction_included_unconfirmed"
            }
            Outcome::Rejected { code } => {
                op.state = if matches!(
                    code.as_str(),
                    "stale_challenge" | "epoch_mismatch" | "wrong_epoch" | "words_mismatch"
                ) {
                    "stale"
                } else {
                    "rejected"
                }
                .into();
                "submission_rejected"
            }
            Outcome::ProcessedRejected {
                code: _,
                next_nonce,
            } => {
                op.state = if !submitted && op.job_id.is_some() && next_nonce.is_some() {
                    "rejected"
                } else {
                    "unknown"
                }
                .into();
                "processed_submission_rejected"
            }
            Outcome::Retry { after_seconds } => {
                if submitted {
                    op.state = "retry".into();
                }
                op.next_at = not_before(self.retry_delay(Some(after_seconds)));
                "submission_backoff"
            }
            Outcome::Expired => {
                if !submitted && op.job_id.is_some() && op.txid.is_none() {
                    op.job_id = None;
                    op.state = "retry".into();
                    op.next_at = not_before(self.retry_delay(retry_after));
                    "queued_job_expired"
                } else {
                    op.state = "unknown".into();
                    op.next_at = not_before(self.retry_delay(retry_after));
                    "unbound_job_expiry"
                }
            }
            Outcome::Unknown { .. } => {
                op.state = "unknown".into();
                op.next_at = not_before(self.retry_delay(retry_after));
                "dispatch_outcome_unknown"
            }
            Outcome::Completed => {
                op.state = "completed".into();
                if !self.config.schedule.mine_each_epoch {
                    self.store
                        .defer(op.kind, self.config.schedule.mine_seconds)?;
                }
                "mine_completed"
            }
        };
        self.store.save(op, event)
    }

    async fn reconcile(&mut self, op: &mut Operation) -> Result<()> {
        if let Some(txid) = op.txid.clone() {
            let Some(response) = self
                .get(op.kind, ReadScope::Receipt, &format!("/api/receipt/{txid}"))
                .await?
            else {
                return Ok(());
            };
            op.next_at = not_before(self.retry_delay(response.retry_after_seconds));
            if let Some(minimum) = response.retry_after_seconds {
                self.store.record_retry_minimum(op.id, minimum)?;
            }
            let evidence = receipt(&response, &txid, &self.config.network.address);
            if evidence != Receipt::Unresolved {
                self.store.safety_observed(op.id)?;
            }
            self.store.record_evidence(op.id, &json!({"stage":"receipt","route":op.kind,"status":response.status,
                "reason":match evidence {Receipt::Final=>"checkpoint_reported",Receipt::Included=>"included",
                    Receipt::Rejected=>"rejected",Receipt::Unresolved=>"unresolved"},
                "retry_after_seconds":response.retry_after_seconds}))?;
            self.read_evaluated(
                ReadScope::Receipt,
                evidence != Receipt::Unresolved,
                response.retry_after_seconds,
            )?;
            match evidence {
                Receipt::Final => {
                    op.state = "final".into();
                    self.store.save(op, "checkpoint_coverage_reported")?;
                }
                Receipt::Included => {
                    op.state = "confirmed".into();
                    self.store.save(op, "receipt_included")?;
                }
                Receipt::Rejected => {
                    op.state = "rejected".into();
                    self.store.save(op, "receipt_rejected")?;
                }
                Receipt::Unresolved => {
                    self.store.save(op, "receipt_unresolved")?;
                }
            }
        } else if let Some(job) = op.job_id.clone() {
            let Some(response) = self
                .get(op.kind, ReadScope::Job, &format!("/api/job/{job}"))
                .await?
            else {
                return Ok(());
            };
            if let Some(minimum) = response.retry_after_seconds {
                self.store.record_retry_minimum(op.id, minimum)?;
            }
            self.store.record_candidates(
                op.id,
                &serde_json::to_value(crate::protocol::response_candidates(&response))?,
            )?;
            let classified = classify_source(op.kind, &response, ResponseSource::BoundJob);
            if matches!(&classified, Outcome::Unknown {reason} if reason == "bound_job_pending")
                && response.body.get("state").and_then(Value::as_str) == Some("queued")
            {
                self.read_evaluated(ReadScope::Job, true, None)?;
                self.store.safety_observed(op.id)?;
                op.state = "queued".into();
                op.next_at = not_before(self.retry_delay(response.retry_after_seconds));
                self.store.save(op, "job_pending")?;
            } else {
                self.store.record_evidence(
                    op.id,
                    &serde_json::to_value(response_evidence(
                        op.kind,
                        ResponseSource::BoundJob,
                        Some(&response),
                    ))?,
                )?;
                let outcome = classified;
                if !matches!(outcome, Outcome::Unknown { .. }) {
                    self.store.safety_observed(op.id)?;
                }
                self.read_evaluated(
                    ReadScope::Job,
                    !matches!(outcome, Outcome::Unknown { .. }),
                    response.retry_after_seconds,
                )?;
                self.outcome(op, outcome, false, response.retry_after_seconds)?;
            }
        }
        // Identifier-less unknowns remain unresolved, but never monopolize the
        // reconciliation cursor. Only explicit participation policy permits risk.
        Ok(())
    }
}

fn assignment_matches(assignment: &Assignment, request: &SolverRequest) -> bool {
    request
        .assignment
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(&assignment.id))
        && request.epoch == assignment.epoch
        && request.candidate.as_deref() == Some(assignment.answer.as_str())
        && request.words == assignment.words
}

fn payload(request: &SolverRequest, result: &SolverResult) -> Result<Value> {
    match request.kind {
        WorkKind::Answer => {
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
        WorkKind::Judge => {
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
        WorkKind::Mine => Ok(json!({})),
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
mod tests {
    use super::*;

    fn response(body: Value) -> Response {
        Response {
            status: 200,
            body,
            retry_after_seconds: None,
            read_failure: None,
        }
    }

    fn request(kind: WorkKind) -> SolverRequest {
        SolverRequest {
            id: "request-test".into(),
            kind,
            epoch: 8,
            words: vec!["burn".into()],
            min_chars: 4,
            max_chars: 100,
            assignment: Some("assignment-test".into()),
            candidate: Some("candidate-test".into()),
            history: Vec::new(),
            guidance: String::new(),
            author_history: None,
            candidate_author: None,
        }
    }

    async fn finish_models(runtime: &mut Runtime) {
        tokio::time::timeout(Duration::from_secs(15), async {
            while !runtime.preparations.is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
                runtime.reload().unwrap();
                runtime.collect_models().await.unwrap();
            }
        })
        .await
        .expect("bounded fixture model completion");
        for kind in [WorkKind::Answer, WorkKind::Judge] {
            if let Some(mut op) = runtime.store.preparation(kind).unwrap()
                && op.state == "generated"
            {
                runtime.dispatch(&mut op).await.unwrap();
            }
        }
    }

    fn result() -> SolverResult {
        SolverResult {
            answer: Some("burning".into()),
            score: Some(2),
            reasoning: Some("Grounded judgment.".into()),
            provider: "test".into(),
            model: "test".into(),
            run_id: "test".into(),
        }
    }

    fn fixture() -> (tempfile::TempDir, Runtime, watch::Sender<bool>) {
        fixture_with(Config::default())
    }

    fn fixture_with(mut config: Config) -> (tempfile::TempDir, Runtime, watch::Sender<bool>) {
        config.schedule.jitter_seconds = 0;
        let temp = tempfile::tempdir().unwrap();
        config.state_dir = temp.path().join("state");
        let path = temp.path().join("config.toml");
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let config = Config::load(&path).unwrap();
        let protocol = Arc::new(Protocol::new(&config).unwrap());
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        store.runtime_state(&config, false).unwrap();
        let (sender, stop) = watch::channel(false);
        let runtime = Runtime {
            config_path: path,
            config,
            protocol,
            store,
            stop,
            reload_blocked: false,
            preparations: Vec::new(),
            controller: true,
            model_wake: Arc::new(Notify::new()),
            urgent_context: false,
        };
        (temp, runtime, sender)
    }

    #[tokio::test]
    async fn completed_model_is_retained_on_stop_but_pause_and_off_still_fence_it() {
        for fence in ["stop", "pause", "off"] {
            let (_temp, mut runtime, sender) = fixture();
            let input = Arc::new(Input {
                solver: request(WorkKind::Answer),
                challenge_fingerprint: Some("current".into()),
            });
            let control = runtime.store.control().unwrap();
            let op = runtime
                .store
                .begin(
                    WorkKind::Answer,
                    "8:current",
                    "generating",
                    &serde_json::to_value(&*input).unwrap(),
                    control,
                    "revision",
                )
                .unwrap();
            let id = op.id;
            let (completed, completion) = oneshot::channel();
            assert!(completed.send(ModelAttempt::Captured(result())).is_ok());
            runtime.preparations.push(Preparation {
                operation: op,
                input,
                control,
                task: tokio::spawn(async {}),
                completion,
            });
            match fence {
                "pause" => runtime.store.set_paused(true).unwrap(),
                "off" => runtime.config.capabilities.answer = Mode::Off,
                _ => {
                    sender.send(true).unwrap();
                }
            }
            runtime.collect_models().await.unwrap();
            let captured = runtime.store.operation(id).unwrap().unwrap();
            assert!(captured.result.is_some());
            assert_eq!(
                captured.state,
                if fence == "stop" {
                    "generated"
                } else {
                    "discarded"
                }
            );
            assert_eq!(captured.payload.is_some(), fence == "stop");
            assert!(!runtime.active(WorkKind::Answer).unwrap());
        }
    }

    #[test]
    fn challenge_policy_reload_shortens_local_delay_and_kind_defer_not_server_floor() {
        let (_temp, mut runtime, _sender) = fixture();
        runtime.read_failed(ReadScope::Challenge, Some(30)).unwrap();
        let before = runtime.store.reads().unwrap();
        let floor = before[0]["server_not_before"].as_i64().unwrap();
        let mut changed = runtime.config.clone();
        changed.schedule.challenge_retry_seconds = Some(1);
        changed.schedule.challenge_backoff_max_seconds = Some(2);
        std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
        runtime.reload().unwrap();
        let after = runtime.store.reads().unwrap();
        assert!(
            after[0]["local_next_at"].as_i64().unwrap()
                < before[0]["local_next_at"].as_i64().unwrap()
        );
        assert_eq!(after[0]["server_not_before"], floor);
        assert_eq!(after[0]["next_at"], floor);
        assert_eq!(runtime.store.next_at(WorkKind::Answer).unwrap(), floor);
    }

    fn judging_inventory(ids: &[String]) -> Response {
        response(
            json!({"has_more":false,"assignments":ids.iter().map(|id| json!({
            "answer_txid":id, "answer_epoch":8, "answer":"candidate-test", "words":["burn"]
        })).collect::<Vec<_>>()}),
        )
    }

    fn judging_input(id: &str) -> Input {
        let mut solver = request(WorkKind::Judge);
        solver.assignment = Some(id.into());
        Input {
            solver,
            challenge_fingerprint: None,
        }
    }

    fn judging_operation(runtime: &mut Runtime, id: &str, state: &str) -> Operation {
        let input = judging_input(id);
        let control = runtime.store.control().unwrap();
        let mut op = runtime
            .store
            .begin(
                WorkKind::Judge,
                id,
                "prepared",
                &serde_json::to_value(&input).unwrap(),
                control,
                &runtime.config.revision().unwrap(),
            )
            .unwrap();
        op.payload = Some(payload(&input.solver, &result()).unwrap());
        if matches!(
            state,
            "dispatching" | "queued" | "unknown" | "included_pending" | "confirmed" | "final"
        ) {
            op.state = "dispatching".into();
            runtime.store.save(&op, "dispatch_intent").unwrap();
        }
        if state == "dispatching" {
            return op;
        }
        op.state = state.into();
        runtime.store.save(&op, "test_judgment_prepared").unwrap();
        op
    }

    #[cfg(unix)]
    fn active_judge_config(dir: &Path) -> Config {
        use std::os::unix::fs::PermissionsExt;
        let mut config = Config::default();
        config.network.chain = format!(
            "test-{}",
            dir.file_name().unwrap().to_str().unwrap().replace('.', "")
        );
        config.network.address = format!("poa1{}", "1".repeat(32));
        config.network.credential_file = dir.join("key");
        std::fs::write(&config.network.credential_file, "pk_test_fixture").unwrap();
        std::fs::set_permissions(
            &config.network.credential_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        config.capabilities.answer = Mode::Off;
        config.capabilities.mine = Mode::Off;
        config.capabilities.judge = Mode::Active;
        config.timeouts.http_seconds = 2;
        config
    }

    async fn judging_reply(
        listener: &tokio::net::TcpListener,
        expected_path: &str,
        body: Value,
        update: Option<(&Path, &Config)>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0 && request.len() + count <= 4096);
            request.extend_from_slice(&buffer[..count]);
        }
        assert!(
            std::str::from_utf8(&request)
                .unwrap()
                .starts_with(&format!("GET {expected_path} HTTP/1.1"))
        );
        if let Some((path, config)) = update {
            std::fs::write(path, toml::to_string(config).unwrap()).unwrap();
        }
        let body = body.to_string();
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(reply.as_bytes()).await.unwrap();
    }

    async fn accept_api_request(
        listener: &tokio::net::TcpListener,
        expected: &str,
    ) -> tokio::net::TcpStream {
        use tokio::io::AsyncReadExt;
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        let header_end = loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 8192);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
        assert!(
            headers.starts_with(&format!("{expected} HTTP/1.1")),
            "{headers}"
        );
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while bytes.len() < header_end + length {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&buffer[..count]);
        }
        stream
    }

    async fn api_reply(
        listener: &tokio::net::TcpListener,
        expected: &str,
        status: u16,
        retry_after: Option<u64>,
        body: Value,
    ) {
        use tokio::io::AsyncWriteExt;
        let mut stream = accept_api_request(listener, expected).await;
        let retry = retry_after
            .map(|seconds| format!("Retry-After: {seconds}\r\n"))
            .unwrap_or_default();
        let body = body.to_string();
        let reply = format!(
            "HTTP/1.1 {status} Fixture\r\n{retry}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn participation_policy_is_rechecked_after_freshness_and_identity_reads() {
        for invalid_reload in [false, true] {
            let credentials = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = active_judge_config(credentials.path());
            config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
            config.participation.mode = ParticipationMode::ParticipationFirst;
            config.participation.allow_judge = true;
            config.participation.uncertainty_grace_seconds = 0;
            let (_temp, mut runtime, _sender) = fixture_with(config);
            let old = judging_operation(&mut runtime, &"a".repeat(64), "unknown");
            let id = "b".repeat(64);
            let mut op = judging_operation(&mut runtime, &id, "generated");
            let mut changed = runtime.config.clone();
            changed.participation.mode = ParticipationMode::Strict;
            let path = runtime.config_path.clone();
            let server = tokio::spawn(async move {
                let prefix = format!("/chain/{}", changed.network.chain);
                judging_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/assignments"),
                    judging_inventory(&[id]).body,
                    None,
                )
                .await;
                if invalid_reload {
                    use tokio::io::AsyncWriteExt;
                    let mut stream =
                        accept_api_request(&listener, &format!("GET {prefix}/api/hosted/me")).await;
                    std::fs::write(&path, "[participation]\nmode='not-a-policy'").unwrap();
                    let body = json!({"address":changed.network.address}).to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()).as_bytes()).await.unwrap();
                } else {
                    judging_reply(
                        &listener,
                        &format!("{prefix}/api/hosted/me"),
                        json!({"address":changed.network.address}),
                        Some((&path, &changed)),
                    )
                    .await;
                }
                listener
            });
            runtime.dispatch(&mut op).await.unwrap();
            let listener = server.await.unwrap();
            assert_eq!(op.state, "generated");
            assert_eq!(
                runtime.store.operation(old.id).unwrap().unwrap().state,
                "unknown"
            );
            assert_eq!(
                runtime.store.status(&runtime.config).unwrap()["participation"]["risk_admissions"],
                0
            );
            assert_eq!(runtime.reload_blocked, invalid_reload);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn separate_read_timeout_reaches_runtime_and_reqwest_without_changing_writes() {
        use tokio::io::AsyncWriteExt;
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.timeouts.http_seconds = 1;
        config.timeouts.read_http_seconds = Some(3);
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let path = format!(
            "GET /chain/{}/api/hosted/assignments",
            runtime.config.network.chain
        );
        let server = tokio::spawn(async move {
            let mut stream = accept_api_request(&listener, &path).await;
            tokio::time::sleep(Duration::from_millis(1200)).await;
            let body = json!({"assignments":[],"has_more":false}).to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        assert!(runtime.assignment_inventory().await.unwrap().is_some());
        server.await.unwrap();
        assert_eq!(runtime.config.timeouts.http_seconds, 1);
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["effective_runtime"]["policy"]["timeouts"]
                ["read_http_seconds"],
            3
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retained_inventory_read_allows_urgent_observation_and_still_completes() {
        use tokio::io::AsyncWriteExt;
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer = Mode::ReadOnly;
        config.timeouts.read_http_seconds = Some(5);
        let (_temp, mut runtime, _sender) = fixture_with(config);
        runtime
            .store
            .defer_until(WorkKind::Answer, now() + 1)
            .unwrap();
        let prefix = format!("GET /chain/{}", runtime.config.network.chain);
        let server = tokio::spawn(async move {
            let mut retained =
                accept_api_request(&listener, &format!("{prefix}/api/hosted/assignments")).await;
            // A serial await would deadlock here until its read deadline.
            tokio::time::timeout(
                Duration::from_secs(2),
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/challenge"),
                    200,
                    None,
                    json!({"epoch":77,"answered":false,"words":["burn"]}),
                ),
            )
            .await
            .unwrap();
            let body = json!({"assignments":[],"has_more":false}).to_string();
            retained
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let inventory = runtime.assignment_inventory().await.unwrap().unwrap();
        server.await.unwrap();
        assert_eq!(inventory.response.body["has_more"], false);
        let status = runtime.store.status(&runtime.config).unwrap();
        assert_eq!(status["observation"]["epoch"], 77);
        assert_eq!(status["reads"][2]["state"], "idle");
        assert!(status["reads"][2]["last_success_at"].is_i64());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stalled_read_body_keeps_status_and_authoritative_retry_floor() {
        use tokio::io::AsyncWriteExt;
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer = Mode::ReadOnly;
        config.timeouts.read_http_seconds = Some(1);
        config.schedule.challenge_retry_seconds = Some(1);
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let path = format!(
            "GET /chain/{}/api/hosted/challenge",
            runtime.config.network.chain
        );
        let server = tokio::spawn(async move {
            let mut stream = accept_api_request(&listener, &path).await;
            stream
                .write_all(
                    b"HTTP/1.1 503 Unavailable\r\nRetry-After: 90\r\nContent-Length: 100\r\n\r\n{",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let before = now();
        assert!(runtime.challenge(WorkKind::Answer).await.unwrap().is_none());
        let reads = runtime.store.reads().unwrap();
        assert_eq!(reads[0]["failure_category"], "timeout");
        assert_eq!(reads[0]["status"], 503);
        assert!(reads[0]["server_not_before"].as_i64().unwrap() >= before + 90);
        assert_eq!(reads[0]["failures"], 1);
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn effectful_get_mining_retains_write_timeout() {
        use tokio::io::AsyncWriteExt;
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.mine = Mode::Active;
        config.timeouts.http_seconds = 3;
        config.timeouts.read_http_seconds = Some(1);
        let (_temp, runtime, _sender) = fixture_with(config);
        let path = format!(
            "GET /chain/{}/api/hosted/mine",
            runtime.config.network.chain
        );
        let server = tokio::spawn(async move {
            let mut stream = accept_api_request(&listener, &path).await;
            tokio::time::sleep(Duration::from_millis(1200)).await;
            let body = json!({"ok":true}).to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let payload = json!({});
        assert_eq!(
            runtime
                .protocol
                .prepare_submission(WorkKind::Mine, &payload)
                .unwrap()
                .await
                .unwrap()
                .status,
            200
        );
        server.await.unwrap();
    }

    fn expire_read_deadlines(runtime: &Runtime) {
        let db =
            rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
        db.execute("UPDATE read_backoff SET next_at=0", []).unwrap();
        db.execute(
            "UPDATE read_observations SET local_next_at=0,server_not_before=0",
            [],
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn http_read_backoff_grows_caps_reopens_and_resets_per_endpoint() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer = Mode::ReadOnly;
        config.schedule.retry_seconds = 2;
        config.schedule.backoff_max_seconds = 5;
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let prefix = format!("GET /chain/{}", runtime.config.network.chain);
        let address = runtime.config.network.address.clone();
        let server = tokio::spawn(async move {
            for (status, retry) in [
                (500, None),
                (502, None),
                (429, Some(75)),
                (503, None),
                (200, None),
                (200, Some(90)),
            ] {
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/challenge"),
                    status,
                    retry,
                    json!({}),
                )
                .await;
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/me"),
                    200,
                    None,
                    json!({"address":address}),
                )
                .await;
            }
            api_reply(
                &listener,
                &format!("{prefix}/api/hosted/challenge"),
                200,
                None,
                json!({"epoch":8,"words":["burn"],"answered":true}),
            )
            .await;
            api_reply(
                &listener,
                &format!("{prefix}/api/hosted/challenge"),
                503,
                Some(1),
                json!({}),
            )
            .await;
            listener
        });
        for (failures, delay) in [(1, 2), (2, 4), (3, 75), (4, 5), (5, 5), (6, 90)] {
            let before = now();
            assert!(runtime.challenge(WorkKind::Answer).await.unwrap().is_none());
            let state = runtime.store.read_backoff(ReadScope::Challenge).unwrap();
            assert_eq!(state.failures, failures);
            assert!(state.next_at > before + delay);
            assert!(state.next_at <= now() + delay + 1);
            runtime.store = Store::open(&runtime.config).unwrap();
            assert_eq!(
                runtime.store.read_backoff(ReadScope::Challenge).unwrap(),
                state
            );
            assert!(runtime.challenge(WorkKind::Answer).await.unwrap().is_none());
            assert!(runtime.identity_matches(WorkKind::Answer).await.unwrap());
            assert_eq!(
                runtime.store.read_backoff(ReadScope::Challenge).unwrap(),
                state
            );
            expire_read_deadlines(&runtime);
        }
        // Normal pre-deferral must not suppress the read; only read failure state gates it.
        runtime.store.defer(WorkKind::Answer, 300).unwrap();
        assert!(runtime.challenge(WorkKind::Answer).await.unwrap().is_some());
        assert_eq!(
            runtime
                .store
                .read_backoff(ReadScope::Challenge)
                .unwrap()
                .failures,
            0
        );
        let before = now();
        assert!(runtime.challenge(WorkKind::Answer).await.unwrap().is_none());
        let state = runtime.store.read_backoff(ReadScope::Challenge).unwrap();
        assert_eq!(state.failures, 1);
        assert!(state.next_at >= before + 3);
        assert!(state.next_at <= now() + 3);
        let listener = server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn transport_disconnect_and_timeout_persist_read_failure_without_replay() {
        for timeout in [false, true] {
            let credentials = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = active_judge_config(credentials.path());
            config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
            config.timeouts.http_seconds = 1;
            let (_temp, mut runtime, _sender) = fixture_with(config);
            let path = format!(
                "GET /chain/{}/api/hosted/assignments",
                runtime.config.network.chain
            );
            let (release, released) = tokio::sync::oneshot::channel::<()>();
            let server = tokio::spawn(async move {
                let stream = accept_api_request(&listener, &path).await;
                if timeout {
                    let _ = released.await;
                }
                drop(stream);
                listener
            });
            assert!(runtime.assignment_inventory().await.unwrap().is_none());
            let state = runtime.store.read_backoff(ReadScope::Assignments).unwrap();
            assert_eq!(state.failures, 1);
            runtime.store = Store::open(&runtime.config).unwrap();
            assert!(runtime.assignment_inventory().await.unwrap().is_none());
            assert_eq!(
                runtime.store.read_backoff(ReadScope::Assignments).unwrap(),
                state
            );
            let _ = release.send(());
            let listener = server.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn http_authoritative_job_expiry_preserves_captured_retry_without_resubmission() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let mut queued = judging_operation(&mut runtime, &"a".repeat(64), "queued");
        queued.job_id = Some("private-job".into());
        let captured_payload = queued.payload.clone();
        runtime.store.save(&queued, "test_job_bound").unwrap();
        let path = format!(
            "GET /chain/{}/api/job/private-job",
            runtime.config.network.chain
        );
        let server = tokio::spawn(async move {
            api_reply(
                &listener,
                &path,
                408,
                Some(600),
                json!({"state":"expired","error":"job_expired"}),
            )
            .await;
            listener
        });
        let before = now();
        runtime.reconcile(&mut queued).await.unwrap();
        assert_eq!(queued.state, "retry");
        assert!(queued.job_id.is_none());
        assert_eq!(queued.payload, captured_payload);
        assert!(queued.next_at >= before + 601);
        assert_eq!(
            runtime.store.read_backoff(ReadScope::Job).unwrap().failures,
            0
        );
        runtime.store.defer(WorkKind::Judge, 600).unwrap();
        runtime.cycle().await.unwrap();
        let listener = server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn complete_inventory_does_not_depend_on_or_reset_explorer_backoff() {
        let credentials = tempfile::tempdir().unwrap();
        let (_temp, mut runtime, _sender) = fixture_with(active_judge_config(credentials.path()));
        let failed = runtime
            .store
            .fail_read(ReadScope::AssignmentEvidence, 120, 900, 0, None)
            .unwrap();
        let id = "a".repeat(64);
        let inventory = response(json!({"assignments":[
            {"answer_txid":id,"answer_epoch":8,"answer":"candidate","words":["burn"]}
        ]}));
        let inventory = Inventory {
            response: inventory,
            pages_usable: true,
        };
        let selected = runtime.assignment(&inventory, &id).await.unwrap().unwrap();
        assert_eq!(selected.epoch, 8);
        assert_eq!(
            runtime
                .store
                .read_backoff(ReadScope::AssignmentEvidence)
                .unwrap(),
            failed
        );
    }

    #[test]
    fn server_minimum_keeps_work_retry_stagger() {
        let (_temp, mut runtime, _sender) = fixture();
        runtime.config.schedule.jitter_seconds = 30;
        runtime.config.network.chain = "retry-stagger-test".into();
        runtime.config.network.address = format!("poa1{}", "1".repeat(32));
        assert!(stagger(&runtime.config, "retry") > 0);
        assert!(runtime.retry_delay(Some(900)) > 900);
        assert!(runtime.retry_delay(Some(900)) <= 930);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn finality_pending_observation_and_hydration_cannot_bypass_read_backoff() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer = Mode::ReadOnly;
        config.capabilities.mine = Mode::ReadOnly;
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let id = "a".repeat(64);
        let txid = "b".repeat(64);
        let mut confirmed = judging_operation(&mut runtime, &id, "confirmed");
        confirmed.txid = Some(txid.clone());
        runtime
            .store
            .save(&confirmed, "test_receipt_bound")
            .unwrap();
        let mut queued = operation(&mut runtime);
        queued.state = "queued".into();
        queued.job_id = Some("private-job".into());
        runtime.store.save(&queued, "test_job_bound").unwrap();
        let inventory = response(json!({"has_more":true,"assignments":[
            {"answer_txid":id,"answer":"candidate-test"},
            {"answer_txid":"c".repeat(64),"answer":"unselected"}
        ]}));
        let inventory = Inventory {
            response: inventory,
            pages_usable: true,
        };
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Backoff is per scope, independent of request completion order.
            for _ in 0..5 {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut bytes = [0_u8; 8192];
                let mut received = 0;
                while !bytes[..received].windows(4).any(|part| part == b"\r\n\r\n") {
                    let count = stream.read(&mut bytes[received..]).await.unwrap();
                    assert!(count > 0);
                    received += count;
                }
                stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            }
            listener
        });
        runtime.follow_finality().await.unwrap();
        runtime.reconcile(&mut queued).await.unwrap();
        runtime.observe_enabled().await.unwrap();
        assert!(runtime.assignment(&inventory, &id).await.unwrap().is_none());
        let listener = server.await.unwrap();
        runtime.store = Store::open(&runtime.config).unwrap();
        let db =
            rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
        db.execute("UPDATE schedule SET next_at=0", []).unwrap();
        drop(db);
        runtime.follow_finality().await.unwrap();
        runtime.cycle().await.unwrap();
        runtime.observe_enabled().await.unwrap();
        assert!(runtime.assignment(&inventory, &id).await.unwrap().is_none());
        assert_eq!(runtime.store.pending().unwrap().unwrap().state, "queued");
        for scope in [
            ReadScope::Receipt,
            ReadScope::Job,
            ReadScope::Challenge,
            ReadScope::Assignments,
            ReadScope::AssignmentEvidence,
        ] {
            assert_eq!(runtime.store.read_backoff(scope).unwrap().failures, 1);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        expire_read_deadlines(&runtime);
        let path = format!(
            "GET /chain/{}/api/explorer/tx/{id}",
            runtime.config.network.chain
        );
        let selected = id.clone();
        let server = tokio::spawn(async move {
            api_reply(&listener, &path, 200, None, json!({
                "id":selected,"body":{"type":"challenge","epoch":7,"answer":"candidate-test","words":["burn"]}
            })).await;
            listener
        });
        let hydrated = runtime.assignment(&inventory, &id).await.unwrap().unwrap();
        assert_eq!(hydrated.id, id);
        assert_eq!(hydrated.epoch, 7);
        assert_eq!(hydrated.words, vec!["burn"]);
        assert_eq!(
            runtime
                .store
                .read_backoff(ReadScope::AssignmentEvidence)
                .unwrap()
                .failures,
            0
        );
        // Successful hydration resets only its own failure streak.
        assert_eq!(
            runtime.store.read_backoff(ReadScope::Job).unwrap().failures,
            1
        );
        let listener = server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn identity_stagger_is_deterministic_bounded_and_disabled_by_zero() {
        let mut config = Config::default();
        config.schedule.jitter_seconds = 30;
        for phase in ["startup", "poll", "retry"] {
            let mut offsets = std::collections::HashSet::new();
            for index in 0..32 {
                config.network.address = format!("poa1{index:032}");
                let delay = stagger(&config, phase);
                assert_eq!(delay, stagger(&config.clone(), phase));
                assert!(delay <= 30);
                offsets.insert(delay);
            }
            assert!(offsets.len() > 1);
        }
        config.schedule.jitter_seconds = 0;
        for phase in ["startup", "poll", "retry"] {
            assert_eq!(stagger(&config, phase), 0);
        }
    }

    #[tokio::test]
    async fn once_skips_startup_stagger_and_waits_are_shutdown_interruptible() {
        let (_temp, mut runtime, sender) = fixture();
        runtime.config.capabilities.answer = Mode::Off;
        runtime.config.capabilities.judge = Mode::Off;
        runtime.config.capabilities.mine = Mode::Off;
        runtime.config.schedule.jitter_seconds = 30;
        // Choose a nonzero deterministic startup offset without relying on a hash fixture.
        while stagger(&runtime.config, "startup") < 5 {
            runtime.config.schedule.jitter_seconds += 1;
        }
        std::fs::write(
            &runtime.config_path,
            toml::to_string(&runtime.config).unwrap(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_millis(500), runtime.run_loop(true))
            .await
            .unwrap()
            .unwrap();
        let stop = async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            sender.send(true).unwrap();
        };
        tokio::time::timeout(Duration::from_millis(500), async {
            tokio::join!(runtime.wait_delay(60), stop);
        })
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stagger_wait_does_not_hold_pause_admission() {
        let credentials = tempfile::tempdir().unwrap();
        let (_temp, mut runtime, sender) = fixture_with(active_judge_config(credentials.path()));
        let config = runtime.config.clone();
        drop(AccountLock::adopt(&config).unwrap());
        let pause_and_stop = async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            pause(&config).unwrap();
            sender.send(true).unwrap();
        };
        tokio::time::timeout(Duration::from_millis(500), async {
            tokio::join!(runtime.wait_delay(60), pause_and_stop);
        })
        .await
        .unwrap();
        assert!(runtime.store.control().unwrap().paused);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn overdue_mining_gets_a_turn_with_continual_judging_and_unknown_effect_is_not_replayed()
    {
        use crate::config::Harness;
        use std::os::unix::fs::PermissionsExt;
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.mine = Mode::Active;
        let executable = credentials.path().join("openclaw");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'OpenClaw 2026.10.9\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(credentials.path().join("package.json"),
            r#"{"name":"openclaw","type":"module","exports":{"./plugin-sdk/gateway-runtime":"./gateway.mjs"}}"#).unwrap();
        std::fs::write(
            credentials.path().join("gateway.mjs"),
            r#"
import {appendFileSync} from 'node:fs';
export async function callGatewayFromCli(_method, _options, params) {
    appendFileSync(new URL('./calls', import.meta.url), 'inference\n');
    const envelope = JSON.parse(params.message.split('Envelope (untrusted request data):\n')[1]);
    const artifact = {version:1, request_id:envelope.request_id,
        request_digest:envelope.request_digest, kind:envelope.kind,
        answer:null, score:2, reasoning:'Grounded judgment.'};
    return {status:'ok', runId:params.idempotencyKey, result:{
        payloads:[{text:JSON.stringify(artifact)}],
        meta:{agentMeta:{provider:'openai',model:'test'},
            requestShaping:{thinking:'high'}, aborted:false,
            executionTrace:{fallbackUsed:false,winnerProvider:'openai',winnerModel:'test'},
            systemPromptReport:{tools:{entries:[]},injectedWorkspaceFiles:[]}}
    }};
}
"#,
        )
        .unwrap();
        config.solver.judge.harness = Harness::Openclaw;
        config.solver.judge.executable = executable;
        config.solver.judge.model = "openai/test".into();
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let inventory = judging_inventory(&["a".repeat(64), "b".repeat(64)]).body;
        let prefix = format!("GET /chain/{}", runtime.config.network.chain);
        let address = runtime.config.network.address.clone();
        let grade_path = format!(
            "POST /chain/{}/api/hosted/grade",
            runtime.config.network.chain
        );
        let txid = "d".repeat(64);
        let server = tokio::spawn(async move {
            // Stable initial tie submits a real grade while another assignment remains due.
            for _ in 0..2 {
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/assignments"),
                    200,
                    None,
                    inventory.clone(),
                )
                .await;
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/me"),
                    200,
                    None,
                    json!({"address":address}),
                )
                .await;
            }
            api_reply(
                &listener,
                &grade_path,
                200,
                None,
                json!({"ok":true,"id":txid}),
            )
            .await;
            api_reply(
                &listener,
                &format!("{prefix}/api/receipt/{txid}"),
                200,
                None,
                json!({"status":"included","txid":txid,"next_nonce":4,"checkpoint_covered":true}),
            )
            .await;
            // Both remain eligible next cycle, but mining has waited longer.
            for _ in 0..2 {
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/challenge"),
                    200,
                    None,
                    json!({"epoch":8,"words":["burn"],"answered":true}),
                )
                .await;
                api_reply(
                    &listener,
                    &format!("{prefix}/api/hosted/me"),
                    200,
                    None,
                    json!({"address":address}),
                )
                .await;
            }
            let stream = accept_api_request(&listener, &format!("{prefix}/api/hosted/mine")).await;
            // An actual accepted mutation loses its response: never infer completion or retry.
            drop(stream);
            api_reply(
                &listener,
                &format!("{prefix}/api/hosted/assignments"),
                200,
                None,
                inventory,
            )
            .await;
            listener
        });
        runtime.cycle().await.unwrap();
        finish_models(&mut runtime).await;
        let mut grade = runtime.store.pending().unwrap().unwrap();
        assert_eq!(grade.kind, WorkKind::Judge);
        assert_eq!(grade.state, "included_pending");
        runtime.reconcile(&mut grade).await.unwrap();
        assert_eq!(grade.state, "final");
        assert!(runtime.store.pending().unwrap().is_none());
        assert_eq!(
            std::fs::read_to_string(credentials.path().join("calls")).unwrap(),
            "inference\n"
        );
        let db =
            rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
        db.execute(
            "UPDATE schedule SET next_at=?1 WHERE kind='judge'",
            [now() - 1],
        )
        .unwrap();
        drop(db);
        let before_mine = now();
        runtime.cycle().await.unwrap();
        let pending = runtime.store.pending().unwrap().unwrap();
        assert_eq!(pending.kind, WorkKind::Mine);
        assert_eq!(pending.state, "unknown");
        assert!(
            runtime.store.next_at(WorkKind::Mine).unwrap()
                >= before_mine + runtime.config.schedule.mine_seconds as i64
        );
        runtime.store = Store::open(&runtime.config).unwrap();
        runtime.store.recover().unwrap();
        for _ in 0..3 {
            runtime.cycle().await.unwrap();
        }
        assert_eq!(runtime.store.pending().unwrap().unwrap().id, pending.id);
        let listener = server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["operations"],
            json!([{"kind":"judge","state":"final","count":1},
                {"kind":"mine","state":"unknown","count":1}])
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn answer_keeps_priority_over_older_judging_and_mining() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer = Mode::Active;
        config.capabilities.mine = Mode::Active;
        config.solver.answer.executable = credentials.path().join("absent-model");
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let db =
            rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO schedule(kind,next_at) VALUES ('answer',?1)",
            [now() - 1],
        )
        .unwrap();
        drop(db);
        let prefix = format!("GET /chain/{}", runtime.config.network.chain);
        let address = runtime.config.network.address.clone();
        let server = tokio::spawn(async move {
            api_reply(
                &listener,
                &format!("{prefix}/api/hosted/challenge"),
                200,
                None,
                json!({"epoch":8,"words":["burn"],"answered":false}),
            )
            .await;
            api_reply(
                &listener,
                &format!("{prefix}/api/hosted/me"),
                200,
                None,
                json!({"address":address}),
            )
            .await;
            listener
        });
        runtime.cycle().await.unwrap();
        finish_models(&mut runtime).await;
        let listener = server.await.unwrap();
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["operations"],
            json!([{"kind":"answer","state":"prelaunch_failed","count":1}])
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn identity_matches_persists_latest_success_mismatch_and_unavailable_result() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let (_temp, mut runtime, _sender) = fixture_with(config);
        assert_eq!(
            runtime
                .store
                .status(&runtime.config)
                .unwrap()
                .get("hosted_identity_verified"),
            Some(&Value::Null)
        );
        let path = format!("/chain/{}/api/hosted/me", runtime.config.network.chain);
        let address = runtime.config.network.address.clone();
        let chain = runtime.config.network.chain.clone();
        let server = tokio::spawn(async move {
            for body in [
                json!({"address":address}),
                json!({"address":"different-account"}),
                json!({"address":address}),
                json!({"address":address,"ok":false}),
                json!({"address":address,"success":false}),
                json!({"address":address,"chain_id":null}),
                json!({"address":address,"chain_id":17}),
                json!({"address":address,"chain_id":"wrong-chain"}),
                json!({"address":address,"ok":"true"}),
                json!({"address":address,"chain_id":chain,"ok":true,"success":true}),
            ] {
                judging_reply(&listener, &path, body, None).await;
            }
            let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            drop(stream);
        });
        for matched in [
            true, false, true, false, false, false, false, false, false, true,
        ] {
            let scheduled = runtime.store.next_at(WorkKind::Judge).unwrap();
            let before = now();
            assert_eq!(
                runtime.identity_matches(WorkKind::Judge).await.unwrap(),
                matched
            );
            assert_eq!(
                runtime.store.status(&runtime.config).unwrap()["hosted_identity_verified"],
                matched
            );
            let after = runtime.store.next_at(WorkKind::Judge).unwrap();
            if matched {
                assert_eq!(after, scheduled);
            } else {
                assert!(after >= before + runtime.config.schedule.retry_seconds as i64);
                assert!(!runtime.identity_matches(WorkKind::Judge).await.unwrap());
                expire_read_deadlines(&runtime);
            }
        }
        let before = now();
        assert!(!runtime.identity_matches(WorkKind::Judge).await.unwrap());
        server.await.unwrap();
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["hosted_identity_verified"],
            false
        );
        assert!(
            runtime
                .store
                .read_backoff(ReadScope::Identity)
                .unwrap()
                .next_at
                >= before + runtime.config.schedule.retry_seconds as i64
        );
        let events = runtime.store.events(100).unwrap();
        let events = events.as_array().unwrap();
        assert!(
            events
                .iter()
                .any(|event| event["event"] == "upstream_read_failed")
        );
    }

    #[test]
    fn judging_selection_is_expiry_first_deterministic_and_skips_exclusions() {
        let (_temp, mut runtime, _sender) = fixture();
        let ids = vec!["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        let mut inventory = judging_inventory(&ids);
        inventory.body["assignments"][1]["pending_meta"] = json!({"expires_at_epoch":10});
        inventory.body["assignments"][2]["pending_meta"] = json!({"expires_at_epoch":9});
        runtime.config.excluded_judging_assignments = vec![ids[0].to_uppercase()];
        for expected in [&ids[2], &ids[2], &ids[2]] {
            assert_eq!(
                runtime
                    .next_judging_assignment(&inventory)
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
        }
        assert!(!runtime.store.attempted(WorkKind::Judge, &ids[0]).unwrap());
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["operations"],
            json!([])
        );
        judging_operation(&mut runtime, &ids[2], "abstained");
        assert_eq!(
            runtime
                .next_judging_assignment(&inventory)
                .unwrap()
                .as_ref(),
            Some(&ids[1])
        );
        runtime.config.excluded_judging_assignments = ids;
        assert!(
            runtime
                .next_judging_assignment(&inventory)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn excluded_judgments_do_not_launch_or_block_unexcluded_model_admission() {
        let native = tempfile::tempdir().unwrap();
        let mut config = active_judge_config(native.path());
        config.solver.judge.executable = native.path().join("absent-model");
        let excluded = "a".repeat(64);
        let allowed = "b".repeat(64);
        config.excluded_judging_assignments = vec![excluded.clone()];
        let (_temp, mut runtime, _sender) = fixture_with(config);
        runtime
            .generate(WorkKind::Judge, &excluded, judging_input(&excluded))
            .await
            .unwrap();
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["operations"],
            json!([])
        );
        runtime
            .generate(WorkKind::Judge, &allowed, judging_input(&allowed))
            .await
            .unwrap();
        finish_models(&mut runtime).await;
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["operations"],
            json!([{"kind":"judge","state":"prelaunch_failed","count":1}])
        );
        assert!(!runtime.store.attempted(WorkKind::Judge, &excluded).unwrap());
    }

    #[tokio::test]
    async fn excluded_captured_and_retryable_judgments_release_unsent_boundary() {
        for state in ["generated", "prepared", "retry"] {
            let id = "a".repeat(64);
            let config = Config {
                excluded_judging_assignments: vec![id.clone()],
                ..Config::default()
            };
            let (_temp, mut runtime, _sender) = fixture_with(config);
            let mut op = judging_operation(&mut runtime, &id, state);
            runtime.dispatch(&mut op).await.unwrap();
            assert_eq!(op.state, "discarded");
            assert!(runtime.store.pending().unwrap().is_none());
            assert!(
                runtime
                    .next_judging_assignment(&judging_inventory(&[id]))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cycle_discards_excluded_unsent_judgments_before_backoff_and_activity_gates() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        for (state, mode, paused) in [
            ("generated", Mode::Active, false),
            ("prepared", Mode::Active, false),
            ("retry", Mode::Active, false),
            ("retry", Mode::Active, true),
            ("retry", Mode::ReadOnly, false),
            ("retry", Mode::ReadOnly, true),
            ("retry", Mode::Off, false),
        ] {
            let id = "a".repeat(64);
            let allowed = "b".repeat(64);
            let mut config = active_judge_config(credentials.path());
            config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
            config.capabilities.judge = mode;
            config.excluded_judging_assignments = vec![id.clone()];
            let (_temp, mut runtime, _sender) = fixture_with(config);
            let mut op = judging_operation(&mut runtime, &id, state);
            op.next_at = not_before(86_400);
            runtime.store.save(&op, "test_submission_backoff").unwrap();
            runtime.store.defer(WorkKind::Judge, 86_400).unwrap();
            let scheduled = runtime.store.next_at(WorkKind::Judge).unwrap();
            runtime.store.set_paused(paused).unwrap();

            runtime.cycle().await.unwrap();

            assert!(runtime.store.pending().unwrap().is_none());
            assert_eq!(
                runtime.store.status(&runtime.config).unwrap()["operations"],
                json!([{"kind":"judge","state":"discarded","count":1}])
            );
            assert_eq!(runtime.store.next_at(WorkKind::Judge).unwrap(), scheduled);
            let events = runtime.store.events(100).unwrap();
            assert_eq!(
                events
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|event| event["event"] == "judging_assignment_excluded")
                    .count(),
                1
            );
            assert!(
                !events
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|event| event["event"] == "dispatch_intent")
            );
            runtime.store.set_paused(false).unwrap();
            judging_operation(&mut runtime, &allowed, "prepared");
            assert_eq!(runtime.store.pending().unwrap().unwrap().key, allowed);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cycle_preserves_excluded_ambiguous_judgments_and_reconciliation_bindings() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        for state in [
            "generating",
            "dispatching",
            "unknown",
            "queued",
            "included_pending",
        ] {
            let id = "a".repeat(64);
            let mut config = active_judge_config(credentials.path());
            config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
            config.excluded_judging_assignments = vec![id.clone()];
            let (_temp, mut runtime, _sender) = fixture_with(config);
            let mut op = judging_operation(&mut runtime, &id, state);
            if state == "queued" {
                op.job_id = Some("test-job".into());
            } else if state == "included_pending" {
                op.txid = Some("b".repeat(64));
            }
            op.next_at = not_before(86_400);
            runtime.store.save(&op, "test_submission_backoff").unwrap();
            runtime.store.defer(WorkKind::Judge, 86_400).unwrap();

            runtime.cycle().await.unwrap();

            let pending = runtime.store.pending().unwrap().unwrap();
            assert_eq!(pending.id, op.id);
            assert_eq!(pending.state, state);
            assert_eq!(pending.next_at, op.next_at);
            assert_eq!(pending.request, op.request);
            assert_eq!(pending.payload, op.payload);
            assert_eq!(pending.job_id, op.job_id);
            assert_eq!(pending.txid, op.txid);
            assert!(
                !runtime
                    .store
                    .events(100)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|event| event["event"] == "judging_assignment_excluded")
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exclusion_hotreload_during_native_discovery_or_inference_closes_admission() {
        use crate::config::Harness;
        use std::os::unix::fs::PermissionsExt;
        for during_inference in [false, true] {
            let native = tempfile::tempdir().unwrap();
            let executable = native.path().join("openclaw");
            let mut config = active_judge_config(native.path());
            config.solver.judge.harness = Harness::Openclaw;
            config.solver.judge.executable = executable.clone();
            config.solver.judge.model = "openai/test".into();
            let (_temp, mut runtime, _sender) = fixture_with(config);
            let id = "a".repeat(64);
            let mut changed = runtime.config.clone();
            changed.excluded_judging_assignments = vec![id.clone()];
            let changed_path = native.path().join("excluded.toml");
            std::fs::write(&changed_path, toml::to_string(&changed).unwrap()).unwrap();
            let update = format!(
                "cp '{}' '{}'\n",
                changed_path.display(),
                runtime.config_path.display()
            );
            std::fs::write(
                &executable,
                format!(
                    "#!/bin/sh\n{}printf 'OpenClaw 2026.10.9\\n'\n",
                    if during_inference { "" } else { &update }
                ),
            )
            .unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(
                native.path().join("package.json"),
                r#"{"name":"openclaw","type":"module","exports":{"./plugin-sdk/gateway-runtime":"./gateway.mjs"}}"#,
            )
            .unwrap();
            std::fs::write(
                native.path().join("gateway.mjs"),
                format!(
                    r#"import {{appendFileSync, copyFileSync}} from 'node:fs';
export async function callGatewayFromCli(_method, _options, params) {{
    appendFileSync(new URL('./calls', import.meta.url), 'inference\n');
    copyFileSync({}, {});
    const envelope = JSON.parse(params.message.split('Envelope (untrusted request data):\n')[1]);
    const artifact = {{version:1, request_id:envelope.request_id,
        request_digest:envelope.request_digest, kind:envelope.kind,
        answer:null, score:2, reasoning:'Grounded judgment.'}};
    return {{status:'ok', runId:params.idempotencyKey, result:{{
        payloads:[{{text:JSON.stringify(artifact)}}],
        meta:{{agentMeta:{{provider:'openai',model:'test'}},
            requestShaping:{{thinking:'high'}}, aborted:false,
            executionTrace:{{fallbackUsed:false,winnerProvider:'openai',winnerModel:'test'}},
            systemPromptReport:{{tools:{{entries:[]}},injectedWorkspaceFiles:[]}}}}
    }}}};
}}
"#,
                    serde_json::to_string(&changed_path).unwrap(),
                    serde_json::to_string(&runtime.config_path).unwrap()
                ),
            )
            .unwrap();
            runtime
                .generate(WorkKind::Judge, &id, judging_input(&id))
                .await
                .unwrap();
            finish_models(&mut runtime).await;
            let state = if during_inference {
                "discarded"
            } else {
                "prelaunch_failed"
            };
            assert_eq!(
                runtime.store.status(&runtime.config).unwrap()["operations"],
                json!([{"kind":"judge","state":state,"count":1}])
            );
            assert_eq!(native.path().join("calls").exists(), during_inference);
            let events = runtime.store.events(100).unwrap();
            assert!(
                !events
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|event| event["event"] == "dispatch_intent")
            );
            assert!(runtime.store.pending().unwrap().is_none());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exclusion_hotreload_at_final_dispatch_admission_discards_unsent_work() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let id = "a".repeat(64);
        let mut op = judging_operation(&mut runtime, &id, "generated");
        let mut changed = runtime.config.clone();
        changed.excluded_judging_assignments = vec![id.clone()];
        let path = runtime.config_path.clone();
        let server = tokio::spawn(async move {
            let prefix = format!("/chain/{}", changed.network.chain);
            judging_reply(
                &listener,
                &format!("{prefix}/api/hosted/assignments"),
                judging_inventory(&[id]).body,
                None,
            )
            .await;
            judging_reply(
                &listener,
                &format!("{prefix}/api/hosted/me"),
                json!({"address":changed.network.address}),
                Some((&path, &changed)),
            )
            .await;
        });
        runtime.dispatch(&mut op).await.unwrap();
        server.await.unwrap();
        assert_eq!(op.state, "discarded");
        assert!(runtime.store.pending().unwrap().is_none());
        assert!(
            !runtime
                .store
                .events(100)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["event"] == "dispatch_intent")
        );
    }

    #[tokio::test]
    async fn excluded_sent_judgment_keeps_job_receipt_and_unknown_reconciliation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let id = "a".repeat(64);
        let txid = "b".repeat(64);
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.excluded_judging_assignments = vec![id.clone()];
        let (_temp, mut runtime, _sender) = fixture_with(config);
        let mut op = judging_operation(&mut runtime, &id, "queued");
        op.job_id = Some("test-job".into());
        runtime.store.save(&op, "test_job_bound").unwrap();
        let server = tokio::spawn(async move {
            judging_reply(
                &listener,
                "/chain/poa-mainnet-1/api/job/test-job",
                json!({"ok":true, "state":"done", "id":txid}),
                None,
            )
            .await;
            judging_reply(
                &listener,
                &format!("/chain/poa-mainnet-1/api/receipt/{txid}"),
                json!({
                    "status":"included", "txid":txid, "next_nonce":4, "checkpoint_covered":true
                }),
                None,
            )
            .await;
        });
        runtime.reconcile(&mut op).await.unwrap();
        assert_eq!(op.state, "included_pending");
        runtime.reconcile(&mut op).await.unwrap();
        server.await.unwrap();
        assert_eq!(op.state, "final");
        let mut unknown = judging_operation(&mut runtime, &id, "unknown");
        runtime.reconcile(&mut unknown).await.unwrap();
        assert_eq!(runtime.store.pending().unwrap().unwrap().state, "unknown");
        assert_eq!(unknown.state, "unknown");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_failure_stays_unknown_without_retry_or_private_diagnostics() {
        use crate::config::{Harness, Mode};
        use std::os::unix::fs::PermissionsExt;

        let native = tempfile::tempdir().unwrap();
        let executable = native.path().join("openclaw");
        let calls = native.path().join("calls");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'OpenClaw 2026.10.9\\n'\n").unwrap();
        std::fs::write(
            native.path().join("package.json"),
            r#"{"name":"openclaw","type":"module","exports":{"./plugin-sdk/gateway-runtime":"./gateway.mjs"}}"#,
        ).unwrap();
        std::fs::write(
            native.path().join("gateway.mjs"),
            "import {appendFileSync} from 'node:fs';\nexport async function callGatewayFromCli() {\nappendFileSync(new URL('./calls', import.meta.url), 'attempt\\n');\nconsole.log('private-native-stdout-canary');\nconsole.error('private-native-stderr-canary');\nthrow new Error('private-native-canary');\n}\n",
        ).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = Config::default();
        config.network.chain = format!(
            "test-{}",
            native
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .replace('.', "")
        );
        config.network.address = format!("poa1{}", "1".repeat(32));
        config.network.credential_file = native.path().join("key");
        std::fs::write(&config.network.credential_file, "pk_test_fixture").unwrap();
        std::fs::set_permissions(
            &config.network.credential_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        config.capabilities.answer = Mode::Active;
        config.solver.answer.harness = Harness::Openclaw;
        config.solver.answer.executable = executable;
        config.solver.answer.model = "openai/test".into();
        config.preparation.max_attempts_per_work = 2;
        let (_temp, mut runtime, _signal) = fixture_with(config);
        let mut input = request(WorkKind::Answer);
        input.assignment = None;
        input.candidate = None;
        runtime
            .generate(
                WorkKind::Answer,
                "8:fixture",
                Input {
                    solver: input.clone(),
                    challenge_fingerprint: Some("fixture".into()),
                },
            )
            .await
            .unwrap();
        finish_models(&mut runtime).await;
        runtime.store.retry_models(&runtime.config).unwrap();
        runtime
            .generate(
                WorkKind::Answer,
                "8:fixture",
                Input {
                    solver: input,
                    challenge_fingerprint: Some("fixture".into()),
                },
            )
            .await
            .unwrap();
        assert!(runtime.preparations.is_empty());
        assert!(runtime.store.answer_epoch_attempted(8).unwrap());
        assert_eq!(std::fs::read_to_string(calls).unwrap(), "attempt\n");
        assert_eq!(
            runtime.store.status(&runtime.config).unwrap()["operations"],
            json!([{"kind":"answer", "state":"model_unknown", "count":1}])
        );
        let events = runtime.store.events(100).unwrap();
        assert!(
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["event"] == "openclaw_exception")
        );
        assert!(!events.to_string().contains("private-native"));
    }

    fn operation(runtime: &mut Runtime) -> Operation {
        let control = runtime.store.control().unwrap();
        let mut op = runtime
            .store
            .begin(
                WorkKind::Answer,
                "8:words",
                "prepared",
                &json!({}),
                control,
                "captured-revision",
            )
            .unwrap();
        op.state = "dispatching".into();
        runtime.store.save(&op, "dispatch_intent").unwrap();
        op
    }

    #[test]
    fn receipt_needs_positive_inclusion_and_nonce_evidence() {
        assert_eq!(
            receipt(&response(json!({"status":"included"})), "tx", "account"),
            Receipt::Unresolved
        );
        assert_eq!(
            receipt(
                &response(json!({"status":"included","valid_in_open_window":true})),
                "tx",
                "account"
            ),
            Receipt::Unresolved
        );
        assert_eq!(
            receipt(
                &response(json!({"status":"included","valid_in_open_window":true,"next_nonce":4})),
                "tx",
                "account"
            ),
            Receipt::Included
        );
        assert_eq!(
            receipt(
                &response(json!({"status":"included","checkpoint_covered":true,"next_nonce":4})),
                "tx",
                "account"
            ),
            Receipt::Final
        );
    }

    #[test]
    fn receipt_cannot_cross_known_transaction_or_case_sensitive_account() {
        let body =
            json!({"status":"included","valid_in_open_window":true,"next_nonce":4,"txid":"other"});
        assert_eq!(
            receipt(&response(body), "known", "Account"),
            Receipt::Unresolved
        );
        let body = json!({"status":"included","valid_in_open_window":true,"next_nonce":4,"address":"account"});
        assert_eq!(
            receipt(&response(body), "known", "Account"),
            Receipt::Unresolved
        );
        let missing = Response {
            status: 404,
            body: json!({"status":"rejected"}),
            retry_after_seconds: None,
            read_failure: None,
        };
        assert_eq!(receipt(&missing, "known", "Account"), Receipt::Unresolved);
        for field in ["txid", "address", "sender"] {
            let mut malformed = json!({
                "status":"included","valid_in_open_window":true,"next_nonce":4
            });
            malformed[field] = json!(17);
            assert_eq!(
                receipt(&response(malformed), "known", "Account"),
                Receipt::Unresolved
            );
        }
    }

    #[test]
    fn contradictory_receipts_cannot_release_the_effect_slot() {
        for status in ["included", "rejected"] {
            for field in ["ok", "success"] {
                for value in [json!(false), Value::Null, json!("true")] {
                    let mut body = json!({
                        "status":status,"checkpoint_covered":true,"next_nonce":4
                    });
                    body[field] = value;
                    assert_eq!(
                        receipt(&response(body), "known", "Account"),
                        Receipt::Unresolved
                    );
                }
            }
        }
    }

    #[test]
    fn generic_success_and_answered_flags_do_not_resolve_a_receipt() {
        assert_eq!(
            receipt(
                &response(json!({"ok":true,"answered":true})),
                "known",
                "account"
            ),
            Receipt::Unresolved
        );
        assert_eq!(
            receipt(&response(json!({"status":"rejected"})), "known", "account"),
            Receipt::Unresolved
        );
        assert_eq!(
            receipt(
                &response(json!({"status":"rejected","next_nonce":4})),
                "known",
                "account"
            ),
            Receipt::Rejected
        );
    }

    #[test]
    fn answer_constraints_use_protocol_utf16_and_substrings() {
        let mut request = request(WorkKind::Answer);
        assert!(payload(&request, &result()).is_ok());
        request.words.clear();
        request.min_chars = 2;
        request.max_chars = 2;
        let mut output = result();
        output.answer = Some("\u{1f600}".into());
        assert!(payload(&request, &output).is_ok());
        request.max_chars = 1;
        assert!(payload(&request, &output).is_err());
    }

    #[test]
    fn judgment_never_fabricates_score_or_reasoning() {
        let request = request(WorkKind::Judge);
        let mut output = result();
        assert_eq!(
            payload(&request, &output).unwrap()["assignment"],
            "assignment-test"
        );
        output.score = None;
        assert!(payload(&request, &output).is_err());
        output.score = Some(4);
        assert!(payload(&request, &output).is_err());
        output.score = Some(2);
        output.reasoning = Some(" ".into());
        assert!(payload(&request, &output).is_err());
    }

    #[test]
    fn grading_refresh_binds_exact_candidate_assignment_and_answer_epoch() {
        let request = request(WorkKind::Judge);
        let mut assignment = Assignment {
            id: "assignment-test".into(),
            epoch: 8,
            answer: "candidate-test".into(),
            words: vec!["burn".into()],
            expires_at_epoch: None,
            author: None,
            author_prior: Default::default(),
        };
        assert!(assignment_matches(&assignment, &request));
        assignment.epoch = 9;
        assert!(!assignment_matches(&assignment, &request));
        assignment.epoch = 8;
        assignment.answer.push('x');
        assert!(!assignment_matches(&assignment, &request));
    }

    #[test]
    fn mutable_model_settings_do_not_change_identity_but_address_case_does() {
        let mut original = Config::default();
        original.network.address = "AccountCase".into();
        let mut changed = original.clone();
        changed.solver.answer.model = "different-model".into();
        changed.capabilities.answer = Mode::Off;
        assert!(same_identity(&original, &changed));
        changed.network.address = "accountcase".into();
        assert!(!same_identity(&original, &changed));
    }

    #[test]
    fn local_status_and_events_do_not_initialize_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: temp.path().join("absent"),
            ..Config::default()
        };
        let status = status(&config).unwrap();
        assert_eq!(status["initialized"], false);
        assert_eq!(status.get("hosted_identity_verified"), Some(&Value::Null));
        assert_eq!(events(&config, 10).unwrap(), json!([]));
        assert_eq!(reads(&config).unwrap(), json!([]));
        assert!(!config.state_dir.exists());
    }

    #[test]
    fn queued_response_honors_retry_after_and_preserves_private_job() {
        let (_temp, mut runtime, _sender) = fixture();
        let mut op = operation(&mut runtime);
        let before = now();
        runtime
            .outcome(
                &mut op,
                Outcome::Queued {
                    job_id: "private-job".into(),
                },
                true,
                Some(90),
            )
            .unwrap();
        assert_eq!(op.state, "queued");
        assert!(op.next_at >= before + 90);
        assert_eq!(
            runtime.store.pending().unwrap().unwrap().job_id.as_deref(),
            Some("private-job")
        );
        runtime
            .outcome(
                &mut op,
                Outcome::Queued {
                    job_id: "other-job".into(),
                },
                false,
                None,
            )
            .unwrap();
        assert_eq!(op.state, "unknown");
        assert_eq!(op.job_id.as_deref(), Some("private-job"));
    }

    #[test]
    fn queued_retry_does_not_become_a_resubmission_intent() {
        let (_temp, mut runtime, _sender) = fixture();
        let mut op = operation(&mut runtime);
        runtime
            .outcome(
                &mut op,
                Outcome::Queued {
                    job_id: "private-job".into(),
                },
                true,
                None,
            )
            .unwrap();
        runtime
            .outcome(&mut op, Outcome::Retry { after_seconds: 120 }, false, None)
            .unwrap();
        assert_eq!(op.state, "queued");
        assert!(op.next_at >= now() + 119);
        runtime
            .outcome(
                &mut op,
                Outcome::Unknown {
                    reason: "private-upstream-message".into(),
                },
                false,
                None,
            )
            .unwrap();
        assert_eq!(op.state, "unknown");
        assert!(
            !runtime
                .store
                .events(100)
                .unwrap()
                .to_string()
                .contains("private-upstream-message")
        );
    }

    #[test]
    fn authoritative_bound_job_expiry_permits_a_fresh_submission_only() {
        let (_temp, mut runtime, _sender) = fixture();
        let mut op = operation(&mut runtime);
        op.job_id = Some("original-job".into());
        op.payload = Some(json!({"answer":"captured answer"}));
        op.state = "queued".into();
        runtime
            .outcome(&mut op, Outcome::Expired, false, Some(120))
            .unwrap();
        assert_eq!(op.state, "retry");
        assert!(op.job_id.is_none());
        assert_eq!(op.payload.as_ref().unwrap()["answer"], "captured answer");
        assert!(op.next_at >= now() + 120);
        op.state = "dispatching".into();
        runtime.store.save(&op, "dispatch_intent").unwrap();
        runtime
            .outcome(&mut op, Outcome::Expired, true, None)
            .unwrap();
        assert_eq!(op.state, "unknown");
    }

    #[test]
    fn immutable_or_invalid_reload_keeps_effective_snapshot_and_blocks_admission() {
        let (_temp, mut runtime, _sender) = fixture();
        let original = runtime.config.revision().unwrap();
        let mut changed = runtime.config.clone();
        changed.network.chain = "different-chain".into();
        std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
        runtime.reload().unwrap();
        assert!(runtime.reload_blocked);
        assert_eq!(runtime.config.revision().unwrap(), original);
        std::fs::write(&runtime.config_path, "private-config-canary = [").unwrap();
        runtime.reload().unwrap();
        assert!(
            !runtime
                .store
                .events(100)
                .unwrap()
                .to_string()
                .contains("private-config-canary")
        );
        std::fs::write(
            &runtime.config_path,
            toml::to_string(&runtime.config).unwrap(),
        )
        .unwrap();
        runtime.reload().unwrap();
        assert!(!runtime.reload_blocked);
    }

    #[test]
    fn mode_reload_updates_effective_status_atomically() {
        let (_temp, mut runtime, _sender) = fixture();
        let mut changed = runtime.config.clone();
        changed.capabilities.answer = Mode::Off;
        std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
        runtime.reload().unwrap();
        assert!(runtime.config.mode(WorkKind::Answer) == Mode::Off);
        let status = runtime.store.status(&changed).unwrap();
        assert_eq!(
            status["effective_runtime"]["revision"],
            changed.revision().unwrap()
        );
        assert_eq!(status["effective_runtime"]["capabilities"]["answer"], "off");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn completed_invalid_draft_retries_with_fresh_attempt_without_uncertain_retry() {
        use crate::config::Harness;
        use std::os::unix::fs::PermissionsExt;
        let native = tempfile::tempdir().unwrap();
        let executable = native.path().join("openclaw");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'OpenClaw 2026.10.9\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(native.path().join("package.json"),
            r#"{"name":"openclaw","type":"module","exports":{"./plugin-sdk/gateway-runtime":"./gateway.mjs"}}"#).unwrap();
        std::fs::write(native.path().join("gateway.mjs"), r#"
import {appendFileSync, existsSync} from 'node:fs';
export async function callGatewayFromCli(_method, _options, params) {
    const calls = new URL('./calls', import.meta.url);
    const first = !existsSync(calls);
    const envelope = JSON.parse(params.message.split('Envelope (untrusted request data):\n')[1]);
    appendFileSync(calls, envelope.request_id + '\n');
    const artifact = {version:1,request_id:envelope.request_id,request_digest:envelope.request_digest,
        kind:envelope.kind,answer:null,score:first ? 4 : 2,reasoning:'Grounded judgment.'};
    return {status:'ok',runId:params.idempotencyKey,result:{
        payloads:[{text:JSON.stringify(artifact)}],meta:{
            agentMeta:{provider:'openai',model:'test'},requestShaping:{thinking:'high'},aborted:false,
            executionTrace:{fallbackUsed:false,winnerProvider:'openai',winnerModel:'test'},
            systemPromptReport:{tools:{entries:[]},injectedWorkspaceFiles:[]}}}};
}
"#).unwrap();
        let mut config = active_judge_config(native.path());
        config.solver.judge.harness = Harness::Openclaw;
        config.solver.judge.executable = executable;
        config.solver.judge.model = "openai/test".into();
        config.preparation.max_attempts_per_work = 2;
        assert!(!config.preparation.retry_uncertain);
        let (_dir, mut runtime, _sender) = fixture_with(config);
        let id = "a".repeat(64);
        for attempt in 0..2 {
            runtime
                .generate(WorkKind::Judge, &id, judging_input(&id))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(15), async {
                while !runtime.preparations.is_empty() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    runtime.collect_models().await.unwrap();
                }
            })
            .await
            .unwrap();
            if attempt == 0 {
                assert!(
                    runtime
                        .store
                        .preparation(WorkKind::Judge)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    runtime.store.status(&runtime.config).unwrap()["operations"][0]["state"],
                    "rejected"
                );
                runtime.store.retry_models(&runtime.config).unwrap();
            }
        }
        let prepared = runtime.store.preparation(WorkKind::Judge).unwrap().unwrap();
        assert_eq!(prepared.state, "generated");
        assert_eq!(prepared.payload.unwrap()["score"], 2);
        assert!(runtime.store.effect().unwrap().is_none());
        let calls = std::fs::read_to_string(native.path().join("calls")).unwrap();
        let ids: Vec<_> = calls.lines().collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_recovery_rejects_unbound_candidates_and_resolves_bound_job_while_off() {
        let credentials = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = active_judge_config(credentials.path());
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer = Mode::Off;
        config.capabilities.judge = Mode::Off;
        config.capabilities.mine = Mode::Off;
        let (_dir, mut runtime, _sender) = fixture_with(config);
        let mut op = judging_operation(&mut runtime, &"a".repeat(64), "unknown");
        let path = runtime.config_path.clone();
        let config = runtime.config.clone();
        drop(AccountLock::adopt(&config).unwrap());
        let prefix = format!("GET /chain/{}", config.network.chain);
        assert!(
            recovery_resolve(&path, op.id, Some("guessed-job"), None)
                .await
                .is_err()
        );
        assert_eq!(runtime.store.effect().unwrap().unwrap().state, "unknown");
        op.job_id = Some("bound-job".into());
        op.state = "queued".into();
        runtime.store.save(&op, "test_bound_job").unwrap();
        assert!(
            recovery_resolve(&path, op.id, Some("different-job"), None)
                .await
                .is_err()
        );
        let txid = "b".repeat(64);
        let address = config.network.address.clone();
        let server = tokio::spawn(async move {
            api_reply(
                &listener,
                &format!("{prefix}/api/hosted/me"),
                200,
                None,
                json!({"address":address}),
            )
            .await;
            api_reply(
                &listener,
                &format!("{prefix}/api/job/bound-job"),
                200,
                None,
                json!({"state":"done","ok":true,"id":txid}),
            )
            .await;
            api_reply(
                &listener,
                &format!("{prefix}/api/receipt/{txid}"),
                200,
                None,
                json!({"txid":txid,"sender":address,"status":"included","next_nonce":3,
                    "valid_in_open_window":true,"checkpoint_covered":true}),
            )
            .await;
        });
        drop(runtime);
        let result = recovery_resolve(&path, op.id, Some("bound-job"), None)
            .await
            .unwrap();
        assert_eq!(result["resolved"], true);
        assert_eq!(result["state"], "final");
        server.await.unwrap();
        assert!(
            !status(&config).unwrap()["admission_blocked"]
                .as_bool()
                .unwrap()
        );
    }
}
