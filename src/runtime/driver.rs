use super::*;

impl HostAccess {
    pub(super) fn new(
        config_path: PathBuf,
        config: Config,
        protocol: Arc<Protocol>,
        store: Store,
        stop: watch::Receiver<bool>,
        controller: bool,
    ) -> Result<Self> {
        let authority = authority_fingerprint(&config, &protocol)?;
        let authority_epoch = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let authority_instance = digest(format!(
            "{}:{authority_epoch}:{authority}",
            std::process::id()
        ));
        store.set_authority_epoch(authority_epoch)?;
        Ok(Self {
            config_path,
            config,
            protocol,
            store,
            stop,
            controller,
            reload_blocked: false,
            authority,
            authority_instance,
            authority_epoch,
            sequence: 0,
            wake: Arc::new(Notify::new()),
            lanes: NativeLanes::default(),
            recovery: LaneId::ALL
                .into_iter()
                .map(|_| Recovery::default())
                .collect(),
            identity: None,
            permit: None,
            effect: None,
            once: None,
            identity_nonblocking: false,
        })
    }

    pub(in crate::runtime) fn stopping(&self) -> bool {
        *self.stop.borrow()
    }

    pub(in crate::runtime) fn active(&self, kind: LaneId) -> Result<bool> {
        Ok(self.controller
            && !self.stopping()
            && !self.reload_blocked
            && self.config.mode(kind) == Mode::Active
            && !self.store.control()?.paused
            && !self.store.lane_control(kind)?.paused)
    }

    pub(in crate::runtime) fn heartbeat(&self) -> Result<()> {
        if self.controller {
            self.store.heartbeat()?;
        }
        Ok(())
    }

    pub(in crate::runtime) fn reload(&mut self) -> Result<()> {
        if !self.controller {
            return Ok(());
        }
        let candidate = Config::load(&self.config_path).and_then(|config| {
            config.validate()?;
            if !same_identity(&self.config, &config) {
                bail!("immutable runtime identity changed");
            }
            let protocol = Protocol::reload(&config, &self.protocol)?;
            let authority = authority_fingerprint(&config, &protocol)?;
            Ok((config, protocol, authority))
        });
        match candidate {
            Ok((config, protocol, authority)) => {
                let changed = config.revision()? != self.config.revision()?;
                if authority != self.authority {
                    self.authority_epoch = self
                        .authority_epoch
                        .checked_add(1)
                        .context("authority epoch exhausted")?;
                    self.store.set_authority_epoch(self.authority_epoch)?;
                    self.authority = authority;
                    self.protocol = Arc::new(protocol);
                    self.permit = None;
                }
                if changed {
                    self.config = config;
                    self.store.reschedule_all_reads(&self.config)?;
                    self.store.event("config_reloaded", None)?;
                }
                if self.reload_blocked {
                    self.store.event("config_reload_recovered", None)?;
                }
                self.reload_blocked = false;
            }
            Err(_) => {
                if !self.reload_blocked {
                    self.store.event("config_reload_rejected", None)?;
                }
                self.reload_blocked = true;
                self.permit = None;
            }
        }
        Ok(())
    }

    pub(in crate::runtime) fn gate(&self) -> Result<Option<AccountAdmissionGuard>> {
        if self.effect.is_some() || self.stopping() {
            return Ok(None);
        }
        match AccountAdmissionGuard::try_acquire(&self.config) {
            Ok(guard) => Ok(Some(guard)),
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::WouldBlock)
                }) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(in crate::runtime) fn retry_delay(&self, kind: LaneId, minimum: Option<u64>) -> u64 {
        self.config
            .schedule(kind)
            .retry_seconds
            .max(minimum.unwrap_or(0))
            .saturating_add(self.jitter(kind, "retry"))
    }

    pub(in crate::runtime) fn jitter(&self, kind: LaneId, phase: &str) -> u64 {
        stagger(
            &self.config,
            self.config.schedule(kind).jitter_seconds,
            &format!("{}:{phase}", kind.as_str()),
        )
    }

    pub(in crate::runtime) fn discovery_key(kind: LaneId) -> ReadKey {
        ReadKey::Discovery {
            lane: kind,
            source: if kind == LaneId::Judge {
                DiscoverySource::Assignments
            } else {
                DiscoverySource::Challenge
            },
        }
    }

    pub(in crate::runtime) fn discovery_allowed(&self, kind: LaneId) -> Result<bool> {
        Ok(!self.stopping()
            && self.config.mode(kind) != Mode::Off
            && self.store.next_at(kind)? <= self.deadline_now()
            && self
                .once
                .as_ref()
                .is_none_or(|plan| plan.lane(kind).discovery))
    }

    pub(in crate::runtime) fn discovered(&mut self, kind: LaneId) -> Result<()> {
        if let Some(plan) = self.once.as_mut() {
            plan.lane_mut(kind).discovery = false;
        }
        self.store.defer(
            kind,
            self.config
                .schedule(kind)
                .poll_seconds
                .saturating_add(self.jitter(kind, "poll")),
        )
    }

    pub(in crate::runtime) fn model_allowed(&self, kind: LaneId) -> bool {
        self.once
            .as_ref()
            .is_none_or(|plan| plan.lane(kind).model && plan.lane(kind).effect)
    }

    pub(in crate::runtime) fn effect_allowed(&self, kind: LaneId) -> bool {
        self.once.as_ref().is_none_or(|plan| plan.lane(kind).effect)
    }

    pub(in crate::runtime) fn deadline_now(&self) -> i64 {
        self.once.as_ref().map_or_else(now, |plan| plan.entry_at)
    }

    pub(in crate::runtime) fn admission_allowed(&self, op: &Operation) -> Result<bool> {
        if !self.store.admission_allowed(&self.config, op)? {
            return Ok(false);
        }
        if let Some(plan) = self.once.as_ref() {
            return self
                .store
                .admission_allowed_at(&plan.entry_config, op, plan.cutoff);
        }
        Ok(true)
    }

    pub(in crate::runtime) fn preparation_allowed(&self, kind: LaneId, epoch: u64) -> Result<bool> {
        if !self
            .store
            .preparation_allowed(&self.config, kind, Some(epoch))?
        {
            return Ok(false);
        }
        if let Some(plan) = self.once.as_ref() {
            return self.store.preparation_allowed_at(
                &plan.entry_config,
                kind,
                Some(epoch),
                plan.cutoff,
            );
        }
        Ok(true)
    }

    pub(in crate::runtime) fn answer_retry_allowed(&self, original: &Operation) -> Result<bool> {
        if !self.store.answer_retry_allowed(&self.config, original)? {
            return Ok(false);
        }
        if let Some(plan) = self.once.as_ref() {
            return self
                .store
                .answer_retry_allowed_at(&plan.entry_config, original, plan.cutoff);
        }
        Ok(true)
    }

    pub(in crate::runtime) fn model_attempt_limit(&self, kind: LaneId) -> Result<u32> {
        let current = self
            .config
            .preparation(kind)
            .context("model preparation missing")?
            .max_attempts_per_work;
        Ok(self
            .once
            .as_ref()
            .and_then(|plan| plan.entry_config.preparation(kind))
            .map_or(current, |entry| current.min(entry.max_attempts_per_work)))
    }

    pub(in crate::runtime) fn fresh_allowed(&mut self, kind: LaneId, id: i64) -> bool {
        if !self.effect_allowed(kind) {
            return false;
        }
        self.once
            .as_mut()
            .is_none_or(|plan| plan.lane_mut(kind).fresh.insert(id))
    }

    pub(in crate::runtime) fn draft_current(&self, op: &Operation) -> Result<bool> {
        Ok(self.store.operation(op.id)?.is_some_and(|current| {
            current.state == op.state
                && current.binding_revision == op.binding_revision
                && current.generation == op.generation
        }))
    }

    pub(in crate::runtime) fn request_id(&self, kind: LaneId, key: &str) -> Result<String> {
        Ok(digest(format!(
            "{}\n{}\n{}\n{}\n{}",
            self.config.network.chain,
            self.config.network.address,
            kind.as_str(),
            key,
            self.store.control()?.generation
        )))
    }

    pub(in crate::runtime) fn challenge_input(
        &self,
        kind: LaneId,
        challenge: &Challenge,
    ) -> Result<Input> {
        Ok(Input {
            challenge_fingerprint: Some(challenge.fingerprint.clone()),
            solver: SolverRequest {
                id: self.request_id(kind, &challenge.fingerprint)?,
                kind,
                epoch: challenge.epoch,
                words: challenge.words.clone(),
                min_chars: challenge.min_chars,
                max_chars: challenge.max_chars,
                assignment: None,
                candidate: None,
                history: if kind == LaneId::Answer {
                    self.store.history()?
                } else {
                    Vec::new()
                },
                guidance: String::new(),
                core_guidance: String::new(),
                author_history: None,
                candidate_author: None,
            },
        })
    }

    pub(in crate::runtime) fn current_preparation(
        &mut self,
        kind: LaneId,
    ) -> Result<Option<Operation>> {
        let Some(op) = self.store.preparation(kind)? else {
            return Ok(None);
        };
        if op.state == "generating" {
            return Ok(None);
        }
        if op.generation != self.store.control()?.generation
            || self.config.mode(kind) == Mode::Off
            || (kind == LaneId::Judge && self.config.judging_assignment_excluded(&op.key))
            || self
                .store
                .operation_lane_revision(&self.store.operation_binding(&op)?)?
                != self.config.lane_revision(kind)?
        {
            let binding = self.store.operation_binding(&op)?;
            self.store
                .retire_unsent(&binding, "unsent_admission_closed")?;
            return Ok(None);
        }
        Ok(Some(op))
    }

    pub(in crate::runtime) fn ready_current(&self, ready: &ReadyEffect) -> Result<bool> {
        Ok(self.active(ready.op.kind)?
            && self.effect_allowed(ready.op.kind)
            && self.scoped_observation_current(ready.op.kind, &ready.observation)?
            && self.draft_current(&ready.op)?)
    }
    pub(in crate::runtime) fn any_handles(&self) -> bool {
        self.identity.is_some()
            || self.effect.is_some()
            || self.lanes.busy()
            || self
                .recovery
                .iter()
                .any(|recovery| !recovery.reads.is_empty())
    }
    pub(in crate::runtime) async fn collect(&mut self) -> Result<()> {
        self.collect_identity()?;
        self.collect_effect()?;
        let mut lanes = std::mem::take(&mut self.lanes);
        let result = lanes.iter_mut().try_for_each(|mut lane| lane.collect(self));
        self.lanes = lanes;
        result
    }
    pub(in crate::runtime) fn plan(&mut self) -> Result<()> {
        self.refresh_idle_identity()?;
        self.store.retry_models(&self.config)?;
        let mut lanes = std::mem::take(&mut self.lanes);
        let result = lanes.iter_mut().try_for_each(|mut lane| lane.advance(self));
        self.lanes = lanes;
        result?;
        self.record_admission_observations()?;
        self.arbitrate()
    }

    pub(in crate::runtime) async fn run_loop(&mut self, once: bool) -> Result<()> {
        self.identity_nonblocking = self.controller && !once;
        self.store.reschedule_all_reads(&self.config)?;
        if once {
            self.once = Some(OncePlan::capture(self)?);
        }
        loop {
            self.store.continuity()?;
            let before = self.store.work_revision()?;
            // Every completion turn ingests assembled safety evidence before any launch.
            self.collect().await?;
            self.reload()?;
            self.store
                .runtime_state(&self.config, self.reload_blocked)?;
            if self.stopping() {
                break;
            }
            self.plan()?;
            if self.store.work_revision()? != before {
                continue;
            }
            if once && !self.any_handles() {
                break;
            }
            let wake = Arc::clone(&self.wake);
            let seconds = if once {
                1
            } else {
                self.store.wake_delay(&self.config, 1)?.max(1)
            };
            tokio::select! {
                biased;
                _ = self.stop.changed() => {},
                _ = wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(seconds)) => {},
            }
        }
        self.shutdown().await?;
        self.store.event("runtime_stopped", None)?;
        Ok(())
    }

    pub(in crate::runtime) async fn shutdown(&mut self) -> Result<()> {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.config.runtime.shutdown_seconds);
        while self.any_handles() {
            self.collect().await?;
            if !self.any_handles() {
                break;
            }
            let wake = Arc::clone(&self.wake);
            tokio::select! {
                _ = wake.notified() => {},
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        self.collect().await?;
        if let Some(read) = self.identity.as_mut() {
            read.flight.abort().await;
        }
        self.collect_identity()?;
        if let Some(read) = self.identity.take() {
            self.store.cancel_read(&read.flight.key)?;
        }
        self.permit = None;
        let mut lanes = std::mem::take(&mut self.lanes);
        let mut result = Ok(());
        for mut lane in lanes.iter_mut() {
            if let Err(error) = lane.stop(self).await {
                result = Err(error);
                break;
            }
        }
        self.lanes = lanes;
        result?;
        if let Some(effect) = self.effect.as_mut() {
            effect.task.abort();
            let _ = (&mut effect.task).await;
        }
        self.collect_effect()?;
        if let Some(effect) = self.effect.take() {
            self.finish_effect(effect, Err(anyhow::anyhow!("shutdown outcome unknown")))?;
        }
        Ok(())
    }
}

pub(in crate::runtime) struct OnceLane {
    pub(in crate::runtime) discovery: bool,
    pub(in crate::runtime) model: bool,
    pub(in crate::runtime) effect: bool,
    pub(in crate::runtime) recovery: Vec<i64>,
    pub(in crate::runtime) reads: Vec<ReadKey>,
    pub(in crate::runtime) hydrations: usize,
    pub(in crate::runtime) fresh: std::collections::HashSet<i64>,
}
pub(in crate::runtime) struct OncePlan {
    lanes: Vec<OnceLane>,
    pub(in crate::runtime) entry_at: i64,
    pub(in crate::runtime) entry_config: Config,
    pub(in crate::runtime) cutoff: AdmissionCutoff,
}
impl OncePlan {
    pub(in crate::runtime) fn capture(runtime: &HostAccess) -> Result<Self> {
        let cutoff = runtime.store.admission_cutoff()?;
        let entry_at = cutoff.at;
        let capture = |kind| -> Result<OnceLane> {
            Ok(OnceLane {
                discovery: runtime.config.mode(kind) != Mode::Off
                    && runtime.store.next_at(kind)? <= entry_at,
                model: runtime.config.mode(kind) == Mode::Active,
                effect: runtime.config.mode(kind) == Mode::Active,
                recovery: runtime
                    .store
                    .reconciliation_batch(kind)?
                    .into_iter()
                    .map(|op| op.id)
                    .collect(),
                reads: Vec::new(),
                hydrations: 0,
                fresh: std::collections::HashSet::new(),
            })
        };
        Ok(Self {
            lanes: LaneId::ALL
                .into_iter()
                .map(capture)
                .collect::<Result<_>>()?,
            entry_at,
            cutoff,
            entry_config: runtime.config.clone(),
        })
    }
    pub(in crate::runtime) fn lane(&self, kind: LaneId) -> &OnceLane {
        &self.lanes[crate::runtime::registry::lane_index(kind)]
    }
    pub(in crate::runtime) fn lane_mut(&mut self, kind: LaneId) -> &mut OnceLane {
        &mut self.lanes[crate::runtime::registry::lane_index(kind)]
    }
}
