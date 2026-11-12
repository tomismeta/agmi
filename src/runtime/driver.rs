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
            && self.store.discovery_next_at(
                &self.config,
                kind,
                &self.store.read_backoff(&Self::discovery_key(kind))?,
            )? <= self.deadline_now()
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
                .discovery_poll_seconds(kind, self.jitter(kind, "poll")),
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

    pub(in crate::runtime) fn model_attempt_limit(
        &self,
        kind: LaneId,
    ) -> Result<crate::config::CountLimit> {
        let current = self
            .config
            .preparation(kind)
            .context("model preparation missing")?
            .max_attempts_per_work;
        Ok(self
            .once
            .as_ref()
            .and_then(|plan| plan.entry_config.preparation(kind))
            .map_or(current, |entry| {
                current.intersect(entry.max_attempts_per_work)
            }))
    }

    pub(in crate::runtime) fn model_retry_blocker(
        &self,
        kind: LaneId,
        key: &str,
    ) -> Result<Option<&'static str>> {
        let current =
            self.store
                .model_retry_assessment(kind, key, &self.config, self.deadline_now())?;
        if current.blocker.is_some() {
            return Ok(current.blocker);
        }
        if let Some(plan) = &self.once {
            return Ok(self
                .store
                .model_retry_assessment(kind, key, &plan.entry_config, plan.entry_at)?
                .blocker);
        }
        Ok(None)
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
            || !self
                .store
                .operation_config_current(&self.config, &self.store.operation_binding(&op)?)?
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
        self.collect().await?;
        if let Some(read) = self.identity.as_mut() {
            read.flight.abort(deadline).await;
        }
        self.collect_identity()?;
        if let Some(read) = self.identity.take() {
            self.store.cancel_read(&read.flight.key)?;
        }
        self.permit = None;
        let mut lanes = std::mem::take(&mut self.lanes);
        let mut result = Ok(());
        for mut lane in lanes.iter_mut() {
            if let Err(error) = lane.stop(self, deadline).await {
                result = Err(error);
            }
        }
        self.lanes = lanes;
        // Only an already-sent effect needs a drain window. Unrelated reads and
        // model work have been cancelled without releasing its admission gates.
        while self.effect.is_some() {
            self.collect_effect()?;
            if self.effect.is_none() {
                break;
            }
            let wake = Arc::clone(&self.wake);
            tokio::select! {
                _ = wake.notified() => {},
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        if let Some(effect) = self.effect.as_mut() {
            effect.task.abort();
            let _ = tokio::time::timeout_at(deadline, &mut effect.task).await;
        }
        self.collect_effect()?;
        if let Some(effect) = self.effect.take() {
            self.finish_effect(effect, Err(anyhow::anyhow!("shutdown outcome unknown")))?;
        }
        // Cleanup cannot delay an assembled effect or its conservative unknown
        // bookkeeping, and gets only the remainder of the original drain window.
        let cleanup = crate::solver::drain_native_cleanup_until(deadline).await;
        result?;
        if !cleanup? {
            self.store.event("native_cleanup_deadline", None)?;
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
                    && runtime.store.discovery_next_at(
                        &runtime.config,
                        kind,
                        &runtime
                            .store
                            .read_backoff(&HostAccess::discovery_key(kind))?,
                    )? <= entry_at,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::host::tests::{accept, fixture_with, identity_fixture, reply};

    fn challenge_response(epoch: u64, answered: bool) -> Response {
        Response {
            status: 200,
            body: json!({"epoch":epoch,"words":["burn"],"min_chars":4,"max_chars":100,
                "answered":answered}),
            retry_after_seconds: None,
            read_failure: None,
        }
    }

    #[tokio::test]
    async fn challenge_drafts_revalidate_while_blocked_without_discarding_reusable_work() {
        for lane in [LaneId::Answer, LaneId::Mine] {
            for scenario in [
                "capacity_unchanged",
                "capacity_changed",
                "accepted",
                "operation_floor",
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut config = Config::default();
                config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
                config.capabilities.answer.timeouts.read_http_seconds = 7;
                config
                    .capabilities
                    .answer
                    .schedule
                    .observation_max_age_seconds = 40;
                config.capabilities.answer.mode = Mode::Off;
                config.capabilities.judge.mode = Mode::Off;
                config.capabilities.mine.mode = Mode::Off;
                match lane {
                    LaneId::Answer => {
                        config.capabilities.answer.mode = Mode::Active;
                        config
                            .capabilities
                            .answer
                            .participation
                            .max_unresolved_operations = 1.into();
                    }
                    LaneId::Mine => {
                        config.capabilities.mine.mode = Mode::Active;
                        config
                            .capabilities
                            .mine
                            .participation
                            .max_unresolved_operations = 1.into();
                        config.capabilities.mine.schedule.each_epoch = true;
                    }
                    LaneId::Judge => unreachable!(),
                }
                let (_temp, mut runtime, _stop) = fixture_with(config);
                identity_fixture(&mut runtime, &listener).await;
                runtime.store.defer(lane, 3600).unwrap();
                let original = parse_challenge(&challenge_response(8, false)).unwrap();
                let input = serde_json::to_value(runtime.challenge_input(lane, &original).unwrap())
                    .unwrap();
                let revision = runtime.config.lane_revision(lane).unwrap();
                let mut prior = runtime
                    .store
                    .seed_operation_for_test(
                        lane,
                        if scenario == "accepted" {
                            "8:prior"
                        } else {
                            "7:prior"
                        },
                        "prepared",
                        &input,
                        runtime.store.control().unwrap(),
                        &revision,
                    )
                    .unwrap();
                prior.state = "dispatching".into();
                runtime
                    .store
                    .seed_transition_for_test(&prior, "fixture_prior_dispatch")
                    .unwrap();
                prior.state = if scenario == "accepted" {
                    "confirmed"
                } else {
                    "unknown"
                }
                .into();
                prior.next_at = now() + 3600;
                if scenario == "accepted" {
                    prior.txid = Some("a".repeat(64));
                }
                runtime
                    .store
                    .seed_transition_for_test(&prior, "fixture_prior_effect")
                    .unwrap();
                let mut draft = runtime
                    .store
                    .seed_operation_for_test(
                        lane,
                        "8:draft",
                        "prepared",
                        &input,
                        runtime.store.control().unwrap(),
                        &revision,
                    )
                    .unwrap();
                draft.payload =
                    (lane == LaneId::Answer).then(|| json!({"answer":"burning answer"}));
                if scenario == "operation_floor" {
                    draft.next_at = now() + 3600;
                }
                runtime
                    .store
                    .seed_transition_for_test(&draft, "fixture_unsent_draft")
                    .unwrap();
                assert!(
                    !runtime.admission_allowed(&draft).unwrap(),
                    "{lane:?}: {scenario}"
                );
                runtime.plan().unwrap();
                if scenario == "operation_floor" {
                    assert!(
                        !runtime.lanes.busy(),
                        "operation floors still prevent early refresh"
                    );
                } else {
                    assert!(
                        runtime.lanes.busy(),
                        "blocked admission cannot prevent revalidation"
                    );
                    let (stream, request) = accept(&listener).await;
                    assert!(request.contains("/challenge"), "{request}");
                    let changed = scenario != "capacity_unchanged";
                    let response = challenge_response(
                        if changed && lane == LaneId::Mine {
                            9
                        } else {
                            8
                        },
                        changed && lane == LaneId::Answer,
                    );
                    reply(stream, 200, None, response.body).await;
                    tokio::time::timeout(Duration::from_secs(5), async {
                        while runtime.lanes.busy() {
                            runtime.collect().await.unwrap();
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                }
                if scenario != "operation_floor" {
                    let status = runtime.store.status(&runtime.config).unwrap();
                    let assessment = &status["lane_participation"][lane.as_str()]["assessment"];
                    assert_eq!(
                        assessment["valid_until"].as_i64().unwrap(),
                        assessment["observed_at"].as_i64().unwrap()
                            + runtime.config.schedule(lane).observation_max_age_seconds as i64,
                    );
                }
                let retained = runtime.store.operation(draft.id).unwrap().unwrap();
                let retired = matches!(scenario, "capacity_changed" | "accepted");
                assert_eq!(
                    retained.state,
                    if retired { "discarded" } else { "prepared" }
                );
                assert_eq!(
                    runtime.store.operation(prior.id).unwrap().unwrap().state,
                    prior.state
                );
                if !retired {
                    assert_eq!(
                        runtime.current_preparation(lane).unwrap().unwrap().id,
                        draft.id
                    );
                } else {
                    assert!(runtime.current_preparation(lane).unwrap().is_none());
                }
                assert!(
                    runtime.effect.is_none(),
                    "revalidation is not dispatch authority"
                );
                runtime.shutdown().await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn once_inventory_continuation_survives_runtime_and_journal_reopen() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer.mode = Mode::Off;
        config.capabilities.judge.mode = Mode::ReadOnly;
        config.capabilities.mine.mode = Mode::Off;
        let (_temp, mut runtime, _stop) = fixture_with(config);
        // Cross the former protocol offset ceiling using real page progress,
        // then require the reopened runtime to fetch the persisted tail.
        runtime.store.set_judge_inventory_offset(9_700).unwrap();
        let config = runtime.config.clone();
        let path = runtime.config_path.clone();
        let server = tokio::spawn(async move {
            for offset in [9_700, 9_800, 9_900, 10_000, 10_100] {
                let (stream, request) = accept(&listener).await;
                assert!(request.contains(&format!("offset={offset}")), "{request}");
                let rows = if offset == 10_100 {
                    vec![json!({"answer_txid":"f".repeat(64),"answer_epoch":8,
                        "answer":"tail candidate","words":["tail"]})]
                } else {
                    (1..=100)
                        .map(|id| {
                            json!({
                                "answer_txid":format!("{id:064x}"),"answer_epoch":8,
                                "answer":"burning candidate","words":["burn"]
                            })
                        })
                        .collect::<Vec<_>>()
                };
                reply(
                    stream,
                    200,
                    None,
                    json!({
                        "assignments":rows,"has_more":offset != 10_100,
                    }),
                )
                .await;
            }
        });
        tokio::time::timeout(Duration::from_secs(10), runtime.run_loop(true))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runtime.store.judge_inventory_offset().unwrap(), 10_100);
        drop(runtime);
        let (_writer, store) = AccountLock::acquire(&config).unwrap();
        assert_eq!(store.judge_inventory_offset().unwrap(), 10_100);
        store.defer_until(LaneId::Judge, now() - 1).unwrap();
        let (_sender, stop) = watch::channel(false);
        let mut restarted = HostAccess::new(
            path,
            config.clone(),
            Arc::new(Protocol::new(&config).unwrap()),
            store,
            stop,
            true,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), restarted.run_loop(true))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restarted.store.judge_inventory_offset().unwrap(), 0);
        let status = restarted.store.status(&config).unwrap();
        assert_eq!(
            status["work"]["judge"]["assessment"]["observed_opportunities"],
            1
        );
        assert_eq!(
            status["work"]["judge"]["assessment"]["completeness"],
            "bounded_partial"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn observation_age_uses_original_completion_and_not_transport_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.answer.timeouts.read_http_seconds = 7;
        config
            .capabilities
            .answer
            .schedule
            .observation_max_age_seconds = 40;
        let (_temp, mut runtime, _stop) = fixture_with(config);
        let mut flight = runtime.begin_challenge(LaneId::Answer).unwrap().unwrap();
        let (stream, _) = accept(&listener).await;
        reply(stream, 200, None, challenge_response(8, false).body).await;
        tokio::time::timeout(Duration::from_secs(5), &mut flight.task)
            .await
            .unwrap()
            .unwrap();
        let result = flight.take().unwrap();
        runtime
            .finish_scoped_read(LaneId::Answer, &flight, result)
            .unwrap();
        let observation = runtime.read_observation(LaneId::Answer, &flight).unwrap();
        assert_eq!(
            observation.admit_before,
            flight.completed().unwrap() + Duration::from_secs(40)
        );
        assert_eq!(observation.admit_before_unix, flight.completed_at + 40);
        runtime.discovered(LaneId::Answer).unwrap();
        assert!(runtime.store.next_at(LaneId::Answer).unwrap() <= now() + 21);
        let mut expired = observation;
        expired.admit_before = Instant::now() - Duration::from_secs(1);
        assert!(
            !runtime
                .scoped_observation_current(LaneId::Answer, &expired)
                .unwrap()
        );
    }
}
