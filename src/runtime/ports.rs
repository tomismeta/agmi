use super::*;
use crate::config::{AnswerConfig, JudgeConfig};
use crate::protocol::{AnswerIntent, EffectIntent, GradeIntent, MineIntent};
use crate::runtime::registry::lane_index;
use crate::solver::contract::{AnswerTask, GradeTask};
use crate::store::{AdmissionObservation, LaneAdmissionGuard, PreparationInputs};

impl HostAccess {
    pub(in crate::runtime) fn answer_config(&self) -> &AnswerConfig {
        &self.config.capabilities.answer
    }
    pub(in crate::runtime) fn grade_config(&self) -> &JudgeConfig {
        &self.config.capabilities.judge
    }
    pub(in crate::runtime) fn lane_revision(&self, lane: LaneId) -> Result<String> {
        self.config.lane_revision(lane)
    }
    pub(in crate::runtime) fn admission_stamp(
        &self,
        lane: LaneId,
    ) -> Result<AdmissionStampSnapshot> {
        Ok(AdmissionStampSnapshot {
            account_generation: self.store.control()?.generation,
            lane_control_revision: self.store.lane_control(lane)?.control_revision,
            authority_epoch: self.authority_epoch,
            lane_config_revision: self.config.lane_revision(lane)?,
        })
    }
    pub(in crate::runtime) fn lane_gates(
        &self,
        lane: LaneId,
    ) -> Result<Option<(AccountAdmissionGuard, LaneAdmissionGuard)>> {
        let Some(account) = self.gate()? else {
            return Ok(None);
        };
        match LaneAdmissionGuard::try_acquire(&self.config, lane) {
            Ok(gate) => Ok(Some((account, gate))),
            Err(error) if gate_busy(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn validate_binding(&self, lane: LaneId, binding: &OperationBinding) -> Result<Operation> {
        anyhow::ensure!(binding.lane_id == lane, "operation lane binding mismatch");
        let op = self
            .store
            .operation(binding.operation_id)?
            .context("operation missing")?;
        anyhow::ensure!(
            self.store.operation_binding(&op)? == *binding,
            "operation account or revision binding mismatch"
        );
        Ok(op)
    }
    pub(in crate::runtime) fn scoped_binding(
        &self,
        lane: LaneId,
        op: &Operation,
    ) -> Result<OperationBinding> {
        anyhow::ensure!(op.kind == lane, "operation lane mismatch");
        let binding = self.store.operation_binding(op)?;
        self.validate_binding(lane, &binding)?;
        Ok(binding)
    }
    pub(in crate::runtime) fn scoped_draft_current(
        &self,
        lane: LaneId,
        binding: &OperationBinding,
    ) -> Result<bool> {
        let op = self.validate_binding(lane, binding)?;
        Ok(matches!(
            op.state.as_str(),
            "generating" | "generated" | "prepared" | "retry"
        ) && op.generation == self.store.control()?.generation)
    }
    pub(in crate::runtime) fn retire_unsent(
        &mut self,
        lane: LaneId,
        binding: &OperationBinding,
        reason: &'static str,
    ) -> Result<()> {
        self.validate_binding(lane, binding)?;
        self.store.retire_unsent(binding, reason)
    }
    pub(in crate::runtime) fn has_preparation(&self, lane: LaneId) -> Result<bool> {
        Ok(self.store.preparation(lane)?.is_some())
    }
    pub(in crate::runtime) fn effect_busy(&self) -> bool {
        self.effect.is_some()
    }
    pub(in crate::runtime) fn scoped_ready_current(
        &self,
        lane: LaneId,
        ready: &ReadyEffect,
    ) -> Result<bool> {
        self.scoped_binding(lane, &ready.op)?;
        self.ready_current(ready)
    }
    fn validate_read(&self, lane: LaneId, flight: &ReadFlight) -> Result<()> {
        let owned = match &flight.key {
            ReadKey::Discovery { lane: owner, .. } => *owner == lane,
            ReadKey::Assignment { .. } => lane == LaneId::Judge,
            _ => false,
        };
        anyhow::ensure!(owned, "read flight is not owned by lane");
        Ok(())
    }
    pub(in crate::runtime) fn read_observation(
        &self,
        lane: LaneId,
        flight: &ReadFlight,
    ) -> Result<Observation> {
        self.validate_read(lane, flight)?;
        let completed = flight.completed()?;
        let budget = Duration::from_secs(self.config.schedule(lane).observation_max_age_seconds);
        Ok(Observation {
            stamp: flight
                .lane_stamp
                .clone()
                .context("lane observation stamp missing")?,
            admit_before: completed + budget,
            admit_before_unix: flight
                .completed_at
                .saturating_add(i64::try_from(budget.as_secs()).unwrap_or(i64::MAX)),
        })
    }
    pub(in crate::runtime) fn scoped_observation_current(
        &self,
        lane: LaneId,
        observation: &Observation,
    ) -> Result<bool> {
        Ok(observation.stamp == self.admission_stamp(lane)?
            && Instant::now() < observation.admit_before
            && !self.reload_blocked)
    }
    pub(in crate::runtime) fn finish_scoped_read(
        &mut self,
        lane: LaneId,
        flight: &ReadFlight,
        result: Result<HostedResponse>,
    ) -> Result<Option<Response>> {
        self.validate_read(lane, flight)?;
        self.finish_read(flight, result)
    }
    pub(in crate::runtime) fn cancel_scoped_read(
        &mut self,
        lane: LaneId,
        flight: &ReadFlight,
    ) -> Result<()> {
        self.validate_read(lane, flight)?;
        self.store.cancel_read(&flight.key)
    }
    pub(in crate::runtime) fn begin_challenge(
        &mut self,
        lane: LaneId,
    ) -> Result<Option<ReadFlight>> {
        anyhow::ensure!(
            lane != LaneId::Judge,
            "judge cannot read challenge through this port"
        );
        self.launch_read(
            lane,
            Self::discovery_key(lane),
            Endpoint::Challenge,
            None,
            None,
        )
    }
    pub(in crate::runtime) fn begin_inventory(
        &mut self,
        offset: Option<u64>,
    ) -> Result<Option<ReadFlight>> {
        self.launch_read(
            LaneId::Judge,
            Self::discovery_key(LaneId::Judge),
            Endpoint::Assignments,
            None,
            offset,
        )
    }
    pub(in crate::runtime) fn judge_inventory_offset(&self) -> Result<u64> {
        self.store.judge_inventory_offset()
    }
    pub(in crate::runtime) fn set_judge_inventory_offset(&self, offset: u64) -> Result<()> {
        self.store.set_judge_inventory_offset(offset)
    }
    pub(in crate::runtime) fn begin_hydration(
        &mut self,
        id: &str,
        ordinary: bool,
    ) -> Result<Option<ReadFlight>> {
        if ordinary
            && self
                .once
                .as_ref()
                .is_some_and(|plan| plan.lane(LaneId::Judge).hydrations >= 2)
        {
            return Ok(None);
        }
        let flight = self.launch_read(
            LaneId::Judge,
            ReadKey::Assignment {
                assignment_id: id.into(),
            },
            Endpoint::ExplorerTx,
            Some(id),
            None,
        )?;
        if flight.is_some()
            && ordinary
            && let Some(plan) = &mut self.once
        {
            plan.lane_mut(LaneId::Judge).hydrations += 1;
        }
        Ok(flight)
    }
    pub(in crate::runtime) fn collect_reconciliation(&mut self, lane: LaneId) -> Result<()> {
        let index = lane_index(lane);
        let mut recovery = std::mem::take(&mut self.recovery[index]);
        let result = recovery.collect(self);
        self.recovery[index] = recovery;
        result
    }
    pub(in crate::runtime) fn poll_reconciliation(&mut self, lane: LaneId) -> Result<()> {
        let index = lane_index(lane);
        let mut recovery = std::mem::take(&mut self.recovery[index]);
        let result = recovery.plan(self, lane);
        self.recovery[index] = recovery;
        result
    }
    pub(in crate::runtime) async fn cancel_reconciliation(
        &mut self,
        lane: LaneId,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let index = lane_index(lane);
        let mut recovery = std::mem::take(&mut self.recovery[index]);
        let result = recovery.cancel(self, deadline).await;
        self.recovery[index] = recovery;
        result
    }
    fn make_ready(
        &self,
        lane: LaneId,
        binding: OperationBinding,
        observation: Observation,
        intent: EffectIntent,
    ) -> Result<ReadyEffect> {
        let op = self.validate_binding(lane, &binding)?;
        anyhow::ensure!(intent.lane() == lane, "typed intent lane mismatch");
        anyhow::ensure!(
            self.config.lane_revision(lane)? == observation.stamp.lane_config_revision
                && self
                    .store
                    .operation_config_current(&self.config, &binding)?,
            "prepared configuration changed"
        );
        let due_at = self.store.operation_ready_at(op.id)?;
        Ok(ReadyEffect {
            op,
            binding,
            observation,
            due_at,
            intent,
        })
    }
    pub(in crate::runtime) fn answer_ready(
        &self,
        intent: AnswerIntent,
        binding: OperationBinding,
        observation: Observation,
    ) -> Result<ReadyEffect> {
        self.make_ready(
            LaneId::Answer,
            binding,
            observation,
            EffectIntent::Answer(intent),
        )
    }
    pub(in crate::runtime) fn grade_ready(
        &self,
        intent: GradeIntent,
        binding: OperationBinding,
        observation: Observation,
    ) -> Result<ReadyEffect> {
        self.make_ready(
            LaneId::Judge,
            binding,
            observation,
            EffectIntent::Grade(intent),
        )
    }
    pub(in crate::runtime) fn mine_ready(
        &self,
        intent: MineIntent,
        binding: OperationBinding,
        observation: Observation,
    ) -> Result<ReadyEffect> {
        self.make_ready(
            LaneId::Mine,
            binding,
            observation,
            EffectIntent::Mine(intent),
        )
    }
    pub(in crate::runtime) fn answer_epoch_attempted(&self, epoch: u64) -> Result<bool> {
        self.store.answer_epoch_attempted(epoch)
    }
    pub(in crate::runtime) fn uncertain_answer(&self, epoch: u64) -> Result<Option<Operation>> {
        self.store.uncertain_answer(epoch)
    }
    pub(in crate::runtime) fn scoped_answer_retry_allowed(&self, op: &Operation) -> Result<bool> {
        self.scoped_binding(LaneId::Answer, op)?;
        self.answer_retry_allowed(op)
    }
    pub(in crate::runtime) fn begin_answer_retry(
        &mut self,
        binding: &OperationBinding,
        key: &str,
        observation: &Observation,
    ) -> Result<bool> {
        let original = self.validate_binding(LaneId::Answer, binding)?;
        anyhow::ensure!(
            key == original.key,
            "captured retry key does not match canonical origin"
        );
        if !self.effect_allowed(LaneId::Answer) {
            return Ok(false);
        }
        if !self.permit_current()? {
            self.start_identity(LaneId::Answer)?;
            return Ok(false);
        }
        let Some((account, lane)) = self.lane_gates(LaneId::Answer)? else {
            return Ok(false);
        };
        self.reload()?;
        if !self.active(LaneId::Answer)?
            || !self.permit_current()?
            || !self.scoped_observation_current(LaneId::Answer, observation)?
            || !self.answer_retry_allowed(&original)?
        {
            return Ok(false);
        }
        let stamp = self.admission_stamp(LaneId::Answer)?;
        Ok(self
            .store
            .begin_preparation(
                &self.config,
                &account,
                &lane,
                &stamp,
                PreparationInputs {
                    lane: LaneId::Answer,
                    key,
                    request: &original.request,
                    retry: Some((&original, true)),
                    policy: &json!({"lane_revision":stamp.lane_config_revision}),
                },
            )?
            .is_some())
    }
    pub(in crate::runtime) fn answer_task(&self, challenge: &Challenge) -> Result<AnswerTask> {
        let mut input = self.challenge_input(LaneId::Answer, challenge)?;
        input.solver.guidance = self.config.capabilities.answer.model.guidance.to_string();
        input.solver.core_guidance = self
            .config
            .capabilities
            .answer
            .model
            .core_guidance
            .to_string();
        AnswerTask::new(input.solver)
    }
    pub(in crate::runtime) fn grade_task(&self, assignment: &Assignment) -> Result<GradeTask> {
        GradeTask::new(SolverRequest {
            id: self.request_id(LaneId::Judge, &assignment.id)?,
            kind: LaneId::Judge,
            epoch: assignment.epoch,
            words: assignment.words.clone(),
            min_chars: 0,
            max_chars: 0,
            assignment: Some(assignment.id.clone()),
            candidate: Some(assignment.answer.clone()),
            history: Vec::new(),
            guidance: self.config.capabilities.judge.model.guidance.to_string(),
            core_guidance: self
                .config
                .capabilities
                .judge
                .model
                .core_guidance
                .to_string(),
            author_history: Some(assignment.author_prior.clone()),
            candidate_author: assignment.author.clone(),
        })
    }
    pub(in crate::runtime) fn assignment_excluded(&self, id: &str) -> bool {
        self.config.judging_assignment_excluded(id)
    }
    pub(in crate::runtime) fn record_grade_abstention(
        &mut self,
        assignment: &Assignment,
        observation: &Observation,
    ) -> Result<bool> {
        anyhow::ensure!(
            assignment.words.is_empty(),
            "grade abstention requires missing words"
        );
        if !self.active(LaneId::Judge)? || self.assignment_excluded(&assignment.id) {
            return Ok(false);
        }
        let Some((account, lane)) = self.lane_gates(LaneId::Judge)? else {
            return Ok(false);
        };
        self.reload()?;
        if !self.active(LaneId::Judge)?
            || !self.scoped_observation_current(LaneId::Judge, observation)?
            || self.assignment_excluded(&assignment.id)
            || self.store.attempted(LaneId::Judge, &assignment.id)?
        {
            return Ok(false);
        }
        let stamp = self.admission_stamp(LaneId::Judge)?;
        let Some(mut op) = self.store.begin_preparation(
            &self.config,
            &account,
            &lane,
            &stamp,
            PreparationInputs {
                lane: LaneId::Judge,
                key: &assignment.id,
                request: &json!({"assignment":assignment.id,"local_abstention":"required_words_absent"}),
                retry: None,
                policy: &json!({"lane_revision":stamp.lane_config_revision}),
            },
        )?
        else {
            return Ok(false);
        };
        let binding = self.store.operation_binding(&op)?;
        op.state = "abstained".into();
        self.store
            .complete_preparation(&binding, &op, "assignment_evidence_insufficient")?;
        Ok(true)
    }
    pub(in crate::runtime) fn assignment_blocker(&self, id: &str) -> Result<Option<&'static str>> {
        if self.assignment_excluded(id) {
            return Ok(Some("configured_exclusion"));
        }
        if let Some(blocker) = self.model_retry_blocker(LaneId::Judge, id)? {
            return Ok(Some(blocker));
        }
        if self.store.attempted(LaneId::Judge, id)? {
            return Ok(Some("already_attempted"));
        }
        if self
            .store
            .read_backoff(&ReadKey::Assignment {
                assignment_id: id.into(),
            })?
            .next_at
            > now()
        {
            return Ok(Some("assignment_read_backoff"));
        }
        if self
            .store
            .request_not_before(&self.config, Endpoint::ExplorerTx, Some(id))?
            > now()
        {
            return Ok(Some("assignment_resource_restricted"));
        }
        Ok(None)
    }
    pub(in crate::runtime) fn evaluate_assignment(&self, id: &str, usable: bool) -> Result<()> {
        self.evaluate_read(
            &ReadKey::Assignment {
                assignment_id: id.into(),
            },
            usable,
        )
    }
    pub(in crate::runtime) fn evaluate_inventory(&self, usable: bool) -> Result<()> {
        self.evaluate_read(&Self::discovery_key(LaneId::Judge), usable)
    }
    pub(in crate::runtime) fn record_participation(
        &self,
        lane: LaneId,
        observation: &Observation,
        value: &Value,
    ) -> Result<()> {
        self.store
            .record_lane_participation(lane, &observation.stamp, value)
    }
    pub(in crate::runtime) fn begin_mine_preparation(
        &mut self,
        challenge: &Challenge,
        observation: &Observation,
    ) -> Result<bool> {
        let schedule = &self.config.capabilities.mine.schedule;
        if (schedule.each_epoch && self.store.mine_epoch_attempted(challenge.epoch)?)
            || (!schedule.each_epoch
                && self.store.participation_next_at(LaneId::Mine)? > self.deadline_now())
            || !self.preparation_allowed(LaneId::Mine, challenge.epoch)?
        {
            return Ok(false);
        }
        if !self.permit_current()? {
            self.start_identity(LaneId::Mine)?;
            return Ok(false);
        }
        let Some((account, lane)) = self.lane_gates(LaneId::Mine)? else {
            return Ok(false);
        };
        self.reload()?;
        if !self.active(LaneId::Mine)?
            || !self.permit_current()?
            || !self.scoped_observation_current(LaneId::Mine, observation)?
        {
            return Ok(false);
        }
        let key = format!("{}:{}", challenge.epoch, now());
        let input = self.challenge_input(LaneId::Mine, challenge)?;
        let stamp = self.admission_stamp(LaneId::Mine)?;
        let begun = self
            .store
            .begin_preparation(
                &self.config,
                &account,
                &lane,
                &stamp,
                PreparationInputs {
                    lane: LaneId::Mine,
                    key: &key,
                    request: &serde_json::to_value(input)?,
                    retry: None,
                    policy: &json!({"lane_revision":stamp.lane_config_revision}),
                },
            )?
            .is_some();
        Ok(begun)
    }
    pub(in crate::runtime) fn record_admission_observations(&self) -> Result<()> {
        for id in LaneId::ALL {
            let stamp = self.admission_stamp(id)?;
            let mut reasons = Vec::new();
            if !self.active(id)? {
                reasons.push("runtime_admission_closed");
            }
            if self.effect.is_some() {
                reasons.push("effect_in_flight");
            }
            if !self.permit_current()? {
                reasons.push("identity_unverified");
            }
            let mut valid_until = None;
            if let Some(ready) = self.lanes.ready(id) {
                if !self.ready_current(ready)? {
                    reasons.push("ready_stale");
                }
                if !self.admission_allowed(&ready.op)? {
                    reasons.push("participation_blocked");
                }
                if ready.op.next_at > self.deadline_now() {
                    reasons.push("operation_not_due");
                }
                if self
                    .store
                    .request_not_before(&self.config, ready.intent.endpoint(), None)?
                    > now()
                {
                    reasons.push("endpoint_restricted");
                }
                if let Some(permit) = &self.permit {
                    valid_until = Some(
                        ready.observation.admit_before_unix.min(
                            permit
                                .observed_at
                                .saturating_add(self.config.identity.read_http_seconds as i64),
                        ),
                    );
                }
            } else {
                reasons.push("no_current_ready_work");
            }
            self.store.record_admission_observation(
                id,
                &stamp,
                AdmissionObservation {
                    runtime_instance: &self.authority_instance,
                    state: if reasons.is_empty() { "open" } else { "closed" },
                    reasons: &reasons,
                    observed_at: now(),
                    valid_until,
                },
            )?;
        }
        Ok(())
    }
}
pub(super) fn gate_busy(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<crate::store::LaneControlError>(),
        Some(crate::store::LaneControlError::Busy)
    ) || error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
    })
}
