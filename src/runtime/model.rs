use super::*;
use crate::runtime::answer::AnswerInputMatch;
use crate::runtime::judge::GradeInputMatch;
use crate::solver::contract::*;
use crate::solver::{
    InferenceStart, PendingLaunch, PreflightCompletion, PreflightStart, start_preflight,
};
use crate::store::ModelProducerDraft;

enum Stage {
    Preflight {
        task: tokio::task::JoinHandle<()>,
        result: oneshot::Receiver<PreflightCompletion>,
    },
    Pending,
    Admitting,
    Running {
        task: tokio::task::JoinHandle<()>,
        result: oneshot::Receiver<NativeCompletion>,
    },
}
struct ModelWork {
    op: Operation,
    request: NativeRequest,
    challenge_fingerprint: Option<String>,
    producer: ModelProducerProvenance,
    stage: Stage,
    pending: Option<PendingLaunch>,
    preflight_started_at: Option<i64>,
    inference_spawned_at: Option<i64>,
}
impl Drop for ModelWork {
    fn drop(&mut self) {
        match &self.stage {
            Stage::Preflight { task, .. } | Stage::Running { task, .. } => task.abort(),
            Stage::Pending | Stage::Admitting => {}
        }
    }
}
#[derive(Default)]
struct ModelSlot {
    work: Option<ModelWork>,
}
#[derive(Default)]
pub(in crate::runtime) struct AnswerModelSlot(ModelSlot);
#[derive(Default)]
pub(in crate::runtime) struct GradeModelSlot(ModelSlot);
macro_rules! role_slot {
    ($slot:ident, $task:ident, $variant:ident) => {
        impl $slot {
            pub(in crate::runtime) fn occupied(&self) -> bool {
                self.0.work.is_some()
            }
            pub(in crate::runtime) fn busy(&self) -> bool {
                self.0
                    .work
                    .as_ref()
                    .is_some_and(|work| !matches!(work.stage, Stage::Pending))
            }
            pub(in crate::runtime) fn pending_work(&self) -> Option<PendingWorkRef<'_, $task>> {
                let work = self.0.work.as_ref()?;
                if !matches!(work.stage, Stage::Pending) {
                    return None;
                }
                let NativeRequest::$variant(task) = &work.request else {
                    unreachable!("role-bound model slot")
                };
                work.pending.as_ref()?;
                Some(PendingWorkRef {
                    key: ModelSlot::key(work),
                    task,
                    producer: &work.producer,
                })
            }
        }
    };
}
role_slot!(AnswerModelSlot, AnswerTask, Answer);
role_slot!(GradeModelSlot, GradeTask, Grade);
impl AnswerModelSlot {
    pub(in crate::runtime) fn pending_challenge_fingerprint(&self) -> Option<&str> {
        self.0
            .work
            .as_ref()
            .and_then(|work| work.challenge_fingerprint.as_deref())
    }
}
impl ModelSlot {
    fn key(work: &ModelWork) -> PendingWorkKey {
        PendingWorkKey {
            operation: work.producer.operation.clone(),
            request_digest: work.producer.request_digest.clone(),
        }
    }
    fn begin(
        &mut self,
        host: &mut HostAccess,
        request: NativeRequest,
        fingerprint: Option<String>,
        key: &str,
        retry: Option<&Operation>,
        observation: &Observation,
    ) -> Result<bool> {
        let kind = request.request().kind;
        if self.work.is_some()
            || !host.model_allowed(kind)
            || !host.active(kind)?
            || host.store.preparation(kind)?.is_some()
            || (retry.is_none() && host.store.attempted(kind, key)?)
            || host.store.model_retry_not_before(kind, key)? > host.deadline_now()
            || host.store.model_budget_used(kind, key)? >= host.model_attempt_limit(kind)?
            || !host.preparation_allowed(kind, request.request().epoch)?
        {
            return Ok(false);
        }
        if !host.permit_current()? {
            host.start_identity(kind)?;
            return Ok(false);
        }
        let Some((account, lane)) = host.lane_gates(kind)? else {
            return Ok(false);
        };
        host.reload()?;
        if !host.active(kind)?
            || !host.permit_current()?
            || !host.scoped_observation_current(kind, observation)?
            || (kind == LaneId::Judge && host.config.judging_assignment_excluded(key))
        {
            return Ok(false);
        }
        if let Some(original) = retry
            && !host.answer_retry_allowed(original)?
        {
            return Ok(false);
        }
        let max_attempts = host.model_attempt_limit(kind)?;
        if host.store.model_budget_used(kind, key)? >= max_attempts
            || !host.preparation_allowed(kind, request.request().epoch)?
        {
            return Ok(false);
        }
        let model = host.config.model(kind).context("model route missing")?;
        let selection = ModelSelection::new(model)?;
        let timeout = host
            .config
            .model_seconds(kind)
            .context("model deadline missing")?;
        let count = host.store.attempt_count(kind, key)?;
        let mut wire = request.request().clone();
        wire.id = digest(format!("{}:attempt:{}", wire.id, count + 1));
        // Validate again after binding the final immutable request identifier.
        let request = match request {
            NativeRequest::Answer(_) => NativeRequest::Answer(AnswerTask::new(wire)?),
            NativeRequest::Grade(_) => NativeRequest::Grade(GradeTask::new(wire)?),
        };
        let input = json!({"solver":request.request(),"challenge_fingerprint":fingerprint});
        let stamp = host.admission_stamp(kind)?;
        let policy = host
            .config
            .preparation(kind)
            .context("model preparation missing")?;
        let captured = json!({"schema_version":2,"model":model,"lane_revision":stamp.lane_config_revision,
            "model_seconds":timeout,"attempt":count+1,"retry_uncertain":policy.retry_uncertain,
            "max_attempts_per_work":max_attempts,"configured_max_attempts_per_work":policy.max_attempts_per_work});
        let draft = ModelProducerDraft {
            task_kind: if kind == LaneId::Answer {
                "answer"
            } else {
                "grade"
            }
            .into(),
            request_id: request.request().id.clone(),
            request_digest: request.digest()?,
            lane_config_revision: stamp.lane_config_revision.clone(),
            requested: selection.clone(),
            preflight_admission: stamp.clone(),
        };
        let Some((op, producer)) = host.store.begin_model_attempt(
            &host.config,
            &account,
            &lane,
            &stamp,
            kind,
            key,
            &input,
            retry.map(|op| (op, false)),
            &captured,
            draft,
        )?
        else {
            return Ok(false);
        };
        let mut work = ModelWork {
            op,
            request,
            challenge_fingerprint: fingerprint,
            producer,
            stage: Stage::Admitting,
            pending: None,
            preflight_started_at: None,
            inference_spawned_at: None,
        };
        if let Some(plan) = host.once.as_mut() {
            plan.lane_mut(kind).model = false;
        }
        // A committed producer is not proof that the input is still fresh after SQLite waits.
        let current = Self::final_start_current(host, &work, observation);
        if !matches!(current, Ok(true)) {
            Self::finish_not_started(host, &work, "model_preflight_no_longer_current")?;
            current?;
            return Ok(true);
        }
        // Both gates remain owned until the synchronous boundary owns the discovery child.
        let started = start_preflight(
            work.request.clone(),
            selection,
            Duration::from_secs(timeout),
        );
        match started {
            PreflightStart::Started(flight) => {
                work.preflight_started_at = Some(flight.preflight_started_at());
                drop(lane);
                drop(account);
                let (sender, result) = oneshot::channel();
                let wake = Arc::clone(&host.wake);
                let task = tokio::spawn(async move {
                    let _ = sender.send(flight.collect().await);
                    wake.notify_one();
                });
                work.stage = Stage::Preflight { task, result };
                self.work = Some(work);
            }
            PreflightStart::Finished(completion) => {
                drop(lane);
                drop(account);
                Self::capture(host, &work, completion)?;
            }
        }
        Ok(true)
    }
    fn collect(&mut self, host: &mut HostAccess) -> Result<()> {
        if let Some(work) = self.work.as_ref()
            && matches!(work.stage, Stage::Pending)
            && Self::pending_expired(work)
        {
            let key = Self::key(work);
            return self.retire(host, &key, "model_execution_deadline_expired");
        }
        if let Some(work) = self.work.as_ref()
            && matches!(work.stage, Stage::Pending)
            && (work.op.generation != host.store.control()?.generation
                || work.producer.preflight_admission.authority_epoch != host.authority_epoch
                || work.producer.lane_config_revision != host.config.lane_revision(work.op.kind)?
                || host.config.mode(work.op.kind) == Mode::Off)
        {
            let key = Self::key(work);
            return self.retire(host, &key, "model_origin_no_longer_current");
        }
        let Some(work) = self.work.as_mut() else {
            return Ok(());
        };
        let completion = match &mut work.stage {
            Stage::Preflight { result, .. } => match result.try_recv() {
                Ok(PreflightCompletion::Pending(pending)) => {
                    host.store.capture_model_pending(
                        work.op.id,
                        u64::try_from(pending.remaining_execution_budget().as_millis())
                            .context("model budget exceeds journal range")?,
                        pending.execution_deadline().unix_seconds,
                    )?;
                    work.pending = Some(pending);
                    work.stage = Stage::Pending;
                    if Self::pending_expired(work) {
                        let key = Self::key(work);
                        return self.retire(host, &key, "model_execution_deadline_expired");
                    }
                    return Ok(());
                }
                Ok(PreflightCompletion::Finished(completion)) => Some(completion),
                Err(oneshot::error::TryRecvError::Empty) => None,
                Err(oneshot::error::TryRecvError::Closed) => {
                    Some(Self::interrupted(work, false, None))
                }
            },
            Stage::Running { result, .. } => match result.try_recv() {
                Ok(completion) => Some(completion),
                Err(oneshot::error::TryRecvError::Empty) => None,
                Err(oneshot::error::TryRecvError::Closed) => {
                    Some(Self::interrupted(work, true, None))
                }
            },
            Stage::Pending | Stage::Admitting => None,
        };
        if let Some(completion) = completion {
            let work = self.work.take().expect("completed model work");
            Self::capture(host, &work, completion)?;
        }
        Ok(())
    }
    // Only role-specific lane match tokens reach this private common implementation.
    fn launch_matched(
        &mut self,
        host: &mut HostAccess,
        key: PendingWorkKey,
        observation: Observation,
        revision: String,
    ) -> Result<()> {
        let Some(work) = self.work.as_ref() else {
            return Ok(());
        };
        if !matches!(work.stage, Stage::Pending) || Self::key(work) != key {
            return Ok(());
        }
        if Self::pending_expired(work) {
            return self.retire(host, &key, "model_execution_deadline_expired");
        }
        let kind = work.op.kind;
        if revision != work.producer.lane_config_revision
            || !host.scoped_observation_current(kind, &observation)?
        {
            return Ok(());
        }
        if !host.active(kind)? || !host.preparation_allowed(kind, work.request.request().epoch)? {
            return Ok(());
        }
        if !host.permit_current()? {
            host.start_identity(kind)?;
            return Ok(());
        }
        let Some((account, lane)) = host.lane_gates(kind)? else {
            return Ok(());
        };
        host.reload()?;
        if !host.active(kind)?
            || !host.permit_current()?
            || !host.scoped_observation_current(kind, &observation)?
            || host.config.lane_revision(kind)? != work.producer.lane_config_revision
            || work.op.generation != host.store.control()?.generation
            || work.producer.preflight_admission.authority_epoch != host.authority_epoch
            || !host.preparation_allowed(kind, work.request.request().epoch)?
        {
            return Ok(());
        }
        let stamp = host.admission_stamp(kind)?;
        let deadline = work
            .pending
            .as_ref()
            .expect("pending model launch")
            .execution_deadline();
        if !host.store.admit_model_launch(
            &host.config,
            &account,
            &lane,
            &stamp,
            &key.operation,
            deadline.unix_seconds,
            observation.admit_before,
        )? {
            if Self::pending_expired(self.work.as_ref().expect("pending model work")) {
                return self.retire(host, &key, "model_execution_deadline_expired");
            }
            return Ok(());
        }
        self.start_admitted(host, observation, deadline, account, lane)
    }
    fn start_admitted(
        &mut self,
        host: &mut HostAccess,
        observation: Observation,
        deadline: crate::solver::ExecutionDeadline,
        account: AccountAdmissionGuard,
        lane: crate::store::LaneAdmissionGuard,
    ) -> Result<()> {
        // Consume pending ownership once permission commits, even when the final bound fails.
        // An immutable launch record must never be offered for a second native start.
        let mut work = self.work.take().expect("admitted model work");
        work.stage = Stage::Admitting;
        let current = Self::final_start_current(host, &work, &observation);
        if !matches!(current, Ok(true)) || Self::pending_expired(&work) {
            Self::finish_not_started(host, &work, "model_launch_no_longer_current")?;
            current?;
            return Ok(());
        }
        let started = work
            .pending
            .take()
            .expect("pending model launch")
            .start(deadline);
        match started {
            InferenceStart::Started(flight) => {
                work.inference_spawned_at = Some(flight.inference_spawned_at());
                drop(lane);
                drop(account);
                let (sender, result) = oneshot::channel();
                let wake = Arc::clone(&host.wake);
                let task = tokio::spawn(async move {
                    let _ = sender.send(flight.collect().await);
                    wake.notify_one();
                });
                work.stage = Stage::Running { task, result };
                self.work = Some(work);
            }
            InferenceStart::Finished(completion) => {
                drop(lane);
                drop(account);
                Self::capture(host, &work, completion)?;
            }
        }
        Ok(())
    }
    fn pending_expired(work: &ModelWork) -> bool {
        work.pending.as_ref().is_some_and(|pending| {
            let deadline = pending.execution_deadline();
            tokio::time::Instant::now() >= deadline.at || now() >= deadline.unix_seconds
        })
    }
    fn final_start_current(
        host: &HostAccess,
        work: &ModelWork,
        observation: &Observation,
    ) -> Result<bool> {
        let kind = work.op.kind;
        if !host.active(kind)?
            || host.config.lane_revision(kind)? != work.producer.lane_config_revision
            || work.op.generation != host.store.control()?.generation
            || work.producer.preflight_admission.authority_epoch != host.authority_epoch
        {
            return Ok(false);
        }
        host.store.continuity()?;
        Ok(host.permit_current()? && host.scoped_observation_current(kind, observation)?)
    }
    fn retire(
        &mut self,
        host: &mut HostAccess,
        key: &PendingWorkKey,
        reason: &'static str,
    ) -> Result<()> {
        let Some(work) = self.work.as_ref() else {
            return Ok(());
        };
        if Self::key(work) != *key || !matches!(work.stage, Stage::Pending) {
            return Ok(());
        }
        let work = self.work.take().expect("retired pending model work");
        Self::finish_not_started(host, &work, reason)
    }
    fn finish_not_started(
        host: &mut HostAccess,
        work: &ModelWork,
        reason: &'static str,
    ) -> Result<()> {
        let mut completion = Self::interrupted(work, false, None);
        if work.pending.is_some() {
            completion.evidence.phase = NativePhase::Inference;
        }
        completion.evidence.reason_code = NativeReasonCode::PendingRetired;
        completion.result = Err(NativeReasonCode::PendingRetired);
        let mut op = host
            .store
            .operation(work.op.id)?
            .context("pending operation missing")?;
        op.state = "discarded".into();
        host.store
            .finish_model_attempt(&work.producer.operation, &op, &completion.evidence, reason)
    }
    fn interrupted(work: &ModelWork, running: bool, cancelled_at: Option<i64>) -> NativeCompletion {
        NativeCompletion {
            result: Err(NativeReasonCode::Interrupted),
            evidence: NativeAttemptCompletion {
                phase: if running {
                    NativePhase::Inference
                } else {
                    NativePhase::Preflight
                },
                execution: if running {
                    NativeExecution::Unknown
                } else {
                    NativeExecution::NotStarted
                },
                outcome: if running {
                    NativeOutcome::Unknown
                } else {
                    NativeOutcome::NotStarted
                },
                reason_code: NativeReasonCode::Interrupted,
                collected_at: Some(now()),
                preflight_started_at: work.preflight_started_at,
                inference_spawned_at: work.inference_spawned_at,
                reported: Default::default(),
                cancellation: CancellationEvidence {
                    requested_at: cancelled_at,
                    local_process_stop: if cancelled_at.is_some() {
                        LocalProcessStop::Unknown
                    } else {
                        LocalProcessStop::NotRequested
                    },
                    remote_run_stop: if running {
                        RemoteRunStop::Unknown
                    } else {
                        RemoteRunStop::NotRequested
                    },
                },
            },
        }
    }
    fn capture(
        host: &mut HostAccess,
        work: &ModelWork,
        mut completion: NativeCompletion,
    ) -> Result<()> {
        let Some(mut op) = host.store.operation(work.op.id)? else {
            return Ok(());
        };
        if op.state != "generating" || op.binding_revision != work.op.binding_revision {
            return Ok(());
        }
        let event = match completion.result {
            Ok(artifact) => {
                let result = artifact.into_result();
                op.result = Some(serde_json::to_value(&result)?);
                if op.generation != host.store.control()?.generation
                    || host.config.mode(op.kind) == Mode::Off
                    || (op.kind == LaneId::Judge
                        && host.config.judging_assignment_excluded(&op.key))
                {
                    op.state = "discarded".into();
                    "late_model_result_discarded"
                } else {
                    match payload(work.request.request(), &result) {
                        Ok(payload) => {
                            op.payload = Some(payload);
                            op.state = "generated".into();
                            "model_result_captured"
                        }
                        Err(_) => {
                            op.state = "rejected".into();
                            op.next_at = model_retry_deadline(host, &op)?;
                            completion.evidence.phase = NativePhase::ArtifactValidation;
                            completion.evidence.outcome = NativeOutcome::Invalid;
                            completion.evidence.reason_code =
                                NativeReasonCode::NativeArtifactInvalid;
                            "model_result_invalid"
                        }
                    }
                }
            }
            Err(code) => {
                op.state = match (completion.evidence.execution, completion.evidence.outcome) {
                    (NativeExecution::NotStarted, _) => "prelaunch_failed",
                    (NativeExecution::Completed, NativeOutcome::Invalid) => "rejected",
                    _ => "model_unknown",
                }
                .into();
                op.next_at = model_retry_deadline(host, &op)?;
                code.as_str()
            }
        };
        host.store
            .finish_model_attempt(&work.producer.operation, &op, &completion.evidence, event)
    }
    async fn cancel(
        &mut self,
        host: &mut HostAccess,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        self.collect(host)?;
        let Some(mut work) = self.work.take() else {
            return Ok(());
        };
        let running = matches!(work.stage, Stage::Running { .. } | Stage::Admitting);
        let cancelled = now();
        match &mut work.stage {
            Stage::Preflight { task, .. } | Stage::Running { task, .. } => {
                task.abort();
                let _ = tokio::time::timeout_at(deadline, task).await;
            }
            Stage::Pending | Stage::Admitting => {}
        }
        // An assembled terminal result wins over conservative cancellation classification.
        let completion = match &mut work.stage {
            Stage::Preflight { result, .. } => match result.try_recv() {
                Ok(PreflightCompletion::Finished(completion)) => completion,
                Ok(PreflightCompletion::Pending(pending)) => {
                    work.preflight_started_at = Some(pending.preflight_started_at());
                    Self::interrupted(&work, false, Some(cancelled))
                }
                Err(_) => Self::interrupted(&work, false, Some(cancelled)),
            },
            Stage::Running { result, .. } => result
                .try_recv()
                .unwrap_or_else(|_| Self::interrupted(&work, true, Some(cancelled))),
            _ => Self::interrupted(&work, running, None),
        };
        Self::capture(host, &work, completion)
    }
}
fn model_retry_deadline(host: &HostAccess, op: &Operation) -> Result<i64> {
    let schedule = host.config.schedule(op.kind);
    let attempts = host.store.attempt_count(op.kind, &op.key)?;
    let multiplier = 1_u64
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Ok(not_before(
        schedule
            .retry_seconds
            .saturating_mul(multiplier)
            .min(schedule.backoff_max_seconds.max(schedule.retry_seconds))
            .saturating_add(host.jitter(op.kind, "model-retry")),
    ))
}
impl HostAccess {
    pub(in crate::runtime) fn begin_answer_model(
        &mut self,
        slot: &mut AnswerModelSlot,
        task: AnswerTask,
        fingerprint: String,
        key: &str,
        retry: Option<&Operation>,
        observation: &Observation,
    ) -> Result<bool> {
        if let Some(op) = retry {
            self.scoped_binding(LaneId::Answer, op)?;
        }
        slot.0.begin(
            self,
            NativeRequest::Answer(task),
            Some(fingerprint),
            key,
            retry,
            observation,
        )
    }
    pub(in crate::runtime) fn begin_grade_model(
        &mut self,
        slot: &mut GradeModelSlot,
        task: GradeTask,
        key: &str,
        observation: &Observation,
    ) -> Result<bool> {
        slot.0.begin(
            self,
            NativeRequest::Grade(task),
            None,
            key,
            None,
            observation,
        )
    }
    pub(in crate::runtime) fn collect_answer_model(
        &mut self,
        slot: &mut AnswerModelSlot,
    ) -> Result<()> {
        slot.0.collect(self)
    }
    pub(in crate::runtime) fn collect_grade_model(
        &mut self,
        slot: &mut GradeModelSlot,
    ) -> Result<()> {
        slot.0.collect(self)
    }
    pub(in crate::runtime) fn launch_answer_model(
        &mut self,
        slot: &mut AnswerModelSlot,
        matched: AnswerInputMatch,
    ) -> Result<()> {
        let (key, observation, revision) = matched.into_parts();
        slot.0.launch_matched(self, key, observation, revision)
    }
    pub(in crate::runtime) fn launch_grade_model(
        &mut self,
        slot: &mut GradeModelSlot,
        matched: GradeInputMatch,
    ) -> Result<()> {
        let (key, observation, revision) = matched.into_parts();
        slot.0.launch_matched(self, key, observation, revision)
    }
    pub(in crate::runtime) fn retire_answer_model(
        &mut self,
        slot: &mut AnswerModelSlot,
        key: &PendingWorkKey,
        reason: &'static str,
    ) -> Result<()> {
        slot.0.retire(self, key, reason)
    }
    pub(in crate::runtime) fn retire_grade_model(
        &mut self,
        slot: &mut GradeModelSlot,
        key: &PendingWorkKey,
        reason: &'static str,
    ) -> Result<()> {
        slot.0.retire(self, key, reason)
    }
    pub(in crate::runtime) async fn cancel_answer_model(
        &mut self,
        slot: &mut AnswerModelSlot,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        slot.0.cancel(self, deadline).await
    }
    pub(in crate::runtime) async fn cancel_grade_model(
        &mut self,
        slot: &mut GradeModelSlot,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        slot.0.cancel(self, deadline).await
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
