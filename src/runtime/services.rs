use super::host::HostAccess;
use super::*;
use crate::config::{AnswerConfig, JudgeConfig};
use crate::solver::contract::{AnswerTask, GradeTask};

// Possession of HostAccess is required to construct a service. Its constructor and
// backing authority live in the sibling host module, never in a controller.
pub(super) struct AnswerServices<'a> {
    host: &'a mut HostAccess,
}
pub(super) struct GradeServices<'a> {
    host: &'a mut HostAccess,
}
pub(super) struct MineServices<'a> {
    host: &'a mut HostAccess,
}

macro_rules! common_services {
    ($service:ident, $lane:ident) => {
        impl<'a> $service<'a> {
            pub(super) fn new(host: &'a mut HostAccess) -> Self {
                Self { host }
            }
            pub(super) fn observation(&self, flight: &ReadFlight) -> Result<Observation> {
                self.host.read_observation(LaneId::$lane, flight)
            }
            pub(super) fn observation_current(&self, observation: &Observation) -> Result<bool> {
                self.host
                    .scoped_observation_current(LaneId::$lane, observation)
            }
            pub(super) fn active(&self) -> Result<bool> {
                self.host.active(LaneId::$lane)
            }
            pub(super) fn discovery_allowed(&self) -> Result<bool> {
                self.host.discovery_allowed(LaneId::$lane)
            }
            pub(super) fn discovered(&mut self) -> Result<()> {
                self.host.discovered(LaneId::$lane)
            }
            pub(super) fn finish_read(
                &mut self,
                flight: &ReadFlight,
                result: Result<crate::protocol::HostedResponse>,
            ) -> Result<Option<Response>> {
                self.host.finish_scoped_read(LaneId::$lane, flight, result)
            }
            pub(super) fn cancel_read(&mut self, flight: &ReadFlight) -> Result<()> {
                self.host.cancel_scoped_read(LaneId::$lane, flight)
            }
            pub(super) fn collect_reconciliation(&mut self) -> Result<()> {
                self.host.collect_reconciliation(LaneId::$lane)
            }
            pub(super) fn poll_reconciliation(&mut self) -> Result<()> {
                self.host.poll_reconciliation(LaneId::$lane)
            }
            pub(super) async fn cancel_reconciliation(&mut self) -> Result<()> {
                self.host.cancel_reconciliation(LaneId::$lane).await
            }
            pub(super) fn preparation(&mut self) -> Result<Option<Operation>> {
                self.host.current_preparation(LaneId::$lane)
            }
            pub(super) fn has_preparation(&self) -> Result<bool> {
                self.host.has_preparation(LaneId::$lane)
            }
            pub(super) fn binding(&self, op: &Operation) -> Result<OperationBinding> {
                self.host.scoped_binding(LaneId::$lane, op)
            }
            pub(super) fn draft_current(&self, binding: &OperationBinding) -> Result<bool> {
                self.host.scoped_draft_current(LaneId::$lane, binding)
            }
            pub(super) fn retire_unsent(
                &mut self,
                binding: &OperationBinding,
                reason: &'static str,
            ) -> Result<()> {
                self.host.retire_unsent(LaneId::$lane, binding, reason)
            }
            pub(super) fn ready_current(&self, ready: &ReadyEffect) -> Result<bool> {
                self.host.scoped_ready_current(LaneId::$lane, ready)
            }
            pub(super) fn admission_allowed(&self, op: &Operation) -> Result<bool> {
                self.host.scoped_admission_allowed(LaneId::$lane, op)
            }
            pub(super) fn fresh_allowed(&mut self, id: i64) -> bool {
                self.host.fresh_allowed(LaneId::$lane, id)
            }
            pub(super) fn deadline_now(&self) -> i64 {
                self.host.deadline_now()
            }
            pub(super) fn start_identity(&mut self) -> Result<()> {
                self.host.start_identity(LaneId::$lane)
            }
        }
    };
}
common_services!(AnswerServices, Answer);
common_services!(GradeServices, Judge);
common_services!(MineServices, Mine);

impl AnswerServices<'_> {
    pub(super) fn config(&self) -> &AnswerConfig {
        self.host.answer_config()
    }
    pub(super) fn lane_revision(&self) -> Result<String> {
        self.host.lane_revision(LaneId::Answer)
    }
    pub(super) fn effect_busy(&self) -> bool {
        self.host.effect_busy()
    }
    pub(super) fn participation(&self, observation: &Observation, value: &Value) -> Result<()> {
        self.host
            .record_participation(LaneId::Answer, observation, value)
    }
    pub(super) fn begin_discovery(&mut self) -> Result<Option<ReadFlight>> {
        self.host.begin_challenge(LaneId::Answer)
    }
    pub(super) fn observe_challenge(
        &mut self,
        flight: &ReadFlight,
        response: &Response,
    ) -> Result<Option<Challenge>> {
        self.host
            .observe_challenge(LaneId::Answer, flight, response)
    }
    pub(super) fn emit_ready(
        &self,
        intent: crate::protocol::AnswerIntent,
        binding: OperationBinding,
        observation: Observation,
    ) -> Result<ReadyEffect> {
        self.host.answer_ready(intent, binding, observation)
    }
    pub(super) fn answer_epoch_attempted(&self, epoch: u64) -> Result<bool> {
        self.host.answer_epoch_attempted(epoch)
    }
    pub(super) fn uncertain_answer(&self, epoch: u64) -> Result<Option<Operation>> {
        self.host.uncertain_answer(epoch)
    }
    pub(super) fn answer_retry_allowed(&self, op: &Operation) -> Result<bool> {
        self.host.scoped_answer_retry_allowed(op)
    }
    pub(super) fn begin_retry(
        &mut self,
        original: &OperationBinding,
        key: &str,
        observation: &Observation,
    ) -> Result<bool> {
        self.host.begin_answer_retry(original, key, observation)
    }
    pub(super) fn task(&self, challenge: &Challenge) -> Result<AnswerTask> {
        self.host.answer_task(challenge)
    }
    pub(super) fn begin_model(
        &mut self,
        slot: &mut AnswerModelSlot,
        task: AnswerTask,
        fingerprint: String,
        key: &str,
        retry: Option<&Operation>,
        observation: &Observation,
    ) -> Result<bool> {
        self.host
            .begin_answer_model(slot, task, fingerprint, key, retry, observation)
    }
    pub(super) fn collect_model(&mut self, slot: &mut AnswerModelSlot) -> Result<()> {
        self.host.collect_answer_model(slot)
    }
    pub(super) fn launch_pending(
        &mut self,
        slot: &mut AnswerModelSlot,
        matched: super::answer::AnswerInputMatch,
    ) -> Result<()> {
        self.host.launch_answer_model(slot, matched)
    }
    pub(super) fn retire_pending(
        &mut self,
        slot: &mut AnswerModelSlot,
        key: &PendingWorkKey,
        reason: &'static str,
    ) -> Result<()> {
        self.host.retire_answer_model(slot, key, reason)
    }
    pub(super) async fn cancel_model(&mut self, slot: &mut AnswerModelSlot) -> Result<()> {
        self.host.cancel_answer_model(slot).await
    }
}
impl GradeServices<'_> {
    pub(super) fn config(&self) -> &JudgeConfig {
        self.host.grade_config()
    }
    pub(super) fn lane_revision(&self) -> Result<String> {
        self.host.lane_revision(LaneId::Judge)
    }
    pub(super) fn effect_busy(&self) -> bool {
        self.host.effect_busy()
    }
    pub(super) fn effect_allowed(&self) -> bool {
        self.host.effect_allowed(LaneId::Judge)
    }
    pub(super) fn participation(&self, observation: &Observation, value: &Value) -> Result<()> {
        self.host
            .record_participation(LaneId::Judge, observation, value)
    }
    pub(super) fn begin_discovery(&mut self, offset: Option<u64>) -> Result<Option<ReadFlight>> {
        self.host.begin_inventory(offset)
    }
    pub(super) fn begin_hydration(
        &mut self,
        id: &str,
        ordinary: bool,
    ) -> Result<Option<ReadFlight>> {
        self.host.begin_hydration(id, ordinary)
    }
    pub(super) fn evaluate_assignment(&self, id: &str, usable: bool) -> Result<()> {
        self.host.evaluate_assignment(id, usable)
    }
    pub(super) fn evaluate_inventory(&self, usable: bool) -> Result<()> {
        self.host.evaluate_inventory(usable)
    }
    pub(super) fn assignment_blocker(&self, id: &str) -> Result<Option<&'static str>> {
        self.host.assignment_blocker(id)
    }
    pub(super) fn assignment_excluded(&self, id: &str) -> bool {
        self.host.assignment_excluded(id)
    }
    pub(super) fn record_abstention(
        &mut self,
        assignment: &Assignment,
        observation: &Observation,
    ) -> Result<bool> {
        self.host.record_grade_abstention(assignment, observation)
    }
    pub(super) fn emit_ready(
        &self,
        intent: crate::protocol::GradeIntent,
        binding: OperationBinding,
        observation: Observation,
    ) -> Result<ReadyEffect> {
        self.host.grade_ready(intent, binding, observation)
    }
    pub(super) fn task(&self, assignment: &Assignment) -> Result<GradeTask> {
        self.host.grade_task(assignment)
    }
    pub(super) fn begin_model(
        &mut self,
        slot: &mut GradeModelSlot,
        task: GradeTask,
        key: &str,
        observation: &Observation,
    ) -> Result<bool> {
        self.host.begin_grade_model(slot, task, key, observation)
    }
    pub(super) fn collect_model(&mut self, slot: &mut GradeModelSlot) -> Result<()> {
        self.host.collect_grade_model(slot)
    }
    pub(super) fn launch_pending(
        &mut self,
        slot: &mut GradeModelSlot,
        matched: super::judge::GradeInputMatch,
    ) -> Result<()> {
        self.host.launch_grade_model(slot, matched)
    }
    pub(super) fn retire_pending(
        &mut self,
        slot: &mut GradeModelSlot,
        key: &PendingWorkKey,
        reason: &'static str,
    ) -> Result<()> {
        self.host.retire_grade_model(slot, key, reason)
    }
    pub(super) async fn cancel_model(&mut self, slot: &mut GradeModelSlot) -> Result<()> {
        self.host.cancel_grade_model(slot).await
    }
}
impl MineServices<'_> {
    pub(super) fn effect_allowed(&self) -> bool {
        self.host.effect_allowed(LaneId::Mine)
    }
    pub(super) fn begin_discovery(&mut self) -> Result<Option<ReadFlight>> {
        self.host.begin_challenge(LaneId::Mine)
    }
    pub(super) fn observe_challenge(
        &mut self,
        flight: &ReadFlight,
        response: &Response,
    ) -> Result<Option<Challenge>> {
        self.host.observe_challenge(LaneId::Mine, flight, response)
    }
    pub(super) fn emit_ready(
        &self,
        intent: crate::protocol::MineIntent,
        binding: OperationBinding,
        observation: Observation,
    ) -> Result<ReadyEffect> {
        self.host.mine_ready(intent, binding, observation)
    }
    pub(super) fn begin_preparation(
        &mut self,
        challenge: &Challenge,
        observation: &Observation,
    ) -> Result<bool> {
        self.host.begin_mine_preparation(challenge, observation)
    }
}
