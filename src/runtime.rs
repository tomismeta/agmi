//! Native lane controllers receive only role-bound services. Account authority stays in host.
use crate::capability::LaneId;
use crate::config::Mode;
use crate::protocol::{
    Assignment, Challenge, Response, assignment_ids, assignment_needs_hydration,
    parse_selected_assignment,
};
use crate::solver::SolverRequest;
use crate::store::{AdmissionStampSnapshot, ModelProducerProvenance, Operation, OperationBinding};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

mod answer;
mod host;
mod judge;
mod mine;
mod registry;
mod services;
use host::{AnswerModelSlot, GradeModelSlot, ReadFlight, ReadyEffect};
pub use host::{
    build_info, events, operations_list, pause, reads, recover_model, recovery_adopt,
    recovery_authorize, recovery_grants, recovery_inspect, recovery_resolve, recovery_revoke,
    resume, run, status,
};
pub(crate) use host::{restore_update_pause, status_evidence};
use registry::NativeLanes;
use services::{AnswerServices, GradeServices, MineServices};

#[derive(Serialize, Deserialize)]
struct Input {
    solver: SolverRequest,
    challenge_fingerprint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingWorkKey {
    operation: OperationBinding,
    request_digest: String,
}
struct PendingWorkRef<'a, Task> {
    key: PendingWorkKey,
    task: &'a Task,
    producer: &'a ModelProducerProvenance,
}
#[derive(Clone)]
struct Observation {
    stamp: AdmissionStampSnapshot,
    admit_before: Instant,
    admit_before_unix: i64,
}
enum PendingRetirementReason {
    ConfigChanged,
    InputChanged,
}
impl PendingRetirementReason {
    fn code(&self) -> &'static str {
        match self {
            Self::ConfigChanged => "model_config_changed",
            Self::InputChanged => "request_no_longer_current",
        }
    }
}
enum PendingWaitReason {
    ObservationStale,
}
enum PendingInputDecision<Match> {
    Unchanged(Match),
    Retire(PendingRetirementReason),
    Wait(PendingWaitReason),
}
