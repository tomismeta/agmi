use super::host::HostAccess;
use super::*;
use super::{answer::AnswerLane, judge::JudgeLane, mine::MineLane};

pub(super) enum NativeLane {
    Answer(AnswerLane),
    Judge(JudgeLane),
    Mine(MineLane),
}
impl NativeLane {
    pub(super) fn new(id: LaneId) -> Self {
        match id {
            LaneId::Answer => Self::Answer(AnswerLane::default()),
            LaneId::Judge => Self::Judge(JudgeLane::default()),
            LaneId::Mine => Self::Mine(MineLane::default()),
        }
    }
    pub(super) fn id(&self) -> LaneId {
        match self {
            Self::Answer(_) => LaneId::Answer,
            Self::Judge(_) => LaneId::Judge,
            Self::Mine(_) => LaneId::Mine,
        }
    }
    pub(super) fn busy(&self) -> bool {
        match self {
            Self::Answer(lane) => lane.busy(),
            Self::Judge(lane) => lane.busy(),
            Self::Mine(lane) => lane.busy(),
        }
    }
    pub(super) fn ready(&self) -> Option<&ReadyEffect> {
        match self {
            Self::Answer(lane) => lane.ready.as_ref(),
            Self::Judge(lane) => lane.ready.as_ref(),
            Self::Mine(lane) => lane.ready.as_ref(),
        }
    }
    pub(super) fn take_ready(&mut self) -> Option<ReadyEffect> {
        match self {
            Self::Answer(lane) => lane.ready.take(),
            Self::Judge(lane) => lane.ready.take(),
            Self::Mine(lane) => lane.ready.take(),
        }
    }
    pub(super) fn collect(&mut self, host: &mut HostAccess) -> Result<()> {
        match self {
            Self::Answer(lane) => lane.collect(&mut AnswerServices::new(host)),
            Self::Judge(lane) => lane.collect(&mut GradeServices::new(host)),
            Self::Mine(lane) => lane.collect(&mut MineServices::new(host)),
        }
    }
    pub(super) fn advance(&mut self, host: &mut HostAccess) -> Result<()> {
        match self {
            Self::Answer(lane) => lane.plan(&mut AnswerServices::new(host)),
            Self::Judge(lane) => lane.plan(&mut GradeServices::new(host)),
            Self::Mine(lane) => lane.plan(&mut MineServices::new(host)),
        }
    }
    pub(super) async fn stop(&mut self, host: &mut HostAccess) -> Result<()> {
        match self {
            Self::Answer(lane) => lane.cancel(&mut AnswerServices::new(host)).await,
            Self::Judge(lane) => lane.cancel(&mut GradeServices::new(host)).await,
            Self::Mine(lane) => lane.cancel(&mut MineServices::new(host)).await,
        }
    }
}
pub(super) fn lane_index(id: LaneId) -> usize {
    LaneId::ALL
        .iter()
        .position(|registered| *registered == id)
        .expect("registered native lane")
}
