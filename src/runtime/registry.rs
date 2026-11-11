use super::host::HostAccess;
use super::*;
use super::{answer::AnswerLane, judge::JudgeLane, mine::MineLane};

#[derive(Default)]
pub(super) struct NativeLanes {
    pub(super) answer: AnswerLane,
    pub(super) judge: JudgeLane,
    pub(super) mine: MineLane,
}

impl NativeLanes {
    pub(super) fn busy(&self) -> bool {
        self.answer.busy() || self.judge.busy() || self.mine.busy()
    }

    pub(super) fn ready(&self, id: LaneId) -> Option<&ReadyEffect> {
        match id {
            LaneId::Answer => self.answer.ready.as_ref(),
            LaneId::Judge => self.judge.ready.as_ref(),
            LaneId::Mine => self.mine.ready.as_ref(),
        }
    }

    pub(super) fn take_ready(&mut self, id: LaneId) -> Option<ReadyEffect> {
        match id {
            LaneId::Answer => self.answer.ready.take(),
            LaneId::Judge => self.judge.ready.take(),
            LaneId::Mine => self.mine.ready.take(),
        }
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = NativeLane<'_>> {
        [
            NativeLane::Answer(&mut self.answer),
            NativeLane::Judge(&mut self.judge),
            NativeLane::Mine(&mut self.mine),
        ]
        .into_iter()
    }
}

pub(super) enum NativeLane<'a> {
    Answer(&'a mut AnswerLane),
    Judge(&'a mut JudgeLane),
    Mine(&'a mut MineLane),
}

impl NativeLane<'_> {
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
