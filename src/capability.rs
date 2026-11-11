//! Stable native capability identity and public metadata, independent of configuration.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneId {
    Answer,
    Judge,
    Mine,
}

impl LaneId {
    pub const ALL: [Self; 3] = [Self::Answer, Self::Judge, Self::Mine];
    pub const COUNT: usize = Self::ALL.len();
    pub const NAMES: [&'static str; Self::COUNT] = {
        let mut names = [""; Self::COUNT];
        let mut index = 0;
        while index < Self::COUNT {
            names[index] = Self::ALL[index].as_str();
            index += 1;
        }
        names
    };

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Judge => "judge",
            Self::Mine => "mine",
        }
    }

    pub fn descriptor(self) -> &'static LaneDescriptor {
        &DESCRIPTORS[self as usize]
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct LaneDescriptor {
    pub id: LaneId,
    pub summary: &'static str,
    /// Native model task; absent lanes have no model or guidance route.
    pub model_task: Option<&'static str>,
}

pub static DESCRIPTORS: [LaneDescriptor; LaneId::COUNT] = [
    LaneDescriptor {
        id: LaneId::Answer,
        summary: "Generate and submit challenge answers",
        model_task: Some("answer"),
    },
    LaneDescriptor {
        id: LaneId::Judge,
        summary: "Assess assignments and submit grades",
        model_task: Some("grade"),
    },
    LaneDescriptor {
        id: LaneId::Mine,
        summary: "Participate in mining without a model",
        model_task: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_lanes_preserve_wire_identity_and_model_roles() {
        for (index, lane) in LaneId::ALL.into_iter().enumerate() {
            assert_eq!(lane.descriptor().id, lane);
            assert_eq!(LaneId::NAMES[index], lane.as_str());
            let wire = serde_json::to_value(lane).unwrap();
            assert_eq!(wire, lane.as_str());
            assert_eq!(serde_json::from_value::<LaneId>(wire).unwrap(), lane);
        }
        assert_eq!(LaneId::Answer.descriptor().model_task, Some("answer"));
        assert_eq!(LaneId::Judge.descriptor().model_task, Some("grade"));
        assert_eq!(LaneId::Mine.descriptor().model_task, None);
    }
}
