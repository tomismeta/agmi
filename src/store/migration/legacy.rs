//! The only reader of the retired configuration shape.
use super::*;
use crate::config::{
    CountLimit, HistoricalAnswerCapacity, ModelConfig, NetworkConfig, ParticipationMode,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Legacy {
    pub network: NetworkConfig,
    pub state_dir: PathBuf,
    pub capabilities: Modes,
    pub solver: Models,
    pub timeouts: Timeouts,
    pub schedule: Schedule,
    pub preparation: Preparation,
    pub participation: Participation,
    pub excluded_judging_assignments: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Modes {
    answer: crate::config::Mode,
    judge: crate::config::Mode,
    mine: crate::config::Mode,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Models {
    answer: ModelConfig,
    judge: ModelConfig,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Timeouts {
    http_seconds: u64,
    #[serde(default)]
    read_http_seconds: Option<u64>,
    model_seconds: u64,
    shutdown_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Schedule {
    poll_seconds: u64,
    mine_seconds: u64,
    #[serde(default)]
    mine_each_epoch: bool,
    retry_seconds: u64,
    #[serde(default = "backoff")]
    backoff_max_seconds: u64,
    #[serde(default)]
    challenge_retry_seconds: Option<u64>,
    #[serde(default)]
    challenge_backoff_max_seconds: Option<u64>,
    #[serde(default)]
    assignments_retry_seconds: Option<u64>,
    #[serde(default)]
    assignments_backoff_max_seconds: Option<u64>,
    #[serde(default)]
    queued_job_polling: Option<crate::config::QueuedJobPolling>,
    #[serde(default = "jitter")]
    jitter_seconds: u64,
}
fn backoff() -> u64 {
    900
}
fn jitter() -> u64 {
    30
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Preparation {
    answer_while_blocked: bool,
    retry_uncertain: bool,
    max_attempts_per_work: u32,
}
impl Default for Preparation {
    fn default() -> Self {
        Self {
            answer_while_blocked: true,
            retry_uncertain: false,
            max_attempts_per_work: 2,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Participation {
    pub mode: ParticipationMode,
    pub uncertainty_grace_seconds: u64,
    pub max_unresolved_operations: u32,
    pub max_historical_unknown_answers: u32,
    pub historical_unknown_answer_capacity: HistoricalAnswerCapacity,
    pub answer_reserved_slots: u32,
    pub allow_answer: bool,
    pub allow_mine: bool,
    pub allow_judge: bool,
    pub retry_uncertain_answers: bool,
    pub uncertain_answer_retry_seconds: u64,
    pub max_answer_attempts_per_epoch: u32,
}
impl Default for Participation {
    fn default() -> Self {
        Self {
            mode: ParticipationMode::Strict,
            uncertainty_grace_seconds: 300,
            max_unresolved_operations: 4,
            max_historical_unknown_answers: 0,
            historical_unknown_answer_capacity: HistoricalAnswerCapacity::Bounded,
            answer_reserved_slots: 0,
            allow_answer: true,
            allow_mine: true,
            allow_judge: false,
            retry_uncertain_answers: false,
            uncertain_answer_retry_seconds: 600,
            max_answer_attempts_per_epoch: 2,
        }
    }
}
impl Default for Legacy {
    fn default() -> Self {
        let config = Config::default();
        Self {
            network: config.network,
            state_dir: config.state_dir,
            capabilities: Modes {
                answer: crate::config::Mode::ReadOnly,
                judge: crate::config::Mode::ReadOnly,
                mine: crate::config::Mode::ReadOnly,
            },
            solver: Models {
                answer: config.capabilities.answer.model,
                judge: config.capabilities.judge.model,
            },
            timeouts: Timeouts {
                http_seconds: 90,
                read_http_seconds: None,
                model_seconds: 300,
                shutdown_seconds: 30,
            },
            schedule: Schedule {
                poll_seconds: 120,
                mine_seconds: 86400,
                mine_each_epoch: false,
                retry_seconds: 180,
                backoff_max_seconds: 900,
                challenge_retry_seconds: None,
                challenge_backoff_max_seconds: None,
                assignments_retry_seconds: None,
                assignments_backoff_max_seconds: None,
                queued_job_polling: None,
                jitter_seconds: 30,
            },
            preparation: Preparation::default(),
            participation: Participation::default(),
            excluded_judging_assignments: vec![],
        }
    }
}
impl Legacy {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_BYTES,
            "legacy configuration exceeds 64 KiB"
        );
        let legacy: Self = toml::from_str(std::str::from_utf8(bytes)?)
            .map_err(|_| anyhow::anyhow!("invalid legacy configuration"))?;
        ensure!(
            legacy.participation.max_unresolved_operations
                > legacy.participation.answer_reserved_slots,
            "invalid legacy max/reservation"
        );
        Ok(legacy)
    }
    pub(super) fn candidate(&self, caps: Option<&Value>) -> Result<String> {
        let mut value = serde_json::to_value(Config::default())?;
        value["network"] = serde_json::to_value(&self.network)?;
        value["state_dir"] = json!(self.state_dir);
        let read = self
            .timeouts
            .read_http_seconds
            .unwrap_or(self.timeouts.http_seconds);
        value["runtime"] = json!({"shutdown_seconds":self.timeouts.shutdown_seconds});
        value["identity"] = json!({"read_http_seconds":read,"retry_seconds":self.schedule.retry_seconds,
            "backoff_max_seconds":self.schedule.backoff_max_seconds,"jitter_seconds":self.schedule.jitter_seconds});
        let p = &self.participation;
        if let Some(caps) = caps {
            ensure!(
                caps.as_object().is_some_and(|o| o.len() == 3),
                "caps requires answer, judge and mine"
            );
        } else {
            ensure!(
                p.mode == ParticipationMode::Strict
                    || (!p.allow_answer && !p.allow_judge && !p.allow_mine),
                super::MigrationError::LimitsRequired
            );
        }
        for (lane, mode, allowed) in [
            ("answer", self.capabilities.answer, p.allow_answer),
            ("judge", self.capabilities.judge, p.allow_judge),
            ("mine", self.capabilities.mine, p.allow_mine),
        ] {
            let cap = match caps {
                Some(c) => serde_json::from_value::<CountLimit>(c[lane].clone())
                    .context("explicit positive lane cap or unbounded required")?,
                None => CountLimit::Bounded(p.max_unresolved_operations),
            };
            let out = &mut value["capabilities"][lane];
            out["mode"] = json!(mode);
            out["participation"]["mode"] = json!(if allowed {
                p.mode
            } else {
                ParticipationMode::Strict
            });
            out["participation"]["uncertainty_grace_seconds"] = json!(p.uncertainty_grace_seconds);
            out["participation"]["max_unresolved_operations"] = json!(cap);
            out["timeouts"]["http_seconds"] = json!(self.timeouts.http_seconds);
            out["timeouts"]["read_http_seconds"] = json!(read);
            let s = &self.schedule;
            out["schedule"] = json!({"poll_seconds":s.poll_seconds,"retry_seconds":s.retry_seconds,
                "backoff_max_seconds":s.backoff_max_seconds,"jitter_seconds":s.jitter_seconds});
            let (retry, max) = if lane == "judge" {
                (
                    s.assignments_retry_seconds,
                    s.assignments_backoff_max_seconds,
                )
            } else {
                (s.challenge_retry_seconds, s.challenge_backoff_max_seconds)
            };
            if let Some(n) = retry {
                out["schedule"]["discovery_retry_seconds"] = json!(n);
            }
            if let Some(n) = max {
                out["schedule"]["discovery_backoff_max_seconds"] = json!(n);
            }
            if let Some(q) = s.queued_job_polling {
                out["schedule"]["queued_job_polling"] = json!(q);
            }
            if lane == "mine" {
                out["schedule"]["interval_seconds"] = json!(s.mine_seconds);
                out["schedule"]["each_epoch"] = json!(s.mine_each_epoch);
            } else {
                out["model"] = serde_json::to_value(if lane == "answer" {
                    &self.solver.answer
                } else {
                    &self.solver.judge
                })?;
                out["timeouts"]["model_seconds"] = json!(self.timeouts.model_seconds);
                out["preparation"] = json!({"while_blocked":(lane == "answer" && self.preparation.answer_while_blocked)
                    || (p.mode != ParticipationMode::Strict && allowed),
                    "retry_uncertain":self.preparation.retry_uncertain,"max_attempts_per_work":self.preparation.max_attempts_per_work});
            }
        }
        let answer = &mut value["capabilities"]["answer"]["participation"];
        answer["retry_uncertain_answers"] = json!(p.retry_uncertain_answers);
        answer["uncertain_answer_retry_seconds"] = json!(p.uncertain_answer_retry_seconds);
        answer["max_answer_attempts_per_epoch"] = json!(p.max_answer_attempts_per_epoch);
        answer["max_historical_unknown_answers"] = json!(p.max_historical_unknown_answers);
        answer["historical_unknown_answer_capacity"] = json!(p.historical_unknown_answer_capacity);
        value["capabilities"]["judge"]["excluded_assignments"] =
            json!(self.excluded_judging_assignments);
        Ok(toml::to_string_pretty(&value)?)
    }
    pub(super) fn risk(&self, candidate: &Config, unresolved: [u64; 3]) -> Value {
        let p = &self.participation;
        let kinds = LaneId::ALL;
        let caps = kinds.map(|kind| candidate.participation(kind).max_unresolved_operations);
        let unbounded_exposure = caps.iter().any(|cap| cap.finite().is_none());
        let model_cost_increased = [LaneId::Answer, LaneId::Judge].iter().any(|&kind| {
            let preparation = candidate.preparation(kind).expect("model lane");
            preparation
                .max_attempts_per_work
                .finite()
                .is_none_or(|limit| limit > self.preparation.max_attempts_per_work)
                || (preparation.retry_uncertain && !self.preparation.retry_uncertain)
                || preparation.max_uncertain_replacements_per_work > 1
                || (preparation.while_blocked
                    && !match kind {
                        LaneId::Answer => {
                            self.preparation.answer_while_blocked
                                || (p.mode != ParticipationMode::Strict && p.allow_answer)
                        }
                        LaneId::Judge => p.mode != ParticipationMode::Strict && p.allow_judge,
                        LaneId::Mine => false,
                    })
        });
        let all_strict = kinds
            .iter()
            .all(|kind| candidate.participation(*kind).mode == ParticipationMode::Strict);
        let answer = &candidate.capabilities.answer.participation;
        let no_recharge = answer.historical_unknown_answer_capacity
            == HistoricalAnswerCapacity::Bounded
            && answer.max_historical_unknown_answers == 0;
        let answer_retry_preserved = answer.max_answer_attempts_per_epoch
            <= p.max_answer_attempts_per_epoch
            && (!answer.retry_uncertain_answers
                || (p.retry_uncertain_answers
                    && answer.uncertain_answer_retry_seconds >= p.uncertain_answer_retry_seconds));
        let same_or_stricter = kinds.iter().enumerate().all(|(i, kind)| {
            let lane = candidate.participation(*kind);
            let allowed = [p.allow_answer, p.allow_judge, p.allow_mine][i];
            lane.mode == ParticipationMode::Strict
                || (allowed
                    && lane.mode == p.mode
                    && lane.uncertainty_grace_seconds >= p.uncertainty_grace_seconds)
        });
        let non_answer_risky = [LaneId::Judge, LaneId::Mine]
            .iter()
            .any(|kind| candidate.participation(*kind).mode != ParticipationMode::Strict);
        let bound = u64::from(
            p.max_unresolved_operations
                - if non_answer_risky {
                    p.answer_reserved_slots
                } else {
                    0
                },
        );
        let aggregate_caps = caps.iter().try_fold(0u64, |sum, cap| {
            cap.finite().map(|limit| sum + u64::from(limit))
        });
        let exposure = caps
            .iter()
            .zip(unresolved)
            .try_fold(0u64, |sum, (cap, used)| {
                cap.finite().map(|limit| sum + u64::from(limit).max(used))
            });
        let preserved = !unbounded_exposure
            && !model_cost_increased
            && answer_retry_preserved
            && (all_strict
                || (no_recharge
                    && same_or_stricter
                    && exposure.is_some_and(|value| value <= bound)));
        json!({"old_shared_max":p.max_unresolved_operations,"old_answer_reserved_slots":p.answer_reserved_slots,
            "proposed_caps":caps,"aggregate_caps":aggregate_caps,"unresolved_by_kind":unresolved,
            "exposure_including_backlog":exposure,"conservative_old_bound":bound,
            "over_cap":caps.iter().zip(unresolved).map(|(c,u)| c.finite().map(|limit| u.saturating_sub(u64::from(limit)))).collect::<Vec<_>>(),
            "unbounded_exposure":unbounded_exposure,"model_cost_increased":model_cost_increased,
            "answer_retry_policy_increased":!answer_retry_preserved,
            "recurring_inference_possible":([LaneId::Answer,LaneId::Judge].iter().any(|&kind| candidate.preparation(kind).is_some_and(|p|p.max_attempts_per_work.finite().is_none()))),
            "historical_recharge_possible":!no_recharge,"preservation_proven":preserved,
            "risk_change_required":!preserved,"old_policy":p,
            "new_policies":kinds.map(|kind| serde_json::to_value(candidate.participation(kind)).unwrap()),
            "answer_retry_history":answer,"model_cost_policy":{
                "answer":candidate.capabilities.answer.preparation,"judge":candidate.capabilities.judge.preparation}})
    }
}
