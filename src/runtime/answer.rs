use super::*;
use crate::solver::contract::AnswerTask;

pub(super) struct AnswerInputMatch {
    pending_key: PendingWorkKey,
    observation: Observation,
    matched_lane_config_revision: String,
}
impl AnswerInputMatch {
    pub(super) fn into_parts(self) -> (PendingWorkKey, Observation, String) {
        (
            self.pending_key,
            self.observation,
            self.matched_lane_config_revision,
        )
    }
}

enum Target {
    Prepared(Operation),
    Pending(PendingWorkKey),
}
struct ChallengeRead {
    flight: ReadFlight,
    target: Option<Target>,
}
struct ObservedChallenge {
    challenge: Challenge,
    observation: Observation,
}
#[derive(Default)]
pub(super) struct AnswerLane {
    read: Option<ChallengeRead>,
    observed: Option<ObservedChallenge>,
    model: AnswerModelSlot,
    pub(super) ready: Option<ReadyEffect>,
}
impl AnswerLane {
    #[cfg(test)]
    pub(in crate::runtime) fn with_model_for_test(model: AnswerModelSlot) -> Self {
        Self {
            model,
            ..Self::default()
        }
    }
    pub(super) fn busy(&self) -> bool {
        self.read.is_some() || self.model.busy()
    }

    pub(super) fn collect(&mut self, services: &mut AnswerServices<'_>) -> Result<()> {
        services.collect_reconciliation()?;
        services.collect_model(&mut self.model)?;
        let Some(read) = self.read.as_mut() else {
            return Ok(());
        };
        let Some(result) = read.flight.take() else {
            return Ok(());
        };
        let read = self.read.take().expect("answer read completion");
        let Some(response) = services.finish_read(&read.flight, result)? else {
            return Ok(());
        };
        let Some(challenge) = services.observe_challenge(&read.flight, &response)? else {
            return Ok(());
        };
        let observation = services.observation(&read.flight)?;
        services.participation(&observation, &json!({"source":"validated_challenge","observed_at":read.flight.completed_at,
            "valid_until":read.flight.completed_at.saturating_add(services.config().timeouts.read_http_seconds as i64),
            "completeness":"single_challenge","observed_opportunities":1,
            "locally_eligible":!challenge.answered,"exclusion_reason":if challenge.answered {Some("already_answered")} else {None},
            "assessment_creates_model_work":false,"outcome":"unobserved"}))?;
        match read.target {
            Some(Target::Prepared(op)) => {
                let binding = services.binding(&op)?;
                if !services.draft_current(&binding)? {
                    return Ok(());
                }
                let input: Input = serde::Deserialize::deserialize(&op.request)?;
                if challenge_matches(
                    &challenge,
                    &input.solver,
                    input.challenge_fingerprint.as_deref(),
                    true,
                ) {
                    let intent = crate::protocol::AnswerIntent::new(
                        op.payload.as_ref().context("answer payload missing")?,
                    )?;
                    self.ready = Some(services.emit_ready(intent, binding, observation)?);
                } else {
                    services.retire_unsent(&binding, "request_no_longer_current")?;
                }
            }
            Some(Target::Pending(key)) => {
                self.revalidate_pending(services, &challenge, observation.clone(), Some(&key))?;
                if self.model.pending_work().is_some() {
                    self.observed = Some(ObservedChallenge {
                        challenge,
                        observation,
                    });
                }
            }
            None => {
                self.observed = Some(ObservedChallenge {
                    challenge,
                    observation,
                })
            }
        }
        Ok(())
    }

    fn revalidate_pending(
        &mut self,
        services: &mut AnswerServices<'_>,
        challenge: &Challenge,
        observation: Observation,
        expected: Option<&PendingWorkKey>,
    ) -> Result<()> {
        let Some(pending) = self.model.pending_work() else {
            return Ok(());
        };
        if expected.is_some_and(|key| key != &pending.key) {
            return Ok(());
        }
        let key = pending.key.clone();
        let current = services.observation_current(&observation)?;
        let decision = match_pending(
            challenge,
            pending,
            self.model.pending_challenge_fingerprint(),
            observation,
            &services.lane_revision()?,
            current,
        );
        match decision {
            PendingInputDecision::Unchanged(matched) => {
                services.launch_pending(&mut self.model, matched)
            }
            PendingInputDecision::Retire(reason) => {
                services.retire_pending(&mut self.model, &key, reason.code())
            }
            PendingInputDecision::Wait(_reason) => Ok(()),
        }
    }

    pub(super) fn plan(&mut self, services: &mut AnswerServices<'_>) -> Result<()> {
        services.poll_reconciliation()?;
        if let Some(ready) = self.ready.as_ref()
            && !services.ready_current(ready)?
        {
            self.ready = None;
        }
        if self.model.pending_work().is_some() {
            if services.config().mode == Mode::Off {
                let key = self.model.pending_work().expect("pending answer").key;
                services.retire_pending(&mut self.model, &key, "model_lane_off")?;
            } else if services.active()? {
                if let Some(observed) = self.observed.take()
                    && services.observation_current(&observed.observation)?
                {
                    self.revalidate_pending(
                        services,
                        &observed.challenge,
                        observed.observation.clone(),
                        None,
                    )?;
                    if self.model.pending_work().is_some() {
                        self.observed = Some(observed);
                    }
                }
                if self.read.is_none()
                    && self.observed.is_none()
                    && let Some(pending) = self.model.pending_work()
                {
                    let key = pending.key;
                    if services.fresh_allowed(key.operation.operation_id)
                        && let Some(flight) = services.begin_discovery()?
                    {
                        self.read = Some(ChallengeRead {
                            flight,
                            target: Some(Target::Pending(key)),
                        });
                        services.start_identity()?;
                    }
                }
            }
        }
        let preparation = services.preparation()?;
        if let Some(op) = preparation
            && self.read.is_none()
            && self.ready.is_none()
            && services.active()?
            && services.admission_allowed(&op)?
            && op.next_at <= services.deadline_now()
            && services.fresh_allowed(op.id)
            && let Some(flight) = services.begin_discovery()?
        {
            self.read = Some(ChallengeRead {
                flight,
                target: Some(Target::Prepared(op)),
            });
            services.start_identity()?;
        }
        if self.read.is_none()
            && services.discovery_allowed()?
            && let Some(flight) = services.begin_discovery()?
        {
            services.discovered()?;
            self.read = Some(ChallengeRead {
                flight,
                target: None,
            });
        }
        if self.model.occupied()
            || services.effect_busy()
            || services.has_preparation()?
            || !services.active()?
        {
            return Ok(());
        }
        let Some(observed) = self.observed.as_ref() else {
            return Ok(());
        };
        if !services.observation_current(&observed.observation)? || observed.challenge.answered {
            self.observed = None;
            return Ok(());
        }
        let challenge = &observed.challenge;
        let key = format!("{}:{}", challenge.epoch, challenge.fingerprint);
        let retry = if services.answer_epoch_attempted(challenge.epoch)? {
            let Some(original) = services.uncertain_answer(challenge.epoch)? else {
                return Ok(());
            };
            if !services.answer_retry_allowed(&original)? {
                return Ok(());
            }
            Some(original)
        } else {
            None
        };
        let begun = if let Some(original) = retry.as_ref().filter(|op| op.key == key) {
            let binding = services.binding(original)?;
            services.begin_retry(&binding, &key, &observed.observation)?
        } else {
            let task = services.task(challenge)?;
            services.begin_model(
                &mut self.model,
                task,
                challenge.fingerprint.clone(),
                &key,
                retry.as_ref(),
                &observed.observation,
            )?
        };
        if begun {
            self.observed = None;
        }
        Ok(())
    }

    pub(super) async fn cancel(
        &mut self,
        services: &mut AnswerServices<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        if let Some(read) = self.read.as_mut() {
            read.flight.abort(deadline).await;
        }
        self.collect(services)?;
        if let Some(read) = self.read.take() {
            services.cancel_read(&read.flight)?;
        }
        services.cancel_reconciliation(deadline).await?;
        services.cancel_model(&mut self.model, deadline).await
    }
}

fn match_pending(
    challenge: &Challenge,
    pending: PendingWorkRef<'_, AnswerTask>,
    fingerprint: Option<&str>,
    observation: Observation,
    revision: &str,
    current: bool,
) -> PendingInputDecision<AnswerInputMatch> {
    if revision != pending.producer.lane_config_revision {
        return PendingInputDecision::Retire(PendingRetirementReason::ConfigChanged);
    }
    if !current {
        return PendingInputDecision::Wait(PendingWaitReason::ObservationStale);
    }
    if !challenge_matches(challenge, pending.task.request(), fingerprint, true) {
        return PendingInputDecision::Retire(PendingRetirementReason::InputChanged);
    }
    PendingInputDecision::Unchanged(AnswerInputMatch {
        pending_key: pending.key,
        observation,
        matched_lane_config_revision: revision.to_owned(),
    })
}
pub(super) fn challenge_matches(
    challenge: &Challenge,
    request: &SolverRequest,
    fingerprint: Option<&str>,
    answer: bool,
) -> bool {
    challenge.epoch == request.epoch
        && fingerprint == Some(challenge.fingerprint.as_str())
        && challenge.words == request.words
        && challenge.min_chars == request.min_chars
        && challenge.max_chars == request.max_chars
        && (!answer || !challenge.answered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::contract::ModelSelection;
    fn inputs() -> (Challenge, AnswerTask, ModelProducerProvenance, Observation) {
        let challenge = Challenge {
            epoch: 8,
            words: vec!["burn".into()],
            answered: false,
            min_chars: 4,
            max_chars: 100,
            fingerprint: "original".into(),
        };
        let task = AnswerTask::new(SolverRequest {
            id: "request".into(),
            kind: LaneId::Answer,
            epoch: 8,
            words: challenge.words.clone(),
            min_chars: 4,
            max_chars: 100,
            assignment: None,
            candidate: None,
            history: Vec::new(),
            guidance: String::new(),
            core_guidance: "Evaluate protocol input.".into(),
            author_history: None,
            candidate_author: None,
        })
        .unwrap();
        let stamp = AdmissionStampSnapshot {
            account_generation: 1,
            lane_control_revision: 7,
            authority_epoch: 3,
            lane_config_revision: "config".into(),
        };
        let producer = ModelProducerProvenance {
            operation: OperationBinding {
                database_id: "db".into(),
                operation_id: 9,
                lane_id: LaneId::Answer,
                binding_revision: 0,
            },
            task_kind: "answer".into(),
            request_id: "request".into(),
            request_digest: "digest".into(),
            lane_config_revision: "config".into(),
            requested: ModelSelection::new(&crate::config::ModelConfig::default()).unwrap(),
            preflight_admission: stamp.clone(),
            created_at: 1,
        };
        let completed = Instant::now();
        let observation = Observation {
            stamp,
            admit_before: completed + Duration::from_secs(10),
            admit_before_unix: 11,
        };
        (challenge, task, producer, observation)
    }
    #[test]
    fn pending_answer_uses_canonical_match_and_distinguishes_stale_observation() {
        let (mut challenge, task, producer, observation) = inputs();
        let descriptor = || PendingWorkRef {
            key: PendingWorkKey {
                operation: producer.operation.clone(),
                request_digest: producer.request_digest.clone(),
            },
            task: &task,
            producer: &producer,
        };
        assert!(matches!(
            match_pending(
                &challenge,
                descriptor(),
                Some("original"),
                observation.clone(),
                "config",
                true
            ),
            PendingInputDecision::Unchanged(_)
        ));
        assert!(matches!(
            match_pending(
                &challenge,
                descriptor(),
                Some("original"),
                observation.clone(),
                "config",
                false
            ),
            PendingInputDecision::Wait(PendingWaitReason::ObservationStale)
        ));
        assert!(matches!(
            match_pending(
                &challenge,
                descriptor(),
                Some("original"),
                observation.clone(),
                "changed",
                true
            ),
            PendingInputDecision::Retire(PendingRetirementReason::ConfigChanged)
        ));
        challenge.answered = true;
        assert!(matches!(
            match_pending(
                &challenge,
                descriptor(),
                Some("original"),
                observation.clone(),
                "config",
                true
            ),
            PendingInputDecision::Retire(PendingRetirementReason::InputChanged)
        ));
        challenge.answered = false;
        challenge.words.push("changed".into());
        assert!(matches!(
            match_pending(
                &challenge,
                descriptor(),
                Some("original"),
                observation,
                "config",
                true
            ),
            PendingInputDecision::Retire(PendingRetirementReason::InputChanged)
        ));
        assert_eq!(producer.preflight_admission.lane_control_revision, 7);
    }

    #[test]
    fn pending_and_prepared_answer_share_every_challenge_field_and_mine_answer_policy() {
        for changed in [
            "unchanged",
            "epoch",
            "fingerprint",
            "missing_fingerprint",
            "words",
            "min",
            "max",
            "answered",
        ] {
            let (mut challenge, task, producer, observation) = inputs();
            let mut fingerprint = Some("original");
            match changed {
                "epoch" => challenge.epoch += 1,
                "fingerprint" => challenge.fingerprint.push_str("-changed"),
                "missing_fingerprint" => fingerprint = None,
                "words" => challenge.words.push("changed".into()),
                "min" => challenge.min_chars += 1,
                "max" => challenge.max_chars += 1,
                "answered" => challenge.answered = true,
                _ => {}
            }
            let pending = PendingWorkRef {
                key: PendingWorkKey {
                    operation: producer.operation.clone(),
                    request_digest: producer.request_digest.clone(),
                },
                task: &task,
                producer: &producer,
            };
            let prepared = challenge_matches(&challenge, task.request(), fingerprint, true);
            assert_eq!(prepared, changed == "unchanged", "{changed}");
            assert_eq!(
                matches!(
                    match_pending(
                        &challenge,
                        pending,
                        fingerprint,
                        observation,
                        "config",
                        true
                    ),
                    PendingInputDecision::Unchanged(_)
                ),
                prepared,
                "{changed}: pending and prepared must agree",
            );
            assert_eq!(
                challenge_matches(&challenge, task.request(), fingerprint, false),
                matches!(changed, "unchanged" | "answered"),
                "{changed}: mining does not require an unanswered challenge",
            );
        }
    }
}
