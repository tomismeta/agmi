//! The three write-once model facts, committed with their corresponding journal state.
use super::*;
use crate::solver::SolverRequest;
use crate::solver::contract::{
    AnswerTask, CancellationEvidence, GradeTask, LocalProcessStop, ModelSelection,
    NativeAttemptCompletion, NativeExecution, NativeOutcome, NativePhase, NativeReasonCode,
    NativeRequest, RemoteRunStop,
};
use anyhow::ensure;
use serde::{Deserialize, Serialize};

const MAX_MODEL_ATTEMPT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelProducerDraft {
    pub task_kind: String,
    pub request_id: String,
    pub request_digest: String,
    pub lane_config_revision: String,
    pub requested: ModelSelection,
    pub preflight_admission: AdmissionStampSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelProducerProvenance {
    pub operation: OperationBinding,
    pub task_kind: String,
    pub request_id: String,
    pub request_digest: String,
    pub lane_config_revision: String,
    pub requested: ModelSelection,
    pub preflight_admission: AdmissionStampSnapshot,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelLaunchRecord {
    pub admission: AdmissionStampSnapshot,
    pub admitted_at: i64,
    pub execution_deadline: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelAttemptRecord {
    pub producer: ModelProducerProvenance,
    pub launch: Option<ModelLaunchRecord>,
    pub completion: Option<NativeAttemptCompletion>,
}

fn task_kind(lane: LaneId) -> Result<&'static str> {
    match lane {
        LaneId::Answer => Ok("answer"),
        LaneId::Judge => Ok("grade"),
        LaneId::Mine => bail!("mining has no model attempt"),
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}

fn validate_completion(completion: &NativeAttemptCompletion) -> Result<()> {
    let reported = &completion.reported;
    for value in [
        &reported.provider,
        &reported.model,
        &reported.reasoning_effort,
        &reported.run_id,
        &reported.winner_provider,
        &reported.winner_model,
        &reported.prompt_channel,
    ]
    .into_iter()
    .flatten()
    {
        ensure!(
            valid_identifier(&value.value),
            "invalid bounded native evidence identifier"
        );
    }
    for count in [&reported.tool_count, &reported.bootstrap_file_count]
        .into_iter()
        .flatten()
    {
        ensure!(
            count.value <= 1_000_000,
            "native evidence count exceeds bound"
        );
    }
    for at in [
        completion.collected_at,
        completion.preflight_started_at,
        completion.inference_spawned_at,
        completion.cancellation.requested_at,
    ]
    .into_iter()
    .flatten()
    {
        ensure!(at >= 0, "invalid native evidence timestamp");
    }
    Ok(())
}

fn encode_attempt(record: &ModelAttemptRecord) -> Result<String> {
    let encoded = serde_json::to_string(record)?;
    ensure!(
        encoded.len() <= MAX_MODEL_ATTEMPT_BYTES,
        "model attempt exceeds evidence bound"
    );
    Ok(encoded)
}

fn read_attempt_in(db: &Connection, id: i64) -> Result<Option<(String, ModelAttemptRecord)>> {
    let encoded: Option<String> = db
        .query_row(
            "SELECT model_attempt FROM operation_evidence WHERE operation_id=?1",
            [id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    encoded
        .map(|encoded| {
            ensure!(
                encoded.len() <= MAX_MODEL_ATTEMPT_BYTES,
                "model attempt exceeds evidence bound"
            );
            let record =
                serde_json::from_str(&encoded).context("invalid retained model attempt")?;
            Ok((encoded, record))
        })
        .transpose()
}

fn validate_bound_attempt_in(
    db: &Connection,
    binding: &OperationBinding,
    record: &ModelAttemptRecord,
) -> Result<()> {
    ensure!(
        Store::validate_operation_binding_in(db, binding)?,
        "model operation binding changed"
    );
    ensure!(
        record.producer.operation == *binding,
        "model producer binding mismatch"
    );
    ensure!(
        record.producer.task_kind == task_kind(binding.lane_id)?,
        "model producer role mismatch"
    );
    let (generation, revision, created_at): (i64, String, i64) = db.query_row(
        "SELECT generation,revision,created_at FROM operations WHERE id=?1",
        [binding.operation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    ensure!(
        generation == record.producer.preflight_admission.account_generation
            && revision == record.producer.lane_config_revision
            && revision == record.producer.preflight_admission.lane_config_revision
            && created_at == record.producer.created_at,
        "model producer journal provenance mismatch"
    );
    Ok(())
}

fn bound_attempt_in(
    db: &Connection,
    binding: &OperationBinding,
) -> Result<(String, ModelAttemptRecord)> {
    let (encoded, record) =
        read_attempt_in(db, binding.operation_id)?.context("operation has no model producer")?;
    validate_bound_attempt_in(db, binding, &record)?;
    Ok((encoded, record))
}

fn replace_attempt_in(
    db: &Connection,
    id: i64,
    previous: &str,
    record: &ModelAttemptRecord,
) -> Result<()> {
    let changed = db.execute(
        "UPDATE operation_evidence SET model_attempt=?3
         WHERE operation_id=?1 AND model_attempt=?2",
        params![id, previous, encode_attempt(record)?],
    )?;
    ensure!(changed == 1, "model attempt changed during transition");
    Ok(())
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_model_attempt(
        &mut self,
        config: &Config,
        account: &AccountAdmissionGuard,
        lane_guard: &LaneAdmissionGuard,
        stamp: &AdmissionStampSnapshot,
        lane: LaneId,
        key: &str,
        request: &Value,
        retry: Option<(&Operation, bool)>,
        policy: &Value,
        draft: ModelProducerDraft,
    ) -> Result<Option<(Operation, ModelProducerProvenance)>> {
        self.continuity()?;
        ensure!(
            lane_guard.lane_id() == lane,
            "model admission lane guard mismatch"
        );
        ensure!(
            draft.task_kind == task_kind(lane)?,
            "model draft role mismatch"
        );
        ensure!(
            draft.preflight_admission == *stamp
                && draft.lane_config_revision == stamp.lane_config_revision
                && draft.lane_config_revision == config.lane_revision(lane)?,
            "model draft admission mismatch"
        );
        let model = config.model(lane).context("model route missing")?;
        ensure!(
            draft.requested == ModelSelection::new(model)?,
            "model draft route mismatch"
        );
        let wire =
            SolverRequest::deserialize(request.get("solver").context("model request missing")?)?;
        ensure!(
            wire.kind == lane && wire.id == draft.request_id,
            "model draft request binding mismatch"
        );
        ensure!(
            wire.guidance == model.guidance.as_ref()
                && wire.core_guidance == model.core_guidance.as_ref(),
            "model request guidance mismatch"
        );
        let native = match lane {
            LaneId::Answer => NativeRequest::Answer(AnswerTask::new(wire)?),
            LaneId::Judge => NativeRequest::Grade(GradeTask::new(wire)?),
            LaneId::Mine => unreachable!("model lane checked above"),
        };
        ensure!(
            draft.request_digest == native.digest()?,
            "model draft request digest mismatch"
        );
        ensure!(
            retry.is_none_or(|(_, reused)| !reused),
            "model attempt cannot reuse a payload"
        );
        ensure!(
            policy["lane_revision"].as_str() == Some(draft.lane_config_revision.as_str())
                && policy["model_seconds"].as_u64() == config.model_seconds(lane),
            "model captured policy mismatch"
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !Self::validate_admission_in(&tx, config, account, lane_guard, stamp, None)? {
            return Ok(None);
        }
        let id = Self::begin_linked_in(
            &tx,
            lane,
            key,
            ("generating", request),
            Control {
                paused: false,
                generation: stamp.account_generation,
            },
            &draft.lane_config_revision,
            retry,
        )?;
        let (database_id, binding_revision, created_at): (String, i64, i64) = tx.query_row(
            "SELECT a.database_id,o.binding_revision,o.created_at
             FROM operations o JOIN authority a ON a.singleton=1 WHERE o.id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let record = ModelAttemptRecord {
            producer: ModelProducerProvenance {
                operation: OperationBinding {
                    database_id,
                    operation_id: id,
                    lane_id: lane,
                    binding_revision,
                },
                task_kind: draft.task_kind,
                request_id: draft.request_id,
                request_digest: draft.request_digest,
                lane_config_revision: draft.lane_config_revision,
                requested: draft.requested,
                preflight_admission: draft.preflight_admission,
                created_at,
            },
            launch: None,
            completion: None,
        };
        tx.execute(
            "INSERT INTO operation_evidence(operation_id,policy,model_attempt) VALUES(?1,?2,?3)",
            params![id, serde_json::to_string(policy)?, encode_attempt(&record)?],
        )?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        Ok(Some((
            self.operation(id)?
                .context("durable model operation missing")?,
            record.producer,
        )))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_model_launch(
        &mut self,
        config: &Config,
        account: &AccountAdmissionGuard,
        lane_guard: &LaneAdmissionGuard,
        stamp: &AdmissionStampSnapshot,
        binding: &OperationBinding,
        deadline: i64,
        observation_admit_before: std::time::Instant,
    ) -> Result<bool> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if std::time::Instant::now() >= observation_admit_before {
            return Ok(false);
        }
        let (previous, mut record) = bound_attempt_in(&tx, binding)?;
        ensure!(
            record.completion.is_none(),
            "completed model attempt cannot launch"
        );
        let (state, captured_deadline): (String, Option<i64>) = tx.query_row(
            "SELECT o.state,e.model_deadline FROM operations o
             JOIN operation_evidence e ON e.operation_id=o.id WHERE o.id=?1",
            [binding.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure!(
            state == "generating",
            "model launch requires generating operation"
        );
        if let Some(launch) = &record.launch {
            ensure!(
                launch.admission == *stamp
                    && launch.execution_deadline == deadline
                    && captured_deadline == Some(deadline),
                "conflicting model launch replacement"
            );
            // An idempotent journal retry is not permission for another native spawn.
            return Ok(false);
        }
        ensure!(
            captured_deadline.is_none(),
            "model deadline has no launch provenance"
        );
        if record.producer.lane_config_revision != stamp.lane_config_revision
            || !Self::validate_admission_in(&tx, config, account, lane_guard, stamp, Some(binding))?
        {
            return Ok(false);
        }
        let admitted_at = now();
        if deadline <= admitted_at {
            return Ok(false);
        }
        let pending_deadline: Option<i64> = tx.query_row(
            "SELECT json_extract(policy,'$.pending_execution_deadline')
             FROM operation_evidence WHERE operation_id=?1",
            [binding.operation_id],
            |row| row.get(0),
        )?;
        ensure!(
            pending_deadline == Some(deadline),
            "model launch differs from captured execution deadline"
        );
        record.launch = Some(ModelLaunchRecord {
            admission: stamp.clone(),
            admitted_at,
            execution_deadline: deadline,
        });
        replace_attempt_in(&tx, binding.operation_id, &previous, &record)?;
        let changed = tx.execute(
            "UPDATE operation_evidence SET model_deadline=?2,
             evidence='{\"stage\":\"model\",\"execution\":\"launch_admitted\"}',observed_at=?3
             WHERE operation_id=?1 AND model_deadline IS NULL",
            params![binding.operation_id, deadline, admitted_at],
        )?;
        ensure!(changed == 1, "model launch deadline changed");
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        if std::time::Instant::now() >= observation_admit_before || now() >= deadline {
            return Ok(false);
        }
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn capture_model_pending(
        &mut self,
        id: i64,
        remaining_millis: u64,
        execution_deadline_unix: i64,
    ) -> Result<()> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, record) = read_attempt_in(&tx, id)?.context("operation has no model producer")?;
        ensure!(
            record.producer.operation.operation_id == id,
            "model pending operation mismatch"
        );
        validate_bound_attempt_in(&tx, &record.producer.operation, &record)?;
        ensure!(
            record.launch.is_none() && record.completion.is_none(),
            "model attempt is no longer pending"
        );
        let (state, deadline, policy): (String, Option<i64>, String) = tx.query_row(
            "SELECT o.state,e.model_deadline,e.policy FROM operations o
             JOIN operation_evidence e ON e.operation_id=o.id WHERE o.id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        ensure!(
            state == "generating" && deadline.is_none(),
            "model attempt is not awaiting launch"
        );
        let mut policy: Value = serde_json::from_str(&policy)?;
        if let Some(captured) = policy.get("pending_execution_deadline") {
            ensure!(
                captured.as_i64() == Some(execution_deadline_unix),
                "conflicting pending model deadline"
            );
        }
        policy["pending_execution_deadline"] = json!(execution_deadline_unix);
        let configured = policy["model_seconds"]
            .as_u64()
            .context("captured model budget missing")?;
        ensure!(
            remaining_millis <= configured.saturating_mul(1000)
                && remaining_millis <= i64::MAX as u64,
            "pending model budget exceeds captured policy"
        );
        let evidence = json!({"stage":"model_preflight","execution":"not_started",
            "state":"awaiting_admission","remaining_budget_millis":remaining_millis});
        // Completion of an already-started preflight is evidence, not new admission:
        // a pause or account-generation change must not discard this fact.
        tx.execute(
            "UPDATE operation_evidence SET evidence=?2,observed_at=?3,policy=?4 WHERE operation_id=?1",
            params![id, serde_json::to_string(&evidence)?, now(), serde_json::to_string(&policy)?],
        )?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn finish_model_attempt(
        &mut self,
        binding: &OperationBinding,
        op: &Operation,
        completion: &NativeAttemptCompletion,
        event: &str,
    ) -> Result<()> {
        self.continuity()?;
        validate_completion(completion)?;
        ensure!(
            op.id == binding.operation_id
                && op.kind == binding.lane_id
                && op.binding_revision == binding.binding_revision
                && op.persisted_binding_revision.get() == binding.binding_revision,
            "native completion operation binding mismatch"
        );
        ensure!(
            !event.is_empty()
                && event
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "invalid local event code"
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (previous, mut record) = bound_attempt_in(&tx, binding)?;
        let (state, key, request, generation, result, payload, job, txid, next_at): (
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
        ) = tx.query_row(
            "SELECT state,work_key,request,generation,result,payload,job_id,txid,next_at
             FROM operations WHERE id=?1",
            [op.id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )?;
        ensure!(
            key == op.key
                && serde_json::from_str::<Value>(&request)? == op.request
                && generation == op.generation,
            "native completion immutable operation mismatch"
        );
        if let Some(retained) = &record.completion {
            ensure!(
                retained == completion,
                "conflicting model completion replacement"
            );
            ensure!(
                state == op.state
                    && result
                        .map(|value| serde_json::from_str::<Value>(&value))
                        .transpose()?
                        == op.result
                    && payload
                        .map(|value| serde_json::from_str::<Value>(&value))
                        .transpose()?
                        == op.payload
                    && job == op.job_id
                    && txid == op.txid
                    && next_at == op.next_at,
                "conflicting finalized model transition"
            );
            Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
            tx.commit()?;
            Self::transition_committed(op, &op.state, binding.binding_revision);
            return Ok(());
        }
        ensure!(
            state == "generating" && op.persisted_state.borrow().as_str() == "generating",
            "native completion requires generating operation"
        );
        ensure!(
            job.is_none() && txid.is_none() && op.job_id.is_none() && op.txid.is_none(),
            "native completion cannot create protocol effects"
        );
        ensure!(
            record.launch.is_some()
                || (completion.execution == NativeExecution::NotStarted
                    && completion.inference_spawned_at.is_none()),
            "native completion has no launch admission"
        );
        let target = match (completion.execution, completion.outcome) {
            (NativeExecution::Completed, NativeOutcome::Captured) => {
                ensure!(op.result.is_some(), "captured model result missing");
                "generated"
            }
            (NativeExecution::Completed, NativeOutcome::Invalid) => "rejected",
            (NativeExecution::NotStarted, NativeOutcome::NotStarted) => "prelaunch_failed",
            (NativeExecution::Unknown, NativeOutcome::Unknown) => "model_unknown",
            _ => bail!("contradictory native completion certainty"),
        };
        ensure!(
            op.state == target || op.state == "discarded",
            "native completion state mismatch"
        );
        ensure!(
            if op.state == "generated" {
                op.payload.is_some()
            } else {
                op.payload.is_none()
            },
            "native completion payload state mismatch"
        );
        record.completion = Some(completion.clone());
        replace_attempt_in(&tx, op.id, &previous, &record)?;
        // No current-control admission check: safely sourced results survive fences.
        let revision = Self::save_transition_in(&tx, op, event, &op.state, None)?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        Self::transition_committed(op, &op.state, revision);
        Ok(())
    }

    pub(crate) fn model_attempt(&self, id: i64) -> Result<Option<ModelAttemptRecord>> {
        Ok(read_attempt_in(&self.db, id)?.map(|(_, record)| record))
    }

    /// Called inside the existing startup recovery transaction, before its
    /// generating -> model_unknown transition. Never changes retry eligibility.
    pub(super) fn recover_interrupted_model(db: &Connection) -> Result<()> {
        ensure!(
            !db.is_autocommit(),
            "model recovery requires the recovery transaction"
        );
        let mut statement = db.prepare(
            "SELECT o.id FROM operations o JOIN operation_evidence e ON e.operation_id=o.id
             WHERE o.state='generating' AND e.model_attempt IS NOT NULL ORDER BY o.id",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for id in ids {
            let (previous, mut record) =
                read_attempt_in(db, id)?.context("model producer disappeared during recovery")?;
            if record.completion.is_some() {
                continue;
            }
            ensure!(
                record.producer.operation.operation_id == id,
                "model recovery operation mismatch"
            );
            validate_bound_attempt_in(db, &record.producer.operation, &record)?;
            let launched = record.launch.is_some();
            record.completion = Some(NativeAttemptCompletion {
                phase: NativePhase::Recovery,
                execution: if launched {
                    NativeExecution::Unknown
                } else {
                    NativeExecution::NotStarted
                },
                outcome: if launched {
                    NativeOutcome::Unknown
                } else {
                    NativeOutcome::NotStarted
                },
                reason_code: NativeReasonCode::Interrupted,
                collected_at: Some(now()),
                preflight_started_at: None,
                inference_spawned_at: None,
                reported: Default::default(),
                cancellation: CancellationEvidence {
                    requested_at: None,
                    local_process_stop: LocalProcessStop::Unknown,
                    remote_run_stop: if launched {
                        RemoteRunStop::Unknown
                    } else {
                        RemoteRunStop::NotRequested
                    },
                },
            });
            replace_attempt_in(db, id, &previous, &record)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::contract::{EvidenceSource, NativeReportedEvidence, Reported};

    fn fixture(
        launched: bool,
    ) -> (
        tempfile::TempDir,
        Config,
        Store,
        Operation,
        ModelAttemptRecord,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: dir.path().join("state"),
            ..Config::default()
        };
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        let control = store.control().unwrap();
        let revision = config.lane_revision(LaneId::Answer).unwrap();
        let database_id = store.database_identity().unwrap().0;
        let tx = store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let id = Store::begin_linked_in(
            &tx,
            LaneId::Answer,
            "model-fixture",
            (
                "generating",
                &json!({"solver":{"id":"request","kind":"answer","epoch":1}}),
            ),
            control,
            &revision,
            None,
        )
        .unwrap();
        let (created_at, binding_revision): (i64, i64) = tx
            .query_row(
                "SELECT created_at,binding_revision FROM operations WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let stamp = AdmissionStampSnapshot {
            account_generation: control.generation,
            lane_control_revision: 0,
            authority_epoch: 1,
            lane_config_revision: revision.clone(),
        };
        let record = ModelAttemptRecord {
            producer: ModelProducerProvenance {
                operation: OperationBinding {
                    database_id,
                    operation_id: id,
                    lane_id: LaneId::Answer,
                    binding_revision,
                },
                task_kind: "answer".into(),
                request_id: "request".into(),
                request_digest: digest("native-request"),
                lane_config_revision: revision.clone(),
                requested: ModelSelection::new(config.model(LaneId::Answer).unwrap()).unwrap(),
                preflight_admission: stamp.clone(),
                created_at,
            },
            launch: launched.then(|| ModelLaunchRecord {
                admission: AdmissionStampSnapshot {
                    lane_control_revision: 2,
                    ..stamp
                },
                admitted_at: created_at,
                execution_deadline: created_at + 10,
            }),
            completion: None,
        };
        tx.execute(
            "INSERT INTO operation_evidence(operation_id,policy,model_attempt,model_deadline)
             VALUES(?1,?2,?3,?4)",
            params![
                id,
                json!({"model_seconds":10,"lane_revision":revision}).to_string(),
                encode_attempt(&record).unwrap(),
                record
                    .launch
                    .as_ref()
                    .map(|launch| launch.execution_deadline)
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        let op = store.operation(id).unwrap().unwrap();
        (dir, config, store, op, record)
    }

    fn completion(execution: NativeExecution, outcome: NativeOutcome) -> NativeAttemptCompletion {
        NativeAttemptCompletion {
            phase: if execution == NativeExecution::NotStarted {
                NativePhase::Preflight
            } else {
                NativePhase::ArtifactValidation
            },
            execution,
            outcome,
            reason_code: NativeReasonCode::NativeProvenanceMismatch,
            collected_at: Some(now()),
            preflight_started_at: Some(now()),
            inference_spawned_at: (execution != NativeExecution::NotStarted).then(now),
            reported: NativeReportedEvidence {
                model: Some(Reported {
                    value: "reported-other-model".into(),
                    source: EvidenceSource::NativeEnvelope,
                }),
                fallback_used: Some(Reported {
                    value: true,
                    source: EvidenceSource::NativeEnvelope,
                }),
                run_id: Some(Reported {
                    value: "reported-run".into(),
                    source: EvidenceSource::NativeEnvelope,
                }),
                ..Default::default()
            },
            cancellation: Default::default(),
        }
    }

    #[test]
    fn rejected_native_facts_survive_controls_diagnostics_recovery_and_reopen() {
        let (_dir, config, mut store, mut op, before) = fixture(true);
        store.set_paused_unbound(true).unwrap();
        let facts = completion(NativeExecution::Unknown, NativeOutcome::Unknown);
        op.state = "model_unknown".into();
        store
            .finish_model_attempt(
                &before.producer.operation,
                &op,
                &facts,
                "native_provenance_mismatch",
            )
            .unwrap();
        let retained = store.model_attempt(op.id).unwrap().unwrap();
        assert_eq!(retained.producer, before.producer);
        assert_eq!(retained.launch, before.launch);
        assert_eq!(retained.completion.as_ref(), Some(&facts));
        assert_ne!(
            retained.producer.requested.model(),
            facts.reported.model.as_ref().unwrap().value
        );
        store
            .record_evidence(
                op.id,
                &json!({"stage":"reconciliation","state":"unresolved"}),
            )
            .unwrap();
        store.recover().unwrap();
        drop(store);
        let reopened = Store::read_only(&config).unwrap().unwrap();
        assert_eq!(reopened.model_attempt(op.id).unwrap().unwrap(), retained);
        assert_eq!(
            reopened.operation(op.id).unwrap().unwrap().state,
            "model_unknown"
        );
    }

    #[test]
    fn completion_is_idempotent_but_never_replaces_truth_or_accepts_wrong_binding() {
        let (_dir, _config, mut store, mut op, before) = fixture(true);
        let facts = completion(NativeExecution::Completed, NativeOutcome::Captured);
        op.result = Some(json!({"answer":"captured"}));
        op.payload = Some(json!({"answer":"captured"}));
        op.state = "generated".into();
        for bad in [
            OperationBinding {
                database_id: "another-database".into(),
                ..before.producer.operation.clone()
            },
            OperationBinding {
                lane_id: LaneId::Judge,
                ..before.producer.operation.clone()
            },
            OperationBinding {
                binding_revision: before.producer.operation.binding_revision + 1,
                ..before.producer.operation.clone()
            },
        ] {
            assert!(
                store
                    .finish_model_attempt(&bad, &op, &facts, "model_result_captured")
                    .is_err()
            );
            assert!(
                store
                    .model_attempt(op.id)
                    .unwrap()
                    .unwrap()
                    .completion
                    .is_none()
            );
        }
        store
            .finish_model_attempt(
                &before.producer.operation,
                &op,
                &facts,
                "model_result_captured",
            )
            .unwrap();
        let events: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        let truth = store.model_attempt(op.id).unwrap().unwrap();
        store
            .finish_model_attempt(
                &before.producer.operation,
                &op,
                &facts,
                "model_result_captured",
            )
            .unwrap();
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            events
        );
        let mut conflicting = facts.clone();
        conflicting.reported.fallback_used.as_mut().unwrap().value = false;
        assert!(
            store
                .finish_model_attempt(
                    &before.producer.operation,
                    &op,
                    &conflicting,
                    "model_result_captured"
                )
                .is_err()
        );
        op.payload = Some(json!({"answer":"replacement"}));
        assert!(
            store
                .finish_model_attempt(
                    &before.producer.operation,
                    &op,
                    &facts,
                    "model_result_captured"
                )
                .is_err()
        );
        assert_eq!(store.model_attempt(op.id).unwrap().unwrap(), truth);
        assert_eq!(
            store.operation(op.id).unwrap().unwrap().payload,
            Some(json!({"answer":"captured"}))
        );
    }

    #[test]
    fn failed_operation_cas_rolls_back_completion_and_preserves_retryable_handle() {
        let (_dir, _config, mut store, mut op, before) = fixture(true);
        let facts = completion(NativeExecution::Completed, NativeOutcome::Invalid);
        op.state = "rejected".into();
        store
            .db
            .execute_batch(
                "CREATE TEMP TRIGGER reject_model_transition BEFORE UPDATE ON operations
             BEGIN SELECT RAISE(ABORT,'fixture operation transition failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .finish_model_attempt(
                    &before.producer.operation,
                    &op,
                    &facts,
                    "model_result_invalid"
                )
                .is_err()
        );
        assert_eq!(store.model_attempt(op.id).unwrap().unwrap(), before);
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "generating");
        assert_eq!(op.persisted_state.borrow().as_str(), "generating");
        store
            .db
            .execute_batch("DROP TRIGGER reject_model_transition")
            .unwrap();
        store
            .finish_model_attempt(
                &before.producer.operation,
                &op,
                &facts,
                "model_result_invalid",
            )
            .unwrap();
        assert_eq!(
            store.model_attempt(op.id).unwrap().unwrap().completion,
            Some(facts)
        );
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "rejected");
    }

    #[test]
    fn pending_budget_survives_fence_but_cannot_be_renewed_or_replace_completion() {
        let (_dir, _config, mut store, mut op, before) = fixture(false);
        store.set_paused_unbound(true).unwrap();
        let fixed_deadline = now() + 5;
        store
            .capture_model_pending(op.id, 5000, fixed_deadline)
            .unwrap();
        store
            .capture_model_pending(op.id, 4000, fixed_deadline)
            .unwrap();
        assert!(
            store
                .capture_model_pending(op.id, 6000, fixed_deadline + 1)
                .is_err()
        );
        assert!(
            store
                .capture_model_pending(op.id, 11_000, fixed_deadline)
                .is_err()
        );
        let (deadline, budget): (Option<i64>, u64) = store
            .db
            .query_row(
                "SELECT model_deadline,json_extract(evidence,'$.remaining_budget_millis')
             FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(deadline, None);
        assert_eq!(budget, 4000);
        assert_eq!(store.model_attempt(op.id).unwrap().unwrap(), before);
        let facts = completion(NativeExecution::NotStarted, NativeOutcome::NotStarted);
        op.state = "prelaunch_failed".into();
        store
            .finish_model_attempt(
                &before.producer.operation,
                &op,
                &facts,
                "native_process_failed",
            )
            .unwrap();
        let finalized = store.model_attempt(op.id).unwrap().unwrap();
        assert!(
            store
                .capture_model_pending(op.id, 5000, fixed_deadline)
                .is_err()
        );
        assert_eq!(store.model_attempt(op.id).unwrap().unwrap(), finalized);
    }

    #[test]
    fn model_launch_observation_expires_while_waiting_for_sqlite() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        thread_local! {
            static BUSY: std::cell::RefCell<Option<mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
        }
        fn busy(_: i32) -> bool {
            BUSY.with(|slot| {
                if let Some(sender) = slot.borrow_mut().take() {
                    sender.send(()).unwrap();
                }
            });
            std::thread::sleep(Duration::from_millis(1));
            true
        }
        let (_directory, mut config) = super::super::tests::bound_fixture();
        config.capabilities.answer.mode = Mode::Active;
        config.capabilities.answer.model.core_guidance = "Answer the supplied task.".into();
        let (_writer, mut store) = AccountLock::acquire(&config).unwrap();
        let account = AccountAdmissionGuard::try_acquire(&config).unwrap();
        store.set_paused(false, &account).unwrap();
        store.set_authority_epoch(1).unwrap();
        store.runtime_state(&config, false).unwrap();
        let gate = LaneAdmissionGuard::try_acquire(&config, LaneId::Answer).unwrap();
        let stamp = AdmissionStampSnapshot {
            account_generation: store.control().unwrap().generation,
            lane_control_revision: store.lane_control(LaneId::Answer).unwrap().control_revision,
            authority_epoch: 1,
            lane_config_revision: config.lane_revision(LaneId::Answer).unwrap(),
        };
        let model = config.model(LaneId::Answer).unwrap();
        let native = NativeRequest::Answer(
            AnswerTask::new(SolverRequest {
                id: "sqlite-contention".into(),
                kind: LaneId::Answer,
                epoch: 8,
                words: vec!["clock".into()],
                min_chars: 5,
                max_chars: 200,
                assignment: None,
                candidate: None,
                history: Vec::new(),
                guidance: model.guidance.to_string(),
                core_guidance: model.core_guidance.to_string(),
                candidate_author: None,
                author_history: None,
            })
            .unwrap(),
        );
        let draft = ModelProducerDraft {
            task_kind: "answer".into(),
            request_id: native.request().id.clone(),
            request_digest: native.digest().unwrap(),
            lane_config_revision: stamp.lane_config_revision.clone(),
            requested: ModelSelection::new(model).unwrap(),
            preflight_admission: stamp.clone(),
        };
        let (op, producer) = store.begin_model_attempt(
            &config, &account, &gate, &stamp, LaneId::Answer, "8:sqlite-contention",
            &json!({"solver":native.request()}), None,
            &json!({"lane_revision":stamp.lane_config_revision,"model_seconds":config.model_seconds(LaneId::Answer).unwrap()}),
            draft,
        ).unwrap().unwrap();
        let deadline = now() + 30;
        store.capture_model_pending(op.id, 1000, deadline).unwrap();
        // Latest diagnostics may change, but cannot replace pending deadline authority.
        store
            .record_evidence(op.id, &json!({"stage":"diagnostic"}))
            .unwrap();
        let (busy_tx, busy_rx) = mpsc::channel();
        let (locked_tx, locked_rx) = mpsc::channel();
        let (expiry_tx, expiry_rx) = mpsc::channel::<Instant>();
        let blocker_config = config.clone();
        let blocker = std::thread::spawn(move || {
            let mut other = Store::open(&blocker_config).unwrap();
            let tx = other
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            locked_tx.send(()).unwrap();
            busy_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let expires = expiry_rx.recv().unwrap();
            std::thread::sleep(
                expires.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
            );
            tx.commit().unwrap();
        });
        locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        BUSY.with(|slot| *slot.borrow_mut() = Some(busy_tx));
        store.db.busy_handler(Some(busy)).unwrap();
        let expires = Instant::now() + Duration::from_millis(100);
        expiry_tx.send(expires).unwrap();
        assert!(
            !store
                .admit_model_launch(
                    &config,
                    &account,
                    &gate,
                    &stamp,
                    &producer.operation,
                    deadline,
                    expires,
                )
                .unwrap()
        );
        blocker.join().unwrap();
        store.db.busy_timeout(Duration::from_secs(5)).unwrap();
        let retained = store.model_attempt(op.id).unwrap().unwrap();
        assert_eq!(retained.producer, producer);
        assert!(retained.launch.is_none());
        let committed: Option<i64> = store
            .db
            .query_row(
                "SELECT model_deadline FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(committed, None);
        assert!(
            store
                .admit_model_launch(
                    &config,
                    &account,
                    &gate,
                    &stamp,
                    &producer.operation,
                    deadline + 1,
                    Instant::now() + Duration::from_secs(5),
                )
                .is_err()
        );
        assert!(
            store
                .admit_model_launch(
                    &config,
                    &account,
                    &gate,
                    &stamp,
                    &producer.operation,
                    deadline,
                    Instant::now() + Duration::from_secs(5),
                )
                .unwrap()
        );
    }

    #[test]
    fn recovery_distinguishes_launch_admission_without_inventing_execution_or_legacy_facts() {
        for launched in [false, true] {
            let (_dir, _config, mut store, op, before) = fixture(launched);
            store.db.execute(
                "INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at)
                 SELECT kind,'legacy','generating',request,generation,revision,created_at,updated_at
                 FROM operations WHERE id=?1", [op.id],
            ).unwrap();
            let legacy_id = store.db.last_insert_rowid();
            store
                .db
                .execute(
                    "INSERT INTO operation_evidence(operation_id) VALUES(?1)",
                    [legacy_id],
                )
                .unwrap();
            assert!(Store::recover_interrupted_model(&store.db).is_err());
            {
                let tx = store
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                Store::recover_interrupted_model(&tx).unwrap();
                tx.execute(
                    "UPDATE operations SET state='model_unknown' WHERE state='generating'",
                    [],
                )
                .unwrap();
                tx.commit().unwrap();
            }
            let retained = store.model_attempt(op.id).unwrap().unwrap();
            assert_eq!(retained.producer, before.producer);
            assert_eq!(retained.launch, before.launch);
            let recovered = retained.completion.as_ref().unwrap();
            assert_eq!(recovered.phase, NativePhase::Recovery);
            assert_eq!(
                recovered.execution,
                if launched {
                    NativeExecution::Unknown
                } else {
                    NativeExecution::NotStarted
                }
            );
            assert_eq!(recovered.reported, NativeReportedEvidence::default());
            assert_eq!(recovered.inference_spawned_at, None);
            assert_eq!(recovered.preflight_started_at, None);
            assert_eq!(
                store.operation(op.id).unwrap().unwrap().state,
                "model_unknown"
            );
            assert_eq!(store.model_attempt(legacy_id).unwrap(), None);
            store.recover().unwrap();
            assert_eq!(store.model_attempt(op.id).unwrap().unwrap(), retained);
        }
    }
}
