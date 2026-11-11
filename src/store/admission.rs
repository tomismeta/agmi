use super::*;
use anyhow::ensure;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct OperationBinding {
    pub database_id: String,
    pub operation_id: i64,
    pub lane_id: LaneId,
    pub binding_revision: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct AdmissionStampSnapshot {
    pub account_generation: i64,
    pub lane_control_revision: i64,
    pub authority_epoch: u64,
    pub lane_config_revision: String,
}

pub(crate) struct EffectCandidate<'a> {
    pub operation: &'a Operation,
    pub stamp: &'a AdmissionStampSnapshot,
    pub observation_admit_before: Instant,
    pub observation_admit_before_unix: i64,
    pub due_at: i64,
    pub coordinator_exclusion: Option<&'static str>,
}

struct FairSelection {
    index: usize,
    reset_round: bool,
    eligible: [bool; LaneId::COUNT],
    served: [bool; LaneId::COUNT],
    exclusions: [Option<&'static str>; LaneId::COUNT],
}

impl Store {
    pub(crate) fn operation_binding(&self, op: &Operation) -> Result<OperationBinding> {
        let binding = OperationBinding {
            database_id: self.database_identity()?.0,
            operation_id: op.id,
            lane_id: op.kind,
            binding_revision: op.persisted_binding_revision.get(),
        };
        ensure!(
            Self::validate_operation_binding_in(&self.db, &binding)?,
            "operation binding changed"
        );
        Ok(binding)
    }

    pub(crate) fn operation_lane_revision(&self, binding: &OperationBinding) -> Result<String> {
        ensure!(
            Self::validate_operation_binding_in(&self.db, binding)?,
            "operation binding changed"
        );
        Ok(self.db.query_row(
            "SELECT revision FROM operations WHERE id=?1",
            [binding.operation_id],
            |r| r.get(0),
        )?)
    }

    pub(super) fn validate_operation_binding_in(
        db: &Connection,
        binding: &OperationBinding,
    ) -> Result<bool> {
        Ok(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations o,authority a WHERE a.singleton=1
            AND a.database_id=?1 AND o.id=?2 AND o.kind=?3 AND o.binding_revision=?4)",
            params![
                binding.database_id,
                binding.operation_id,
                binding.lane_id.as_str(),
                binding.binding_revision
            ],
            |r| r.get(0),
        )?)
    }

    pub(super) fn validate_admission_in(
        db: &Connection,
        config: &Config,
        account: &AccountAdmissionGuard,
        lane: &LaneAdmissionGuard,
        stamp: &AdmissionStampSnapshot,
        binding: Option<&OperationBinding>,
    ) -> Result<bool> {
        account.validate(config)?;
        lane.validate(db, config)?;
        let kind = lane.lane_id();
        let (paused, generation): (bool, i64) = db.query_row(
            "SELECT paused,generation FROM control WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let control = Self::lane_control_in(db, kind)?;
        let authority: Option<u64> = db
            .query_row(
                "SELECT authority_epoch FROM runtime_authority WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let blocked: bool = db.query_row(
            "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)
            OR EXISTS(SELECT 1 FROM hosted_identity_evidence WHERE rejection IS NOT NULL)",
            [],
            |r| r.get(0),
        )?;
        if paused
            || control.paused
            || blocked
            || config.mode(kind) != Mode::Active
            || generation != stamp.account_generation
            || control.control_revision != stamp.lane_control_revision
            || authority != Some(stamp.authority_epoch)
            || config.lane_revision(kind)? != stamp.lane_config_revision
        {
            return Ok(false);
        }
        if let Some(binding) = binding {
            if binding.lane_id != kind || !Self::validate_operation_binding_in(db, binding)? {
                return Ok(false);
            }
            let matching: bool = db.query_row(
                "SELECT generation=?2 AND revision=?3 FROM operations WHERE id=?1",
                params![
                    binding.operation_id,
                    stamp.account_generation,
                    stamp.lane_config_revision
                ],
                |r| r.get(0),
            )?;
            if !matching {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn begin_preparation(
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
    ) -> Result<Option<Operation>> {
        self.continuity()?;
        ensure!(
            lane == lane_guard.lane_id(),
            "preparation lane does not match its gate"
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
            ("prepared", request),
            Control {
                paused: false,
                generation: stamp.account_generation,
            },
            &stamp.lane_config_revision,
            retry,
        )?;
        tx.execute(
            "INSERT INTO operation_evidence(operation_id,policy) VALUES(?1,?2)",
            params![id, serde_json::to_string(policy)?],
        )?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        Ok(Some(
            self.operation(id)?
                .context("prepared operation disappeared")?,
        ))
    }

    fn select_ready_effect_in(
        db: &Connection,
        config: &Config,
        account: &AccountAdmissionGuard,
        gates: &[LaneAdmissionGuard],
        candidates: &[EffectCandidate<'_>],
    ) -> Result<Option<FairSelection>> {
        ensure!(
            candidates.len() <= LaneId::COUNT,
            "more than one candidate per registered lane"
        );
        account.validate(config)?;
        let mut eligible = [false; LaneId::COUNT];
        let mut served = [false; LaneId::COUNT];
        let mut exclusions = [None; LaneId::COUNT];
        let current = Instant::now();
        let cutoff = AdmissionCutoff::current();
        let mut any = false;
        let mut all_served = true;
        for (index, candidate) in candidates.iter().enumerate() {
            ensure!(
                !candidates[..index]
                    .iter()
                    .any(|other| other.operation.kind == candidate.operation.kind),
                "duplicate ready lane"
            );
            let op = candidate.operation;
            if let Some(reason) = candidate.coordinator_exclusion {
                exclusions[index] = Some(reason);
                continue;
            }
            let Some(gate) = gates.iter().find(|gate| gate.lane_id() == op.kind) else {
                exclusions[index] = Some("lane_gate_unavailable");
                continue;
            };
            if current >= candidate.observation_admit_before {
                exclusions[index] = Some("observation_expired");
                continue;
            }
            if !matches!(op.state.as_str(), "generated" | "prepared" | "retry")
                || *op.persisted_state.borrow() != op.state
                || op.payload.is_none()
            {
                exclusions[index] = Some("operation_not_ready");
                continue;
            }
            let id: String = db.query_row(
                "SELECT database_id FROM authority WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            let binding = OperationBinding {
                database_id: id,
                operation_id: op.id,
                lane_id: op.kind,
                binding_revision: op.persisted_binding_revision.get(),
            };
            if !Self::validate_admission_in(
                db,
                config,
                account,
                gate,
                candidate.stamp,
                Some(&binding),
            )? {
                exclusions[index] = Some("admission_stamp_changed");
                continue;
            }
            if Self::risk_decision_at(db, config, op, cutoff)?.is_none() {
                exclusions[index] = Some("account_policy_closed");
                continue;
            }
            let value: i64 = db.query_row(
                "SELECT served_in_round FROM schedule WHERE kind=?1",
                [op.kind.as_str()],
                |r| r.get(0),
            )?;
            ensure!(matches!(value, 0 | 1), LaneControlError::MissingState);
            eligible[index] = true;
            served[index] = value == 1;
            any = true;
            all_served &= served[index];
        }
        if !any {
            return Ok(None);
        }
        let index = candidates
            .iter()
            .enumerate()
            .filter(|(index, _)| eligible[*index] && (all_served || !served[*index]))
            .min_by_key(|(_, candidate)| {
                (
                    candidate.observation_admit_before,
                    candidate.due_at,
                    candidate.operation.kind.as_str(),
                    candidate.operation.id,
                )
            })
            .map(|(index, _)| index)
            .context("eligible fairness set unexpectedly empty")?;
        Ok(Some(FairSelection {
            index,
            reset_round: all_served,
            eligible,
            served,
            exclusions,
        }))
    }

    pub(crate) fn select_ready_effect(
        &self,
        config: &Config,
        account: &AccountAdmissionGuard,
        gates: &[LaneAdmissionGuard],
        candidates: &[EffectCandidate<'_>],
    ) -> Result<Option<usize>> {
        self.continuity()?;
        let tx = self.db.unchecked_transaction()?;
        let selection = Self::select_ready_effect_in(&tx, config, account, gates, candidates)?
            .map(|value| value.index);
        tx.commit()?;
        Ok(selection)
    }

    pub(crate) fn admit_effect(
        &mut self,
        config: &Config,
        account: &AccountAdmissionGuard,
        gates: &[LaneAdmissionGuard],
        candidates: &[EffectCandidate<'_>],
        selected: usize,
    ) -> Result<Option<i64>> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(selection) =
            Self::select_ready_effect_in(&tx, config, account, gates, candidates)?
        else {
            return Ok(None);
        };
        if selection.index != selected {
            return Ok(None);
        }
        let candidate = &candidates[selected];
        let op = candidate.operation;
        if selection.reset_round {
            for lane in LaneId::ALL {
                ensure!(
                    tx.execute(
                        "UPDATE schedule SET served_in_round=0 WHERE kind=?1",
                        [lane.as_str()]
                    )? == 1,
                    LaneControlError::MissingState
                );
            }
        }
        let binding =
            Self::save_transition_in(&tx, op, "dispatch_intent", "dispatching", Some(config))?;
        ensure!(
            tx.execute(
                "UPDATE schedule SET served_in_round=1 WHERE kind=?1",
                [op.kind.as_str()]
            )? == 1,
            LaneControlError::MissingState
        );
        let encoded: String = tx.query_row(
            "SELECT policy FROM operation_evidence WHERE operation_id=?1",
            [op.id],
            |r| r.get(0),
        )?;
        let mut policy: Value = serde_json::from_str(&encoded)?;
        policy["dispatch_admission"] = serde_json::to_value(candidate.stamp)?;
        let offered: Vec<Value> = candidates.iter().enumerate().map(|(index, candidate)| json!({
            "lane":candidate.operation.kind,"operation_id":candidate.operation.id,
            "eligible":selection.eligible[index],"exclusion":selection.exclusions[index],
            "served_in_round":selection.eligible[index].then_some(selection.served[index]),
            "local_observation_admit_before":candidate.observation_admit_before_unix,"due_at":candidate.due_at
        })).collect();
        policy["arbitration"] = json!({"policy":"unserved_round_local_freshness","round_reset":selection.reset_round,
            "local_observation_admit_before":candidate.observation_admit_before_unix,"due_at":candidate.due_at,
            "deadline_basis":"local_observation_freshness","remote_deadline_known":false,
            "eligibility_basis":"guarded_store_admission_with_coordinator_exclusions","offered":offered});
        tx.execute(
            "UPDATE operation_evidence SET policy=?1 WHERE operation_id=?2",
            params![serde_json::to_string(&policy)?, op.id],
        )?;
        let sequence: i64 = tx.query_row(
            "SELECT dispatch_sequence FROM authority WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        if Instant::now() >= candidate.observation_admit_before {
            return Ok(None);
        }
        tx.commit()?;
        Self::transition_committed(op, "dispatching", binding);
        // External witness publication precedes returning permission to poll HTTP.
        self.publish_dispatch_witness()?;
        Ok(Some(sequence))
    }

    fn finish_bound_transition(
        &mut self,
        binding: &OperationBinding,
        op: &Operation,
        event: &str,
        effect: bool,
    ) -> Result<()> {
        self.continuity()?;
        ensure!(
            binding.operation_id == op.id
                && binding.lane_id == op.kind
                && binding.binding_revision == op.persisted_binding_revision.get(),
            "operation result binding mismatch"
        );
        ensure!(
            op.state != "dispatching",
            "result transition cannot admit an effect"
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            Self::validate_operation_binding_in(&tx, binding)?,
            "operation binding changed"
        );
        let predecessor = op.persisted_state.borrow();
        let sent = matches!(
            predecessor.as_str(),
            "dispatching" | "queued" | "unknown" | "included_pending" | "confirmed"
        );
        ensure!(
            sent == effect,
            "operation result is outside its lifecycle owner"
        );
        drop(predecessor);
        if !effect {
            ensure!(
                matches!(
                    op.state.as_str(),
                    "generated"
                        | "prepared"
                        | "retry"
                        | "discarded"
                        | "stale"
                        | "abstained"
                        | "locally_rejected"
                ),
                "invalid unsent result transition"
            );
        } else {
            ensure!(
                matches!(
                    op.state.as_str(),
                    "queued"
                        | "unknown"
                        | "included_pending"
                        | "confirmed"
                        | "final"
                        | "completed"
                        | "retry"
                        | "rejected"
                        | "refused"
                        | "expired"
                        | "stale"
                ),
                "invalid sent-work result transition"
            );
        }
        let revision = Self::save_transition_in(&tx, op, event, &op.state, None)?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        Self::transition_committed(op, &op.state, revision);
        Ok(())
    }

    pub(crate) fn complete_preparation(
        &mut self,
        binding: &OperationBinding,
        op: &Operation,
        event: &str,
    ) -> Result<()> {
        self.finish_bound_transition(binding, op, event, false)
    }

    pub(crate) fn complete_effect(
        &mut self,
        account: &AccountAdmissionGuard,
        lane: &LaneAdmissionGuard,
        binding: &OperationBinding,
        op: &Operation,
        event: &str,
    ) -> Result<()> {
        lane.validate_bound(&self.db)?;
        ensure!(
            lane.lane_id() == binding.lane_id,
            "effect result lane mismatch"
        );
        // The account guard remains owned through this response bookkeeping.
        lane.validate_account(account)?;
        self.finish_bound_transition(binding, op, event, true)
    }

    pub(crate) fn complete_reconciliation(
        &mut self,
        binding: &OperationBinding,
        op: &Operation,
        event: &str,
    ) -> Result<()> {
        self.finish_bound_transition(binding, op, event, true)
    }

    pub(crate) fn retire_unsent(&mut self, binding: &OperationBinding, reason: &str) -> Result<()> {
        ensure!(
            Self::validate_operation_binding_in(&self.db, binding)?,
            "operation binding changed"
        );
        let mut op = self
            .operation(binding.operation_id)?
            .context("operation missing")?;
        ensure!(
            matches!(
                op.state.as_str(),
                "generating" | "generated" | "prepared" | "retry"
            ),
            "only reusable unsent work can retire"
        );
        if let Some(attempt) = self.model_attempt(op.id)? {
            ensure!(
                attempt.completion.is_some(),
                "finalize model execution evidence before retirement"
            );
        }
        op.state = "discarded".into();
        self.complete_preparation(binding, &op, reason)
    }

    #[cfg(test)]
    pub(crate) fn seed_operation_for_test(
        &mut self,
        kind: LaneId,
        key: &str,
        state: &str,
        request: &Value,
        control: Control,
        revision: &str,
    ) -> Result<Operation> {
        self.begin(kind, key, state, request, control, revision)
    }

    #[cfg(test)]
    pub(crate) fn seed_transition_for_test(&mut self, op: &Operation, event: &str) -> Result<()> {
        self.save(op, event)
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
