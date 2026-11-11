use super::*;

pub(in crate::runtime) struct IdentityRead {
    pub(in crate::runtime) flight: ReadFlight,
}
pub(in crate::runtime) struct IdentityPermit {
    authority_epoch: u64,
    control: Control,
    completed_at: Instant,
    pub(super) observed_at: i64,
}
pub(in crate::runtime) struct ReadyEffect {
    pub(super) op: Operation,
    pub(super) binding: OperationBinding,
    pub(super) observation: Observation,
    pub(super) due_at: i64,
    pub(super) intent: crate::protocol::EffectIntent,
}
pub(in crate::runtime) struct EffectInFlight {
    op: Operation,
    dispatch_sequence: i64,
    pub(in crate::runtime) task: tokio::task::JoinHandle<()>,
    completion: oneshot::Receiver<Result<HostedResponse>>,
    // Effect-long: only dropped after assembled response/unknown bookkeeping.
    account_gate: AccountAdmissionGuard,
    lane_gate: crate::store::LaneAdmissionGuard,
}
impl Drop for EffectInFlight {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl HostAccess {
    pub(in crate::runtime) fn refresh_idle_identity(&mut self) -> Result<()> {
        if !self.identity_nonblocking || !self.store.identity_refresh_needed()? {
            return Ok(());
        }
        for kind in LaneId::ALL {
            if self.active(kind)? {
                self.start_identity(kind)?;
                break;
            }
        }
        Ok(())
    }

    pub(in crate::runtime) fn permit_current(&self) -> Result<bool> {
        Ok(self.permit.as_ref().is_some_and(|permit| {
            permit.authority_epoch == self.authority_epoch
                && permit.completed_at.elapsed()
                    <= Duration::from_secs(self.config.identity.read_http_seconds)
                && self
                    .store
                    .control()
                    .is_ok_and(|control| control == permit.control)
        }) && !self.reload_blocked)
    }

    pub(in crate::runtime) fn start_identity(&mut self, kind: LaneId) -> Result<()> {
        if !self.permit_current()? {
            self.permit = None;
        }
        if self.identity.is_none()
            && self.permit.is_none()
            && !self.stopping()
            && !self.reload_blocked
        {
            self.identity = self
                .launch_read(kind, ReadKey::Identity, Endpoint::Identity, None, None)?
                .map(|flight| IdentityRead { flight });
        }
        Ok(())
    }

    pub(in crate::runtime) fn collect_identity(&mut self) -> Result<()> {
        if !self.permit_current()? {
            self.permit = None;
        }
        let Some(read) = self.identity.as_mut() else {
            return Ok(());
        };
        let Some(result) = read.flight.take() else {
            return Ok(());
        };
        let read = self.identity.take().expect("ready identity handle");
        let response = self.finish_read(&read.flight, result)?;
        if !self.observation_current(&read.flight)? || self.reload_blocked {
            return Ok(());
        }
        if let Some(response) = response {
            let outcome = classify_hosted_identity(&self.config, &response);
            self.store.complete_identity_read(
                Some(response.status),
                crate::protocol::failure_category(&response),
                outcome,
                self.identity_policy(),
                None,
            )?;
            let completed_at = read.flight.completed()?;
            if outcome == HostedIdentityOutcome::Verified
                && completed_at.elapsed()
                    <= Duration::from_secs(self.config.identity.read_http_seconds)
            {
                self.permit = Some(IdentityPermit {
                    authority_epoch: self.authority_epoch,
                    control: read.flight.control,
                    completed_at,
                    observed_at: read.flight.completed_at,
                });
            }
        }
        Ok(())
    }

    pub(in crate::runtime) fn arbitrate(&mut self) -> Result<()> {
        if self.effect.is_some() {
            return Ok(());
        }
        if !self.permit_current()? {
            if let Some(kind) = self
                .lanes
                .iter()
                .filter_map(|lane| lane.ready().map(|ready| ready.op.kind))
                .next()
            {
                self.start_identity(kind)?;
            }
            return Ok(());
        }
        let Some(account_gate) = self.gate()? else {
            return Ok(());
        };
        self.reload()?;
        if !self.permit_current()? {
            return Ok(());
        }
        // Move the collection without reallocating, so host bookkeeping cannot alias a controller.
        let mut lanes = std::mem::take(&mut self.lanes);
        let result = self.arbitrate_lanes(&mut lanes, account_gate);
        self.lanes = lanes;
        result
    }
    fn arbitrate_lanes(
        &mut self,
        lanes: &mut [NativeLane],
        account_gate: AccountAdmissionGuard,
    ) -> Result<()> {
        let mut gates = Vec::with_capacity(LaneId::COUNT);
        let mut candidates = Vec::with_capacity(LaneId::COUNT);
        for id in LaneId::ALL {
            let lane = &lanes[crate::runtime::registry::lane_index(id)];
            let Some(ready) = lane.ready() else { continue };
            let mut coordinator_exclusion = if !self.ready_current(ready)? {
                Some("ready_not_current")
            } else if !self.admission_allowed(&ready.op)? {
                Some("coordinator_admission_closed")
            } else if self
                .store
                .request_not_before(&self.config, ready.intent.endpoint(), None)?
                > now()
            {
                Some("request_restricted")
            } else {
                None
            };
            if coordinator_exclusion.is_none() {
                match crate::store::LaneAdmissionGuard::try_acquire(&self.config, id) {
                    Ok(gate) => gates.push(gate),
                    Err(error) if super::ports::gate_busy(&error) => {
                        coordinator_exclusion = Some("lane_gate_busy")
                    }
                    Err(error) => return Err(error),
                }
            }
            candidates.push(crate::store::EffectCandidate {
                coordinator_exclusion,
                operation: &ready.op,
                stamp: &ready.observation.stamp,
                observation_admit_before: ready.observation.admit_before,
                observation_admit_before_unix: ready.observation.admit_before_unix,
                due_at: ready.due_at,
            });
        }
        let Some(selected) =
            self.store
                .select_ready_effect(&self.config, &account_gate, &gates, &candidates)?
        else {
            return Ok(());
        };
        let selected_lane = candidates[selected].operation.kind;
        let index = crate::runtime::registry::lane_index(selected_lane);
        let ready = lanes[index]
            .ready()
            .context("selected ready operation missing")?;
        let (_, prior_sequence) = self.store.database_identity()?;
        let next_sequence = prior_sequence
            .checked_add(1)
            .context("dispatch sequence exhausted")?;
        let meta = self.meta(
            Some(selected_lane),
            None,
            Some(&ready.op),
            Some(next_sequence as u64),
        )?;
        let deadline = EffectDeadline::seconds(self.config.timeouts(selected_lane).http_seconds)?;
        let prepared = match ready.intent.prepare(
            &self.protocol,
            ready
                .op
                .payload
                .as_ref()
                .context("prepared payload missing")?,
            deadline,
            meta,
        ) {
            Ok(prepared) => prepared,
            Err(_) => {
                self.store
                    .retire_unsent(&ready.binding, "submission_preflight_rejected")?;
                if let Some(plan) = self.once.as_mut() {
                    plan.lane_mut(selected_lane).effect = false;
                }
                return Ok(());
            }
        };
        if !self.permit_current()? {
            return Ok(());
        }
        let Some(dispatch_sequence) =
            self.store
                .admit_effect(&self.config, &account_gate, &gates, &candidates, selected)?
        else {
            return Ok(());
        };
        anyhow::ensure!(
            dispatch_sequence == next_sequence,
            "dispatch sequence changed during guarded handoff"
        );
        drop(candidates);
        let mut ready = lanes[index].take_ready().expect("admitted ready operation");
        ready.op.state = "dispatching".into();
        let gate_index = gates
            .iter()
            .position(|gate| gate.lane_id() == selected_lane)
            .context("selected lane gate missing")?;
        let lane_gate = gates.remove(gate_index);
        // Unselected gates never survive into an HTTP wait or even its first poll.
        drop(gates);
        self.permit = None;
        if let Some(plan) = self.once.as_mut() {
            plan.lane_mut(selected_lane).effect = false;
        }
        self.store.continuity()?;
        let (sender, completion) = oneshot::channel();
        let wake = Arc::clone(&self.wake);
        let task = tokio::spawn(async move {
            let result = prepared.await;
            let _ = sender.send(result);
            wake.notify_one();
        });
        self.effect = Some(EffectInFlight {
            op: ready.op,
            dispatch_sequence,
            task,
            completion,
            account_gate,
            lane_gate,
        });
        Ok(())
    }

    pub(in crate::runtime) fn collect_effect(&mut self) -> Result<()> {
        let Some(effect) = self.effect.as_mut() else {
            return Ok(());
        };
        let result = match effect.completion.try_recv() {
            Ok(result) => result,
            Err(oneshot::error::TryRecvError::Empty) => return Ok(()),
            Err(oneshot::error::TryRecvError::Closed) => Err(anyhow::anyhow!("effect task ended")),
        };
        let effect = self.effect.take().expect("ready effect handle");
        self.finish_effect(effect, result)
    }

    pub(in crate::runtime) fn finish_effect(
        &mut self,
        effect: EffectInFlight,
        result: Result<HostedResponse>,
    ) -> Result<()> {
        let response = match result {
            Ok(hosted) => {
                self.store.ingest_restrictions(&hosted.restrictions())?;
                if hosted.context.meta.dispatch_sequence != Some(effect.dispatch_sequence as u64) {
                    bail!("effect response dispatch identity mismatch");
                }
                Some(hosted.response)
            }
            Err(_) => None,
        };
        self.store.record_submission_evidence(
            effect.op.id,
            &serde_json::to_value(response_evidence(
                effect.op.kind,
                ResponseSource::Submit,
                response.as_ref(),
            ))?,
            &response
                .as_ref()
                .map(crate::protocol::response_candidates)
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(Value::Null),
        )?;
        // Sent intent is not an unsent draft: pause/mode/config generations do not suppress bookkeeping.
        if let Some(mut current) = self.store.operation(effect.op.id)?
            && current.state == "dispatching"
            && current.binding_revision == effect.op.binding_revision
        {
            if let Some(response) = response {
                let outcome = classify_source(current.kind, &response, ResponseSource::Submit);
                self.outcome(
                    &mut current,
                    outcome,
                    true,
                    response.retry_after_seconds,
                    Some((&effect.account_gate, &effect.lane_gate)),
                )?;
            } else {
                current.state = "unknown".into();
                current.next_at = not_before(self.retry_delay(current.kind, None));
                let binding = self.store.operation_binding(&current)?;
                self.store.complete_effect(
                    &effect.account_gate,
                    &effect.lane_gate,
                    &binding,
                    &current,
                    "dispatch_outcome_unknown",
                )?;
            }
        }
        drop(effect);
        Ok(())
    }

    pub(in crate::runtime) fn outcome(
        &mut self,
        op: &mut Operation,
        outcome: Outcome,
        submitted: bool,
        retry_after: Option<u64>,
        gates: Option<(&AccountAdmissionGuard, &crate::store::LaneAdmissionGuard)>,
    ) -> Result<()> {
        let event = match outcome {
            Outcome::Queued { job_id } => {
                if !submitted && op.job_id.as_ref().is_some_and(|known| known != &job_id) {
                    op.next_at = not_before(self.retry_delay(op.kind, None));
                    op.state = "unknown".into();
                    "job_binding_mismatch"
                } else {
                    op.next_at = self.queued_job_next_at(op, submitted)?;
                    op.job_id = Some(job_id);
                    op.state = "queued".into();
                    "submission_queued"
                }
            }
            Outcome::Included { txid } => {
                op.txid = Some(txid);
                op.state = "included_pending".into();
                op.next_at = 0;
                "transaction_included_unconfirmed"
            }
            Outcome::Rejected { code } => {
                op.state = if matches!(
                    code.as_str(),
                    "stale_challenge" | "epoch_mismatch" | "wrong_epoch" | "words_mismatch"
                ) {
                    "stale"
                } else {
                    "rejected"
                }
                .into();
                "submission_rejected"
            }
            Outcome::ProcessedRejected { code, next_nonce } => {
                op.state = if !submitted && op.job_id.is_some() && next_nonce.is_some() {
                    if code == "stale_seed" {
                        "stale"
                    } else {
                        "rejected"
                    }
                } else {
                    "unknown"
                }
                .into();
                "processed_submission_rejected"
            }
            Outcome::Retry { after_seconds } => {
                if submitted {
                    op.state = "retry".into();
                }
                // Actual server minima were already ingested with their original observation time.
                // Only the classifier's no-minimum fallback is a new local retry delay.
                let fallback = retry_after.is_none().then_some(after_seconds);
                op.next_at = not_before(self.retry_delay(op.kind, fallback))
                    .max(self.store.operation_poll_timing(op.id)?.1);
                "submission_backoff"
            }
            Outcome::Expired => {
                if !submitted && op.job_id.is_some() && op.txid.is_none() {
                    op.job_id = None;
                    op.state = "retry".into();
                    op.next_at = not_before(self.retry_delay(op.kind, None));
                    "queued_job_expired"
                } else {
                    op.state = "unknown".into();
                    op.next_at = not_before(self.retry_delay(op.kind, None));
                    "unbound_job_expiry"
                }
            }
            Outcome::Unknown { .. } => {
                op.state = "unknown".into();
                op.next_at = not_before(self.retry_delay(op.kind, None));
                "dispatch_outcome_unknown"
            }
            Outcome::Completed => {
                op.state = "completed".into();
                "mine_completed"
            }
        };
        let binding = self.store.operation_binding(op)?;
        match gates {
            Some((account, lane)) => self
                .store
                .complete_effect(account, lane, &binding, op, event),
            None => self.store.complete_reconciliation(&binding, op, event),
        }
    }
}
