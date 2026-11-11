use super::*;
use crate::store::{LaneObservation, LaneObservationStamp};

pub(in crate::runtime) struct ReadFlight {
    pub(in crate::runtime) key: ReadKey,
    pub(in crate::runtime) control: Control,
    pub(in crate::runtime) authority_epoch: u64,
    pub(in crate::runtime) lane_stamp: Option<AdmissionStampSnapshot>,
    pub(in crate::runtime) sequence: u64,
    pub(in crate::runtime) started_at: i64,
    pub(in crate::runtime) completed_at: i64,
    finished: Option<Instant>,
    cancelled: bool,
    pub(in crate::runtime) task: tokio::task::JoinHandle<()>,
    pub(in crate::runtime) completion: oneshot::Receiver<(Instant, Result<HostedResponse>)>,
}
impl Drop for ReadFlight {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ReadFlight {
    pub(in crate::runtime) fn take(&mut self) -> Option<Result<HostedResponse>> {
        match self.completion.try_recv() {
            Ok((finished, result)) => {
                self.finished = Some(finished);
                if let Ok(hosted) = &result {
                    self.started_at = hosted.context.started_at;
                    self.completed_at = hosted.completed_at;
                }
                Some(result)
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) if self.cancelled => None,
            Err(oneshot::error::TryRecvError::Closed) => {
                Some(Err(anyhow::anyhow!("read task ended")))
            }
        }
    }
    pub(in crate::runtime) fn completed(&self) -> Result<Instant> {
        self.finished.context("read completion timestamp missing")
    }
    pub(in crate::runtime) async fn abort(&mut self, deadline: tokio::time::Instant) {
        self.cancelled = true;
        self.task.abort();
        let _ = tokio::time::timeout_at(deadline, &mut self.task).await;
    }
}

pub(in crate::runtime) struct RecoveryRead {
    op: Operation,
    flight: ReadFlight,
}
#[derive(Default)]
pub(in crate::runtime) struct Recovery {
    pub(in crate::runtime) reads: Vec<RecoveryRead>,
}
impl Recovery {
    pub(in crate::runtime) fn collect(&mut self, runtime: &mut HostAccess) -> Result<()> {
        let mut index = 0;
        while index < self.reads.len() {
            let Some(result) = self.reads[index].flight.take() else {
                index += 1;
                continue;
            };
            let mut read = self.reads.swap_remove(index);
            let response = runtime.finish_read(&read.flight, result)?;
            // Safety ingestion above is unconditional; local state is binding-key fenced.
            if !runtime.store.read_current(&read.flight.key)? {
                continue;
            }
            if let Some(response) = response {
                runtime.recovery_response(&mut read.op, &read.flight.key, &response)?;
            }
        }
        Ok(())
    }

    pub(in crate::runtime) fn plan(
        &mut self,
        runtime: &mut HostAccess,
        kind: LaneId,
    ) -> Result<()> {
        if runtime.stopping() {
            return Ok(());
        }
        for op in runtime.store.reconciliation_batch(kind)? {
            if self.reads.len() >= 2 {
                break;
            }
            let Some(key) = Store::operation_read_key(&op) else {
                continue;
            };
            if let Some(plan) = runtime.once.as_ref() {
                let lane = plan.lane(kind);
                if lane.reads.len() >= 2
                    || !lane.recovery.contains(&op.id)
                    || lane.reads.contains(&key)
                {
                    continue;
                }
            }
            let (endpoint, resource) = if let Some(txid) = op.txid.as_deref() {
                (Endpoint::Receipt, txid)
            } else if let Some(job) = op.job_id.as_deref() {
                (Endpoint::Job, job)
            } else {
                continue;
            };
            if let Some(flight) =
                runtime.launch_read(kind, key.clone(), endpoint, Some(resource), None)?
            {
                runtime.store.reconciliation_attempted(kind, op.id)?;
                if let Some(plan) = runtime.once.as_mut() {
                    plan.lane_mut(kind).reads.push(key);
                }
                self.reads.push(RecoveryRead { op, flight });
            }
        }
        Ok(())
    }

    pub(in crate::runtime) async fn cancel(
        &mut self,
        runtime: &mut HostAccess,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        for read in &mut self.reads {
            read.flight.abort(deadline).await;
        }
        self.collect(runtime)?;
        for read in self.reads.drain(..) {
            runtime.store.cancel_read(&read.flight.key)?;
        }
        Ok(())
    }
}

impl HostAccess {
    pub(in crate::runtime) fn meta(
        &mut self,
        kind: Option<LaneId>,
        key: Option<&ReadKey>,
        operation: Option<&Operation>,
        dispatch: Option<u64>,
    ) -> Result<RequestMeta> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("request sequence exhausted")?;
        let (database_id, _) = self.store.database_identity()?;
        let (operation_id, binding_revision) = match key {
            Some(ReadKey::Operation {
                operation_id,
                binding_revision,
                ..
            }) => (
                Some(operation_id.to_string()),
                Some(*binding_revision as u64),
            ),
            _ => (
                operation.map(|op| op.id.to_string()),
                operation.map(|op| op.binding_revision as u64),
            ),
        };
        let read_key = key
            .map(|key| self.store.read_key_projection(key))
            .transpose()?
            .map(|value| serde_json::to_string(&value))
            .transpose()?;
        Ok(RequestMeta {
            request_id: format!(
                "{}:{}:{}",
                self.authority_instance, self.authority_epoch, self.sequence
            ),
            database_id,
            authority_epoch: self.authority_epoch,
            owner: kind,
            operation_id,
            binding_revision,
            dispatch_sequence: dispatch,
            read_key,
        })
    }

    pub(in crate::runtime) fn launch_read(
        &mut self,
        kind: LaneId,
        key: ReadKey,
        endpoint: Endpoint,
        resource: Option<&str>,
        offset: Option<u64>,
    ) -> Result<Option<ReadFlight>> {
        let cutoff = self.deadline_now();
        if self.stopping()
            || self
                .store
                .request_not_before(&self.config, endpoint, resource)?
                > cutoff
            || self.store.read_backoff(&key)?.next_at > cutoff
            || !self.store.read_started(&key)?
        {
            return Ok(None);
        }
        let meta = self.meta(Some(kind), Some(&key), None, None)?;
        let sequence = self.sequence;
        let deadline = ReadDeadline::seconds(if key == ReadKey::Identity {
            self.config.identity.read_http_seconds
        } else {
            self.config.timeouts(kind).read_http_seconds
        })?;
        let protocol = Arc::clone(&self.protocol);
        let resource = resource.map(str::to_owned);
        let wake = Arc::clone(&self.wake);
        let (sender, completion) = oneshot::channel();
        let control = self.store.control()?;
        let lane_stamp = if key == ReadKey::Identity || matches!(key, ReadKey::Operation { .. }) {
            None
        } else {
            Some(self.admission_stamp(kind)?)
        };
        self.heartbeat()?;
        let task = tokio::spawn(async move {
            let result = if let Some(offset) = offset {
                protocol.assignment_page(offset, 100, deadline, meta).await
            } else {
                protocol
                    .get(endpoint, resource.as_deref(), deadline, meta)
                    .await
            };
            let _ = sender.send((Instant::now(), result));
            wake.notify_one();
        });
        Ok(Some(ReadFlight {
            key,
            control,
            authority_epoch: self.authority_epoch,
            lane_stamp,
            sequence,
            started_at: now(),
            completed_at: 0,
            finished: None,
            cancelled: false,
            task,
            completion,
        }))
    }

    pub(in crate::runtime) fn finish_read(
        &mut self,
        flight: &ReadFlight,
        result: Result<HostedResponse>,
    ) -> Result<Option<Response>> {
        match result {
            Ok(hosted) => {
                self.store.ingest_restrictions(&hosted.restrictions())?;
                if !matches!(flight.key, ReadKey::Operation { .. })
                    && !self.observation_current(flight)?
                {
                    self.store.cancel_read(&flight.key)?;
                    return Ok(None);
                }
                self.store.read_finished(
                    &flight.key,
                    Some(hosted.response.status),
                    crate::protocol::failure_category(&hosted.response),
                )?;
                Ok(Some(hosted.response))
            }
            Err(error) => {
                if !matches!(flight.key, ReadKey::Operation { .. })
                    && !self.observation_current(flight)?
                {
                    self.store.cancel_read(&flight.key)?;
                    return Ok(None);
                }
                let category = transport_failure(&error);
                if flight.key == ReadKey::Identity {
                    self.store.complete_identity_read(
                        None,
                        Some(category.as_str()),
                        identity_read_failure(category),
                        self.identity_policy(),
                        None,
                    )?;
                } else {
                    self.store
                        .read_finished(&flight.key, None, Some(category.as_str()))?;
                    self.evaluate_read(&flight.key, false)?;
                }
                Ok(None)
            }
        }
    }

    pub(in crate::runtime) fn identity_policy(&self) -> (u64, u64, u64) {
        let policy = &self.config.identity;
        (
            policy.retry_seconds,
            policy.backoff_max_seconds,
            stagger(&self.config, policy.jitter_seconds, "identity:retry"),
        )
    }

    pub(in crate::runtime) fn evaluate_read(&self, key: &ReadKey, usable: bool) -> Result<()> {
        if usable {
            return self.store.reset_read(key);
        }
        let (base, cap, jitter) = match key {
            ReadKey::Identity => self.identity_policy(),
            _ => {
                let kind = match key {
                    ReadKey::Discovery { lane, .. } => *lane,
                    ReadKey::Assignment { .. } => LaneId::Judge,
                    ReadKey::Operation { operation_id, .. } => {
                        let Some(op) = self.store.operation(*operation_id)? else {
                            return Ok(());
                        };
                        op.kind
                    }
                    ReadKey::Identity => unreachable!(),
                };
                let schedule = self.config.schedule(kind);
                let discovery = matches!(key, ReadKey::Discovery { .. });
                (
                    if discovery {
                        schedule
                            .discovery_retry_seconds
                            .unwrap_or(schedule.retry_seconds)
                    } else {
                        schedule.retry_seconds
                    },
                    if discovery {
                        schedule
                            .discovery_backoff_max_seconds
                            .unwrap_or(schedule.backoff_max_seconds)
                    } else {
                        schedule.backoff_max_seconds
                    },
                    self.jitter(kind, "retry"),
                )
            }
        };
        self.store.fail_read(key, base, cap, jitter, None)?;
        Ok(())
    }

    pub(in crate::runtime) fn observation_current(&self, flight: &ReadFlight) -> Result<bool> {
        Ok(flight.authority_epoch == self.authority_epoch
            && flight.control == self.store.control()?
            && match &flight.lane_stamp {
                Some(stamp) => {
                    let kind = match &flight.key {
                        ReadKey::Discovery { lane, .. } => *lane,
                        ReadKey::Assignment { .. } => LaneId::Judge,
                        _ => return Ok(false),
                    };
                    *stamp == self.admission_stamp(kind)?
                }
                None => true,
            })
    }

    pub(in crate::runtime) fn observe_challenge(
        &self,
        kind: LaneId,
        flight: &ReadFlight,
        response: &Response,
    ) -> Result<Option<Challenge>> {
        let parsed = parse_challenge(response).ok();
        if !self.observation_current(flight)? {
            return Ok(None);
        }
        self.evaluate_read(&flight.key, parsed.is_some())?;
        let Some(challenge) = parsed else {
            return Ok(None);
        };
        if !self.store.observe_lane(
            kind,
            LaneObservationStamp {
                authority_epoch: flight.authority_epoch,
                generation: flight.control.generation,
                request_sequence: flight.sequence,
                started_at: flight.started_at,
                completed_at: flight.completed_at,
            },
            LaneObservation {
                epoch: challenge.epoch,
                answered: challenge.answered,
                fingerprint: &challenge.fingerprint,
                challenge: &response.body,
            },
            flight
                .lane_stamp
                .as_ref()
                .context("lane observation admission stamp missing")?,
        )? {
            return Ok(None);
        }
        Ok(Some(challenge))
    }

    pub(in crate::runtime) fn queued_job_next_at(
        &self,
        op: &Operation,
        submitted: bool,
    ) -> Result<i64> {
        let (since, retained) = self.store.operation_poll_timing(op.id)?;
        let delay = if let Some(policy) = self.config.schedule(op.kind).queued_job_polling {
            let interval = if submitted || op.state != "queued" {
                policy.initial_seconds
            } else if let Some(since) = since {
                queued_poll_interval(
                    policy.initial_seconds,
                    policy.max_seconds,
                    now().saturating_sub(since).max(0) as u64,
                )
            } else {
                policy.max_seconds
            };
            interval
                .saturating_add(self.jitter(op.kind, "queued-job"))
                .min(policy.max_seconds)
        } else {
            self.retry_delay(op.kind, None)
        };
        Ok(not_before(delay).max(retained))
    }

    pub(in crate::runtime) fn recovery_response(
        &mut self,
        op: &mut Operation,
        key: &ReadKey,
        response: &Response,
    ) -> Result<()> {
        if !self.store.read_current(key)? {
            return Ok(());
        }
        if let Some(txid) = op.txid.as_deref() {
            let evidence = receipt(response, txid, &self.config.network.address);
            self.evaluate_read(key, evidence != Receipt::Unresolved)?;
            op.next_at = not_before(self.retry_delay(op.kind, None));
            self.store.record_evidence(op.id, &json!({"stage":"receipt","route":op.kind,
                "status":response.status,"reason":match evidence { Receipt::Final=>"checkpoint_reported",
                Receipt::Included=>"included",Receipt::Rejected=>"rejected",Receipt::Unresolved=>"unresolved" }}))?;
            if evidence != Receipt::Unresolved {
                self.store.safety_observed(op.id)?;
            }
            let event = match evidence {
                Receipt::Final => {
                    op.state = "final".into();
                    "checkpoint_coverage_reported"
                }
                Receipt::Included => {
                    op.state = "confirmed".into();
                    "receipt_included"
                }
                Receipt::Rejected => {
                    op.state = "rejected".into();
                    "receipt_rejected"
                }
                Receipt::Unresolved => "receipt_unresolved",
            };
            let binding = self.store.operation_binding(op)?;
            self.store.complete_reconciliation(&binding, op, event)?;
        } else if op.job_id.is_some() {
            self.store.record_candidates(
                op.id,
                &serde_json::to_value(crate::protocol::response_candidates(response))?,
            )?;
            let outcome = classify_source(op.kind, response, ResponseSource::BoundJob);
            // Only the known 202 pending shape may omit its already-bound job ID.
            // A malformed identifier or contradictory evidence is not a pending poll.
            let pending = response.status == 202
                && matches!(&outcome, Outcome::Unknown { reason } if reason == "bound_job_pending")
                && matches!(
                    response.body.get("state").and_then(Value::as_str),
                    Some("queued" | "running" | "processing")
                )
                && ["job_id", "code", "error"]
                    .iter()
                    .all(|field| response.body.get(field).is_none());
            self.evaluate_read(key, pending || !matches!(outcome, Outcome::Unknown { .. }))?;
            if pending {
                self.store.safety_observed(op.id)?;
                op.next_at = self.queued_job_next_at(op, false)?;
                op.state = "queued".into();
                let binding = self.store.operation_binding(op)?;
                self.store
                    .complete_reconciliation(&binding, op, "job_pending")?;
            } else {
                self.store.record_evidence(
                    op.id,
                    &serde_json::to_value(response_evidence(
                        op.kind,
                        ResponseSource::BoundJob,
                        Some(response),
                    ))?,
                )?;
                if !matches!(outcome, Outcome::Unknown { .. }) {
                    self.store.safety_observed(op.id)?;
                }
                self.outcome(op, outcome, false, response.retry_after_seconds, None)?;
            }
        }
        Ok(())
    }
}
