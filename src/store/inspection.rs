use super::projection::RemoteWorkContext;
use super::*;
use crate::endpoints::Endpoint;

/// Sanitized retained evidence, never an effect or replay authorization.
#[derive(serde::Serialize)]
pub(crate) struct OperationInspection {
    pub(crate) operation_id: i64,
    pub(crate) mining: Value,
    pub(crate) reconciliation: Value,
}

struct InspectionOperation {
    kind: LaneId,
    key: String,
    state: String,
    job_id: Option<String>,
    txid: Option<String>,
    next_at: i64,
    binding_revision: i64,
    epoch: Option<u64>,
    created_at: i64,
}

impl InspectionOperation {
    fn read_key(&self, operation_id: i64) -> Option<ReadKey> {
        Some(ReadKey::Operation {
            operation_id,
            binding_revision: self.binding_revision,
            phase: if self.txid.is_some() {
                reads::ReadPhase::Receipt
            } else if self.job_id.is_some() {
                reads::ReadPhase::Job
            } else {
                return None;
            },
        })
    }

    fn pollable(&self) -> bool {
        matches!(
            self.state.as_str(),
            "queued" | "unknown" | "included_pending" | "confirmed"
        )
    }
}

struct PollFloors {
    operation: i64,
    local: i64,
    server: i64,
    retained: i64,
    source: Option<i64>,
    service: Option<i64>,
    historical_missing: Option<i64>,
    kind: &'static str,
    gate: i64,
}

impl PollFloors {
    fn projection(&self) -> Value {
        let mut value = json!({"operation":self.operation,"local":self.local,"server":self.server,
            "retained":self.retained,"historical_missing":self.historical_missing});
        if let Some(source) = self.source {
            value["source"] = json!(source);
            value["service"] = json!(self.service);
        }
        value
    }
}

impl Store {
    pub(super) fn reconciliation_provenance(
        &self,
        id: i64,
        revision: i64,
    ) -> Result<Option<ReconciliationProvenance>> {
        let raw: Option<String> = self.db.query_row(
            "SELECT json_extract(policy,'$.reconciliation') FROM operation_evidence WHERE operation_id=?1",
            [id], |r| r.get(0)).optional()?.flatten();
        Ok(raw
            .and_then(|raw| serde_json::from_str::<ReconciliationProvenance>(&raw).ok())
            .filter(|p| p.binding_revision == revision && p.consecutive_404 <= 2))
    }

    pub(super) fn save_reconciliation_provenance(
        &self,
        id: i64,
        value: &ReconciliationProvenance,
    ) -> Result<()> {
        let object:bool=self.db.query_row(
            "SELECT policy IS NULL OR json_type(policy)='object' FROM operation_evidence WHERE operation_id=?1",
            [id],|r|r.get(0)).optional()?.unwrap_or(true);
        if !object {
            bail!("captured operation policy is not an object");
        }
        self.db.execute("INSERT INTO operation_evidence(operation_id,policy) VALUES (?1,json_object('reconciliation',json(?2)))
            ON CONFLICT(operation_id) DO UPDATE SET policy=json_set(COALESCE(operation_evidence.policy,'{}'),'$.reconciliation',json(?2))",
            params![id, serde_json::to_string(value)?])?;
        Ok(())
    }

    pub(super) fn binding_provenance_at(
        &self,
        id: i64,
        revision: i64,
        at: i64,
    ) -> Result<ReconciliationProvenance> {
        Ok(self
            .reconciliation_provenance(id, revision)?
            .filter(|p| {
                p.first_observed_at >= 0
                    && p.first_observed_at <= at
                    && p.bound_since
                        .is_none_or(|since| since >= 0 && since <= p.first_observed_at)
            })
            .unwrap_or(ReconciliationProvenance {
                binding_revision: revision,
                bound_since: None,
                first_observed_at: at,
                consecutive_404: 0,
                last_result_at: None,
                last_status: None,
                observer_authority_epoch: None,
                active_request_sequence: None,
            }))
    }

    pub(super) fn reconciliation_decay_at(
        &self,
        id: i64,
        context: &RemoteWorkContext,
        at: i64,
    ) -> Result<Option<(i64, i64)>> {
        if !self.reconciliation_decay_relevant(id, context)? {
            return Ok(None);
        }
        self.reconciliation_decay_binding_at(id, at)
    }

    pub(super) fn reconciliation_decay_relevant(
        &self,
        id: i64,
        context: &RemoteWorkContext,
    ) -> Result<bool> {
        if !context.has_decay_provenance() {
            return Ok(false);
        }
        let (state, epoch, key, job, tx): (String, Option<u64>, String, bool, bool) = self.db.query_row(
            "SELECT state,CASE WHEN json_type(request,'$.solver.epoch')='integer'
             AND json_extract(request,'$.solver.epoch')>=0 AND json_extract(request,'$.solver.kind')=kind
             THEN json_extract(request,'$.solver.epoch') END,work_key,job_id IS NOT NULL,txid IS NOT NULL FROM operations WHERE id=?1",
            [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        Ok(matches!(state.as_str(), "queued" | "unknown")
            && job
            && !tx
            && context.nonblocking(&state, epoch, &key) == Some(true)
            && context.historical(epoch, &key))
    }

    pub(super) fn reconciliation_decay_binding_at(
        &self,
        id: i64,
        at: i64,
    ) -> Result<Option<(i64, i64)>> {
        let revision: Option<i64> = self.db.query_row(
            "SELECT binding_revision FROM operations WHERE id=?1 AND state IN ('queued','unknown')
             AND job_id IS NOT NULL AND txid IS NULL", [id], |r|r.get(0)).optional()?;
        let Some(revision) = revision else {
            return Ok(None);
        };
        let Some(p) = self.reconciliation_provenance(id, revision)? else {
            return Ok(None);
        };
        let authority: Option<u64> = self
            .db
            .query_row(
                "SELECT authority_epoch FROM runtime_authority WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let since = p.bound_since.unwrap_or(p.first_observed_at);
        if since < 0
            || since > at
            || p.first_observed_at < since
            || p.first_observed_at > at
            || at.saturating_sub(since) < 86_400
            || p.consecutive_404 < 2
            || p.active_request_sequence.is_some()
            || p.last_result_at
                .is_none_or(|result| result < 0 || result > at)
            || authority.is_none()
            || p.observer_authority_epoch != authority
            || p.last_status != Some(404)
        {
            return Ok(None);
        }
        let read: Option<(Option<i64>, Option<u16>, bool)> = self.db.query_row(
            "SELECT started_at,status,in_flight FROM read_state WHERE operation_id=?1 AND binding_revision=?2 AND purpose='job' AND retired=0",
            params![id, revision], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((Some(started), Some(404), false)) = read else {
            return Ok(None);
        };
        if started < 0 || started > at {
            return Ok(None);
        }
        let cadence = if at.saturating_sub(since) >= 7 * 86_400 {
            86_400
        } else {
            21_600
        };
        let (uuid, _) = self.database_identity()?;
        let mut hash = Sha256::new();
        hash.update(uuid.as_bytes());
        hash.update(id.to_be_bytes());
        hash.update(revision.to_be_bytes());
        let hash = hash.finalize();
        let jitter = u64::from_be_bytes(hash[..8].try_into().expect("SHA256 prefix")) % 301;
        Ok(Some((
            started
                .saturating_add(cadence)
                .saturating_add(jitter as i64),
            cadence,
        )))
    }

    fn inspection_operation(&self, id: i64) -> Result<Option<InspectionOperation>> {
        Ok(self.db.query_row(
            "SELECT kind,work_key,state,job_id,txid,next_at,binding_revision,
             CASE WHEN json_type(request,'$.solver.epoch')='integer'
             AND json_extract(request,'$.solver.epoch')>=0 AND json_extract(request,'$.solver.kind')=kind
             THEN json_extract(request,'$.solver.epoch') END,created_at FROM operations WHERE id=?1",
            [id], |r| {
                let kind = r.get_ref(0)?.as_str()?;
                Ok(InspectionOperation {
                    kind: LaneId::ALL.into_iter().find(|lane| lane.as_str() == kind)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    key:r.get(1)?,state:r.get(2)?,job_id:r.get(3)?,txid:r.get(4)?,next_at:r.get(5)?,
                    binding_revision:r.get(6)?,epoch:r.get(7)?,created_at:r.get(8)?,
                })
            },
        ).optional()?)
    }

    fn exact_poll_read(&self, key: &ReadKey) -> Result<Value> {
        let ReadKey::Operation {
            operation_id,
            binding_revision,
            ..
        } = key
        else {
            unreachable!("poll inspection requires an operation binding");
        };
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        let row = self.db.query_row(
            "SELECT started_at,finished_at,status,last_success_at,in_flight,local_next_at,server_not_before,retained_conservative_floor,failures
             FROM read_state WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0
             AND operation_id=?4 AND binding_revision=?5",
            params![owner, purpose, resource, operation_id, binding_revision],
            |r| Ok(json!({"started_at":r.get::<_,Option<i64>>(0)?,"checked_at":r.get::<_,Option<i64>>(1)?,
                "status":r.get::<_,Option<u16>>(2)?,"usable_at":r.get::<_,Option<i64>>(3)?,
                "in_flight":r.get::<_,bool>(4)?,"local":r.get::<_,i64>(5)?,"server":r.get::<_,i64>(6)?,
                "retained":r.get::<_,i64>(7)?,"failures":r.get::<_,u32>(8)?})),
        ).optional()?;
        Ok(row.unwrap_or(Value::Null))
    }

    /// Read-only mirror of the persisted reconciliation claim gates. Page
    /// traversal, live slot availability and successful settlement are not forecast.
    fn poll_floors(
        &self,
        config: &Config,
        op: &InspectionOperation,
        read: &Value,
        decay: Option<(i64, i64)>,
    ) -> Result<PollFloors> {
        let schedule = (
            self.reconciliation_schedule(&format!("reconciliation:{}", op.kind.as_str()))?
                .0,
            self.reconciliation_schedule(&format!("reconciliation:fair:{}", op.kind.as_str()))?
                .0,
            self.reconciliation_schedule(&format!("reconciliation:missing:{}", op.kind.as_str()))?
                .0,
        );
        self.poll_floors_with_schedule(config, op, read, decay, schedule)
    }

    fn poll_floors_with_schedule(
        &self,
        config: &Config,
        op: &InspectionOperation,
        read: &Value,
        decay: Option<(i64, i64)>,
        (recent, fair, missing_schedule): (i64, i64, i64),
    ) -> Result<PollFloors> {
        let local = read["local"].as_i64().unwrap_or(0);
        let server = read["server"].as_i64().unwrap_or(0);
        let retained = read["retained"].as_i64().unwrap_or(0);
        let (source, service, basis) =
            if let Some(remote) = op.txid.as_deref().or(op.job_id.as_deref()) {
                let endpoint = if op.txid.is_some() {
                    Endpoint::Receipt
                } else {
                    Endpoint::Job
                };
                let (source, basis, _) =
                    Self::request_floor_in(&self.db, config, endpoint, Some(remote))?;
                let missing = op.txid.is_none()
                    && read["status"] == 404
                    && read["failures"].as_u64().is_some_and(|count| count >= 2);
                let service = if missing {
                    fair.max(missing_schedule)
                } else {
                    recent.min(fair)
                };
                (Some(source), Some(service), basis)
            } else {
                (None, None, None)
            };
        let source_kind = match basis {
            Some("server_retry_after") => "server_restriction",
            Some("local_unscoped_429_cooldown") => "local_backoff",
            Some("retained_legacy_floor") => "retained_floor",
            _ => "shared_restriction",
        };
        let (kind, time) = [
            ("operation_poll", op.next_at),
            ("local_backoff", local),
            ("retained_floor", retained),
            ("reconciliation_service", service.unwrap_or(0)),
            (
                "historical_missing_binding",
                decay.map_or(0, |(next, _)| next),
            ),
            ("server_restriction", server),
            (source_kind, source.unwrap_or(0)),
        ]
        .into_iter()
        .max_by_key(|(_, time)| *time)
        .expect("poll floors");
        Ok(PollFloors {
            operation: op.next_at,
            local,
            server,
            retained,
            source,
            service,
            historical_missing: decay.map(|(next, _)| next),
            kind,
            gate: time,
        })
    }

    pub(super) fn bound_next_observation(
        &self,
        config: &Config,
        id: i64,
        context: &RemoteWorkContext,
        at: i64,
    ) -> Result<Value> {
        let Some(op) = self.inspection_operation(id)? else {
            return Ok(Value::Null);
        };
        let Some(key) = op.read_key(id) else {
            return Ok(Value::Null);
        };
        if !op.pollable() {
            return Ok(Value::Null);
        }
        let read = self.exact_poll_read(&key)?;
        let decay = self.reconciliation_decay_at(id, context, at)?;
        let floors = self.poll_floors(config, &op, &read, decay)?;
        let in_flight = read["in_flight"] == true;
        let not_before = (!in_flight && floors.gate > at).then_some(floors.gate);
        let mut observation = json!({
            "owner":op.kind, "purpose":if op.txid.is_some() {"receipt"} else {"job"},
            "operation_id":id, "binding_revision":op.binding_revision,
            "not_before":not_before, "floor_kind":not_before.map(|_| floors.kind),
            "status":if in_flight {"in_flight"} else if not_before.is_some() {"waiting"} else {"eligible"},
        });
        if read["status"] == 404 {
            let provenance = self
                .reconciliation_provenance(id, op.binding_revision)?
                .filter(|p| {
                    p.first_observed_at >= 0
                        && p.first_observed_at <= at
                        && p.bound_since
                            .is_none_or(|since| since >= 0 && since <= p.first_observed_at)
                });
            observation["http_status"] = json!(404);
            observation["scope"] = json!(match context.nonblocking(&op.state, op.epoch, &op.key) {
                Some(false) => "current",
                Some(true) => "background",
                None => "unassessed",
            });
            observation["historical_cadence_qualified"] = json!(decay.is_some());
            observation["cadence_seconds"] = json!(decay.map(|(_, cadence)| cadence));
            observation["binding_age_seconds"] = json!(
                provenance
                    .as_ref()
                    .map(|p| at.saturating_sub(p.bound_since.unwrap_or(p.first_observed_at)))
            );
            observation["consecutive_404"] = json!(provenance.map(|p| p.consecutive_404));
        }
        Ok(observation)
    }

    /// One caller-selected page; stable caller order, no raw remote/work identifiers.
    pub(crate) fn operation_inspection(
        &self,
        config: &Config,
        ids: &[i64],
        at: i64,
    ) -> Result<Vec<OperationInspection>> {
        validate_page(None, ids.len().max(1))?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let policy = self.diagnostic_runtime_policy()?;
        let applied = if let Some(policy) = policy.as_ref() {
            let (_, stored) = self.diagnostic_journal_identity()?;
            Self::diagnostic_applied_config(config, &stored, Some(policy))?
        } else {
            None
        };
        let lane_revisions = policy
            .as_ref()
            .filter(|_| applied.is_some())
            .map(|p| &p["lane_revisions"]);
        let config = applied.as_ref().unwrap_or(config);
        let mut finite_totals: Option<[UncertaintyAccounting; LaneId::COUNT]> = None;
        let mut contexts: [Option<RemoteWorkContext>; LaneId::COUNT] =
            std::array::from_fn(|_| None);
        // Preload lane schedules, operations/evidence, and live poll reads for the whole page.
        let mut schedules = [(0_i64, 0_i64, 0_i64); LaneId::COUNT];
        for (index, lane) in LaneId::ALL.into_iter().enumerate() {
            schedules[index] = (
                self.reconciliation_schedule(&format!("reconciliation:{}", lane.as_str()))?
                    .0,
                self.reconciliation_schedule(&format!("reconciliation:fair:{}", lane.as_str()))?
                    .0,
                self.reconciliation_schedule(&format!("reconciliation:missing:{}", lane.as_str()))?
                    .0,
            );
        }
        let ids_json = serde_json::to_string(ids)?;
        let mut ops_by_id: std::collections::HashMap<
            i64,
            (InspectionOperation, Option<String>, Option<String>),
        > = std::collections::HashMap::with_capacity(ids.len());
        {
            let mut stmt = self.db.prepare(
                "SELECT o.id,o.kind,o.work_key,o.state,o.job_id,o.txid,o.next_at,o.binding_revision,
                 CASE WHEN json_type(o.request,'$.solver.epoch')='integer'
                  AND json_extract(o.request,'$.solver.epoch')>=0
                  AND json_extract(o.request,'$.solver.kind')=o.kind
                  THEN json_extract(o.request,'$.solver.epoch') END,
                 o.created_at,
                 json_extract(e.policy,'$.reconciliation'),
                 e.evidence
                 FROM json_each(?1) j
                 JOIN operations o ON o.id=j.value
                 LEFT JOIN operation_evidence e ON e.operation_id=o.id",
            )?;
            let mut rows = stmt.query([&ids_json])?;
            while let Some(r) = rows.next()? {
                let id: i64 = r.get(0)?;
                let kind = r.get_ref(1)?.as_str()?;
                let kind = LaneId::ALL
                    .into_iter()
                    .find(|lane| lane.as_str() == kind)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let op = InspectionOperation {
                    kind,
                    key: r.get(2)?,
                    state: r.get(3)?,
                    job_id: r.get(4)?,
                    txid: r.get(5)?,
                    next_at: r.get(6)?,
                    binding_revision: r.get(7)?,
                    epoch: r.get(8)?,
                    created_at: r.get(9)?,
                };
                ops_by_id.insert(id, (op, r.get(10)?, r.get(11)?));
            }
        }
        let mut reads_by_key: std::collections::HashMap<(i64, i64, String), Value> =
            std::collections::HashMap::new();
        {
            let mut stmt = self.db.prepare(
                "SELECT r.operation_id,r.binding_revision,r.purpose,
                 r.started_at,r.finished_at,r.status,r.last_success_at,r.in_flight,
                 r.local_next_at,r.server_not_before,r.retained_conservative_floor,r.failures
                 FROM json_each(?1) j
                 JOIN read_state r ON r.operation_id=j.value AND r.retired=0
                 WHERE r.purpose IN ('job','receipt')",
            )?;
            let mut rows = stmt.query([&ids_json])?;
            while let Some(r) = rows.next()? {
                let op_id: i64 = r.get(0)?;
                let rev: i64 = r.get(1)?;
                let purpose: String = r.get(2)?;
                reads_by_key.insert(
                    (op_id, rev, purpose),
                    json!({
                        "started_at":r.get::<_,Option<i64>>(3)?,
                        "checked_at":r.get::<_,Option<i64>>(4)?,
                        "status":r.get::<_,Option<u16>>(5)?,
                        "usable_at":r.get::<_,Option<i64>>(6)?,
                        "in_flight":r.get::<_,bool>(7)?,
                        "local":r.get::<_,i64>(8)?,
                        "server":r.get::<_,i64>(9)?,
                        "retained":r.get::<_,i64>(10)?,
                        "failures":r.get::<_,u32>(11)?,
                    }),
                );
            }
        }
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let Some((op, raw_provenance, diagnostic)) = ops_by_id.get(id) else {
                continue;
            };
            let index = LaneId::ALL
                .iter()
                .position(|lane| *lane == op.kind)
                .expect("known lane");
            if contexts[index].is_none()
                && let Some(lane_revisions) = lane_revisions
            {
                let mut context = self.remote_observation_context_with_revision(
                    config,
                    op.kind,
                    at,
                    true,
                    lane_revisions[op.kind.as_str()].as_str(),
                )?;
                let policy = config.participation(op.kind);
                let mut totals = if policy.mode == ParticipationMode::ParticipationFirst
                    && policy.max_unresolved_operations == CountLimit::Unbounded
                {
                    Self::uncertainty_accounting(&self.db, config, op.kind, None, None, false)?
                } else {
                    if finite_totals.is_none() {
                        finite_totals = Some(accounting::reconciliation_totals(&self.db, config)?);
                    }
                    finite_totals.as_ref().expect("initialized totals")[index].clone()
                };
                let open = self.fresh_lane_admission_open(
                    config,
                    op.kind,
                    context.epoch(),
                    at,
                    &mut totals,
                )?;
                context.set_admission_open(open);
                contexts[index] = Some(context);
            }
            let context = contexts[index].as_ref();
            let epoch = op.epoch;
            let historical = context.is_some_and(|context| context.historical(epoch, &op.key));
            let scope = if historical {
                "historical"
            } else if context
                .and_then(|context| context.nonblocking(&op.state, epoch, &op.key))
                .is_some()
            {
                "current"
            } else {
                "not_assessed"
            };
            let provenance = raw_provenance
                .as_deref()
                .and_then(|raw| serde_json::from_str::<ReconciliationProvenance>(raw).ok())
                .filter(|p| {
                    p.binding_revision == op.binding_revision
                        && p.consecutive_404 <= 2
                        && p.first_observed_at >= 0
                        && p.first_observed_at <= at
                        && p.bound_since
                            .is_none_or(|since| since >= 0 && since <= p.first_observed_at)
                });
            let since = provenance
                .as_ref()
                .map(|p| p.bound_since.unwrap_or(p.first_observed_at))
                .filter(|since| *since >= 0 && *since <= at);
            let age_source = if since.is_none() {
                "unknown"
            } else if provenance.as_ref().is_some_and(|p| p.bound_since.is_some()) {
                "committed_binding"
            } else {
                "first_observed_binding"
            };
            let created = op.created_at;
            let key = op.read_key(*id);
            let read = match &key {
                Some(ReadKey::Operation {
                    operation_id,
                    binding_revision,
                    phase,
                }) => {
                    let purpose = if *phase == reads::ReadPhase::Receipt {
                        "receipt"
                    } else {
                        "job"
                    };
                    reads_by_key
                        .get(&(*operation_id, *binding_revision, purpose.to_owned()))
                        .cloned()
                        .unwrap_or(Value::Null)
                }
                _ => Value::Null,
            };
            let decay = if matches!(op.state.as_str(), "queued" | "unknown")
                && op.job_id.is_some()
                && op.txid.is_none()
            {
                context
                    .map(|context| self.reconciliation_decay_at(*id, context, at))
                    .transpose()?
                    .flatten()
            } else {
                None
            };
            let poll =
                self.poll_floors_with_schedule(config, op, &read, decay, schedules[index])?;
            let floors = poll.projection();
            let next = (key.is_some() && op.pollable()).then_some(poll.gate);
            let reason = if matches!(
                op.state.as_str(),
                "completed"
                    | "final"
                    | "rejected"
                    | "refused"
                    | "expired"
                    | "stale"
                    | "discarded"
                    | "abstained"
                    | "locally_rejected"
                    | "prelaunch_failed"
                    | "abandoned_model"
                    | "superseded_model_unknown"
            ) {
                "terminal_evidence"
            } else if op.state == "model_unknown" {
                "model_uncertain"
            } else if key.is_none() {
                "no_safe_binding"
            } else if op.txid.is_some() {
                "receipt_pending"
            } else if read["status"] == 404 {
                "job_missing"
            } else if read["status"] == 202 {
                "job_pending"
            } else {
                "not_assessed"
            };
            let mining = diagnostic
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .and_then(|d| {
                    (op.kind == LaneId::Mine
                        && matches!(d["stage"].as_str(), Some("submit" | "bound_job"))
                        && d["route"] == "mine"
                        && d["status"] == 200
                        && d["reason"] == "completed"
                        && d["mining"]["ok"] == true)
                        .then(|| d["mining"]["attested"].as_u64())
                        .flatten()
                })
                .map_or_else(
                    || json!({"status":"not_recorded"}),
                    |count| json!({"status":"recorded","ok":true,"attested":count}),
                );
            let last_actual_check_at = provenance
                .as_ref()
                .and_then(|p| p.last_result_at)
                .map_or_else(|| read["checked_at"].clone(), Value::from);
            let last_status = provenance
                .as_ref()
                .filter(|p| p.last_result_at.is_some())
                .map_or_else(|| read["status"].clone(), |p| json!(p.last_status));
            let last_check_source = if last_actual_check_at.is_null() || last_status.is_null() {
                "not_recorded"
            } else {
                match &key {
                    Some(ReadKey::Operation {
                        phase: reads::ReadPhase::Job,
                        ..
                    }) => "bound_job",
                    Some(ReadKey::Operation {
                        phase: reads::ReadPhase::Receipt,
                        ..
                    }) => "bound_receipt",
                    _ => "not_recorded",
                }
            };
            result.push(OperationInspection { operation_id:*id, mining, reconciliation: json!({
                "scope":scope,"operation_age_seconds":(created >= 0 && created <= at).then(||at.saturating_sub(created)),
                "job_bound":op.job_id.is_some(),"transaction_bound":op.txid.is_some(),"binding_age_source":age_source,
                "binding_age_seconds":since.map(|since|at.saturating_sub(since)),
                "last_actual_check_at":last_actual_check_at,"last_status":last_status,
                "last_check_source":last_check_source,
                "last_usable_evidence_at":read["usable_at"],"missing_streak":provenance.as_ref().map(|p|p.consecutive_404),
                "in_flight":read["in_flight"].as_bool().unwrap_or(false),"next_eligible_at":next,"floors":floors,
                "cadence_reason":if decay.is_some(){"historical_missing_binding"}else{"ordinary_reconciliation"},
                "cadence_seconds":decay.map(|(_,cadence)|cadence),"service_time":"not_promised_bounded_page",
                "reason":reason,"evidence_missing":read["usable_at"].is_null(),
                "safe_next_action":if reason=="terminal_evidence"{"none"}else if reason=="model_uncertain"{"recover_model"}else if key.is_some(){"await_authoritative_read"}else{"inspect_authoritative_recovery"},
                "replay_authorized":false
            }) });
        }
        Ok(result)
    }
}
