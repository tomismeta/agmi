use super::*;
use std::collections::BTreeMap;

// Narrow rows only: neither admission nor its read-local snapshot reconstructs
// request/result/payload JSON for unrelated unresolved operations.
#[derive(Clone, Copy)]
struct UncertainRow {
    id: i64,
    lane: LaneId,
    dispatching: bool,
    since: i64,
    witness: Option<i64>,
}

fn visit_uncertain(db: &Connection, mut visit: impl FnMut(UncertainRow)) -> Result<()> {
    let mut statement = db.prepare(&format!(
        "WITH historical AS ({HISTORICAL_ANSWERS})
         SELECT o.id,o.kind,o.state='dispatching',COALESCE(e.blocked_since,o.created_at),h.accepted_answer_id
         FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
         LEFT JOIN historical h ON h.operation_id=o.id
         WHERE o.state IN ('dispatching','queued','unknown','included_pending') ORDER BY o.id"
    ))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let lane = match row.get_ref(1)?.as_str()? {
            "answer" => LaneId::Answer,
            "judge" => LaneId::Judge,
            "mine" => LaneId::Mine,
            _ => bail!("invalid uncertainty lane"),
        };
        visit(UncertainRow {
            id: row.get(0)?,
            lane,
            dispatching: row.get(2)?,
            since: row.get(3)?,
            witness: row.get(4)?,
        });
    }
    Ok(())
}

fn accumulate(
    result: &mut UncertaintyAccounting,
    row: UncertainRow,
    config: &Config,
    lane: LaneId,
    capture_blockers: bool,
) {
    let policy = config.participation(lane);
    let answer = &config.capabilities.answer.participation;
    let own = row.lane == lane;
    result.total += 1;
    result.own_total += u64::from(own);
    result.eligible += u64::from(own && row.witness.is_some());
    let exempt = own
        && lane == LaneId::Answer
        && row.witness.is_some()
        && policy.mode == ParticipationMode::ParticipationFirst
        && (answer.historical_unknown_answer_capacity == HistoricalAnswerCapacity::AcceptedLinked
            || result.own_exempt < u64::from(answer.max_historical_unknown_answers));
    if exempt {
        result.exempt += 1;
        result.own_exempt += 1;
        if result.historical.len() < HISTORICAL_EXAMPLE_LIMIT {
            result.historical.push(HistoricalAnswer {
                operation_id: row.id,
                accepted_answer_id: row.witness.expect("exempt row has direct witness"),
            });
        }
    }
    if capture_blockers {
        if result.blockers.len() < HISTORICAL_EXAMPLE_LIMIT {
            result.blockers.push(row.id);
        }
        if own && !exempt && result.own_blockers.len() < HISTORICAL_EXAMPLE_LIMIT {
            result.own_blockers.push(row.id);
        }
    }
    result.writing |= row.dispatching;
    result.grace_until = result.grace_until.max(
        row.since
            .saturating_add(i64::try_from(policy.uncertainty_grace_seconds).unwrap_or(i64::MAX)),
    );
}

fn apply_floor(
    db: &Connection,
    config: &Config,
    lane: LaneId,
    result: &mut UncertaintyAccounting,
) -> Result<()> {
    let (floor, legacy, scope) =
        Store::request_floor_in(db, config, reads::effect_endpoint(lane), None)?;
    result.retry_not_before = floor;
    result.legacy_floor = legacy;
    result.restriction_scope = scope;
    Ok(())
}

fn origin_floor(db: &Connection, retry_of: Option<i64>) -> Result<i64> {
    Ok(db.query_row(
        "SELECT COALESCE((SELECT retry_not_before FROM operation_timing WHERE operation_id=?1),0)",
        [retry_of],
        |row| row.get(0),
    )?)
}

pub(super) fn uncertainty_accounting(
    db: &Connection,
    config: &Config,
    kind: LaneId,
    excluding: Option<i64>,
    retry_of: Option<i64>,
    capture_blockers: bool,
) -> Result<UncertaintyAccounting> {
    let mut result = UncertaintyAccounting::default();
    visit_uncertain(db, |row| {
        if Some(row.id) == excluding {
            return;
        }
        accumulate(&mut result, row, config, kind, capture_blockers);
        if Some(row.id) == retry_of {
            result.retry_grace_until = row.since.saturating_add(
                i64::try_from(
                    config
                        .capabilities
                        .answer
                        .participation
                        .uncertain_answer_retry_seconds,
                )
                .unwrap_or(i64::MAX),
            );
        }
    })?;
    apply_floor(db, config, kind, &mut result)?;
    if retry_of.is_some() {
        result.retry_origin_floor = origin_floor(db, retry_of)?;
    }
    Ok(result)
}

#[derive(Clone)]
pub(super) struct AdmissionProjection {
    pub(super) value: Value,
    pub(super) pre_intent_blocker: Option<(&'static str, Option<i64>)>,
}

/// Exists only inside the caller's SQLite read transaction. Ordinary projections
/// reuse lane totals; candidate exclusions never accidentally remove their retry
/// origin. Rare exclusions of unresolved rows are recalculated in canonical order
/// so capped historical exemptions promote the next eligible direct witness.
pub(super) struct AccountingReadSnapshot {
    rows: BTreeMap<i64, UncertainRow>,
    lanes: BTreeMap<LaneId, UncertaintyAccounting>,
    witness_ranks: BTreeMap<i64, u64>,
    pub(super) admissions: std::cell::RefCell<BTreeMap<(LaneId, Option<u64>), AdmissionProjection>>,
    pub(super) cutoff: AdmissionCutoff,
}

impl AccountingReadSnapshot {
    pub(super) fn load(db: &Connection, config: &Config) -> Result<Self> {
        let mut rows = BTreeMap::new();
        let mut lanes: BTreeMap<_, _> = LaneId::ALL
            .into_iter()
            .map(|lane| (lane, UncertaintyAccounting::default()))
            .collect();
        let mut witness_ranks = BTreeMap::new();
        visit_uncertain(db, |row| {
            if row.witness.is_some() {
                witness_ranks.insert(row.id, witness_ranks.len() as u64 + 1);
            }
            for (&lane, result) in &mut lanes {
                accumulate(result, row, config, lane, true);
            }
            rows.insert(row.id, row);
        })?;
        for (&lane, result) in &mut lanes {
            apply_floor(db, config, lane, result)?;
        }
        Ok(Self {
            rows,
            lanes,
            witness_ranks,
            admissions: Default::default(),
            cutoff: AdmissionCutoff::current(),
        })
    }

    pub(super) fn accounting(
        &self,
        db: &Connection,
        config: &Config,
        lane: LaneId,
        excluding: Option<i64>,
        retry_of: Option<i64>,
    ) -> Result<UncertaintyAccounting> {
        let base = &self.lanes[&lane];
        let mut result = if excluding.is_some_and(|id| self.rows.contains_key(&id)) {
            let mut result = UncertaintyAccounting::default();
            for row in self.rows.values() {
                if Some(row.id) != excluding {
                    accumulate(&mut result, *row, config, lane, true);
                }
            }
            result.retry_not_before = base.retry_not_before;
            result.legacy_floor = base.legacy_floor;
            result.restriction_scope = base.restriction_scope.clone();
            result
        } else {
            base.clone()
        };
        if let Some(id) = retry_of {
            if Some(id) != excluding
                && let Some(row) = self.rows.get(&id)
            {
                result.retry_grace_until = row.since.saturating_add(
                    i64::try_from(
                        config
                            .capabilities
                            .answer
                            .participation
                            .uncertain_answer_retry_seconds,
                    )
                    .unwrap_or(i64::MAX),
                );
            }
            result.retry_origin_floor = origin_floor(db, retry_of)?;
        }
        Ok(result)
    }

    pub(super) fn capacity_counted(&self, config: &Config, lane: LaneId, id: i64) -> bool {
        let Some(row) = self.rows.get(&id) else {
            return false;
        };
        let policy = &config.capabilities.answer.participation;
        if lane != LaneId::Answer
            || policy.mode != ParticipationMode::ParticipationFirst
            || row.witness.is_none()
        {
            return true;
        }
        if policy.historical_unknown_answer_capacity == HistoricalAnswerCapacity::AcceptedLinked {
            return false;
        }
        // The capped exemption list is ordered by original ID, not witness ID.
        self.witness_ranks[&id] > u64::from(policy.max_historical_unknown_answers)
    }
}

pub(super) fn risk_decision_at(
    db: &Connection,
    config: &Config,
    op: &Operation,
    cutoff: AdmissionCutoff,
) -> Result<Option<RiskDecision>> {
    risk_decision_with(db, config, op, cutoff, None)
}

pub(super) fn risk_decision_with(
    db: &Connection,
    config: &Config,
    op: &Operation,
    cutoff: AdmissionCutoff,
    snapshot: Option<&AccountingReadSnapshot>,
) -> Result<Option<RiskDecision>> {
    // Retrying this operation must honor its own server floor, not only
    // the floors of other uncertain operations in the accounting below.
    let retry_not_before: i64 = db.query_row(
        "SELECT COALESCE((SELECT retry_not_before FROM operation_timing WHERE operation_id=?1),0)",
        [op.id],
        |row| row.get(0),
    )?;
    if retry_not_before > cutoff.at || op.next_at > cutoff.at {
        return Ok(None);
    }
    let reload_blocked: bool = db.query_row(
        "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)
             OR EXISTS(SELECT 1 FROM hosted_identity_evidence WHERE rejection IS NOT NULL)",
        [],
        |r| r.get(0),
    )?;
    if reload_blocked {
        return Ok(None);
    }
    let policy = config.participation(op.kind);
    let answer = &config.capabilities.answer.participation;
    let epoch = op.request["solver"]["epoch"].as_u64();
    let retry_of: Option<i64> = db
        .query_row(
            "SELECT retry_of FROM operation_links WHERE operation_id=?1",
            [op.id],
            |r| r.get(0),
        )
        .optional()?;
    let accounting = match snapshot {
        Some(snapshot) => snapshot.accounting(db, config, op.kind, Some(op.id), retry_of)?,
        None => uncertainty_accounting(db, config, op.kind, Some(op.id), retry_of, true)?,
    };
    let grant: Option<i64> = if policy.mode == ParticipationMode::Manual {
        db.query_row(
            "SELECT g.id FROM manual_grants g JOIN lane_control l ON l.lane=g.kind
                 WHERE g.epoch=?1 AND g.kind=?2 AND g.generation=?3
                 AND g.lane_control_revision=l.control_revision
                 AND g.id<=?4 AND g.created_at<=?5 AND g.consumed_by IS NULL AND NOT EXISTS(
                   SELECT 1 FROM manual_grant_revocations WHERE grant_id=g.id)
                 ORDER BY g.id LIMIT 1",
            params![
                epoch,
                op.kind.as_str(),
                op.generation,
                cutoff.grant_id,
                cutoff.at
            ],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    if Store::account_blocker_at(policy, &accounting, grant.is_some(), cutoff).is_some() {
        return Ok(None);
    }
    if op.kind == LaneId::Answer {
        let Some(epoch) = epoch else { return Ok(None) };
        let pattern = format!("{epoch}:%");
        let (attempts, accepted, uncertain): (u32, bool, bool) = db.query_row(
                "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0),
                COALESCE(MAX(o.state IN ('dispatching','queued','unknown','included_pending')),0)
                FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
                WHERE o.kind='answer' AND o.work_key>=?1 AND o.work_key<?3 AND o.id!=?2
                AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
                params![format!("{epoch}:"),op.id,format!("{epoch};")], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            )?;
        if accepted
            || attempts >= answer.max_answer_attempts_per_epoch
            || (uncertain && retry_of.is_none())
        {
            return Ok(None);
        }
        if let Some(origin) = retry_of {
            let eligible: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 AND kind='answer'
                    AND work_key LIKE ?2 AND state IN ('queued','unknown') AND txid IS NULL AND payload IS NOT NULL)",
                    params![origin,pattern], |r| r.get(0),
                )?;
            if !eligible || !answer.retry_uncertain_answers {
                return Ok(None);
            }
        }
    }
    if op.kind == LaneId::Mine && config.capabilities.mine.schedule.each_epoch {
        let Some(epoch) = epoch else { return Ok(None) };
        if Store::mine_epoch_attempted_in(db, epoch, Some(op.id))? {
            return Ok(None);
        }
    }
    Ok(Some(RiskDecision {
        accounting,
        retry_of,
        grant,
    }))
}

impl Store {
    pub(crate) fn preparation_allowed(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
    ) -> Result<bool> {
        self.preparation_allowed_at(config, kind, epoch, AdmissionCutoff::current())
    }

    pub(crate) fn preparation_allowed_at(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
        cutoff: AdmissionCutoff,
    ) -> Result<bool> {
        let control = self.control()?;
        let blocked: bool = self.db.query_row(
            "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)
            OR EXISTS(SELECT 1 FROM hosted_identity_evidence WHERE rejection IS NOT NULL)",
            [],
            |r| r.get(0),
        )?;
        let lane_paused: bool = self.db.query_row(
            "SELECT paused FROM lane_control WHERE lane=?1",
            [kind.as_str()],
            |r| r.get(0),
        )?;
        if control.paused || lane_paused || blocked || config.mode(kind) != Mode::Active {
            return Ok(false);
        }
        if config
            .preparation(kind)
            .is_some_and(|policy| policy.while_blocked)
        {
            return Ok(true);
        }
        let accounting = Self::uncertainty_accounting(&self.db, config, kind, None, None, false)?;
        Ok(self
            .uncertainty_blocker_with_at(config, kind, epoch, &accounting, cutoff)?
            .is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Connection, Config) {
        let db = Connection::open_in_memory().unwrap();
        schema::initialize_schema(&db).unwrap();
        db.execute("INSERT INTO control(singleton,paused,generation,identity,version) VALUES(1,0,1,'{}',4)", []).unwrap();
        for lane in LaneId::ALL {
            db.execute("INSERT INTO lane_control(lane,paused,control_revision,gate_device,gate_inode) VALUES(?1,0,0,0,0)",
                [lane.as_str()]).unwrap();
        }
        let mut config = Config::default();
        config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .answer
            .participation
            .max_historical_unknown_answers = 1;
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = 100;
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 10;
        config
            .capabilities
            .answer
            .participation
            .uncertain_answer_retry_seconds = 20;
        (db, config)
    }

    fn operation(db: &Connection, id: i64, lane: LaneId, state: &str, epoch: u64) {
        db.execute("INSERT INTO operations(id,kind,work_key,state,request,generation,revision,created_at,updated_at)
            VALUES(?1,?2,?3,?4,?5,1,'revision',100,100)",
            params![id,lane.as_str(),format!("{epoch}:{id}"),state,json!({"solver":{"epoch":epoch}}).to_string()]).unwrap();
        db.execute("INSERT INTO operation_evidence(operation_id,dispatch_sequence,blocked_since) VALUES(?1,?1,100)",[id]).unwrap();
    }

    fn witness(db: &Connection, original: i64, accepted: i64) {
        operation(db, accepted, LaneId::Answer, "final", 7);
        db.execute(
            "UPDATE operations SET txid='accepted' WHERE id=?1",
            [accepted],
        )
        .unwrap();
        db.execute(
            "INSERT INTO operation_links VALUES(?1,?2,1)",
            params![accepted, original],
        )
        .unwrap();
    }

    fn view(a: &UncertaintyAccounting) -> Value {
        json!({"total":a.total,"own_total":a.own_total,"own_exempt":a.own_exempt,
            "own_blockers":a.own_blockers,"eligible":a.eligible,"exempt":a.exempt,
            "historical":a.historical,"blockers":a.blockers,"writing":a.writing,
            "retry_not_before":a.retry_not_before,"grace_until":a.grace_until,
            "retry_grace_until":a.retry_grace_until,"restriction_scope":a.restriction_scope,
            "retry_origin_floor":a.retry_origin_floor,"legacy_floor":a.legacy_floor})
    }

    #[test]
    fn snapshot_matches_streaming_for_exact_exclusions_and_retry_origins() {
        let (db, mut config) = fixture();
        for id in 1..=25 {
            operation(&db, id, LaneId::Answer, "unknown", 7);
        }
        operation(&db, 30, LaneId::Judge, "dispatching", 8);
        witness(&db, 1, 101);
        witness(&db, 2, 102);
        db.execute(
            "INSERT INTO operation_timing(operation_id,retry_not_before) VALUES(2,131)",
            [],
        )
        .unwrap();
        // Exercise capped and linked modes without using a sampled exemption as a count.
        for linked in [false, true] {
            if linked {
                config
                    .capabilities
                    .answer
                    .participation
                    .historical_unknown_answer_capacity = HistoricalAnswerCapacity::AcceptedLinked;
            }
            let snapshot = AccountingReadSnapshot::load(&db, &config).unwrap();
            for lane in LaneId::ALL {
                for excluded in [None, Some(1), Some(2), Some(30), Some(999)] {
                    for retry in [None, Some(2), Some(30)] {
                        let streamed =
                            uncertainty_accounting(&db, &config, lane, excluded, retry, true)
                                .unwrap();
                        let read = snapshot
                            .accounting(&db, &config, lane, excluded, retry)
                            .unwrap();
                        assert_eq!(view(&streamed), view(&read));
                    }
                }
            }
            let a = snapshot
                .accounting(&db, &config, LaneId::Answer, None, None)
                .unwrap();
            assert_eq!(a.total, 26);
            assert_eq!(a.blockers.len(), HISTORICAL_EXAMPLE_LIMIT);
            assert!(a.writing);
            let excluded = snapshot
                .accounting(&db, &config, LaneId::Answer, Some(1), None)
                .unwrap();
            assert_eq!(excluded.historical[0].operation_id, 2);
            assert!(!snapshot.capacity_counted(&config, LaneId::Answer, 1));
        }
    }

    #[test]
    fn linked_witness_is_revoked_and_never_inferred_from_epoch_or_age() {
        let (db, config) = fixture();
        operation(&db, 1, LaneId::Answer, "unknown", 7);
        witness(&db, 1, 101);
        witness(&db, 1, 102);
        let read =
            || uncertainty_accounting(&db, &config, LaneId::Answer, None, None, true).unwrap();
        assert_eq!(read().historical[0].accepted_answer_id, 101);
        db.execute(
            "UPDATE operations SET txid=NULL,state='unknown' WHERE id=101",
            [],
        )
        .unwrap();
        assert_eq!(read().historical[0].accepted_answer_id, 102);
        db.execute(
            "UPDATE operations SET request='{\"solver\":{\"epoch\":8}}' WHERE id=102",
            [],
        )
        .unwrap();
        assert_eq!(read().exempt, 0);
        db.execute(
            "UPDATE operations SET request='{\"solver\":{\"epoch\":7}}' WHERE id=102",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE operations SET job_id='still-pollable' WHERE id=1",
            [],
        )
        .unwrap();
        assert_eq!(read().exempt, 0);
        db.execute("UPDATE operations SET job_id=NULL WHERE id=1", [])
            .unwrap();
        db.execute(
            "UPDATE operation_evidence SET dispatch_sequence=NULL WHERE operation_id=1",
            [],
        )
        .unwrap();
        assert_eq!(read().exempt, 0);
    }

    #[test]
    fn retry_and_server_floors_remain_strict_at_cutoff_boundaries() {
        let (db, mut config) = fixture();
        operation(&db, 1, LaneId::Answer, "unknown", 7);
        db.execute(
            "INSERT INTO operation_timing(operation_id,retry_not_before) VALUES(1,121)",
            [],
        )
        .unwrap();
        let authority = format!("{}\n{}", config.network.chain, config.network.address);
        let origin = reqwest::Url::parse(&config.network.base_url)
            .unwrap()
            .origin()
            .ascii_serialization();
        db.execute("INSERT INTO request_restrictions(authority,origin,scope,target,basis,not_before,observed_at,request_id,source,read_class,effect_class)
            VALUES(?1,?2,'answer_judge_effects','','server',130,100,'r','server',0,1)",params![authority,origin]).unwrap();
        let a = uncertainty_accounting(&db, &config, LaneId::Answer, None, Some(1), false).unwrap();
        let policy = config.participation(LaneId::Answer);
        assert_eq!(
            Store::account_blocker_at(
                policy,
                &a,
                true,
                AdmissionCutoff {
                    at: 120,
                    grant_id: 0
                }
            )
            .unwrap()
            .0,
            "operation_retry_minimum"
        );
        assert_eq!(
            Store::account_blocker_at(
                policy,
                &a,
                true,
                AdmissionCutoff {
                    at: 129,
                    grant_id: 0
                }
            )
            .unwrap()
            .0,
            "shared_server_restriction"
        );
        assert!(
            Store::account_blocker_at(
                policy,
                &a,
                true,
                AdmissionCutoff {
                    at: 130,
                    grant_id: 0
                }
            )
            .is_none()
        );
        let mine = uncertainty_accounting(&db, &config, LaneId::Mine, None, None, false).unwrap();
        assert_eq!(mine.retry_not_before, 0);
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = u64::MAX;
        assert_eq!(
            uncertainty_accounting(&db, &config, LaneId::Answer, None, None, false)
                .unwrap()
                .grace_until,
            i64::MAX
        );
    }

    #[test]
    fn manual_grant_requires_current_lane_revision_and_no_revocation() {
        let (db, mut config) = fixture();
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 0;
        operation(&db, 1, LaneId::Judge, "unknown", 7);
        operation(&db, 2, LaneId::Answer, "prepared", 9);
        db.execute(
            "UPDATE operation_evidence SET dispatch_sequence=NULL WHERE operation_id=2",
            [],
        )
        .unwrap();
        let op = Operation {
            id: 2,
            kind: LaneId::Answer,
            key: "9:2".into(),
            state: "prepared".into(),
            request: json!({"solver":{"epoch":9}}),
            result: None,
            payload: None,
            job_id: None,
            txid: None,
            next_at: 0,
            binding_revision: 0,
            persisted_binding_revision: std::cell::Cell::new(0),
            persisted_state: std::cell::RefCell::new("prepared".into()),
            generation: 1,
        };
        db.execute("INSERT INTO manual_grants(id,epoch,kind,generation,created_at,lane_control_revision) VALUES(1,9,'answer',1,100,NULL)",[]).unwrap();
        let cutoff = AdmissionCutoff {
            at: 200,
            grant_id: 1,
        };
        assert!(
            risk_decision_at(&db, &config, &op, cutoff)
                .unwrap()
                .is_none()
        );
        db.execute(
            "UPDATE manual_grants SET lane_control_revision=0 WHERE id=1",
            [],
        )
        .unwrap();
        assert!(
            risk_decision_at(&db, &config, &op, cutoff)
                .unwrap()
                .is_some()
        );
        assert!(
            risk_decision_at(
                &db,
                &config,
                &op,
                AdmissionCutoff {
                    at: 200,
                    grant_id: 0
                }
            )
            .unwrap()
            .is_none()
        );
        assert!(
            risk_decision_at(
                &db,
                &config,
                &op,
                AdmissionCutoff {
                    at: 99,
                    grant_id: 1
                }
            )
            .unwrap()
            .is_none()
        );
        db.execute("UPDATE manual_grants SET consumed_by=2 WHERE id=1", [])
            .unwrap();
        assert!(
            risk_decision_at(&db, &config, &op, cutoff)
                .unwrap()
                .is_none()
        );
        db.execute("UPDATE manual_grants SET consumed_by=NULL WHERE id=1", [])
            .unwrap();
        db.execute(
            "UPDATE lane_control SET control_revision=1 WHERE lane='judge'",
            [],
        )
        .unwrap();
        assert!(
            risk_decision_at(&db, &config, &op, cutoff)
                .unwrap()
                .is_some()
        );
        db.execute(
            "UPDATE lane_control SET control_revision=1 WHERE lane='answer'",
            [],
        )
        .unwrap();
        assert!(
            risk_decision_at(&db, &config, &op, cutoff)
                .unwrap()
                .is_none()
        );
        db.execute(
            "UPDATE manual_grants SET lane_control_revision=1 WHERE id=1",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO manual_grant_revocations VALUES(1,150)", [])
            .unwrap();
        assert!(
            risk_decision_at(&db, &config, &op, cutoff)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn dispatch_residue_survives_recovery_and_confirmation_releases_capacity() {
        let (db, config) = fixture();
        operation(&db, 1, LaneId::Judge, "dispatching", 7);
        let initial =
            uncertainty_accounting(&db, &config, LaneId::Judge, None, None, false).unwrap();
        assert_eq!(initial.total, 1);
        assert!(initial.writing);
        db.execute("UPDATE operations SET state='unknown' WHERE id=1", [])
            .unwrap();
        let recovered =
            uncertainty_accounting(&db, &config, LaneId::Judge, None, None, false).unwrap();
        assert_eq!(recovered.total, 1);
        assert!(!recovered.writing);
        assert_eq!(initial.grace_until, recovered.grace_until);
        db.execute(
            "UPDATE operations SET state='included_pending',txid='tx' WHERE id=1",
            [],
        )
        .unwrap();
        assert_eq!(
            uncertainty_accounting(&db, &config, LaneId::Judge, None, None, false)
                .unwrap()
                .active(),
            1
        );
        db.execute("UPDATE operations SET state='confirmed' WHERE id=1", [])
            .unwrap();
        assert_eq!(
            uncertainty_accounting(&db, &config, LaneId::Judge, None, None, false)
                .unwrap()
                .total,
            0
        );
    }
}
