use super::*;
use crate::endpoints::Endpoint;

fn fixture() -> (tempfile::TempDir, Config, Store) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        state_dir: dir.path().join("state"),
        ..Config::default()
    };
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.mine.mode = Mode::Active;
    config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 0;
    config.capabilities.judge.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .judge
        .participation
        .uncertainty_grace_seconds = 0;
    config.capabilities.mine.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .mine
        .participation
        .uncertainty_grace_seconds = 0;
    let mut store = Store::open(&config).unwrap();
    store.set_paused_unbound(false).unwrap();
    store.set_authority_epoch(1).unwrap();
    (dir, config, store)
}
fn prepared(store: &mut Store, kind: LaneId, epoch: u64) -> Operation {
    let mut op = store
        .begin(
            kind,
            &format!("{epoch}:test"),
            "prepared",
            &json!({"solver":{"epoch":epoch}}),
            store.control().unwrap(),
            "test",
        )
        .unwrap();
    op.payload = Some(json!({"answer":"captured"}));
    store.save(&op, "prepared").unwrap();
    op
}
fn unknown(
    store: &mut Store,
    config: &Config,
    kind: LaneId,
    epoch: u64,
    job: Option<&str>,
) -> Operation {
    let mut op = prepared(store, kind, epoch);
    assert!(store.dispatch_intent(&mut op, config).unwrap());
    op.state = "unknown".into();
    op.job_id = job.map(str::to_owned);
    store.save(&op, "dispatch_outcome_unknown").unwrap();
    store.operation(op.id).unwrap().unwrap()
}
struct RestrictionFixture<'a> {
    scope: &'a str,
    target: &'a str,
    basis: &'a str,
    deadline: i64,
    reads: bool,
    effects: bool,
}

fn restriction(store: &Store, config: &Config, evidence: RestrictionFixture<'_>) {
    let RestrictionFixture {
        scope,
        target,
        basis,
        deadline,
        reads,
        effects,
    } = evidence;
    store.db.execute("INSERT INTO request_restrictions VALUES(?1,?2,?3,?4,?5,?6,?7,'fixture','job',?8,?9,NULL,NULL)",
        params![format!("{}\n{}",config.network.chain,config.network.address),
            reqwest::Url::parse(&config.network.base_url).unwrap().origin().ascii_serialization(),scope,target,basis,deadline,now(),reads,effects]).unwrap();
}

#[test]
fn lane_capacity_and_account_risk_are_independent_decisions() {
    let (_dir, mut config, mut store) = fixture();
    config
        .capabilities
        .judge
        .participation
        .max_unresolved_operations = 1;
    let judge = unknown(&mut store, &config, LaneId::Judge, 1, Some("a"));
    config.capabilities.answer.participation.mode = ParticipationMode::Strict;
    let answer = prepared(&mut store, LaneId::Answer, 2);
    let view = store
        .admission_projection(&config, LaneId::Answer, Some(2), Some(&answer))
        .unwrap();
    assert_eq!(view["own_count"], 0);
    assert_eq!(view["own_remaining"], 4);
    assert_eq!(view["reason"], "account_uncertainty");
    assert_eq!(view["blocker_ids"], json!([judge.id]));
    let judge_view = store
        .admission_projection(&config, LaneId::Judge, Some(2), None)
        .unwrap();
    assert_eq!(judge_view["reason"], "lane_unresolved_capacity");
    assert_eq!(judge_view["required_release"], 1);
    config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
    assert!(store.admission_allowed(&config, &answer).unwrap());
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 300;
    assert_eq!(
        store
            .admission_projection(&config, LaneId::Answer, Some(2), Some(&answer))
            .unwrap()["reason"],
        "account_uncertainty_grace"
    );
    assert_eq!(store.operation(judge.id).unwrap().unwrap().state, "unknown");
}

#[test]
fn missing_job_failure_does_not_delay_healthy_same_lane_or_other_lane() {
    let (_dir, config, mut store) = fixture();
    let a = unknown(&mut store, &config, LaneId::Judge, 1, Some("a"));
    let b = unknown(&mut store, &config, LaneId::Judge, 2, Some("b"));
    let c = unknown(&mut store, &config, LaneId::Answer, 3, Some("c"));
    let ka = Store::operation_read_key(&a).unwrap();
    let kb = Store::operation_read_key(&b).unwrap();
    assert!(store.read_started(&ka).unwrap());
    store
        .read_finished(&ka, Some(404), Some("not_found"))
        .unwrap();
    store.fail_read(&ka, 180, 900, 0, None).unwrap();
    assert_eq!(
        store
            .reconciliation_batch(LaneId::Judge)
            .unwrap()
            .iter()
            .map(|o| o.id)
            .collect::<Vec<_>>(),
        vec![b.id]
    );
    assert_eq!(
        store.reconciliation_batch(LaneId::Answer).unwrap()[0].id,
        c.id
    );
    store.read_finished(&kb, Some(200), None).unwrap();
    store.reset_read(&kb).unwrap();
    assert_eq!(store.read_backoff(&ka).unwrap().failures, 1);
    store.fail_read(&ka, 180, 900, 0, None).unwrap();
    assert_eq!(store.read_backoff(&ka).unwrap().failures, 2);
    assert_eq!(store.read_backoff(&kb).unwrap().failures, 0);
    assert_eq!(
        store
            .request_not_before(&config, Endpoint::Answer, None)
            .unwrap(),
        0
    );
}

#[test]
fn replacing_binding_retires_every_old_completion_clock_and_state() {
    let (_dir, config, mut store) = fixture();
    let mut op = unknown(&mut store, &config, LaneId::Judge, 1, Some("j1"));
    let stale = op.clone();
    let old = Store::operation_read_key(&op).unwrap();
    store.fail_read(&old, 180, 900, 0, None).unwrap();
    op.job_id = None;
    op.state = "retry".into();
    store.save(&op, "bound_job_expired").unwrap();
    assert!(store.dispatch_intent(&mut op, &config).unwrap());
    op.job_id = Some("j2".into());
    op.state = "queued".into();
    store.save(&op, "submission_queued").unwrap();
    let current = store.operation(op.id).unwrap().unwrap();
    let fresh = Store::operation_read_key(&current).unwrap();
    assert!(current.binding_revision > stale.binding_revision);
    store.read_finished(&old, Some(200), None).unwrap();
    store.reset_read(&old).unwrap();
    store.fail_read(&old, 900, 900, 0, None).unwrap();
    store.cancel_read(&old).unwrap();
    assert!(!store.read_started(&old).unwrap());
    assert_eq!(store.read_backoff(&fresh).unwrap(), ReadBackoff::default());
    assert!(store.save(&stale, "stale_result").is_err());
    assert_eq!(
        store.operation(op.id).unwrap().unwrap().job_id.as_deref(),
        Some("j2")
    );
}

#[test]
fn recovery_round_robin_is_lane_owned_and_includes_off_finality() {
    let (_dir, mut config, mut store) = fixture();
    let mut ids = Vec::new();
    for n in 1..=4 {
        ids.push(
            unknown(
                &mut store,
                &config,
                LaneId::Judge,
                n,
                Some(&format!("j{n}")),
            )
            .id,
        );
    }
    let mut finality = unknown(&mut store, &config, LaneId::Answer, 5, None);
    finality.txid = Some("a".repeat(64));
    finality.state = "confirmed".into();
    store.save(&finality, "receipt_included").unwrap();
    config.capabilities.answer.mode = Mode::Off;
    let batch = store.reconciliation_batch(LaneId::Judge).unwrap();
    assert_eq!(batch.len(), 2);
    let key = Store::operation_read_key(&batch[0]).unwrap();
    assert!(store.read_started(&key).unwrap());
    store
        .reconciliation_attempted(LaneId::Judge, batch[0].id)
        .unwrap();
    let next = store.reconciliation_batch(LaneId::Judge).unwrap();
    assert_eq!(next[0].id, ids[1]);
    assert_eq!(
        store.reconciliation_batch(LaneId::Answer).unwrap()[0].id,
        finality.id
    );
    drop(store);
    let mut store = Store::open(&config).unwrap();
    store.recover().unwrap();
    assert_eq!(
        store.reconciliation_batch(LaneId::Judge).unwrap()[0].id,
        ids[1]
    );
}

#[test]
fn queued_resource_floor_and_shared_floor_have_distinct_authority() {
    let (_dir, config, mut store) = fixture();
    let a = unknown(&mut store, &config, LaneId::Judge, 1, Some("a"));
    let b = unknown(&mut store, &config, LaneId::Judge, 2, Some("b"));
    restriction(
        &store,
        &config,
        RestrictionFixture {
            scope: "resource",
            target: "job:a",
            basis: "server_retry_after",
            deadline: now() + 300,
            reads: true,
            effects: false,
        },
    );
    assert_eq!(
        store.reconciliation_batch(LaneId::Judge).unwrap()[0].id,
        b.id
    );
    assert_eq!(
        store
            .request_not_before(&config, Endpoint::Answer, None)
            .unwrap(),
        0
    );
    restriction(
        &store,
        &config,
        RestrictionFixture {
            scope: "account_authenticated",
            target: "*",
            basis: "local_unscoped_429_cooldown",
            deadline: now() + 30,
            reads: true,
            effects: true,
        },
    );
    assert!(
        store
            .reconciliation_batch(LaneId::Judge)
            .unwrap()
            .is_empty()
    );
    store
        .reset_read(&Store::operation_read_key(&a).unwrap())
        .unwrap();
    assert!(
        store
            .request_not_before(&config, Endpoint::Answer, None)
            .unwrap()
            > now()
    );
    assert_eq!(
        store
            .request_not_before(&config, Endpoint::ExplorerTx, Some(&"a".repeat(64)))
            .unwrap(),
        0
    );
    let deadline = store
        .request_not_before(&config, Endpoint::Answer, None)
        .unwrap();
    drop(store);
    let store = Store::open(&config).unwrap();
    assert_eq!(
        store
            .request_not_before(&config, Endpoint::Answer, None)
            .unwrap(),
        deadline
    );
}

#[test]
fn reload_retimes_only_original_resource_failure_and_preserves_minima() {
    let (_dir, mut config, mut store) = fixture();
    let op = unknown(&mut store, &config, LaneId::Judge, 1, Some("a"));
    let key = Store::operation_read_key(&op).unwrap();
    let answer = ReadKey::Discovery {
        lane: LaneId::Answer,
        source: DiscoverySource::Challenge,
    };
    store.fail_read(&key, 300, 900, 0, None).unwrap();
    store.fail_read(&answer, 300, 900, 0, None).unwrap();
    let before = store.read_backoff(&answer).unwrap();
    store
        .db
        .execute(
            "UPDATE read_state SET retained_conservative_floor=?1 WHERE operation_id=?2",
            params![now() + 200, op.id],
        )
        .unwrap();
    config.capabilities.judge.schedule.retry_seconds = 1;
    config.capabilities.judge.schedule.backoff_max_seconds = 2;
    config.capabilities.answer.schedule.retry_seconds = 300;
    config.capabilities.answer.schedule.jitter_seconds = 0;
    store.reschedule_all_reads(&config).unwrap();
    assert_eq!(store.read_backoff(&answer).unwrap(), before);
    assert!(store.read_backoff(&key).unwrap().next_at >= now() + 199);
    store.reset_read(&key).unwrap();
    assert!(store.read_backoff(&key).unwrap().next_at >= now() + 199);
}

#[test]
fn lane_snapshots_reject_stale_sequences_authority_and_regressed_epoch() {
    let (_dir, _config, store) = fixture();
    let generation = store.control().unwrap().generation;
    let completed = now() - 60;
    assert!(
        store
            .seed_lane_observation_for_test(
                LaneId::Answer,
                LaneObservationStamp {
                    authority_epoch: 1,
                    generation,
                    request_sequence: 2,
                    started_at: completed - 10,
                    completed_at: completed,
                },
                11,
                false,
                "a",
                &json!({"private":"answer"})
            )
            .unwrap()
    );
    assert!(
        store
            .seed_lane_observation_for_test(
                LaneId::Mine,
                LaneObservationStamp {
                    authority_epoch: 1,
                    generation,
                    request_sequence: 1,
                    started_at: now(),
                    completed_at: now(),
                },
                10,
                false,
                "b",
                &json!({})
            )
            .unwrap()
    );
    assert!(
        !store
            .seed_lane_observation_for_test(
                LaneId::Answer,
                LaneObservationStamp {
                    authority_epoch: 1,
                    generation,
                    request_sequence: 1,
                    started_at: now(),
                    completed_at: now(),
                },
                12,
                true,
                "old",
                &json!({})
            )
            .unwrap()
    );
    assert!(
        !store
            .seed_lane_observation_for_test(
                LaneId::Answer,
                LaneObservationStamp {
                    authority_epoch: 1,
                    generation,
                    request_sequence: 3,
                    started_at: now(),
                    completed_at: now(),
                },
                9,
                true,
                "old",
                &json!({})
            )
            .unwrap()
    );
    store.set_authority_epoch(2).unwrap();
    assert!(
        !store
            .seed_lane_observation_for_test(
                LaneId::Answer,
                LaneObservationStamp {
                    authority_epoch: 1,
                    generation,
                    request_sequence: 4,
                    started_at: now(),
                    completed_at: now(),
                },
                12,
                true,
                "old",
                &json!({})
            )
            .unwrap()
    );
    assert_eq!(
        store.lane_observation(LaneId::Answer).unwrap().unwrap()["epoch"],
        11
    );
    assert_eq!(
        store.lane_observation(LaneId::Mine).unwrap().unwrap()["epoch"],
        10
    );
    assert!(
        store
            .seed_lane_observation_for_test(
                LaneId::Answer,
                LaneObservationStamp {
                    authority_epoch: 2,
                    generation,
                    request_sequence: 1,
                    started_at: now() - 40,
                    completed_at: now() - 30,
                },
                11,
                false,
                "new",
                &json!({})
            )
            .unwrap()
    );
    let snapshot = store.lane_observation(LaneId::Answer).unwrap().unwrap();
    assert_eq!(snapshot["first_observed_at"], completed);
    assert!(snapshot["observed_at"].as_i64().unwrap() > completed);
}

#[test]
fn future_answer_retry_does_not_reserve_lower_lane_admission() {
    let (_dir, mut config, mut store) = fixture();
    config
        .capabilities
        .answer
        .participation
        .retry_uncertain_answers = true;
    config
        .capabilities
        .answer
        .participation
        .uncertain_answer_retry_seconds = 3600;
    let original = unknown(&mut store, &config, LaneId::Answer, 1, None);
    assert!(!store.answer_retry_allowed(&config, &original).unwrap());
    let judge = prepared(&mut store, LaneId::Judge, 2);
    assert!(store.admission_allowed(&config, &judge).unwrap());
    assert_eq!(
        store
            .admission_projection(&config, LaneId::Judge, Some(2), Some(&judge))
            .unwrap()["own_count"],
        0
    );
}

#[test]
fn pending_migration_blocks_normal_mutations_without_touching_generation() {
    let (_dir, config, mut store) = fixture();
    let generation = store.control().unwrap().generation;
    store.db.execute_batch("CREATE TABLE capability_migration(singleton INTEGER PRIMARY KEY,phase TEXT,token TEXT,sealed TEXT);
        INSERT INTO capability_migration VALUES(1,'journal_ready','test','{}');").unwrap();
    assert!(store.set_paused_unbound(true).is_err());
    assert!(store.defer(LaneId::Answer, 1).is_err());
    assert!(store.read_started(&ReadKey::Identity).is_err());
    assert!(Store::open(&config).is_err());
    assert_eq!(store.control().unwrap().generation, generation);
    assert_eq!(store.status(&config).unwrap()["migration"]["pending"], true);
}

#[test]
fn ordinary_schema_open_never_upgrades_legacy_or_recreates_authority() {
    let (_dir, config, store) = fixture();
    let id = store.database_identity().unwrap();
    store
        .db
        .execute("UPDATE control SET version=2", [])
        .unwrap();
    drop(store);
    assert!(Store::open(&config).is_err());
    let db = Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT version FROM control", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row(
            "SELECT database_id,dispatch_sequence FROM authority",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        )
        .unwrap(),
        id
    );
}

#[test]
fn mining_interval_does_not_gate_discovery_or_existing_recovery() {
    let (_dir, config, mut store) = fixture();
    let op = unknown(&mut store, &config, LaneId::Mine, 1, Some("mine"));
    store.defer_participation(LaneId::Mine, 86400).unwrap();
    store.defer_until(LaneId::Mine, 0).unwrap();
    assert_eq!(store.next_at(LaneId::Mine).unwrap(), 0);
    assert!(store.participation_next_at(LaneId::Mine).unwrap() > now());
    assert_eq!(
        store.reconciliation_batch(LaneId::Mine).unwrap()[0].id,
        op.id
    );
}

#[test]
fn manual_grant_cannot_borrow_a_full_lane_but_can_accept_foreign_uncertainty() {
    let (_dir, mut config, mut store) = fixture();
    config
        .capabilities
        .judge
        .participation
        .max_unresolved_operations = 1;
    let judge = unknown(&mut store, &config, LaneId::Judge, 1, None);
    config.capabilities.judge.participation.mode = ParticipationMode::Manual;
    assert!(store.authorize(&config, 2, LaneId::Judge).is_err());
    config.capabilities.answer.participation.mode = ParticipationMode::Manual;
    config
        .capabilities
        .answer
        .participation
        .max_unresolved_operations = 1;
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 3600;
    let mut answer = prepared(&mut store, LaneId::Answer, 2);
    assert!(!store.admission_allowed(&config, &answer).unwrap());
    store.authorize(&config, 2, LaneId::Answer).unwrap();
    assert!(store.dispatch_intent(&mut answer, &config).unwrap());
    answer.state = "unknown".into();
    store.save(&answer, "dispatch_outcome_unknown").unwrap();
    assert!(store.authorize(&config, 3, LaneId::Answer).is_err());
    assert_eq!(store.operation(judge.id).unwrap().unwrap().state, "unknown");
}

#[test]
fn model_retry_clock_is_per_work_and_does_not_advance_discovery() {
    let (_dir, config, mut store) = fixture();
    let mut model = store
        .begin(
            LaneId::Answer,
            "retry-model",
            "generating",
            &json!({}),
            store.control().unwrap(),
            "route",
        )
        .unwrap();
    model.state = "rejected".into();
    model.next_at = now() + 300;
    store.save(&model, "model_result_invalid").unwrap();
    assert_eq!(
        store
            .model_retry_not_before(LaneId::Answer, "retry-model")
            .unwrap(),
        model.next_at
    );
    assert_eq!(
        store
            .model_retry_not_before(LaneId::Answer, "other-model")
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .model_retry_not_before(LaneId::Judge, "retry-model")
            .unwrap(),
        0
    );
    assert_eq!(store.next_at(LaneId::Answer).unwrap(), 0);
    store.retry_models(&config).unwrap();
    assert_eq!(
        store.operation(model.id).unwrap().unwrap().state,
        "rejected"
    );
    model.next_at = 0;
    store.save(&model, "model_retry_ready").unwrap();
    store.retry_models(&config).unwrap();
    assert_eq!(
        store.operation(model.id).unwrap().unwrap().state,
        "retry_model"
    );
}

#[test]
fn current_read_projection_bounds_presentation_without_deleting_binding_history() {
    let (_dir, config, store) = fixture();
    store.read_started(&ReadKey::Identity).unwrap();
    for lane in [LaneId::Answer, LaneId::Judge, LaneId::Mine] {
        store
            .read_started(&ReadKey::Discovery {
                lane,
                source: if lane == LaneId::Judge {
                    DiscoverySource::Assignments
                } else {
                    DiscoverySource::Challenge
                },
            })
            .unwrap();
    }
    store
        .db
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<257)
        INSERT INTO read_state(owner,purpose,resource,in_flight,started_at)
        SELECT 'judge','assignment','live-'||i,1,?1 FROM n",
            [now()],
        )
        .unwrap();
    store
        .db
        .execute(
            "INSERT INTO read_state(owner,purpose,resource,retired,server_not_before)
        VALUES('judge','job','old:1',1,?1)",
            [now() + 3600],
        )
        .unwrap();
    drop(store);
    let store = Store::read_only(&config).unwrap().unwrap();
    let status = store.status(&config).unwrap();
    let reads = status["reads"].as_array().unwrap();
    assert_eq!(reads.len(), 256);
    assert_eq!(status["reads_truncated"], true);
    assert!(reads.iter().any(|row| row["purpose"] == "identity"));
    for lane in ["answer", "judge", "mine"] {
        assert!(
            reads
                .iter()
                .any(|row| row["owner"] == lane && row["purpose"] == "discovery")
        );
    }
    assert!(reads.iter().all(|row| row["retired"] == false));
    assert_eq!(
        store
            .db
            .query_row("SELECT COUNT(*) FROM read_state WHERE retired=1", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(store.reads_projection().unwrap()["reads_truncated"], true);
}

#[test]
fn once_cutoff_cannot_acquire_a_new_grant_even_with_identical_second_timestamp() {
    let (_dir, mut config, mut store) = fixture();
    unknown(&mut store, &config, LaneId::Judge, 1, None);
    config.capabilities.answer.participation.mode = ParticipationMode::Manual;
    config.capabilities.answer.preparation.while_blocked = false;
    let answer = prepared(&mut store, LaneId::Answer, 2);
    let cutoff = store.admission_cutoff().unwrap();
    let grant = store.authorize(&config, 2, LaneId::Answer).unwrap()["grant_id"]
        .as_i64()
        .unwrap();
    store
        .db
        .execute(
            "UPDATE manual_grants SET created_at=?1 WHERE id=?2",
            params![cutoff.at, grant],
        )
        .unwrap();
    assert!(store.admission_allowed(&config, &answer).unwrap());
    assert!(
        !store
            .admission_allowed_at(&config, &answer, cutoff)
            .unwrap()
    );
    assert!(
        store
            .preparation_allowed(&config, LaneId::Answer, Some(2))
            .unwrap()
    );
    assert!(
        !store
            .preparation_allowed_at(&config, LaneId::Answer, Some(2), cutoff)
            .unwrap()
    );
}

#[test]
fn once_cutoff_uses_original_grace_retry_and_shared_floor_clocks() {
    let (_dir, mut config, mut store) = fixture();
    let judge = unknown(&mut store, &config, LaneId::Judge, 1, None);
    let cutoff = store.admission_cutoff().unwrap();
    store
        .db
        .execute(
            "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
            params![cutoff.at - 299, judge.id],
        )
        .unwrap();
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 300;
    config.capabilities.answer.preparation.while_blocked = false;
    let answer = prepared(&mut store, LaneId::Answer, 2);
    let later = AdmissionCutoff {
        at: cutoff.at + 2,
        ..cutoff
    };
    assert!(
        !store
            .admission_allowed_at(&config, &answer, cutoff)
            .unwrap()
    );
    assert!(store.admission_allowed_at(&config, &answer, later).unwrap());
    assert!(
        !store
            .preparation_allowed_at(&config, LaneId::Answer, Some(2), cutoff)
            .unwrap()
    );
    assert!(
        store
            .preparation_allowed_at(&config, LaneId::Answer, Some(2), later)
            .unwrap()
    );
    restriction(
        &store,
        &config,
        RestrictionFixture {
            scope: "account_authenticated",
            target: "*",
            basis: "server_retry_after",
            deadline: cutoff.at + 1,
            reads: true,
            effects: true,
        },
    );
    assert!(
        !store
            .admission_allowed_at(&config, &answer, cutoff)
            .unwrap()
    );
    assert!(store.admission_allowed_at(&config, &answer, later).unwrap());

    let (_other, mut config, mut store) = fixture();
    config
        .capabilities
        .answer
        .participation
        .retry_uncertain_answers = true;
    config
        .capabilities
        .answer
        .participation
        .uncertain_answer_retry_seconds = 60;
    let original = unknown(&mut store, &config, LaneId::Answer, 3, None);
    let cutoff = store.admission_cutoff().unwrap();
    store
        .db
        .execute(
            "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
            params![cutoff.at - 59, original.id],
        )
        .unwrap();
    assert!(
        !store
            .answer_retry_allowed_at(&config, &original, cutoff)
            .unwrap()
    );
    assert!(
        store
            .answer_retry_allowed_at(
                &config,
                &original,
                AdmissionCutoff {
                    at: cutoff.at + 2,
                    ..cutoff
                }
            )
            .unwrap()
    );
}
