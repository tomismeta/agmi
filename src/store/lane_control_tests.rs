use super::*;
use crate::solver::SolverRequest;
use crate::solver::contract::{AnswerTask, GradeTask, ModelSelection, NativeRequest};
use crate::store::tests::bound_fixture;
use std::collections::BTreeMap;
use std::sync::mpsc;

struct Fixture {
    store: Store,
    _writer: AccountLock,
    config: Config,
    _anchors: Anchors,
    _directory: tempfile::TempDir,
}

// Fields above release the journal and lifetime writer before these private,
// uniquely addressed test anchors are removed. Admission guards are test locals.
struct Anchors(Vec<PathBuf>);
impl Drop for Anchors {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn fixture() -> Fixture {
    let (directory, mut config) = bound_fixture();
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.mine.mode = Mode::Active;
    config.capabilities.answer.model.core_guidance = "Answer the supplied task.".into();
    config.capabilities.judge.model.core_guidance = "Grade the supplied candidate.".into();
    let (writer, mut store) = AccountLock::acquire(&config).unwrap();
    store
        .set_paused(false, &AccountAdmissionGuard::acquire(&config).unwrap())
        .unwrap();
    store.set_authority_epoch(1).unwrap();
    store.runtime_state(&config, false).unwrap();
    let database_id = store.database_identity().unwrap().0;
    let mut paths: Vec<_> = LaneId::ALL
        .into_iter()
        .map(|lane| gate_path(&config, &database_id, lane).unwrap())
        .collect();
    paths.extend(
        ["binding", "binding-next", "admission", "writer"]
            .into_iter()
            .map(|suffix| lock_path(&config, suffix).unwrap()),
    );
    Fixture {
        store,
        _writer: writer,
        config,
        _anchors: Anchors(paths),
        _directory: directory,
    }
}

fn stamp(store: &Store, config: &Config, lane: LaneId) -> AdmissionStampSnapshot {
    AdmissionStampSnapshot {
        account_generation: store.control().unwrap().generation,
        lane_control_revision: store.lane_control(lane).unwrap().control_revision,
        authority_epoch: 1,
        lane_config_revision: config.lane_revision(lane).unwrap(),
    }
}

fn token(config: &Config, lane: LaneId) -> String {
    lane_control_status(config, lane).unwrap()["desired"]["control_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn set(config: &Config, lane: LaneId, paused: bool, expected: &str) -> Value {
    set_lane_paused(
        config,
        lane,
        paused,
        expected,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap()
}

fn event_count(store: &Store) -> i64 {
    store
        .db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap()
}

fn assert_error(error: &anyhow::Error, expected: &str) {
    assert_eq!(
        error
            .downcast_ref::<LaneControlError>()
            .map(LaneControlError::code),
        Some(expected),
        "{error:#}"
    );
}

type Rows = Vec<Vec<rusqlite::types::Value>>;
fn rows(db: &Connection, table: &str) -> Rows {
    let mut statement = db
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn retained_state(store: &Store) -> BTreeMap<&'static str, Rows> {
    [
        "control",
        "authority",
        "operations",
        "operation_evidence",
        "operation_timing",
        "operation_links",
        "risk_admissions",
        "risk_historical_answers",
        "risk_accounting_snapshots",
        "schedule",
        "runtime_state",
        "runtime_policy",
        "runtime_authority",
        "manual_grants",
        "lane_observations",
        "lane_observation_evidence",
        "hosted_identity_evidence",
    ]
    .into_iter()
    .map(|table| (table, rows(&store.db, table)))
    .collect()
}

fn prepared(store: &mut Store, config: &Config, lane: LaneId, epoch: u64) -> Operation {
    let account = AccountAdmissionGuard::try_acquire(config).unwrap();
    let gate = LaneAdmissionGuard::try_acquire(config, lane).unwrap();
    let current = stamp(store, config, lane);
    let mut op = store
        .begin_preparation(
            config,
            &account,
            &gate,
            &current,
            PreparationInputs {
                lane,
                key: &format!("{epoch}:lane-control"),
                request: &json!({"solver":{"epoch":epoch},"captured_input":"original"}),
                retry: None,
                policy: &json!({"lane_revision":current.lane_config_revision,"captured_policy":"original"}),
            },
        )
        .unwrap()
        .expect("unpaused lane admits preparation");
    if lane != LaneId::Mine {
        let binding = store.operation_binding(&op).unwrap();
        op.payload = Some(json!({"answer":"captured answer","score":2}));
        op.result = Some(json!({"captured_result":"original"}));
        store
            .complete_preparation(&binding, &op, "prepared")
            .unwrap();
    }
    store.operation(op.id).unwrap().unwrap()
}

fn candidate<'a>(op: &'a Operation, stamp: &'a AdmissionStampSnapshot) -> EffectCandidate<'a> {
    EffectCandidate {
        coordinator_exclusion: None,
        operation: op,
        stamp,
        observation_admit_before: Instant::now() + Duration::from_secs(30),
        observation_admit_before_unix: now() + 30,
        due_at: now(),
    }
}

fn dispatch(store: &mut Store, config: &Config, op: &Operation) -> i64 {
    let account = AccountAdmissionGuard::try_acquire(config).unwrap();
    let gates = [LaneAdmissionGuard::try_acquire(config, op.kind).unwrap()];
    let current = stamp(store, config, op.kind);
    store
        .admit_effect(config, &account, &gates, &[candidate(op, &current)], 0)
        .unwrap()
        .expect("eligible effect has a durable admission")
}

fn model_input(
    config: &Config,
    lane: LaneId,
    current: &AdmissionStampSnapshot,
    id: &str,
) -> (Value, Value, ModelProducerDraft) {
    let model = config.model(lane).unwrap();
    let wire = SolverRequest {
        id: id.into(),
        kind: lane,
        epoch: 8,
        words: vec!["clock".into()],
        min_chars: if lane == LaneId::Judge { 0 } else { 5 },
        max_chars: if lane == LaneId::Judge { 0 } else { 200 },
        assignment: (lane == LaneId::Judge).then(|| "c".repeat(64)),
        candidate: (lane == LaneId::Judge).then(|| "A clock bounds repeated identity work.".into()),
        history: Vec::new(),
        guidance: model.guidance.to_string(),
        core_guidance: model.core_guidance.to_string(),
        candidate_author: None,
        author_history: (lane == LaneId::Judge).then(Default::default),
    };
    let native = match lane {
        LaneId::Answer => NativeRequest::Answer(AnswerTask::new(wire).unwrap()),
        LaneId::Judge => NativeRequest::Grade(GradeTask::new(wire).unwrap()),
        LaneId::Mine => panic!("mining does not use models"),
    };
    let draft = ModelProducerDraft {
        task_kind: if lane == LaneId::Answer {
            "answer"
        } else {
            "grade"
        }
        .into(),
        request_id: id.into(),
        request_digest: native.digest().unwrap(),
        lane_config_revision: current.lane_config_revision.clone(),
        requested: ModelSelection::new(model).unwrap(),
        preflight_admission: current.clone(),
    };
    (
        json!({"solver":native.request()}),
        json!({"lane_revision":current.lane_config_revision,"model_seconds":config.model_seconds(lane).unwrap()}),
        draft,
    )
}

#[test]
fn lane_control_cas_checks_token_before_noop_and_never_churns_noop_history() {
    let fixture = fixture();
    let config = &fixture.config;
    let store = &fixture.store;
    let initial = token(config, LaneId::Answer);
    let judge = token(config, LaneId::Judge);
    let before = retained_state(store);
    let events = event_count(store);
    let initial_revision = store.lane_control(LaneId::Answer).unwrap().control_revision;

    let wrong_lane = set_lane_paused(
        config,
        LaneId::Answer,
        false,
        &judge,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_error(&wrong_lane, "lane_control_conflict");
    assert_eq!(event_count(store), events);
    let noop = set(config, LaneId::Answer, false, &initial);
    assert_eq!(noop["fence_ack"]["acknowledged"], true);
    assert_eq!(noop["fence_ack"]["changed"], false);
    assert_eq!(noop["desired"]["control_token"], initial);
    assert_eq!(noop["desired"]["control_revision"], initial_revision);
    assert_eq!(noop["authoritative_closure"]["state"], "not_closed");
    assert_eq!(noop["observed_admission"]["state"], "unknown");
    assert_eq!(event_count(store), events);

    let paused = set(config, LaneId::Answer, true, &initial);
    assert_eq!(paused["fence_ack"]["acknowledged"], true);
    assert_eq!(paused["fence_ack"]["scope"], "local_admission");
    assert_eq!(paused["fence_ack"]["changed"], true);
    assert!(paused["fence_ack"]["committed_at"].as_i64().unwrap() > 0);
    assert_eq!(paused["desired"]["control_revision"], initial_revision + 1);
    assert_eq!(
        paused["authoritative_closure"]["reasons"],
        json!(["lane_paused"])
    );
    let current = paused["desired"]["control_token"].as_str().unwrap();
    assert_ne!(current, initial);
    let stale = set_lane_paused(
        config,
        LaneId::Answer,
        true,
        &initial,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_error(&stale, "lane_control_conflict");
    let repeated = set(config, LaneId::Answer, true, current);
    assert_eq!(repeated["fence_ack"]["changed"], false);
    assert_eq!(repeated["desired"], paused["desired"]);
    assert_eq!(event_count(store), events + 1);

    let resumed = set(config, LaneId::Answer, false, current);
    assert_eq!(resumed["desired"]["control_revision"], initial_revision + 2);
    assert_eq!(resumed["authoritative_closure"]["state"], "not_closed");
    assert_eq!(resumed["observed_admission"]["state"], "unknown");
    // The original boolean matches again, but an ABA token is still stale.
    let stale = set_lane_paused(
        config,
        LaneId::Answer,
        false,
        &initial,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_error(&stale, "lane_control_conflict");
    assert_eq!(token(config, LaneId::Judge), judge);
    assert_eq!(event_count(store), events + 2);
    assert_eq!(retained_state(store), before);
    assert_eq!(
        lane_control_status(config, LaneId::Answer).unwrap()["desired"],
        resumed["desired"]
    );
}

#[test]
fn held_judge_gate_times_out_without_ack_while_answer_pause_ignores_account_writer() {
    let fixture = fixture();
    let config = &fixture.config;
    let account = AccountAdmissionGuard::try_acquire(config).unwrap();
    let judge_gate = LaneAdmissionGuard::try_acquire(config, LaneId::Judge).unwrap();
    let judge_token = token(config, LaneId::Judge);
    let answer_token = token(config, LaneId::Answer);
    let judge_before = fixture.store.lane_control(LaneId::Judge).unwrap();
    let generation = fixture.store.control().unwrap().generation;
    let events = event_count(&fixture.store);
    let (judge_tx, judge_rx) = mpsc::channel();
    let judge_config = config.clone();
    let expected = judge_token.clone();
    let judge_thread = std::thread::spawn(move || {
        let result = set_lane_paused(
            &judge_config,
            LaneId::Judge,
            true,
            &expected,
            Instant::now() + Duration::from_millis(100),
        );
        let _ = judge_tx.send(result);
    });
    let (answer_tx, answer_rx) = mpsc::channel();
    let answer_config = config.clone();
    let answer_thread = std::thread::spawn(move || {
        let result = set_lane_paused(
            &answer_config,
            LaneId::Answer,
            true,
            &answer_token,
            Instant::now() + Duration::from_secs(1),
        );
        let _ = answer_tx.send(result);
    });

    let answer = answer_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("answer control must not wait for the held account/writer/judge gates")
        .unwrap();
    let judge = judge_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("judge control must respect its finite gate deadline")
        .unwrap_err();
    answer_thread.join().unwrap();
    judge_thread.join().unwrap();
    assert_eq!(answer["fence_ack"]["acknowledged"], true);
    assert_eq!(answer["desired"]["paused"], true);
    assert_error(&judge, "lane_control_busy");
    assert_eq!(
        fixture.store.lane_control(LaneId::Judge).unwrap(),
        judge_before
    );
    assert_eq!(token(config, LaneId::Judge), judge_token);
    assert_eq!(fixture.store.control().unwrap().generation, generation);
    assert_eq!(event_count(&fixture.store), events + 1);
    drop(judge_gate);
    let released = set(config, LaneId::Judge, true, &judge_token);
    assert_eq!(released["fence_ack"]["acknowledged"], true);
    assert_eq!(
        released["desired"]["control_revision"],
        judge_before.control_revision + 1
    );
    drop(account);
}

#[test]
fn pause_fences_prepared_effects_without_rewriting_history_or_other_lane_admission() {
    let mut fixture = fixture();
    let config = &fixture.config;
    let store = &mut fixture.store;
    let answer = prepared(store, config, LaneId::Answer, 8);
    let mine = prepared(store, config, LaneId::Mine, 9);
    let original = stamp(store, config, LaneId::Answer);
    let mine_stamp = stamp(store, config, LaneId::Mine);
    let judge_before = store.lane_control(LaneId::Judge).unwrap();
    let before = retained_state(store);
    {
        let account = AccountAdmissionGuard::try_acquire(config).unwrap();
        let gates = [LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap()];
        assert_eq!(
            store
                .select_ready_effect(config, &account, &gates, &[candidate(&answer, &original)])
                .unwrap(),
            Some(0)
        );
    }
    let ack = set(config, LaneId::Answer, true, &token(config, LaneId::Answer));
    assert_eq!(ack["fence_ack"]["acknowledged"], true);
    assert_eq!(
        ack["dispatch_uncertainty"]["dispatch_intent_unsettled_count"],
        0
    );
    assert_eq!(retained_state(store), before);
    assert_eq!(store.lane_control(LaneId::Judge).unwrap(), judge_before);
    assert_eq!(stamp(store, config, LaneId::Mine), mine_stamp);
    {
        let account = AccountAdmissionGuard::try_acquire(config).unwrap();
        let gates = [LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap()];
        let paused = stamp(store, config, LaneId::Answer);
        for attempted_stamp in [&original, &paused] {
            assert_eq!(
                store
                    .admit_effect(
                        config,
                        &account,
                        &gates,
                        &[candidate(&answer, attempted_stamp)],
                        0
                    )
                    .unwrap(),
                None
            );
            assert!(
                store
                    .begin_preparation(
                        config,
                        &account,
                        &gates[0],
                        attempted_stamp,
                        PreparationInputs {
                            lane: LaneId::Answer,
                            key: "10:after-pause",
                            request: &json!({"solver":{"epoch":10}}),
                            retry: None,
                            policy: &json!({}),
                        },
                    )
                    .unwrap()
                    .is_none()
            );
        }
    }
    assert_eq!(retained_state(store), before);
    assert_eq!(
        store.operation(answer.id).unwrap().unwrap().state,
        "prepared"
    );
    assert!(dispatch(store, config, &mine) > 0);
    assert_eq!(
        store.operation(mine.id).unwrap().unwrap().state,
        "dispatching"
    );
    assert_eq!(
        store.operation(answer.id).unwrap().unwrap().payload,
        answer.payload
    );
}

#[test]
fn pause_fences_model_production_and_pending_launch_without_retagging_producer() {
    let mut fixture = fixture();
    let config = &fixture.config;
    let store = &mut fixture.store;
    let original = stamp(store, config, LaneId::Answer);
    let (input, policy, draft) =
        model_input(config, LaneId::Answer, &original, "answer-before-pause");
    let (operation, producer) = {
        let account = AccountAdmissionGuard::try_acquire(config).unwrap();
        let gate = LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap();
        store
            .begin_model_attempt(
                config,
                &account,
                &gate,
                &original,
                LaneId::Answer,
                "8:model",
                &input,
                None,
                &policy,
                draft,
            )
            .unwrap()
            .unwrap()
    };
    let execution_deadline = now() + 30;
    let observation_admit_before = Instant::now() + Duration::from_secs(30);
    store
        .capture_model_pending(operation.id, 30_000, execution_deadline)
        .unwrap();
    let before = retained_state(store);
    let ack = set(config, LaneId::Answer, true, &token(config, LaneId::Answer));
    assert_eq!(ack["fence_ack"]["acknowledged"], true);
    {
        let account = AccountAdmissionGuard::try_acquire(config).unwrap();
        let gate = LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap();
        let paused = stamp(store, config, LaneId::Answer);
        for attempted_stamp in [&original, &paused] {
            let (input, policy, draft) = model_input(
                config,
                LaneId::Answer,
                attempted_stamp,
                "answer-after-pause",
            );
            assert!(
                store
                    .begin_model_attempt(
                        config,
                        &account,
                        &gate,
                        attempted_stamp,
                        LaneId::Answer,
                        "9:blocked-model",
                        &input,
                        None,
                        &policy,
                        draft
                    )
                    .unwrap()
                    .is_none()
            );
            assert!(
                !store
                    .admit_model_launch(
                        config,
                        &account,
                        &gate,
                        attempted_stamp,
                        &producer.operation,
                        execution_deadline,
                        observation_admit_before,
                    )
                    .unwrap()
            );
        }
    }
    assert_eq!(retained_state(store), before);
    assert_eq!(
        store.model_attempt(operation.id).unwrap().unwrap().producer,
        producer
    );
    // The unpaused judge retains its original authority while answer is fenced.
    {
        let current = stamp(store, config, LaneId::Judge);
        let (input, policy, draft) =
            model_input(config, LaneId::Judge, &current, "judge-during-answer-pause");
        let account = AccountAdmissionGuard::try_acquire(config).unwrap();
        let gate = LaneAdmissionGuard::try_acquire(config, LaneId::Judge).unwrap();
        let (judge, provenance) = store
            .begin_model_attempt(
                config,
                &account,
                &gate,
                &current,
                LaneId::Judge,
                &"c".repeat(64),
                &input,
                None,
                &policy,
                draft,
            )
            .unwrap()
            .unwrap();
        store
            .capture_model_pending(judge.id, 30_000, execution_deadline)
            .unwrap();
        assert!(
            store
                .admit_model_launch(
                    config,
                    &account,
                    &gate,
                    &current,
                    &provenance.operation,
                    execution_deadline,
                    observation_admit_before,
                )
                .unwrap()
        );
    }
    let resume = set(
        config,
        LaneId::Answer,
        false,
        ack["desired"]["control_token"].as_str().unwrap(),
    );
    assert_eq!(resume["fence_ack"]["acknowledged"], true);
    let account = AccountAdmissionGuard::try_acquire(config).unwrap();
    let gate = LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap();
    assert!(
        !store
            .admit_model_launch(
                config,
                &account,
                &gate,
                &original,
                &producer.operation,
                execution_deadline,
                observation_admit_before,
            )
            .unwrap()
    );
    let fresh = stamp(store, config, LaneId::Answer);
    assert_eq!(fresh.account_generation, original.account_generation);
    assert!(
        store
            .admit_model_launch(
                config,
                &account,
                &gate,
                &fresh,
                &producer.operation,
                execution_deadline,
                observation_admit_before,
            )
            .unwrap()
    );
    let retained = store.model_attempt(operation.id).unwrap().unwrap();
    assert_eq!(retained.producer, producer);
    assert_eq!(retained.launch.unwrap().admission, fresh);
}

#[test]
fn pause_reports_dispatch_residue_without_recovery_or_history_mutation() {
    let mut fixture = fixture();
    let config = &fixture.config;
    let store = &mut fixture.store;
    let judge = prepared(store, config, LaneId::Judge, 8);
    dispatch(store, config, &judge);
    let answer = prepared(store, config, LaneId::Answer, 9);
    let answer_control = store.lane_control(LaneId::Answer).unwrap();
    let mine_control = store.lane_control(LaneId::Mine).unwrap();
    let history = store.inspect(judge.id).unwrap();
    let before = retained_state(store);
    let binding_before = fs::read(lock_path(config, "binding").unwrap()).unwrap();
    let ack = set(config, LaneId::Judge, true, &token(config, LaneId::Judge));
    assert_eq!(ack["fence_ack"]["acknowledged"], true);
    assert_eq!(ack["authoritative_closure"]["state"], "closed");
    assert_eq!(
        ack["dispatch_uncertainty"]["dispatch_intent_unsettled_count"],
        1
    );
    assert_eq!(
        ack["dispatch_uncertainty"]["dispatch_intent_unsettled_ids"],
        json!([judge.id])
    );
    assert_eq!(ack["dispatch_uncertainty"]["ids_truncated"], false);
    assert_eq!(ack["dispatch_uncertainty"]["unresolved_sent_count"], 1);
    assert_eq!(
        ack["dispatch_uncertainty"]["source"],
        "journal_control_transaction"
    );
    assert_eq!(retained_state(store), before);
    assert_eq!(store.inspect(judge.id).unwrap(), history);
    assert_eq!(
        store.operation(judge.id).unwrap().unwrap().state,
        "dispatching"
    );
    assert_eq!(
        store.operation(answer.id).unwrap().unwrap().payload,
        answer.payload
    );
    assert_eq!(store.lane_control(LaneId::Answer).unwrap(), answer_control);
    assert_eq!(store.lane_control(LaneId::Mine).unwrap(), mine_control);
    assert_eq!(
        fs::read(lock_path(config, "binding").unwrap()).unwrap(),
        binding_before
    );
    assert_eq!(
        lane_control_status(config, LaneId::Judge).unwrap()["dispatch_uncertainty"],
        ack["dispatch_uncertainty"]
    );
}

#[test]
fn journal_ahead_witness_allows_control_without_witness_repair_or_residue_recovery() {
    let mut fixture = fixture();
    let config = &fixture.config;
    let store = &mut fixture.store;
    let old_binding = read_bound_binding(config).unwrap();
    let judge = prepared(store, config, LaneId::Judge, 8);
    let sequence = dispatch(store, config, &judge);
    assert!(sequence > old_binding.dispatch_sequence);
    // Recreate the durable COMMIT-before-witness-publication crash image using
    // the genuine admitted intent and the preceding complete binding witness.
    write_binding(&lock_path(config, "binding").unwrap(), &old_binding).unwrap();
    let witness_before = fs::read(lock_path(config, "binding").unwrap()).unwrap();
    let before = retained_state(store);
    let ack = set(config, LaneId::Judge, true, &token(config, LaneId::Judge));
    assert_eq!(ack["fence_ack"]["acknowledged"], true);
    assert_eq!(
        ack["dispatch_uncertainty"]["dispatch_intent_unsettled_ids"],
        json!([judge.id])
    );
    assert_eq!(ack["dispatch_uncertainty"]["unresolved_sent_count"], 1);
    assert_eq!(retained_state(store), before);
    assert_eq!(store.database_identity().unwrap().1, sequence);
    assert_eq!(
        read_bound_binding(config).unwrap().dispatch_sequence,
        old_binding.dispatch_sequence
    );
    assert_eq!(
        fs::read(lock_path(config, "binding").unwrap()).unwrap(),
        witness_before
    );
    assert_eq!(
        store.operation(judge.id).unwrap().unwrap().state,
        "dispatching"
    );
}

#[test]
fn missing_or_replaced_established_gate_fails_closed_without_repair() {
    for replace in [false, true] {
        let fixture = fixture();
        let config = &fixture.config;
        let store = &fixture.store;
        let expected = token(config, LaneId::Judge);
        let before = retained_state(store);
        let controls = rows(&store.db, "lane_control");
        let events = event_count(store);
        let path = gate_path(config, &store.database_identity().unwrap().0, LaneId::Judge).unwrap();
        // Keep the old inode open, but unlocked, to exclude inode-number reuse.
        let original = opened_file(&path, true, false).unwrap();
        let original_inode = inode(&original.metadata().unwrap()).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = replace.then(|| opened_file(&path, true, true).unwrap());
        if let Some(file) = &replacement {
            assert_ne!(inode(&file.metadata().unwrap()).unwrap(), original_inode);
        }
        let error = set_lane_paused(
            config,
            LaneId::Judge,
            true,
            &expected,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert_error(
            &error,
            if replace {
                "lane_control_continuity"
            } else {
                "lane_control_state_missing"
            },
        );
        assert!(lane_control_status(config, LaneId::Judge).is_err());
        assert!(LaneAdmissionGuard::try_acquire(config, LaneId::Judge).is_err());
        assert_eq!(
            path.exists(),
            replace,
            "missing authority must not be reprovisioned"
        );
        if let Some(file) = &replacement {
            assert_eq!(
                inode(&fs::metadata(&path).unwrap()).unwrap(),
                inode(&file.metadata().unwrap()).unwrap()
            );
        }
        assert_eq!(retained_state(store), before);
        assert_eq!(rows(&store.db, "lane_control"), controls);
        assert_eq!(event_count(store), events);
    }
}

#[test]
fn stale_lane_observation_cannot_overwrite_current_snapshot_or_sibling_observation() {
    let fixture = fixture();
    let config = &fixture.config;
    let store = &fixture.store;
    let answer = stamp(store, config, LaneId::Answer);
    let judge = stamp(store, config, LaneId::Judge);
    let observed_at = now();
    for (lane, current) in [(LaneId::Answer, &answer), (LaneId::Judge, &judge)] {
        store
            .record_admission_observation(
                lane,
                current,
                AdmissionObservation {
                    runtime_instance: "runtime-original",
                    state: "open",
                    reasons: &[],
                    observed_at,
                    valid_until: Some(observed_at + 60),
                },
            )
            .unwrap();
        store
            .record_lane_participation(lane, current, &json!({"allowed":true,"reason":"original"}))
            .unwrap();
    }
    let before = rows(&store.db, "runtime_state");
    let ack = set(config, LaneId::Answer, true, &token(config, LaneId::Answer));
    assert_eq!(rows(&store.db, "runtime_state"), before);
    assert_eq!(ack["observed_admission"]["state"], "unknown");
    assert_eq!(
        ack["observed_admission"]["observed_control_revision"],
        answer.lane_control_revision
    );
    let current = stamp(store, config, LaneId::Answer);
    let mut bad_generation = current.clone();
    bad_generation.account_generation += 1;
    let mut bad_authority = current.clone();
    bad_authority.authority_epoch += 1;
    let mut bad_config = current.clone();
    bad_config.lane_config_revision.push_str("-superseded");
    for stale in [answer, bad_generation, bad_authority, bad_config] {
        store
            .record_admission_observation(
                LaneId::Answer,
                &stale,
                AdmissionObservation {
                    runtime_instance: "stale-writer",
                    state: "closed",
                    reasons: &["stale_write"],
                    observed_at,
                    valid_until: Some(observed_at + 60),
                },
            )
            .unwrap();
        store
            .record_lane_participation(
                LaneId::Answer,
                &stale,
                &json!({"allowed":false,"reason":"stale_write"}),
            )
            .unwrap();
        assert_eq!(rows(&store.db, "runtime_state"), before);
    }
    store
        .record_admission_observation(
            LaneId::Answer,
            &current,
            AdmissionObservation {
                runtime_instance: "runtime-original",
                state: "closed",
                reasons: &["lane_paused"],
                observed_at,
                valid_until: Some(observed_at + 60),
            },
        )
        .unwrap();
    store
        .record_lane_participation(
            LaneId::Judge,
            &judge,
            &json!({"allowed":true,"reason":"judge_still_current"}),
        )
        .unwrap();
    let raw: String = store
        .db
        .query_row(
            "SELECT lane_participation FROM runtime_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let participation: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(participation["answer"]["assessment"]["reason"], "original");
    assert_eq!(
        participation["judge"]["assessment"]["reason"],
        "judge_still_current"
    );
    let status = lane_control_status(config, LaneId::Answer).unwrap();
    assert_eq!(status["authoritative_closure"]["state"], "closed");
    assert_eq!(status["observed_admission"]["state"], "unknown");
    assert_eq!(
        status["observed_admission"]["observed_control_revision"],
        current.lane_control_revision
    );
    assert_eq!(
        status["observed_admission"]["last_observed_state"],
        "closed"
    );
}

fn account_control_state(store: &Store) -> BTreeMap<&'static str, Rows> {
    let mut snapshot = retained_state(store);
    for table in ["events", "lane_control", "routing_profile"] {
        snapshot.insert(table, rows(&store.db, table));
    }
    snapshot
}

#[test]
fn held_account_gate_loss_refuses_global_pause_without_mutation() {
    for replace in [false, true] {
        let mut fixture = fixture();
        let config = &fixture.config;
        let account = AccountAdmissionGuard::acquire(config).unwrap();
        let lane = LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap();
        let before = account_control_state(&fixture.store);
        let binding_path = lock_path(config, "binding").unwrap();
        let binding = fs::read(&binding_path).unwrap();
        let path = lock_path(config, "admission").unwrap();
        if replace {
            let next = path.with_extension("gate-replacement");
            let replacement = opened_file(&next, true, true).unwrap();
            replacement.sync_all().unwrap();
            fs::rename(next, &path).unwrap();
            // A detached old owner cannot exclude this new pathname with flock.
            let replacement = opened_file(&path, true, false).unwrap();
            replacement.try_lock().unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        assert!(AccountAdmissionGuard::acquire(config).is_err());
        assert!(AccountAdmissionGuard::try_acquire(config).is_err());
        assert!(AccountLock::rotation_admission(config).is_err());
        assert!(crate::runtime::pause(config).is_err());
        assert!(fixture.store.set_paused(true, &account).is_err());
        assert!(account.validate(config).is_err());
        assert!(lane.validate_account(&account).is_err());
        assert!(fixture.store.continuity().is_err());
        assert_eq!(account_control_state(&fixture.store), before);
        assert_eq!(fs::read(binding_path).unwrap(), binding);
        assert_eq!(
            path.exists(),
            replace,
            "ordinary control must never recreate a gate"
        );
    }
}

#[test]
fn cached_store_and_held_guard_never_learn_rewritten_admission_anchor() {
    let mut fixture = fixture();
    let config = &fixture.config;
    let account = AccountAdmissionGuard::acquire(config).unwrap();
    let lane = LaneAdmissionGuard::try_acquire(config, LaneId::Answer).unwrap();
    let before = account_control_state(&fixture.store);
    let path = lock_path(config, "admission").unwrap();
    let next = path.with_extension("gate-replacement");
    let replacement = opened_file(&next, true, true).unwrap();
    replacement.sync_all().unwrap();
    fs::rename(next, &path).unwrap();
    let mut binding = read_binding(config).unwrap().unwrap();
    binding.admission_inode =
        Some(WriterInode::from_metadata(&replacement.metadata().unwrap()).unwrap());
    write_binding(&lock_path(config, "binding").unwrap(), &binding).unwrap();
    assert!(account.validate(config).is_err());
    assert!(lane.validate_account(&account).is_err());
    assert!(fixture.store.continuity().is_err());
    assert!(fixture.store.publish_dispatch_witness().is_err());
    let new_gate = AccountAdmissionGuard::acquire(config).unwrap();
    assert!(fixture.store.set_paused(true, &new_gate).is_err());
    assert_eq!(account_control_state(&fixture.store), before);
}

#[test]
fn provisional_account_gate_does_not_initialize_or_authorize_until_fresh_control() {
    let (_directory, config) = bound_fixture();
    let mut anchors = Anchors(
        ["binding", "binding-next", "admission", "writer"]
            .into_iter()
            .map(|suffix| lock_path(&config, suffix).unwrap())
            .collect(),
    );
    assert!(AccountAdmissionGuard::acquire(&config).is_err());
    assert!(AccountAdmissionGuard::try_acquire(&config).is_err());
    assert!(!lock_path(&config, "admission").unwrap().exists());
    let provisional = AccountAdmissionGuard::for_provisioning(&config).unwrap();
    let admission = WriterInode::from_metadata(&provisional.0.metadata().unwrap()).unwrap();
    assert!(provisional.validate(&config).is_err());
    assert!(!config.state_dir.join("state.sqlite3").exists());
    assert!(!lock_path(&config, "binding").unwrap().exists());
    assert!(!lock_path(&config, "writer").unwrap().exists());
    drop(provisional);
    crate::runtime::pause(&config).unwrap();
    let binding = read_binding(&config).unwrap().unwrap();
    assert_eq!(binding.admission_inode, Some(admission));
    assert!(binding.writer_inode.is_some());
    assert_eq!(
        fs::read(lock_path(&config, "writer").unwrap()).unwrap(),
        WRITER_MARKER
    );
    let gate = AccountAdmissionGuard::acquire(&config).unwrap();
    gate.validate(&config).unwrap();
    let store = Store::read_only(&config).unwrap().unwrap();
    assert_eq!(
        store.control().unwrap(),
        Control {
            paused: true,
            generation: 1
        }
    );
    assert_eq!(
        store.writer_authority_status().unwrap()["state"],
        "anchored"
    );
    anchors.0.extend(
        LaneId::ALL
            .into_iter()
            .map(|lane| gate_path(&config, &binding.database_id, lane).unwrap()),
    );
}

#[test]
fn explicit_adoption_fills_only_missing_anchors_and_never_auto_adopts() {
    for (writer_present, admission_present, status) in [
        (false, false, "unanchored"),
        (true, false, "admission_unanchored"),
        (false, true, "writer_unanchored"),
        (true, true, "anchored"),
    ] {
        let fixture = fixture();
        let config = &fixture.config;
        let before = account_control_state(&fixture.store);
        let original = read_binding(config).unwrap().unwrap();
        drop(fixture.store);
        drop(fixture._writer);
        let mut partial = original.clone();
        if !writer_present {
            partial.writer_inode = None;
        }
        if !admission_present {
            partial.admission_inode = None;
        }
        let path = lock_path(config, "binding").unwrap();
        write_binding(&path, &partial).unwrap();
        let bytes = fs::read(&path).unwrap();
        let metadata = Store::read_only(config).unwrap().unwrap();
        assert_eq!(metadata.writer_authority_status().unwrap()["state"], status);
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "metadata must not normalize anchors"
        );
        drop(metadata);
        if !writer_present || !admission_present {
            assert!(AccountAdmissionGuard::for_provisioning(config).is_err());
            assert!(AccountAdmissionGuard::acquire(config).is_err());
            assert!(AccountLock::acquire(config).is_err());
            assert!(crate::runtime::pause(config).is_err());
            assert!(lane_control_status(config, LaneId::Answer).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let (_writer, adopted) = AccountLock::adopt(config).unwrap();
        let installed = read_binding(config).unwrap().unwrap();
        assert!(installed == original);
        assert_eq!(account_control_state(&adopted), before);
        AccountAdmissionGuard::acquire(config)
            .unwrap()
            .validate(config)
            .unwrap();
    }
}

#[test]
fn adoption_refuses_missing_gate_and_every_present_anchor_contradiction() {
    for (writer_present, admission_present) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        for missing in [false, true] {
            let fixture = fixture();
            let config = &fixture.config;
            let before = account_control_state(&fixture.store);
            let mut binding = read_binding(config).unwrap().unwrap();
            drop(fixture.store);
            drop(fixture._writer);
            if !writer_present {
                binding.writer_inode = None;
            }
            if !admission_present {
                binding.admission_inode = None;
            }
            let path = lock_path(config, "binding").unwrap();
            write_binding(&path, &binding).unwrap();
            let bytes = fs::read(&path).unwrap();
            let gate_path = lock_path(config, "admission").unwrap();
            if missing {
                fs::remove_file(&gate_path).unwrap();
            } else if admission_present {
                let next = gate_path.with_extension("gate-replacement");
                drop(opened_file(&next, true, true).unwrap());
                fs::rename(next, &gate_path).unwrap();
            } else if writer_present {
                let writer_path = lock_path(config, "writer").unwrap();
                let next = writer_path.with_extension("writer-replacement");
                let mut replacement = opened_file(&next, true, true).unwrap();
                replacement.write_all(WRITER_MARKER).unwrap();
                replacement.sync_all().unwrap();
                fs::rename(next, writer_path).unwrap();
            } else {
                // No present anchor exists to contradict in this combination.
                continue;
            }
            assert!(AccountLock::adopt(config).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(gate_path.exists(), !missing);
            let db = Connection::open_with_flags(
                config.state_dir.join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            for (table, expected) in &before {
                assert_eq!(&rows(&db, table), expected);
            }
        }
    }
}

#[test]
fn present_malformed_admission_anchor_is_not_legacy_absence() {
    let fixture = fixture();
    let config = &fixture.config;
    drop(fixture.store);
    drop(fixture._writer);
    let path = lock_path(config, "binding").unwrap();
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for invalid in [
        Value::Null,
        json!({"device": 1}),
        json!({"device": 1, "inode": 0}),
        json!({"device": 1, "inode": 2, "extra": 3}),
    ] {
        let mut binding = original.clone();
        binding["admission_inode"] = invalid;
        let bytes = serde_json::to_vec(&binding).unwrap();
        write_binding_bytes(&path, &bytes).unwrap();
        assert!(AccountAdmissionGuard::acquire(config).is_err());
        assert!(AccountLock::adopt(config).is_err());
        assert!(Store::read_only(config).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn lane_control_gate_replacement_precommit_rolls_back_without_account_lock() {
    let fixture = fixture();
    let config = &fixture.config;
    let before = account_control_state(&fixture.store);
    let mut control = ExistingLaneControlStore::open(config, true).unwrap();
    let tx = control
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "UPDATE lane_control SET paused=1,control_revision=control_revision+1 WHERE lane='answer'",
        [],
    )
    .unwrap();
    let path = lock_path(config, "admission").unwrap();
    let next = path.with_extension("gate-replacement");
    drop(opened_file(&next, true, true).unwrap());
    fs::rename(next, path).unwrap();
    assert!(
        ExistingLaneControlStore::check_witness(
            &tx,
            &control.binding,
            &control.writer_path,
            &control.writer
        )
        .is_err()
    );
    drop(tx);
    assert_eq!(account_control_state(&fixture.store), before);
}

#[test]
fn global_pause_gate_replacement_during_sqlite_wait_rolls_back() {
    thread_local! {
        static WAITING: std::cell::RefCell<Option<mpsc::Sender<()>>> =
            const { std::cell::RefCell::new(None) };
    }
    fn busy(_: i32) -> bool {
        WAITING.with(|slot| {
            if let Some(sender) = slot.borrow_mut().take() {
                sender.send(()).unwrap();
            }
        });
        std::thread::sleep(Duration::from_millis(1));
        true
    }
    let mut fixture = fixture();
    let account = AccountAdmissionGuard::acquire(&fixture.config).unwrap();
    let before = account_control_state(&fixture.store);
    let database = fixture.config.state_dir.join("state.sqlite3");
    let path = lock_path(&fixture.config, "admission").unwrap();
    let saved = path.with_extension("held-admission");
    let (locked_tx, locked_rx) = mpsc::channel();
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let replaced_path = path.clone();
    let saved_path = saved.clone();
    let blocker = std::thread::spawn(move || {
        let mut other = Connection::open(database).unwrap();
        let tx = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        locked_tx.send(()).unwrap();
        waiting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        fs::rename(&replaced_path, &saved_path).unwrap();
        drop(opened_file(&replaced_path, true, true).unwrap());
        tx.commit().unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    WAITING.with(|slot| *slot.borrow_mut() = Some(waiting_tx));
    fixture.store.db.busy_handler(Some(busy)).unwrap();
    let result = fixture.store.set_paused(true, &account);
    blocker.join().unwrap();
    fixture
        .store
        .db
        .busy_timeout(Duration::from_secs(5))
        .unwrap();
    fs::remove_file(&path).unwrap();
    fs::rename(saved, path).unwrap();
    assert!(result.is_err());
    assert_eq!(account_control_state(&fixture.store), before);
}

#[test]
fn global_pause_postcommit_gate_loss_reports_uncertainty_not_acknowledgment() {
    struct Replacement {
        path: PathBuf,
        result: Option<Result<()>>,
    }
    unsafe extern "C" fn after_commit(
        context: *mut std::ffi::c_void,
        _: *mut rusqlite::ffi::sqlite3,
        _: *const std::ffi::c_char,
        _: std::ffi::c_int,
    ) -> std::ffi::c_int {
        let replacement = unsafe { &mut *context.cast::<Replacement>() };
        replacement.result = Some((|| {
            let next = replacement.path.with_extension("gate-replacement");
            let file = opened_file(&next, true, true)?;
            file.sync_all()?;
            fs::rename(next, &replacement.path)?;
            Ok(())
        })());
        rusqlite::ffi::SQLITE_OK
    }
    let mut fixture = fixture();
    let account = AccountAdmissionGuard::acquire(&fixture.config).unwrap();
    let generation = fixture.store.control().unwrap().generation;
    let binding_path = lock_path(&fixture.config, "binding").unwrap();
    let binding = fs::read(&binding_path).unwrap();
    let mut replacement = Replacement {
        path: lock_path(&fixture.config, "admission").unwrap(),
        result: None,
    };
    // SQLite invokes the WAL hook after the commit, before returning to Store.
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(
            fixture.store.db.handle(),
            Some(after_commit),
            (&mut replacement as *mut Replacement).cast(),
        );
    }
    let result = fixture.store.set_paused(true, &account);
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(fixture.store.db.handle(), None, std::ptr::null_mut());
    }
    replacement.result.unwrap().unwrap();
    assert!(result.is_err());
    assert_eq!(
        fixture.store.control().unwrap(),
        Control {
            paused: true,
            generation: generation + 1
        }
    );
    assert_eq!(fs::read(binding_path).unwrap(), binding);
    assert!(account.validate(&fixture.config).is_err());
}

#[test]
fn lane_pause_postcommit_witness_regression_reports_uncertainty() {
    struct Rollback {
        path: PathBuf,
        binding: Binding,
        result: Option<Result<()>>,
    }
    unsafe extern "C" fn after_commit(
        context: *mut std::ffi::c_void,
        _: *mut rusqlite::ffi::sqlite3,
        _: *const std::ffi::c_char,
        _: std::ffi::c_int,
    ) -> std::ffi::c_int {
        let rollback = unsafe { &mut *context.cast::<Rollback>() };
        rollback.result = Some(write_binding(&rollback.path, &rollback.binding));
        rusqlite::ffi::SQLITE_OK
    }
    let mut fixture = fixture();
    let config = &fixture.config;
    let control = ExistingLaneControlStore::open(config, true).unwrap();
    let old_binding = read_bound_binding(config).unwrap();
    // A genuine sibling dispatch advances the witness after control opened.
    let answer = prepared(&mut fixture.store, config, LaneId::Answer, 8);
    let sequence = dispatch(&mut fixture.store, config, &answer);
    assert!(sequence > old_binding.dispatch_sequence);
    let expected = token(config, LaneId::Judge);
    let mut rollback = Rollback {
        path: lock_path(config, "binding").unwrap(),
        binding: old_binding,
        result: None,
    };
    // This connection-local hook runs after durable commit, before ACK validation.
    // commit_lane_control owns and closes the connection before rollback is dropped.
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(
            control.db.handle(),
            Some(after_commit),
            (&mut rollback as *mut Rollback).cast(),
        );
    }
    let result = commit_lane_control(
        control,
        config,
        LaneId::Judge,
        true,
        &expected,
        Instant::now() + Duration::from_secs(5),
    );
    rollback.result.unwrap().unwrap();
    assert!(matches!(
        result.unwrap_err().downcast_ref::<LaneControlError>(),
        Some(LaneControlError::CommitUncertain)
    ));
    let committed: (bool, i64) = fixture
        .store
        .db
        .query_row(
            "SELECT paused,control_revision FROM lane_control WHERE lane='judge'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(committed, (true, 1));
    assert_eq!(read_bound_binding(config).unwrap().dispatch_sequence, 0);
    assert_eq!(fixture.store.database_identity().unwrap().1, sequence);
}

#[test]
fn partial_anchor_status_distinguishes_lost_evidence_without_mutation() {
    use std::os::unix::fs::PermissionsExt;
    for (suffix, unsafe_mode) in [("admission", false), ("writer", false), ("admission", true)] {
        let fixture = fixture();
        let config = &fixture.config;
        let before = account_control_state(&fixture.store);
        let mut partial = read_binding(config).unwrap().unwrap();
        drop(fixture.store);
        drop(fixture._writer);
        if suffix == "admission" {
            partial.admission_inode = None;
        } else {
            partial.writer_inode = None;
        }
        let binding_path = lock_path(config, "binding").unwrap();
        write_binding(&binding_path, &partial).unwrap();
        let bytes = fs::read(&binding_path).unwrap();
        let lost_path = lock_path(config, suffix).unwrap();
        if unsafe_mode {
            fs::set_permissions(&lost_path, fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            fs::remove_file(&lost_path).unwrap();
        }
        let metadata = Store::read_only(config).unwrap().unwrap();
        assert_eq!(
            metadata.writer_authority_status().unwrap()["state"],
            "authority_incomplete"
        );
        assert_eq!(account_control_state(&metadata), before);
        drop(metadata);
        assert!(AccountLock::adopt(config).is_err());
        assert_eq!(fs::read(binding_path).unwrap(), bytes);
        assert_eq!(lost_path.exists(), unsafe_mode);
        if unsafe_mode {
            assert_eq!(
                fs::metadata(lost_path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }
}
