use super::*;
use std::time::Duration;

struct Fixture {
    store: Store,
    gates: Vec<LaneAdmissionGuard>,
    account: AccountAdmissionGuard,
    _writer: AccountLock,
    config: Config,
    _dir: tempfile::TempDir,
}

#[derive(Clone)]
struct Ready {
    operation: Operation,
    stamp: AdmissionStampSnapshot,
    deadline: Instant,
    deadline_unix: i64,
    due_at: i64,
}

impl Fixture {
    fn new() -> Self {
        Self::configured(|_| {})
    }

    fn configured(configure: impl FnOnce(&mut Config)) -> Self {
        let (dir, mut config) = crate::store::tests::bound_fixture();
        config.capabilities.answer.mode = Mode::Active;
        config.capabilities.judge.mode = Mode::Active;
        config.capabilities.mine.mode = Mode::Active;
        config.capabilities.answer.participation.mode = ParticipationMode::Strict;
        config.capabilities.judge.participation.mode = ParticipationMode::Strict;
        config.capabilities.mine.participation.mode = ParticipationMode::Strict;
        configure(&mut config);
        let (writer, mut store) = AccountLock::acquire(&config).unwrap();
        let account = AccountAdmissionGuard::try_acquire(&config).unwrap();
        let gates = LaneId::ALL
            .into_iter()
            .map(|lane| LaneAdmissionGuard::try_acquire(&config, lane).unwrap())
            .collect();
        store.set_paused(false, &account).unwrap();
        store.set_authority_epoch(1).unwrap();
        Self {
            store,
            gates,
            account,
            _writer: writer,
            config,
            _dir: dir,
        }
    }

    fn stamp(&self, lane: LaneId) -> AdmissionStampSnapshot {
        AdmissionStampSnapshot {
            account_generation: self.store.control().unwrap().generation,
            lane_control_revision: self.store.lane_control(lane).unwrap().control_revision,
            authority_epoch: 1,
            lane_config_revision: self.config.lane_revision(lane).unwrap(),
        }
    }

    fn observe(
        &self,
        lane: LaneId,
        sequence: u64,
        at: i64,
        epoch: u64,
        fingerprint: &str,
        answered: bool,
    ) -> bool {
        let stamp = self.stamp(lane);
        self.store
            .observe_lane(
                lane,
                LaneObservationStamp {
                    authority_epoch: stamp.authority_epoch,
                    generation: stamp.account_generation,
                    request_sequence: sequence,
                    started_at: at,
                    completed_at: at,
                },
                LaneObservation {
                    epoch,
                    answered,
                    fingerprint,
                    challenge: &json!({"epoch":epoch,"answered":answered}),
                },
                &stamp,
            )
            .unwrap()
    }

    fn grade_abstention(&mut self, assignment: &str, admit_before: Instant) -> Result<bool> {
        let stamp = self.stamp(LaneId::Judge);
        let gate = self
            .gates
            .iter()
            .find(|gate| gate.lane_id() == LaneId::Judge)
            .unwrap();
        self.store.record_grade_abstention(
            &self.config,
            &self.account,
            gate,
            &stamp,
            assignment,
            admit_before,
        )
    }

    fn prepare(&mut self, lane: LaneId, epoch: u64) -> Ready {
        let stamp = self.stamp(lane);
        let gate = self
            .gates
            .iter()
            .find(|gate| gate.lane_id() == lane)
            .unwrap();
        let mut operation = self
            .store
            .begin_preparation(
                &self.config,
                &self.account,
                gate,
                &stamp,
                PreparationInputs {
                    lane,
                    key: &format!("{epoch}:fairness"),
                    request: &json!({"solver":{"epoch":epoch},"challenge_fingerprint":"fixture"}),
                    retry: None,
                    policy: &json!({}),
                },
            )
            .unwrap()
            .unwrap();
        let binding = self.store.operation_binding(&operation).unwrap();
        operation.payload = Some(json!({"captured":"ready effect"}));
        self.store
            .complete_preparation(&binding, &operation, "prepared")
            .unwrap();
        Ready {
            operation,
            stamp,
            deadline: Instant::now() + Duration::from_secs(3600),
            deadline_unix: now() + 3600,
            due_at: 0,
        }
    }

    fn select(&self, ready: &[Ready]) -> Option<usize> {
        self.store
            .select_ready_effect(&self.config, &self.account, &self.gates, &candidates(ready))
            .unwrap()
    }

    fn admit(&mut self, ready: &[Ready], selected: usize) -> Result<Option<i64>> {
        self.store.admit_effect(
            &self.config,
            &self.account,
            &self.gates,
            &candidates(ready),
            selected,
        )
    }

    fn dispatch(&mut self, ready: &Ready) -> i64 {
        let candidates = std::slice::from_ref(ready);
        assert_eq!(self.select(candidates), Some(0));
        let sequence = self.admit(candidates, 0).unwrap().unwrap();
        assert_eq!(
            self.store
                .operation(ready.operation.id)
                .unwrap()
                .unwrap()
                .state,
            "dispatching"
        );
        sequence
    }

    fn outcome(&mut self, id: i64, state: &str) {
        let mut operation = self.store.operation(id).unwrap().unwrap();
        let binding = self.store.operation_binding(&operation).unwrap();
        let gate = self
            .gates
            .iter()
            .find(|gate| gate.lane_id() == operation.kind)
            .unwrap();
        operation.state = state.into();
        self.store
            .complete_effect(
                &self.account,
                gate,
                &binding,
                &operation,
                "dispatch_outcome",
            )
            .unwrap();
    }

    fn round(&self) -> Vec<LaneId> {
        LaneId::ALL
            .into_iter()
            .filter(|lane| {
                self.store
                    .db
                    .query_row(
                        "SELECT served_in_round FROM schedule WHERE kind=?1",
                        [lane.as_str()],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap()
            })
            .collect()
    }

    fn assert_round(&self, expected: &[LaneId]) {
        let served = self.round();
        assert_eq!(served.len(), expected.len());
        for lane in expected {
            assert!(served.contains(lane), "{lane:?} lost its served bit");
        }
    }

    fn sequence(&self) -> i64 {
        self.store.database_identity().unwrap().1
    }

    fn dispatch_events(&self) -> i64 {
        self.store
            .db
            .query_row(
                "SELECT COUNT(*) FROM events WHERE code='dispatch_intent'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn policy(&self, id: i64) -> Value {
        let encoded: String = self
            .store
            .db
            .query_row(
                "SELECT policy FROM operation_evidence WHERE operation_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&encoded).unwrap()
    }

    fn fail_dispatch_evidence(&self) {
        // Runs after the operation, sequence, grant and served-bit writes, so the
        // test exercises their common rollback rather than an early rejection.
        self.store
            .db
            .execute_batch(
                "CREATE TEMP TRIGGER reject_fairness_evidence
             BEFORE UPDATE OF policy ON operation_evidence
             WHEN json_extract(NEW.policy,'$.arbitration.policy') IS NOT NULL
             BEGIN SELECT RAISE(ABORT,'fixture rejects dispatch evidence'); END;",
            )
            .unwrap();
    }

    fn allow_dispatch_evidence(&self) {
        self.store
            .db
            .execute_batch("DROP TRIGGER reject_fairness_evidence")
            .unwrap();
    }

    fn grant_consumer(&self, grant: i64) -> Option<i64> {
        self.store
            .db
            .query_row(
                "SELECT consumed_by FROM manual_grants WHERE id=?1",
                [grant],
                |row| row.get(0),
            )
            .unwrap()
    }
}

fn candidates(ready: &[Ready]) -> Vec<EffectCandidate<'_>> {
    ready
        .iter()
        .map(|item| EffectCandidate {
            coordinator_exclusion: None,
            operation: &item.operation,
            stamp: &item.stamp,
            observation_admit_before: item.deadline,
            observation_admit_before_unix: item.deadline_unix,
            due_at: item.due_at,
        })
        .collect()
}

#[test]
fn newer_same_lane_challenge_vetoes_the_final_transaction() {
    for (lane, epoch, fingerprint, answered) in [
        (LaneId::Answer, 8, "fixture", false),
        (LaneId::Answer, 7, "changed", false),
        (LaneId::Answer, 7, "fixture", true),
        (LaneId::Mine, 8, "fixture", false),
        (LaneId::Mine, 7, "changed", false),
    ] {
        let mut fixture = Fixture::new();
        fixture.store.runtime_state(&fixture.config, false).unwrap();
        let ready = [fixture.prepare(lane, 7)];
        assert!(fixture.observe(lane, 1, 10, 7, "fixture", false));
        let selected = fixture.select(&ready).unwrap();
        // The newer observation arrives after tentative selection, in the
        // same wall-clock second. Dispatch must recheck the committed source.
        assert!(fixture.observe(lane, 2, 10, epoch, fingerprint, answered));
        assert_eq!(fixture.admit(&ready, selected).unwrap(), None);
        assert_eq!(fixture.sequence(), 0);
        assert_eq!(fixture.dispatch_events(), 0);
        fixture.assert_round(&[]);
        let durable = fixture
            .store
            .operation(ready[0].operation.id)
            .unwrap()
            .unwrap();
        assert_eq!(durable.state, "prepared");
        assert_eq!(durable.payload, ready[0].operation.payload);
    }
}

#[test]
fn matching_challenge_ignores_other_lanes_regressed_reads_and_partial_inventory() {
    for lane in LaneId::ALL {
        let mut fixture = Fixture::new();
        fixture.store.runtime_state(&fixture.config, false).unwrap();
        let ready = fixture.prepare(lane, 7);
        if lane == LaneId::Judge {
            fixture
                .store
                .record_lane_participation(
                    lane,
                    &ready.stamp,
                    &json!({"completeness":"bounded_partial","observed_opportunities":0}),
                )
                .unwrap();
        } else {
            assert!(fixture.observe(lane, 1, 10, 7, "fixture", false));
            assert!(fixture.observe(lane, 2, 11, 7, "fixture", lane == LaneId::Mine));
            assert!(!fixture.observe(lane, 3, 12, 6, "old", true));
        }
        let other = if lane == LaneId::Answer {
            LaneId::Mine
        } else {
            LaneId::Answer
        };
        assert!(fixture.observe(other, 1, 12, 9, "unrelated", true));
        assert!(
            !fixture
                .store
                .challenge_contradicts_ready(&ready.operation, &ready.stamp)
                .unwrap()
        );
        assert_eq!(fixture.dispatch(&ready), 1);
    }
}

#[test]
fn local_grade_abstention_commits_terminal_state_event_and_policy_together() {
    let mut fixture = Fixture::new();
    let assignment = "b".repeat(64);
    let expires = Instant::now() + Duration::from_secs(60);
    assert!(
        !fixture
            .grade_abstention(&assignment, Instant::now())
            .unwrap()
    );
    fixture
        .store
        .db
        .execute_batch(
            "CREATE TEMP TRIGGER reject_abstention_evidence BEFORE INSERT ON operation_evidence
             BEGIN SELECT RAISE(ABORT,'fixture rejects abstention evidence'); END;",
        )
        .unwrap();
    assert!(fixture.grade_abstention(&assignment, expires).is_err());
    for query in [
        "SELECT COUNT(*) FROM operations",
        "SELECT COUNT(*) FROM operation_timing",
        "SELECT COUNT(*) FROM operation_evidence",
        "SELECT COUNT(*) FROM events WHERE operation_id IS NOT NULL",
    ] {
        assert_eq!(
            fixture
                .store
                .db
                .query_row(query, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    fixture
        .store
        .db
        .execute_batch("DROP TRIGGER reject_abstention_evidence")
        .unwrap();
    assert!(fixture.grade_abstention(&assignment, expires).unwrap());
    assert!(!fixture.grade_abstention(&assignment, expires).unwrap());
    let (id, state, events, event): (i64, String, i64, String) = fixture
        .store
        .db
        .query_row(
            "SELECT o.id,o.state,COUNT(*),MIN(e.code) FROM operations o
             JOIN events e ON e.operation_id=o.id GROUP BY o.id,o.state",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(state, "abstained");
    assert_eq!(events, 1);
    assert_eq!(event, "assignment_evidence_insufficient");
    assert_eq!(
        fixture.policy(id),
        json!({"lane_revision":fixture.stamp(LaneId::Judge).lane_config_revision})
    );
    assert!(fixture.store.preparation(LaneId::Judge).unwrap().is_none());
    assert_eq!(fixture.sequence(), 0);
    assert_eq!(fixture.dispatch_events(), 0);
    fixture.assert_round(&[]);
}

#[test]
fn startup_repairs_only_exact_never_dispatched_grade_abstention() {
    for (mutation, repair) in [
        ("", true),
        ("UPDATE operations SET request='{' WHERE id=?1", false),
        ("UPDATE operations SET payload='{}' WHERE id=?1", false),
        (
            "UPDATE operations SET binding_revision=1 WHERE id=?1",
            false,
        ),
        (
            "UPDATE operations SET job_id='bound-job' WHERE id=?1",
            false,
        ),
        (
            "UPDATE operations SET revision=CAST(revision AS BLOB) WHERE id=?1",
            false,
        ),
        (
            "UPDATE operation_evidence SET dispatch_sequence=1 WHERE operation_id=?1",
            false,
        ),
        (
            "UPDATE operation_timing SET dispatch_started_at=1 WHERE operation_id=?1",
            false,
        ),
        (
            "UPDATE operation_evidence SET policy='{}' WHERE operation_id=?1",
            false,
        ),
        ("DELETE FROM events WHERE operation_id=?1", false),
        (
            "INSERT INTO events(at,code,kind,operation_id) VALUES(1,'dispatch_intent','judge',?1)",
            false,
        ),
    ] {
        let mut fixture = Fixture::new();
        let stamp = fixture.stamp(LaneId::Judge);
        let assignment = "c".repeat(64);
        let gate = fixture
            .gates
            .iter()
            .find(|gate| gate.lane_id() == LaneId::Judge)
            .unwrap();
        let legacy = fixture
            .store
            .begin_preparation(
                &fixture.config,
                &fixture.account,
                gate,
                &stamp,
                PreparationInputs {
                    lane: LaneId::Judge,
                    key: &assignment,
                    request: &json!({"assignment":assignment,"local_abstention":"required_words_absent"}),
                    retry: None,
                    policy: &json!({"lane_revision":stamp.lane_config_revision}),
                },
            )
            .unwrap()
            .unwrap();
        if !mutation.is_empty() {
            fixture.store.db.execute(mutation, [legacy.id]).unwrap();
        }
        // Recover twice: do not repeat the terminal event or remove original
        // provenance, and leave any possible dispatch fence intact.
        fixture.store.recover().unwrap();
        fixture.store.recover().unwrap();
        let (state, completions): (String, i64) = fixture
            .store
            .db
            .query_row(
                "SELECT state,(SELECT COUNT(*) FROM events WHERE operation_id=?1
                               AND code='assignment_evidence_insufficient') FROM operations WHERE id=?1",
                [legacy.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            state,
            if repair { "abstained" } else { "prepared" },
            "{mutation}"
        );
        assert_eq!(completions, i64::from(repair), "{mutation}");
        assert!(fixture.store.attempted(LaneId::Judge, &assignment).unwrap());
        assert_eq!(fixture.sequence(), 0);
    }
}

#[test]
fn read_only_challenge_history_keeps_transitions_not_identical_polls() {
    let lane = LaneId::Answer;
    let fixture = Fixture::configured(|config| config.capabilities.answer.mode = Mode::ReadOnly);
    fixture.store.runtime_state(&fixture.config, false).unwrap();
    // Retain prior audit rows; the cutover only bounds new writes.
    fixture
        .store
        .db
        .execute(
            "INSERT INTO lane_observation_evidence VALUES('answer',0,0,1,1,5,'legacy',1)",
            [],
        )
        .unwrap();
    for sequence in 1..=8 {
        assert!(fixture.observe(lane, sequence, 10 + sequence as i64, 7, "fixture", false));
    }
    let snapshot = fixture.store.lane_observation(lane).unwrap().unwrap();
    assert_eq!(snapshot["observed_at"], 18);
    assert_eq!(snapshot["first_observed_at"], 11);
    assert!(fixture.observe(lane, 9, 19, 7, "fixture", true));
    assert!(fixture.observe(lane, 10, 20, 7, "alternative", true));
    for sequence in 11..=18 {
        assert!(!fixture.observe(lane, sequence, 10 + sequence as i64, 6, "old", true));
    }
    let snapshot = fixture.store.lane_observation(lane).unwrap().unwrap();
    assert_eq!(snapshot["observed_at"], 20);
    assert_eq!(snapshot["first_observed_at"], 11);
    assert!(fixture.observe(lane, 19, 29, 8, "new-epoch", false));
    let snapshot = fixture.store.lane_observation(lane).unwrap().unwrap();
    assert_eq!(snapshot["first_observed_at"], 29);
    assert_eq!(snapshot["request_sequence"], 19);
    let mut statement = fixture
        .store
        .db
        .prepare(
            "SELECT request_sequence FROM lane_observation_evidence ORDER BY authority_epoch,request_sequence",
        )
        .unwrap();
    let sequences: Vec<i64> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(sequences, [1, 1, 9, 10, 11, 19]);
    assert_eq!(fixture.sequence(), 0);
}

#[test]
fn earliest_monotonic_freshness_wins_only_among_unserved_eligible_lanes() {
    let mut fixture = Fixture::new();
    let previous_answer = fixture.prepare(LaneId::Answer, 1);
    assert_eq!(fixture.dispatch(&previous_answer), 1);
    fixture.outcome(previous_answer.operation.id, "completed");

    let mut ready = vec![
        fixture.prepare(LaneId::Answer, 2),
        fixture.prepare(LaneId::Judge, 3),
        fixture.prepare(LaneId::Mine, 4),
    ];
    let base = Instant::now() + Duration::from_secs(3600);
    ready[0].deadline = base;
    ready[1].deadline = base + Duration::from_secs(120);
    ready[2].deadline = base + Duration::from_secs(60);
    // Wall-clock projection and due order deliberately disagree with the
    // monotonic order. Neither is authority to spend freshness.
    ready[0].deadline_unix = 1;
    ready[1].deadline_unix = 2;
    ready[2].deadline_unix = 3;
    ready[0].due_at = 0;
    ready[1].due_at = 1;
    ready[2].due_at = 2;

    assert_eq!(fixture.select(&ready), Some(2));
    fixture.assert_round(&[LaneId::Answer]);
    assert_eq!(fixture.admit(&ready, 2).unwrap(), Some(2));
    fixture.assert_round(&[LaneId::Answer, LaneId::Mine]);
    assert_eq!(
        fixture.policy(ready[2].operation.id)["arbitration"]["round_reset"],
        false
    );
    let audit = fixture.policy(ready[2].operation.id)["arbitration"].clone();
    assert_eq!(audit["offered"][0]["lane"], "answer");
    assert_eq!(audit["offered"][0]["eligible"], true);
    assert_eq!(audit["offered"][0]["served_in_round"], true);
    assert_eq!(audit["offered"][1]["lane"], "judge");
    assert_eq!(audit["offered"][1]["eligible"], true);
    assert_eq!(audit["offered"][1]["served_in_round"], false);
    assert_eq!(audit["offered"][2]["lane"], "mine");
    assert_eq!(audit["offered"][2]["eligible"], true);
    assert_eq!(audit["offered"][2]["served_in_round"], false);
    fixture.outcome(ready[2].operation.id, "completed");

    let remaining = &ready[..2];
    assert_eq!(fixture.select(remaining), Some(1));
    assert_eq!(fixture.admit(remaining, 1).unwrap(), Some(3));
    fixture.assert_round(&LaneId::ALL);
    assert_eq!(
        fixture
            .store
            .operation(ready[0].operation.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
    assert_eq!(
        fixture
            .store
            .operation(ready[1].operation.id)
            .unwrap()
            .unwrap()
            .state,
        "dispatching"
    );
}

#[test]
fn a_new_round_resets_only_with_a_committed_dispatch_intent() {
    let mut fixture = Fixture::new();
    for (index, lane) in LaneId::ALL.into_iter().enumerate() {
        let ready = fixture.prepare(lane, index as u64 + 1);
        fixture.dispatch(&ready);
        fixture.outcome(ready.operation.id, "completed");
    }
    fixture.assert_round(&LaneId::ALL);
    let before = fixture.sequence();
    let events = fixture.dispatch_events();
    let mut ready = vec![
        fixture.prepare(LaneId::Answer, 10),
        fixture.prepare(LaneId::Judge, 11),
        fixture.prepare(LaneId::Mine, 12),
    ];
    let base = Instant::now() + Duration::from_secs(3600);
    ready[0].deadline = base + Duration::from_secs(60);
    ready[1].deadline = base;
    ready[2].deadline = base + Duration::from_secs(120);
    for _ in 0..3 {
        assert_eq!(fixture.select(&ready), Some(1));
        fixture.assert_round(&LaneId::ALL);
    }
    // A previously selected candidate can lose freshness before write admission.
    let mut expired = ready.clone();
    for candidate in &mut expired {
        candidate.deadline = Instant::now() - Duration::from_secs(1);
    }
    assert_eq!(fixture.select(&expired), None);
    assert_eq!(fixture.admit(&expired, 1).unwrap(), None);
    assert_eq!(fixture.admit(&ready, 0).unwrap(), None);
    fixture.assert_round(&LaneId::ALL);
    assert_eq!(fixture.sequence(), before);
    assert_eq!(fixture.dispatch_events(), events);

    fixture.fail_dispatch_evidence();
    let error = fixture.admit(&ready, 1).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fixture rejects dispatch evidence")
    );
    fixture.assert_round(&LaneId::ALL);
    assert_eq!(fixture.sequence(), before);
    assert_eq!(fixture.dispatch_events(), events);
    for candidate in &ready {
        assert_eq!(
            fixture
                .store
                .operation(candidate.operation.id)
                .unwrap()
                .unwrap()
                .state,
            "prepared"
        );
        assert_eq!(
            candidate.operation.persisted_state.borrow().as_str(),
            "prepared"
        );
    }
    fixture.allow_dispatch_evidence();

    assert_eq!(fixture.admit(&ready, 1).unwrap(), Some(before + 1));
    fixture.assert_round(&[LaneId::Judge]);
    assert_eq!(fixture.dispatch_events(), events + 1);
    assert_eq!(
        fixture.policy(ready[1].operation.id)["arbitration"]["round_reset"],
        true
    );
    assert_eq!(
        fixture
            .store
            .operation(ready[1].operation.id)
            .unwrap()
            .unwrap()
            .state,
        "dispatching"
    );
}

#[test]
fn rejected_stamps_freshness_and_stale_operation_cas_do_not_spend_a_turn() {
    let mut fixture = Fixture::new();
    let mut ready = vec![
        fixture.prepare(LaneId::Answer, 1),
        fixture.prepare(LaneId::Judge, 2),
    ];
    ready[1].deadline = ready[0].deadline + Duration::from_secs(60);
    type Rejection = (&'static str, fn(&mut Ready));
    let rejections: [Rejection; 8] = [
        ("expired observation", |ready| {
            ready.deadline = Instant::now() - Duration::from_secs(1)
        }),
        ("stale account", |ready| ready.stamp.account_generation -= 1),
        ("stale lane control", |ready| {
            ready.stamp.lane_control_revision += 1
        }),
        ("stale authority", |ready| ready.stamp.authority_epoch += 1),
        ("stale lane config", |ready| {
            ready.stamp.lane_config_revision.push_str("-stale")
        }),
        ("missing payload", |ready| ready.operation.payload = None),
        ("rejected operation", |ready| {
            ready.operation.state = "locally_rejected".into()
        }),
        ("not due", |ready| ready.operation.next_at = now() + 3600),
    ];
    for (reason, reject) in rejections {
        let mut rejected = ready.clone();
        reject(&mut rejected[0]);
        assert_eq!(fixture.select(&rejected), Some(1), "{reason}");
        assert_eq!(fixture.admit(&rejected, 0).unwrap(), None, "{reason}");
        fixture.assert_round(&[]);
        assert_eq!(fixture.sequence(), 0, "{reason}");
        assert_eq!(fixture.dispatch_events(), 0, "{reason}");
    }

    assert_eq!(fixture.select(&ready), Some(0));
    let binding = fixture
        .store
        .operation_binding(&ready[0].operation)
        .unwrap();
    fixture
        .store
        .retire_unsent(&binding, "unsent_admission_closed")
        .unwrap();
    // Keep the old ready value to exercise a genuine selection-to-CAS race.
    assert!(!matches!(fixture.admit(&ready, 0), Ok(Some(_))));
    fixture.assert_round(&[]);
    assert_eq!(fixture.sequence(), 0);
    assert_eq!(fixture.dispatch_events(), 0);
    assert_eq!(
        fixture
            .store
            .operation(ready[0].operation.id)
            .unwrap()
            .unwrap()
            .state,
        "discarded"
    );
    assert_eq!(fixture.dispatch(&ready[1]), 1);
    fixture.assert_round(&[LaneId::Judge]);
}

#[test]
fn a_busy_lane_and_an_in_flight_effect_do_not_consume_other_lanes_turns() {
    let mut fixture = Fixture::new();
    let mut ready = vec![
        fixture.prepare(LaneId::Answer, 1),
        fixture.prepare(LaneId::Judge, 2),
    ];
    ready[1].deadline = ready[0].deadline + Duration::from_secs(60);
    let answer_gate = fixture
        .gates
        .iter()
        .position(|gate| gate.lane_id() == LaneId::Answer)
        .unwrap();
    let held_gate = fixture.gates.remove(answer_gate);
    // A distinct open file description contends on the real OS gate. The
    // runtime omits that unavailable guard from this selection turn.
    let busy = LaneAdmissionGuard::try_acquire(&fixture.config, LaneId::Answer)
        .err()
        .expect("the held lane gate must be busy");
    assert!(matches!(
        busy.downcast_ref::<LaneControlError>(),
        Some(LaneControlError::Busy)
    ));
    assert_eq!(fixture.select(&ready), Some(1));
    assert_eq!(fixture.admit(&ready, 0).unwrap(), None);
    fixture.assert_round(&[]);
    assert_eq!(fixture.admit(&ready, 1).unwrap(), Some(1));
    fixture.assert_round(&[LaneId::Judge]);
    let audit = fixture.policy(ready[1].operation.id)["arbitration"].clone();
    assert_eq!(audit["offered"][0]["lane"], "answer");
    assert_eq!(audit["offered"][0]["eligible"], false);
    assert_eq!(audit["offered"][0]["exclusion"], "lane_gate_unavailable");
    assert!(audit["offered"][0]["served_in_round"].is_null());
    assert_eq!(audit["offered"][1]["lane"], "judge");
    assert_eq!(audit["offered"][1]["eligible"], true);
    assert!(audit["offered"][1]["exclusion"].is_null());

    drop(held_gate);
    fixture
        .gates
        .push(LaneAdmissionGuard::try_acquire(&fixture.config, LaneId::Answer).unwrap());
    // The gate is now available, but the shared HTTP effect is not settled.
    assert_eq!(fixture.select(&ready[..1]), None);
    assert_eq!(fixture.admit(&ready[..1], 0).unwrap(), None);
    fixture.assert_round(&[LaneId::Judge]);
    assert_eq!(fixture.sequence(), 1);
    fixture.outcome(ready[1].operation.id, "completed");
    assert_eq!(fixture.dispatch(&ready[0]), 2);
    fixture.assert_round(&[LaneId::Answer, LaneId::Judge]);
    assert_eq!(
        fixture.policy(ready[0].operation.id)["arbitration"]["round_reset"],
        false
    );
}

#[test]
fn fairness_cannot_bypass_risk_or_spend_a_manual_grant_on_failed_admission() {
    let mut fixture = Fixture::configured(|config| {
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
    });
    let unresolved = fixture.prepare(LaneId::Mine, 1);
    fixture.dispatch(&unresolved);
    fixture.outcome(unresolved.operation.id, "unknown");
    let mut ready = vec![
        fixture.prepare(LaneId::Answer, 2),
        fixture.prepare(LaneId::Judge, 3),
    ];
    ready[1].deadline = ready[0].deadline + Duration::from_secs(60);
    assert_eq!(fixture.select(&ready), None);
    assert_eq!(fixture.admit(&ready, 0).unwrap(), None);
    fixture.assert_round(&[LaneId::Mine]);

    let wrong_epoch = fixture
        .store
        .authorize(&fixture.config, 99, LaneId::Answer)
        .unwrap()["grant_id"]
        .as_i64()
        .unwrap();
    assert_eq!(fixture.select(&ready), None);
    let grant = fixture
        .store
        .authorize(&fixture.config, 2, LaneId::Answer)
        .unwrap()["grant_id"]
        .as_i64()
        .unwrap();
    let mut stale = ready.clone();
    stale[0].stamp.account_generation -= 1;
    assert_eq!(fixture.select(&stale), None);
    assert_eq!(fixture.admit(&stale, 0).unwrap(), None);
    assert_eq!(fixture.grant_consumer(grant), None);
    fixture.assert_round(&[LaneId::Mine]);

    assert_eq!(fixture.select(&ready), Some(0));
    fixture.fail_dispatch_evidence();
    assert!(fixture.admit(&ready, 0).is_err());
    assert_eq!(fixture.grant_consumer(grant), None);
    assert_eq!(fixture.grant_consumer(wrong_epoch), None);
    fixture.assert_round(&[LaneId::Mine]);
    assert_eq!(fixture.sequence(), 1);
    assert_eq!(fixture.dispatch_events(), 1);
    let risk_rows: i64 = fixture
        .store
        .db
        .query_row(
            "SELECT COUNT(*) FROM risk_admissions WHERE operation_id=?1",
            [ready[0].operation.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(risk_rows, 0);
    fixture.allow_dispatch_evidence();

    assert_eq!(fixture.admit(&ready, 0).unwrap(), Some(2));
    assert_eq!(fixture.grant_consumer(grant), Some(ready[0].operation.id));
    assert_eq!(fixture.grant_consumer(wrong_epoch), None);
    fixture.assert_round(&[LaneId::Answer, LaneId::Mine]);
    let (retained_grant, blockers): (i64, String) = fixture
        .store
        .db
        .query_row(
            "SELECT manual_grant_id,blocker_ids FROM risk_admissions WHERE operation_id=?1",
            [ready[0].operation.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained_grant, grant);
    assert_eq!(
        serde_json::from_str::<Vec<i64>>(&blockers).unwrap(),
        vec![unresolved.operation.id]
    );
    assert_eq!(
        fixture
            .store
            .operation(ready[1].operation.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
}

#[test]
fn continuously_eligible_lanes_obey_the_finite_round_starvation_bound() {
    let mut fixture = Fixture::new();
    let mut epoch = 1;
    let mut ready: Vec<_> = LaneId::ALL
        .into_iter()
        .map(|lane| {
            let operation = fixture.prepare(lane, epoch);
            epoch += 1;
            operation
        })
        .collect();
    let mut last_service = [None; LaneId::COUNT];
    let mut longest_gap = [0; LaneId::COUNT];
    let mut dispatches = 0;
    let bound = 2 * LaneId::COUNT - 1;
    let base = Instant::now() + Duration::from_secs(3600);

    for round in 0..4 {
        let mut priority = LaneId::ALL.to_vec();
        if round % 2 != 0 {
            priority.reverse();
        }
        for (rank, lane) in priority.iter().enumerate() {
            let candidate = ready
                .iter_mut()
                .find(|candidate| candidate.operation.kind == *lane)
                .unwrap();
            candidate.deadline = base + Duration::from_secs(rank as u64 * 60);
        }
        for (turn, expected) in priority.iter().enumerate() {
            let before_selection = fixture.round();
            let selected = fixture.select(&ready).unwrap();
            assert_eq!(fixture.round(), before_selection);
            assert_eq!(ready[selected].operation.kind, *expected);
            dispatches += 1;
            assert_eq!(
                fixture.admit(&ready, selected).unwrap(),
                Some(dispatches as i64)
            );
            assert_eq!(
                fixture.policy(ready[selected].operation.id)["arbitration"]["round_reset"],
                round > 0 && turn == 0,
            );
            if let Some(previous) = last_service[selected] {
                let gap = dispatches - previous;
                assert!(
                    gap <= bound,
                    "{expected:?} waited {gap} successful admissions"
                );
                longest_gap[selected] = longest_gap[selected].max(gap);
            } else {
                assert!(dispatches <= LaneId::COUNT);
            }
            last_service[selected] = Some(dispatches);
            fixture.outcome(ready[selected].operation.id, "completed");

            // Immediately replenish the just-served lane with equally urgent
            // work. It remains eligible but must not jump its unserved peers.
            let deadline = ready[selected].deadline;
            ready[selected] = fixture.prepare(*expected, epoch);
            epoch += 1;
            ready[selected].deadline = deadline;
        }
        fixture.assert_round(&LaneId::ALL);
    }
    // First in one round, last in the next attains the worst-case gap: the
    // contract is not the stronger (and false) N-admission sliding-window bound.
    assert_eq!(longest_gap[0], bound);
    assert!(last_service.iter().all(Option::is_some));
    assert_eq!(fixture.dispatch_events(), (4 * LaneId::COUNT) as i64);
}

#[test]
fn writer_replacement_during_sqlite_wait_rolls_back_dispatch_authority() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
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

    let mut fixture = Fixture::configured(|config| {
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
    });
    let unresolved = fixture.prepare(LaneId::Mine, 1);
    fixture.dispatch(&unresolved);
    fixture.outcome(unresolved.operation.id, "unknown");
    let ready = fixture.prepare(LaneId::Answer, 8);
    let grant = fixture
        .store
        .authorize(&fixture.config, 8, LaneId::Answer)
        .unwrap()["grant_id"]
        .as_i64()
        .unwrap();
    let before_sequence = fixture.sequence();
    let before_round = fixture.round();
    let before_events = fixture.dispatch_events();
    let before_policy = fixture.policy(ready.operation.id);
    let writer = lock_path(&fixture.config, "writer").unwrap();
    let saved = writer.with_extension("held-writer");
    let marker = fs::read(&writer).unwrap();
    let database = fixture.config.state_dir.join("state.sqlite3");
    let (locked_tx, locked_rx) = mpsc::channel();
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let replacement_path = writer.clone();
    let saved_path = saved.clone();
    let blocker = std::thread::spawn(move || {
        let mut other = Connection::open(database).unwrap();
        let tx = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        locked_tx.send(()).unwrap();
        waiting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // Admission passed its initial continuity check and is now blocked.
        fs::rename(&replacement_path, &saved_path).unwrap();
        fs::write(&replacement_path, marker).unwrap();
        fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).unwrap();
        tx.commit().unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    WAITING.with(|slot| *slot.borrow_mut() = Some(waiting_tx));
    fixture.store.db.busy_handler(Some(busy)).unwrap();
    let result = fixture.admit(std::slice::from_ref(&ready), 0);
    blocker.join().unwrap();
    fixture
        .store
        .db
        .busy_timeout(Duration::from_secs(5))
        .unwrap();
    // Restore the original fixture inode before checking retained state.
    fs::remove_file(&writer).unwrap();
    fs::rename(&saved, &writer).unwrap();
    assert!(result.is_err(), "lost writer authority committed dispatch");
    assert_eq!(fixture.sequence(), before_sequence);
    assert_eq!(fixture.round(), before_round);
    assert_eq!(fixture.dispatch_events(), before_events);
    assert_eq!(fixture.policy(ready.operation.id), before_policy);
    assert_eq!(fixture.grant_consumer(grant), None);
    let retained_risk: i64 = fixture
        .store
        .db
        .query_row(
            "SELECT COUNT(*) FROM risk_admissions WHERE operation_id=?1",
            [ready.operation.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_risk, 0);
    assert_eq!(
        fixture
            .store
            .operation(ready.operation.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
}

#[test]
fn current_stamp_dispatches_prepared_capture_and_preserves_its_revision() {
    let mut fixture = Fixture::new();
    let ready = fixture.prepare(LaneId::Answer, 7);
    let binding = fixture.store.operation_binding(&ready.operation).unwrap();
    // The helper accepts the unchanged full revision without any producer
    // proof beyond the binding itself.
    assert!(
        Store::operation_config_current_in(&fixture.store.db, &fixture.config, &binding).unwrap()
    );
    // A stale generation stamp cannot dispatch the same capture: root
    // generation and current controls remain mandatory.
    let mut stale = ready.clone();
    stale.stamp.account_generation += 1;
    assert_eq!(fixture.select(std::slice::from_ref(&stale)), None);
    // The current stamp dispatches without rewriting the captured revision.
    let revision_before: String = fixture
        .store
        .db
        .query_row(
            "SELECT revision FROM operations WHERE id=?1",
            [ready.operation.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fixture.select(std::slice::from_ref(&ready)), Some(0));
    fixture.dispatch(&ready);
    let after = fixture
        .store
        .operation(ready.operation.id)
        .unwrap()
        .unwrap();
    assert_eq!(after.state, "dispatching");
    let revision_after: String = fixture
        .store
        .db
        .query_row(
            "SELECT revision FROM operations WHERE id=?1",
            [ready.operation.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revision_after, revision_before);
    let policy = fixture.policy(ready.operation.id);
    assert_eq!(
        policy["dispatch_admission"]["lane_config_revision"],
        ready.stamp.lane_config_revision
    );
}

#[test]
fn admission_only_config_change_without_producer_proof_stays_fenced() {
    let mut fixture = Fixture::new();
    let mut ready = fixture.prepare(LaneId::Answer, 7);
    let producer_before = fixture.config.producer_revision(LaneId::Answer).unwrap();
    // Grace is scheduling intent, not producer input: it moves the full
    // lane revision while the producer revision is unchanged.
    fixture
        .config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds += 1;
    assert_ne!(
        fixture.config.lane_revision(LaneId::Answer).unwrap(),
        ready.stamp.lane_config_revision
    );
    assert_eq!(
        fixture.config.producer_revision(LaneId::Answer).unwrap(),
        producer_before
    );
    // A legacy capture carrying no producer hash must not gain the exception:
    // provenance is never invented.
    ready.stamp.lane_config_revision = fixture.config.lane_revision(LaneId::Answer).unwrap();
    let binding = fixture.store.operation_binding(&ready.operation).unwrap();
    assert!(
        !Store::operation_config_current_in(&fixture.store.db, &fixture.config, &binding).unwrap()
    );
    assert_eq!(fixture.select(std::slice::from_ref(&ready)), None);
    assert_eq!(
        fixture
            .store
            .operation(ready.operation.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
}
