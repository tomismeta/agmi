use super::*;

fn fixture() -> (tempfile::TempDir, Config, Store) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        state_dir: dir.path().join("state"),
        ..Config::default()
    };
    config.capabilities.judge.schedule.retry_seconds = 10;
    config.capabilities.judge.schedule.backoff_max_seconds = 50;
    config.capabilities.judge.schedule.jitter_seconds = 0;
    let store = Store::open(&config).unwrap();
    (dir, config, store)
}

fn seed(store: &Store, lane: LaneId, id: i64, missing: bool) -> ReadKey {
    store.db.execute(
        "INSERT INTO operations(id,kind,work_key,state,request,job_id,generation,revision,created_at,updated_at,binding_revision)
        VALUES (?1,?2,?3,'unknown','{}',?4,0,'test',0,0,1)",
        params![id, lane.as_str(), format!("work-{id}"), format!("job-{id}")],
    ).unwrap();
    let key = ReadKey::Operation {
        operation_id: id,
        binding_revision: 1,
        phase: ReadPhase::Job,
    };
    assert!(store.ensure_read_row(&key).unwrap());
    if missing {
        store.db.execute(
            "UPDATE read_state SET failures=2,status=404,failure_category='not_found' WHERE operation_id=?1",
            [id],
        ).unwrap();
    }
    key
}

#[test]
fn inspection_reports_only_recorded_binding_checks_not_reservations_or_cancellation() {
    for phase in [ReadPhase::Job, ReadPhase::Receipt] {
        for completed in [false, true] {
            let (_dir, config, store) = fixture();
            let mut key = seed(&store, LaneId::Judge, 1, false);
            if phase == ReadPhase::Receipt {
                store
                    .db
                    .execute(
                        "UPDATE operations SET txid=?1,binding_revision=2 WHERE id=1",
                        ["a".repeat(64)],
                    )
                    .unwrap();
                key = ReadKey::Operation {
                    operation_id: 1,
                    binding_revision: 2,
                    phase,
                };
            }
            store.set_authority_epoch(7).unwrap();
            let at = now();
            let inspect = || {
                store
                    .operation_inspection(&config, &[1], now())
                    .unwrap()
                    .remove(0)
            };
            assert_eq!(
                inspect().reconciliation["last_check_source"],
                "not_recorded"
            );
            assert!(
                store
                    .reconciliation_claim_at_stamped(
                        &config,
                        LaneId::Judge,
                        &key,
                        at,
                        None,
                        Some((7, 1)),
                    )
                    .unwrap()
            );
            assert_eq!(
                inspect().reconciliation["last_check_source"],
                "not_recorded"
            );
            if completed {
                assert!(
                    store
                        .finish_reconciliation_read(&key, 7, 1, Some(404), None, true)
                        .unwrap()
                );
                let checked = inspect();
                assert_eq!(checked.reconciliation["last_status"], 404);
                assert!(
                    checked.reconciliation["last_actual_check_at"]
                        .as_i64()
                        .is_some()
                );
                assert_eq!(
                    checked.reconciliation["last_check_source"],
                    if phase == ReadPhase::Job {
                        "bound_job"
                    } else {
                        "bound_receipt"
                    },
                );
            } else {
                assert!(store.cancel_reconciliation_read(&key, 7, 1).unwrap());
                assert_eq!(
                    inspect().reconciliation["last_check_source"],
                    "not_recorded"
                );
            }
        }
    }
}

fn start_candidates(store: &Store, config: &Config, at: i64) -> Vec<(i64, bool)> {
    let candidates = store
        .reconciliation_selection(config, LaneId::Judge, at)
        .unwrap()
        .into_iter()
        .map(|(id, service)| (id, Some(service)))
        .collect();
    start_claims(store, config, at, candidates)
}

fn start_selected(
    store: &Store,
    config: &Config,
    at: i64,
    candidates: Vec<i64>,
) -> Vec<(i64, bool)> {
    start_claims(
        store,
        config,
        at,
        candidates.into_iter().map(|id| (id, None)).collect(),
    )
}

fn start_claims(
    store: &Store,
    config: &Config,
    at: i64,
    candidates: Vec<(i64, Option<ReconciliationService>)>,
) -> Vec<(i64, bool)> {
    assert!(candidates.len() <= 2);
    let mut started = Vec::new();
    // Keep both reads in flight until the captured batch has been launched,
    // exactly as Recovery::plan does before collecting any completion.
    for (candidate, service) in candidates {
        let op = store.operation(candidate).unwrap().unwrap();
        let key = Store::operation_read_key(&op).unwrap();
        assert!(
            store
                .reconciliation_claim_at(config, LaneId::Judge, &key, at, service)
                .unwrap()
        );
        let missing = store
            .db
            .query_row(
                "SELECT COALESCE(status=404 AND failures>=2,0) FROM read_state
            WHERE operation_id=?1 AND binding_revision=?2 AND retired=0",
                params![op.id, op.binding_revision],
                |row| row.get::<_, bool>(0),
            )
            .unwrap();
        started.push((op.id, missing));
    }
    for (id, missing) in &started {
        let op = store.operation(*id).unwrap().unwrap();
        store
            .read_finished(
                &Store::operation_read_key(&op).unwrap(),
                Some(if *missing { 404 } else { 202 }),
                if *missing { Some("not_found") } else { None },
            )
            .unwrap();
    }
    started
}

#[test]
fn reconciliation_traffic_is_bounded_durable_and_independent_of_discovery() {
    let (_dir, config, mut store) = fixture();
    let tx = store.db.unchecked_transaction().unwrap();
    for id in 1..=2000 {
        seed(&store, LaneId::Judge, id, true);
    }
    seed(&store, LaneId::Judge, 2001, false);
    seed(&store, LaneId::Judge, 2002, false);
    let other = seed(&store, LaneId::Answer, 2003, false);
    tx.commit().unwrap();
    let start = now();
    let mut total = 0;
    let mut missing_times = Vec::new();
    for elapsed in 0..=100 {
        let started = start_candidates(&store, &config, start + elapsed);
        total += started.len();
        for (_, missing) in started {
            if missing {
                missing_times.push(start + elapsed);
            }
        }
        if elapsed == 5 {
            drop(store);
            store = Store::open(&config).unwrap();
            store.recover().unwrap();
            assert!(
                store
                    .reconciliation_candidates(&config, LaneId::Judge, start + elapsed)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .reconciliation_read_started_at(
                        &config,
                        LaneId::Answer,
                        &other,
                        start + elapsed
                    )
                    .unwrap()
            );
            let discovery = ReadKey::Discovery {
                lane: LaneId::Judge,
                source: DiscoverySource::Assignments,
            };
            assert!(store.read_started(&discovery).unwrap());
            store.cancel_read(&discovery).unwrap();
        }
    }
    assert!(total > 2);
    assert!(total <= 2 * (1 + 100 / 11));
    assert!(missing_times.len() >= 2);
    assert!(
        missing_times
            .windows(2)
            .all(|times| times[1] - times[0] >= 51)
    );
    let retained: i64 = store.db.query_row(
        "SELECT COUNT(*) FROM operations WHERE id<=2000 AND state='unknown' AND job_id IS NOT NULL",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(retained, 2000);
}

#[test]
fn reconciliation_fair_cursors_cannot_be_overtaken_by_new_work() {
    let (_dir, mut config, store) = fixture();
    config.capabilities.judge.schedule.backoff_max_seconds = 10;
    for id in 1..=12 {
        seed(&store, LaneId::Judge, id, id > 6);
    }
    let start = now();
    let mut visited = std::collections::HashSet::new();
    for round in 0..30 {
        let newest = 13 + round;
        seed(&store, LaneId::Judge, newest, false);
        let at = start + round * 11;
        let candidates = store
            .reconciliation_candidates(&config, LaneId::Judge, at)
            .unwrap();
        assert_eq!(candidates[0], newest);
        visited.extend(
            start_candidates(&store, &config, at)
                .into_iter()
                .map(|(id, _)| id),
        );
    }
    for id in 1..=12 {
        assert!(visited.contains(&id), "retained operation {id} was starved");
    }
}

#[test]
fn reconciliation_claim_preserves_floors_and_rejects_stale_bindings() {
    let (_dir, config, store) = fixture();
    let key = seed(&store, LaneId::Judge, 1, false);
    let at = now();
    store.db.execute(
        "UPDATE read_state SET server_not_before=?1,retained_conservative_floor=?2 WHERE operation_id=1",
        params![at + 40, at + 60],
    ).unwrap();
    assert!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at + 59)
            .unwrap()
            .is_empty()
    );
    assert!(
        !store
            .reconciliation_read_started_at(&config, LaneId::Judge, &key, at + 59)
            .unwrap()
    );
    assert!(
        store
            .reconciliation_read_started_at(&config, LaneId::Judge, &key, at + 60)
            .unwrap()
    );
    store
        .db
        .execute(
            "UPDATE operations SET txid=?1,state='included_pending',binding_revision=2 WHERE id=1",
            ["a".repeat(64)],
        )
        .unwrap();
    assert!(
        !store
            .reconciliation_read_started_at(&config, LaneId::Judge, &key, at + 100)
            .unwrap()
    );
    store
        .read_finished(&key, Some(404), Some("not_found"))
        .unwrap();
    let current = store.operation(1).unwrap().unwrap();
    let current_key = Store::operation_read_key(&current).unwrap();
    assert_eq!(current.state, "included_pending");
    assert_eq!(store.read_backoff(&current_key).unwrap().failures, 0);
    assert!(
        store
            .reconciliation_read_started_at(&config, LaneId::Judge, &current_key, at + 100)
            .unwrap()
    );
    let old_floor: i64 = store.db.query_row(
        "SELECT retained_conservative_floor FROM read_state WHERE operation_id=1 AND binding_revision=1",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(old_floor, at + 60);
}

#[test]
fn reconciliation_never_polls_identifierless_work_or_resolves_missing_jobs() {
    let (_dir, config, store) = fixture();
    let missing = seed(&store, LaneId::Judge, 1, true);
    seed(&store, LaneId::Judge, 2, false);
    store
        .db
        .execute("UPDATE operations SET job_id=NULL WHERE id=2", [])
        .unwrap();
    assert!(Store::operation_read_key(&store.operation(2).unwrap().unwrap()).is_none());
    let at = now();
    let candidates = store
        .reconciliation_candidates(&config, LaneId::Judge, at)
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0], 1);
    assert!(
        store
            .reconciliation_read_started_at(&config, LaneId::Judge, &missing, at)
            .unwrap()
    );
    store
        .read_finished(&missing, Some(404), Some("not_found"))
        .unwrap();
    assert!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at + 50)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at + 51)
            .unwrap()[0],
        1
    );
    let retained = store.operation(1).unwrap().unwrap();
    assert_eq!(retained.state, "unknown");
    assert_eq!(retained.job_id.as_deref(), Some("job-1"));
    assert_eq!(retained.binding_revision, 1);
}

#[test]
fn reconciliation_services_older_pending_jobs_ahead_of_missing_history() {
    let (_dir, config, store) = fixture();
    let tx = store.db.unchecked_transaction().unwrap();
    for id in 1..=1000 {
        seed(&store, LaneId::Judge, id, true);
    }
    for id in 1001..=1003 {
        seed(&store, LaneId::Judge, id, false);
    }
    tx.commit().unwrap();
    let start = now();
    let mut serviced = std::collections::HashSet::new();
    for round in 0..3 {
        serviced.extend(
            start_candidates(&store, &config, start + round * 11)
                .into_iter()
                .map(|(id, _)| id),
        );
    }
    assert!((1001..=1003).all(|id| serviced.contains(&id)));
}

#[test]
fn reconciliation_uses_queued_poll_cadence_without_refunding_started_slots() {
    let (_dir, mut config, store) = fixture();
    config.capabilities.judge.schedule.queued_job_polling = Some(crate::config::QueuedJobPolling {
        initial_seconds: 2,
        max_seconds: 20,
    });
    seed(&store, LaneId::Judge, 1, false);
    seed(&store, LaneId::Judge, 2, false);
    let at = now();
    assert_eq!(start_candidates(&store, &config, at).len(), 2);
    config
        .capabilities
        .judge
        .schedule
        .queued_job_polling
        .as_mut()
        .unwrap()
        .initial_seconds = 1;
    assert!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at + 2)
            .unwrap()
            .is_empty()
    );
    assert_eq!(start_candidates(&store, &config, at + 3).len(), 2);
    assert!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at + 4)
            .unwrap()
            .is_empty()
    );
    assert_eq!(start_candidates(&store, &config, at + 5).len(), 2);
}

fn measure_sql_work<T>(store: &Store, run: impl FnOnce() -> T) -> (T, u64) {
    use std::cell::Cell;
    unsafe extern "C" fn progress(context: *mut std::ffi::c_void) -> std::ffi::c_int {
        let steps = unsafe { &*context.cast::<Cell<u64>>() };
        steps.set(steps.get() + 100);
        0
    }
    struct ProgressGuard<'a>(&'a Connection);
    impl Drop for ProgressGuard<'_> {
        fn drop(&mut self) {
            unsafe {
                rusqlite::ffi::sqlite3_progress_handler(
                    self.0.handle(),
                    0,
                    None,
                    std::ptr::null_mut(),
                );
            }
        }
    }
    let steps = Cell::new(0_u64);
    let guard = ProgressGuard(&store.db);
    unsafe {
        rusqlite::ffi::sqlite3_progress_handler(
            store.db.handle(),
            100,
            Some(progress),
            (&steps as *const Cell<u64>).cast_mut().cast(),
        );
    }
    let result = run();
    drop(guard);
    (result, steps.get())
}

fn backlog_work(count: i64, missing: bool) -> (u64, u64) {
    let (_dir, config, store) = fixture();
    let at = now();
    let tx = store.db.unchecked_transaction().unwrap();
    for id in 1..=count {
        seed(&store, LaneId::Judge, id, missing);
    }
    if !missing {
        store
            .db
            .execute(
                "UPDATE operations SET next_at=?1 WHERE id%4=0",
                [at + 10_000],
            )
            .unwrap();
        store
            .db
            .execute(
                "UPDATE read_state SET server_not_before=?1 WHERE operation_id%4=1",
                [at + 10_000],
            )
            .unwrap();
        store
            .db
            .execute(
                "UPDATE read_state SET retained_conservative_floor=?1 WHERE operation_id%4=2",
                [at + 10_000],
            )
            .unwrap();
    }
    // Retained resource restrictions must not make every account-scope probe
    // scan unrelated job history, even when no current row can be serviced.
    store.db.execute(
        "INSERT INTO request_restrictions
            (authority,origin,scope,target,basis,not_before,observed_at,request_id,source,read_class,effect_class)
        SELECT ?1,?2,'resource','job:'||job_id,'server_retry_after',?3,0,'fixture','job',1,0
        FROM operations WHERE id%4=3",
        params![
            format!("{}\n{}", config.network.chain, config.network.address),
            reqwest::Url::parse(&config.network.base_url).unwrap().origin().ascii_serialization(),
            if missing { 0 } else { at + 10_000 }
        ],
    ).unwrap();
    tx.commit().unwrap();
    let (candidates, selection_work) = measure_sql_work(&store, || {
        store
            .reconciliation_candidates(&config, LaneId::Judge, at)
            .unwrap()
    });
    assert_eq!(candidates.len(), usize::from(missing));
    let (delay, wake_work) = measure_sql_work(&store, || store.wake_delay(&config, 60).unwrap());
    assert!((1..=10).contains(&delay));
    let cursor = store
        .reconciliation_schedule("reconciliation:judge")
        .unwrap()
        .1;
    assert_eq!(cursor, count - RECONCILIATION_PAGE_SIZE as i64 + 1);
    store
        .reconciliation_candidates(&config, LaneId::Judge, at)
        .unwrap();
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:judge")
            .unwrap()
            .1,
        cursor - RECONCILIATION_PAGE_SIZE as i64,
        "an empty recent page must advance rather than rescan the head"
    );
    seed(&store, LaneId::Judge, count + 1, false);
    let started = start_candidates(&store, &config, at);
    assert_eq!(started[0], (count + 1, false));
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT COUNT(*) FROM operations WHERE state='unknown' AND job_id IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        count + 1
    );
    (selection_work, wake_work)
}

#[test]
fn reconciliation_candidate_and_wake_work_do_not_scale_with_ineligible_history() {
    for missing in [true, false] {
        let small = backlog_work(256, missing);
        let large = backlog_work(8192, missing);
        assert!(
            large.0 <= small.0 * 2 + 1000,
            "selection work grew with retained history: {small:?} -> {large:?}"
        );
        assert!(
            large.1 <= small.1 * 2 + 1000,
            "wake work grew with retained history: {small:?} -> {large:?}"
        );
    }
}

#[test]
fn reconciliation_empty_walks_survive_restart_and_find_sparse_due_work() {
    let (_dir, config, mut store) = fixture();
    let at = now();
    let count = RECONCILIATION_PAGE_SIZE as i64 * 6;
    let tx = store.db.unchecked_transaction().unwrap();
    for id in 1..=count {
        seed(&store, LaneId::Judge, id, id == 2);
    }
    store
        .db
        .execute(
            "UPDATE read_state SET server_not_before=?1 WHERE operation_id>2",
            [at + 10_000],
        )
        .unwrap();
    store
        .db
        .execute(
            "UPDATE read_state SET server_not_before=?1 WHERE operation_id=2",
            [at + 100],
        )
        .unwrap();
    tx.commit().unwrap();
    assert!(start_candidates(&store, &config, at).is_empty());
    let cursors = [
        "reconciliation:judge",
        "reconciliation:fair:judge",
        "reconciliation:missing:judge",
    ]
    .map(|name| store.reconciliation_schedule(name).unwrap().1);
    assert_eq!(cursors, [count - RECONCILIATION_PAGE_SIZE as i64 + 1; 3]);
    drop(store);
    store = Store::open(&config).unwrap();
    store.recover().unwrap();
    for (index, name) in [
        "reconciliation:judge",
        "reconciliation:fair:judge",
        "reconciliation:missing:judge",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            store.reconciliation_schedule(name).unwrap().1,
            cursors[index]
        );
    }
    let mut ordinary_seen = false;
    let mut missing_times = Vec::new();
    for round in 1..=24 {
        let newest = count + round;
        seed(&store, LaneId::Judge, newest, false);
        let time = at + round * 11;
        let started = start_candidates(&store, &config, time);
        assert!(started.contains(&(newest, false)));
        for (id, missing) in started {
            assert!(id <= 2 || id > count, "a future server floor was bypassed");
            ordinary_seen |= id == 1;
            if missing {
                assert_eq!(id, 2);
                assert!(time >= at + 100);
                missing_times.push(time);
            }
        }
    }
    assert!(ordinary_seen, "fresh arrivals starved older eligible work");
    assert!(!missing_times.is_empty(), "sparse missing work was starved");
    assert!(
        missing_times
            .windows(2)
            .all(|times| times[1] - times[0] >= 51)
    );
}

#[test]
fn reconciliation_captured_entry_batch_survives_later_cursor_advancement() {
    let (_dir, config, store) = fixture();
    for id in 1..=4 {
        seed(&store, LaneId::Judge, id, false);
    }
    let at = now();
    let entry = store
        .reconciliation_candidates(&config, LaneId::Judge, at)
        .unwrap();
    assert_eq!(entry, vec![4, 3]);
    seed(&store, LaneId::Judge, 5, false);
    assert_eq!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at)
            .unwrap()[0],
        5
    );
    assert_eq!(
        start_selected(&store, &config, at, entry),
        vec![(4, false), (3, false)]
    );
    assert!(
        store
            .reconciliation_candidates(&config, LaneId::Judge, at)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reconciliation_wake_keeps_lane_cadence_slots_and_discovery_independent() {
    let (_dir, mut config, store) = fixture();
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Off;
    let at = 1_000_000;
    seed(&store, LaneId::Judge, 1, true);
    store
        .db
        .execute(
            "UPDATE read_state SET server_not_before=?1 WHERE operation_id=1",
            [at + 1000],
        )
        .unwrap();
    assert_eq!(store.wake_delay_at(&config, 60, at).unwrap(), 10);
    store
        .db
        .execute(
            "INSERT INTO schedule(kind,next_at) VALUES('reconciliation:fair:judge',?1)",
            [at + 4],
        )
        .unwrap();
    assert_eq!(store.wake_delay_at(&config, 60, at).unwrap(), 4);
    config.capabilities.judge.mode = Mode::Active;
    let discovery = ReadKey::Discovery {
        lane: LaneId::Judge,
        source: DiscoverySource::Assignments,
    };
    assert!(store.ensure_read_row(&discovery).unwrap());
    store
        .db
        .execute(
            "UPDATE read_state SET local_next_at=?1 WHERE owner='judge' AND purpose='discovery'",
            [at + 2],
        )
        .unwrap();
    assert_eq!(store.wake_delay_at(&config, 60, at).unwrap(), 2);
    assert_eq!(store.wake_delay_at(&config, 1, at).unwrap(), 1);
}

#[test]
fn reconciliation_recent_pending_work_keeps_service_while_ordinary_walk_advances() {
    let (_dir, config, store) = fixture();
    let count = RECONCILIATION_PAGE_SIZE as i64 * 4;
    let tx = store.db.unchecked_transaction().unwrap();
    for id in 1..=count {
        seed(&store, LaneId::Judge, id, false);
    }
    tx.commit().unwrap();
    let at = now();
    for round in 0..3 {
        let started = start_candidates(&store, &config, at + round * 11);
        assert_eq!(started, vec![(count, false), (count - round - 1, false)]);
    }
}

#[test]
fn reconciliation_selection_retains_unclaimed_candidates_across_restart() {
    let (_dir, config, mut store) = fixture();
    for id in 1..=5 {
        seed(&store, LaneId::Judge, id, id <= 2);
    }
    let at = now();
    let selected = store
        .reconciliation_selection(&config, LaneId::Judge, at)
        .unwrap();
    assert_eq!(
        selected,
        vec![
            (5, ReconciliationService::Recent),
            (2, ReconciliationService::Missing),
        ]
    );
    let cursors = ["reconciliation:fair:judge", "reconciliation:missing:judge"]
        .map(|name| store.reconciliation_schedule(name).unwrap());
    for _ in 0..4 {
        assert_eq!(
            store
                .reconciliation_selection(&config, LaneId::Judge, at)
                .unwrap(),
            selected
        );
        assert_eq!(
            ["reconciliation:fair:judge", "reconciliation:missing:judge"]
                .map(|name| store.reconciliation_schedule(name).unwrap()),
            cursors
        );
    }
    drop(store);
    store = Store::open(&config).unwrap();
    store.recover().unwrap();
    assert_eq!(
        store
            .reconciliation_selection(&config, LaneId::Judge, at)
            .unwrap(),
        selected
    );
    assert_eq!(
        start_candidates(&store, &config, at),
        vec![(5, false), (2, true)]
    );
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:fair:judge")
            .unwrap(),
        (at + 11, 5, true)
    );
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:missing:judge")
            .unwrap(),
        (at + 51, 2, false)
    );
}

#[test]
fn reconciliation_failed_claim_preserves_cursor_and_service_until_actual_claim() {
    let (_dir, config, mut store) = fixture();
    seed(&store, LaneId::Judge, 1, true);
    let ordinary = seed(&store, LaneId::Judge, 2, false);
    let recent = seed(&store, LaneId::Judge, 3, false);
    let at = now();
    // Missing is not due yet, so the second selected candidate is ordinary.
    store
        .db
        .execute(
            "INSERT INTO schedule(kind,next_at) VALUES('reconciliation:missing:judge',?1)",
            [at + 50],
        )
        .unwrap();
    assert_eq!(
        store
            .reconciliation_selection(&config, LaneId::Judge, at)
            .unwrap(),
        vec![
            (3, ReconciliationService::Recent),
            (2, ReconciliationService::Fair)
        ]
    );
    assert!(
        store
            .reconciliation_claim_at(
                &config,
                LaneId::Judge,
                &recent,
                at,
                Some(ReconciliationService::Recent)
            )
            .unwrap()
    );
    // A concurrent reservation wins after selection, before Recovery can claim.
    assert!(store.read_started(&ordinary).unwrap());
    let fair = store
        .reconciliation_schedule("reconciliation:fair:judge")
        .unwrap();
    assert!(
        !store
            .reconciliation_claim_at(
                &config,
                LaneId::Judge,
                &ordinary,
                at,
                Some(ReconciliationService::Fair)
            )
            .unwrap()
    );
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:fair:judge")
            .unwrap(),
        fair
    );
    store.cancel_read(&ordinary).unwrap();
    store.cancel_read(&recent).unwrap();
    drop(store);
    store = Store::open(&config).unwrap();
    store.recover().unwrap();
    seed(&store, LaneId::Judge, 4, false);
    assert_eq!(
        store
            .reconciliation_selection(&config, LaneId::Judge, at + 11)
            .unwrap(),
        vec![
            (2, ReconciliationService::Fair),
            (4, ReconciliationService::Recent)
        ]
    );
    assert!(
        store
            .reconciliation_claim_at(
                &config,
                LaneId::Judge,
                &ordinary,
                at + 11,
                Some(ReconciliationService::Fair)
            )
            .unwrap()
    );
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:fair:judge")
            .unwrap(),
        (at + 22, 2, false)
    );
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:judge")
            .unwrap()
            .0,
        at + 11,
        "a fair claim must not spend the recent service floor"
    );
    assert_eq!(
        store
            .reconciliation_schedule("reconciliation:missing:judge")
            .unwrap()
            .0,
        at + 50
    );
    store.cancel_read(&ordinary).unwrap();
    drop(store);
    store = Store::open(&config).unwrap();
    store.recover().unwrap();
    assert!(
        !store
            .reconciliation_claim_at(
                &config,
                LaneId::Judge,
                &ordinary,
                at + 21,
                Some(ReconciliationService::Fair)
            )
            .unwrap()
    );
    let missing = Store::operation_read_key(&store.operation(1).unwrap().unwrap()).unwrap();
    assert!(
        !store
            .reconciliation_claim_at(
                &config,
                LaneId::Judge,
                &missing,
                at + 49,
                Some(ReconciliationService::Missing)
            )
            .unwrap()
    );
}

#[test]
fn discovery_refresh_clamps_only_successful_cadence_and_preserves_durable_floors() {
    let (_dir, mut config, mut store) = fixture();
    config.capabilities.judge.schedule.poll_seconds = 120;
    config.capabilities.judge.schedule.jitter_seconds = 30;
    config
        .capabilities
        .judge
        .schedule
        .observation_max_age_seconds = 120;
    let key = ReadKey::Discovery {
        lane: LaneId::Judge,
        source: DiscoverySource::Assignments,
    };
    store.reset_read(&key).unwrap();
    let at = 1_000_000;
    store.defer_until(LaneId::Judge, at + 150).unwrap();
    store
        .db
        .execute(
            "UPDATE read_state SET last_success_at=?1 WHERE owner='judge' AND purpose='discovery'",
            [at],
        )
        .unwrap();
    let next = |store: &Store| {
        store
            .discovery_next_at(&config, LaneId::Judge, &store.read_backoff(&key).unwrap())
            .unwrap()
    };
    assert_eq!(next(&store), at + 61);
    store.db.execute(
        "UPDATE read_state SET local_next_at=?1,server_not_before=?2,retained_conservative_floor=?3
        WHERE owner='judge' AND purpose='discovery'",
        params![at + 70, at + 80, at + 90],
    ).unwrap();
    assert_eq!(next(&store), at + 90);
    drop(store);
    store = Store::open(&config).unwrap();
    store.recover().unwrap();
    store.reschedule_all_reads(&config).unwrap();
    assert_eq!(next(&store), at + 90);
    store
        .db
        .execute(
            "UPDATE read_state SET failures=1,local_next_at=?1
        WHERE owner='judge' AND purpose='discovery'",
            [at + 200],
        )
        .unwrap();
    assert_eq!(next(&store), at + 200);
    let success: i64 = store
        .db
        .query_row(
            "SELECT last_success_at FROM read_state WHERE owner='judge' AND purpose='discovery'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        success, at,
        "a timing calculation must not renew observation evidence"
    );
}

#[test]
fn reconciliation_streak_requires_consecutive_complete_fenced_responses() {
    let (_dir, config, store) = fixture();
    let key = seed(&store, LaneId::Judge, 1, false);
    store.set_authority_epoch(7).unwrap();
    let at = now();
    let claim = |sequence, at| {
        store
            .db
            .execute(
                "DELETE FROM schedule WHERE kind LIKE 'reconciliation:%'",
                [],
            )
            .unwrap();
        assert!(
            store
                .reconciliation_claim_at_stamped(
                    &config,
                    LaneId::Judge,
                    &key,
                    at,
                    None,
                    Some((7, sequence))
                )
                .unwrap()
        );
    };
    let count = || {
        store
            .reconciliation_provenance(1, 1)
            .unwrap()
            .unwrap()
            .consecutive_404
    };
    claim(1, at);
    assert!(
        store
            .finish_reconciliation_read(&key, 7, 1, Some(404), Some("not_found"), true)
            .unwrap()
    );
    assert_eq!(count(), 1);
    claim(2, at + 1);
    assert!(
        !store
            .finish_reconciliation_read(&key, 7, 1, Some(202), None, true)
            .unwrap()
    );
    assert!(!store.cancel_reconciliation_read(&key, 7, 1).unwrap());
    store
        .read_finished(&key, Some(404), Some("not_found"))
        .unwrap();
    assert!(
        store.has_stamped_operation_read(&key).unwrap(),
        "legacy completion cannot consume a tracked flight"
    );
    assert!(
        store
            .finish_reconciliation_read(&key, 7, 2, Some(404), None, true)
            .unwrap()
    );
    assert_eq!(count(), 2);
    assert!(
        !store
            .finish_reconciliation_read(&key, 7, 2, Some(202), None, true)
            .unwrap()
    );
    assert_eq!(count(), 2);
    for (sequence, status, complete, category) in [
        (3, Some(202), true, None),
        (4, Some(404), false, None),
        (5, Some(404), true, Some("malformed_json")),
        (6, None, false, Some("transport")),
    ] {
        claim(sequence, at + sequence as i64);
        store
            .finish_reconciliation_read(&key, 7, sequence, status, category, complete)
            .unwrap();
        assert_eq!(count(), 0);
    }
    claim(7, at + 7);
    store
        .finish_reconciliation_read(&key, 7, 7, Some(404), None, true)
        .unwrap();
    claim(8, at + 8);
    store.cancel_reconciliation_read(&key, 7, 8).unwrap();
    assert_eq!(count(), 0);
    claim(9, at + 9);
    store.set_authority_epoch(8).unwrap();
    assert!(
        !store
            .finish_reconciliation_read(&key, 7, 9, Some(404), None, true)
            .unwrap()
    );
    assert!(!store.cancel_reconciliation_read(&key, 7, 9).unwrap());
    assert_eq!(count(), 0, "superseded authority never contributes a miss");
    let p = store.reconciliation_provenance(1, 1).unwrap().unwrap();
    assert_eq!(p.bound_since, None);
    assert_eq!(
        p.first_observed_at, at,
        "legacy binding age starts only on upgraded observation"
    );
}

#[test]
fn operation_flights_fence_receipt_and_job_stale_completion_cancellation_and_authority() {
    for phase in [ReadPhase::Job, ReadPhase::Receipt] {
        let (_dir, config, store) = fixture();
        seed(&store, LaneId::Judge, 1, false);
        if phase == ReadPhase::Receipt {
            store
                .db
                .execute(
                    "UPDATE operations SET txid='receipt-binding' WHERE id=1",
                    [],
                )
                .unwrap();
            store
                .db
                .execute("DELETE FROM read_state WHERE operation_id=1", [])
                .unwrap();
        }
        let key = ReadKey::Operation {
            operation_id: 1,
            binding_revision: 1,
            phase,
        };
        store.set_authority_epoch(7).unwrap();
        let at = now();
        let claim = |epoch, sequence, offset| {
            assert!(
                store
                    .reconciliation_claim_at_stamped(
                        &config,
                        LaneId::Judge,
                        &key,
                        at + offset,
                        None,
                        Some((epoch, sequence)),
                    )
                    .unwrap(),
                "{phase:?}: claim {epoch}/{sequence}"
            );
        };
        let in_flight = || {
            store
                .db
                .query_row(
                    "SELECT in_flight FROM read_state WHERE operation_id=1 AND retired=0",
                    [],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap()
        };
        let evidence = || {
            store
                .db
                .query_row(
                    "SELECT json_array(r.started_at,r.finished_at,r.status,r.failure_category,
                r.failures,r.local_next_at,r.server_not_before,r.retained_conservative_floor,
                r.last_http_success_at,r.last_success_at,o.state,o.next_at,o.binding_revision)
             FROM read_state r JOIN operations o ON o.id=r.operation_id
             WHERE r.operation_id=1 AND r.retired=0",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
        };
        claim(7, 1, 0);
        assert!(store.cancel_reconciliation_read(&key, 7, 1).unwrap());
        claim(7, 2, 100_000);
        let b = evidence();
        assert!(
            !store
                .finish_reconciliation_read(&key, 7, 1, Some(401), Some("unauthorized"), true)
                .unwrap()
        );
        assert!(!store.cancel_reconciliation_read(&key, 7, 1).unwrap());
        store
            .read_finished(&key, Some(401), Some("unauthorized"))
            .unwrap();
        store.cancel_read(&key).unwrap();
        assert!(in_flight(), "{phase:?}: stale A cannot consume B");
        assert_eq!(
            evidence(),
            b,
            "{phase:?}: stale A cannot change B evidence or floors"
        );
        assert!(
            store
                .finish_reconciliation_read(&key, 7, 2, Some(404), None, true)
                .unwrap()
        );
        let completed = evidence();
        assert!(
            !store
                .finish_reconciliation_read(&key, 7, 2, Some(202), None, true)
                .unwrap()
        );
        assert!(!store.cancel_reconciliation_read(&key, 7, 2).unwrap());
        assert_eq!(
            evidence(),
            completed,
            "{phase:?}: completion is consumed once"
        );

        claim(7, 3, 200_000);
        store.set_authority_epoch(8).unwrap();
        let obsolete = evidence();
        assert!(
            !store
                .finish_reconciliation_read(&key, 7, 3, Some(401), Some("unauthorized"), true)
                .unwrap()
        );
        assert!(
            !in_flight(),
            "{phase:?}: obsolete matching flight is retired, not wedged"
        );
        assert_eq!(
            evidence(),
            obsolete,
            "{phase:?}: old authority supplies no response evidence"
        );
        assert!(
            !store
                .reconciliation_claim_at_stamped(
                    &config,
                    LaneId::Judge,
                    &key,
                    at + 300_000,
                    None,
                    Some((7, 4)),
                )
                .unwrap()
        );
        claim(8, 4, 300_000);
        store.set_authority_epoch(9).unwrap();
        let obsolete = evidence();
        assert!(!store.cancel_reconciliation_read(&key, 8, 4).unwrap());
        assert!(
            !in_flight(),
            "{phase:?}: cancellation also retires obsolete matching flight"
        );
        assert_eq!(evidence(), obsolete);
        claim(9, 5, 400_000);
        let current = evidence();
        assert!(!store.cancel_reconciliation_read(&key, 8, 4).unwrap());
        assert!(
            !store
                .finish_reconciliation_read(&key, 7, 3, Some(401), None, true)
                .unwrap()
        );
        assert!(in_flight());
        assert_eq!(
            evidence(),
            current,
            "{phase:?}: retirement cannot clear a newer flight"
        );
        assert!(
            store
                .finish_reconciliation_read(&key, 9, 5, Some(202), None, true)
                .unwrap()
        );
        let p = store.reconciliation_provenance(1, 1).unwrap().unwrap();
        assert_eq!(p.active_request_sequence, None);
        assert_eq!(p.consecutive_404, 0);
        assert_eq!(p.bound_since, None);
        assert_eq!(
            p.first_observed_at, at,
            "authority changes preserve the actual first observation"
        );
        if phase == ReadPhase::Receipt {
            assert_eq!(
                p.last_status, None,
                "receipt status is not job-404 evidence"
            );
            let inspection = store
                .operation_inspection(&config, &[1], at + 400_000)
                .unwrap();
            assert_eq!(
                inspection[0].reconciliation["binding_age_source"],
                "first_observed_binding"
            );
            assert_eq!(inspection[0].reconciliation["binding_age_seconds"], 400_000);
            assert!(
                store
                    .reconciliation_decay_binding_at(1, at + 400_000)
                    .unwrap()
                    .is_none()
            );
        }
    }
}

fn mine_relevance_fixture() -> (tempfile::TempDir, Config, Store, ReadKey, i64) {
    let (dir, mut config, store) = fixture();
    config.capabilities.mine.mode = Mode::Active;
    config.capabilities.mine.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .mine
        .participation
        .uncertainty_grace_seconds = 0;
    config
        .capabilities
        .mine
        .participation
        .max_unresolved_operations = CountLimit::Unbounded;
    store.db.execute("UPDATE control SET paused=0", []).unwrap();
    store.set_authority_epoch(1).unwrap();
    store.runtime_state(&config, false).unwrap();
    let at = now();
    let key = seed(&store, LaneId::Mine, 1, true);
    store.db.execute("UPDATE operations SET request='{\"solver\":{\"kind\":\"mine\",\"epoch\":9}}' WHERE id=1",[]).unwrap();
    refresh_mine_observation(&store, &config, 10, 1, at);
    (dir, config, store, key, at)
}

#[test]
fn historical_missing_decay_is_revision_aged_dynamic_and_never_a_persisted_floor() {
    let (_dir, config, store, key, at) = mine_relevance_fixture();
    let mut p = store.binding_provenance_at(1, 1, at).unwrap();
    p.bound_since = Some(at - 86_400 + 1);
    p.first_observed_at = at - 86_400 + 1;
    p.consecutive_404 = 2;
    p.observer_authority_epoch = Some(1);
    p.last_status = Some(404);
    p.last_result_at = Some(at - 100);
    store.save_reconciliation_provenance(1, &p).unwrap();
    store
        .db
        .execute(
            "UPDATE read_state SET started_at=?1,finished_at=?1 WHERE operation_id=1",
            [at - 100],
        )
        .unwrap();
    let accounting = accounting::AccountingReadSnapshot::load(&store.db, &config).unwrap();
    let context = store
        .remote_work_context(&config, LaneId::Mine, at, &accounting)
        .unwrap();
    assert_eq!(
        context.nonblocking("unknown", Some(9), "work-1"),
        Some(true)
    );
    assert_eq!(
        store.reconciliation_decay_at(1, &context, at).unwrap(),
        None
    );
    p.bound_since = Some(at - 86_400);
    store.save_reconciliation_provenance(1, &p).unwrap();
    let (due, cadence) = store
        .reconciliation_decay_at(1, &context, at)
        .unwrap()
        .unwrap();
    assert_eq!(cadence, 21_600);
    assert!((at - 100 + 21_600..=at - 100 + 21_600 + 300).contains(&due));
    assert!(
        store
            .reconciliation_selection(&config, LaneId::Mine, at)
            .unwrap()
            .is_empty()
    );
    assert!(
        !store
            .reconciliation_claim_at_stamped(&config, LaneId::Mine, &key, at, None, Some((1, 2)))
            .unwrap()
    );
    store.db.execute("UPDATE operations SET request='{\"solver\":{\"kind\":\"mine\",\"epoch\":10}}' WHERE id=1",[]).unwrap();
    assert_eq!(
        store.reconciliation_decay_at(1, &context, at).unwrap(),
        None,
        "same epoch is not historical"
    );
    assert!(
        store
            .reconciliation_claim_at_stamped(&config, LaneId::Mine, &key, at, None, Some((1, 2)))
            .unwrap()
    );
    store.cancel_reconciliation_read(&key, 1, 2).unwrap();
    assert_eq!(
        store.read_backoff(&key).unwrap().next_at,
        0,
        "dynamic decay never becomes generic backoff"
    );
    store.db.execute("UPDATE operations SET request='{\"solver\":{\"kind\":\"mine\",\"epoch\":11}}' WHERE id=1",[]).unwrap();
    assert_eq!(
        store.reconciliation_decay_at(1, &context, at).unwrap(),
        None,
        "future work is not historical"
    );
    store
        .db
        .execute("UPDATE operations SET binding_revision=2 WHERE id=1", [])
        .unwrap();
    let new = store.binding_provenance_at(1, 2, at).unwrap();
    assert_eq!(new.bound_since, None);
    assert_eq!(new.first_observed_at, at);
    assert_eq!(new.consecutive_404, 0);
}

#[test]
fn mining_inspection_retains_valid_producer_counts_without_settling_uncertainty() {
    use crate::protocol::{Response, ResponseSource, response_evidence};
    let (_dir, config, store) = fixture();
    for (id, count, source) in [
        (1, 0, ResponseSource::Submit),
        (2, 37, ResponseSource::BoundJob),
        (3, 0, ResponseSource::BoundJob),
        (4, 37, ResponseSource::Submit),
    ] {
        seed(&store, LaneId::Mine, id, false);
        let mut body = json!({"ok":true,"attested":count});
        if source == ResponseSource::BoundJob {
            body["state"] = json!("done");
        }
        let response = Response {
            status: 200,
            body,
            retry_after_seconds: None,
            read_failure: None,
        };
        let evidence =
            serde_json::to_value(response_evidence(LaneId::Mine, source, Some(&response))).unwrap();
        store.record_evidence(id, &evidence).unwrap();
        let row = store
            .operation_inspection(&config, &[id], now())
            .unwrap()
            .remove(0);
        assert_eq!(row.mining["attested"], count);
        assert_eq!(
            store.operation(id).unwrap().unwrap().state,
            "unknown",
            "diagnostic-before-transition crash is still uncertain"
        );
        for (field, value) in [
            ("stage", json!("receipt")),
            ("route", json!("judge")),
            ("status", json!(404)),
            ("reason", json!("queued")),
        ] {
            let mut bad = evidence.clone();
            bad[field] = value;
            store.record_evidence(id, &bad).unwrap();
            assert_eq!(
                store.operation_inspection(&config, &[id], now()).unwrap()[0].mining["status"],
                "not_recorded"
            );
        }
        let mut legacy = evidence;
        legacy.as_object_mut().unwrap().remove("mining");
        store.record_evidence(id, &legacy).unwrap();
        assert_eq!(
            store.operation_inspection(&config, &[id], now()).unwrap()[0].mining["status"],
            "not_recorded"
        );
    }
    let public = serde_json::to_string(
        &store
            .operation_inspection(&config, &[1, 2, 3, 4], now())
            .unwrap(),
    )
    .unwrap();
    assert!(!public.contains("job-"));
    assert!(!public.contains("work-"));
    assert!(!public.contains("earnings"));
}

#[test]
fn rebound_and_restarted_observers_cannot_inherit_missing_continuity() {
    let (_dir, config, store) = fixture();
    let old = seed(&store, LaneId::Judge, 1, false);
    let at = now();
    store.set_authority_epoch(1).unwrap();
    assert!(
        store
            .reconciliation_claim_at_stamped(&config, LaneId::Judge, &old, at, None, Some((1, 1)))
            .unwrap()
    );
    store
        .db
        .execute(
            "UPDATE operations SET binding_revision=2,job_id='replacement-job' WHERE id=1",
            [],
        )
        .unwrap();
    let new = ReadKey::Operation {
        operation_id: 1,
        binding_revision: 2,
        phase: ReadPhase::Job,
    };
    store
        .db
        .execute(
            "DELETE FROM schedule WHERE kind LIKE 'reconciliation:%'",
            [],
        )
        .unwrap();
    assert!(
        store
            .reconciliation_claim_at_stamped(&config, LaneId::Judge, &new, at, None, Some((1, 2)))
            .unwrap()
    );
    assert!(
        !store
            .finish_reconciliation_read(&old, 1, 1, Some(404), None, true)
            .unwrap()
    );
    assert_eq!(
        store
            .reconciliation_provenance(1, 2)
            .unwrap()
            .unwrap()
            .active_request_sequence,
        Some(2)
    );
    store
        .finish_reconciliation_read(&new, 1, 2, Some(404), None, true)
        .unwrap();
    let mut p = store.reconciliation_provenance(1, 2).unwrap().unwrap();
    p.bound_since = Some(at - 2 * 86_400);
    p.first_observed_at = at - 2 * 86_400;
    p.consecutive_404 = 2;
    store.save_reconciliation_provenance(1, &p).unwrap();
    store.set_authority_epoch(2).unwrap();
    store
        .db
        .execute(
            "DELETE FROM schedule WHERE kind LIKE 'reconciliation:%'",
            [],
        )
        .unwrap();
    assert!(
        store
            .reconciliation_claim_at_stamped(&config, LaneId::Judge, &new, at, None, Some((2, 3)))
            .unwrap()
    );
    let p = store.reconciliation_provenance(1, 2).unwrap().unwrap();
    assert_eq!(
        p.bound_since,
        Some(at - 2 * 86_400),
        "authority rollover preserves revision age"
    );
    assert_eq!(p.consecutive_404, 0);
    store
        .finish_reconciliation_read(&new, 2, 3, Some(404), None, true)
        .unwrap();
    assert_eq!(
        store
            .reconciliation_provenance(1, 2)
            .unwrap()
            .unwrap()
            .consecutive_404,
        1
    );
}

fn aged_missing_provenance(store: &Store, id: i64, at: i64) {
    let mut p = store.binding_provenance_at(id, 1, at).unwrap();
    p.bound_since = Some(at - 86_400);
    p.first_observed_at = at - 86_400;
    p.consecutive_404 = 2;
    p.last_status = Some(404);
    p.last_result_at = Some(at - 100);
    p.observer_authority_epoch = Some(1);
    store.save_reconciliation_provenance(id, &p).unwrap();
    store
        .db
        .execute(
            "UPDATE read_state SET started_at=?2,finished_at=?2 WHERE operation_id=?1",
            params![id, at - 100],
        )
        .unwrap();
}

#[test]
fn decay_pass_is_lazy_and_drops_only_extra_gate_on_current_evidence_change() {
    let (_dir, config, store, key, at) = mine_relevance_fixture();
    aged_missing_provenance(&store, 1, at);
    let mut pass = ReconciliationPass::default();
    assert!(
        store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut pass)
            .unwrap()
    );
    assert!(
        pass.finite_totals.is_none(),
        "unbounded admission never materializes retained history"
    );
    refresh_mine_observation(&store, &config, 11, 2, at);
    assert!(
        !store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut pass)
            .unwrap()
    );
    assert!(
        pass.invalidated,
        "source rollover invalidates rather than rescans a captured pass"
    );
    let mut pass = ReconciliationPass::default();
    assert!(
        store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut pass)
            .unwrap()
    );
    store
        .db
        .execute("UPDATE control SET work_revision=work_revision+1", [])
        .unwrap();
    assert!(
        !store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut pass)
            .unwrap()
    );
    assert!(pass.invalidated);
    let mut pass = ReconciliationPass::default();
    store
        .db
        .execute(
            "UPDATE read_state SET server_not_before=?1 WHERE operation_id=1",
            [at + 600],
        )
        .unwrap();
    assert!(
        !store
            .reconciliation_claim_with_pass(
                &config,
                LaneId::Mine,
                &key,
                ReconciliationClaim {
                    at,
                    service: None,
                    flight: Some((1, 2)),
                },
                &mut pass
            )
            .unwrap()
    );
    assert_eq!(
        store.read_backoff(&key).unwrap().next_at,
        at + 600,
        "staleness never removes existing floors"
    );
    assert!(
        pass.lanes.iter().all(Option::is_none),
        "source floors are checked before optional relevance"
    );
}

#[test]
fn enabled_unbounded_decay_page_work_does_not_scale_with_historical_backlog() {
    let work = |count: i64| {
        let (_dir, config, store, _key, at) = mine_relevance_fixture();
        aged_missing_provenance(&store, 1, at);
        let tx = store.db.unchecked_transaction().unwrap();
        tx.execute("WITH RECURSIVE ids(n) AS (SELECT 2 UNION ALL SELECT n+1 FROM ids WHERE n<?1)
            INSERT INTO operations(id,kind,work_key,state,request,job_id,generation,revision,created_at,updated_at,binding_revision)
            SELECT n,'mine','old-'||n,'unknown','{\"solver\":{\"kind\":\"mine\",\"epoch\":9}}','job-'||n,0,'test',0,0,1 FROM ids",
            [count]).unwrap();
        tx.execute("INSERT INTO operation_evidence(operation_id,policy) SELECT id,(SELECT policy FROM operation_evidence WHERE operation_id=1) FROM operations WHERE id>1",[]).unwrap();
        tx.execute("INSERT INTO read_state(owner,purpose,resource,operation_id,binding_revision,remote_resource,failures,status,started_at,finished_at)
            SELECT 'mine','job',id||':1',id,1,job_id,2,404,?1,?1 FROM operations WHERE id>1",[at-100]).unwrap();
        tx.commit().unwrap();
        let mut pass = ReconciliationPass::default();
        let (rows, steps) = measure_sql_work(&store, || {
            store
                .reconciliation_selection_in(&config, LaneId::Mine, at, &mut pass)
                .unwrap()
        });
        assert!(rows.is_empty());
        assert!(
            pass.lanes.iter().any(Option::is_some),
            "the measured walk actually evaluates enabled decay"
        );
        assert!(pass.finite_totals.is_none());
        steps
    };
    let small = work(256);
    let large = work(8192);
    assert!(
        large <= small * 2 + 1000,
        "enabled decay grew with history: {small} -> {large}"
    );
}

#[test]
fn legacy_binding_age_is_a_lower_bound_and_seven_day_cadence_is_exact() {
    let (_dir, config, store, _key, at) = mine_relevance_fixture();
    aged_missing_provenance(&store, 1, at);
    let mut p = store.reconciliation_provenance(1, 1).unwrap().unwrap();
    p.bound_since = None;
    p.first_observed_at = at - 86_400 + 1;
    store.save_reconciliation_provenance(1, &p).unwrap();
    let accounting = accounting::AccountingReadSnapshot::load(&store.db, &config).unwrap();
    let context = store
        .remote_work_context(&config, LaneId::Mine, at, &accounting)
        .unwrap();
    assert!(
        store
            .reconciliation_decay_at(1, &context, at)
            .unwrap()
            .is_none()
    );
    p.first_observed_at = at - 86_400;
    store.save_reconciliation_provenance(1, &p).unwrap();
    assert_eq!(
        store
            .reconciliation_decay_at(1, &context, at)
            .unwrap()
            .unwrap()
            .1,
        21_600
    );
    p.first_observed_at = at - 7 * 86_400;
    store.save_reconciliation_provenance(1, &p).unwrap();
    assert_eq!(
        store
            .reconciliation_decay_at(1, &context, at)
            .unwrap()
            .unwrap()
            .1,
        86_400
    );
    let row = store
        .operation_inspection(&config, &[1], at)
        .unwrap()
        .remove(0);
    assert_eq!(
        row.reconciliation["binding_age_source"],
        "first_observed_binding"
    );
    assert_eq!(row.reconciliation["binding_age_seconds"], 7 * 86_400);
}

#[test]
fn decayed_history_walk_keeps_fresh_arrivals_and_eventually_services_older_due_job() {
    let (_dir, mut config, store, _key, at) = mine_relevance_fixture();
    config
        .capabilities
        .mine
        .schedule
        .observation_max_age_seconds = 86_400;
    store.runtime_state(&config, false).unwrap();
    refresh_mine_observation(&store, &config, 10, 2, at);
    for id in 2..=130 {
        seed(&store, LaneId::Mine, id, true);
        store.db.execute("UPDATE operations SET request='{\"solver\":{\"kind\":\"mine\",\"epoch\":9}}' WHERE id=?1",[id]).unwrap();
        aged_missing_provenance(&store, id, at);
    }
    let mut served_old = false;
    for round in 0..5 {
        let fresh = 200 + round;
        seed(&store, LaneId::Mine, fresh, false);
        let mut pass = ReconciliationPass::default();
        let selected = store
            .reconciliation_selection_in(&config, LaneId::Mine, at, &mut pass)
            .unwrap();
        assert!(selected.len() <= 2);
        assert!(
            selected
                .iter()
                .any(|(id, service)| *id == fresh && *service == ReconciliationService::Recent)
        );
        if selected
            .iter()
            .any(|(id, service)| *id == 1 && *service == ReconciliationService::Missing)
        {
            served_old = true;
            break;
        }
    }
    assert!(
        served_old,
        "bounded ineligible pages advance despite continuously arriving fresh jobs"
    );
}

#[test]
fn judge_history_requires_complete_positive_inventory_absence() {
    let (_dir, mut config, store) = fixture();
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.judge.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .judge
        .participation
        .max_unresolved_operations = CountLimit::Unbounded;
    store.set_authority_epoch(1).unwrap();
    store.runtime_state(&config, false).unwrap();
    let at = now();
    let stamp = AdmissionStampSnapshot {
        account_generation: store.control().unwrap().generation,
        lane_control_revision: 0,
        authority_epoch: 1,
        lane_config_revision: config.lane_revision(LaneId::Judge).unwrap(),
    };
    let assessment = json!({"observed_at":at,"valid_until":at+120,"completeness":"complete",
        "observed_opportunities":0,"eligible_candidates":0,"exclusions":{},"locally_judgeable":false,
        "excluded_work":[],"excluded_work_truncated":false});
    let set = |assessment: Value| {
        store
            .db
            .execute(
                "UPDATE runtime_state SET lane_participation=?1",
                [json!({"judge":{"stamp":stamp,"assessment":assessment}}).to_string()],
            )
            .unwrap();
    };
    set(assessment.clone());
    let current = || {
        store
            .remote_observation_context(&config, LaneId::Judge, at, true)
            .unwrap()
    };
    assert!(current().historical(None, "known-private-key"));
    let mut partial = assessment.clone();
    partial["excluded_work_truncated"] = json!(true);
    set(partial);
    assert!(!current().historical(None, "known-private-key"));
    let mut present = assessment.clone();
    present["observed_opportunities"] = json!(1);
    present["exclusions"] = json!({"already_attempted":1});
    present["excluded_work"] =
        json!([{"work_key":"known-private-key","reason":"already_attempted"}]);
    set(present);
    assert!(!current().historical(None, "known-private-key"));
    let mut stale = assessment;
    stale["valid_until"] = json!(at);
    set(stale);
    assert!(!current().historical(None, "known-private-key"));
}

#[test]
fn finite_capacity_is_canonical_and_changed_policy_does_not_reuse_pass_totals() {
    let (_dir, mut config, store, _key, at) = mine_relevance_fixture();
    aged_missing_provenance(&store, 1, at);
    config
        .capabilities
        .mine
        .participation
        .max_unresolved_operations = CountLimit::Bounded(1);
    store.runtime_state(&config, false).unwrap();
    refresh_mine_observation(&store, &config, 10, 2, at);
    let mut pass = ReconciliationPass::default();
    assert!(
        !store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut pass)
            .unwrap(),
        "a capacity-blocked lane receives no additional decay"
    );
    assert!(pass.finite_totals.is_some());
    config
        .capabilities
        .mine
        .participation
        .max_unresolved_operations = CountLimit::Bounded(2);
    store.runtime_state(&config, false).unwrap();
    refresh_mine_observation(&store, &config, 10, 3, at);
    assert!(
        !store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut pass)
            .unwrap()
    );
    assert!(
        pass.invalidated,
        "changed captured policy cannot borrow stale totals"
    );
    let mut fresh = ReconciliationPass::default();
    assert!(
        store
            .reconciliation_delayed(&config, LaneId::Mine, 1, at, &mut fresh)
            .unwrap()
    );
}

fn refresh_mine_observation(store: &Store, config: &Config, epoch: u64, sequence: u64, at: i64) {
    let admission = AdmissionStampSnapshot {
        account_generation: store.control().unwrap().generation,
        lane_control_revision: store
            .db
            .query_row(
                "SELECT control_revision FROM lane_control WHERE lane='mine'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        authority_epoch: 1,
        lane_config_revision: config.lane_revision(LaneId::Mine).unwrap(),
    };
    assert!(
        store
            .observe_lane(
                LaneId::Mine,
                LaneObservationStamp {
                    authority_epoch: 1,
                    generation: store.control().unwrap().generation,
                    request_sequence: sequence,
                    started_at: at,
                    completed_at: at,
                },
                LaneObservation {
                    epoch,
                    answered: false,
                    fingerprint: "test",
                    challenge: &json!({})
                },
                &admission
            )
            .unwrap()
    );
}

#[test]
fn legacy_challenge_provenance_absence_keeps_ordinary_reconciliation() {
    let (_dir, config, store, _key, at) = mine_relevance_fixture();
    aged_missing_provenance(&store, 1, at);
    store.db.execute("UPDATE runtime_state SET lane_participation=json_remove(lane_participation,'$.challenge_provenance')",[]).unwrap();
    let accounting = accounting::AccountingReadSnapshot::load(&store.db, &config).unwrap();
    let context = store
        .remote_work_context(&config, LaneId::Mine, at, &accounting)
        .unwrap();
    assert_eq!(
        context.nonblocking("unknown", Some(9), "work-1"),
        Some(true),
        "new optional decay provenance is not an ordinary participation requirement"
    );
    assert!(
        store
            .reconciliation_decay_at(1, &context, at)
            .unwrap()
            .is_none()
    );
    let mut pass = ReconciliationPass::default();
    let selected = store
        .reconciliation_selection_in(&config, LaneId::Mine, at, &mut pass)
        .unwrap();
    assert!(selected.iter().any(|(id, _)| *id == 1));
    assert!(pass.lanes.iter().all(Option::is_none));
    assert_eq!(store.operation(1).unwrap().unwrap().state, "unknown");
}

fn remote_context_constructions() -> usize {
    crate::store::projection::REMOTE_CONTEXT_CONSTRUCTIONS.with(std::cell::Cell::get)
}

#[test]
fn decay_context_constructs_once_across_pages_and_claims_without_renewing_expiry() {
    let (_dir, config, store, key, at) = mine_relevance_fixture();
    aged_missing_provenance(&store, 1, at);
    for id in 2..=130 {
        seed(&store, LaneId::Mine, id, true);
        store.db.execute(
            "UPDATE operations SET request='{\"solver\":{\"kind\":\"mine\",\"epoch\":9}}' WHERE id=?1",
            [id],
        ).unwrap();
        aged_missing_provenance(&store, id, at);
    }
    let baseline = remote_context_constructions();
    let mut pass = ReconciliationPass::default();
    for _ in 0..3 {
        assert!(
            store
                .reconciliation_selection_in(&config, LaneId::Mine, at, &mut pass)
                .unwrap()
                .is_empty()
        );
        assert!(
            !pass.invalidated,
            "our cursor writes must not invalidate source reuse"
        );
        assert_eq!(remote_context_constructions() - baseline, 1);
    }
    assert!(
        !store
            .reconciliation_claim_with_pass(
                &config,
                LaneId::Mine,
                &key,
                ReconciliationClaim {
                    at,
                    service: None,
                    flight: Some((1, 2))
                },
                &mut pass,
            )
            .unwrap()
    );
    assert_eq!(
        remote_context_constructions() - baseline,
        1,
        "claim uses the captured context"
    );
    let expiry = at + config.schedule(LaneId::Mine).observation_max_age_seconds as i64;
    assert!(
        store
            .reconciliation_claim_with_pass(
                &config,
                LaneId::Mine,
                &key,
                ReconciliationClaim {
                    at: expiry,
                    service: None,
                    flight: Some((1, 3))
                },
                &mut pass,
            )
            .unwrap(),
        "original observation expiry removes only the optional gate"
    );
    assert!(pass.invalidated);
    assert_eq!(
        remote_context_constructions() - baseline,
        1,
        "expired context is not rebuilt"
    );
    assert!(pass.finite_totals.is_none());
}

#[test]
fn decay_pass_rejects_same_stamp_assessment_replacement_without_reconstruction() {
    let (_dir, mut config, store) = fixture();
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.judge.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .judge
        .participation
        .uncertainty_grace_seconds = 0;
    config
        .capabilities
        .judge
        .participation
        .max_unresolved_operations = CountLimit::Unbounded;
    store.db.execute("UPDATE control SET paused=0", []).unwrap();
    store.set_authority_epoch(1).unwrap();
    store.runtime_state(&config, false).unwrap();
    let at = now();
    seed(&store, LaneId::Judge, 1, true);
    aged_missing_provenance(&store, 1, at);
    let stamp = AdmissionStampSnapshot {
        account_generation: store.control().unwrap().generation,
        lane_control_revision: 0,
        authority_epoch: 1,
        lane_config_revision: config.lane_revision(LaneId::Judge).unwrap(),
    };
    let mut assessment = json!({
        "observed_at":at,"valid_until":at+120,"completeness":"complete",
        "observed_opportunities":1,"eligible_candidates":0,
        "exclusions":{"already_attempted":1},"locally_judgeable":false,
        "excluded_work":[{"work_key":"other-work","reason":"already_attempted"}],
        "excluded_work_truncated":false
    });
    store
        .record_lane_participation(LaneId::Judge, &stamp, &assessment)
        .unwrap();
    let baseline = remote_context_constructions();
    let source = store.reconciliation_source_stamp(LaneId::Judge).unwrap();
    let mut pass = ReconciliationPass::default();
    assert!(
        store
            .reconciliation_delayed(&config, LaneId::Judge, 1, at, &mut pass)
            .unwrap()
    );
    assessment["excluded_work"][0]["work_key"] = json!("work-1");
    store
        .record_lane_participation(LaneId::Judge, &stamp, &assessment)
        .unwrap();
    assert_eq!(
        store.reconciliation_source_stamp(LaneId::Judge).unwrap(),
        source,
        "same-second replacement deliberately retains every narrow source stamp"
    );
    assert!(
        !store
            .reconciliation_delayed(&config, LaneId::Judge, 1, at, &mut pass)
            .unwrap()
    );
    assert!(pass.invalidated);
    assert_eq!(
        remote_context_constructions() - baseline,
        1,
        "native SQLite change evidence invalidates instead of comparing full witnesses"
    );
}

#[test]
fn decay_pass_external_commit_is_not_blessed_by_cursor_writes() {
    let (_dir, config, store, _key, at) = mine_relevance_fixture();
    aged_missing_provenance(&store, 1, at);
    let mut pass = ReconciliationPass::default();
    assert!(
        store
            .reconciliation_selection_in(&config, LaneId::Mine, at, &mut pass)
            .unwrap()
            .is_empty()
    );
    let captured = pass.database_stamp.unwrap();
    let external = Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
    external.execute(
        "UPDATE lane_observations SET challenge=json_set(challenge,'$.same_stamp_change',1) WHERE lane='mine'",
        [],
    ).unwrap();
    assert_eq!(
        store.db.total_changes(),
        captured.0,
        "external commit is invisible to local total_changes"
    );
    let baseline = remote_context_constructions();
    let selected = store
        .reconciliation_selection_in(&config, LaneId::Mine, at, &mut pass)
        .unwrap();
    assert!(pass.invalidated);
    assert!(
        selected.iter().any(|(id, _)| *id == 1),
        "ordinary reconciliation remains eligible"
    );
    assert_eq!(
        pass.database_stamp.unwrap().1,
        captured.1,
        "cursor writes never renew data_version"
    );
    assert_eq!(remote_context_constructions(), baseline);
}
