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

fn start_candidates(store: &Store, config: &Config, at: i64) -> Vec<(i64, bool)> {
    let candidates = store
        .reconciliation_selection(LaneId::Judge, at)
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
                    .reconciliation_candidates(LaneId::Judge, start + elapsed)
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
        let candidates = store.reconciliation_candidates(LaneId::Judge, at).unwrap();
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
            .reconciliation_candidates(LaneId::Judge, at + 59)
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
    let candidates = store.reconciliation_candidates(LaneId::Judge, at).unwrap();
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
            .reconciliation_candidates(LaneId::Judge, at + 50)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .reconciliation_candidates(LaneId::Judge, at + 51)
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
            .reconciliation_candidates(LaneId::Judge, at + 2)
            .unwrap()
            .is_empty()
    );
    assert_eq!(start_candidates(&store, &config, at + 3).len(), 2);
    assert!(
        store
            .reconciliation_candidates(LaneId::Judge, at + 4)
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
        store.reconciliation_candidates(LaneId::Judge, at).unwrap()
    });
    assert_eq!(candidates.len(), usize::from(missing));
    let (delay, wake_work) = measure_sql_work(&store, || store.wake_delay(&config, 60).unwrap());
    assert!((1..=10).contains(&delay));
    let cursor = store
        .reconciliation_schedule("reconciliation:judge")
        .unwrap()
        .1;
    assert_eq!(cursor, count - RECONCILIATION_PAGE_SIZE as i64 + 1);
    store.reconciliation_candidates(LaneId::Judge, at).unwrap();
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
    let entry = store.reconciliation_candidates(LaneId::Judge, at).unwrap();
    assert_eq!(entry, vec![4, 3]);
    seed(&store, LaneId::Judge, 5, false);
    assert_eq!(
        store.reconciliation_candidates(LaneId::Judge, at).unwrap()[0],
        5
    );
    assert_eq!(
        start_selected(&store, &config, at, entry),
        vec![(4, false), (3, false)]
    );
    assert!(
        store
            .reconciliation_candidates(LaneId::Judge, at)
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
    let selected = store.reconciliation_selection(LaneId::Judge, at).unwrap();
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
            store.reconciliation_selection(LaneId::Judge, at).unwrap(),
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
        store.reconciliation_selection(LaneId::Judge, at).unwrap(),
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
        store.reconciliation_selection(LaneId::Judge, at).unwrap(),
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
            .reconciliation_selection(LaneId::Judge, at + 11)
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
