use super::*;
use crate::config::Config;
use crate::runtime::host::{HostAccess, tests};
use crate::solver::contract::ModelSelection;
use crate::store::now;

fn paged_inventory(runtime: &HostAccess, count: usize) -> Inventory {
    let mut sources = [None, None, None, None];
    let mut rows = Vec::new();
    for (index, source) in sources.iter_mut().enumerate().take(count) {
        rows.push(json!({
            "answer_txid": format!("{:064x}", index + 1),
            "answer_epoch": 8,
            "answer": "burning candidate",
            "words": ["burn"],
            "pending_meta": {"expires_at_epoch": index + 10},
        }));
        *source = Some(InventorySource {
            observation: tests::observation(runtime, LaneId::Judge),
            completed_at: now(),
            rows: index..index + 1,
        });
    }
    Inventory {
        ids: rows
            .iter()
            .map(|row| row["answer_txid"].as_str().unwrap().to_owned())
            .collect(),
        response: Response {
            status: 200,
            body: json!({"assignments": rows, "has_more": true}),
            retry_after_seconds: None,
            read_failure: None,
        },
        sources,
        pages: count,
        start_offset: 0,
        offset: count as u64,
        complete: false,
        overlapping_pages: false,
        more: count < 4,
        usable: true,
        eligible_candidates: 0,
        exclusions: Default::default(),
        excluded_work: Vec::new(),
        target: None,
    }
}

#[tokio::test]
async fn excluded_assignment_witnesses_are_public_bounded_and_explicitly_truncated() {
    let mut config = Config::default();
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (_temp, mut runtime, _stop) = tests::fixture_with(config.clone());
    let mut inventory = paged_inventory(&runtime, 1);
    for index in 2..=40 {
        let id = format!("{index:064x}");
        inventory.ids.push(id.clone());
        let mut row = inventory.response.body["assignments"][0].clone();
        row["answer_txid"] = json!(id);
        inventory.response.body["assignments"]
            .as_array_mut()
            .unwrap()
            .push(row);
    }
    inventory.sources[0].as_mut().unwrap().rows = 0..40;
    inventory.complete = true;
    inventory.more = false;
    let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
    for id in &inventory.ids {
        let store = tests::store(&mut runtime);
        let mut operation = store
            .seed_operation_for_test(
                LaneId::Judge,
                id,
                "prepared",
                &json!({}),
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        operation.state = "completed".into();
        operation.payload = Some(json!({"grade": 50}));
        store
            .seed_transition_for_test(&operation, "fixture_completed_judgment")
            .unwrap();
    }
    let mut lane = JudgeLane {
        inventory: Some(inventory),
        ..Default::default()
    };
    lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
    let status = tests::store(&mut runtime).status(&config).unwrap();
    let assessment = &status["work"]["judge"]["assessment"];
    assert_eq!(assessment["locally_judgeable"], false);
    assert_eq!(assessment["exclusions"]["already_attempted"], 40);
    assert_eq!(assessment["excluded_work_truncated"], true);
    let witnesses = assessment["excluded_work"].as_array().unwrap();
    assert_eq!(witnesses.len(), 32);
    for (index, witness) in witnesses.iter().enumerate() {
        assert_eq!(witness["work_key"], format!("{:064x}", index + 1));
        assert_eq!(witness["reason"], "already_attempted");
        assert_eq!(witness.as_object().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn partial_page_is_assessed_before_next_read_and_hydration_cannot_renew_it() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (_temp, mut runtime, _stop) = tests::fixture_with(config);
    tests::store(&mut runtime)
        .defer(LaneId::Judge, 3600)
        .unwrap();
    let inventory = paged_inventory(&runtime, 1);
    let original_deadline = inventory.source(0).observation.admit_before;
    let mut lane = JudgeLane {
        inventory: Some(inventory),
        ..Default::default()
    };
    let mut services = GradeServices::new(&mut runtime);
    lane.plan(&mut services).unwrap();
    let selected = lane
        .selected
        .as_ref()
        .expect("first page assessed immediately");
    assert_eq!(selected.observation.admit_before, original_deadline);
    assert!(
        matches!(
            lane.read.as_ref().map(|read| &read.kind),
            Some(JudgeReadKind::Page { .. })
        ),
        "assessment must precede the next page, not await the whole traversal"
    );
    lane.cancel(
        &mut services,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    lane.selected = None;
    lane.inventory.as_mut().unwrap().more = true;
    lane.inventory.as_mut().unwrap().response.body["assignments"][0]
        .as_object_mut()
        .unwrap()
        .remove("answer_epoch");
    lane.plan(&mut services).unwrap();
    assert!(matches!(
        lane.read.as_ref().map(|read| &read.kind),
        Some(JudgeReadKind::Hydration { .. })
    ));
    lane.cancel(
        &mut services,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    let id = format!("{:064x}", 1);
    let hydration = Response {
        status: 200,
        body: json!({"id": id, "body": {
            "type": "challenge", "epoch": 8, "words": ["burn"],
            "answer": "burning candidate"
        }}),
        retry_after_seconds: None,
        read_failure: None,
    };
    lane.accept_assignment(&mut services, &id, Some(&hydration))
        .unwrap();
    assert_eq!(
        lane.selected.as_ref().unwrap().observation.admit_before,
        original_deadline,
        "successful hydration retains its page's deadline"
    );
    lane.selected = None;
    lane.inventory.as_mut().unwrap().sources[0]
        .as_mut()
        .unwrap()
        .observation
        .admit_before = Instant::now() - Duration::from_secs(1);
    lane.accept_assignment(&mut services, &id, Some(&hydration))
        .unwrap();
    assert!(
        lane.selected.is_none(),
        "hydration must not renew an expired page"
    );
}

#[tokio::test]
async fn slow_pages_preserve_each_candidate_deadline_and_cannot_prove_stale_absence() {
    let mut config = Config::default();
    config.capabilities.judge.mode = Mode::ReadOnly;
    config.capabilities.judge.timeouts.read_http_seconds = 15;
    config
        .capabilities
        .judge
        .schedule
        .observation_max_age_seconds = 15;
    let (_temp, mut runtime, _stop) = tests::fixture_with(config);
    let mut inventory = paged_inventory(&runtime, 4);
    // Four six-second reads: at page four, page one is eighteen seconds old.
    let current = Instant::now();
    let wall = now();
    for (index, source) in inventory.sources.iter_mut().flatten().enumerate() {
        let age = (3 - index) as u64 * 6;
        source.completed_at = wall - age as i64;
        source.observation.admit_before =
            current - Duration::from_secs(age) + Duration::from_secs(15);
        source.observation.admit_before_unix = source.completed_at + 15;
    }
    inventory.complete = true;
    let second_deadline = inventory.source(1).observation.admit_before;
    let mut lane = JudgeLane {
        inventory: Some(inventory),
        ..Default::default()
    };
    {
        let mut services = GradeServices::new(&mut runtime);
        lane.select(&mut services).unwrap();
    }
    let selected = lane.selected.as_ref().unwrap();
    assert_eq!(selected.assignment.id, format!("{:064x}", 2));
    assert_eq!(selected.observation.admit_before, second_deadline);
    assert_eq!(
        lane.inventory
            .as_ref()
            .unwrap()
            .exclusions
            .get("observation_stale"),
        Some(&1)
    );
    let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
    let store = tests::store(&mut runtime);
    let op = store
        .seed_operation_for_test(
            LaneId::Judge,
            &"f".repeat(64),
            "prepared",
            &json!({}),
            store.control().unwrap(),
            &revision,
        )
        .unwrap();
    lane.selected = None;
    lane.inventory.as_mut().unwrap().target = Some(Target::Prepared(op.clone()));
    lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
    assert!(
        lane.inventory.is_some(),
        "stale absence retains its target until the next bounded rediscovery"
    );
    assert_eq!(
        tests::store(&mut runtime)
            .operation(op.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
}

#[tokio::test]
async fn selected_candidate_entering_model_cooldown_is_replaced() {
    let mut config = Config::default();
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (_temp, mut runtime, _stop) = tests::fixture_with(config);
    tests::store(&mut runtime)
        .defer(LaneId::Judge, 3600)
        .unwrap();
    let mut inventory = paged_inventory(&runtime, 2);
    inventory.more = false;
    inventory.complete = true;
    let mut lane = JudgeLane {
        inventory: Some(inventory),
        ..Default::default()
    };
    lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
    let first = lane.selected.as_ref().unwrap().assignment.id.clone();
    let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
    let store = tests::store(&mut runtime);
    let mut op = store
        .seed_operation_for_test(
            LaneId::Judge,
            &first,
            "generating",
            &json!({}),
            store.control().unwrap(),
            &revision,
        )
        .unwrap();
    op.state = "prelaunch_failed".into();
    op.next_at = runtime.deadline_now() + 3600;
    tests::store(&mut runtime)
        .seed_transition_for_test(&op, "fixture_model_cooldown")
        .unwrap();
    lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
    assert_eq!(
        lane.selected.as_ref().unwrap().assignment.id,
        format!("{:064x}", 2)
    );
    assert_eq!(
        lane.inventory
            .as_ref()
            .unwrap()
            .exclusions
            .get("model_retry_cooldown"),
        Some(&1)
    );
}

#[tokio::test]
async fn partial_retries_preserve_inventory_failure_and_can_continue_paging() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (temp, mut runtime, _stop) = tests::fixture_with(config);
    let config = Config::load(&temp.path().join("config.toml")).unwrap();
    let page = |index: usize, more: bool| {
        let inventory = paged_inventory(&runtime, index);
        json!({"assignments":[inventory.response.body["assignments"][index - 1].clone()],
            "has_more":more})
    };
    let bodies = vec![
        page(1, true),
        json!({"assignments":"malformed"}),
        page(1, true),
        page(2, true),
        page(3, true),
        page(4, true),
        page(1, true),
        page(1, false),
        page(1, false),
    ];
    let server = tokio::spawn(async move {
        for body in bodies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            let body = body.to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    async fn collect_page(lane: &mut JudgeLane, runtime: &mut HostAccess) {
        tokio::time::timeout(
            Duration::from_secs(5),
            &mut lane.read.as_mut().expect("page admitted").flight.task,
        )
        .await
        .unwrap()
        .unwrap();
        lane.collect(&mut GradeServices::new(runtime)).unwrap();
    }
    let key = HostAccess::discovery_key(LaneId::Judge);
    let mut lane = JudgeLane::default();
    assert!(
        lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
            .unwrap()
    );
    collect_page(&mut lane, &mut runtime).await;
    lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
    collect_page(&mut lane, &mut runtime).await;
    assert!(!lane.inventory.as_ref().unwrap().usable);
    assert_eq!(
        tests::store(&mut runtime)
            .read_backoff(&key)
            .unwrap()
            .failures,
        1
    );
    // Move only the elapsed retry deadline; keep the failed traversal evidence.
    let db = rusqlite::Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE read_state SET local_next_at=?1 WHERE owner='judge' AND purpose='discovery'",
        [now() - 1],
    )
    .unwrap();
    let failure = tests::store(&mut runtime).read_backoff(&key).unwrap();
    assert!(
        lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
            .unwrap()
    );
    for index in 0..4 {
        collect_page(&mut lane, &mut runtime).await;
        assert_eq!(
            tests::store(&mut runtime).read_backoff(&key).unwrap(),
            failure
        );
        if index < 3 {
            lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
            assert!(
                lane.read.is_some(),
                "retained failure must not deadlock pages"
            );
        }
    }
    assert!(!lane.inventory.as_ref().unwrap().more);
    assert!(!lane.inventory.as_ref().unwrap().complete);
    let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
    let store = tests::store(&mut runtime);
    let op = store
        .seed_operation_for_test(
            LaneId::Judge,
            &format!("{:064x}", 1),
            "prepared",
            &json!({}),
            store.control().unwrap(),
            &revision,
        )
        .unwrap();
    assert!(
        lane.start_inventory(
            &mut GradeServices::new(&mut runtime),
            Some(Target::Prepared(op))
        )
        .unwrap()
    );
    collect_page(&mut lane, &mut runtime).await;
    assert!(!lane.inventory.as_ref().unwrap().more);
    assert!(!lane.inventory.as_ref().unwrap().complete);
    assert_eq!(
        tests::store(&mut runtime).read_backoff(&key).unwrap(),
        failure
    );
    let status = tests::store(&mut runtime).status(&config).unwrap();
    let discovery = status["reads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|read| read["owner"] == "judge" && read["purpose"] == "discovery")
        .unwrap();
    assert_eq!(discovery["failure_category"], "unusable_response");
    assert!(discovery["last_success_at"].is_null());
    for (status, category) in [(None, Some("timeout")), (Some(200), None)] {
        tests::store(&mut runtime)
            .read_finished(&key, status, category)
            .unwrap();
        let category: String = db
            .query_row(
                "SELECT failure_category FROM read_state WHERE owner='judge' AND purpose='discovery'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            category, "timeout",
            "new failure replaces retained evidence"
        );
    }
    assert!(
        lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
            .unwrap()
    );
    collect_page(&mut lane, &mut runtime).await;
    assert!(!lane.inventory.as_ref().unwrap().complete);
    assert_eq!(
        tests::store(&mut runtime).judge_inventory_offset().unwrap(),
        0
    );
    assert_eq!(
        tests::store(&mut runtime)
            .read_backoff(&key)
            .unwrap()
            .failures,
        failure.failures,
        "a tail-only end page is not whole-inventory recovery"
    );
    assert!(
        lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
            .unwrap()
    );
    collect_page(&mut lane, &mut runtime).await;
    assert!(lane.inventory.as_ref().unwrap().complete);
    assert_eq!(
        tests::store(&mut runtime)
            .read_backoff(&key)
            .unwrap()
            .failures,
        0
    );
    let recovered: (Option<String>, Option<i64>) = db
        .query_row(
            "SELECT failure_category,last_success_at FROM read_state WHERE owner='judge' AND purpose='discovery'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(recovered.0.is_none());
    assert!(recovered.1.is_some());
    server.await.unwrap();
}

#[tokio::test]
async fn aggregate_assessment_expires_with_earliest_page_not_selected_or_last_page() {
    let mut config = Config::default();
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (temp, mut runtime, _stop) = tests::fixture_with(config);
    let config = Config::load(&temp.path().join("config.toml")).unwrap();
    runtime.heartbeat().unwrap();
    let mut inventory = paged_inventory(&runtime, 2);
    inventory.complete = true;
    inventory.more = false;
    let earliest = now() + 2;
    let first = inventory.sources[0].as_mut().unwrap();
    first.observation.admit_before = Instant::now() + Duration::from_secs(2);
    first.observation.admit_before_unix = earliest;
    let last = inventory.sources[1].as_mut().unwrap();
    last.observation.admit_before = Instant::now() + Duration::from_secs(60);
    last.observation.admit_before_unix = now() + 60;
    let candidate = inventory.ids[1].clone();
    let lane = JudgeLane {
        inventory: Some(inventory),
        ..Default::default()
    };
    for candidate in [Some(candidate.as_str()), None] {
        lane.report(
            &GradeServices::new(&mut runtime),
            Some(candidate.is_some()),
            None,
            candidate,
        )
        .unwrap();
        let status = tests::store(&mut runtime).status(&config).unwrap();
        let participation = &status["lane_participation"]["judge"];
        assert_eq!(participation["assessment"]["completeness"], "complete");
        assert_eq!(participation["assessment"]["valid_until"], earliest);
        assert_eq!(participation["freshness"], "current_observation");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let last = &lane.inventory.as_ref().unwrap().source(1).observation;
    assert!(
        GradeServices::new(&mut runtime)
            .observation_current(last)
            .unwrap()
    );
    let status = tests::store(&mut runtime).status(&config).unwrap();
    assert_eq!(status["lane_participation"]["judge"]["freshness"], "stale");
}

#[tokio::test]
async fn bounded_target_search_continues_past_duplicate_pages_and_tail_absence_is_partial() {
    for pending in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.judge.mode = Mode::ReadOnly;
        let (_temp, mut runtime, _stop) = tests::fixture_with(config);
        let row = |id: String| {
            json!({
                "answer_txid":id,"answer_epoch":8,"answer":"burning candidate","words":["burn"]
            })
        };
        let first = (1..=100)
            .map(|id| row(format!("{id:064x}")))
            .collect::<Vec<_>>();
        let target_id = "f".repeat(64);
        let tail = row(target_id.clone());
        let server = tokio::spawn(async move {
            for offset in [0, 100, 200, 300, 400, 0] {
                let (stream, request) = tests::accept(&listener).await;
                assert!(request.contains(&format!("offset={offset}")), "{request}");
                assert!(request.contains("limit=100"), "{request}");
                let body = if offset == 400 {
                    json!({"assignments":[tail.clone()],"has_more":false})
                } else {
                    // A moving view may repeat every ID without repeating
                    // its offset. Such pages must not reset the traversal.
                    json!({"assignments":first.clone(),"has_more":true})
                };
                tests::reply(stream, 200, None, body).await;
            }
        });
        let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
        let store = tests::store(&mut runtime);
        let op = store
            .seed_operation_for_test(
                LaneId::Judge,
                &target_id,
                "prepared",
                &json!({}),
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        let target = if pending {
            Target::Pending(
                PendingWorkKey {
                    operation: GradeServices::new(&mut runtime).binding(&op).unwrap(),
                    request_digest: "pending-digest".into(),
                },
                target_id.clone(),
            )
        } else {
            Target::Prepared(op.clone())
        };
        let mut lane = JudgeLane::default();
        assert!(
            lane.start_inventory(&mut GradeServices::new(&mut runtime), Some(target.clone()),)
                .unwrap()
        );
        for page in 0..4 {
            tokio::time::timeout(
                Duration::from_secs(5),
                &mut lane.read.as_mut().unwrap().flight.task,
            )
            .await
            .unwrap()
            .unwrap();
            lane.collect(&mut GradeServices::new(&mut runtime)).unwrap();
            if page < 3 {
                lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
            }
        }
        assert_eq!(lane.inventory.as_ref().unwrap().pages, 4);
        assert_eq!(lane.inventory.as_ref().unwrap().ids.len(), 100);
        assert!(!lane.inventory.as_ref().unwrap().more);
        lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
        assert!(
            lane.read.is_none(),
            "a bounded slice waits for its next scheduled cycle"
        );
        assert_eq!(
            tests::store(&mut runtime).judge_inventory_offset().unwrap(),
            400
        );
        assert_eq!(
            tests::store(&mut runtime)
                .operation(op.id)
                .unwrap()
                .unwrap()
                .state,
            "prepared"
        );

        // Reconstructing the controller must use the journal's continuation,
        // not a transient field from the old in-memory inventory.
        lane = JudgeLane::default();
        assert!(
            lane.start_inventory(&mut GradeServices::new(&mut runtime), Some(target.clone()),)
                .unwrap()
        );
        tokio::time::timeout(
            Duration::from_secs(5),
            &mut lane.read.as_mut().unwrap().flight.task,
        )
        .await
        .unwrap()
        .unwrap();
        lane.collect(&mut GradeServices::new(&mut runtime)).unwrap();
        assert_eq!(
            lane.candidates(&GradeServices::new(&mut runtime))
                .unwrap()
                .candidates,
            vec![target_id],
        );
        assert!(!lane.inventory.as_ref().unwrap().complete);
        assert_eq!(
            tests::store(&mut runtime).judge_inventory_offset().unwrap(),
            0
        );
        // Even an explicit end flag only completes this tail window. It
        // cannot retire a target omitted from the beginning of the list.
        lane.inventory.as_mut().unwrap().target = Some(Target::Prepared(op.clone()));
        lane.inventory.as_mut().unwrap().ids[0] = "e".repeat(64);
        lane.inventory.as_mut().unwrap().response.body["assignments"][0]["answer_txid"] =
            json!("e".repeat(64));
        lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
        assert_eq!(
            tests::store(&mut runtime)
                .operation(op.id)
                .unwrap()
                .unwrap()
                .state,
            "prepared"
        );
        assert!(
            lane.start_inventory(&mut GradeServices::new(&mut runtime), Some(target),)
                .unwrap()
        );
        tokio::time::timeout(
            Duration::from_secs(5),
            &mut lane.read.as_mut().unwrap().flight.task,
        )
        .await
        .unwrap()
        .unwrap();
        lane.collect(&mut GradeServices::new(&mut runtime)).unwrap();
        assert_eq!(lane.inventory.as_ref().unwrap().start_offset, 0);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn overlapping_zero_offset_pages_cannot_retire_an_unseen_preparation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (_temp, mut runtime, _stop) = tests::fixture_with(config);
    let server = tokio::spawn(async move {
        for (offset, ids, more) in [
            (0, vec![1, 2], true),
            (2, vec![2, 3], true),
            (4, vec![4], false),
        ] {
            let (stream, request) = tests::accept(&listener).await;
            assert!(request.contains(&format!("offset={offset}")), "{request}");
            let rows = ids
                .into_iter()
                .map(|id| {
                    json!({
                        "answer_txid":format!("{id:064x}"),"answer_epoch":8,
                        "answer":"burning candidate","words":["burn"]
                    })
                })
                .collect::<Vec<_>>();
            tests::reply(
                stream,
                200,
                None,
                json!({"assignments":rows,"has_more":more}),
            )
            .await;
        }
    });
    let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
    let store = tests::store(&mut runtime);
    let op = store
        .seed_operation_for_test(
            LaneId::Judge,
            &"f".repeat(64),
            "prepared",
            &json!({}),
            store.control().unwrap(),
            &revision,
        )
        .unwrap();
    let mut lane = JudgeLane::default();
    assert!(
        lane.start_inventory(
            &mut GradeServices::new(&mut runtime),
            Some(Target::Prepared(op.clone())),
        )
        .unwrap()
    );
    for _ in 0..3 {
        tokio::time::timeout(
            Duration::from_secs(5),
            &mut lane.read.as_mut().unwrap().flight.task,
        )
        .await
        .unwrap()
        .unwrap();
        lane.collect(&mut GradeServices::new(&mut runtime)).unwrap();
        lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
    }
    server.await.unwrap();
    assert!(!lane.inventory.as_ref().unwrap().complete);
    assert_eq!(
        tests::store(&mut runtime)
            .operation(op.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
    assert!(lane.ready.is_none());
    assert!(!lane.model.busy());
}

#[tokio::test]
async fn blocked_judge_draft_revalidates_and_only_changed_input_retires() {
    for changed in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.judge.mode = Mode::Active;
        config
            .capabilities
            .judge
            .participation
            .max_unresolved_operations = 1.into();
        let (_temp, mut runtime, _stop) = tests::fixture_with(config);
        tests::store(&mut runtime)
            .defer(LaneId::Judge, 3600)
            .unwrap();
        let inventory = paged_inventory(&runtime, 1);
        let id = inventory.ids[0].clone();
        let assignment = parse_selected_assignment(&inventory.response, &id, None).unwrap();
        let task = GradeServices::new(&mut runtime).task(&assignment).unwrap();
        let input = json!({"solver":task.request(),"challenge_fingerprint":null});
        let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
        let store = tests::store(&mut runtime);
        let mut prior = store
            .seed_operation_for_test(
                LaneId::Judge,
                &"a".repeat(64),
                "prepared",
                &input,
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        prior.state = "dispatching".into();
        store
            .seed_transition_for_test(&prior, "fixture_grade_dispatch")
            .unwrap();
        prior.state = "unknown".into();
        prior.next_at = now() + 3600;
        store
            .seed_transition_for_test(&prior, "fixture_unknown_grade")
            .unwrap();
        let mut op = store
            .seed_operation_for_test(
                LaneId::Judge,
                &id,
                "prepared",
                &input,
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        op.payload =
            Some(json!({"assignment":id,"score":2,"reasoning":"Grounded grade reasoning."}));
        store
            .seed_transition_for_test(&op, "fixture_prepared_grade")
            .unwrap();
        assert!(!runtime.admission_allowed(&op).unwrap());
        let mut lane = JudgeLane::default();
        lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
        assert!(
            matches!(lane.read.as_ref().and_then(|read| read.target.as_ref()),
            Some(Target::Prepared(current)) if current.id == op.id)
        );
        // Complete only the assignment flight; the unrelated identity
        // request remains fenced and is cancelled at shutdown.
        let mut response = inventory.response;
        response.body["has_more"] = json!(false);
        if changed {
            response.body["assignments"][0]["answer"] = json!("changed candidate");
        }
        let (stream, request) = tests::accept(&listener).await;
        if request.contains("/assignments") {
            tests::reply(stream, 200, None, response.body).await;
        } else {
            tests::reply(stream, 503, None, json!({"error":"unavailable"})).await;
            let (stream, request) = tests::accept(&listener).await;
            assert!(request.contains("/assignments"), "{request}");
            tests::reply(stream, 200, None, response.body).await;
        }
        tokio::time::timeout(
            Duration::from_secs(5),
            &mut lane.read.as_mut().unwrap().flight.task,
        )
        .await
        .unwrap()
        .unwrap();
        lane.collect(&mut GradeServices::new(&mut runtime)).unwrap();
        lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
        assert_eq!(
            tests::store(&mut runtime)
                .operation(op.id)
                .unwrap()
                .unwrap()
                .state,
            if changed { "discarded" } else { "prepared" }
        );
        assert_eq!(lane.ready.is_some(), !changed);
        assert_eq!(
            tests::store(&mut runtime)
                .operation(prior.id)
                .unwrap()
                .unwrap()
                .state,
            "unknown"
        );
        lane.cancel(
            &mut GradeServices::new(&mut runtime),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        runtime.shutdown().await.unwrap();
    }
}

#[test]
fn pending_grade_binds_candidate_history_and_waits_on_observation_expiry() {
    let mut assignment = Assignment {
        id: "a".repeat(64),
        epoch: 8,
        answer: "burning candidate".into(),
        words: vec!["burn".into()],
        expires_at_epoch: Some(12),
        author: Some("author".into()),
        author_prior: Default::default(),
    };
    let task = GradeTask::new(SolverRequest {
        id: "request".into(),
        kind: LaneId::Judge,
        epoch: 8,
        words: assignment.words.clone(),
        min_chars: 0,
        max_chars: 0,
        assignment: Some(assignment.id.clone()),
        candidate: Some(assignment.answer.clone()),
        history: Vec::new(),
        guidance: String::new(),
        core_guidance: "Evaluate protocol input.".into(),
        author_history: Some(assignment.author_prior.clone()),
        candidate_author: assignment.author.clone(),
    })
    .unwrap();
    let stamp = AdmissionStampSnapshot {
        account_generation: 1,
        lane_control_revision: 7,
        authority_epoch: 3,
        lane_config_revision: "config".into(),
    };
    let producer = ModelProducerProvenance {
        operation: OperationBinding {
            database_id: "db".into(),
            operation_id: 9,
            lane_id: LaneId::Judge,
            binding_revision: 0,
        },
        task_kind: "grade".into(),
        request_id: "request".into(),
        request_digest: "digest".into(),
        lane_config_revision: "config".into(),
        requested: ModelSelection::new(&crate::config::ModelConfig::default()).unwrap(),
        preflight_admission: stamp.clone(),
        created_at: 1,
    };
    let completed = Instant::now();
    let observation = Observation {
        stamp,
        admit_before: completed + Duration::from_secs(10),
        admit_before_unix: 11,
    };
    let descriptor = || PendingWorkRef {
        key: PendingWorkKey {
            operation: producer.operation.clone(),
            request_digest: producer.request_digest.clone(),
        },
        task: &task,
        producer: &producer,
    };
    assert!(matches!(
        match_pending(
            &assignment,
            descriptor(),
            observation.clone(),
            "config",
            true
        ),
        PendingInputDecision::Unchanged(_)
    ));
    assert!(matches!(
        match_pending(
            &assignment,
            descriptor(),
            observation.clone(),
            "config",
            false
        ),
        PendingInputDecision::Wait(PendingWaitReason::ObservationStale)
    ));
    assignment.author_prior.coverage = crate::protocol::EvidenceCoverage::Supplied;
    assert!(matches!(
        match_pending(
            &assignment,
            descriptor(),
            observation.clone(),
            "config",
            true
        ),
        PendingInputDecision::Retire(PendingRetirementReason::InputChanged)
    ));
    assignment.author_prior = Default::default();
    assignment.answer.push('!');
    assert!(matches!(
        match_pending(&assignment, descriptor(), observation, "config", true),
        PendingInputDecision::Retire(PendingRetirementReason::InputChanged)
    ));
}
