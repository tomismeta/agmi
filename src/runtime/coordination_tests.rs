use super::*;

async fn identity(runtime: &mut HostAccess, listener: &tokio::net::TcpListener) {
    runtime.start_identity(LaneId::Answer).unwrap();
    let (stream, _) = accept(listener).await;
    reply(
        stream,
        200,
        None,
        json!({"address":runtime.config.network.address,"chain_id":runtime.config.network.chain}),
    )
    .await;
    collect_until(runtime, |runtime| runtime.permit_current().unwrap()).await;
}

#[tokio::test]
async fn effect_guard_is_retained_through_bookkeeping_while_recovery_progresses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Active;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    let control = runtime.store.control().unwrap();
    let op = runtime
        .store
        .seed_operation_for_test(
            LaneId::Mine,
            "8:mine",
            "prepared",
            &json!({"solver":request(LaneId::Mine)}),
            control,
            &runtime.config.lane_revision(LaneId::Mine).unwrap(),
        )
        .unwrap();
    offer_mine(&mut runtime, op.clone());
    let busy_lane =
        crate::store::LaneAdmissionGuard::try_acquire(&runtime.config, LaneId::Mine).unwrap();
    runtime.arbitrate().unwrap();
    assert!(
        runtime.effect.is_none(),
        "a busy lane must defer without consuming its ready effect"
    );
    assert!(
        runtime.permit_current().unwrap(),
        "no effect intent means no identity consumption"
    );
    let deferred = runtime.store.operation(op.id).unwrap().unwrap();
    assert_eq!(deferred.state, "prepared");
    assert_eq!(runtime.store.database_identity().unwrap().1, 0);
    assert!(runtime.lanes.ready(LaneId::Mine).is_some());
    drop(busy_lane);
    runtime.arbitrate().unwrap();
    let (effect_stream, _) = accept(&listener).await;
    assert!(runtime.effect.is_some());
    assert!(runtime.gate().unwrap().is_none());
    assert!(AccountAdmissionGuard::try_acquire(&runtime.config).is_err());
    assert!(crate::store::LaneAdmissionGuard::try_acquire(&runtime.config, LaneId::Mine).is_err());
    for unrelated in [LaneId::Answer, LaneId::Judge] {
        let gate =
            crate::store::LaneAdmissionGuard::try_acquire(&runtime.config, unrelated).unwrap();
        drop(gate);
    }
    let recovery = seed_bound(
        &mut runtime,
        LaneId::Judge,
        "recovery",
        "recovery-during-effect",
    );
    runtime.plan().unwrap();
    let (stream, path) = accept(&listener).await;
    assert!(path.contains("recovery-during-effect"));
    reply(stream, 404, None, json!({"error":"not_found"})).await;
    collect_until(&mut runtime, |runtime| {
        runtime
            .store
            .read_backoff(&Store::operation_read_key(&recovery).unwrap())
            .unwrap()
            .failures
            == 1
    })
    .await;
    assert!(runtime.effect.is_some());
    assert!(AccountAdmissionGuard::try_acquire(&runtime.config).is_err());
    runtime.config.capabilities.mine.mode = Mode::Off;
    persist(&runtime);
    runtime.reload().unwrap();
    reply(effect_stream, 200, None, json!({"ok":true,"attested":1})).await;
    collect_until(&mut runtime, |runtime| runtime.effect.is_none()).await;
    assert_eq!(
        runtime.store.operation(op.id).unwrap().unwrap().state,
        "completed"
    );
    let _released = AccountAdmissionGuard::try_acquire(&runtime.config).unwrap();
    assert!(
        !runtime.permit_current().unwrap(),
        "effect consumes its one-use permit"
    );
}

#[tokio::test]
async fn queued_submission_minimum_preserves_binding_and_only_delays_its_job() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Active;
    config.capabilities.mine.schedule.retry_seconds = 1;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    let control = runtime.store.control().unwrap();
    let op = runtime
        .store
        .seed_operation_for_test(
            LaneId::Mine,
            "8:mine",
            "prepared",
            &json!({"solver":request(LaneId::Mine)}),
            control,
            &runtime.config.lane_revision(LaneId::Mine).unwrap(),
        )
        .unwrap();
    offer_mine(&mut runtime, op.clone());
    runtime.arbitrate().unwrap();
    assert!(runtime.effect.is_some());
    let (stream, path) = accept(&listener).await;
    assert!(path.contains("/api/hosted/mine"));
    reply(stream, 202, Some(2), json!({"job_id":"submitted-mine"})).await;
    collect_until(&mut runtime, |runtime| runtime.effect.is_none()).await;

    let queued = runtime.store.operation(op.id).unwrap().unwrap();
    assert_eq!(queued.state, "queued");
    assert_eq!(queued.job_id.as_deref(), Some("submitted-mine"));
    let floor = runtime
        .store
        .request_not_before(&runtime.config, Endpoint::Job, Some("submitted-mine"))
        .unwrap();
    assert!(floor > now());
    assert!(
        runtime
            .store
            .request_not_before(&runtime.config, Endpoint::Answer, None)
            .unwrap()
            <= now()
    );
    let unrelated = seed_bound(&mut runtime, LaneId::Judge, "other", "unrelated-job");
    runtime.plan().unwrap();
    let (stream, path) = accept(&listener).await;
    assert!(path.contains("/api/job/unrelated-job"));
    reply(stream, 202, None, json!({"state":"queued"})).await;
    collect_until(&mut runtime, |runtime| {
        runtime
            .store
            .operation(unrelated.id)
            .unwrap()
            .unwrap()
            .state
            == "queued"
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "queued submission minimum was bypassed"
    );

    let due = queued.next_at.max(floor);
    tokio::time::sleep(Duration::from_secs(due.saturating_sub(now()).max(0) as u64)).await;
    runtime.plan().unwrap();
    let (stream, path) = tokio::time::timeout(Duration::from_secs(5), accept(&listener))
        .await
        .unwrap();
    assert!(path.contains("/api/job/submitted-mine"));
    reply(
        stream,
        200,
        None,
        json!({"state":"done","ok":true,"attested":1}),
    )
    .await;
    collect_until(&mut runtime, |runtime| {
        runtime.store.operation(op.id).unwrap().unwrap().state == "completed"
    })
    .await;
    assert_eq!(
        runtime
            .store
            .operation(op.id)
            .unwrap()
            .unwrap()
            .job_id
            .as_deref(),
        Some("submitted-mine")
    );
}

#[tokio::test]
async fn eligible_assignment_after_cooled_first_candidate_gets_the_model_opportunity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.judge.model.executable = "/nonexistent/native-fixture".into();
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    runtime.plan().unwrap();
    let (stream, _) = accept(&listener).await;
    reply(stream, 200, None, json!({"has_more":false,"assignments":[
        {"answer_txid":a,"answer":"candidate-a","pending_meta":{"expires_at_epoch":10}},
        {"answer_txid":b,"answer_epoch":8,"answer":"candidate-b","words":["burn"],"pending_meta":{"expires_at_epoch":11}}
    ]})).await;
    collect_until(&mut runtime, |runtime| {
        runtime
            .store
            .lane_observation(LaneId::Answer)
            .unwrap()
            .is_none()
            && !runtime.any_handles()
    })
    .await;
    runtime.plan().unwrap();
    let (stream, path) = accept(&listener).await;
    assert!(path.contains(&a));
    reply(stream, 404, None, json!({"error":"not_found"})).await;
    collect_until(&mut runtime, |runtime| !runtime.any_handles()).await;
    runtime.plan().unwrap();
    let (stream, _) = accept(&listener).await;
    reply(
        stream,
        200,
        None,
        json!({"address":runtime.config.network.address,"chain_id":runtime.config.network.chain}),
    )
    .await;
    collect_until(&mut runtime, |runtime| runtime.permit_current().unwrap()).await;
    runtime.plan().unwrap();
    assert_eq!(runtime.store.attempt_count(LaneId::Judge, &a).unwrap(), 0);
    assert_eq!(runtime.store.attempt_count(LaneId::Judge, &b).unwrap(), 1);
    assert_eq!(
        runtime
            .store
            .read_backoff(&ReadKey::Assignment { assignment_id: a })
            .unwrap()
            .failures,
        1
    );
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn owning_read_deadlines_bound_body_without_a_shared_client_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.timeouts.read_http_seconds = 1;
    config.capabilities.judge.timeouts.read_http_seconds = 3;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let a = seed_bound(&mut runtime, LaneId::Answer, "a", "deadline-a");
    let b = seed_bound(&mut runtime, LaneId::Judge, "b", "deadline-b");
    let mut answer = runtime
        .launch_read(
            LaneId::Answer,
            Store::operation_read_key(&a).unwrap(),
            Endpoint::Job,
            Some("deadline-a"),
            None,
        )
        .unwrap()
        .unwrap();
    let mut judge = runtime
        .launch_read(
            LaneId::Judge,
            Store::operation_read_key(&b).unwrap(),
            Endpoint::Job,
            Some("deadline-b"),
            None,
        )
        .unwrap()
        .unwrap();
    let (mut first, _) = accept(&listener).await;
    let (mut second, _) = accept(&listener).await;
    let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\nConnection: close\r\n\r\n";
    first.write_all(headers).await.unwrap();
    second.write_all(headers).await.unwrap();
    let began = Instant::now();
    let result = read_result(&mut runtime, &mut answer).await;
    let response = runtime.finish_read(&answer, result).unwrap().unwrap();
    assert!(response.read_failure.is_some());
    assert!(began.elapsed() < Duration::from_secs(2));
    assert!(
        judge.take().is_none(),
        "judge body owns its longer complete deadline"
    );
    let result = read_result(&mut runtime, &mut judge).await;
    assert!(
        runtime
            .finish_read(&judge, result)
            .unwrap()
            .unwrap()
            .read_failure
            .is_some()
    );
}

#[tokio::test]
async fn lane_observations_are_attributed_and_cannot_roll_answer_epoch_backward() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.judge.mode = Mode::Off;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let mut mine = runtime
        .launch_read(
            LaneId::Mine,
            HostAccess::discovery_key(LaneId::Mine),
            Endpoint::Challenge,
            None,
            None,
        )
        .unwrap()
        .unwrap();
    let (mine_stream, _) = accept(&listener).await;
    let mut answer = runtime
        .launch_read(
            LaneId::Answer,
            HostAccess::discovery_key(LaneId::Answer),
            Endpoint::Challenge,
            None,
            None,
        )
        .unwrap()
        .unwrap();
    let (answer_stream, _) = accept(&listener).await;
    reply(
        answer_stream,
        200,
        None,
        json!({"epoch":10,"words":["burn"],"min_chars":4,"max_chars":100,"answered":false}),
    )
    .await;
    let result = read_result(&mut runtime, &mut answer).await;
    let response = runtime.finish_read(&answer, result).unwrap().unwrap();
    runtime
        .observe_challenge(LaneId::Answer, &answer, &response)
        .unwrap()
        .unwrap();
    reply(
        mine_stream,
        200,
        None,
        json!({"epoch":9,"words":["burn"],"min_chars":4,"max_chars":100,"answered":false}),
    )
    .await;
    let result = read_result(&mut runtime, &mut mine).await;
    let response = runtime.finish_read(&mine, result).unwrap().unwrap();
    runtime
        .observe_challenge(LaneId::Mine, &mine, &response)
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .store
            .lane_observation(LaneId::Answer)
            .unwrap()
            .unwrap()["epoch"],
        10
    );
    assert_eq!(
        runtime
            .store
            .lane_observation(LaneId::Mine)
            .unwrap()
            .unwrap()["epoch"],
        9
    );
}

#[tokio::test]
async fn external_admission_contention_defers_once_without_an_attempt_or_wait() {
    let (_temp, mut runtime, _stop) = fixture();
    no_discovery(&runtime);
    let gate = AccountAdmissionGuard::acquire(&runtime.config).unwrap();
    assert!(runtime.gate().unwrap().is_none());
    tokio::time::timeout(Duration::from_millis(500), runtime.run_loop(true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.store.work_revision().unwrap(), 0);
    drop(gate);
}

#[tokio::test]
async fn captured_native_routes_and_attempt_deadlines_remain_lane_owned() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.answer.model.model = "exact-answer-model".into();
    config.capabilities.judge.model.model = "exact-judge-model".into();
    config.capabilities.answer.model.executable = "/nonexistent/answer-native".into();
    config.capabilities.judge.model.executable = "/nonexistent/judge-native".into();
    config.capabilities.answer.timeouts.model_seconds = 7;
    config.capabilities.judge.timeouts.model_seconds = 19;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    identity(&mut runtime, &listener).await;
    use crate::solver::contract::{AnswerTask, GradeTask};
    let mut answer = AnswerModelSlot::default();
    let mut judge = GradeModelSlot::default();
    let answer_observation = observation(&runtime, LaneId::Answer);
    let judge_observation = observation(&runtime, LaneId::Judge);
    let answer_request = AnswerTask::new(task_request(&runtime, LaneId::Answer)).unwrap();
    let mut wire = task_request(&runtime, LaneId::Judge);
    wire.assignment = Some("a".repeat(64));
    wire.min_chars = 0;
    wire.max_chars = 0;
    let judge_request = GradeTask::new(wire).unwrap();
    assert!(
        runtime
            .begin_answer_model(
                &mut answer,
                answer_request,
                "fixture".into(),
                "8:answer",
                None,
                &answer_observation
            )
            .unwrap()
    );
    assert!(
        runtime
            .begin_grade_model(
                &mut judge,
                judge_request,
                &"a".repeat(64),
                &judge_observation
            )
            .unwrap()
    );
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    for (kind, model, seconds) in [
        (LaneId::Answer, "exact-answer-model", 7),
        (LaneId::Judge, "exact-judge-model", 19),
    ] {
        let id: i64 = db
            .query_row(
                "SELECT id FROM operations WHERE kind=?1 ORDER BY id DESC LIMIT 1",
                [kind.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let op = runtime.store.operation(id).unwrap().unwrap();
        let policy: String = db
            .query_row(
                "SELECT policy FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |row| row.get(0),
            )
            .unwrap();
        let policy: Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(policy["model"]["model"], model);
        assert_eq!(policy["model_seconds"], seconds);
        assert_eq!(policy["max_attempts_per_work"], 2);
    }
    runtime.cancel_answer_model(&mut answer).await.unwrap();
    runtime.cancel_grade_model(&mut judge).await.unwrap();
}

#[tokio::test]
async fn once_does_not_admit_a_future_prepared_effect_while_a_bound_read_drains() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.mine.mode = Mode::Active;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    seed_bound(&mut runtime, LaneId::Judge, "held", "held-job");
    let input = Input {
        solver: request(LaneId::Mine),
        challenge_fingerprint: Some("fixture".into()),
    };
    let mut mine = runtime
        .store
        .seed_operation_for_test(
            LaneId::Mine,
            "8:future",
            "prepared",
            &serde_json::to_value(input).unwrap(),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Mine).unwrap(),
        )
        .unwrap();
    mine.next_at = now() + 1;
    mine.payload = Some(json!({}));
    runtime
        .store
        .seed_transition_for_test(&mine, "fixture_future_effect")
        .unwrap();
    let server = tokio::spawn(async move {
        let (stream, path) = accept(&listener).await;
        assert!(path.contains("held-job"));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        reply(
            stream,
            409,
            None,
            json!({"state":"done","error":"off_panel"}),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    tokio::time::timeout(Duration::from_secs(5), runtime.run_loop(true))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    assert_eq!(
        runtime.store.operation(mine.id).unwrap().unwrap().state,
        "prepared"
    );
    assert!(runtime.store.operation(mine.id).unwrap().unwrap().next_at <= now());
}

#[tokio::test]
async fn once_mining_has_one_discovery_one_freshness_and_one_effect_opportunity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Active;
    config.capabilities.mine.schedule.each_epoch = true;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let address = runtime.config.network.address.clone();
    let chain = runtime.config.network.chain.clone();
    let server = tokio::spawn(async move {
        for step in 0..4 {
            let (stream, _) = accept(&listener).await;
            let body = match step {
                0 | 2 => {
                    json!({"epoch":8,"words":["burn"],"answered":false,"min_chars":4,"max_chars":100})
                }
                1 => json!({"address":address,"chain_id":chain}),
                _ => json!({"ok":true,"attested":1}),
            };
            reply(stream, 200, None, body).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    tokio::time::timeout(Duration::from_secs(5), runtime.run_loop(true))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    let counts: (i64, i64) = db
        .query_row(
            "SELECT COUNT(*),SUM(state='completed') FROM operations WHERE kind='mine'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
}

#[test]
fn read_inspection_keeps_truncation_metadata_without_initializing_state() {
    let temp = tempfile::tempdir().unwrap();
    let config = Config {
        state_dir: temp.path().join("absent"),
        ..Config::default()
    };
    assert_eq!(
        reads(&config).unwrap(),
        json!({"reads":[],"reads_truncated":false})
    );
    assert!(!config.state_dir.exists());
}

#[tokio::test]
async fn lane_fence_is_consumed_without_reloading_or_invalidating_account_identity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.judge.mode = Mode::Active;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    identity(&mut runtime, &listener).await;
    let account = runtime.store.control().unwrap();
    let answer = runtime.admission_stamp(LaneId::Answer).unwrap();
    let judge = runtime.admission_stamp(LaneId::Judge).unwrap();
    let status = crate::store::lane_control_status(&runtime.config, LaneId::Answer).unwrap();
    let ack = crate::store::set_lane_paused(
        &runtime.config,
        LaneId::Answer,
        true,
        status["desired"]["control_token"].as_str().unwrap(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(ack["fence_ack"]["acknowledged"], true);
    assert!(!runtime.active(LaneId::Answer).unwrap());
    assert!(runtime.active(LaneId::Judge).unwrap());
    assert!(runtime.permit_current().unwrap());
    assert_eq!(runtime.store.control().unwrap(), account);
    assert_eq!(runtime.admission_stamp(LaneId::Judge).unwrap(), judge);
    assert_ne!(runtime.admission_stamp(LaneId::Answer).unwrap(), answer);
}

#[tokio::test]
async fn lane_stale_read_ingests_restrictions_before_discarding_projection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let mut flight = runtime.begin_challenge(LaneId::Answer).unwrap().unwrap();
    let (stream, _) = accept(&listener).await;
    let status = crate::store::lane_control_status(&runtime.config, LaneId::Answer).unwrap();
    crate::store::set_lane_paused(
        &runtime.config,
        LaneId::Answer,
        true,
        status["desired"]["control_token"].as_str().unwrap(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    reply(stream, 429, Some(20), json!({"error":"rate_limited"})).await;
    let result = read_result(&mut runtime, &mut flight).await;
    assert!(runtime.finish_read(&flight, result).unwrap().is_none());
    assert!(
        runtime
            .store
            .request_not_before(&runtime.config, Endpoint::Challenge, None)
            .unwrap()
            > now()
    );
    assert!(!runtime.observation_current(&flight).unwrap());
}

#[test]
fn scoped_services_reject_persisted_lane_database_and_revision_mismatches() {
    let (_temp, mut runtime, _stop) = fixture();
    let op = runtime
        .store
        .seed_operation_for_test(
            LaneId::Answer,
            "scoped",
            "prepared",
            &json!({"solver":request(LaneId::Answer)}),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Answer).unwrap(),
        )
        .unwrap();
    let original = runtime.store.operation_binding(&op).unwrap();
    for changed in ["lane", "database", "revision"] {
        let mut binding = original.clone();
        match changed {
            "lane" => binding.lane_id = LaneId::Judge,
            "database" => binding.database_id.push_str("-other"),
            _ => binding.binding_revision += 1,
        }
        let observed = observation(&runtime, LaneId::Answer);
        let mut services = AnswerServices::new(&mut runtime);
        assert!(
            services
                .retire_unsent(&binding, "fixture_mismatch")
                .is_err()
        );
        assert!(
            services
                .emit_ready(
                    crate::protocol::AnswerIntent::new(&json!({"answer":"burning"})).unwrap(),
                    binding,
                    observed,
                )
                .is_err()
        );
    }
    let mut stale_config = observation(&runtime, LaneId::Answer);
    stale_config.stamp.lane_config_revision.push_str("-changed");
    assert!(
        AnswerServices::new(&mut runtime)
            .emit_ready(
                crate::protocol::AnswerIntent::new(&json!({"answer":"burning"})).unwrap(),
                original,
                stale_config,
            )
            .is_err()
    );
    assert_eq!(
        runtime.store.operation(op.id).unwrap().unwrap().state,
        "prepared"
    );
}

#[tokio::test]
async fn local_grade_abstention_is_active_only_and_spends_no_model_or_effect_authority() {
    let mut config = Config::default();
    config.capabilities.judge.mode = Mode::ReadOnly;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let assignment = Assignment {
        id: "b".repeat(64),
        epoch: 8,
        answer: "Candidate with unavailable required words.".into(),
        words: Vec::new(),
        expires_at_epoch: None,
        author: None,
        author_prior: Default::default(),
    };
    let read_only = observation(&runtime, LaneId::Judge);
    assert!(
        !runtime
            .record_grade_abstention(&assignment, &read_only)
            .unwrap()
    );
    runtime.config.capabilities.judge.mode = Mode::Active;
    persist(&runtime);
    runtime.reload().unwrap();
    runtime.store.runtime_state(&runtime.config, false).unwrap();
    let status = crate::store::lane_control_status(&runtime.config, LaneId::Judge).unwrap();
    crate::store::set_lane_paused(
        &runtime.config,
        LaneId::Judge,
        true,
        status["desired"]["control_token"].as_str().unwrap(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    let paused = observation(&runtime, LaneId::Judge);
    assert!(
        !runtime
            .record_grade_abstention(&assignment, &paused)
            .unwrap()
    );
    let status = crate::store::lane_control_status(&runtime.config, LaneId::Judge).unwrap();
    crate::store::set_lane_paused(
        &runtime.config,
        LaneId::Judge,
        false,
        status["desired"]["control_token"].as_str().unwrap(),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert!(
        !runtime
            .record_grade_abstention(&assignment, &paused)
            .unwrap(),
        "resuming cannot renew old input authority"
    );
    let fresh = observation(&runtime, LaneId::Judge);
    assert!(
        runtime
            .record_grade_abstention(&assignment, &fresh)
            .unwrap()
    );
    assert!(
        !runtime
            .record_grade_abstention(&assignment, &fresh)
            .unwrap(),
        "one assignment has one local abstention"
    );
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    let states: (i64, String) = db
        .query_row("SELECT COUNT(*),MIN(state) FROM operations", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(states, (1, "abstained".into()));
    for sql in [
        "SELECT COUNT(*) FROM operation_evidence WHERE model_attempt IS NOT NULL",
        "SELECT COUNT(*) FROM risk_admissions",
        "SELECT COUNT(*) FROM manual_grants",
    ] {
        assert_eq!(
            db.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap(),
            0
        );
    }
    assert_eq!(runtime.store.database_identity().unwrap().1, 0);
}

fn prepared_answer(runtime: &mut HostAccess, next_at: i64) -> Operation {
    let mut op = runtime
        .store
        .seed_operation_for_test(
            LaneId::Answer,
            "8:canonical",
            "prepared",
            &json!({"solver":request(LaneId::Answer),"challenge_fingerprint":"fixture"}),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Answer).unwrap(),
        )
        .unwrap();
    op.payload = Some(json!({"answer":"canonical burning"}));
    op.next_at = next_at;
    runtime
        .store
        .seed_transition_for_test(&op, "fixture_answer_prepared")
        .unwrap();
    runtime.store.operation(op.id).unwrap().unwrap()
}

fn uncertain_captured_answer(runtime: &mut HostAccess) -> Operation {
    let mut original = runtime
        .store
        .seed_operation_for_test(
            LaneId::Answer,
            "8:fixture",
            "prepared",
            &json!({"solver":request(LaneId::Answer),"challenge_fingerprint":"fixture"}),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Answer).unwrap(),
        )
        .unwrap();
    original.payload = Some(json!({"answer":"canonical burning"}));
    let mut captured = result();
    captured.answer = Some("canonical burning".into());
    original.result = Some(serde_json::to_value(captured).unwrap());
    original.state = "dispatching".into();
    runtime
        .store
        .seed_transition_for_test(&original, "fixture_answer_dispatch")
        .unwrap();
    original.state = "unknown".into();
    runtime
        .store
        .seed_transition_for_test(&original, "fixture_answer_unknown")
        .unwrap();
    runtime.store.operation(original.id).unwrap().unwrap()
}

#[tokio::test]
async fn captured_retry_binding_rejects_changed_key_and_retains_canonical_input_and_artifacts() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.participation.mode =
        crate::config::ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .answer
        .participation
        .retry_uncertain_answers = true;
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 0;
    config
        .capabilities
        .answer
        .participation
        .uncertain_answer_retry_seconds = 0;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    let canonical = uncertain_captured_answer(&mut runtime);
    let observed = observation(&runtime, LaneId::Answer);
    let mut services = AnswerServices::new(&mut runtime);
    let mut detached = services.uncertain_answer(8).unwrap().unwrap();
    detached.request["solver"]["id"] = json!("detached-request");
    detached.request["solver"]["words"] = json!(["water"]);
    detached.request["solver"]["min_chars"] = json!(5);
    detached.request["solver"]["max_chars"] = json!(80);
    detached.request["challenge_fingerprint"] = json!("changed");
    detached.key = "8:changed".into();
    detached.payload = Some(json!({"answer":"detached payload"}));
    detached.result = Some(json!({"answer":"detached result"}));
    assert_eq!(detached.request["solver"]["epoch"], 8);
    let binding = services.binding(&detached).unwrap();
    let error = services
        .begin_retry(&binding, &detached.key, &observed)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("captured retry key does not match canonical origin")
    );
    assert!(services.preparation().unwrap().is_none());
    assert!(
        services
            .begin_retry(&binding, &canonical.key, &observed)
            .unwrap()
    );
    let retry = services.preparation().unwrap().unwrap();
    assert_ne!(retry.id, canonical.id);
    assert_eq!(retry.request, canonical.request);
    assert_eq!(retry.key, canonical.key);
    assert_eq!(retry.payload, canonical.payload);
    assert_eq!(retry.result, canonical.result);
    let inspection = runtime.store.inspect(retry.id).unwrap();
    assert_eq!(inspection["retry_of"], canonical.id);
    assert_eq!(inspection["payload_reused"], true);
}

#[tokio::test]
async fn changed_challenge_retry_creates_a_fresh_typed_model_attempt_without_reusing_payload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.model.executable = "/nonexistent/answer-native".into();
    config.capabilities.answer.participation.mode =
        crate::config::ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .answer
        .participation
        .retry_uncertain_answers = true;
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 0;
    config
        .capabilities
        .answer
        .participation
        .uncertain_answer_retry_seconds = 0;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    let original = uncertain_captured_answer(&mut runtime);
    let observed = observation(&runtime, LaneId::Answer);
    let challenge = Challenge {
        epoch: 8,
        words: vec!["water".into()],
        answered: false,
        min_chars: 5,
        max_chars: 80,
        fingerprint: "changed".into(),
    };
    let mut slot = AnswerModelSlot::default();
    let mut services = AnswerServices::new(&mut runtime);
    let task = services.task(&challenge).unwrap();
    assert!(
        services
            .begin_model(
                &mut slot,
                task,
                challenge.fingerprint.clone(),
                "8:changed",
                Some(&original),
                &observed,
            )
            .unwrap()
    );
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    let (id, reused, attempt): (i64, bool, String) = db
        .query_row(
            "SELECT l.operation_id,l.payload_reused,e.model_attempt
             FROM operation_links l JOIN operation_evidence e ON e.operation_id=l.operation_id
             WHERE l.retry_of=?1",
            [original.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(!reused);
    let retry = runtime.store.operation(id).unwrap().unwrap();
    assert_eq!(retry.key, "8:changed");
    assert_eq!(retry.request["solver"]["epoch"], 8);
    assert_eq!(retry.request["solver"]["words"], json!(challenge.words));
    assert_eq!(retry.request["solver"]["min_chars"], challenge.min_chars);
    assert_eq!(retry.request["solver"]["max_chars"], challenge.max_chars);
    assert_eq!(
        retry.request["challenge_fingerprint"],
        challenge.fingerprint
    );
    assert_ne!(
        retry.request["solver"]["id"],
        original.request["solver"]["id"]
    );
    assert!(retry.payload.is_none());
    assert!(retry.result.is_none());
    let attempt: Value = serde_json::from_str(&attempt).unwrap();
    assert_eq!(attempt["producer"]["task_kind"], "answer");
    assert_eq!(attempt["producer"]["operation"]["operation_id"], id);
    assert_eq!(
        attempt["producer"]["request_id"],
        retry.request["solver"]["id"]
    );
    runtime.cancel_answer_model(&mut slot).await.unwrap();
}

fn offer_mutated_answer(runtime: &mut HostAccess, canonical: &Operation, next_at: i64) {
    let observed = observation(runtime, LaneId::Answer);
    let mut services = AnswerServices::new(runtime);
    let mut detached = services.preparation().unwrap().unwrap();
    assert_eq!(detached.id, canonical.id);
    let binding = services.binding(&detached).unwrap();
    detached.request["solver"]["epoch"] = json!(9);
    detached.payload = Some(json!({"answer":"forged burning"}));
    detached.key = "9:forged".into();
    detached.next_at = next_at;
    let intent = crate::protocol::AnswerIntent::new(detached.payload.as_ref().unwrap()).unwrap();
    let ready = services.emit_ready(intent, binding, observed).unwrap();
    assert_eq!(ready.op.request, canonical.request);
    assert_eq!(ready.op.payload, canonical.payload);
    assert_eq!(ready.op.key, canonical.key);
    assert_eq!(ready.op.next_at, canonical.next_at);
    runtime.lanes.answer.ready = Some(ready);
}

async fn accept_json(listener: &tokio::net::TcpListener) -> (tokio::net::TcpStream, Value) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        let header_end = loop {
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break end + 4;
            }
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0 && bytes.len() < 8192);
            bytes.extend_from_slice(&buffer[..n]);
        };
        let length: usize = std::str::from_utf8(&bytes[..header_end])
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .unwrap()
            .1
            .trim()
            .parse()
            .unwrap();
        assert!(length < 8192);
        while bytes.len() < header_end + length {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buffer[..n]);
        }
        let payload = serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
        (stream, payload)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn detached_answer_mutations_cannot_change_transmitted_payload_or_manual_grant_epoch() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.participation.mode = crate::config::ParticipationMode::Manual;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    seed_bound(&mut runtime, LaneId::Judge, "unresolved", "unresolved-job");
    runtime
        .store
        .authorize(&runtime.config, 9, LaneId::Answer)
        .unwrap();
    runtime
        .store
        .authorize(&runtime.config, 8, LaneId::Answer)
        .unwrap();
    let canonical = prepared_answer(&mut runtime, 0);
    offer_mutated_answer(&mut runtime, &canonical, i64::MAX);
    runtime.arbitrate().unwrap();
    let (stream, sent) = accept_json(&listener).await;
    assert_eq!(
        sent["answer"],
        canonical.payload.as_ref().unwrap()["answer"]
    );
    reply(stream, 202, None, json!({"job_id":"canonical-answer"})).await;
    collect_until(&mut runtime, |runtime| runtime.effect.is_none()).await;
    let persisted = runtime.store.operation(canonical.id).unwrap().unwrap();
    assert_eq!(persisted.request, canonical.request);
    assert_eq!(persisted.payload, canonical.payload);
    assert_eq!(persisted.key, canonical.key);
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    let admitted_epoch: i64 = db
        .query_row(
            "SELECT g.epoch FROM risk_admissions r JOIN manual_grants g ON g.id=r.manual_grant_id
         WHERE r.operation_id=?1",
            [canonical.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(admitted_epoch, 8);
    let forged_grant: Option<i64> = db
        .query_row(
            "SELECT consumed_by FROM manual_grants WHERE epoch=9 AND kind='answer'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(forged_grant, None);
}

#[tokio::test]
async fn detached_answer_epoch_cannot_bypass_an_accepted_original_epoch() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    let accepted = seed_bound(&mut runtime, LaneId::Answer, "8:accepted", "accepted-job");
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE operations SET state='confirmed',txid=?2 WHERE id=?1",
        rusqlite::params![accepted.id, "a".repeat(64)],
    )
    .unwrap();
    let canonical = prepared_answer(&mut runtime, 0);
    offer_mutated_answer(&mut runtime, &canonical, 0);
    runtime.arbitrate().unwrap();
    assert!(runtime.effect.is_none());
    assert_eq!(
        runtime
            .store
            .operation(canonical.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
    assert_eq!(runtime.store.database_identity().unwrap().1, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn detached_next_at_cannot_accelerate_answer_or_displace_an_eligible_mine_gate() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.mine.mode = Mode::Active;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    identity(&mut runtime, &listener).await;
    let canonical = prepared_answer(&mut runtime, now() + 3600);
    offer_mutated_answer(&mut runtime, &canonical, 0);
    let mine = runtime
        .store
        .seed_operation_for_test(
            LaneId::Mine,
            "8:mine",
            "prepared",
            &json!({"solver":request(LaneId::Mine)}),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Mine).unwrap(),
        )
        .unwrap();
    offer_mine(&mut runtime, mine.clone());
    runtime.arbitrate().unwrap();
    let (stream, path) = tokio::time::timeout(Duration::from_secs(2), accept(&listener))
        .await
        .unwrap();
    assert!(path.contains("/api/hosted/mine"));
    assert!(crate::store::LaneAdmissionGuard::try_acquire(&runtime.config, LaneId::Mine).is_err());
    assert!(crate::store::LaneAdmissionGuard::try_acquire(&runtime.config, LaneId::Answer).is_ok());
    assert_eq!(
        runtime
            .store
            .operation(canonical.id)
            .unwrap()
            .unwrap()
            .next_at,
        canonical.next_at
    );
    assert_eq!(
        runtime
            .store
            .operation(canonical.id)
            .unwrap()
            .unwrap()
            .state,
        "prepared"
    );
    reply(stream, 200, None, json!({"ok":true,"attested":1})).await;
    collect_until(&mut runtime, |runtime| runtime.effect.is_none()).await;
    assert_eq!(
        runtime.store.operation(mine.id).unwrap().unwrap().state,
        "completed"
    );
}
