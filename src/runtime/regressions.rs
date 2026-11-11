use super::*;

#[tokio::test]
async fn missing_and_slow_jobs_never_own_healthy_same_lane_or_other_lane_slots() {
    for slow in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.judge.schedule.retry_seconds = 20;
        config.capabilities.judge.schedule.backoff_max_seconds = 60;
        config.capabilities.answer.schedule.retry_seconds = 2;
        let (_temp, mut runtime, _stop) = fixture_with(config);
        no_discovery(&runtime);
        let bad = seed_bound(&mut runtime, LaneId::Judge, "bad", "missing-a");
        let good = seed_bound(&mut runtime, LaneId::Judge, "good", "healthy-b");
        let answer = seed_bound(&mut runtime, LaneId::Answer, "answer", "healthy-c");
        let release = Arc::new(Notify::new());
        let released = Arc::clone(&release);
        let server = tokio::spawn(async move {
            let mut replies = Vec::new();
            for _ in 0..3 {
                let (stream, line) = accept(&listener).await;
                let released = Arc::clone(&released);
                replies.push(tokio::spawn(async move {
                    if line.contains("missing-a") {
                        if slow {
                            released.notified().await;
                        }
                        reply(stream, 404, None, json!({"error":"not_found"})).await;
                    } else if line.contains("healthy-b") {
                        reply(
                            stream,
                            200,
                            None,
                            json!({"state":"done","ok":true,"id":"b".repeat(64)}),
                        )
                        .await;
                    } else {
                        assert!(line.contains("healthy-c"));
                        reply(
                            stream,
                            200,
                            None,
                            json!({"state":"done","ok":true,"challenge_txid":"c".repeat(64)}),
                        )
                        .await;
                    }
                }));
            }
            for task in replies {
                task.await.unwrap();
            }
        });
        runtime.plan().unwrap();
        collect_until(&mut runtime, |runtime| {
            runtime.store.operation(good.id).unwrap().unwrap().state == "included_pending"
                && runtime.store.operation(answer.id).unwrap().unwrap().state == "included_pending"
        })
        .await;
        let bad_key = Store::operation_read_key(&bad).unwrap();
        if slow {
            assert_eq!(runtime.store.read_backoff(&bad_key).unwrap().failures, 0);
            assert_eq!(
                runtime
                    .store
                    .operation(bad.id)
                    .unwrap()
                    .unwrap()
                    .job_id
                    .as_deref(),
                Some("missing-a")
            );
            release.notify_one();
        }
        server.await.unwrap();
        collect_until(&mut runtime, |runtime| {
            runtime.store.read_backoff(&bad_key).unwrap().failures == 1
        })
        .await;
        let retained = runtime.store.operation(bad.id).unwrap().unwrap();
        assert_eq!(retained.state, "unknown");
        assert_eq!(retained.job_id.as_deref(), Some("missing-a"));
        assert_eq!(
            runtime
                .store
                .read_backoff(&Store::operation_read_key(&good).unwrap())
                .unwrap()
                .failures,
            0
        );
        assert_eq!(
            runtime
                .store
                .read_backoff(&Store::operation_read_key(&answer).unwrap())
                .unwrap()
                .failures,
            0
        );
        runtime.evaluate_read(&bad_key, false).unwrap();
        assert_eq!(runtime.store.read_backoff(&bad_key).unwrap().failures, 2);
        assert_eq!(
            runtime
                .store
                .read_backoff(&HostAccess::discovery_key(LaneId::Answer))
                .unwrap()
                .failures,
            0
        );
    }
}

#[tokio::test]
async fn stale_job_minima_ingest_before_binding_cas_and_split_queued_headers_stay_local() {
    for shared in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let (_temp, mut runtime, _stop) = fixture_with(config);
        let mut original = seed_bound(&mut runtime, LaneId::Judge, "bound", "old-job");
        let old_key = Store::operation_read_key(&original).unwrap();
        let mut flight = runtime
            .launch_read(
                LaneId::Judge,
                old_key.clone(),
                Endpoint::Job,
                Some("old-job"),
                None,
            )
            .unwrap()
            .unwrap();
        let (mut stream, _) = accept(&listener).await;
        let body = if shared {
            json!({"error":"rate_limited"})
        } else {
            json!({"state":"queued"})
        }
        .to_string();
        stream.write_all(format!("HTTP/1.1 {} Fixture\r\nRetry-After: 30\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            if shared { 429 } else { 202 }, body.len()).as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(flight.take().is_none(), "headers are not a completion");
        assert!(
            runtime
                .store
                .request_not_before(&runtime.config, Endpoint::Answer, None)
                .unwrap()
                <= now()
        );
        original.txid = Some("d".repeat(64));
        original.state = "included_pending".into();
        runtime
            .store
            .seed_transition_for_test(&original, "fixture_advanced_binding")
            .unwrap();
        let advanced = runtime.store.operation(original.id).unwrap().unwrap();
        let current_key = Store::operation_read_key(&advanced).unwrap();
        stream.write_all(body.as_bytes()).await.unwrap();
        let result = read_result(&mut runtime, &mut flight).await;
        let response = runtime.finish_read(&flight, result).unwrap().unwrap();
        runtime
            .recovery_response(&mut original, &old_key, &response)
            .unwrap();
        let current = runtime.store.operation(original.id).unwrap().unwrap();
        assert_eq!(current.state, "included_pending");
        assert_eq!(current.binding_revision, advanced.binding_revision);
        assert_eq!(
            runtime.store.read_backoff(&current_key).unwrap().failures,
            0
        );
        let effect_floor = runtime
            .store
            .request_not_before(&runtime.config, Endpoint::Answer, None)
            .unwrap();
        assert_eq!(effect_floor > now(), shared);
        assert!(
            runtime
                .store
                .request_not_before(&runtime.config, Endpoint::Job, Some("old-job"))
                .unwrap()
                > now()
        );
        if !shared {
            assert!(
                runtime
                    .store
                    .request_not_before(&runtime.config, Endpoint::Job, Some("new-job"))
                    .unwrap()
                    <= now()
            );
        }
    }
}

#[tokio::test]
async fn body_failure_retains_header_limit_and_bare_429_uses_shared_fixed_cooldown() {
    for interrupted in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let (_temp, mut runtime, _stop) = fixture_with(config);
        let op = seed_bound(&mut runtime, LaneId::Judge, "bounded", "bound-job");
        let key = Store::operation_read_key(&op).unwrap();
        let mut flight = runtime
            .launch_read(LaneId::Judge, key, Endpoint::Job, Some("bound-job"), None)
            .unwrap()
            .unwrap();
        let (mut stream, _) = accept(&listener).await;
        if interrupted {
            stream.write_all(b"HTTP/1.1 202 Fixture\r\nRetry-After: 40\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{").await.unwrap();
            drop(stream);
        } else {
            reply(stream, 429, None, json!({"error":"rate_limited"})).await;
        }
        let result = read_result(&mut runtime, &mut flight).await;
        runtime.finish_read(&flight, result).unwrap();
        let floor = runtime
            .store
            .request_not_before(&runtime.config, Endpoint::Answer, None)
            .unwrap();
        assert!(floor >= now() + if interrupted { 39 } else { 29 });
    }
}

#[tokio::test]
async fn once_launches_only_entry_due_recoveries_and_never_waits_for_future_work() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Off;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let a = seed_bound(&mut runtime, LaneId::Judge, "one", "first");
    let b = seed_bound(&mut runtime, LaneId::Judge, "two", "second");
    let future = seed_bound(&mut runtime, LaneId::Answer, "future", "future");
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE operations SET next_at=?1 WHERE id=?2",
        rusqlite::params![now() + 3600, future.id],
    )
    .unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, line) = accept(&listener).await;
            assert!(!line.contains("future"));
            reply(stream, 202, None, json!({"state":"queued"})).await;
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
    assert_eq!(
        runtime.store.operation(a.id).unwrap().unwrap().state,
        "queued"
    );
    assert_eq!(
        runtime.store.operation(b.id).unwrap().unwrap().state,
        "queued"
    );
    assert_eq!(
        runtime.store.operation(future.id).unwrap().unwrap().state,
        "unknown"
    );
}

#[test]
fn lane_error_backoff_and_model_settings_are_independent() {
    let (_temp, mut runtime, _stop) = fixture();
    runtime.config.capabilities.answer.schedule.retry_seconds = 2;
    runtime
        .config
        .capabilities
        .answer
        .schedule
        .backoff_max_seconds = 3;
    runtime.config.capabilities.judge.schedule.retry_seconds = 20;
    runtime
        .config
        .capabilities
        .judge
        .schedule
        .backoff_max_seconds = 80;
    runtime.config.capabilities.answer.timeouts.model_seconds = 17;
    runtime.config.capabilities.judge.timeouts.model_seconds = 91;
    let answer = HostAccess::discovery_key(LaneId::Answer);
    let judge = HostAccess::discovery_key(LaneId::Judge);
    runtime.evaluate_read(&answer, false).unwrap();
    runtime.evaluate_read(&answer, false).unwrap();
    runtime.evaluate_read(&judge, false).unwrap();
    let a = runtime.store.read_backoff(&answer).unwrap();
    let j = runtime.store.read_backoff(&judge).unwrap();
    assert_eq!(a.failures, 2);
    assert_eq!(j.failures, 1);
    assert!(a.next_at < j.next_at);
    runtime.evaluate_read(&judge, true).unwrap();
    assert_eq!(runtime.store.read_backoff(&answer).unwrap().failures, 2);
    assert_eq!(runtime.config.model_seconds(LaneId::Answer), Some(17));
    assert_eq!(runtime.config.model_seconds(LaneId::Judge), Some(91));
    assert_eq!(runtime.config.model_seconds(LaneId::Mine), None);
}

#[tokio::test]
async fn discovery_retry_reload_and_restart_use_one_clock_without_losing_server_minima() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::ReadOnly;
    config.capabilities.answer.schedule.retry_seconds = 30;
    config.capabilities.answer.schedule.discovery_retry_seconds = Some(30);
    config
        .capabilities
        .answer
        .schedule
        .discovery_backoff_max_seconds = Some(30);
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let key = HostAccess::discovery_key(LaneId::Answer);
    let cadence = runtime.store.next_at(LaneId::Answer).unwrap();
    let mut flight = runtime
        .launch_read(LaneId::Answer, key.clone(), Endpoint::Challenge, None, None)
        .unwrap()
        .unwrap();
    let (stream, _) = accept(&listener).await;
    reply(stream, 503, Some(12), json!({"error":"unavailable"})).await;
    let result = read_result(&mut runtime, &mut flight).await;
    let response = runtime.finish_read(&flight, result).unwrap().unwrap();
    assert!(
        runtime
            .observe_challenge(LaneId::Answer, &flight, &response)
            .unwrap()
            .is_none()
    );
    assert_eq!(runtime.store.next_at(LaneId::Answer).unwrap(), cadence);
    let original = runtime.store.read_backoff(&key).unwrap();
    let floor = runtime
        .store
        .request_not_before(&runtime.config, Endpoint::Challenge, None)
        .unwrap();
    assert!(original.next_at > floor && floor > now());
    // Simulate the duplicated retry timestamp left by a previous runtime.
    runtime
        .store
        .defer_until(LaneId::Answer, original.next_at)
        .unwrap();
    let mut changed = runtime.config.clone();
    changed.capabilities.answer.schedule.discovery_retry_seconds = Some(1);
    changed
        .capabilities
        .answer
        .schedule
        .discovery_backoff_max_seconds = Some(1);
    std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
    runtime.reload().unwrap();
    let shortened = runtime.store.read_backoff(&key).unwrap();
    assert!(shortened.next_at < floor);
    assert_eq!(
        runtime
            .store
            .discovery_next_at(&runtime.config, LaneId::Answer, &shortened)
            .unwrap(),
        floor
    );
    assert!(!runtime.discovery_allowed(LaneId::Answer).unwrap());
    assert!(
        !OncePlan::capture(&runtime)
            .unwrap()
            .lane(LaneId::Answer)
            .discovery
    );
    assert_eq!(
        runtime.store.status(&runtime.config).unwrap()["work"]["answer"]["next_at"],
        floor
    );

    let config = runtime.config.clone();
    let path = runtime.config_path.clone();
    let protocol = Arc::clone(&runtime.protocol);
    drop(runtime);
    let store = Store::open(&config).unwrap();
    let (_stop, stop) = watch::channel(false);
    let runtime = HostAccess::new(path, config, protocol, store, stop, true).unwrap();
    runtime.store.reschedule_all_reads(&runtime.config).unwrap();
    assert_eq!(runtime.store.read_backoff(&key).unwrap(), shortened);
    assert_eq!(
        runtime
            .store
            .request_not_before(&runtime.config, Endpoint::Challenge, None)
            .unwrap(),
        floor
    );
    assert!(!runtime.discovery_allowed(LaneId::Answer).unwrap());
    assert_eq!(
        runtime.store.status(&runtime.config).unwrap()["work"]["answer"]["next_at"],
        floor
    );

    // Advance the persisted deadlines, not wall time, to exercise eligibility
    // after the minimum while the obsolete lane timestamp is still in the future.
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE read_state SET last_failure_at=?1 WHERE owner='answer' AND purpose='discovery'",
        [now() - 3],
    )
    .unwrap();
    db.execute("UPDATE request_restrictions SET not_before=?1", [now() - 1])
        .unwrap();
    runtime.store.reschedule_all_reads(&runtime.config).unwrap();
    assert!(runtime.store.next_at(LaneId::Answer).unwrap() > now());
    assert!(runtime.discovery_allowed(LaneId::Answer).unwrap());
    assert!(
        OncePlan::capture(&runtime)
            .unwrap()
            .lane(LaneId::Answer)
            .discovery
    );
    assert!(
        runtime.store.status(&runtime.config).unwrap()["work"]["answer"]["next_at"]
            .as_i64()
            .unwrap()
            <= now()
    );

    // Successful reads still honor the ordinary discovery cadence.
    runtime.evaluate_read(&key, true).unwrap();
    assert!(!runtime.discovery_allowed(LaneId::Answer).unwrap());
}

#[tokio::test]
async fn prepared_revalidation_projects_retry_and_api_floors_without_ordinary_cadence() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.schedule.discovery_retry_seconds = Some(60);
    config
        .capabilities
        .answer
        .schedule
        .discovery_backoff_max_seconds = Some(60);
    let (_temp, mut runtime, _stop) = fixture_with(config);
    let key = HostAccess::discovery_key(LaneId::Answer);
    let mut flight = runtime
        .launch_read(LaneId::Answer, key.clone(), Endpoint::Challenge, None, None)
        .unwrap()
        .unwrap();
    let (stream, _) = accept(&listener).await;
    reply(stream, 503, Some(30), json!({"error":"unavailable"})).await;
    let result = read_result(&mut runtime, &mut flight).await;
    let response = runtime.finish_read(&flight, result).unwrap().unwrap();
    runtime
        .observe_challenge(LaneId::Answer, &flight, &response)
        .unwrap();
    let floor = runtime
        .store
        .request_not_before(&runtime.config, Endpoint::Challenge, None)
        .unwrap();
    let op = runtime
        .store
        .seed_operation_for_test(
            LaneId::Answer,
            "8:prepared-timing",
            "prepared",
            &json!({"solver":request(LaneId::Answer)}),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Answer).unwrap(),
        )
        .unwrap();
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    let assert_states = |runtime: &HostAccess, expected: i64| {
        for state in ["prepared", "generated", "retry"] {
            db.execute(
                "UPDATE operations SET state=?1 WHERE id=?2",
                rusqlite::params![state, op.id],
            )
            .unwrap();
            let status = runtime.store.status(&runtime.config).unwrap();
            assert_eq!(
                status["work"]["answer"]["next_at"], expected,
                "{state}: {status}"
            );
        }
    };
    let retry = runtime.store.read_backoff(&key).unwrap().next_at;
    assert!(retry > floor && floor > now());
    runtime
        .store
        .defer_until(LaneId::Answer, retry + 300)
        .unwrap();
    assert_states(&runtime, retry);

    let mut changed = runtime.config.clone();
    changed.capabilities.answer.schedule.discovery_retry_seconds = Some(1);
    changed
        .capabilities
        .answer
        .schedule
        .discovery_backoff_max_seconds = Some(1);
    std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
    runtime.reload().unwrap();
    assert_states(&runtime, floor);
    // A shorter operation blocker must not hide the later read/API floor.
    db.execute(
        "UPDATE operations SET next_at=?1 WHERE id=?2",
        rusqlite::params![floor - 10, op.id],
    )
    .unwrap();
    assert_states(&runtime, floor);
    db.execute("UPDATE operations SET next_at=0 WHERE id=?1", [op.id])
        .unwrap();

    let config = runtime.config.clone();
    let path = runtime.config_path.clone();
    let protocol = Arc::clone(&runtime.protocol);
    drop(runtime);
    let store = Store::open(&config).unwrap();
    let (_stop, stop) = watch::channel(false);
    let runtime = HostAccess::new(path, config, protocol, store, stop, true).unwrap();
    runtime.store.reschedule_all_reads(&runtime.config).unwrap();
    assert_states(&runtime, floor);

    db.execute("UPDATE request_restrictions SET not_before=?1", [now() - 1])
        .unwrap();
    runtime.evaluate_read(&key, true).unwrap();
    assert!(runtime.store.next_at(LaneId::Answer).unwrap() > now());
    for state in ["prepared", "generated", "retry"] {
        db.execute(
            "UPDATE operations SET state=?1 WHERE id=?2",
            rusqlite::params![state, op.id],
        )
        .unwrap();
        let status = runtime.store.status(&runtime.config).unwrap();
        let work = &status["work"]["answer"];
        assert_eq!(work["admission"]["allowed"], true, "{status}");
        assert_eq!(work["reason"], "fresh_evidence_required");
        assert!(work["next_at"].as_i64().unwrap() <= now());
    }
    assert!(runtime.store.read_started(&key).unwrap());
    assert!(runtime.store.status(&runtime.config).unwrap()["work"]["answer"]["next_at"].is_null());
    runtime.store.cancel_read(&key).unwrap();
}

#[tokio::test]
async fn shutdown_cancels_discovery_before_draining_sent_effect() {
    for completed in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.runtime.shutdown_seconds = 2;
        config.capabilities.answer.mode = Mode::ReadOnly;
        config.capabilities.answer.timeouts.read_http_seconds = 15;
        config.capabilities.judge.mode = Mode::Off;
        config.capabilities.mine.mode = Mode::Active;
        config.capabilities.mine.timeouts.http_seconds = 8;
        let (_temp, mut runtime, stop) = fixture_with(config);
        no_discovery(&runtime);
        identity_fixture(&mut runtime, &listener).await;
        let op = runtime
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
        offer_mine(&mut runtime, op.clone());
        runtime.arbitrate().unwrap();
        let (effect_stream, _) = accept(&listener).await;
        runtime.store.defer_until(LaneId::Answer, 0).unwrap();
        runtime.plan().unwrap();
        let (_read_stream, path) = accept(&listener).await;
        assert!(path.contains("/challenge"));
        stop.send(true).unwrap();
        let config = runtime.config.clone();
        let db = rusqlite::Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
        let observe = async {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let in_flight: bool = db.query_row(
                        "SELECT in_flight FROM read_state WHERE owner='answer' AND purpose='discovery'",
                        [], |row| row.get(0),
                    ).unwrap();
                    if !in_flight {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.expect("discovery cancellation must not await the effect");
            let state: String = db
                .query_row("SELECT state FROM operations WHERE id=?1", [op.id], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(state, "dispatching");
            assert!(AccountAdmissionGuard::try_acquire(&config).is_err());
            assert!(crate::store::LaneAdmissionGuard::try_acquire(&config, LaneId::Mine).is_err());
            if completed {
                reply(effect_stream, 200, None, json!({"ok":true,"attested":1})).await;
            } else {
                // Keep the upstream socket open beyond the drain deadline.
                tokio::time::sleep(Duration::from_secs(3)).await;
                drop(effect_stream);
            }
        };
        let shutdown = async {
            tokio::time::timeout(Duration::from_secs(3), runtime.shutdown())
                .await
                .expect("shutdown exceeded its bounded drain")
                .unwrap();
        };
        tokio::join!(shutdown, observe);
        assert!(!runtime.any_handles());
        assert_eq!(
            runtime.store.operation(op.id).unwrap().unwrap().state,
            if completed { "completed" } else { "unknown" }
        );
        assert!(AccountAdmissionGuard::try_acquire(&config).is_ok());
        assert!(crate::store::LaneAdmissionGuard::try_acquire(&config, LaneId::Mine).is_ok());
    }
}

#[tokio::test]
async fn lane_only_reload_preserves_identity_permit_but_shared_policy_and_credentials_fence_it() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    let (_temp, mut runtime, _stop) = fixture_with(config);
    runtime.start_identity(LaneId::Answer).unwrap();
    let (stream, _) = accept(&listener).await;
    reply(
        stream,
        200,
        None,
        json!({"address":runtime.config.network.address,"chain_id":runtime.config.network.chain}),
    )
    .await;
    collect_until(&mut runtime, |runtime| runtime.permit_current().unwrap()).await;
    let epoch = runtime.authority_epoch;
    let mut changed = runtime.config.clone();
    changed.capabilities.judge.schedule.retry_seconds += 1;
    std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
    runtime.reload().unwrap();
    assert_eq!(runtime.authority_epoch, epoch);
    assert!(runtime.permit_current().unwrap());
    changed.identity.retry_seconds += 1;
    std::fs::write(&runtime.config_path, toml::to_string(&changed).unwrap()).unwrap();
    runtime.reload().unwrap();
    assert_ne!(runtime.authority_epoch, epoch);
    assert!(!runtime.permit_current().unwrap());
    let policy_epoch = runtime.authority_epoch;
    std::fs::write(&runtime.config.network.credential_file, "pk_test_changed").unwrap();
    runtime.reload().unwrap();
    assert_ne!(runtime.authority_epoch, policy_epoch);
}

#[tokio::test]
async fn idle_identity_refresh_remains_supervised_only_and_does_not_clear_rejection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    let (_temp, mut runtime, _stop) = fixture_with(config);
    no_discovery(&runtime);
    runtime.refresh_idle_identity().unwrap();
    assert!(runtime.identity.is_none());
    runtime.identity_nonblocking = true;
    runtime.refresh_idle_identity().unwrap();
    assert!(runtime.identity.is_some());
    let (stream, _) = accept(&listener).await;
    reply(stream, 401, None, json!({"error":"unauthorized"})).await;
    collect_until(&mut runtime, |runtime| runtime.identity.is_none()).await;
    assert!(!runtime.store.identity_refresh_needed().unwrap());
    runtime.refresh_idle_identity().unwrap();
    assert!(runtime.identity.is_none());
    assert!(!runtime.permit_current().unwrap());
}

#[test]
fn exclusion_discards_only_unsent_artifacts_not_possibly_sent_judgments() {
    let (_temp, mut runtime, _stop) = fixture();
    let sent = seed_bound(&mut runtime, LaneId::Judge, &"a".repeat(64), "sent-job");
    runtime.config.capabilities.judge.excluded_assignments = vec![sent.key.clone()];
    assert!(
        runtime
            .current_preparation(LaneId::Judge)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .store
            .operation(sent.id)
            .unwrap()
            .unwrap()
            .job_id
            .as_deref(),
        Some("sent-job")
    );
    let key = "b".repeat(64);
    let prepared = runtime
        .store
        .seed_operation_for_test(
            LaneId::Judge,
            &key,
            "prepared",
            &json!({}),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(LaneId::Judge).unwrap(),
        )
        .unwrap();
    runtime
        .config
        .capabilities
        .judge
        .excluded_assignments
        .push(key);
    assert!(
        runtime
            .current_preparation(LaneId::Judge)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime.store.operation(prepared.id).unwrap().unwrap().state,
        "discarded"
    );
}

#[test]
fn queued_cadence_never_creates_an_effect_retry_and_expiry_retires_its_binding() {
    for state in ["queued", "running", "processing"] {
        let (_temp, mut runtime, _stop) = fixture();
        let mut op = seed_bound(&mut runtime, LaneId::Judge, "original", "j1");
        let other = seed_bound(&mut runtime, LaneId::Judge, "other", "j2");
        let key = Store::operation_read_key(&op).unwrap();
        let other_key = Store::operation_read_key(&other).unwrap();
        runtime.evaluate_read(&key, false).unwrap();
        runtime.evaluate_read(&other_key, false).unwrap();
        let mut pending = response(json!({"state":state}));
        pending.status = 202;
        pending.retry_after_seconds = Some(600);
        runtime.recovery_response(&mut op, &key, &pending).unwrap();
        let mut current = runtime.store.operation(op.id).unwrap().unwrap();
        assert_eq!(current.state, "queued");
        assert_eq!(current.job_id.as_deref(), Some("j1"));
        assert_eq!(Store::operation_read_key(&current).as_ref(), Some(&key));
        assert_eq!(runtime.store.read_backoff(&key).unwrap().failures, 0);
        assert_eq!(runtime.store.read_backoff(&other_key).unwrap().failures, 1);
        let schedule = runtime.config.schedule(LaneId::Judge);
        let local_delay = schedule
            .queued_job_polling
            .map_or(schedule.retry_seconds, |policy| policy.initial_seconds)
            .saturating_add(schedule.jitter_seconds);
        assert!(
            current.next_at <= now().saturating_add(local_delay as i64).saturating_add(1),
            "local cadence must not rebase a server minimum already ingested by the read collector"
        );
        assert!(
            !runtime
                .store
                .admission_allowed(&runtime.config, &current)
                .unwrap()
        );
        let mut expiry = response(json!({"state":"expired","error":"job_expired"}));
        expiry.status = 408;
        runtime
            .recovery_response(&mut current, &key, &expiry)
            .unwrap();
        let expired = runtime.store.operation(op.id).unwrap().unwrap();
        assert_eq!(expired.state, "retry");
        assert!(expired.job_id.is_none());
        assert!(expired.binding_revision > current.binding_revision);
        assert!(!runtime.store.read_current(&key).unwrap());
        runtime.recovery_response(&mut op, &key, &pending).unwrap();
        let retained = runtime.store.operation(op.id).unwrap().unwrap();
        assert_eq!(retained.state, "retry");
        assert!(retained.job_id.is_none());
        assert_eq!(retained.binding_revision, expired.binding_revision);
    }
}

#[test]
fn malformed_pending_and_unproven_expiry_keep_the_bound_job_uncertain() {
    for (status, body) in [
        (200, json!({"state":"queued"})),
        (404, json!({"state":"queued"})),
        (202, json!({})),
        (202, json!({"state":null})),
        (202, json!({"state":"unrecognized"})),
        (202, json!({"state":"queued","job_id":null})),
        (202, json!({"state":"queued","job_id":"invalid/job"})),
        (202, json!({"state":"queued","code":"unexpected"})),
        (202, json!({"state":"queued","error":false})),
        (202, json!({"state":"queued","error":"duplicate_in_flight"})),
        (202, json!({"state":"queued","ok":false})),
        (202, json!({"state":"queued","id":"a".repeat(64)})),
        (408, json!({"state":"expired"})),
        (404, json!({"state":"expired","error":"job_expired"})),
        (408, json!({"state":"queued","error":"job_expired"})),
    ] {
        let (_temp, mut runtime, _stop) = fixture();
        let mut op = seed_bound(&mut runtime, LaneId::Judge, "original", "j1");
        op.state = "queued".into();
        runtime
            .store
            .seed_transition_for_test(&op, "fixture_pending")
            .unwrap();
        let key = Store::operation_read_key(&op).unwrap();
        let mut uncertain = response(body);
        uncertain.status = status;
        runtime
            .recovery_response(&mut op, &key, &uncertain)
            .unwrap();
        let retained = runtime.store.operation(op.id).unwrap().unwrap();
        assert_eq!(retained.state, "unknown");
        assert_eq!(retained.job_id.as_deref(), Some("j1"));
        assert!(retained.txid.is_none());
        assert_eq!(Store::operation_read_key(&retained).as_ref(), Some(&key));
        assert_eq!(runtime.store.read_backoff(&key).unwrap().failures, 1);
        assert!(
            !runtime
                .store
                .admission_allowed(&runtime.config, &retained)
                .unwrap()
        );
    }
}

#[test]
fn invalid_reload_keeps_effective_snapshot_and_cap_lowering_keeps_unknowns() {
    let (_temp, mut runtime, _stop) = fixture();
    let original = runtime.config.revision().unwrap();
    std::fs::write(&runtime.config_path, "schema_version = 1\n").unwrap();
    runtime.reload().unwrap();
    assert!(runtime.reload_blocked);
    assert_eq!(runtime.config.revision().unwrap(), original);
    let unknown = seed_bound(&mut runtime, LaneId::Judge, "retained", "retained-job");
    runtime
        .config
        .capabilities
        .judge
        .participation
        .max_unresolved_operations = 1;
    persist(&runtime);
    runtime.reload().unwrap();
    assert!(!runtime.reload_blocked);
    assert_eq!(
        runtime.store.operation(unknown.id).unwrap().unwrap().state,
        "unknown"
    );
}
