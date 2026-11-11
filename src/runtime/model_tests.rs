use super::*;
use crate::runtime::host::tests::{fixture_with, identity_fixture, observation, task_request};

fn attempt(host: &HostAccess, id: i64) -> Value {
    let db = rusqlite::Connection::open(host.config.state_dir.join("state.sqlite3")).unwrap();
    let text: String = db
        .query_row(
            "SELECT model_attempt FROM operation_evidence WHERE operation_id=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&text).unwrap()
}
fn control(host: &HostAccess, lane: LaneId, paused: bool) {
    let status = crate::store::lane_control_status(&host.config, lane).unwrap();
    let token = status["desired"]["control_token"].as_str().unwrap();
    let ack = crate::store::set_lane_paused(
        &host.config,
        lane,
        paused,
        token,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(ack["fence_ack"]["acknowledged"], true);
}

#[cfg(unix)]
#[tokio::test]
async fn started_preflight_pause_pending_and_fresh_launch_keep_one_immutable_producer() {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.timeouts.model_seconds = 10;
    let (temp, mut host, _stop) = fixture_with(config);
    let discovery = temp.path().join("discovery-started");
    let release = temp.path().join("release-discovery");
    let inference = temp.path().join("inference-started");
    let executable = temp.path().join("native");
    let interpreter = temp.path().join("interpreter");
    let reported = json!({"provider":"openai-codex","model":"different-native-model","reasoning_effort":"high","run_id":"observed-run","output":"{}"}).to_string();
    std::fs::write(
        &interpreter,
        format!(
            "#!/bin/sh\nprintf started > '{}'\ncat >/dev/null\nprintf '%s' '{}'\n",
            inference.display(),
            reported
        ),
    )
    .unwrap();
    std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o700)).unwrap();
    let command = serde_json::to_string(&vec![
        interpreter.to_str().unwrap(),
        "-I",
        "-c",
        "fixture-native",
    ])
    .unwrap();
    std::fs::write(&executable,format!("#!/bin/sh\nprintf started > '{}'\nwhile ! test -f '{}'; do sleep 0.01; done\nprintf '%s' '{}'\n",discovery.display(),release.display(),command)).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    host.config.capabilities.answer.model.executable = executable;
    std::fs::write(&host.config_path, toml::to_string(&host.config).unwrap()).unwrap();
    host.reload().unwrap();
    host.store.runtime_state(&host.config, false).unwrap();
    identity_fixture(&mut host, &listener).await;
    let original_observation = observation(&host, LaneId::Answer);
    let mut slot = AnswerModelSlot::default();
    let task = AnswerTask::new(task_request(&host, LaneId::Answer)).unwrap();
    assert!(
        host.begin_answer_model(
            &mut slot,
            task,
            "fingerprint".into(),
            "8:fixture",
            None,
            &original_observation
        )
        .unwrap()
    );
    let work = slot.0.work.as_ref().unwrap();
    let id = work.op.id;
    assert!(matches!(work.stage, Stage::Preflight { .. }));
    assert!(work.preflight_started_at.is_some());
    let producer = attempt(&host, id)["producer"].clone();
    // The collector has not been polled; the child already belongs to its flight.
    control(&host, LaneId::Answer, true);
    assert!(
        host.permit_current().unwrap(),
        "lane control must not clear account identity"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while !discovery.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!inference.exists());
    std::fs::write(&release, b"continue").unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while slot.pending_work().is_none() {
            slot.0.collect(&mut host).unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let pending = slot.pending_work().unwrap();
    let key = pending.key;
    let budget = slot
        .0
        .work
        .as_ref()
        .unwrap()
        .pending
        .as_ref()
        .unwrap()
        .remaining_execution_budget();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let paused = observation(&host, LaneId::Answer);
    slot.0
        .launch_matched(
            &mut host,
            key.clone(),
            paused.clone(),
            paused.stamp.lane_config_revision.clone(),
        )
        .unwrap();
    assert!(
        slot.0
            .work
            .as_ref()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .remaining_execution_budget()
            < budget
    );
    assert!(!inference.exists());
    control(&host, LaneId::Answer, false);
    slot.0
        .launch_matched(
            &mut host,
            key.clone(),
            original_observation.clone(),
            original_observation.stamp.lane_config_revision.clone(),
        )
        .unwrap();
    assert!(
        slot.pending_work().is_some(),
        "an old match may not be retagged after resume"
    );
    let fresh = observation(&host, LaneId::Answer);
    let gate = crate::store::LaneAdmissionGuard::try_acquire(&host.config, LaneId::Answer).unwrap();
    slot.0
        .launch_matched(
            &mut host,
            key.clone(),
            fresh.clone(),
            fresh.stamp.lane_config_revision.clone(),
        )
        .unwrap();
    assert!(slot.pending_work().is_some());
    assert!(!inference.exists());
    drop(gate);
    slot.0
        .launch_matched(
            &mut host,
            key,
            fresh.clone(),
            fresh.stamp.lane_config_revision.clone(),
        )
        .unwrap();
    assert!(slot.pending_work().is_none());
    let launched = attempt(&host, id);
    assert_eq!(launched["producer"], producer);
    assert_eq!(
        launched["launch"]["admission"]["lane_control_revision"],
        fresh.stamp.lane_control_revision
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while slot.occupied() {
            slot.0.collect(&mut host).unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(inference.exists());
    assert_eq!(
        host.store
            .attempt_count(LaneId::Answer, "8:fixture")
            .unwrap(),
        1
    );
    assert_eq!(attempt(&host, id)["producer"], producer);
    assert_eq!(
        host.store.operation(id).unwrap().unwrap().state,
        "model_unknown"
    );
    let terminal = attempt(&host, id);
    assert_eq!(
        terminal["completion"]["reported"]["model"]["value"],
        "different-native-model"
    );
    assert_eq!(
        terminal["completion"]["reported"]["model"]["source"],
        "native_envelope"
    );
    assert_ne!(
        terminal["producer"]["requested"]["model"],
        terminal["completion"]["reported"]["model"]["value"]
    );
    host.store.recover().unwrap();
    assert_eq!(attempt(&host, id)["producer"], producer);
    assert_eq!(attempt(&host, id), terminal);
}

#[tokio::test]
async fn unavailable_native_route_finishes_evidence_without_inference_or_retry_authority() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.model.executable = "/nonexistent/atomic-fixture-native".into();
    let (_temp, mut host, _stop) = fixture_with(config);
    identity_fixture(&mut host, &listener).await;
    let observed = observation(&host, LaneId::Answer);
    let mut slot = AnswerModelSlot::default();
    let task = AnswerTask::new(task_request(&host, LaneId::Answer)).unwrap();
    assert!(
        host.begin_answer_model(
            &mut slot,
            task,
            "fingerprint".into(),
            "8:missing",
            None,
            &observed
        )
        .unwrap()
    );
    assert!(!slot.occupied());
    let db = rusqlite::Connection::open(host.config.state_dir.join("state.sqlite3")).unwrap();
    let id: i64 = db
        .query_row(
            "SELECT id FROM operations WHERE work_key='8:missing'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let record = attempt(&host, id);
    assert_eq!(record["completion"]["execution"], "not_started");
    assert!(record["launch"].is_null());
    assert!(record["completion"]["reported"]["model"].is_null());
    assert_eq!(
        host.store.operation(id).unwrap().unwrap().state,
        "prelaunch_failed"
    );
    let binding = host
        .store
        .operation_binding(&host.store.operation(id).unwrap().unwrap())
        .unwrap();
    let mut op = host.store.operation(id).unwrap().unwrap();
    op.state = "dispatching".into();
    assert!(
        host.store
            .complete_reconciliation(&binding, &op, "forbidden_dispatch")
            .is_err()
    );
    assert_eq!(attempt(&host, id), record);
}

#[cfg(unix)]
async fn pending_fixture(
    seconds: u64,
) -> (
    tempfile::TempDir,
    HostAccess,
    watch::Sender<bool>,
    AnswerModelSlot,
    PathBuf,
) {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.answer.timeouts.model_seconds = seconds;
    let (temp, mut host, stop) = fixture_with(config);
    let inference = temp.path().join("inference-started");
    let interpreter = temp.path().join("interpreter");
    let executable = temp.path().join("native");
    std::fs::write(
        &interpreter,
        format!(
            "#!/bin/sh\nprintf started > '{}'\ncat >/dev/null\nprintf '{{}}'\n",
            inference.display()
        ),
    )
    .unwrap();
    let command = serde_json::to_string(&vec![
        interpreter.to_str().unwrap(),
        "-I",
        "-c",
        "fixture-native",
    ])
    .unwrap();
    std::fs::write(
        &executable,
        format!("#!/bin/sh\nprintf '%s' '{}'\n", command),
    )
    .unwrap();
    for path in [&interpreter, &executable] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    host.config.capabilities.answer.model.executable = executable;
    std::fs::write(&host.config_path, toml::to_string(&host.config).unwrap()).unwrap();
    host.reload().unwrap();
    host.store.runtime_state(&host.config, false).unwrap();
    identity_fixture(&mut host, &listener).await;
    let observed = observation(&host, LaneId::Answer);
    let task = AnswerTask::new(task_request(&host, LaneId::Answer)).unwrap();
    let mut slot = AnswerModelSlot::default();
    assert!(
        host.begin_answer_model(
            &mut slot,
            task,
            "fingerprint".into(),
            "8:deadline",
            None,
            &observed,
        )
        .unwrap()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while slot.pending_work().is_none() {
            assert!(slot.occupied(), "preflight must produce a pending launch");
            slot.0.collect(&mut host).unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (temp, host, stop, slot, inference)
}

#[cfg(unix)]
#[tokio::test]
async fn paused_pending_deadline_expires_without_spawn_or_renewal() {
    let (_temp, mut host, _stop, mut slot, inference) = pending_fixture(3).await;
    let work = slot.0.work.as_ref().unwrap();
    let id = work.op.id;
    let key = ModelSlot::key(work);
    let producer = attempt(&host, id)["producer"].clone();
    let deadline = work.pending.as_ref().unwrap().execution_deadline();
    control(&host, LaneId::Answer, true);
    tokio::time::sleep_until(deadline.at + Duration::from_millis(1)).await;
    slot.0.collect(&mut host).unwrap();
    assert!(
        !slot.occupied(),
        "expired paused work must not keep a pending slot"
    );
    assert!(!inference.exists());
    let terminal = attempt(&host, id);
    assert_eq!(terminal["producer"], producer);
    assert!(terminal["launch"].is_null());
    assert_eq!(terminal["completion"]["execution"], "not_started");
    assert_eq!(terminal["completion"]["reason_code"], "pending_retired");
    assert_eq!(
        host.store.operation(id).unwrap().unwrap().state,
        "discarded"
    );
    control(&host, LaneId::Answer, false);
    let fresh = observation(&host, LaneId::Answer);
    slot.0
        .launch_matched(
            &mut host,
            key,
            fresh.clone(),
            fresh.stamp.lane_config_revision.clone(),
        )
        .unwrap();
    assert!(!slot.occupied());
    assert!(!inference.exists());
    assert_eq!(attempt(&host, id), terminal);
    assert_eq!(
        host.store
            .attempt_count(LaneId::Answer, "8:deadline")
            .unwrap(),
        1
    );
}

#[cfg(unix)]
#[tokio::test]
async fn committed_launch_with_stale_final_bounds_finishes_once_without_spawning() {
    for stale in ["observation", "identity", "deadline"] {
        let seconds = if stale == "deadline" { 3 } else { 10 };
        let (_temp, mut host, _stop, mut slot, inference) = pending_fixture(seconds).await;
        let work = slot.0.work.as_ref().unwrap();
        let id = work.op.id;
        let key = ModelSlot::key(work);
        let producer = attempt(&host, id)["producer"].clone();
        let deadline = work.pending.as_ref().unwrap().execution_deadline();
        let mut observed = observation(&host, LaneId::Answer);
        let (account, lane) = host.lane_gates(LaneId::Answer).unwrap().unwrap();
        assert!(
            host.store
                .admit_model_launch(
                    &host.config,
                    &account,
                    &lane,
                    &observed.stamp,
                    &key.operation,
                    deadline.unix_seconds,
                    observed.admit_before,
                )
                .unwrap()
        );
        let launch = attempt(&host, id)["launch"].clone();
        assert!(!launch.is_null());
        match stale {
            "observation" => observed.admit_before = Instant::now(),
            "identity" => host.permit = None,
            _ => std::thread::sleep(
                deadline
                    .at
                    .saturating_duration_since(tokio::time::Instant::now())
                    + Duration::from_millis(1),
            ),
        }
        slot.0
            .start_admitted(&mut host, observed, deadline, account, lane)
            .unwrap();
        assert!(
            !slot.occupied(),
            "{stale}: committed permission is terminal, not pending"
        );
        assert!(!inference.exists(), "{stale}: inference must not spawn");
        let terminal = attempt(&host, id);
        assert_eq!(terminal["producer"], producer);
        assert_eq!(terminal["launch"], launch);
        assert_eq!(terminal["completion"]["phase"], "inference");
        assert_eq!(terminal["completion"]["execution"], "not_started");
        assert_eq!(terminal["completion"]["outcome"], "not_started");
        assert!(terminal["completion"]["inference_spawned_at"].is_null());
        assert_eq!(
            host.store.operation(id).unwrap().unwrap().state,
            "discarded"
        );
        let fresh = observation(&host, LaneId::Answer);
        slot.0
            .launch_matched(
                &mut host,
                key,
                fresh.clone(),
                fresh.stamp.lane_config_revision.clone(),
            )
            .unwrap();
        slot.0.collect(&mut host).unwrap();
        assert!(!slot.occupied());
        assert!(!inference.exists());
        assert_eq!(
            attempt(&host, id),
            terminal,
            "{stale}: no duplicate immutable launch"
        );
        assert_eq!(
            host.store
                .attempt_count(LaneId::Answer, "8:deadline")
                .unwrap(),
            1
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_native_cleanup_keeps_original_deadline_and_effect_gates() {
    use crate::runtime::host::tests::{accept, offer_mine, reply, request};
    use std::os::unix::fs::PermissionsExt;
    // The paused worker is process-wide; never stall other concurrently running tests.
    const ISOLATED: &str = "AGMI_TEST_ISOLATED_NATIVE_CLEANUP";
    if std::env::var_os(ISOLATED).is_none() {
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::host::model::tests::shutdown_native_cleanup_keeps_original_deadline_and_effect_gates",
                    "--nocapture",
                ])
                .env(ISOLATED, "1")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated cleanup regression exceeded its deadline")
        .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }
    for (running, native_finished) in [(false, false), (true, false), (true, true)] {
        for completed in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = Config::default();
            config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
            config.runtime.shutdown_seconds = 1;
            config.capabilities.answer.mode = Mode::Active;
            config.capabilities.answer.timeouts.model_seconds = 20;
            config.capabilities.mine.mode = Mode::Active;
            let (temp, mut host, stop) = fixture_with(config);
            let marker = temp.path().join("native-owner");
            let executable = temp.path().join("native");
            let interpreter = temp.path().join("interpreter");
            let announced = format!(
                "#!/bin/sh\nprintf '%s\\n%s\\n' \"$$\" \"$PWD\" > '{}.tmp'\nmv '{}.tmp' '{}'\n",
                marker.display(),
                marker.display(),
                marker.display()
            );
            let hanging = format!("{announced}exec sleep 60\n");
            let terminal = json!({"provider":"openai-codex","model":"different-model","reasoning_effort":"high","run_id":"completed-run","output":"{}"});
            std::fs::write(
                &interpreter,
                if native_finished {
                    format!("{announced}cat >/dev/null\nprintf '%s' '{terminal}'\n")
                } else {
                    hanging.clone()
                },
            )
            .unwrap();
            std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o700)).unwrap();
            let command =
                serde_json::to_string(&vec![interpreter.to_str().unwrap(), "-I", "-c", "fixture"])
                    .unwrap();
            std::fs::write(
                &executable,
                if running {
                    format!("#!/bin/sh\nprintf '%s' '{command}'\n")
                } else {
                    hanging
                },
            )
            .unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            host.config.capabilities.answer.model.executable = executable;
            std::fs::write(&host.config_path, toml::to_string(&host.config).unwrap()).unwrap();
            host.reload().unwrap();
            host.store.runtime_state(&host.config, false).unwrap();
            identity_fixture(&mut host, &listener).await;
            let release = crate::solver::pause_native_cleanup_for_test().await;
            let observation = observation(&host, LaneId::Answer);
            let mut slot = AnswerModelSlot::default();
            let task = AnswerTask::new(task_request(&host, LaneId::Answer)).unwrap();
            assert!(
                host.begin_answer_model(
                    &mut slot,
                    task,
                    "fingerprint".into(),
                    "8:shutdown-native",
                    None,
                    &observation
                )
                .unwrap()
            );
            let id = slot.0.work.as_ref().unwrap().op.id;
            if running {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while slot.pending_work().is_none() {
                        slot.0.collect(&mut host).unwrap();
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let key = slot.pending_work().unwrap().key;
                slot.0
                    .launch_matched(
                        &mut host,
                        key,
                        observation.clone(),
                        observation.stamp.lane_config_revision.clone(),
                    )
                    .unwrap();
                assert!(matches!(
                    slot.0.work.as_ref().unwrap().stage,
                    Stage::Running { .. }
                ));
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while !marker.exists() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if native_finished {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let Stage::Running { task, .. } = &slot.0.work.as_ref().unwrap().stage
                        else {
                            panic!("inference collector missing");
                        };
                        if task.is_finished() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("assembled native result waited for filesystem cleanup");
            }
            let owner = std::fs::read_to_string(&marker).unwrap();
            let mut owner = owner.lines();
            let pid: i32 = owner.next().unwrap().parse().unwrap();
            let scratch = PathBuf::from(owner.next().unwrap());
            host.lanes.answer = crate::runtime::answer::AnswerLane::with_model_for_test(slot);
            let effect = host
                .store
                .seed_operation_for_test(
                    LaneId::Mine,
                    "8:shutdown-effect",
                    "prepared",
                    &json!({"solver":request(LaneId::Mine)}),
                    host.store.control().unwrap(),
                    &host.config.lane_revision(LaneId::Mine).unwrap(),
                )
                .unwrap();
            offer_mine(&mut host, effect.clone());
            host.arbitrate().unwrap();
            let (stream, _) = accept(&listener).await;
            stop.send(true).unwrap();
            let config = host.config.clone();
            let db = rusqlite::Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
            let observer = async {
                tokio::time::timeout(Duration::from_millis(500), async {
                    loop {
                        let state: String = db
                            .query_row("SELECT state FROM operations WHERE id=?1", [id], |row| {
                                row.get(0)
                            })
                            .unwrap();
                        if state != "generating" {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("native bookkeeping waited for scratch cleanup");
                assert!(scratch.exists());
                assert!(AccountAdmissionGuard::try_acquire(&config).is_err());
                assert!(
                    crate::store::LaneAdmissionGuard::try_acquire(&config, LaneId::Mine).is_err()
                );
                if completed {
                    reply(stream, 200, None, json!({"ok":true,"attested":1})).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    drop(stream);
                }
            };
            let shutdown = async {
                let started = tokio::time::Instant::now();
                tokio::time::timeout(Duration::from_millis(1500), host.shutdown())
                    .await
                    .expect("native cleanup extended the original deadline")
                    .unwrap();
                assert!(started.elapsed() < Duration::from_millis(1500));
            };
            tokio::join!(shutdown, observer);
            assert_eq!(
                host.store.operation(effect.id).unwrap().unwrap().state,
                if completed { "completed" } else { "unknown" }
            );
            assert_eq!(
                host.store.operation(id).unwrap().unwrap().state,
                if running {
                    "model_unknown"
                } else {
                    "prelaunch_failed"
                }
            );
            let completion = attempt(&host, id)["completion"].clone();
            if native_finished {
                assert_eq!(completion["reason_code"], "native_provenance_mismatch");
                assert_eq!(
                    completion["cancellation"]["local_process_stop"],
                    "not_requested"
                );
            } else {
                assert_eq!(completion["reason_code"], "interrupted");
                assert_eq!(completion["cancellation"]["local_process_stop"], "unknown");
                assert_eq!(
                    completion["cancellation"]["remote_run_stop"],
                    if running { "unknown" } else { "not_requested" }
                );
            }
            assert!(AccountAdmissionGuard::try_acquire(&config).is_ok());
            assert!(crate::store::LaneAdmissionGuard::try_acquire(&config, LaneId::Mine).is_ok());
            assert!(
                scratch.exists(),
                "blocked deletion was reported as completed"
            );
            // SAFETY: this PID came from this test's owned native process.
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            release.send(()).unwrap();
            assert!(
                crate::solver::drain_native_cleanup_until(
                    tokio::time::Instant::now() + Duration::from_secs(5)
                )
                .await
                .unwrap()
            );
            assert!(!scratch.exists());
        }
    }
}
