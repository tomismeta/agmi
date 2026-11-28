use super::*;
#[test]
fn cutover_fault_boundaries_recover_or_preserve_a_closed_history() {
    for boundary in 1..=16 {
        let home = tempfile::tempdir().unwrap();
        let (source, original) = legacy_fixture(home.path(), true);
        let path = durable_path(home.path());
        FILESYSTEM_FAULT.with(|fault| fault.set(Some((boundary, 0))));
        let result = adopt_locked(&path, &source, &source);
        let visited = FILESYSTEM_FAULT.with(|fault| fault.replace(None).unwrap().1);
        assert!(result.is_err(), "boundary {boundary} visited {visited}");
        if path.exists() {
            adopt_locked(&path, &source, &source).unwrap();
            let recovered = read_record(&path).unwrap();
            assert_eq!(recovered.retry_not_before, original.retry_not_before);
            assert_eq!(recovered.attempt_id, original.attempt_id);
            assert_eq!(recovered.outcome, "in_progress");
            assert_eq!(recovered.finished_at, None);
            assert_eq!(recovered.adoption.unwrap().phase, "ready");
            assert!(!source.exists());
        } else {
            assert_eq!(
                read_record(&source).unwrap().attempt_id,
                original.attempt_id
            );
            assert!(adopt_locked(&path, &source, &source).is_err());
        }
    }
}

#[test]
fn legacy_resolution_preserves_override_and_rejects_relative_roots() {
    assert_eq!(
        resolve_legacy_path(Some("/custom/cache".into()), Some("/ignored".into())).unwrap(),
        PathBuf::from("/custom/cache/agmi/update.json")
    );
    assert_eq!(
        resolve_legacy_path(Some("".into()), Some("/account".into())).unwrap(),
        PathBuf::from("/account/.cache/agmi/update.json")
    );
    assert!(resolve_legacy_path(Some("relative".into()), Some("/account".into())).is_err());
    assert!(resolve_legacy_path(None, None).is_err());
}

#[test]
fn readonly_legacy_view_preserves_bytes_mtimes_and_restrictions() {
    let home = tempfile::tempdir().unwrap();
    let (source, original) = legacy_fixture(home.path(), true);
    let lock = source.with_file_name("update.lock");
    let before = (
        fs::read(&source).unwrap(),
        fs::metadata(&source).unwrap().modified().unwrap(),
        fs::metadata(&lock).unwrap().modified().unwrap(),
        fs::metadata(source.parent().unwrap())
            .unwrap()
            .modified()
            .unwrap(),
    );
    for _ in 0..2 {
        let observed = read_view_record(home.path(), Ok(source.clone()))
            .unwrap()
            .unwrap();
        let view = record_view(&unmanaged_context(), Some(&observed), now());
        assert_eq!(view["storage"], "legacy");
        assert_eq!(view["adoption_required"], true);
        assert_eq!(view["availability"], "unknown");
        assert_eq!(view["retry_not_before"], json!(original.retry_not_before));
    }
    assert_eq!(
        (
            fs::read(&source).unwrap(),
            fs::metadata(&source).unwrap().modified().unwrap(),
            fs::metadata(&lock).unwrap().modified().unwrap(),
            fs::metadata(source.parent().unwrap())
                .unwrap()
                .modified()
                .unwrap()
        ),
        before
    );
    assert!(!home.path().join(".local").exists());
    let path = durable_path(home.path());
    drop(acquire(&path).unwrap().unwrap());
    assert!(read_view_record(home.path(), Ok(source.clone())).is_err());
    crate::admin::persist(&path, b"unsupported durable evidence").unwrap();
    assert!(read_view_record(home.path(), Ok(source)).is_err());
}

#[cfg(unix)]
#[test]
fn lock_inode_replacement_is_detected_before_publication() {
    let home = tempfile::tempdir().unwrap();
    let path = test_record_path(home.path());
    let lease = acquire(&path).unwrap().unwrap();
    let lock = path.with_file_name("update.lock");
    fs::rename(&lock, lock.with_file_name("retained-lock")).unwrap();
    drop(acquire(&path).unwrap_err());
    crate::admin::persist(&lock, b"").unwrap();
    assert!(verify_lease(&path, &lease).is_err());
    assert!(acquire(&path).unwrap().is_some());
}

fn legacy_fixture(home: &Path, incomplete: bool) -> (PathBuf, Record) {
    let source = home.join(".cache/agmi/update.json");
    let lease = acquire(&source).unwrap().unwrap();
    let record = Record {
        format: 1,
        source: API.into(),
        context: "original-context".into(),
        started_at: 100,
        finished_at: if incomplete { None } else { Some(101) },
        attempt_id: "original-attempt".into(),
        outcome: if incomplete { "in_progress" } else { "failure" }.into(),
        reason: "update_source_throttled".into(),
        next_due_at: 200,
        retry_not_before: Some(now() + 3600),
        ..Default::default()
    };
    persist(&source, &record).unwrap();
    drop(lease);
    (source, record)
}

#[test]
fn missing_legacy_record_with_surviving_lease_is_not_pristine() {
    let home = tempfile::tempdir().unwrap();
    let (source, _) = legacy_fixture(home.path(), true);
    let lock = source.with_file_name("update.lock");
    let before = fs::read(&lock).unwrap();
    fs::remove_file(&source).unwrap();
    let path = durable_path(home.path());
    assert!(read_view_record(home.path(), Ok(source.clone())).is_err());
    assert!(adopt_locked(&path, &source, &source).is_err());
    assert!(!path.parent().unwrap().exists());
    assert_eq!(fs::read(&lock).unwrap(), before);
}

#[tokio::test]
async fn adoption_preserves_floor_and_incomplete_evidence_without_http() {
    for incomplete in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let (source, record) = legacy_fixture(home.path(), incomplete);
        let original = fs::read(&source).unwrap();
        let lock = fs::metadata(source.with_file_name("update.lock")).unwrap();
        let path = durable_path(home.path());
        adopt_locked(&path, &source, &source).unwrap();
        let adopted = read_record(&path).unwrap();
        let mut expected = serde_json::to_value(&record).unwrap();
        expected["format"] = json!(2);
        expected["adoption"] = serde_json::to_value(Adoption {
            phase: "ready".into(),
            legacy_path: source.clone(),
            source_sha256: Some(format!("{:x}", Sha256::digest(&original))),
        })
        .unwrap();
        assert_eq!(serde_json::to_value(&adopted).unwrap(), expected);
        assert!(!source.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                lock.ino(),
                fs::metadata(source.with_file_name("update.lock"))
                    .unwrap()
                    .ino()
            );
        }
        let request = pending_request();
        let result = TEST_REQUEST
            .scope(
                request.clone(),
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Explicit,
                    Instant::now() + Duration::from_secs(1),
                    path.clone(),
                ),
            )
            .await;
        assert_eq!(result["update"]["reason"], "source_retry_not_before");
        if incomplete {
            assert_eq!(
                result["release_advisory"]["next_action"]["kind"],
                "unavailable"
            );
        }
        assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        if incomplete {
            let lease = acquire(&path).unwrap().unwrap();
            let mut expired = adopted;
            expired.retry_not_before = Some(1);
            persist(&path, &expired).unwrap();
            drop(lease);
            let result = check_path(
                unmanaged_context(),
                CheckTrigger::Explicit,
                Instant::now() + Duration::from_secs(1),
                path,
            )
            .await;
            assert_eq!(result["update"]["reason"], "previous_attempt_incomplete");
        }
    }
}

#[test]
fn adopting_resumes_before_or_after_source_unlink() {
    for removed in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let (source, mut record) = legacy_fixture(home.path(), false);
        let digest = format!("{:x}", Sha256::digest(fs::read(&source).unwrap()));
        let path = durable_path(home.path());
        let lease = acquire(&path).unwrap().unwrap();
        record.format = 2;
        record.adoption = Some(Adoption {
            phase: "adopting".into(),
            legacy_path: source.clone(),
            source_sha256: Some(digest),
        });
        persist(&path, &record).unwrap();
        drop(lease);
        if removed {
            fs::remove_file(&source).unwrap();
        }
        adopt_locked(&path, &source, &source).unwrap();
        assert_eq!(read_record(&path).unwrap().adoption.unwrap().phase, "ready");
        assert!(!source.exists());
    }
}

#[test]
fn conflicting_or_reappearing_source_preserves_both_records() {
    for phase in ["adopting", "ready"] {
        let home = tempfile::tempdir().unwrap();
        let (source, mut record) = legacy_fixture(home.path(), false);
        let path = durable_path(home.path());
        let lease = acquire(&path).unwrap().unwrap();
        record.format = 2;
        record.adoption = Some(Adoption {
            phase: phase.into(),
            legacy_path: source.clone(),
            source_sha256: Some("a".repeat(64)),
        });
        persist(&path, &record).unwrap();
        drop(lease);
        let before = (fs::read(&path).unwrap(), fs::read(&source).unwrap());
        assert!(adopt_locked(&path, &source, &source).is_err());
        assert_eq!(
            (fs::read(&path).unwrap(), fs::read(&source).unwrap()),
            before
        );
    }
}

#[test]
fn durable_footprint_and_ambiguous_sources_are_not_pristine() {
    let home = tempfile::tempdir().unwrap();
    let path = durable_path(home.path());
    let source = home.path().join(".cache/agmi/update.json");
    drop(acquire(&path).unwrap().unwrap());
    assert!(adopt_locked(&path, &source, &source).is_err());
    assert!(!path.exists());
    let second = tempfile::tempdir().unwrap();
    let (canonical, _) = legacy_fixture(second.path(), false);
    let alternate = second.path().join("custom-cache/agmi/update.json");
    assert!(adopt_locked(&durable_path(second.path()), &alternate, &canonical).is_err());
    assert!(canonical.exists());
    assert!(!durable_path(second.path()).exists());
}

#[test]
fn invalid_source_never_defaults_and_destination_is_account_scoped() {
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join(".cache/agmi/update.json");
    drop(acquire(&source).unwrap().unwrap());
    crate::admin::persist(&source, b"{malformed").unwrap();
    let path = durable_path(home.path());
    assert_eq!(
        path,
        home.path()
            .join(".local/share/agmi/update-advisory/update.json")
    );
    assert!(adopt_locked(&path, &source, &source).is_err());
    assert_eq!(fs::read(&source).unwrap(), b"{malformed");
    assert!(!path.exists());
}

fn unmanaged_context() -> LocalUpdateContext {
    LocalUpdateContext {
        config_path: "/unused".into(),
        selected: json!({"ownership":"unmanaged"}),
        identity: None,
    }
}

fn pending_request() -> std::sync::Arc<TestRequest> {
    std::sync::Arc::new(TestRequest {
        starts: std::sync::atomic::AtomicUsize::new(0),
        started: tokio::sync::Notify::new(),
        throttle: None,
    })
}

#[tokio::test]
async fn automatic_clock_rollback_preserves_due_without_contacting_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let context = unmanaged_context();
    let started = now() + 3600;
    let cache = Record {
        format: 2,
        adoption: Some(test_adoption()),
        source: API.into(),
        context: context.key(),
        started_at: started,
        finished_at: Some(started + 1),
        next_due_at: started + INTERVAL,
        outcome: "failure".into(),
        reason: "release_query_failed".into(),
        attempt_id: "before-clock-rollback".into(),
        ..Record::default()
    };
    let lease = acquire(&path).unwrap().unwrap();
    persist(&path, &cache).unwrap();
    drop(lease);
    let request = pending_request();
    let result = TEST_REQUEST
        .scope(
            request.clone(),
            check_path(
                context,
                CheckTrigger::Automatic,
                Instant::now() + Duration::from_secs(1),
                path.clone(),
            ),
        )
        .await;
    assert_eq!(result["update"]["reason"], "not_due");
    assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(read_record(&path).unwrap().attempt_id, cache.attempt_id);
}

#[tokio::test]
async fn stop_cancels_pending_http_and_restart_is_not_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let path = test_record_path(dir.path());
    let (sender, stop) = watch::channel(false);
    let request = pending_request();
    let task = tokio::spawn(CHECK_STOP.scope(
        stop,
        TEST_REQUEST.scope(
            request.clone(),
            check_path(
                unmanaged_context(),
                CheckTrigger::Explicit,
                Instant::now() + Duration::from_secs(20),
                path.clone(),
            ),
        ),
    ));
    tokio::time::timeout(Duration::from_secs(2), request.started.notified())
        .await
        .unwrap();
    sender.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["update"]["reason"], "check_cancelled");
    assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 1);
    let cache = read_record(&path).unwrap();
    assert_eq!(cache.outcome, "failure");
    assert_eq!(cache.reason, "check_cancelled");
    assert!(cache.finished_at.is_some());
    assert!(cache.next_due_at >= cache.started_at + INTERVAL);
    let automatic = TEST_TRANSPORT
        .scope(
            BTreeMap::new(),
            check_path(
                unmanaged_context(),
                CheckTrigger::Automatic,
                Instant::now() + Duration::from_secs(1),
                path.clone(),
            ),
        )
        .await;
    assert_eq!(automatic["update"]["reason"], "not_due");
    let restarted = TEST_TRANSPORT
        .scope(
            BTreeMap::new(),
            check_path(
                unmanaged_context(),
                CheckTrigger::Explicit,
                Instant::now() + Duration::from_secs(1),
                path,
            ),
        )
        .await;
    assert_eq!(restarted["update"]["reason"], "update_discovery_unverified");
}

#[tokio::test]
async fn parsed_throttle_floor_survives_simultaneously_ready_stop() {
    for status in [429, 503] {
        let dir = tempfile::tempdir().unwrap();
        let path = test_record_path(dir.path());
        let (sender, stop) = watch::channel(false);
        let request = std::sync::Arc::new(TestRequest {
            starts: std::sync::atomic::AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            throttle: Some((status, sender)),
        });
        let before = now();
        let result = CHECK_STOP
            .scope(
                stop,
                TEST_REQUEST.scope(
                    request.clone(),
                    check_path(
                        unmanaged_context(),
                        CheckTrigger::Explicit,
                        Instant::now() + Duration::from_secs(2),
                        path.clone(),
                    ),
                ),
            )
            .await;
        assert_eq!(result["update"]["reason"], "check_cancelled");
        assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 1);
        let cache = read_record(&path).unwrap();
        assert_eq!(cache.reason, "check_cancelled");
        assert!(cache.finished_at.is_some());
        assert!(cache.retry_not_before.unwrap() >= before + 3600);
        let result = TEST_TRANSPORT
            .scope(
                BTreeMap::new(),
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Explicit,
                    Instant::now() + Duration::from_secs(1),
                    path,
                ),
            )
            .await;
        assert_eq!(result["update"]["reason"], "source_retry_not_before");
    }
}

#[tokio::test]
async fn stop_during_initial_commit_serializes_cancelled_finalizer_without_http() {
    let dir = tempfile::tempdir().unwrap();
    let path = test_record_path(dir.path());
    let (sender, stop) = watch::channel(false);
    let request = pending_request();
    let gate = std::sync::Arc::new(TestCommit {
        writes: std::sync::atomic::AtomicUsize::new(0),
        started: tokio::sync::Notify::new(),
        released: std::sync::Mutex::new(false),
        release: std::sync::Condvar::new(),
    });
    let task = tokio::spawn(CHECK_STOP.scope(
        stop,
        TEST_REQUEST.scope(
            request.clone(),
            TEST_COMMIT.scope(
                gate.clone(),
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Explicit,
                    Instant::now() + Duration::from_secs(20),
                    path.clone(),
                ),
            ),
        ),
    ));
    tokio::time::timeout(Duration::from_secs(2), gate.started.notified())
        .await
        .unwrap();
    sender.send(true).unwrap();
    assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(acquire(&path).unwrap().is_none());
    *gate.released.lock().unwrap() = true;
    gate.release.notify_one();
    let result = tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["update"]["reason"], "check_cancelled");
    assert_eq!(gate.writes.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
    let cache = read_record(&path).unwrap();
    assert_eq!(cache.reason, "check_cancelled");
    assert!(cache.finished_at.is_some());
}

#[tokio::test]
async fn prestart_stop_creates_no_record_or_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let (_sender, stop) = watch::channel(true);
    let result = CHECK_STOP
        .scope(
            stop,
            check_path(
                unmanaged_context(),
                CheckTrigger::Explicit,
                Instant::now() + Duration::from_secs(1),
                path,
            ),
        )
        .await;
    assert_eq!(result["update"]["reason"], "check_cancelled");
    assert!(!dir.path().join("agmi").exists());
}

#[tokio::test]
async fn host_finalization_allowance_aborts_stalled_task_without_fake_completion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let lease = acquire(&path).unwrap().unwrap();
    persist(
        &path,
        &Record {
            format: 2,
            adoption: Some(test_adoption()),
            source: API.into(),
            outcome: "in_progress".into(),
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease);
    let task = tokio::spawn(std::future::pending::<()>());
    tokio::time::timeout(Duration::from_secs(4), finish_background(task))
        .await
        .unwrap();
    let cache = read_record(&path).unwrap();
    assert_eq!(cache.outcome, "in_progress");
    assert!(cache.finished_at.is_none());
}
#[test]
fn lease_is_kernel_owned_and_never_removed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let first = acquire(&path).unwrap().unwrap();
    assert!(acquire(&path).unwrap().is_none());
    drop(first);
    assert!(path.with_file_name("update.lock").exists());
    assert!(acquire(&path).unwrap().is_some());
}
#[test]
fn retry_floor_is_capped_and_github_403_rate_limits_are_classified() {
    let ceiling = now().saturating_add(MAX_RETRY_FLOOR_SECONDS + 5);
    let capped = retry_floor("999999999").unwrap();
    assert!(capped <= ceiling);
    // Primary GitHub 403 rate limit (X-RateLimit-Remaining: 0)
    let primary = source_failure_with_headers(403, None, Some("0"), Some("9999999999")).unwrap();
    assert!(primary.floor.unwrap() <= ceiling);
    // Negative X-RateLimit-Reset is ignored rather than creating a negative floor.
    let negative = source_failure_with_headers(403, None, Some("0"), Some("-5")).unwrap();
    assert_eq!(negative.floor, None);
    // Secondary GitHub 403 rate limit (Retry-After with non-zero remaining)
    let secondary = source_failure_with_headers(403, Some("120"), Some("50"), None).unwrap();
    assert!(secondary.floor.is_some());
    // Ordinary non-rate-limit 403 is not a throttle failure.
    assert!(source_failure_with_headers(403, None, Some("50"), None).is_none());
}

#[test]
fn record_rejects_oversized_and_foreign_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let _lease = acquire(&path).unwrap().unwrap();
    let cache = Record {
        format: 99,
        source: API.into(),
        ..Default::default()
    };
    assert!(persist(&path, &cache).is_err());
    crate::admin::persist(&path, &serde_json::to_vec(&cache).unwrap()).unwrap();
    assert!(read_record(&path).is_err());
    crate::admin::persist(&path, &vec![b'x'; LIMIT as usize + 1]).unwrap();
    assert!(read_record(&path).is_err());
}
#[cfg(unix)]
#[test]
fn record_symlink_and_hardlink_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let _lease = acquire(&path).unwrap().unwrap();
    let target = dir.path().join("target");
    crate::admin::persist(&target, b"{}").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(read_record(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(read_record(&path).is_err());
}
#[tokio::test]
async fn attempt_persistence_failure_refuses_explicit_and_automatic_http() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    initialize(&path).unwrap();
    fs::create_dir(&path).unwrap();
    let context = LocalUpdateContext {
        config_path: dir.path().join("not-created/config.toml"),
        selected: json!({"ownership":"unmanaged"}),
        identity: None,
    };
    for trigger in [CheckTrigger::Explicit, CheckTrigger::Automatic] {
        let result = TEST_TRANSPORT
            .scope(
                BTreeMap::new(),
                check_path(
                    context.clone(),
                    trigger,
                    Instant::now() + Duration::from_secs(1),
                    path.clone(),
                ),
            )
            .await;
        assert_eq!(result["success"], false);
        assert_eq!(result["update"]["reason"], "advisory_record_invalid");
        assert!(!dir.path().join("not-created").exists());
    }
}

#[tokio::test]
async fn expired_caller_still_commits_shared_source_floor_under_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let lease = std::sync::Arc::new(acquire(&path).unwrap().unwrap());
    let floor = now() + 3600;
    let cache = Record {
        format: 2,
        adoption: Some(test_adoption()),
        source: API.into(),
        outcome: "failure".into(),
        reason: "update_source_throttled".into(),
        retry_not_before: Some(floor),
        finished_at: Some(now()),
        ..Default::default()
    };
    // A 429/503 learned at the deadline must start its commit, not skip it.
    let _ = bounded_persist(&path, &cache, lease.clone(), Instant::now()).await;
    drop(lease);
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(lease) = acquire(&path).unwrap() {
            assert_eq!(read_record(&path).unwrap().retry_not_before, Some(floor));
            drop(lease);
            break;
        }
        assert!(
            Instant::now() < until,
            "floor commit did not release its lease"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let context = LocalUpdateContext {
        config_path: "/unused".into(),
        selected: json!({"ownership":"unmanaged"}),
        identity: None,
    };
    let result = TEST_TRANSPORT
        .scope(
            BTreeMap::new(),
            check_path(context, CheckTrigger::Explicit, until, path),
        )
        .await;
    assert_eq!(result["update"]["reason"], "source_retry_not_before");
    assert_eq!(result["success"], false);
}

#[tokio::test]
async fn unfinished_attempt_fails_closed_when_floor_commit_was_lost() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let lease = acquire(&path).unwrap().unwrap();
    persist(
        &path,
        &Record {
            format: 2,
            adoption: Some(test_adoption()),
            source: API.into(),
            outcome: "in_progress".into(),
            started_at: now() - INTERVAL * 2,
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease);
    let context = LocalUpdateContext {
        config_path: "/unused".into(),
        selected: json!({"ownership":"unmanaged"}),
        identity: None,
    };
    for trigger in [CheckTrigger::Explicit, CheckTrigger::Automatic] {
        let result = TEST_TRANSPORT
            .scope(
                BTreeMap::new(),
                check_path(
                    context.clone(),
                    trigger,
                    Instant::now() + Duration::from_secs(1),
                    path.clone(),
                ),
            )
            .await;
        assert_eq!(result["update"]["reason"], "previous_attempt_incomplete");
    }
}
