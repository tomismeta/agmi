use super::*;
fn fixture() -> (LocalUpdateContext, BTreeMap<String, Vec<u8>>) {
    let mut manifest = String::new();
    for key in IDENTITY_FIELDS {
        let value = match *key {
            "build_format" | "update_protocol" => "1".into(),
            "package_version" => "0.5.0".into(),
            "commit" => "a".repeat(40),
            "source_dirty" => "clean".into(),
            "target" => "x86_64-unknown-linux-musl".into(),
            "profile" => "release".into(),
            "journal_schema" => "4".into(),
            "stop_timeout" => "infinity".into(),
            _ => "b".repeat(64),
        };
        manifest.push_str(&format!("{key}={value}\n"));
    }
    manifest.push_str(&format!("binary_sha256={}\n", "c".repeat(64)));
    let published = Identity::parse(&manifest, true).unwrap();
    let mut current = published.clone();
    current.version = Version::parse("0.4.0").unwrap();
    current.commit = "d".repeat(40);
    current.digest = "e".repeat(64);
    let context = LocalUpdateContext {
        config_path: "/unused".into(),
        selected: json!({"ownership":"managed","root":"/release","release":"base"}),
        identity: Some(current),
    };
    let archive = "agmi-v0.5.0-x86_64-unknown-linux-musl.tar.gz";
    let sums = format!(
        "{:x}  BUILD-INFO.txt\n{}  {archive}\n",
        Sha256::digest(manifest.as_bytes()),
        "f".repeat(64)
    );
    let assets=[("SHA256SUMS",sums.len()),("BUILD-INFO.txt",manifest.len()),(archive,42)].map(|(name,size)|json!({"name":name,"size":size,"state":"uploaded","browser_download_url":format!("{DOWNLOAD}/v0.5.0/{name}")}));
    let mut responses = BTreeMap::new();
    responses.insert(format!("{API}/releases/latest"),serde_json::to_vec(&json!({"tag_name":"v0.5.0","draft":false,"prerelease":false,"published_at":"2026-01-01","assets":assets})).unwrap());
    responses.insert(format!("{DOWNLOAD}/v0.5.0/SHA256SUMS"), sums.into_bytes());
    responses.insert(
        format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt"),
        manifest.into_bytes(),
    );
    let base = context.identity.as_ref().unwrap().commit.clone();
    responses.insert(format!("{API}/compare/{base}...{}",published.commit),serde_json::to_vec(&json!({"url":format!("{API}/compare/{base}...{}",published.commit),"base_commit":{"sha":base},"merge_base_commit":{"sha":base},"status":"ahead","behind_by":0,"ahead_by":1})).unwrap());
    (context, responses)
}
#[tokio::test]
async fn higher_version_still_requires_exact_ancestry() {
    let (context, mut responses) = fixture();
    let client = Client::new();
    TEST_TRANSPORT
        .scope(responses.clone(), async {
            let publication = super::super::discover_publication(&client, true)
                .await
                .unwrap();
            assert_eq!(
                ordering(context.identity.as_ref().unwrap(), &publication.published),
                Ordering::Compare
            );
            assert_eq!(
                ancestry(
                    &client,
                    context.identity.as_ref().unwrap(),
                    &publication.published
                )
                .await
                .unwrap(),
                Ordering::Available
            );
        })
        .await;
    let compare = responses
        .keys()
        .find(|k| k.contains("/compare/"))
        .unwrap()
        .clone();
    responses.insert(compare, b"{}".to_vec());
    TEST_TRANSPORT
        .scope(responses, async {
            let publication = super::super::discover_publication(&client, true)
                .await
                .unwrap();
            assert!(
                ancestry(
                    &client,
                    context.identity.as_ref().unwrap(),
                    &publication.published
                )
                .await
                .is_err()
            );
        })
        .await;
}
#[tokio::test]
async fn checksum_failure_is_not_a_publication() {
    let (_, mut responses) = fixture();
    responses.insert(
        format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt"),
        b"untrusted".to_vec(),
    );
    TEST_TRANSPORT
        .scope(responses, async {
            assert!(
                super::super::discover_publication(&Client::new(), true)
                    .await
                    .is_err()
            );
        })
        .await;
}
#[test]
fn fail_closed_advisory_actions_require_inspection_not_another_check() {
    let (context, _) = fixture();
    assert_eq!(
        record_view(&context, None, 200)["next_action"]["kind"],
        "check"
    );
    for floor in [None, Some(500)] {
        let cache = Record {
            format: 2,
            adoption: Some(test_adoption()),
            source: API.into(),
            started_at: 100,
            outcome: "in_progress".into(),
            reason: "check_in_progress".into(),
            retry_not_before: floor,
            ..Default::default()
        };
        let view = record_view(&context, Some(&cache), 200);
        assert_eq!(view["next_action"]["kind"], "unavailable");
        assert_eq!(view["next_action"]["reason"], "previous_attempt_incomplete");
    }
    for reason in [
        "previous_attempt_incomplete",
        "advisory_record_missing",
        "advisory_record_invalid",
        "advisory_storage_unavailable",
        "advisory_persistence_failed",
        "legacy_source_unavailable",
        "legacy_source_conflict",
    ] {
        let report = report(&context, None, false, reason);
        assert_eq!(report["release_advisory"]["availability"], "unknown");
        assert_eq!(
            report["release_advisory"]["next_action"]["kind"],
            "unavailable"
        );
        assert_eq!(report["release_advisory"]["next_action"]["reason"], reason);
    }
    let busy = report(&context, None, false, "check_in_progress");
    assert_eq!(busy["release_advisory"]["next_action"]["kind"], "check");
}

#[test]
fn clock_regression_preserves_valid_failure_floors_and_last_good_then_recovers() {
    let (context, responses) = fixture();
    let manifest =
        String::from_utf8(responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone()).unwrap();
    let good = Good {
        checked_at: 100,
        context: context.key(),
        availability: "available".into(),
        reason: "verified".into(),
        manifest,
        tag: "v0.5.0".into(),
        archive_sha256: "f".repeat(64),
    };
    for (finished, checked) in [(199, 199), (201, 199), (199, 201)] {
        let home = tempfile::tempdir().unwrap();
        let path = test_record_path(home.path());
        let _lease = acquire(&path).unwrap().unwrap();
        let mut record = read_record(&path).unwrap();
        record.context = context.key();
        record.started_at = 200;
        record.outcome = "success".into();
        record.reason = "verified".into();
        record.attempt_id = "regressed".into();
        record.next_due_at = 1000;
        record.retry_not_before = Some(500);
        record.good = Some(good.clone());
        let mut observed = good.clone();
        observed.checked_at = checked;
        finish_attempt(&mut record, Some(observed), finished);
        persist(&path, &record).unwrap();
        let mut recovered = read_record(&path).unwrap();
        assert_eq!(recovered.finished_at, Some(finished));
        assert_eq!(recovered.reason, "clock_regressed");
        assert_eq!(recovered.outcome, "failure");
        assert_eq!(recovered.retry_not_before, Some(500));
        assert_eq!(recovered.good.as_ref().unwrap().checked_at, 100);
        assert_eq!(
            record_view(&context, Some(&recovered), 300)["availability"],
            "unknown"
        );

        let before = fs::read(&path).unwrap();
        record.finished_at = Some(199);
        record.reason = "release_query_failed".into();
        assert!(persist(&path, &record).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);

        recovered.started_at = 600;
        recovered.outcome = "success".into();
        recovered.reason = "verified".into();
        let mut observed = good.clone();
        observed.checked_at = 601;
        finish_attempt(&mut recovered, Some(observed), 602);
        persist(&path, &recovered).unwrap();
        let recovered = read_record(&path).unwrap();
        assert_eq!(recovered.retry_not_before, Some(500));
        assert_eq!(
            record_view(&context, Some(&recovered), 602)["availability"],
            "available"
        );
    }
}

#[test]
fn failed_attempt_future_clock_and_changed_base_do_not_offer_old_good() {
    let (context, responses) = fixture();
    let manifest =
        String::from_utf8(responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone()).unwrap();
    let good = Good {
        checked_at: 100,
        context: context.key(),
        availability: "available".into(),
        reason: "verified".into(),
        manifest,
        tag: "v0.5.0".into(),
        archive_sha256: "f".repeat(64),
    };
    let mut cache = Record {
        format: 2,
        adoption: Some(test_adoption()),
        source: API.into(),
        context: context.key(),
        started_at: 99,
        finished_at: Some(100),
        attempt_id: "one".into(),
        outcome: "success".into(),
        reason: "verified".into(),
        next_due_at: 1000,
        retry_not_before: None,
        good: Some(good),
    };
    assert_eq!(
        record_view(&context, Some(&cache), 200)["availability"],
        "available"
    );
    assert_eq!(
        record_view(&context, Some(&cache), 99)["availability"],
        "unknown"
    );
    cache.outcome = "failure".into();
    let view = record_view(&context, Some(&cache), 200);
    assert_eq!(view["availability"], "unknown");
    assert_eq!(view["last_good"]["checked_at"], 100);
    cache.outcome = "success".into();
    let mut other = context.clone();
    other.identity.as_mut().unwrap().commit = "1".repeat(40);
    assert_eq!(
        record_view(&other, Some(&cache), 200)["availability"],
        "unknown"
    );
    other.identity = Some(Identity::parse(&cache.good.as_ref().unwrap().manifest, true).unwrap());
    assert_eq!(
        record_view(&other, Some(&cache), 200)["availability"],
        "current"
    );
}
#[test]
fn canonical_check_reports_preserve_owner_specific_actions() {
    let (mut context, responses) = fixture();
    let stamp = now();
    let mut cache = Record {
        format: 2,
        adoption: Some(test_adoption()),
        source: API.into(),
        context: context.key(),
        started_at: stamp,
        finished_at: Some(stamp),
        outcome: "success".into(),
        next_due_at: stamp + INTERVAL,
        good: Some(Good {
            checked_at: stamp,
            context: context.key(),
            availability: "available".into(),
            reason: "verified".into(),
            manifest: String::from_utf8(
                responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone(),
            )
            .unwrap(),
            tag: "v0.5.0".into(),
            archive_sha256: "f".repeat(64),
        }),
        ..Default::default()
    };
    let managed = report(&context, Some(&cache), true, "verified");
    assert_eq!(managed["update"]["status"], "available");
    assert_eq!(
        managed["release_advisory"]["next_action"],
        json!({"kind":"update","argv":["agmi","update"]})
    );
    assert_eq!(
        managed["release_advisory"]["installability"],
        "not_assessed"
    );
    assert!(managed.get("installation").is_none());
    assert!(managed.get("readiness").is_none());
    context.selected["ownership"] = json!("unmanaged");
    cache.context = context.key();
    cache.good.as_mut().unwrap().context = context.key();
    let unmanaged = report(&context, Some(&cache), true, "verified");
    assert_eq!(unmanaged["update"]["status"], "available");
    assert_eq!(
        unmanaged["release_advisory"]["next_action"]["kind"],
        "use_install_owner"
    );
    let failed = report(&context, Some(&cache), false, "advisory_persistence_failed");
    assert_eq!(failed["release_advisory"]["availability"], "unknown");
    assert_eq!(
        failed["release_advisory"]["next_action"]["kind"],
        "unavailable"
    );
    let transient = report(&context, Some(&cache), false, "release_query_failed");
    assert_eq!(
        transient["release_advisory"]["next_action"]["kind"],
        "use_install_owner"
    );
    context.selected["ownership"] = json!("unavailable");
    let unavailable = report(&context, None, false, "managed_installation_unverified");
    assert_eq!(
        unavailable["release_advisory"]["next_action"]["kind"],
        "unavailable"
    );
}
#[tokio::test]
async fn explicit_busy_waits_for_new_completion_not_old_success() {
    let (mut context, responses) = fixture();
    context.selected["ownership"] = json!("unmanaged");
    let manifest =
        String::from_utf8(responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone()).unwrap();
    let stamp = now();
    let good = Good {
        checked_at: stamp,
        context: context.key(),
        availability: "available".into(),
        reason: "verified".into(),
        manifest,
        tag: "v0.5.0".into(),
        archive_sha256: "f".repeat(64),
    };
    let mut cache = Record {
        format: 2,
        adoption: Some(test_adoption()),
        source: API.into(),
        context: context.key(),
        started_at: stamp,
        finished_at: Some(stamp),
        attempt_id: "old".into(),
        outcome: "success".into(),
        reason: "verified".into(),
        next_due_at: stamp + INTERVAL,
        retry_not_before: None,
        good: Some(good),
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agmi/update.json");
    let lease = acquire(&path).unwrap().unwrap();
    persist(&path, &cache).unwrap();
    let result = check_path(
        context.clone(),
        CheckTrigger::Explicit,
        Instant::now() + Duration::from_millis(10),
        path.clone(),
    )
    .await;
    assert_eq!(result["success"], false);
    assert_eq!(result["update"]["reason"], "check_in_progress");
    cache.finished_at = None;
    cache.outcome = "in_progress".into();
    persist(&path, &cache).unwrap();
    let destination = path.clone();
    let completed = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.finished_at = Some(now());
        cache.outcome = "success".into();
        persist(&destination, &cache).unwrap();
        drop(lease);
    });
    let result = check_path(
        context,
        CheckTrigger::Explicit,
        Instant::now() + Duration::from_secs(1),
        path,
    )
    .await;
    completed.await.unwrap();
    assert_eq!(result["success"], true);
}
