use super::*;

#[test]
fn compiled_manifest_keeps_fixed_protocol_one_envelope() {
    let manifest = include_str!(env!("AGMI_BUILD_MANIFEST_PATH"));
    let published = format!("{manifest}binary_sha256={}\n", "a".repeat(64));
    verify_embedded_identity(manifest, &published).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires staged Linux publisher assets in AGMI_UPDATE_TEST_ASSETS"]
async fn staged_release_passes_protocol_one_updater_verification() -> Result<()> {
    let assets = std::path::PathBuf::from(
        std::env::var_os("AGMI_UPDATE_TEST_ASSETS").context("missing staged release assets")?,
    );
    let manifest = std::fs::read_to_string(assets.join("BUILD-INFO.txt"))?;
    let sums = std::fs::read_to_string(assets.join("SHA256SUMS"))?;
    verify(manifest.as_bytes(), &checksum(&sums, "BUILD-INFO.txt")?)?;
    let published = Identity::parse(&manifest, true)?;
    let archive = assets.join(format!(
        "agmi-v{}-{}.tar.gz",
        published.version, published.target
    ));
    let directory = tempfile::tempdir()?;
    let binary = directory.path().join("agmi");
    extract(File::open(archive)?, &binary, &manifest, &published.digest)?;
    embedded_identity(&binary, &manifest).await
}

#[test]
fn future_journal_keeps_fixed_embedded_protocol_one_envelope() {
    let mut manifest = String::new();
    for key in IDENTITY_FIELDS {
        let value = match *key {
            "build_format" | "update_protocol" => "1".to_owned(),
            "package_version" => "0.5.0".to_owned(),
            "commit" => "a".repeat(40),
            "source_dirty" => "clean".to_owned(),
            "target" => "x86_64-unknown-linux-musl".to_owned(),
            "profile" => "release".to_owned(),
            "journal_schema" => "5".to_owned(),
            "stop_timeout" => "infinity".to_owned(),
            _ => "b".repeat(64),
        };
        manifest.push_str(&format!("{key}={value}\n"));
    }
    let published = format!("{manifest}binary_sha256={}\n", "c".repeat(64));
    let future = Identity::parse(&published, true).unwrap();
    assert_eq!(future.update_protocol, 1);
    assert_eq!(
        ordering(&identity("0.4.0", 'd', false), &future),
        Ordering::Compare
    );
    assert!(verify_embedded_identity(&manifest, &published).is_ok());
    for changed in [
        manifest.replace("journal_schema=5", "journal_schema=4"),
        manifest.replace("journal_schema=5\n", ""),
        format!("{manifest}journal_schema=5\n"),
        format!("{manifest}future_field=private\n"),
    ] {
        assert!(verify_embedded_identity(&changed, &published).is_err());
    }
    for protocol in ["0", "2"] {
        let unsupported =
            published.replace("update_protocol=1", &format!("update_protocol={protocol}"));
        let unsupported = Identity::parse(&unsupported, true).unwrap();
        assert_eq!(
            ordering(&unsupported, &unsupported),
            Ordering::Refused("published_installer_protocol_unsupported")
        );
    }
}

#[test]
fn incoming_completion_preserves_restoration_and_future_journal_evidence() {
    for (maintenance, restoration, verified, expected, success) in [
        (false, "restored", true, "updated", true),
        (false, "not_needed", true, "updated", true),
        (true, "not_needed", true, "migration_complete_stopped", true),
        (false, "pending", false, "restoration_incomplete", false),
        (false, "failed", false, "restoration_incomplete", false),
        (false, "cancelled", false, "updated", true),
        (false, "restored", false, "restoration_incomplete", false),
    ] {
        let options = Options {
            migrate: maintenance,
            ..options()
        };
        let mut report = report(&options, "test");
        let child = json!({
            "installation":{"failure_code":"none"},
            "compatibility":{"classification":"conversion","migration_required":true,
                "target_journal_format":5},
            "migration":{"phase":"complete","target_journal_format":5,
                "participation_resumed":!maintenance},
            "restoration":{"status":restoration,"runtime":"running","timer":"stopped",
                "pause_state":"unpaused","verified":verified,"secret":"private-restoration"}
        });
        installer_outcome(&mut report, &child, true, false, false);
        assert_eq!(report["update"]["status"], expected);
        assert_eq!(report["success"], success);
        assert_eq!(report["compatibility"]["target_journal_format"], 5);
        assert_eq!(report["migration"]["target_journal_format"], 5);
        assert_eq!(report["migration"]["participation_resumed"], !maintenance);
        assert_eq!(report["restoration"]["status"], restoration);
        assert_eq!(report["restoration"]["verified"], verified);
        assert!(!report.to_string().contains("private-restoration"));
        assert!(report["readiness"].is_null());
    }
}

#[test]
fn cancelled_restoration_distinguishes_completed_upgrade_from_recovery() {
    for (phase, failure_code, succeeded, expected) in [
        ("complete", "none", true, "updated"),
        ("not_required", "none", true, "updated"),
        ("required", "recovery_required", false, "recovery_required"),
        ("complete", "recovery_required", false, "recovery_required"),
        ("complete", "none", false, "restoration_incomplete"),
    ] {
        let mut report = report(&options(), "test");
        installer_outcome(
            &mut report,
            &json!({"installation":{"failure_code":failure_code,
                "service":"previous_intent_restored"},
                "migration":{"phase":phase},
                "restoration":{"status":"cancelled","verified":false,
                    "runtime":"stopped","timer":"stopped","pause_state":"paused"}}),
            succeeded,
            false,
            false,
        );
        assert_eq!(report["update"]["status"], expected);
        assert_eq!(report["success"], succeeded);
        assert_eq!(report["restoration"]["status"], "cancelled");
        assert_eq!(report["restoration"]["verified"], false);
        assert_ne!(
            report["installation"]["service"],
            "previous_intent_restored"
        );
        if succeeded {
            assert_eq!(
                report["update"]["reason"],
                "installer_completed_restoration_cancelled"
            );
        }
    }
}

#[test]
fn incoming_decisions_conflicts_and_current_are_not_generic_success() {
    for (status, success) in [
        ("decision_required", false),
        ("conflict", false),
        ("restoration_incomplete", false),
        ("recovery_required", false),
        ("current", true),
    ] {
        let mut report = report(&options(), "test");
        installer_outcome(&mut report, &json!({"status":status}), true, false, false);
        assert_eq!(report["update"]["status"], status);
        assert_eq!(report["success"], success);
    }
}

#[test]
fn pending_target_rejects_retargeting_without_replacing_approval() {
    let target = format!("r-{}", "a".repeat(64));
    let other = format!("r-{}", "b".repeat(64));
    let token = format!("agmi.atomic-migration.v1:{}", "c".repeat(64));
    assert!(validate_pending_target(&options(), &target).is_ok());
    let mut continuation = Options {
        release: Some(&target),
        expected_token: Some(&token),
        accept_risk_change: Some(&token),
        ..options()
    };
    assert!(validate_pending_target(&continuation, &target).is_ok());
    continuation.release = Some(&other);
    let error = validate_pending_target(&continuation, &target).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<lifecycle::LifecycleError>()
            .unwrap()
            .code,
        "update_pending_target_conflict"
    );
    continuation.release = None;
    continuation.binary = Some(Path::new("/not-executed"));
    continuation.sha256 = other.strip_prefix("r-");
    assert!(validate_pending_target(&continuation, &target).is_err());
    continuation.sha256 = target.strip_prefix("r-");
    assert!(validate_pending_target(&continuation, &target).is_ok());
}

fn options<'a>() -> Options<'a> {
    Options {
        release: None,
        binary: None,
        sha256: None,
        check: false,
        dry_run: false,
        repair: false,
        stopped: false,
        migration_only: false,
        migrate: false,
        proposal: None,
        expected_token: None,
        accept_risk_change: None,
        expected_release: None,
    }
}

#[test]
fn installer_contract_preserves_phases_without_private_child_leaks() {
    for (phase, success, expected) in [
        ("not_required", true, "updated"),
        ("required", false, "migration_required"),
        ("prepared", true, "decision_required"),
        ("complete", true, "updated"),
        ("complete", false, "failed"),
        ("recovery_required", false, "recovery_required"),
        ("journal_ready", false, "recovery_required"),
        ("failed", false, "failed"),
    ] {
        let mut report = report(&options(), "test");
        let child = json!({
            "installation":{"activation":"loaded_verified","service":"stopped",
                "failure_code":if success {"none"} else {"migration_failed"},
                "message":"private-child-message"},
            "compatibility":{"classification":"conversion","migration_required":true,
                "target_journal_format":crate::journal::CURRENT_JOURNAL_FORMAT,"raw":"private-config"},
            "migration":{"phase":phase,"token":format!("agmi.atomic-migration.v1:{}", "a".repeat(64)),"release_id":format!("r-{}", "b".repeat(64)),
                "participation_resumed":true,"candidate_toml":"private-candidate"},
            "private":true,"preview":{"request":{"candidate_toml":"private-preview"}},
            "output":"private-child-output",
        });
        installer_outcome(&mut report, &child, success, false, false);
        assert_eq!(report["update"]["status"], expected, "{phase}");
        assert_eq!(
            report["success"],
            success && !matches!(phase, "required" | "prepared")
        );
        assert_eq!(report["migration"]["phase"], phase);
        assert_eq!(report["migration"]["participation_resumed"], true);
        assert_eq!(
            report["migration"]["token"],
            format!("agmi.atomic-migration.v1:{}", "a".repeat(64))
        );
        assert_eq!(report["compatibility"]["classification"], "conversion");
        assert!(report["readiness"].is_null());
        assert!(report.get("preview").is_none());
        assert!(!report.to_string().contains("private-"));
    }
}

#[test]
fn historical_completion_keeps_followup_prerequisites_without_private_text() {
    for (further, prerequisite, expected) in [
        (true, Value::Null, "recovery_required"),
        (false, json!("authority_adoption"), "recovery_required"),
        (false, Value::Null, "updated"),
    ] {
        let mut report = report(&options(), "test");
        let child = json!({"installation":{"failure_code":"none"},
            "migration":{"phase":"complete","pending":false,"target_journal_format":4,
                "further_migration_required":further,"recovery_prerequisite":prerequisite}});
        installer_outcome(&mut report, &child, true, false, false);
        assert_eq!(report["update"]["status"], expected);
        assert_eq!(report["success"], expected == "updated");
        assert_eq!(report["migration"]["pending"], false);
        assert_eq!(report["migration"]["recovery_prerequisite"], prerequisite);
    }
    let mut report = report(&options(), "test");
    installer_outcome(
        &mut report,
        &json!({"migration":{"phase":"complete",
        "recovery_prerequisite":"private-unbounded-instruction"}}),
        true,
        false,
        false,
    );
    assert!(!report.to_string().contains("private-unbounded-instruction"));
}

#[test]
fn private_preview_is_only_explicit_successful_preparation() {
    let child = json!({"installation":{"failure_code":"none"},
        "migration":{"phase":"prepared"},"private":true,
        "preview":{"request":{"candidate_toml":"private-preview"}}});
    let mut prepared = report(&options(), "test");
    installer_outcome(&mut prepared, &child, true, false, true);
    assert_eq!(prepared["private"], true);
    assert_eq!(prepared["preview"], child["preview"]);
    assert_eq!(prepared["success"], false);
    assert_eq!(prepared["update"]["status"], "decision_required");
    let mut decision = child.clone();
    decision["migration"]["phase"] = json!("decision_required");
    installer_outcome(&mut prepared, &decision, true, false, true);
    assert_eq!(prepared["private"], true);
    assert_eq!(prepared["preview"], child["preview"]);
    assert_eq!(prepared["success"], false);
    for (success, dry_run, explicit) in [
        (false, false, true),
        (true, true, true),
        (true, false, false),
    ] {
        let mut report = report(&options(), "test");
        installer_outcome(&mut report, &child, success, dry_run, explicit);
        assert!(report.get("preview").is_none());
        assert!(!report.to_string().contains("private-preview"));
        if dry_run {
            assert_eq!(report["compatibility"]["classification"], "not_assessed");
            assert_eq!(report["migration"]["phase"], "unknown");
        }
    }
}

#[test]
fn proposal_transport_is_owned_private_file_never_json_argv() {
    let proposal = json!({"candidate_toml":"private-proposal-body"});
    let mut options = options();
    options.proposal = Some(&proposal);
    let token = format!("agmi.atomic-migration.v1:{}", "c".repeat(64));
    options.expected_token = Some(&token);
    options.accept_risk_change = Some(&token);
    let mut arguments = vec!["activate".into(), format!("r-{}", "a".repeat(64))];
    let file = migration_arguments(&options, &mut arguments)
        .unwrap()
        .unwrap();
    let path = file.path().to_owned();
    assert!(!arguments.join(" ").contains("private-proposal-body"));
    assert!(!arguments.iter().any(|argument| argument == "-"));
    assert!(!arguments.iter().any(|argument| argument == "--migrate"));
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["--expected-token", token.as_str()])
    );
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["--accept-risk-change", token.as_str()])
    );
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), proposal);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            file.as_file().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(file);
    assert!(!path.exists());
    options.dry_run = true;
    let mut arguments = Vec::new();
    assert!(
        migration_arguments(&options, &mut arguments)
            .unwrap()
            .is_none()
    );
    assert!(!arguments.iter().any(|argument| argument == "--proposal"));
}

#[tokio::test]
async fn check_rejects_private_proposal_before_discovery() {
    let proposal = json!({});
    let error = run(
        Path::new("/not-read"),
        Options {
            check: true,
            proposal: Some(&proposal),
            ..options()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<lifecycle::LifecycleError>()
            .unwrap()
            .code,
        "update_invalid_arguments"
    );
}

#[tokio::test]
async fn token_continuation_never_resolves_latest_or_accepts_unpinned_source() {
    let digest = "a".repeat(64);
    let token = format!("agmi.atomic-migration.v1:{digest}");
    for (release, binary, migrate, risk) in [
        (None, None, true, None),
        (None, Some(Path::new("/missing")), true, None),
        (Some("r-invalid"), None, true, Some("different")),
    ] {
        let result = run(
            Path::new("/missing"),
            Options {
                release,
                binary,
                migrate,
                expected_token: Some(&token),
                accept_risk_change: risk,
                sha256: binary.map(|_| digest.as_str()),
                ..options()
            },
        )
        .await;
        let error = result.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<lifecycle::LifecycleError>()
                .unwrap()
                .code,
            "update_invalid_arguments"
        );
        assert!(!error.to_string().contains("different"));
    }
}

#[test]
fn published_metadata_requires_stable_tag_fixed_origin_and_bounded_assets() {
    let mut release = Release {
        tag_name: "v0.2.0".into(),
        draft: false,
        prerelease: false,
        published_at: Some("published".into()),
        assets: vec![Asset {
            name: "BUILD-INFO.txt".into(),
            size: 857,
            state: "uploaded".into(),
            browser_download_url: format!("{DOWNLOAD}/v0.2.0/BUILD-INFO.txt"),
        }],
    };
    assert_eq!(release.version().unwrap(), Version::new(0, 2, 0));
    assert!(release.asset("BUILD-INFO.txt", TEXT_LIMIT).is_ok());
    release.assets[0].browser_download_url = "https://example.invalid/BUILD-INFO.txt".into();
    assert!(release.asset("BUILD-INFO.txt", TEXT_LIMIT).is_err());
    release.assets[0].browser_download_url = format!("{DOWNLOAD}/v0.2.0/BUILD-INFO.txt");
    release.assets[0].size = TEXT_LIMIT as u64 + 1;
    assert!(release.asset("BUILD-INFO.txt", TEXT_LIMIT).is_err());
    release.prerelease = true;
    assert!(release.version().is_err());
    release.prerelease = false;
    release.tag_name = "v0.2.0-rc.1".into();
    assert!(release.version().is_err());
    release.tag_name = "../v0.2.0".into();
    assert!(release.version().is_err());
}

#[test]
fn ancestry_requires_an_actual_descendant_not_just_a_release_tag() {
    let current = identity("0.1.0", 'a', false);
    let published = identity("0.2.0", 'b', false);
    let evidence = |status: &str, base: &str, merge: &str, ahead: u64, behind: u64| {
        serde_json::to_vec(
            &json!({"url":format!("{API}/compare/{}...{}", current.commit, published.commit),
            "status":status,"base_commit":{"sha":base},
            "merge_base_commit":{"sha":merge},"ahead_by":ahead,"behind_by":behind}),
        )
        .unwrap()
    };
    assert_eq!(
        ancestry_result(
            &evidence("ahead", &current.commit, &current.commit, 1, 0),
            &current,
            &published
        )
        .unwrap(),
        Ordering::Available
    );
    assert_eq!(
        ancestry_result(
            &evidence("behind", &current.commit, &"b".repeat(40), 0, 1),
            &current,
            &published
        )
        .unwrap(),
        Ordering::Current("installed_commit_newer")
    );
    assert_eq!(
        ancestry_result(
            &evidence("diverged", &current.commit, &"b".repeat(40), 1, 1),
            &current,
            &published
        )
        .unwrap(),
        Ordering::Refused("commit_ordering_unverified")
    );
    assert_eq!(
        ancestry_result(
            &evidence("ahead", &current.commit, &"b".repeat(40), 1, 0),
            &current,
            &published
        )
        .unwrap(),
        Ordering::Refused("commit_ordering_unverified")
    );
    assert!(
        ancestry_result(
            &evidence("ahead", &"c".repeat(40), &current.commit, 1, 0),
            &current,
            &published
        )
        .is_err()
    );
    let bytes = evidence("ahead", &current.commit, &current.commit, 1, 0);
    assert!(ancestry_result(&bytes, &current, &identity("0.2.0", 'c', false)).is_err());
    let mut missing: Value = serde_json::from_slice(&bytes).unwrap();
    missing.as_object_mut().unwrap().remove("url");
    assert!(ancestry_result(&serde_json::to_vec(&missing).unwrap(), &current, &published).is_err());
}

#[test]
fn changed_selection_discards_readiness_without_erasing_repair_effects() {
    let before = installer::InstalledIdentity {
        manifest: String::new(),
        binary: Path::new("/not-executed").into(),
        release: format!("r-{}", "a".repeat(64)),
        digest: "a".repeat(64),
    };
    let after = installer::InstalledIdentity {
        manifest: String::new(),
        binary: Path::new("/not-executed").into(),
        release: format!("r-{}", "b".repeat(64)),
        digest: "b".repeat(64),
    };
    let initial = json!({"success":true,"update":{},"readiness":{"healthy":true},
        "repair":{"status":"applied","applied_count":1}});
    let mut report = initial.clone();
    qualify_diagnosis(&mut report, &before, Some(&before));
    assert_eq!(report["update"]["doctor_status"], "complete");
    assert_eq!(report["readiness"]["release"], before.release);
    for observed in [None, Some(&after)] {
        let mut report = initial.clone();
        qualify_diagnosis(&mut report, &before, observed);
        assert!(report["readiness"].is_null());
        assert_eq!(report["update"]["doctor_status"], "stale");
        assert_eq!(report["update"]["doctor_release"], before.release);
        assert_eq!(report["repair"]["applied_count"], 1);
        assert_eq!(report["repair"]["status"], "applied");
    }
}

#[test]
fn readiness_preserves_intervention_but_drops_unbounded_strings() {
    let options = Options {
        release: None,
        binary: None,
        sha256: None,
        check: false,
        dry_run: false,
        repair: false,
        stopped: false,
        migration_only: false,
        migrate: false,
        proposal: None,
        expected_token: None,
        accept_risk_change: None,
        expected_release: None,
    };
    let mut result = report(&options, "test");
    let data = json!({"healthy":false,"intervention":{"status":"operator_required",
        "reason":"admission_paused","next_action":"resume","unattended":false,
        "controller":{"ready":true,"reason":"controller_recent"},
        "lanes":{"answer":"operator_required"}},"work":{"answer":{"progress":"blocked",
        "intervention":{"status":"operator_required","reason":"secret-response-body",
            "next_action":"https://credential@example.invalid"}}}});
    doctor_outcome(&mut result, &data, false, false);
    assert_eq!(result["readiness"]["intervention"]["unattended"], false);
    assert_eq!(
        result["readiness"]["intervention"]["controller"]["ready"],
        true
    );
    assert_eq!(
        result["readiness"]["work"]["answer"]["intervention"]["status"],
        "operator_required"
    );
    assert_eq!(
        result["readiness"]["work"]["judge"]["progress"],
        "undetermined"
    );
    assert_eq!(
        result["readiness"]["work"]["judge"]["continuation"]["state"],
        "unknown"
    );
    assert!(result["readiness"]["work"]["judge"]["automatic_step"].is_null());
    assert!(!result.to_string().contains("secret-response-body"));
    assert!(!result.to_string().contains("credential"));
}

#[test]
fn legacy_child_boolean_neither_verifies_nor_rejects_identity() {
    for verified in [false, true] {
        let data = json!({"initialized":true,"hosted_identity_verified":verified});
        let mut report = json!({"success":true});
        doctor_outcome(&mut report, &data, false, false);
        let identity = &report["readiness"]["hosted_identity"];
        assert_eq!(identity["status"], "legacy_unknown");
        assert_eq!(identity["rejection"], Value::Null);
        assert_eq!(identity["legacy_failure"], !verified);
        assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
    }
}

#[test]
fn legacy_child_identity_is_uncertain_without_hiding_independent_operator_work() {
    let old = json!({"status":"operator_required","reason":"hosted_identity_unverified",
        "next_action":"review_credentials","unattended":false});
    let mut data = json!({"initialized":true,"hosted_identity_verified":false,
        "intervention":old,"work":{}});
    for lane in ["answer", "judge", "mine"] {
        data["work"][lane]["intervention"] = old.clone();
        data["intervention"]["lanes"][lane] = json!("operator_required");
    }
    let mut report = json!({"success":true});
    doctor_outcome(&mut report, &data, false, false);
    let readiness = &report["readiness"];
    assert_eq!(readiness["hosted_identity"]["status"], "legacy_unknown");
    assert_eq!(readiness["hosted_identity_verified"], Value::Null);
    assert_eq!(readiness["intervention"]["status"], "undetermined");
    assert_eq!(readiness["intervention"]["unattended"], Value::Null);
    assert_eq!(
        readiness["intervention"]["next_action"],
        "inspect_local_evidence"
    );
    for lane in ["answer", "judge", "mine"] {
        assert_eq!(readiness["intervention"]["lanes"][lane], "undetermined");
        assert_ne!(
            readiness["work"][lane]["intervention"]["next_action"],
            "review_credentials"
        );
    }
    data["work"]["judge"]["intervention"] = json!({"status":"operator_required",
        "reason":"model_authentication_failed","next_action":"review_model_configuration"});
    doctor_outcome(&mut report, &data, false, false);
    assert_eq!(
        report["readiness"]["intervention"]["status"],
        "operator_required"
    );
    assert_eq!(report["readiness"]["intervention"]["unattended"], false);
    assert_eq!(
        report["readiness"]["intervention"]["reason"],
        "model_authentication_failed"
    );
    assert_eq!(
        report["readiness"]["intervention"]["next_action"],
        "review_model_configuration"
    );
}

#[test]
fn identity_repairs_survive_without_operation_ids_and_remain_bounded() {
    let identity = json!({"kind":"identity","classification":"legacy_identity_evidence_normalization",
        "evidence":"private-evidence","credential":"private-credential"});
    let data = json!({"healthy":false,"initialized":true,"repair_requested":true,
        "repair_outcome":"applied",
        "hosted_identity":{"status":"legacy_unknown","observed_at":100,
            "last_verified_at":null,"rejection":null,"legacy_failure":true,
            "raw":"private-upstream-body"},
        "intervention":{"status":"undetermined","reason":"hosted_identity_legacy_unknown",
            "next_action":"inspect_local_evidence"},
        "repairs":{"counts":{"eligible":3,"ineligible":1,"applied":2,"skipped":1},
            "eligible":[identity.clone()],"ineligible":[identity.clone()],
            "applied":[identity.clone(),{"operation_id":7,"kind":"answer",
                "classification":"submit_429_pre_enqueue"}],
            "skipped":[identity],"failure":null,"restoration":{"verified":true}}});
    let mut report = json!({"success":true,"update":{},"repair":{}});
    doctor_outcome(&mut report, &data, true, false);
    assert_eq!(report["success"], true);
    assert_eq!(report["repair"]["status"], "applied");
    assert_eq!(report["repair"]["applied_count"], 2);
    assert_eq!(report["repair"]["applied"][1]["operation_id"], 7);
    assert_eq!(
        report["readiness"]["hosted_identity"]["legacy_failure"],
        true
    );
    assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
    assert_eq!(
        report["readiness"]["intervention"]["reason"],
        "hosted_identity_legacy_unknown"
    );
    assert!(!report.to_string().contains("private-"));

    let mut data = data;
    data["hosted_identity"]["status"] = json!("unavailable");
    data["hosted_identity"]["rejection"] = json!("authentication_failed");
    data["intervention"] = json!({"status":"operator_required",
        "reason":"hosted_identity_authentication_failed","next_action":"review_credentials"});
    doctor_outcome(&mut report, &data, true, false);
    assert_eq!(report["readiness"]["hosted_identity_verified"], false);
    assert_eq!(
        report["readiness"]["intervention"]["reason"],
        "hosted_identity_authentication_failed"
    );
    data["hosted_identity"]["rejection"] = Value::Null;
    data["intervention"] = json!({"status":"automatic_recovery",
        "reason":"hosted_identity_unavailable","next_action":"await_identity","next_at":120});
    doctor_outcome(&mut report, &data, true, false);
    assert_eq!(
        report["readiness"]["intervention"]["next_action"],
        "await_identity"
    );
    assert_eq!(report["readiness"]["intervention"]["next_at"], 120);
    assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
    // New evidence can make the proposed repair unnecessary without making
    // the update fail or manufacturing successful identity verification.
    data["repair_outcome"] = json!("skipped");
    data["repairs"]["applied"] = json!([]);
    data["repairs"]["counts"] = json!({"eligible":1,"ineligible":1,"applied":0,"skipped":1});
    data["repairs"]["skipped"][0]["reason"] = json!("identity_evidence_changed");
    doctor_outcome(&mut report, &data, true, false);
    assert_eq!(report["success"], true);
    assert_eq!(report["repair"]["status"], "skipped");
    assert_eq!(
        report["repair"]["skipped"][0]["reason"],
        "identity_evidence_changed"
    );
    assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
}

#[test]
fn legacy_repair_counts_are_exact_even_with_truncated_or_omitted_rows() {
    let mut data = json!({"repair_requested":true,"repair_outcome":"applied","repairs":{
        "failure":null,"counts":{"eligible":513,"ineligible":700,"applied":510,"skipped":3},
        "eligible":[{"operation_id":1},{"operation_id":2},{"operation_id":3},{"operation_id":4}],
        "applied":[{"operation_id":1}],
    }});
    let repair = repair_receipt(&data);
    assert_eq!(repair["status"], "applied");
    assert_eq!(repair["eligible_count"], 513);
    assert_eq!(repair["ineligible_count"], 700);
    assert_eq!(repair["applied_count"], 510);
    assert_eq!(repair["skipped_count"], 3);
    assert_eq!(repair["details_truncated"], true);

    // Arrays cannot supply even one total when the scalar object is not
    // complete and well-typed.
    for counts in [
        Value::Null,
        json!({"eligible":513,"ineligible":700,"applied":510}),
        json!({"eligible":513,"ineligible":700,"applied":"510","skipped":3}),
        json!({"eligible":513,"ineligible":700,"applied":510,"skipped":-1}),
        json!({"eligible":513,"ineligible":700,"applied":510.0,"skipped":3}),
    ] {
        data["repairs"]["counts"] = counts;
        let repair = repair_receipt(&data);
        assert_eq!(repair["receipt_status"], "unavailable");
        assert_eq!(repair["outcome"], "unknown");
        for key in doctor::REPAIR_ARRAYS {
            assert_eq!(repair[format!("{key}_count")], Value::Null);
        }
        assert_eq!(repair["applied"][0]["operation_id"], 1);
    }
}

#[test]
fn successful_repair_requires_every_result_and_an_exact_total() {
    for (outcome, counts, execution) in [
        ("applied", [Some(5), Some(2), Some(1), Some(0)], "complete"),
        ("skipped", [Some(5), Some(2), Some(0), Some(1)], "complete"),
        ("applied", [Some(5), Some(2), Some(4), Some(2)], "complete"),
        (
            "applied",
            [Some(u64::MAX), Some(0), Some(u64::MAX), Some(1)],
            "complete",
        ),
        ("applied", [Some(5), Some(2), Some(1), None], "complete"),
        ("applied", [Some(5), None, Some(1), Some(4)], "complete"),
        ("applied", [Some(5), Some(2), Some(1), Some(4)], "partial"),
        (
            "applied",
            [Some(5), Some(2), Some(1), Some(4)],
            "not_started",
        ),
        (
            "applied",
            [Some(5), Some(2), Some(1), Some(4)],
            "not_needed",
        ),
        (
            "no_eligible_repairs",
            [Some(0), Some(2), Some(0), Some(0)],
            "not_started",
        ),
        ("skipped", [Some(5), Some(2), Some(1), Some(4)], "complete"),
    ] {
        let [eligible, ineligible, applied, skipped] = counts;
        let repair = repair_receipt(&json!({
            "repair_requested":true,"repair_outcome":outcome,"repairs":{
                "failure":null,"execution":execution,"counts":{
                    "eligible":eligible,"ineligible":ineligible,"applied":applied,"skipped":skipped
                }
            }
        }));
        assert_eq!(repair["receipt_status"], "unavailable", "{repair}");
        assert_eq!(repair["outcome"], "unknown");
        assert_eq!(repair["applied_count"], json!(applied));
        assert_eq!(repair["execution"], execution);
    }
}

#[test]
fn unavailable_receipt_only_forwards_readiness_inspection() {
    let actions = json!([
        {"kind":"command","disposition":"inspect","argv":["agmi","resume"],"authorization_required":true},
        {"kind":"command","disposition":"repair","argv":["agmi","doctor","--repair"],"authorization_required":true},
        {"kind":"wait","until":120,"clock":"unix_seconds","authorization_required":false},
        {"kind":"command","disposition":"inspect","argv":["agmi","operations","list"],"authorization_required":false},
    ]);
    let mut data = json!({"healthy":false,"repair_requested":true,"repair_outcome":"applied",
        "repairs":{"failure":null,"eligible":[{"operation_id":7}],"applied":[{"operation_id":7}]},
        "next_actions":actions,"intervention":{"status":"operator_required","next_action":"resume"},
        "work":{"answer":{"next_actions":actions}}});
    for counts in [
        None,
        Some(json!({"eligible":1,"ineligible":0,"applied":1})),
        Some(json!({"eligible":1,"ineligible":0,"applied":"1","skipped":0})),
        Some(json!({"eligible":5,"ineligible":0,"applied":1,"skipped":0})),
    ] {
        if let Some(counts) = counts {
            data["repairs"]["counts"] = counts;
        }
        let mut report = json!({"success":true});
        doctor_outcome(&mut report, &data, true, true);
        assert_eq!(report["success"], false);
        assert_eq!(report["repair"]["receipt_status"], "unavailable");
        assert_eq!(report["repair"]["outcome"], "unknown");
        assert_eq!(report["repair"]["applied"][0]["operation_id"], 7);
        let readiness = &report["readiness"];
        assert_eq!(readiness["intervention"]["status"], "operator_required");
        let allowed = json!([actions[3]]);
        assert_eq!(readiness["next_actions"], allowed);
        assert_eq!(readiness["work"]["answer"]["next_actions"], allowed);
    }
}

#[test]
fn read_observation_preserves_producer_floor_kind() {
    for kind in [
        "operation_poll",
        "reconciliation_service",
        "historical_missing_binding",
        "server_restriction",
        "local_backoff",
        "retained_floor",
        "shared_restriction",
    ] {
        let observation = safe_observation(&json!({"floor_kind":kind,"not_before":120}));
        assert_eq!(observation["floor_kind"], kind);
        assert_eq!(observation["not_before"], 120);
    }
    let observation = safe_observation(&json!({"floor_kind":"unrecognized"}));
    assert!(observation["floor_kind"].is_null());
}

#[test]
fn typed_readiness_keeps_independent_step_and_rejects_untyped_argv() {
    let data = json!({"healthy":false,"intervention":{"owner":"judge",
        "controller":{"owner":"managed","run_mode":"continuous","state":"running"}},
        "work":{"answer":{"assessment":{"completeness":"single_challenge","observed_opportunities":1}},
            "judge":{"progress":"private-legacy-progress",
            "intent":{"requested_mode":"active","effective_mode":"read_only","configuration":"pending","paused":false},
            "assessment":{"observed_at":20,"valid_until":80,"completeness":"complete",
                "exclusions":{"model_budget_exhausted":3,"private-unknown":4}},
            "continuation":{"state":"unknown","target":"submission","reason":"account_uncertainty",
                "condition":"admission_fenced"},
            "automatic_step":{"state":"waiting_automatically","target":"preparation","reason":"model_retry_backoff",
                "operation_id":17,"not_before":40,"condition":"retry_eligibility","job_id":"private-job"},
            "next_actions":[{"kind":"command","disposition":"inspect","authorization_required":false,
                "argv":["agmi","--config","/private-config","status"]},
                {"kind":"command","disposition":"inspect","authorization_required":false,
                "argv":["agmi","operations","list"]}]}}});
    let mut report = json!({"success":true});
    doctor_outcome(&mut report, &data, false, false);
    let readiness = &report["readiness"];
    assert_eq!(readiness["intervention"]["owner"], "judge");
    assert_eq!(
        readiness["intervention"]["controller"]["run_mode"],
        "continuous"
    );
    let judge = &readiness["work"]["judge"];
    assert_eq!(judge["progress"], "undetermined");
    assert_eq!(judge["continuation"]["condition"], "admission_fenced");
    assert_eq!(judge["automatic_step"]["target"], "preparation");
    assert_eq!(judge["automatic_step"]["not_before"], 40);
    let answer_assessment = &readiness["work"]["answer"]["assessment"];
    assert_eq!(answer_assessment["completeness"], "single_challenge");
    assert_eq!(answer_assessment["observed_opportunities"], 1);
    assert_eq!(
        judge["assessment"]["exclusions"],
        json!({"model_budget_exhausted":3})
    );
    assert!(judge["next_actions"][0]["argv"].is_null());
    assert_eq!(
        judge["next_actions"][1]["argv"],
        json!(["agmi", "operations", "list"])
    );
    assert!(!report.to_string().contains("private-"));
}

fn identity(version: &str, commit: char, dirty: bool) -> Identity {
    Identity {
        version: Version::parse(version).unwrap(),
        commit: commit.to_string().repeat(40),
        dirty,
        target: "x86_64-unknown-linux-musl".into(),
        digest: commit.to_string().repeat(64),
        update_protocol: 1,
    }
}
#[test]
fn never_replace_newer_dirty_or_same_commit_different_build() {
    let published = identity("0.1.0", 'a', false);
    assert_eq!(
        ordering(&identity("0.2.0", 'b', false), &published),
        Ordering::Current("installed_version_newer")
    );
    assert_eq!(
        ordering(&identity("0.1.0", 'b', true), &published),
        Ordering::Refused("installed_dirty_build_preserved")
    );
    assert_eq!(
        ordering(&identity("0.1.0", 'b', false), &published),
        Ordering::Compare
    );
    assert_eq!(
        ordering(&identity("0.0.1", 'b', false), &published),
        Ordering::Compare
    );
    let mut rebuilt = published.clone();
    rebuilt.digest = "b".repeat(64);
    assert_eq!(
        ordering(&rebuilt, &published),
        Ordering::Refused("same_commit_different_build_preserved")
    );
}
#[test]
fn incompatible_incoming_installer_is_never_offered_for_activation() {
    let current = identity("0.1.0", 'a', false);
    let mut published = identity("0.2.0", 'b', false);
    for protocol in [0, 2] {
        published.update_protocol = protocol;
        assert_eq!(
            ordering(&current, &published),
            Ordering::Refused("published_installer_protocol_unsupported")
        );
    }
    published.update_protocol = 1;
    assert_eq!(ordering(&current, &published), Ordering::Compare);
}
#[test]
fn redirect_allowlist_requires_exact_https_asset_hosts_and_paths() {
    for url in [
        "http://release-assets.githubusercontent.com/github-production-release-asset/a",
        "https://evil.example/github-production-release-asset/a",
        "https://release-assets.githubusercontent.com.evil.example/github-production-release-asset/a",
        "https://user@release-assets.githubusercontent.com/github-production-release-asset/a",
        "https://release-assets.githubusercontent.com:444/github-production-release-asset/a",
        "https://github.com/tomismeta/agmi/releases/download/v0.1.0/agmi",
        "https://release-assets.githubusercontent.com/other/a",
        "https://objects.githubusercontent.com/github-production-release-asset-nothex!/a",
    ] {
        assert!(!asset_redirect(&Url::parse(url).unwrap()));
    }
    assert!(asset_redirect(&Url::parse("https://release-assets.githubusercontent.com/github-production-release-asset/1/2?signature=opaque").unwrap()));
    assert!(asset_redirect(&Url::parse("https://objects.githubusercontent.com/github-production-release-asset-2e65be/1234?X-Amz-Signature=abc").unwrap()));
}
#[test]
fn checksum_rejects_duplicate_malformed_and_mismatching_entries() {
    let digest = format!("{:x}", Sha256::digest(b"hello"));
    let sums = format!("{digest}  BUILD-INFO.txt\n");
    assert_eq!(checksum(&sums, "BUILD-INFO.txt").unwrap(), digest);
    assert!(checksum(&(sums.clone() + &sums), "BUILD-INFO.txt").is_err());
    assert!(checksum("invalid", "BUILD-INFO.txt").is_err());
    assert!(checksum(&sums, "agmi").is_err());
    assert!(verify(b"changed", &digest).is_err());
}
#[test]
fn manifest_requires_schema_target_digest_and_unique_identity() {
    let manifest = format!(
        "{}binary_sha256={}\n",
        include_str!(env!("AGMI_BUILD_MANIFEST_PATH")),
        "a".repeat(64)
    );
    for schema in ["1", "2", "3", "5", "4294967295"] {
        let future = manifest.replace(
            &format!("journal_schema={}", crate::journal::CURRENT_JOURNAL_FORMAT),
            &format!("journal_schema={schema}"),
        );
        assert!(Identity::parse(&future, false).is_ok());
    }
    for schema in ["0", "-1", "+5", "4294967296", "five"] {
        let invalid = manifest.replace(
            &format!("journal_schema={}", crate::journal::CURRENT_JOURNAL_FORMAT),
            &format!("journal_schema={schema}"),
        );
        assert!(Identity::parse(&invalid, false).is_err(), "{schema}");
    }
    assert!(Identity::parse(&manifest.replace("binary_sha256=", "not_a_digest="), false).is_err());
    assert!(Identity::parse(&(manifest.clone() + "target=other\n"), false).is_err());
    assert!(
        Identity::parse(
            &manifest.replace("stop_timeout=infinity", "stop_timeout=30"),
            false
        )
        .is_err()
    );
}
#[test]
fn partial_repair_failure_preserves_activation_and_separates_health() {
    let options = Options {
        release: None,
        binary: None,
        sha256: None,
        check: false,
        dry_run: false,
        repair: true,
        stopped: false,
        migration_only: false,
        migrate: false,
        proposal: None,
        expected_token: None,
        accept_risk_change: None,
        expected_release: None,
    };
    let mut report = report(&options, "test");
    outcome(&mut report, true, "updated", "installer_completed");
    report["installation"] = json!({"activation":"loaded_verified"});
    doctor_outcome(
        &mut report,
        &json!({"healthy":false,"attention_required":true,"repair_requested":true,"repair_outcome":"failed",
            "repairs":{"applied":[{"operation_id":7}],"counts":{"eligible":5,"ineligible":0,"applied":1,"skipped":2},
                "failure":"repair_runtime_restore_failed","execution":"partial",
                "restoration":{"verified":false}},"secret":"must_not_escape"}),
        true,
        false,
    );
    assert_eq!(report["success"], false);
    assert_eq!(report["update"]["status"], "updated");
    assert_eq!(report["installation"]["activation"], "loaded_verified");
    assert_eq!(report["repair"]["applied_count"], 1);
    assert_eq!(report["repair"]["applied"][0]["operation_id"], 7);
    assert_eq!(report["repair"]["eligible_count"], 5);
    assert_eq!(report["repair"]["skipped_count"], 2);
    assert_eq!(report["repair"]["execution"], "partial");
    assert_eq!(report["repair"]["restoration_verified"], false);
    assert_eq!(report["repair"]["outcome"], "failed");
    assert_eq!(report["repair"]["receipt_status"], "complete");
    assert_eq!(report["repair"]["reason"], "repair_runtime_restore_failed");
    doctor_outcome(
        &mut report,
        &json!({"healthy":false,"repair_outcome":"failed","repairs":{"failure":"private-unrecognized-error"}}),
        true,
        false,
    );
    assert_eq!(report["repair"]["status"], "unknown");
    assert_eq!(report["repair"]["reason"], "update_doctor_report_invalid");
    assert!(!report.to_string().contains("private-unrecognized-error"));
    assert!(!report.to_string().contains("must_not_escape"));
    // A health failure alone must not alter a successful operation.
    report["success"] = json!(true);
    doctor_outcome(
        &mut report,
        &json!({"healthy":false,"repair_requested":true,"repair_outcome":"no_eligible_repairs",
            "repairs":{"failure":null,"counts":{"eligible":0,"ineligible":0,"applied":0,"skipped":0}}}),
        true,
        false,
    );
    assert_eq!(report["success"], true);
}
#[tokio::test]
async fn explicit_preview_does_not_create_config_or_state() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("absent/config.toml");
    let binary = root.path().join("absent/agmi");
    let digest = "a".repeat(64);
    let value = run(
        &config,
        Options {
            release: None,
            binary: Some(&binary),
            sha256: Some(&digest),
            check: false,
            dry_run: true,
            repair: true,
            stopped: false,
            migration_only: false,
            migrate: false,
            proposal: None,
            expected_token: None,
            accept_risk_change: None,
            expected_release: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(value["success"], true);
    assert_eq!(value["repair"]["status"], "planned");
    assert!(value["readiness"].is_null());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn archive_rejects_links_and_binary_digest_mismatch() {
    let root = tempfile::tempdir().unwrap();
    for link in [false, true] {
        let archive_path = root.path().join(if link { "link.gz" } else { "wrong.gz" });
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            File::create(&archive_path).unwrap(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        if link {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("/outside").unwrap();
            header.set_cksum();
            builder.append_data(&mut header, "agmi", &b""[..]).unwrap();
        } else {
            header.set_size(3);
            header.set_cksum();
            builder
                .append_data(&mut header, "agmi", &b"bad"[..])
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        assert!(
            extract(
                File::open(archive_path).unwrap(),
                &root.path().join(if link { "link" } else { "wrong" }),
                "manifest",
                &"a".repeat(64)
            )
            .is_err()
        );
    }
}
