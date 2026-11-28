use super::*;

static TEST_SERIAL: Mutex<()> = Mutex::new(());
#[test]
fn manager_unit_entry_sanitizes_untrusted_properties() {
    let entry = manager_unit_entry(
        "agmi.service",
        Some("loaded"),
        Some("active"),
        Some("running"),
        Some("123"),
        None,
        None,
    );
    assert_eq!(entry["unit"], "agmi.service");
    assert_eq!(entry["load"], "loaded");
    assert_eq!(entry["active"], "active");
    assert_eq!(entry["substate"], "running");
    assert_eq!(entry["pid"], 123);
    assert!(entry.get("result").is_none());
    assert!(entry["error"].is_null());

    let probe = manager_unit_entry(
        "agmi-health.service",
        Some("loaded"),
        Some("active"),
        Some("running"),
        Some("7"),
        Some((Some("success"), Some("0"))),
        None,
    );
    assert_eq!(probe["result"], "success");
    assert_eq!(probe["exit_code"], 0);

    // Untrusted manager output collapses to bounded explicit values.
    let hostile = manager_unit_entry(
        "agmi-health.service",
        Some("loaded\ninjected"),
        Some("ACTIVE"),
        Some(&"x".repeat(200)),
        Some("0"),
        Some((Some("weird;`rm -rf /`"), Some("99999999999"))),
        None,
    );
    assert_eq!(hostile["load"], "unavailable");
    assert_eq!(hostile["active"], "unavailable");
    assert_eq!(hostile["substate"], "unavailable");
    assert!(hostile["pid"].is_null());
    assert_eq!(hostile["result"], "unknown");
    assert!(hostile["exit_code"].is_null());

    let missing = manager_unit_entry(
        "agmi.service",
        None,
        None,
        None,
        None,
        None,
        Some("client_error"),
    );
    assert_eq!(missing["error"], "client_error");
    assert_eq!(missing["load"], "unavailable");

    let absent = manager_unit_entry(
        "agmi-health.timer",
        Some("not-found"),
        None,
        None,
        None,
        None,
        Some("unavailable"),
    );
    assert_eq!(absent["load"], "not-found");
    assert_eq!(absent["error"], "unavailable");
}

#[test]
fn snapshot_run_mode_reads_only_the_persisted_mode() {
    let once = json!({"effective_runtime":{"policy":{"process":{"run_mode":"once"}}}});
    assert_eq!(crate::installer::snapshot_run_mode(&once), "once");
    let policy = json!({"effective_runtime":{"policy":{"run_mode":"continuous"}}});
    assert_eq!(crate::installer::snapshot_run_mode(&policy), "continuous");
    let garbage = json!({"effective_runtime":{"run_mode":"turbo"}});
    assert_eq!(crate::installer::snapshot_run_mode(&garbage), "unknown");
    assert_eq!(crate::installer::snapshot_run_mode(&json!({})), "unknown");
}

fn bracket_fixture() -> (Value, Value) {
    let process = json!({"pid":1,"start_ticks":2,"run_mode":"continuous",
                "runtime_instance":"ri","authority_epoch":7,"account_generation":3,
                "invocation_id":null});
    let lanes = json!({"answer":{"revision":5,"paused":0},
                "judge":{"revision":6,"paused":0},"mine":{"revision":7,"paused":1}});
    let tuple = json!({"runtime_instance":"ri","revision":"rev","stopped":false,
                "authority_epoch":7,"generation":3,"process":process,
                "lane_controls":lanes,"journal_device":11,"journal_inode":22,
                "paused":false,"database_id":"ab".repeat(16)});
    let status = json!({"paused":false,"controller_stopped":false,"generation":3,
                "effective_runtime":{"revision":"rev","runtime_instance":"ri",
                    "authority_epoch":7,"observed_at":1000,
                    "policy":{"process":tuple["process"]}},
                "lane_controls":{"answer":{"desired":{"control_revision":5,"paused":false}},
                    "judge":{"desired":{"control_revision":6,"paused":false}},
                    "mine":{"desired":{"control_revision":7,"paused":true}}},
                "journal_identity":{"database_id":tuple["database_id"],
                    "device":11,"inode":22}});
    (tuple, status)
}

#[test]
fn bracket_must_match_the_database_actually_read() {
    let (tuple, status) = bracket_fixture();
    let live = json!([1, 2, {"device":11,"inode":22}]);
    let bracket = json!({"tuple":tuple,"live_process":live});
    assert!(matching_bracket(&bracket, &status));
    // Same content, different database: a path swap (including ABA)
    // never grants autonomy.
    let mut swapped = status.clone();
    swapped["journal_identity"]["database_id"] = json!("cd".repeat(16));
    assert!(!matching_bracket(&bracket, &swapped));
    // Same content id, different file object.
    let mut relinked = status.clone();
    relinked["journal_identity"]["inode"] = json!(23);
    assert!(!matching_bracket(&bracket, &relinked));
    // Snapshots without the read database identity prove nothing.
    let mut unidentified = status.clone();
    unidentified
        .as_object_mut()
        .unwrap()
        .remove("journal_identity");
    assert!(!matching_bracket(&bracket, &unidentified));
    // Missing attribution still proves nothing even with identity.
    let mut unattributed = bracket.clone();
    unattributed["live_process"] = Value::Null;
    assert!(!matching_bracket(&unattributed, &status));
}

fn observed_unit_fixture() -> Result<(tempfile::TempDir, PathBuf, String, PathBuf)> {
    let home = tempfile::tempdir()?;
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;
    let root = home.path().join(".local/share/agmi/releases");
    let id = format!("r-{}", "a".repeat(64));
    fs::create_dir_all(root.join(&id))?;
    let unit = home.path().join(".config/systemd/user/agmi.service");
    fs::create_dir_all(unit.parent().unwrap())?;
    for parent in [root.join(&id), unit.parent().unwrap().to_path_buf()] {
        for ancestor in parent.ancestors() {
            fs::set_permissions(ancestor, fs::Permissions::from_mode(0o700))?;
            if ancestor == home.path() {
                break;
            }
        }
    }
    let target = root.join(&id).join("agmi.service");
    fs::write(&target, b"owned unit")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    symlink(&id, root.join("current"))?;
    symlink(root.join("current/agmi.service"), &unit)?;
    Ok((home, root, id, unit))
}

#[test]
fn observed_unit_accepts_only_the_installer_chain_without_writing() -> Result<()> {
    let (home, root, id, unit) = observed_unit_fixture()?;
    let target = root.join(&id).join("agmi.service");
    let before = fs::read(&target)?;
    // The generic helper must still refuse even this authorized symlink.
    assert!(regular(&unit).is_err());
    let (mut file, link, current) = observed_unit(home.path(), &root, &id, &unit)?;
    let image = image_metadata(&file.metadata()?);
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    assert_eq!(contents, before);
    let (again, next_link, next_current) = observed_unit(home.path(), &root, &id, &target)?;
    assert_eq!(image, image_metadata(&again.metadata()?));
    assert_eq!(link, next_link);
    assert_eq!(current, next_current);
    observed_unit(home.path(), &root, &id, &root.join("current/agmi.service"))?;
    assert_eq!(fs::read(&target)?, before);
    assert_eq!(fs::read_link(&unit)?, root.join("current/agmi.service"));
    assert_eq!(fs::read_link(root.join("current"))?, Path::new(&id));
    Ok(())
}

#[test]
fn observed_unit_rejects_foreign_dangling_and_escaped_chains() -> Result<()> {
    let (home, root, id, unit) = observed_unit_fixture()?;
    let target = root.join(&id).join("agmi.service");
    let foreign = home.path().join("foreign.service");
    symlink(&target, &foreign)?;
    assert!(observed_unit(home.path(), &root, &id, &foreign).is_err());
    for link in [
        target.clone(),
        foreign.clone(),
        PathBuf::from("../../../../.local/share/agmi/releases/current/agmi.service"),
        home.path().join("missing.service"),
    ] {
        fs::remove_file(&unit)?;
        symlink(link, &unit)?;
        assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    }
    fs::remove_file(&unit)?;
    symlink(root.join("current/agmi.service"), &unit)?;
    for selection in [
        PathBuf::from("../outside"),
        root.join(&id),
        PathBuf::from(format!("r-{}", "b".repeat(64))),
    ] {
        fs::remove_file(root.join("current"))?;
        symlink(selection, root.join("current"))?;
        assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    }
    fs::remove_file(root.join("current"))?;
    symlink(&id, root.join("current"))?;
    fs::rename(&target, root.join(&id).join("saved.service"))?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    symlink("saved.service", &target)?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    fs::remove_file(&target)?;
    fs::rename(root.join(&id).join("saved.service"), &target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o622))?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    let parent = unit.parent().unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o722))?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    // An exclusively owned directory alias still is not the owned chain.
    let moved = home.path().join("outside-units");
    fs::rename(parent, &moved)?;
    symlink(&moved, parent)?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    fs::remove_file(parent)?;
    fs::rename(moved, parent)?;
    let directory = root.join(&id);
    let moved = home.path().join("outside-release");
    fs::rename(&directory, &moved)?;
    symlink(&moved, &directory)?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    Ok(())
}

#[test]
fn observed_unit_pins_artifact_and_detects_link_replacement() -> Result<()> {
    let (home, root, id, unit) = observed_unit_fixture()?;
    let target = root.join(&id).join("agmi.service");
    let (file, link, current) = observed_unit(home.path(), &root, &id, &unit)?;
    let image = image_metadata(&file.metadata()?);
    // Preserve the old objects so inode reuse cannot make the test flaky.
    fs::rename(&target, root.join(&id).join("old.service"))?;
    fs::write(&target, b"owned unit")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    let (replacement, _, _) = observed_unit(home.path(), &root, &id, &unit)?;
    assert_ne!(image, image_metadata(&replacement.metadata()?));
    assert_eq!(image.inode, file.metadata()?.ino());
    fs::rename(&unit, unit.with_extension("old"))?;
    symlink(root.join("current/agmi.service"), &unit)?;
    let (_, replacement_link, _) = observed_unit(home.path(), &root, &id, &unit)?;
    assert_ne!(link, replacement_link);
    fs::rename(root.join("current"), root.join("old-current"))?;
    symlink(&id, root.join("current"))?;
    let (_, _, replacement_current) = observed_unit(home.path(), &root, &id, &unit)?;
    assert_ne!(current, replacement_current);
    let next_id = format!("r-{}", "b".repeat(64));
    fs::create_dir(root.join(&next_id))?;
    fs::write(root.join(&next_id).join("agmi.service"), b"next unit")?;
    fs::remove_file(root.join("current"))?;
    symlink(next_id, root.join("current"))?;
    assert!(observed_unit(home.path(), &root, &id, &unit).is_err());
    Ok(())
}

#[test]
fn observed_selection_is_metadata_not_checksum_attestation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    let root = temp.path().join("releases");
    fs::create_dir(&root)?;
    let id = format!("r-{}", "a".repeat(64));
    let release = root.join(&id);
    fs::create_dir(&release)?;
    let binary = release.join("agmi");
    fs::write(&binary, b"not the claimed checksum")?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
    let manifest = format!(
        "build_format=1\npackage_version=0.2.0\ncommit={}\nsource_dirty=clean\ntarget=test\njournal_schema=4\nupdate_protocol=1\nrelease_id={id}\nbinary_sha256={}\n",
        "b".repeat(40),
        "a".repeat(64)
    );
    fs::write(release.join("MANIFEST"), &manifest)?;
    symlink(&id, root.join("current"))?;
    let launcher = temp.path().join("agmi");
    symlink(root.join("current/agmi"), &launcher)?;
    let (_, label, first) = selected_metadata(temp.path(), &root, &launcher)?;
    assert_eq!(label, manifest);
    // Same pathname and bytes on another inode are a different object.
    fs::rename(&binary, release.join("old"))?;
    fs::copy(release.join("old"), &binary)?;
    let (_, _, replacement) = selected_metadata(temp.path(), &root, &launcher)?;
    assert_ne!(first, replacement);
    // A path escape or contradictory identity never becomes standalone/match.
    fs::remove_file(root.join("current"))?;
    symlink("../outside", root.join("current"))?;
    assert!(selected_metadata(temp.path(), &root, &launcher).is_err());
    fs::remove_file(root.join("current"))?;
    symlink(&id, root.join("current"))?;
    fs::write(release.join("MANIFEST"), manifest.replace(&id, "r-invalid"))?;
    assert!(selected_metadata(temp.path(), &root, &launcher).is_err());
    Ok(())
}

#[test]
fn observed_arguments_are_exact_and_proc_inputs_are_bounded() -> Result<()> {
    let binary = Path::new("/release/agmi");
    let config = Path::new("/account/config.toml");
    assert!(managed_argv(
        b"/release/agmi\0--config\0/account/config.toml\0run\0",
        binary,
        config
    ));
    for argv in [
        b"/release/agmi\0--config\0/other/config.toml\0run\0".as_slice(),
        b"/release/agmi\0--config\0/account/config.toml\0run\0--once\0",
        b"/release/agmi\0--config\0/account/config.toml\0run",
    ] {
        assert!(!managed_argv(argv, binary, config));
    }
    let file = tempfile::NamedTempFile::new()?;
    fs::write(file.path(), vec![0; 16_385])?;
    assert!(bounded_bytes(file.path()).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn observed_start_ticks_handle_parentheses_and_pid_reuse() -> Result<()> {
    let stat = |start| {
        format!(
            "42 (name ) with spaces) S {} {start} 0",
            vec!["0"; 18].join(" ")
        )
    };
    assert_eq!(process_start(stat(123).as_bytes())?, 123);
    assert_ne!(
        process_start(stat(123).as_bytes())?,
        process_start(stat(124).as_bytes())?
    );
    assert!(process_start(b"42 (truncated) S").is_err());
    assert!(super::super::current_start_ticks().is_some());
    Ok(())
}

#[test]
fn process_snapshot_rollover_and_legacy_absence_are_not_matches() {
    let tuple = json!({"runtime_instance":"instance-a","authority_epoch":3,
                "generation":4,"revision":"revision",
                "process":{"runtime_instance":"instance-a","authority_epoch":3,
                    "account_generation":4,"pid":42}});
    let status = json!({"generation":4,"effective_runtime":{
                "revision":"revision","runtime_instance":"instance-a","authority_epoch":3,
                "policy":{"process":tuple["process"]}}});
    assert!(related_runtime_snapshot(&tuple, &status));
    for (field, changed) in [
        ("runtime_instance", json!("instance-b")),
        ("authority_epoch", json!(4)),
        ("generation", json!(5)),
        ("revision", json!("revision-b")),
    ] {
        let mut rollover = tuple.clone();
        rollover[field] = changed;
        assert!(!related_runtime_snapshot(&rollover, &status), "{field}");
    }
    let mut legacy = status.clone();
    legacy["effective_runtime"]["policy"]["process"] = json!({"pid":42});
    assert!(!related_runtime_snapshot(&tuple, &legacy));
    assert!(!related_runtime_snapshot(&json!({}), &json!({})));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_process_observation_never_claims_a_match() {
    let observed = super::super::observe_process(Path::new("/unread"), &json!({}));
    assert_eq!(observed.state, "not_assessed");
    assert_eq!(observed.reason, "unsupported_platform");
    assert_eq!(super::super::current_start_ticks(), None);
}

// Fixture writers belong to a dedicated process: unrelated libtest spawns
// must not inherit writable descriptors for executables being staged.
fn run_fixture_in_subprocess(name: &str) -> Result<bool> {
    const SELECTED: &str = "AGMI_INSTALLER_FIXTURE_TEST";
    const RECEIPT: &str = "AGMI_INSTALLER_FIXTURE_RECEIPT";
    if std::env::var(SELECTED).ok().as_deref() == Some(name) {
        let receipt = std::env::var_os(RECEIPT).context("missing fixture entry receipt")?;
        fs::write(receipt, b"x")?;
        return Ok(false);
    }
    // Preserve the fixture group's existing serialization of syncfs-heavy work.
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut receipt = tempfile::NamedTempFile::new()?;
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", name, "--nocapture"])
        .env(SELECTED, name)
        .env(RECEIPT, receipt.path())
        .output()
        .context("run isolated installer fixture")?;
    ensure!(
        output.status.success(),
        "isolated installer fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // libtest succeeds when an exact filter matches zero cases.
    let mut entered = [0];
    receipt
        .as_file_mut()
        .read_exact(&mut entered)
        .context("isolated installer case did not enter its original body")?;
    ensure!(entered == *b"x", "invalid fixture entry receipt");
    Ok(true)
}

#[test]
fn target_evidence_preserves_future_schema_and_real_restoration() {
    let raw = json!({"stage":"complete","failure_code":"none",
                "compatibility":{"classification":"conversion","migration_required":true,"target_journal_format":5},
                "migration":{"phase":"complete","target_journal_format":5,"participation_resumed":true},
                "restoration":{"status":"restored","runtime":"running","timer":"stopped","pause_state":"unpaused","verified":true,"private":"never-export"}});
    let bounded = installer_evidence(Some(&raw));
    assert_eq!(bounded["compatibility"]["target_journal_format"], 5);
    assert_eq!(bounded["migration"]["target_journal_format"], 5);
    assert_eq!(bounded["migration"]["participation_resumed"], true);
    assert_eq!(bounded["restoration"]["verified"], true);
    assert!(bounded["restoration"].get("private").is_none());
    let invalid = installer_evidence(Some(&json!({"compatibility":{
                "classification":"conversion","target_journal_format":u64::from(u32::MAX) + 1}})));
    assert!(invalid["compatibility"]["target_journal_format"].is_null());
}

#[test]
fn schema_crossing_requires_exact_explicit_stopped_forward_pair() {
    let current = CURRENT_JOURNAL_FORMAT.to_string();
    for installed in ["1", "2", "3", &current, "99"] {
        for candidate in ["1", "2", "3", &current, "99"] {
            for migration_only in [false, true] {
                for stopped in [false, true] {
                    let allowed = if migration_only {
                        matches!(installed, "2" | "3") && candidate == current && stopped
                    } else {
                        installed == current && candidate == current
                    };
                    assert_eq!(
                        activation_schema(installed, candidate, migration_only, stopped).is_ok(),
                        allowed,
                        "{installed}->{candidate}, migration={migration_only}, stopped={stopped}"
                    );
                }
            }
        }
    }
}

#[test]
fn actual_journal_not_release_pointer_defines_fresh_compatibility() -> Result<()> {
    let temp = OwnedPath::directory(&std::env::temp_dir(), "agmi-journal-policy")?;
    let state = temp.path.join("state");
    fs::create_dir(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let mut installation = Installation::new(temp.path.clone())?;
    installation.state_dir = Some(state.clone());
    assert!(installation.verify_journal_activation().is_ok());
    let path = state.join("state.sqlite3");
    let db = rusqlite::Connection::open(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    db.execute_batch(
        "CREATE TABLE control(singleton INTEGER PRIMARY KEY, version INTEGER);
                INSERT INTO control VALUES(1,3);",
    )?;
    assert!(installation.verify_journal_activation().is_err());
    installation.migration_only = true;
    assert!(installation.verify_journal_activation().is_ok());
    db.execute("UPDATE control SET version=?1", [CURRENT_JOURNAL_FORMAT])?;
    assert!(installation.verify_journal_activation().is_err());
    installation.migration_only = false;
    assert!(installation.verify_journal_activation().is_ok());
    db.execute_batch(
        "CREATE TABLE capability_migration(singleton INTEGER PRIMARY KEY, phase TEXT);
                INSERT INTO capability_migration VALUES(1,'journal_ready');",
    )?;
    assert!(installation.verify_journal_activation().is_err());
    db.execute("UPDATE capability_migration SET phase='complete'", [])?;
    assert!(installation.verify_journal_activation().is_ok());
    db.execute("UPDATE control SET version=99", [])?;
    for migration_only in [false, true] {
        installation.migration_only = migration_only;
        assert!(installation.verify_journal_activation().is_err());
    }
    Ok(())
}

#[test]
fn committed_internal_migration_survives_independent_postcondition_failure() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let token = format!("agmi.atomic-migration.v1:{}", "a".repeat(64));
    for (observed, phase) in [
        (
            json!({"phase":"complete","token":token,"target_journal_format":4}),
            "complete",
        ),
        (
            json!({"phase":"complete","token":format!("agmi.atomic-migration.v1:{}", "b".repeat(64))}),
            "failed",
        ),
        (
            json!({"phase":"journal_ready","pending":true,"token":token,"target_journal_format":4}),
            "recovery_required",
        ),
    ] {
        let mut installation = Installation::new(temp.path().to_owned())?;
        installation.phase = "migration";
        installation.activation = "loaded_verified";
        installation.service = "unknown";
        installation.failure = "stop_failed";
        installation.migration = json!({"phase":"required","token":token,
                    "release_id":format!("r-{}", "c".repeat(64)),"participation_resumed":false});
        installation.record_migration_failure(Some(observed), None);
        let evidence = installation.evidence(false);
        assert_eq!(evidence["migration"]["phase"], phase);
        assert_eq!(evidence["failure_code"], "stop_failed");
        assert_eq!(evidence["activation"], "loaded_verified");
        assert_eq!(evidence["service"], "unknown");
        assert_eq!(evidence["migration"]["participation_resumed"], false);
    }
    let mut completed = Installation::new(temp.path().to_owned())?;
    completed.migration = json!({"phase":"complete","token":token,"participation_resumed":true});
    completed.record_migration_failure(None, None);
    assert_eq!(completed.evidence(false)["migration"]["phase"], "complete");
    completed.record_migration_failure(
        Some(json!({"phase":"complete","token":token,"target_journal_format":4})),
        None,
    );
    assert_eq!(
        completed.evidence(false)["migration"]["participation_resumed"],
        true
    );
    Ok(())
}

#[test]
fn stopped_migration_refuses_live_descendants_and_unsafe_locations() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let group = temp.path().join("unit");
    fs::create_dir(&group)?;
    let events = group.join("cgroup.events");
    fs::write(&events, "populated 1\nfrozen 0\n")?;
    assert!(Installation::verify_empty_cgroup(temp.path(), "/unit").is_err());
    fs::write(&events, "populated 0\nfrozen 0\n")?;
    Installation::verify_empty_cgroup(temp.path(), "/unit")?;
    fs::remove_file(events)?;
    assert!(Installation::verify_empty_cgroup(temp.path(), "/unit").is_err());
    Installation::verify_empty_cgroup(temp.path(), "/already-removed")?;
    for unsafe_path in ["relative", "/../elsewhere"] {
        assert!(Installation::verify_empty_cgroup(temp.path(), unsafe_path).is_err());
    }
    Ok(())
}

#[test]
fn migration_approval_keeps_canonical_token_and_pins_continuation() -> Result<()> {
    let token = format!("agmi.atomic-migration.v1:{}", "a".repeat(64));
    let args = vec![
        "activate".into(),
        format!("r-{}", "b".repeat(64)),
        "--migrate".into(),
        "--expected-token".into(),
        token.clone(),
        "--accept-risk-change".into(),
        token.clone(),
    ];
    assert_eq!(Request::parse(&args)?.expected_token, Some(token.as_str()));
    let mut wrong = args.clone();
    wrong[6] = format!("agmi.atomic-migration.v1:{}", "c".repeat(64));
    assert!(Request::parse(&wrong).is_err());
    let mut legacy = args;
    legacy.push("--migration-only".into());
    legacy.push("--stopped".into());
    assert!(Request::parse(&legacy).is_err());
    Ok(())
}

#[test]
fn migration_request_is_explicit_and_stopped() {
    let id = format!("r-{}", "a".repeat(64));
    let mut args = vec!["activate".into(), id, "--migration-only".into()];
    assert!(Request::parse(&args).is_err());
    args.push("--stopped".into());
    assert!(Request::parse(&args).unwrap().migration_only);
    args.push("--migration-only".into());
    assert!(Request::parse(&args).is_err());
    let args = vec![
        "stage".into(),
        "/candidate".into(),
        "--sha256".into(),
        "a".repeat(64),
        "--migration-only".into(),
    ];
    assert!(Request::parse(&args).is_err());
    let mut args = args;
    args[0] = "install".into();
    let request = Request::parse(&args).unwrap();
    assert!(request.migration_only && request.stopped);
}

#[test]
fn expected_release_fence_refuses_before_any_cutover() -> Result<()> {
    let home = tempfile::tempdir()?;
    let mut installation = Installation::new(home.path().to_owned())?;
    fs::create_dir_all(&installation.root)?;
    let actual = format!("r-{}", "a".repeat(64));
    let expected = format!("r-{}", "b".repeat(64));
    symlink(&actual, installation.root.join("current"))?;
    let arguments = vec![
        "activate".into(),
        actual.clone(),
        "--expected-release".into(),
        expected,
    ];
    let request = Request::parse(&arguments)?;
    let error = installation.activate(&actual, &request).unwrap_err();
    assert!(error.to_string().contains("selected release changed"));
    assert_eq!(installation.phase, "activation_preflight");
    assert_eq!(installation.activation, "not_started");
    assert!(!installation.stop_on_failure);
    assert_eq!(
        fs::read_link(installation.root.join("current"))?,
        Path::new(&actual)
    );
    for bad in [
        vec![
            "activate".into(),
            actual.clone(),
            "--expected-release".into(),
            "invalid".into(),
        ],
        vec![
            "activate".into(),
            actual.clone(),
            "--expected-release".into(),
            actual.clone(),
            "--expected-release".into(),
            actual,
        ],
    ] {
        assert!(Request::parse(&bad).is_err());
    }
    Ok(())
}

fn quoted(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}
fn candidate(path: &Path, state: &Path, dirty: &str) -> Result<String> {
    let mut manifest = format!(
        "build_format=1\ncommit={}\nsource_dirty={dirty}\njournal_schema={CURRENT_JOURNAL_FORMAT}\nstop_timeout=infinity\n",
        "a".repeat(40)
    );
    for (_, key, template) in UNITS {
        manifest.push_str(&format!(
            "{key}={:x}\n",
            Sha256::digest(template.as_bytes())
        ));
    }
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\nbuild-info) cat <<'MANIFEST'\n{manifest}MANIFEST\n;;\n--config) printf '%s\\n' {};;\n*) exit 91;;\nesac\n",
        quoted(state)
    );
    write_file(path, script.as_bytes(), 0o700)?;
    digest(regular(path)?)
}
fn no_temporary_paths(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let name = entry?.file_name();
        assert!(!name.to_string_lossy().starts_with(".stage."));
        assert!(!name.to_string_lossy().starts_with(".agmi-link."));
    }
    Ok(())
}
#[test]
fn migration_bootstrap_requires_durable_disabled_boot_intent() -> Result<()> {
    if run_fixture_in_subprocess(
        "installer::native::tests::migration_bootstrap_requires_durable_disabled_boot_intent",
    )? {
        return Ok(());
    }
    let _cancellation = InstallerCancellation::acquire()?;
    let temporary = OwnedPath::directory(&std::env::temp_dir(), "agmi-bootstrap-test")?;
    let home = temporary.path.join("home");
    fs::create_dir(&home)?;
    let state = home.join("state-not-created");
    let binary = temporary.path.join("candidate");
    let expected = candidate(&binary, &state, "clean")?;
    let verifier = temporary.path.join("verify");
    write_file(&verifier, b"#!/bin/sh\nexit 0\n", 0o700)?;
    let mut installation = Installation::new(home)?;
    installation.analyze = verifier;
    installation.lock = Some(installation.prepare(true)?);
    let id = installation.stage(&binary, &expected)?;
    let release = installation.root.join(&id);

    let old_binary = fs::read_to_string(&binary)?.replace(
        &format!("journal_schema={CURRENT_JOURNAL_FORMAT}\n"),
        "journal_schema=2\n",
    );
    let old_digest = format!("{:x}", Sha256::digest(old_binary.as_bytes()));
    let old_id = format!("r-{old_digest}");
    let old_release = installation.root.join(&old_id);
    fs::create_dir(&old_release)?;
    write_file(&old_release.join("agmi"), old_binary.as_bytes(), 0o700)?;
    for (unit, _, template) in UNITS {
        write_file(
            &old_release.join(unit),
            template.replace("@AGMI_RELEASE_ID@", &old_id).as_bytes(),
            0o600,
        )?;
    }
    let old_manifest = fs::read_to_string(release.join("MANIFEST"))?
        .replace(
            &format!("journal_schema={CURRENT_JOURNAL_FORMAT}\n"),
            "journal_schema=2\n",
        )
        .replace(&id, &old_id)
        .replace(&expected, &old_digest);
    write_file(
        &old_release.join("MANIFEST"),
        old_manifest.as_bytes(),
        0o600,
    )?;
    write_file(
        &old_release.join("SHA256SUMS"),
        checksums(&old_release)?.as_bytes(),
        0o600,
    )?;
    let current = installation.root.join("current");
    symlink(&old_id, &current)?;
    for (unit, _, _) in UNITS {
        symlink(current.join(unit), installation.units.join(unit))?;
    }
    let mut boot_links = Vec::new();
    for (unit, target) in [
        ("agmi.service", "default.target.wants"),
        ("agmi-health.timer", "timers.target.wants"),
    ] {
        let directory = installation.units.join(target);
        fs::create_dir(&directory)?;
        let link = directory.join(unit);
        symlink(installation.units.join(unit), &link)?;
        boot_links.push(link);
    }
    for (unit, _, _) in UNITS {
        fs::write(temporary.path.join(format!("manager-{unit}")), "loaded\n")?;
    }
    let control = temporary.path.join("systemctl");
    write_file(
        &control,
        format!(
            r#"#!/bin/sh
root={}
units="$root/home/.config/systemd/user"
current="$root/home/.local/share/agmi/releases/current"
[ "$1" = --user ] || exit 94
shift
case "$1" in
show)
  case "$3" in
  --property=LoadState) cat "$root/manager-$2";;
  --property=ActiveState) printf 'inactive\n';;
  --property=FragmentPath) printf '%s/%s\n' "$units" "$2";;
  --property=MainPID) printf '0\n';;
  --property=DropInPaths) printf '\n';;
  --property=TimeoutStopUSec) printf 'infinity\n';;
  --property=Description) printf 'fixture [release=%s]\n' "$(readlink "$current")";;
  --property=UnitFileState)
    if [ -L "$units/default.target.wants/$2" ] || [ -L "$units/timers.target.wants/$2" ]; then
      printf 'enabled\n'
    else
      printf 'linked\n'
    fi;;
  *) exit 95;;
  esac;;
disable)
  [ ! -e "$root/refuse-disable" ] || exit 0
  shift
  for unit in "$@"; do
    rm -f "$units/$unit" "$units/default.target.wants/$unit" "$units/timers.target.wants/$unit"
    printf 'not-found\n' > "$root/manager-$unit"
    [ ! -e "$root/partial-disable" ] || exit 1
  done
  if [ -e "$root/replace-definition" ]; then
    ln -s "$root/operator-owned.service" "$units/agmi.service"
    [ ! -e "$root/replace-fails" ] || exit 1
  fi
  if [ -e "$root/break-definitions" ]; then
    mv "$units" "$units.saved"
    : > "$units"
    exit 1
  fi
  if [ -e "$root/cancel-disable" ]; then
    kill -TERM "$PPID"
    exit 1
  fi;;
daemon-reload)
  [ ! -e "$root/fail-reload" ] || exit 1
  if [ -e "$root/replace-on-reload" ]; then
    rm -f "$units/agmi.service"
    ln -s "$root/operator-owned.service" "$units/agmi.service"
  fi
  for unit in agmi.service agmi-health.service agmi-health.timer; do
    if [ -f "$units/$unit" ]; then
      printf 'loaded\n' > "$root/manager-$unit"
    else
      printf 'not-found\n' > "$root/manager-$unit"
    fi
  done;;
stop) exit 0;;
*) exit 96;;
esac
"#,
            quoted(&temporary.path)
        )
        .as_bytes(),
        0o700,
    )?;
    installation.systemctl = control;
    installation.migration_only = true;
    let request = Request {
        action: "activate",
        target: &id,
        digest: None,
        expected_release: None,
        stopped: true,
        migration_only: true,
        migrate: false,
        proposal: None,
        expected_token: None,
        accept_risk_change: None,
    };
    let refusal = temporary.path.join("refuse-disable");
    fs::write(&refusal, [])?;
    assert!(installation.activate(&id, &request).is_err());
    assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
    assert!(boot_links.iter().all(|path| path.is_symlink()));

    fs::remove_file(refusal)?;
    // Failed legacy backup must precede any boot-intent mutation.
    let launcher = installation.bin.join("agmi");
    fs::remove_file(&launcher)?;
    fs::create_dir(&launcher)?;
    assert!(installation.activate(&id, &request).is_err());
    assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
    assert!(boot_links.iter().all(|path| path.is_symlink()));
    fs::remove_dir(&launcher)?;
    symlink(current.join("agmi"), &launcher)?;

    // A manager may remove definitions before reporting failure.
    let partial = temporary.path.join("partial-disable");
    fs::write(&partial, [])?;
    assert!(installation.activate(&id, &request).is_err());
    assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
    for (unit, _, _) in UNITS {
        let definition = installation.units.join(unit);
        assert_eq!(fs::read_link(&definition)?, current.join(unit));
        assert!(definition.is_file());
        assert_eq!(installation.property(unit, "LoadState", false)?, "loaded");
    }
    assert!(!boot_links[0].is_symlink());
    assert!(boot_links[1].is_symlink());
    fs::remove_file(&partial)?;

    // One definition uses a relative target. Disable snapshots must preserve
    // its exact bytes through restore instead of canonicalizing them.
    let relative_unit = "agmi-health.timer";
    let relative_target = {
        let mut target = PathBuf::new();
        for _ in installation
            .units
            .strip_prefix(&installation.home)?
            .components()
        {
            target.push("..");
        }
        target.push(current.strip_prefix(&installation.home)?);
        target.push(relative_unit);
        target
    };
    fs::remove_file(installation.units.join(relative_unit))?;
    symlink(&relative_target, installation.units.join(relative_unit))?;
    let expected_definition = |unit: &str| -> PathBuf {
        if unit == relative_unit {
            relative_target.clone()
        } else {
            current.join(unit)
        }
    };
    installation.service("disable", None)?;
    assert_eq!(
        fs::read_link(installation.units.join(relative_unit))?,
        relative_target
    );
    assert!(installation.units.join(relative_unit).is_file());
    assert_eq!(
        installation.evidence(false)["bootstrap_recovery"]["definitions_restored"],
        true
    );

    let replacement = temporary.path.join("operator-owned.service");
    fs::write(&replacement, "operator-owned definition")?;
    for (marker, disable_fails) in [
        ("replace-definition", false),
        ("replace-definition", true),
        ("replace-on-reload", false),
    ] {
        let marker = temporary.path.join(marker);
        let failed = temporary.path.join("replace-fails");
        fs::write(&marker, [])?;
        if disable_fails {
            fs::write(&failed, [])?;
        }
        assert!(installation.service("disable", None).is_err());
        assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
        let evidence = installation.evidence(false);
        assert_eq!(evidence["failure_code"], "bootstrap_recovery_failed");
        assert_eq!(
            evidence["bootstrap_recovery"]["disable_command_succeeded"],
            !disable_fails
        );
        assert_eq!(
            evidence["bootstrap_recovery"]["definitions_restored"],
            false
        );
        assert_eq!(
            fs::read_link(installation.units.join("agmi.service"))?,
            replacement
        );
        for unit in ["agmi-health.service", "agmi-health.timer"] {
            assert_eq!(
                fs::read_link(installation.units.join(unit))?,
                expected_definition(unit)
            );
        }
        fs::remove_file(marker)?;
        if disable_fails {
            fs::remove_file(failed)?;
        }
        fs::remove_file(installation.units.join("agmi.service"))?;
        symlink(
            current.join("agmi.service"),
            installation.units.join("agmi.service"),
        )?;
    }

    for disable_fails in [false, true] {
        let reload_failure = temporary.path.join("fail-reload");
        fs::write(&reload_failure, [])?;
        if disable_fails {
            fs::write(&partial, [])?;
        }
        let result = installation.activate(&id, &request);
        fs::remove_file(reload_failure)?;
        if disable_fails {
            fs::remove_file(&partial)?;
        }
        assert!(result.is_err());
        assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
        let evidence = installation.evidence(false);
        assert_eq!(evidence["failure_code"], "bootstrap_recovery_failed");
        assert_eq!(
            evidence["bootstrap_recovery"],
            json!({
                "disable_command_succeeded": !disable_fails,
                "definitions_restored": true,
                "manager_reload_succeeded": false
            })
        );
        assert_eq!(
            installation.property("agmi.service", "LoadState", false)?,
            "not-found"
        );
        assert!(installation.units.join("agmi.service").is_file());
    }

    let broken_definitions = temporary.path.join("break-definitions");
    fs::write(&broken_definitions, [])?;
    let result = installation.activate(&id, &request);
    fs::remove_file(broken_definitions)?;
    fs::remove_file(&installation.units)?;
    fs::rename(
        installation.units.with_file_name("user.saved"),
        &installation.units,
    )?;
    assert!(result.is_err());
    assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
    let evidence = installation.evidence(false);
    assert_eq!(evidence["failure_code"], "bootstrap_recovery_failed");
    assert_eq!(
        evidence["bootstrap_recovery"],
        json!({
            "disable_command_succeeded": false,
            "definitions_restored": false,
            "manager_reload_succeeded": true
        })
    );
    assert_eq!(
        installation.property("agmi.service", "LoadState", false)?,
        "not-found"
    );

    let cancellation = temporary.path.join("cancel-disable");
    fs::write(&cancellation, [])?;
    let result = installation.activate(&id, &request);
    let cancelled = CANCELLED.swap(0, Ordering::Relaxed);
    fs::remove_file(cancellation)?;
    assert!(result.is_err());
    assert_ne!(cancelled, 0);
    assert_eq!(fs::read_link(&current)?, Path::new(&old_id));
    for (unit, _, _) in UNITS {
        assert!(installation.units.join(unit).is_file());
        assert_eq!(installation.property(unit, "LoadState", false)?, "loaded");
    }

    installation.activate(&id, &request)?;
    assert_eq!(fs::read_link(&current)?, Path::new(&id));
    assert_eq!(installation.service, "stopped");
    assert_eq!(installation.activation, "loaded_verified");
    drop(installation);
    assert!(boot_links.iter().all(|path| !path.is_symlink()));
    assert!(!state.exists());
    Ok(())
}

/// Native staging/cutover coverage on both Darwin and Linux. Only the
/// external systemd boundary is replaced; real hashes, private copies,
/// manifest validation, publication, fsync and RAII run unchanged.
#[test]
fn filesystem_publication_and_failure_boundaries() -> Result<()> {
    if run_fixture_in_subprocess(
        "installer::native::tests::filesystem_publication_and_failure_boundaries",
    )? {
        return Ok(());
    }
    let _cancellation = InstallerCancellation::acquire()?;
    let temporary = OwnedPath::directory(&std::env::temp_dir(), "agmi-native-installer-test")?;
    let home = temporary.path.join("home");
    fs::create_dir(&home)?;
    assert!(Installation::new(home.clone())?.account_context().is_err());
    Installation::new(crate::store::account_home()?)?.account_context()?;
    let private_input = home.join("private-input");
    write_file(&private_input, b"credential and journal sentinel", 0o600)?;
    let state = home.join("state-not-created");
    let binary = temporary.path.join("candidate");
    let expected = candidate(&binary, &state, "clean")?;
    let verifier = temporary.path.join("verify");
    let verified = temporary.path.join("verified");
    write_file(&verifier, format!("#!/bin/sh\n[ \"$1\" = --user ] && [ \"$2\" = verify ] || exit 92\nshift 2\nfor file in \"$@\"; do [ -f \"$file\" ] || exit 93; done\nprintf '%s\\n' \"$@\" > {}\n", quoted(&verified)).as_bytes(), 0o700)?;
    let mut installation = Installation::new(home.clone())?;
    installation.analyze = verifier.clone();
    installation.systemctl = temporary.path.join("must-not-contact-a-manager");
    installation.lock = Some(installation.prepare(false)?);
    assert!(installation.root.join(".install-lock").is_file());
    let busy = InstallLock::acquire(&installation.root)
        .err()
        .context("lock unexpectedly shared")?;
    assert_eq!(
        busy.downcast_ref::<InstallerError>().unwrap().evidence["failure_code"],
        "update_in_progress"
    );
    let id = installation.stage(&binary, &expected)?;
    let release = installation.root.join(&id);
    assert_eq!(installation.staging, "complete");
    assert_eq!(
        fs::read_to_string(release.join("SHA256SUMS"))?,
        checksums(&release)?
    );
    assert_eq!(digest(regular(&release.join("agmi"))?)?, expected);
    for (unit, _, template) in UNITS {
        assert_eq!(
            fs::read_to_string(release.join(unit))?,
            template.replace("@AGMI_RELEASE_ID@", &id)
        );
        assert_eq!(
            fs::metadata(release.join(unit))?.permissions().mode() & 0o777,
            0o644
        );
    }
    assert!(
        fs::read_to_string(&verified)?
            .lines()
            .all(|line| Path::new(line).starts_with(&release))
    );
    assert!(!exists(&installation.root.join("current"))?);
    assert!(!exists(&installation.bin)?);
    assert!(!exists(&installation.units)?);
    assert!(!state.exists());
    assert_eq!(
        fs::read(&private_input)?,
        b"credential and journal sentinel"
    );
    assert_eq!(installation.stage(&binary, &expected)?, id);
    no_temporary_paths(&installation.root)?;

    // A recomputed mutable checksum cannot authorize a changed unit.
    let timer = release.join("agmi-health.timer");
    let original_timer = fs::read(&timer)?;
    fs::write(&timer, b"[Timer]\nOnUnitActiveSec=1\n")?;
    fs::write(release.join("SHA256SUMS"), checksums(&release)?)?;
    assert!(validate_release(&release, &id).is_err());
    fs::write(&timer, original_timer)?;
    fs::write(release.join("SHA256SUMS"), checksums(&release)?)?;
    validate_release(&release, &id)?;

    // A failed unit check retains the complete published set, but it is
    // neither selected nor silently considered verified.
    let rejected = temporary.path.join("reject-verifier");
    write_file(&rejected, b"#!/bin/sh\nexit 1\n", 0o700)?;
    installation.analyze = rejected;
    let second = temporary.path.join("second-candidate");
    let second_hash = candidate(&second, &state, "dirty")?;
    assert!(installation.stage(&second, &second_hash).is_err());
    assert_eq!(installation.staging, "published");
    assert_eq!(installation.failure, "unit_invalid");
    let second_release = installation.root.join(format!("r-{second_hash}"));
    validate_release(&second_release, &format!("r-{second_hash}"))?;
    assert!(!exists(&installation.root.join("current"))?);
    no_temporary_paths(&installation.root)?;
    installation.analyze = verifier;

    // Bad identity and state containment fail before any publication.
    let invalid = temporary.path.join("unknown-build");
    let invalid_hash = candidate(&invalid, &state, "unknown")?;
    assert!(installation.stage(&invalid, &invalid_hash).is_err());
    assert!(!installation.root.join(format!("r-{invalid_hash}")).exists());
    no_temporary_paths(&installation.root)?;
    let state_alias = home.join("state-alias");
    symlink(&installation.root, &state_alias)?;
    let overlapping = temporary.path.join("overlapping-state");
    let overlapping_hash = candidate(&overlapping, &state_alias.join("missing/journal"), "clean")?;
    assert!(installation.stage(&overlapping, &overlapping_hash).is_err());
    assert_eq!(installation.failure, "configuration_invalid");
    assert!(
        !installation
            .root
            .join(format!("r-{overlapping_hash}"))
            .exists()
    );
    no_temporary_paths(&installation.root)?;

    // Changed bytes and symlink candidates never reach executable use.
    let copied = temporary.path.join("private-copy");
    let mismatch = copy_candidate(&second, &copied, &expected).unwrap_err();
    assert_eq!(
        mismatch.downcast_ref::<InstallerError>().unwrap().evidence["failure_code"],
        "digest_mismatch"
    );
    let linked = temporary.path.join("linked-candidate");
    symlink(&binary, &linked)?;
    assert!(copy_candidate(&linked, &temporary.path.join("linked-copy"), &expected).is_err());
    let mut space_output = String::new();
    let reserve = Installation::space_at(&home, u64::MAX, "test", &mut space_output).unwrap_err();
    assert_eq!(
        reserve.downcast_ref::<InstallerError>().unwrap().evidence["failure_code"],
        "insufficient_space"
    );

    // Fail after the single pointer switch. Drop must stop every unit
    // even under cancellation, while it still owns the installation lock;
    // it must never restore the old pointer or touch private inputs.
    drop(installation.lock.take());
    installation.lock = Some(installation.prepare(true)?);
    let events = temporary.path.join("systemd-events");
    let control = temporary.path.join("systemctl-fixture");
    let lock_path = installation.root.join(".install-lock");
    let active_state = temporary.path.join("active-state");
    let unit_paths = temporary.path.join("unit-paths");
    let fragment_root = temporary.path.join("fragment-root");
    fs::write(
        &fragment_root,
        installation.units.to_string_lossy().as_bytes(),
    )?;
    fs::write(&active_state, "inactive\n")?;
    fs::write(&unit_paths, "/another/home/.config/systemd/user\n")?;
    write_file(
        &control,
        format!(
            r#"#!/bin/sh
[ -f {} ] || exit 94
printf '%s\n' "$*" >> {}
shift
case "$1" in
show)
  if [ "$2" = --property=UnitPath ]; then cat {}; exit; fi
  case "$3" in
  --property=LoadState) printf 'loaded\n';;
  --property=ActiveState) cat {};;
  --property=FragmentPath) printf '%s/%s\n' "$(cat {})" "$2";;
  --property=MainPID) printf '0\n';;
  *) exit 95;;
  esac;;
stop) exit 0;;
daemon-reload) exit 1;;
*) exit 96;;
esac
"#,
            quoted(&lock_path),
            quoted(&events),
            quoted(&unit_paths),
            quoted(&active_state),
            quoted(&fragment_root)
        )
        .as_bytes(),
        0o700,
    )?;
    installation.systemctl = control;
    assert!(installation.manager_context().is_err());
    assert!(!fs::read_to_string(&events)?.contains("--user stop "));
    fs::write(&unit_paths, installation.units.to_string_lossy().as_bytes())?;
    for (unit, _, _) in UNITS {
        symlink(release.join(unit), installation.units.join(unit))?;
    }
    fs::write(temporary.path.join("agmi.service"), "foreign unit")?;
    fs::write(&fragment_root, temporary.path.to_string_lossy().as_bytes())?;
    assert!(installation.manager_context().is_err());
    assert!(!fs::read_to_string(&events)?.contains("--user stop "));
    fs::write(
        &fragment_root,
        installation.units.to_string_lossy().as_bytes(),
    )?;
    installation.manager_context()?;
    for (state, expected) in [
        ("active", true),
        ("reloading", true),
        ("inactive", false),
        ("failed", false),
    ] {
        fs::write(&active_state, state)?;
        assert_eq!(installation.active("agmi.service")?, expected);
    }
    let request = Request {
        action: "activate",
        target: &id,
        digest: None,
        expected_release: None,
        stopped: true,
        migration_only: false,
        migrate: false,
        proposal: None,
        expected_token: None,
        accept_risk_change: None,
    };
    fs::write(&active_state, "activating")?;
    assert!(installation.activate(&id, &request).is_err());
    assert_eq!(installation.failure, "service_state_unavailable");
    assert!(!installation.stop_on_failure);
    assert!(!fs::read_to_string(&events)?.contains("--user stop "));
    fs::write(&active_state, "inactive")?;
    assert!(installation.activate(&id, &request).is_err());
    assert_eq!(installation.phase, "reloading");
    assert_eq!(installation.activation, "selected");
    assert!(installation.stop_on_failure);
    let root = installation.root.clone();
    let bin = installation.bin.clone();
    let units = installation.units.clone();
    CANCELLED.store(libc::SIGTERM, Ordering::Relaxed);
    drop(installation);
    CANCELLED.store(0, Ordering::Relaxed);
    assert_eq!(fs::read_link(root.join("current"))?, Path::new(&id));
    assert_eq!(fs::read_link(bin.join("agmi"))?, root.join("current/agmi"));
    assert!(events.exists());
    let events = fs::read_to_string(events)?;
    assert_eq!(events.matches("--user stop ").count(), 6, "{events}");
    assert!(root.join(".install-lock").is_file());
    assert!(release.is_dir() && second_release.is_dir());
    assert!(!state.exists());
    assert_eq!(
        fs::read(&private_input)?,
        b"credential and journal sentinel"
    );
    no_temporary_paths(&root)?;
    no_temporary_paths(&bin)?;
    no_temporary_paths(&units)?;

    // Pre-feature directory leases are a separate explicit recovery boundary.
    fs::remove_file(root.join(".install-lock"))?;
    fs::create_dir(root.join(".install-lock"))?;
    assert!(InstallLock::acquire(&root).is_err());
    assert!(root.join(".install-lock").is_dir());
    Ok(())
}
fn repair_fixture(directory: &Path) -> Result<Installation> {
    let home = directory.join("home");
    fs::create_dir(&home)?;
    let mut installation = Installation::new(home)?;
    installation.lock = Some(installation.prepare(true)?);
    fs::create_dir_all(installation.config.parent().unwrap())?;
    write_file(
        &installation.config,
        b"paused = true\nprivate sentinel\n",
        0o600,
    )?;
    let binary = directory.join("candidate");
    let expected = candidate(&binary, &directory.join("state"), "clean")?;
    let verifier = directory.join("verify");
    write_file(&verifier, b"#!/bin/sh\nexit 0\n", 0o700)?;
    installation.analyze = verifier;
    let id = installation.stage(&binary, &expected)?;
    symlink(&id, installation.root.join("current"))?;
    symlink(
        installation.root.join("current/agmi"),
        installation.bin.join("agmi"),
    )?;
    for (unit, _, _) in UNITS {
        symlink(
            installation.root.join("current").join(unit),
            installation.units.join(unit),
        )?;
    }
    installation.proc_root = directory.join("proc");
    let process = installation.proc_root.join("42");
    fs::create_dir_all(&process)?;
    let executable = installation.root.join(&id).join("agmi");
    symlink(&executable, process.join("exe"))?;
    let mut command = Vec::new();
    for argument in [
        executable.as_os_str().as_bytes(),
        b"--config",
        installation.config.as_os_str().as_bytes(),
        b"run",
    ] {
        command.extend_from_slice(argument);
        command.push(0);
    }
    fs::write(process.join("cmdline"), command)?;
    fs::write(directory.join("runtime"), "active")?;
    fs::write(directory.join("timer"), "active")?;
    fs::write(directory.join("dropins"), "")?;
    fs::write(directory.join("job"), "0")?;
    fs::write(
        directory.join("fragment"),
        installation.units.as_os_str().as_bytes(),
    )?;
    fs::write(directory.join("events"), "")?;
    installation.systemctl = directory.join("systemctl");
    write_file(
        &installation.systemctl,
        format!(
            r#"#!/bin/sh
root={}
units={}
id={}
[ -f {} ] || exit 94
printf '%s\n' "$*" >> "$root/events"
[ "$1" = --user ] || exit 95
shift
case "$1" in
show)
  if [ "$2" = --property=UnitPath ]; then printf '%s\n' "$units"; exit; fi
  case "$3" in
    --property=LoadState) printf 'loaded\n';;
    --property=FragmentPath) printf '%s/%s\n' "$(cat "$root/fragment")" "$2";;
    --property=Description) printf 'fixture [release=%s]\n' "$id";;
    --property=DropInPaths) cat "$root/dropins";;
    --property=TimeoutStopUSec) printf 'infinity\n';;
    --property=NeedDaemonReload) printf 'no\n';;
    --property=ActiveState)
      case "$2" in
        agmi.service) cat "$root/runtime";;
        agmi-health.timer) cat "$root/timer";;
        *) printf 'inactive\n';;
      esac;;
    --property=SubState) printf 'running\n';;
    --property=Job) cat "$root/job";;
    --property=ControlPID) printf '0\n';;
    --property=MainPID)
      if [ "$(cat "$root/runtime")" = active ]; then printf '42\n'; else printf '0\n'; fi;;
    --property=UnitFileState)
      case "$2" in
        agmi.service) printf 'disabled\n';;
        agmi-health.timer) printf 'enabled\n';;
        *) printf 'static\n';;
      esac;;
    *) exit 96;;
  esac;;
stop)
  [ "$2" = agmi.service ] || exit 97
  [ ! -f "$root/stop-stays-active" ] || exit 1
  printf 'inactive' > "$root/runtime"
  [ ! -f "$root/stop-fails" ];;
start)
  [ "$2" = agmi.service ] || exit 98
  [ ! -f "$root/start-fails" ] || exit 1
  printf 'active' > "$root/runtime";;
*) exit 99;;
esac
"#,
            quoted(directory),
            quoted(&installation.units),
            quoted(Path::new(&id)),
            quoted(&installation.root.join(".install-lock")),
        )
        .as_bytes(),
        0o700,
    )?;
    Ok(installation)
}

fn repair_report() -> Value {
    json!({"repairs":{"applied":1,"failure":null}})
}

fn repair_controls(directory: &Path) -> Result<Vec<String>> {
    Ok(fs::read_to_string(directory.join("events"))?
        .lines()
        .filter(|line| !line.starts_with("--user show "))
        .map(str::to_owned)
        .collect())
}

#[test]
fn repair_restores_active_intent_after_actions_errors_and_cancellation() -> Result<()> {
    if run_fixture_in_subprocess(
        "installer::native::tests::repair_restores_active_intent_after_actions_errors_and_cancellation",
    )? {
        return Ok(());
    }
    let _cancellation = InstallerCancellation::acquire()?;
    let temporary = OwnedPath::directory(&std::env::temp_dir(), "agmi-repair-test")?;
    let directory = &temporary.path;
    let installation = repair_fixture(directory)?;
    let report = installation.repair_runtime(|| {
        assert_eq!(fs::read_to_string(directory.join("runtime"))?, "inactive");
        assert!(InstallLock::acquire(&installation.root).is_err());
        Ok(repair_report())
    })?;
    assert_eq!(report["repairs"]["applied"], 1);
    assert_eq!(report["repairs"]["restoration"]["verified"], true);
    assert_eq!(report["repairs"]["restoration"]["runtime"], "restored");
    assert_eq!(report["repairs"]["restoration"]["prior_runtime"], "active");
    assert_eq!(
        repair_controls(directory)?,
        ["--user stop agmi.service", "--user start agmi.service"]
    );
    assert_eq!(fs::read_to_string(directory.join("timer"))?, "active");
    assert_eq!(
        fs::read(&installation.config)?,
        b"paused = true\nprivate sentinel\n"
    );

    fs::write(directory.join("events"), "")?;
    let error = installation
        .repair_runtime(|| {
            Err(crate::lifecycle::LifecycleError {
                code: "account_locked",
                message: "sanitized action refusal",
            }
            .into())
        })
        .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<crate::lifecycle::LifecycleError>()
            .unwrap()
            .code,
        "account_locked"
    );
    let evidence = error.downcast_ref::<RepairRuntimeError>().unwrap();
    assert_eq!(evidence.code, "repair_action_failed");
    assert_eq!(evidence.restoration["verified"], true);
    assert_eq!(fs::read_to_string(directory.join("runtime"))?, "active");
    assert_eq!(
        repair_controls(directory)?,
        ["--user stop agmi.service", "--user start agmi.service"]
    );

    fs::write(directory.join("events"), "")?;
    let interrupted = installation.repair_runtime(|| {
        CANCELLED.store(libc::SIGTERM, Ordering::Relaxed);
        Ok(repair_report())
    });
    CANCELLED.store(0, Ordering::Relaxed);
    let error = interrupted.unwrap_err();
    let evidence = error.downcast_ref::<RepairRuntimeError>().unwrap();
    assert_eq!(evidence.code, "repair_interrupted");
    assert_eq!(evidence.restoration["verified"], true);
    assert_eq!(evidence.report.as_ref().unwrap()["repairs"]["applied"], 1);
    assert_eq!(fs::read_to_string(directory.join("runtime"))?, "active");
    assert_eq!(
        repair_controls(directory)?,
        ["--user stop agmi.service", "--user start agmi.service"]
    );

    // Stopped and failed intent stays stopped; the paused configuration
    // and even an inactive health timer remain byte-for-byte unchanged.
    fs::write(directory.join("timer"), "inactive")?;
    for state in ["inactive", "failed"] {
        fs::write(directory.join("events"), "")?;
        fs::write(directory.join("runtime"), state)?;
        let report = installation.repair_runtime(|| Ok(repair_report()))?;
        assert_eq!(report["repairs"]["restoration"]["runtime"], "unchanged");
        assert_eq!(report["repairs"]["restoration"]["prior_runtime"], state);
        assert_eq!(report["repairs"]["restoration"]["manager_action"], "none");
        assert_eq!(report["repairs"]["restoration"]["verified"], true);
        assert_eq!(fs::read_to_string(directory.join("runtime"))?, state);
        assert!(repair_controls(directory)?.is_empty());
    }
    assert_eq!(fs::read_to_string(directory.join("timer"))?, "inactive");
    assert_eq!(
        fs::read(&installation.config)?,
        b"paused = true\nprivate sentinel\n"
    );
    Ok(())
}

#[test]
fn repair_stop_and_restore_failures_never_hide_completed_actions() -> Result<()> {
    if run_fixture_in_subprocess(
        "installer::native::tests::repair_stop_and_restore_failures_never_hide_completed_actions",
    )? {
        return Ok(());
    }
    let _cancellation = InstallerCancellation::acquire()?;
    let temporary = OwnedPath::directory(&std::env::temp_dir(), "agmi-repair-failure-test")?;
    let directory = &temporary.path;
    let installation = repair_fixture(directory)?;
    for (flag, controls) in [
        (
            "stop-fails",
            vec!["--user stop agmi.service", "--user start agmi.service"],
        ),
        ("stop-stays-active", vec!["--user stop agmi.service"]),
    ] {
        fs::write(directory.join("events"), "")?;
        fs::write(directory.join(flag), "")?;
        let error = installation
            .repair_runtime(|| panic!("failed stop ran repair"))
            .unwrap_err();
        let evidence = error.downcast_ref::<RepairRuntimeError>().unwrap();
        assert_eq!(evidence.code, "repair_runtime_stop_failed");
        assert_eq!(evidence.restoration["verified"], true);
        assert_eq!(repair_controls(directory)?, controls);
        assert_eq!(fs::read_to_string(directory.join("runtime"))?, "active");
        fs::remove_file(directory.join(flag))?;
    }
    fs::write(directory.join("start-fails"), "")?;
    for action_fails in [false, true] {
        fs::write(directory.join("runtime"), "active")?;
        fs::write(directory.join("events"), "")?;
        let error = installation
            .repair_runtime(|| {
                if action_fails {
                    anyhow::bail!("private callback failure not for presentation");
                }
                Ok(repair_report())
            })
            .unwrap_err();
        let evidence = error.downcast_ref::<RepairRuntimeError>().unwrap();
        assert_eq!(evidence.code, "repair_runtime_restore_failed");
        assert_eq!(evidence.restoration["verified"], false);
        assert_eq!(evidence.restoration["failure_code"], "restoration_failed");
        assert_eq!(evidence.report.is_none(), action_fails);
        if let Some(report) = &evidence.report {
            assert_eq!(report["repairs"]["applied"], 1);
            assert_eq!(report["repairs"]["restoration"]["verified"], false);
        }
        assert!(!error.to_string().contains("private"));
        assert!(!evidence.restoration.to_string().contains("private"));
        assert_eq!(fs::read_to_string(directory.join("runtime"))?, "inactive");
        assert_eq!(
            repair_controls(directory)?,
            ["--user stop agmi.service", "--user start agmi.service"]
        );
    }
    fs::remove_file(directory.join("start-fails"))?;

    // A successful start is insufficient: the actual process must use
    // the selected binary and canonical config before success is claimed.
    fs::write(directory.join("runtime"), "active")?;
    let error = installation
        .repair_runtime(|| {
            fs::write(
                installation.proc_root.join("42/cmdline"),
                b"other\0--config\0private\0run\0",
            )?;
            Ok(repair_report())
        })
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<RepairRuntimeError>().unwrap().code,
        "repair_runtime_restore_failed"
    );
    assert_eq!(
        error
            .downcast_ref::<RepairRuntimeError>()
            .unwrap()
            .restoration["verified"],
        false
    );
    Ok(())
}

#[test]
fn repair_refuses_unvalidated_installations_before_manager_actions() -> Result<()> {
    if run_fixture_in_subprocess(
        "installer::native::tests::repair_refuses_unvalidated_installations_before_manager_actions",
    )? {
        return Ok(());
    }
    let _cancellation = InstallerCancellation::acquire()?;
    let temporary = OwnedPath::directory(&std::env::temp_dir(), "agmi-repair-preflight-test")?;
    let directory = &temporary.path;
    let installation = repair_fixture(directory).context("prepare repair preflight fixture")?;
    let refused = || -> Result<()> {
        fs::write(directory.join("events"), "")?;
        let error = installation
            .repair_runtime(|| panic!("unvalidated installation ran repair"))
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<RepairRuntimeError>().unwrap().code,
            "repair_runtime_unavailable"
        );
        assert_eq!(
            error
                .downcast_ref::<RepairRuntimeError>()
                .unwrap()
                .restoration["manager_action"],
            "none"
        );
        assert!(repair_controls(directory)?.is_empty());
        Ok(())
    };
    for state in ["activating", "deactivating", "reloading"] {
        fs::write(directory.join("runtime"), state)?;
        refused()?;
    }
    fs::write(directory.join("runtime"), "active")?;
    fs::write(directory.join("job"), "12")?;
    refused()?;
    fs::write(directory.join("job"), "0")?;
    fs::write(directory.join("dropins"), "/private/unsupported-override")?;
    refused()?;
    fs::write(directory.join("dropins"), "")?;
    fs::write(directory.join("fragment"), directory.as_os_str().as_bytes())?;
    refused()?;
    fs::write(
        directory.join("fragment"),
        installation.units.as_os_str().as_bytes(),
    )?;
    let override_path = installation.units.join("agmi.service.d");
    fs::create_dir(&override_path)?;
    refused()?;
    fs::remove_dir(override_path)?;
    fs::set_permissions(&installation.config, fs::Permissions::from_mode(0o666))?;
    refused()?;
    fs::set_permissions(&installation.config, fs::Permissions::from_mode(0o600))?;

    let command_path = installation.proc_root.join("42/cmdline");
    let command = fs::read(&command_path)?;
    fs::write(&command_path, b"other\0--config\0different-config\0run\0")?;
    refused()?;
    fs::write(&command_path, command)?;
    let id = fs::read_link(installation.root.join("current"))?;
    let release = installation.root.join(&id);
    let unit = release.join("agmi.service");
    let template = fs::read(&unit)?;
    fs::write(&unit, b"[Service]\nExecStart=/unrelated/runtime\n")?;
    fs::write(release.join("SHA256SUMS"), checksums(&release)?)?;
    refused()?;
    fs::write(&unit, template)?;
    fs::write(release.join("SHA256SUMS"), checksums(&release)?)?;
    replace_link(
        Path::new("not-a-release"),
        &installation.root.join("current"),
    )?;
    refused()?;
    replace_link(&id, &installation.root.join("current"))?;
    assert_eq!(
        installation
            .repair_runtime(|| Ok(repair_report()))
            .context("repair validated installation after refusal cases")?["repairs"]["restoration"]
            ["verified"],
        true
    );
    Ok(())
}
