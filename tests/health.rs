use agmi::config::Config;
use serde_json::Value;
use std::{fs, process::Command};

fn run_health(config: &Config, args: &[&str]) -> (tempfile::TempDir, std::process::Output) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, toml::to_string(config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agmi"))
        .arg("--config")
        .arg(path)
        .args(["--json", "health"])
        .args(args)
        .output()
        .unwrap();
    (dir, output)
}

#[test]
fn default_health_omits_retained_trees_but_verbose_preserves_them() {
    let (_dir, config, _db, _at) = initialized_health_fixture();
    let (_config_dir, compact) = run_health(&config, &["--min-free-mib", "0"]);
    let compact: Value = serde_json::from_slice(&compact.stdout).unwrap();
    let (_config_dir, verbose) = run_health(&config, &["--min-free-mib", "0", "--verbose"]);
    let verbose: Value = serde_json::from_slice(&verbose.stdout).unwrap();
    assert!(compact["data"].get("pending_work").is_none());
    assert!(verbose["data"]["pending_work"].is_array());
    assert_eq!(
        compact["data"]["pending_work_count"],
        verbose["data"]["pending_work"].as_array().unwrap().len()
    );
    for field in [
        "healthy",
        "admission_blocked",
        "effective_capabilities",
        "observations",
        "intervention",
    ] {
        assert_eq!(compact["data"][field], verbose["data"][field], "{field}");
    }
}

#[test]
fn missing_installation_is_nonzero_structured_and_does_not_initialize_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.state_dir = dir.path().join("private-state-canary");
    config.network.chain = format!(
        "health-{}",
        dir.path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('.', "")
    );
    config.network.address = format!("poa1{}", "1".repeat(32));
    config.network.credential_file = dir.path().join("missing-credential-canary");
    config.capabilities.answer.model.guidance_file =
        Some(dir.path().join("missing-guidance-canary"));
    let (_config_dir, output) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "agmi.cli.v1");
    assert_eq!(value["type"], "health");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["healthy"], false);
    assert_eq!(value["data"]["intervention"]["unattended"], false);
    for kind in ["answer", "judge", "mine"] {
        assert_eq!(value["data"]["work"][kind]["progress"], "blocked");
        assert_eq!(
            value["data"]["work"][kind]["intervention"]["status"],
            "operator_required"
        );
    }
    assert_eq!(value["data"]["thresholds"]["warn_free_mib"], 0);
    assert_eq!(value["data"]["admission_blocked"], Value::Null);
    for field in [
        "oldest_unresolved_operation",
        "oldest_unresolved_since",
        "oldest_unresolved_age_seconds",
    ] {
        assert_eq!(value["data"].get(field), Some(&Value::Null));
    }
    for obsolete in ["blocking_operation", "blocked_since", "blocked_age_seconds"] {
        assert!(value["data"].get(obsolete).is_none());
    }
    assert!(
        value["data"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "not_initialized")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("canary"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&config.network.address));
    assert!(!config.state_dir.exists());
}

#[cfg(unix)]
#[test]
fn disk_guard_checks_existing_parent_and_never_creates_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.state_dir = dir.path().join("not-created/state");
    let (_config_dir, output) = run_health(&config, &["--min-free-mib", "18446744073709551615"]);
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["thresholds"]["warn_free_mib"], u64::MAX);
    assert!(
        value["data"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "state_disk_headroom_low")
    );
    assert!(value["data"]["state_free_mib"].as_u64().is_some());
    assert!(
        value["data"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "state_disk_space_low")
    );
    assert_eq!(
        value["data"]["intervention"]["next_action"],
        "inspect_state_filesystem"
    );
    assert_eq!(value["data"]["intervention"]["unattended"], false);
    assert_eq!(
        value["data"]["issues"],
        value["data"]["operational"]["issues"]
    );
    for lane in ["answer", "judge", "mine"] {
        assert!(
            !value["data"]["components"][lane]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == "state_disk_space_low")
        );
    }
    assert!(!dir.path().join("not-created").exists());
}

#[test]
fn health_before_onboarding_is_structured_read_only_and_preserves_config_selection() {
    for invalid in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let private = "private-invalid-config-value";
        if invalid {
            fs::write(&path, format!("invalid = \"{private}\n")).unwrap();
        }
        let before = fs::read_dir(dir.path()).unwrap().count();
        let output = Command::new(env!("CARGO_BIN_EXE_agmi"))
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
            .arg("--config")
            .arg(&path)
            .args(["--json", "health"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        let code = if invalid {
            "config_invalid"
        } else {
            "config_missing"
        };
        assert_eq!(envelope["type"], "health");
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["data"]["issues"], serde_json::json!([code]));
        assert_eq!(envelope["data"]["operational"]["status"], "unknown");
        assert_eq!(
            envelope["data"]["components"]["controller"]["state"],
            "unknown"
        );
        assert_eq!(envelope["data"]["components"]["answer"]["state"], "unknown");
        assert_eq!(
            envelope["data"]["components"]["api"]["lanes"]["answer"]["state"],
            "unknown"
        );
        assert!(envelope["data"]["risk"]["unresolved_effects"].is_null());
        assert_eq!(envelope["data"]["intervention"]["status"], "undetermined");
        assert_eq!(envelope["data"]["intervention"]["unattended"], Value::Null);
        assert_eq!(
            envelope["data"]["assessment_scope"]["state_filesystem"],
            "not_assessed"
        );
        for kind in ["answer", "judge", "mine"] {
            assert_eq!(
                envelope["data"]["work"][kind]["intervention"]["status"],
                "undetermined"
            );
            assert_eq!(
                envelope["data"]["work"][kind]["operational"]["state"],
                "unknown"
            );
            assert_eq!(
                envelope["data"]["work"][kind]["operational"]["reasons"],
                serde_json::json!([code])
            );
        }
        assert_eq!(envelope["data"]["mutations"], false);
        let action = &envelope["data"]["diagnostics"][0]["next_actions"][0];
        assert_eq!(action["kind"], "command");
        assert_eq!(action["authorization_required"], false);
        assert_eq!(action["argv"][1], "--config");
        assert_eq!(action["argv"][2], serde_json::json!(path));
        assert_eq!(before, fs::read_dir(dir.path()).unwrap().count());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(private));
        if invalid {
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                format!("invalid = \"{private}\n")
            );
        }
    }
}

#[test]
fn health_with_default_missing_config_never_creates_onboarding_directories() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agmi"))
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
        .args(["--json", "health"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        envelope["data"]["issues"],
        serde_json::json!(["config_missing"])
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn uninitialized_status_and_health_share_progress_without_creating_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.state_dir = dir.path().join("missing-state");
    let status = agmi::runtime::status(&config).unwrap();
    let result = agmi::health::check(
        &config,
        agmi::health::Options {
            min_free_mib: 0,
            ..agmi::health::Options::default()
        },
    )
    .unwrap();
    assert_eq!(status["work"], result["work"]);
    assert_eq!(status["intervention"], result["intervention"]);
    assert_eq!(status["hosted_identity"], result["hosted_identity"]);
    assert_eq!(status["lane_controls"], result["lane_controls"]);
    assert_eq!(status["lane_participation"], result["lane_participation"]);
    for lane in agmi::capability::LaneId::NAMES {
        assert_ne!(
            result["lane_controls"][lane]["observed_admission"]["state"],
            "open"
        );
        assert!(result["lane_controls"][lane]["fence_ack"].is_null());
    }
    assert_eq!(result["hosted_identity"]["status"], "unobserved");
    assert_eq!(result["hosted_identity"]["rejection"], Value::Null);
    assert_eq!(result["hosted_identity"]["legacy_failure"], false);
    assert_eq!(result["hosted_identity_verified"], Value::Null);
    assert_eq!(result["healthy"], false);
    assert!(!config.state_dir.exists());
}

fn initialized_health_fixture() -> (tempfile::TempDir, Config, rusqlite::Connection, i64) {
    use agmi::config::Mode;
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.state_dir = dir.path().join("state");
    config.network.chain = format!(
        "test-{}",
        dir.path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .replace('.', "")
    );
    config.network.address = format!("poa1{}", "1".repeat(32));
    config.network.credential_file = dir.path().join("missing-credential");
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Active;
    let path = dir.path().join("config.toml");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let initialized = Command::new(env!("CARGO_BIN_EXE_agmi"))
        .arg("--config")
        .arg(&path)
        .args(["--json", "pause"])
        .output()
        .unwrap();
    assert!(initialized.status.success(), "{initialized:?}");
    let db = rusqlite::Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut policy = serde_json::to_value(&config).unwrap();
    policy["schema_version"] = json!(2);
    policy["lane_revisions"] = json!({"answer":"fixture","judge":"fixture","mine":"fixture"});
    db.execute("UPDATE control SET paused=0", []).unwrap();
    db.execute("INSERT OR REPLACE INTO runtime_authority VALUES(1,1)", [])
        .unwrap();
    db.execute(
        "INSERT OR REPLACE INTO runtime_policy VALUES(1,?1)",
        [policy.to_string()],
    )
    .unwrap();
    let (generation, revision): (i64, i64) = db.query_row(
        "SELECT c.generation,l.control_revision FROM control c,lane_control l WHERE l.lane='judge'",
        [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    let participation = json!({"judge":{
        "stamp":{"account_generation":generation,"lane_control_revision":revision,
            "authority_epoch":1,"lane_config_revision":"fixture"},
        "assessment":{"source":"runtime","observed_at":at,"valid_until":at+3600,
            "completeness":"complete","locally_judgeable":false,"observed_opportunities":0}
    }});
    db.execute(
        "INSERT OR REPLACE INTO runtime_state
        (singleton,effective_revision,reload_blocked,capabilities,observed_at,lane_participation)
        VALUES(1,'fixture',0,?1,?2,?3)",
        rusqlite::params![
            json!({"answer":"off","judge":"active","mine":"off"}).to_string(),
            at,
            participation.to_string()
        ],
    )
    .unwrap();
    db.execute(
        "INSERT OR REPLACE INTO hosted_identity_evidence
        (singleton,status,observed_at,last_verified_at,rejection,legacy_failure)
        VALUES(1,'verified',?1,?1,NULL,0)",
        [at],
    )
    .unwrap();
    (dir, config, db, at)
}

#[test]
fn expired_discovery_is_not_healthy_under_the_longer_controller_threshold() {
    use agmi::config::CountLimit;
    for lane in ["answer", "judge", "mine"] {
        let (_dir, mut config, db, at) = initialized_health_fixture();
        diagnostic_lane(&mut config, &db, lane, CountLimit::Unbounded, at);
        assert_eq!(diagnostic_health(&config)["healthy"], true);
        if lane == "judge" {
            db.execute(
                "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
                '$.judge.assessment.observed_at',?1,'$.judge.assessment.valid_until',?2)",
                rusqlite::params![at - 121, at - 1],
            )
            .unwrap();
        } else {
            db.execute(
                "UPDATE lane_observations SET observed_at=?1 WHERE lane=?2",
                rusqlite::params![at - 121, lane],
            )
            .unwrap();
        }
        let path = config
            .state_dir
            .parent()
            .unwrap()
            .join("expiry-config.toml");
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let version: i64 = db
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .unwrap();
        for command in ["status", "health", "doctor"] {
            let mut process = Command::new(env!("CARGO_BIN_EXE_agmi"));
            process
                .arg("--config")
                .arg(&path)
                .args(["--json", command, "--verbose"]);
            if command == "health" {
                process.args(["--min-free-mib", "0"]);
            }
            let output = process.output().unwrap();
            let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
            let report = &envelope["data"];
            assert_ne!(
                report["components"][lane]["state"], "ok",
                "{lane}/{command}: {report}"
            );
            assert_ne!(
                report["operational"]["status"], "clear",
                "{lane}/{command}: {report}"
            );
            if lane == "answer" && command == "health" {
                assert_eq!(
                    report["current_epoch"]["evidence_fresh"], false,
                    "{command}: {report}"
                );
            }
            if command == "health" {
                assert!(!output.status.success());
            }
        }
        let after: i64 = db
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(after, version, "diagnostics mutated the journal");
    }
}

#[test]
fn future_judge_assessment_alone_makes_health_cli_fail() {
    let (_dir, config, db, at) = initialized_health_fixture();
    let (_config_dir, before) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(before.status.success(), "{before:?}");
    let before: Value = serde_json::from_slice(&before.stdout).unwrap();
    assert_eq!(before["data"]["components"]["judge"]["state"], "ok");
    db.execute(
        "UPDATE runtime_state SET lane_participation=json_set(
        lane_participation,'$.judge.assessment.observed_at',?1,
        '$.judge.assessment.valid_until',?2)",
        rusqlite::params![at + 3600, at + 7200],
    )
    .unwrap();
    let (_config_dir, after) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(!after.status.success());
    let after: Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(after["ok"], false);
    assert_eq!(
        after["data"]["issues"],
        serde_json::json!(["clock_regressed"])
    );
    assert_eq!(after["data"]["healthy"], false);
    assert_eq!(after["data"]["attention_required"], true);
    assert_eq!(after["data"]["components"]["judge"]["state"], "unknown");
    assert_eq!(
        after["data"]["work"]["judge"]["intervention"]["reason"],
        "clock_regressed"
    );
}

#[test]
fn pending_execution_bound_reaches_health_cli_without_becoming_launch_authority() {
    use serde_json::json;
    let (_dir, config, db, at) = initialized_health_fixture();
    db.execute(
        "INSERT INTO operations
        (id,kind,work_key,state,request,generation,revision,created_at,updated_at)
        SELECT 1,'judge','pending-model','generating','{}',generation,'fixture',?1,?1 FROM control",
        [at],
    )
    .unwrap();
    db.execute(
        "INSERT INTO operation_evidence(operation_id,policy,evidence)
        VALUES(1,?1,?2)",
        rusqlite::params![
            json!({"pending_execution_deadline":at+3600}).to_string(),
            json!({"stage":"model_preflight","execution":"not_started",
                "state":"awaiting_admission","remaining_budget_millis":1})
            .to_string()
        ],
    )
    .unwrap();
    let (_config_dir, before) = run_health(&config, &["--min-free-mib", "0", "--verbose"]);
    assert!(before.status.success(), "{before:?}");
    let before: Value = serde_json::from_slice(&before.stdout).unwrap();
    for field in ["pending_work", "captured_work"] {
        assert_eq!(
            before["data"][field][0]["pending_execution_deadline"],
            at + 3600
        );
        assert!(before["data"][field][0]["model_deadline"].is_null());
    }
    assert_eq!(
        before["data"]["work"]["judge"]["intervention"]["reason"],
        "model_launch_awaiting_admission"
    );
    db.execute(
        "UPDATE operation_evidence SET policy=?1,evidence=json_set(
        evidence,'$.remaining_budget_millis',999999999)",
        [json!({"pending_execution_deadline":at-1}).to_string()],
    )
    .unwrap();
    let (_config_dir, expired) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(!expired.status.success());
    let expired: Value = serde_json::from_slice(&expired.stdout).unwrap();
    assert_eq!(
        expired["data"]["issues"],
        json!(["pending_model_execution_expired"])
    );
    assert_eq!(
        expired["data"]["work"]["judge"]["intervention"]["reason"],
        "pending_model_execution_expired"
    );
    assert_eq!(expired["data"]["risk"]["attention_required"], false);
    db.execute("UPDATE operation_evidence SET policy='{}'", [])
        .unwrap();
    let (_config_dir, missing) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(!missing.status.success());
    let missing: Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(
        missing["data"]["warnings"],
        json!(["model_deadline_unavailable"])
    );
    assert_eq!(missing["data"]["healthy"], false);
    assert_eq!(missing["data"]["operational"]["status"], "unknown");
    assert_eq!(
        missing["data"]["issues"],
        json!(["model_deadline_unavailable"])
    );
    assert_eq!(
        missing["data"]["issues"],
        missing["data"]["operational"]["issues"]
    );
    assert_eq!(missing["data"]["components"]["judge"]["state"], "unknown");
    assert_eq!(
        missing["data"]["work"]["judge"]["intervention"]["status"],
        "undetermined"
    );
    assert_eq!(
        missing["data"]["work"]["judge"]["intervention"]["reason"],
        "model_deadline_unavailable"
    );
    let deadline: Option<i64> = db
        .query_row(
            "SELECT model_deadline FROM operation_evidence WHERE operation_id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deadline, None);
}

#[test]
fn partial_judge_inventory_fails_required_health_but_not_participation_opt_out() {
    let (_dir, config, db, _at) = initialized_health_fixture();
    db.execute(
        "UPDATE runtime_state SET lane_participation=json_set(
        lane_participation,'$.judge.assessment.completeness','bounded_partial')",
        [],
    )
    .unwrap();
    let (_config_dir, required) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(!required.status.success());
    let required: Value = serde_json::from_slice(&required.stdout).unwrap();
    assert_eq!(required["data"]["healthy"], false);
    assert_eq!(required["data"]["components"]["judge"]["state"], "unknown");
    assert_eq!(required["data"]["operational"]["status"], "unknown");
    assert!(
        required["data"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "work_evidence_unavailable")
    );
    assert_eq!(
        required["data"]["issues"],
        required["data"]["operational"]["issues"]
    );
    let (_config_dir, opted_out) = run_health(
        &config,
        &["--min-free-mib", "0", "--expect-participation", "false"],
    );
    assert!(opted_out.status.success(), "{opted_out:?}");
    let opted_out: Value = serde_json::from_slice(&opted_out.stdout).unwrap();
    assert_eq!(opted_out["data"]["healthy"], true);
    assert_eq!(opted_out["data"]["components"]["judge"]["state"], "unknown");
}

fn insert_unknown_judge_operations(db: &rusqlite::Connection, at: i64, count: i64) {
    for id in 1..=count {
        db.execute(
            "INSERT INTO operations
            (id,kind,work_key,state,request,generation,revision,created_at,updated_at)
            SELECT ?1,'judge',?2,'unknown','{}',generation,'fixture',?3,?3 FROM control",
            rusqlite::params![id, format!("paused-judge-uncertainty-{id}"), at],
        )
        .unwrap();
    }
}

#[test]
fn clear_global_and_lane_pauses_pass_only_participation_opt_out() {
    for (global, pause, reason) in [
        (true, "UPDATE control SET paused=1", "admission_paused"),
        (
            false,
            "UPDATE lane_control SET paused=1 WHERE lane='judge'",
            "lane_paused",
        ),
    ] {
        let (_dir, config, db, _at) = initialized_health_fixture();
        db.execute(pause, []).unwrap();
        for expect in ["true", "false"] {
            let (_config_dir, output) = run_health(
                &config,
                &["--min-free-mib", "0", "--expect-participation", expect],
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let data = &report["data"];
            assert_eq!(output.status.success(), expect == "false", "{report}");
            assert_eq!(data["healthy"], expect == "false");
            assert_eq!(data["paused"], global);
            let admission = &data["participation"]["lanes"]["judge"];
            assert_eq!(admission["allowed"], false);
            assert_eq!(admission["reason"], reason);
            assert_eq!(
                data["components"]["judge"]["reasons"],
                serde_json::json!([reason])
            );
            if !global {
                assert!(
                    !data["issues"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|issue| issue == "admission_paused"),
                    "{report}"
                );
            }
            assert_eq!(admission.get("pre_intent_blocker"), Some(&Value::Null));
            assert_eq!(
                data["lane_controls"]["judge"]["authoritative_closure"]["state"],
                "closed"
            );
            if expect == "false" {
                assert_eq!(data["issues"], serde_json::json!([]));
            } else {
                assert!(
                    data["issues"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|issue| issue == reason),
                    "{report}"
                );
            }
        }
    }
}

#[test]
fn pause_opt_out_preserves_underlying_accounting_and_server_blocks() {
    use agmi::{capability::LaneId, config::ParticipationMode};
    for reason in [
        "account_uncertainty",
        "manual_authorization_required",
        "lane_unresolved_capacity",
        "shared_server_restriction",
    ] {
        let (_dir, mut config, db, at) = initialized_health_fixture();
        db.execute("UPDATE control SET paused=1", []).unwrap();
        match reason {
            "account_uncertainty" => insert_unknown_judge_operations(&db, at, 1),
            "lane_unresolved_capacity" => insert_unknown_judge_operations(&db, at, 4),
            "manual_authorization_required" => {
                config.capabilities.judge.participation.mode = ParticipationMode::Manual;
                let revision = config.lane_revision(LaneId::Judge).unwrap();
                db.execute(
                    "UPDATE runtime_policy SET policy=json_set(policy,
                    '$.capabilities.judge.participation.mode','manual',
                    '$.lane_revisions.judge',?1)",
                    [&revision],
                )
                .unwrap();
                db.execute(
                    "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
                    '$.judge.stamp.lane_config_revision',?1)",
                    [&revision],
                )
                .unwrap();
                insert_unknown_judge_operations(&db, at, 1);
            }
            "shared_server_restriction" => {
                let origin = config
                    .network
                    .base_url
                    .split('/')
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("/");
                let authority = format!("{}\n{}", config.network.chain, config.network.address);
                db.execute("INSERT INTO request_restrictions
                    (authority,origin,scope,target,basis,not_before,observed_at,request_id,source,read_class,effect_class)
                    VALUES(?1,?2,'answer_judge_effects','','server',?3,?4,'paused-server-restriction','server',0,1)",
                    rusqlite::params![authority, origin, at + 3600, at]).unwrap();
            }
            _ => unreachable!(),
        }
        for expect in ["true", "false"] {
            let (_config_dir, output) = run_health(
                &config,
                &["--min-free-mib", "0", "--expect-participation", expect],
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let data = &report["data"];
            assert!(!output.status.success(), "{reason}: {report}");
            assert_eq!(data["healthy"], false);
            let admission = &data["participation"]["lanes"]["judge"];
            assert_eq!(admission["allowed"], false);
            assert_eq!(admission["reason"], "admission_paused");
            assert_eq!(
                admission["pre_intent_blocker"]["reason"], reason,
                "{report}"
            );
            if expect == "false" {
                assert_eq!(data["issues"], serde_json::json!([reason]), "{report}");
                assert_eq!(data["operational"]["status"], "blocked");
            }
        }
    }
}

#[test]
fn paused_current_bindings_keep_read_failures_without_folding_unrelated_reads() {
    use agmi::{capability::LaneId, config::ParticipationMode};
    use serde_json::json;
    for pause in [
        "UPDATE control SET paused=1",
        "UPDATE lane_control SET paused=1 WHERE lane='judge'",
    ] {
        for state in ["queued", "unknown"] {
            let (_dir, mut config, db, at) = initialized_health_fixture();
            config.capabilities.judge.participation.mode = ParticipationMode::ParticipationFirst;
            config
                .capabilities
                .judge
                .participation
                .uncertainty_grace_seconds = 0;
            let revision = config.lane_revision(LaneId::Judge).unwrap();
            db.execute(
                "UPDATE runtime_policy SET policy=json_set(policy,
                '$.capabilities.judge.participation.mode','participation_first',
                '$.capabilities.judge.participation.uncertainty_grace_seconds',0,
                '$.lane_revisions.judge',?1)",
                [&revision],
            )
            .unwrap();
            db.execute(
                "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
                '$.judge.stamp.lane_config_revision',?1)",
                [&revision],
            )
            .unwrap();
            db.execute(pause, []).unwrap();
            db.execute("INSERT INTO operations
                (id,kind,work_key,state,request,generation,revision,created_at,updated_at,job_id,binding_revision)
                SELECT 1,'judge','bound-read',?1,'{}',generation,'fixture',?2,?2,'fixture-job',1 FROM control",
                rusqlite::params![state,at]).unwrap();
            db.execute("INSERT INTO read_state
                (owner,purpose,resource,operation_id,binding_revision,failures,last_failure_at,failure_category,status)
                VALUES('judge','job','1:1',1,1,1,?1,'http',503)", [at]).unwrap();
            for (case, expected_healthy) in [
                ("failed", false),
                ("superseded", true),
                ("wrong_binding", true),
                ("discovery", true),
            ] {
                match case {
                    "superseded" => {
                        db.execute(
                            "UPDATE read_state SET last_success_at=?1,last_failure_at=?2,
                            failure_category=NULL,status=200",
                            rusqlite::params![at, at - 1],
                        )
                        .unwrap();
                    }
                    "wrong_binding" => {
                        db.execute(
                            "UPDATE read_state SET binding_revision=2,last_success_at=NULL,
                            last_failure_at=?1,failure_category='http',status=503",
                            [at],
                        )
                        .unwrap();
                    }
                    "discovery" => {
                        db.execute(
                            "UPDATE read_state SET purpose='discovery',resource='assignments',
                            operation_id=NULL,binding_revision=NULL",
                            [],
                        )
                        .unwrap();
                    }
                    _ => {}
                }
                let (_config_dir, output) = run_health(
                    &config,
                    &["--min-free-mib", "0", "--expect-participation", "false"],
                );
                let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                let data = &report["data"];
                assert_eq!(
                    data["participation"]["lanes"]["judge"].get("pre_intent_blocker"),
                    Some(&Value::Null),
                    "{case}: {report}"
                );
                assert_eq!(
                    output.status.success(),
                    expected_healthy,
                    "{state}/{case}: {report}"
                );
                assert_eq!(data["healthy"], expected_healthy);
                assert_eq!(
                    data["issues"],
                    if expected_healthy {
                        json!([])
                    } else {
                        json!(["api_dependency_unavailable"])
                    },
                    "{state}/{case}: {report}"
                );
                if !expected_healthy {
                    assert_eq!(data["operational"]["status"], "degraded");
                }
            }
        }
    }
}

fn persist_diagnostic_policy(config: &Config, db: &rusqlite::Connection) {
    use serde_json::json;
    let mut policy = serde_json::to_value(config).unwrap();
    policy["schema_version"] = json!(2);
    policy["lane_revisions"] = json!({"answer":"fixture","judge":"fixture","mine":"fixture"});
    db.execute("UPDATE runtime_policy SET policy=?1", [policy.to_string()])
        .unwrap();
}

fn diagnostic_lane(
    config: &mut Config,
    db: &rusqlite::Connection,
    lane: &str,
    limit: agmi::config::CountLimit,
    at: i64,
) {
    use agmi::config::{Mode, ParticipationMode};
    use serde_json::json;
    config.capabilities.answer.mode = if lane == "answer" {
        Mode::Active
    } else {
        Mode::Off
    };
    config.capabilities.judge.mode = if lane == "judge" {
        Mode::Active
    } else {
        Mode::Off
    };
    config.capabilities.mine.mode = if lane == "mine" {
        Mode::Active
    } else {
        Mode::Off
    };
    config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
    config
        .capabilities
        .answer
        .participation
        .uncertainty_grace_seconds = 0;
    config
        .capabilities
        .answer
        .participation
        .max_unresolved_operations = limit;
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
        .max_unresolved_operations = limit;
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
        .max_unresolved_operations = limit;
    config.capabilities.mine.schedule.each_epoch = true;
    persist_diagnostic_policy(config, db);
    if lane != "judge" {
        db.execute("INSERT OR REPLACE INTO lane_observations
            (lane,authority_epoch,generation,request_sequence,started_at,observed_at,epoch,first_observed_at,answered,fingerprint,challenge)
            SELECT ?1,1,generation,1,?2,?2,2,?2,0,'fixture','{}' FROM control",
            rusqlite::params![lane,at]).unwrap();
    }
    db.execute(
        "INSERT OR REPLACE INTO read_state(owner,purpose,resource,last_success_at,status)
        VALUES(?1,'discovery',?2,?3,200)",
        rusqlite::params![
            lane,
            if lane == "judge" {
                "assignments"
            } else {
                "challenge"
            },
            at
        ],
    )
    .unwrap();
    if lane == "judge" {
        db.execute("UPDATE runtime_state SET lane_participation=json_set(lane_participation,
            '$.judge.assessment.locally_judgeable',json('true'),
            '$.judge.assessment.observed_opportunities',1,'$.judge.assessment.eligible_candidates',1)",
            []).unwrap();
    }
    // Keep serialized effective modes coherent with the canonical policy.
    db.execute(
        "UPDATE runtime_state SET capabilities=?1",
        [json!({"answer":config.capabilities.answer.mode,
            "judge":config.capabilities.judge.mode,"mine":config.capabilities.mine.mode})
        .to_string()],
    )
    .unwrap();
}

fn retained_remote(db: &rusqlite::Connection, lane: &str, state: &str, epoch: u64, at: i64) {
    use serde_json::json;
    let receipt = matches!(state, "included_pending" | "confirmed");
    db.execute("INSERT INTO operations
        (id,kind,work_key,state,request,payload,generation,revision,created_at,updated_at,job_id,txid,binding_revision)
        SELECT 1,?1,?2,?3,?4,'{}',generation,'fixture',?5,?5,?6,?7,1 FROM control",
        rusqlite::params![lane,format!("{epoch}:retained"),state,
            json!({"solver":{"epoch":epoch}}).to_string(),at-10000,
            if receipt {None} else {Some("retained-job")},
            if receipt {Some("a".repeat(64))} else {None}]).unwrap();
    db.execute("INSERT INTO read_state
        (owner,purpose,resource,operation_id,binding_revision,failures,last_failure_at,failure_category,status,local_next_at)
        VALUES(?1,?2,'1:1',1,1,3,?3,'http',404,?4)",
        rusqlite::params![lane,if receipt {"receipt"} else {"job"},at,at+60]).unwrap();
}

fn diagnostic_health(config: &Config) -> Value {
    agmi::health::check(
        config,
        agmi::health::Options {
            min_free_mib: 0,
            ..agmi::health::Options::default()
        },
    )
    .unwrap()
}

#[test]
fn finite_and_unbounded_remote_history_is_risk_across_every_lane_and_surface() {
    use agmi::config::CountLimit;
    for lane in ["answer", "judge", "mine"] {
        for limit in [CountLimit::Bounded(4), CountLimit::Unbounded] {
            for state in ["unknown", "queued", "included_pending", "confirmed"] {
                let (_dir, mut config, db, at) = initialized_health_fixture();
                diagnostic_lane(&mut config, &db, lane, limit, at);
                retained_remote(&db, lane, state, 1, at);
                let version: i64 = db
                    .query_row("PRAGMA data_version", [], |row| row.get(0))
                    .unwrap();
                let health = diagnostic_health(&config);
                let status = agmi::runtime::status(&config).unwrap();
                for report in [&health, &status] {
                    assert_eq!(
                        report["healthy"], true,
                        "{lane}/{limit:?}/{state}: {report}"
                    );
                    assert_eq!(report["operational"]["status"], "clear");
                    assert_eq!(report["components"][lane]["state"], "ok");
                    assert_eq!(report["work"][lane]["operational"]["state"], "ok");
                    assert_eq!(report["risk"]["background_remote_work"], 1);
                    assert_eq!(report["risk"]["attention_required"], true);
                    assert_eq!(report["attention_required"], true);
                    assert_eq!(
                        report["work"][lane]["background_recovery"]["bound_count"],
                        1
                    );
                    assert_eq!(report["pending_work"][0]["state"], state);
                    assert_eq!(
                        report["pending_work"][0]["nonblocking_for_fresh_work"],
                        true
                    );
                    assert_eq!(report["participation"]["lanes"][lane]["allowed"], true);
                    assert_ne!(report["work"][lane]["next_action"], "read_job");
                    assert_ne!(report["work"][lane]["next_action"], "read_receipt");
                    assert_eq!(
                        report["components"]["api"]["resources"][0]["health"]["state"],
                        "degraded"
                    );
                }
                assert_eq!(
                    status["assessment_scope"]["state_filesystem"],
                    "not_assessed"
                );
                if limit == CountLimit::Bounded(4) && state == "queued" {
                    let path = config
                        .state_dir
                        .parent()
                        .unwrap()
                        .join("diagnostic-config.toml");
                    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
                    for command in ["status", "health", "doctor"] {
                        let mut process = Command::new(env!("CARGO_BIN_EXE_agmi"));
                        process.arg("--config").arg(&path).args(["--json", command]);
                        if command == "health" {
                            process.args(["--min-free-mib", "0"]);
                        }
                        let output = process.output().unwrap();
                        assert!(
                            output.status.success(),
                            "{command}: {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
                        let report = &envelope["data"];
                        assert_eq!(report["operational"]["status"], "clear");
                        assert_eq!(report["risk"]["background_remote_work"], 1);
                        assert_eq!(
                            report["work"][lane]["background_recovery"]["bound_count"],
                            1
                        );
                        assert!(
                            report["work"][lane]["background_recovery"]["next_actions"].is_array()
                        );
                        assert_eq!(
                            report["components"]["api"]["background_resources"]["degraded"],
                            1
                        );
                    }
                }
                let after: i64 = db
                    .query_row("PRAGMA data_version", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(after, version, "diagnostics mutated the journal");
            }
        }
    }
}

#[test]
fn finite_capacity_and_strict_gates_survive_background_recovery() {
    use agmi::config::{CountLimit, ParticipationMode};
    for lane in ["answer", "judge", "mine"] {
        let (_dir, mut config, db, at) = initialized_health_fixture();
        diagnostic_lane(&mut config, &db, lane, CountLimit::Bounded(1), at);
        retained_remote(&db, lane, "unknown", 1, at);
        let full = diagnostic_health(&config);
        assert_eq!(full["healthy"], false, "{full}");
        assert_eq!(
            full["participation"]["lanes"][lane]["reason"],
            "lane_unresolved_capacity"
        );
        assert_eq!(full["work"][lane]["background_recovery"]["count"], 0);
        assert_eq!(full["components"][lane]["state"], "blocked");
        diagnostic_lane(&mut config, &db, lane, CountLimit::Bounded(4), at);
        assert_eq!(diagnostic_health(&config)["healthy"], true);
        match lane {
            "answer" => config.capabilities.answer.participation.mode = ParticipationMode::Strict,
            "judge" => config.capabilities.judge.participation.mode = ParticipationMode::Strict,
            _ => config.capabilities.mine.participation.mode = ParticipationMode::Strict,
        }
        persist_diagnostic_policy(&config, &db);
        let strict = diagnostic_health(&config);
        assert_eq!(strict["healthy"], false);
        assert_eq!(
            strict["participation"]["lanes"][lane]["reason"],
            "account_uncertainty"
        );
        assert_eq!(strict["pending_work"][0]["state"], "unknown");
    }
}

#[test]
fn same_work_without_a_viable_path_is_not_background_or_healthy() {
    use agmi::config::CountLimit;
    for lane in ["answer", "judge", "mine"] {
        let (_dir, mut config, db, at) = initialized_health_fixture();
        diagnostic_lane(&mut config, &db, lane, CountLimit::Bounded(4), at);
        retained_remote(&db, lane, "unknown", 2, at);
        // Isolate the work obligation from a transport failure.
        db.execute("DELETE FROM read_state WHERE purpose='job'", [])
            .unwrap();
        if lane == "judge" {
            db.execute(
                "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
                '$.judge.assessment.locally_judgeable',json('false'),
                '$.judge.assessment.eligible_candidates',0,
                '$.judge.assessment.exclusions',json('{\"already_attempted\":1}'),
                '$.judge.assessment.excluded_work',json('[{\"work_key\":\"2:retained\",\"reason\":\"already_attempted\"}]'),
                '$.judge.assessment.excluded_work_truncated',json('false'))",
                [],
            )
            .unwrap();
        }
        let health = diagnostic_health(&config);
        assert_eq!(health["healthy"], false, "{lane}: {health}");
        assert_eq!(health["components"][lane]["state"], "blocked");
        assert_eq!(health["work"][lane]["background_recovery"]["count"], 0);
        assert_eq!(
            health["pending_work"][0]["nonblocking_for_fresh_work"],
            false
        );
        assert!(
            health["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue == "current_work_outcome_unresolved")
        );
        assert!(
            !health["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue == "pending_work_overdue")
        );
    }
}

#[test]
fn accepted_linked_answer_and_current_confirmed_receipt_are_followup_not_failure() {
    use agmi::config::{CountLimit, HistoricalAnswerCapacity};
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "answer", CountLimit::Bounded(1), at);
    config
        .capabilities
        .answer
        .participation
        .historical_unknown_answer_capacity = HistoricalAnswerCapacity::AcceptedLinked;
    persist_diagnostic_policy(&config, &db);
    retained_remote(&db, "answer", "unknown", 2, at);
    db.execute("UPDATE operations SET job_id=NULL WHERE id=1", [])
        .unwrap();
    db.execute("DELETE FROM read_state WHERE purpose='job'", [])
        .unwrap();
    db.execute(
        "INSERT INTO operation_evidence(operation_id,dispatch_sequence) VALUES(1,1)",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO operations
        (id,kind,work_key,state,request,payload,generation,revision,created_at,updated_at,txid,binding_revision)
        SELECT 2,'answer','2:accepted','confirmed',request,payload,generation,revision,created_at,updated_at,?1,1
        FROM operations WHERE id=1", ["b".repeat(64)]).unwrap();
    db.execute(
        "INSERT INTO operation_links(operation_id,retry_of,payload_reused) VALUES(2,1,1)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE lane_observations SET answered=1 WHERE lane='answer'",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO read_state
        (owner,purpose,resource,operation_id,binding_revision,failures,last_failure_at,failure_category,status)
        VALUES('answer','receipt','2:1',2,1,2,?1,'transport',503)", [at]).unwrap();
    let report = diagnostic_health(&config);
    assert_eq!(report["healthy"], true, "{report}");
    assert_eq!(
        report["participation"]["lanes"]["answer"]["capacity_exempt_count"],
        1
    );
    assert_eq!(report["risk"]["unresolved_effects"], 1);
    assert_eq!(report["risk"]["background_remote_work"], 2);
    assert_eq!(
        report["work"]["answer"]["background_recovery"]["unbound_count"],
        1
    );
    assert_eq!(
        report["work"]["answer"]["background_recovery"]["bound_count"],
        1
    );
    assert_eq!(report["components"]["answer"]["state"], "ok");
    assert_eq!(report["work"]["answer"]["progress"], "complete");
    assert_eq!(report["pending_work"][0]["state"], "unknown");
    assert_eq!(report["pending_work"][1]["state"], "confirmed");
}

#[test]
fn background_history_cannot_supply_missing_inventory_or_hide_current_failures() {
    use agmi::config::CountLimit;
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "judge", CountLimit::Bounded(4), at);
    retained_remote(&db, "judge", "queued", 1, at);
    db.execute("UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.locally_judgeable',json('false'),'$.judge.assessment.observed_opportunities',0,
        '$.judge.assessment.eligible_candidates',0)", []).unwrap();
    let idle = diagnostic_health(&config);
    assert_eq!(idle["healthy"], true, "{idle}");
    assert_eq!(idle["work"]["judge"]["progress"], "idle");
    for mutation in [
        "UPDATE runtime_state SET lane_participation=json_set(lane_participation,'$.judge.assessment.completeness','bounded_partial')",
        "UPDATE runtime_state SET lane_participation=json_set(lane_participation,'$.judge.assessment.completeness','complete','$.judge.assessment.valid_until',0)",
        "UPDATE runtime_state SET lane_participation=NULL",
    ] {
        db.execute(mutation, []).unwrap();
        let missing = diagnostic_health(&config);
        assert_eq!(missing["healthy"], false, "{missing}");
        assert_eq!(missing["components"]["judge"]["state"], "unknown");
        assert_ne!(missing["work"]["judge"]["progress"], "idle");
        assert_eq!(missing["risk"]["background_remote_work"], 1);
        assert!(
            !missing["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue == "pending_work_overdue")
        );
    }
    db.execute("UPDATE read_state SET last_failure_at=?1,failures=1,status=503,failure_category='transport'
        WHERE purpose='discovery'", [at]).unwrap();
    let failed = diagnostic_health(&config);
    assert_eq!(failed["healthy"], false);
    assert_eq!(failed["components"]["judge"]["state"], "degraded");
    assert!(
        failed["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue == "api_dependency_unavailable")
    );
    db.execute(
        "UPDATE hosted_identity_evidence SET rejection='authentication_failed'",
        [],
    )
    .unwrap();
    let rejected = diagnostic_health(&config);
    assert_eq!(rejected["healthy"], false);
    assert_ne!(rejected["components"]["controller"]["state"], "ok");
}

#[test]
fn current_local_deadlines_survive_background_history_and_intent_overlays() {
    use agmi::config::{CountLimit, Mode};
    for lane in ["answer", "judge", "mine"] {
        for intent in ["active", "paused", "off", "read_only", "stopped"] {
            let (_dir, mut config, db, at) = initialized_health_fixture();
            diagnostic_lane(&mut config, &db, lane, CountLimit::Unbounded, at);
            retained_remote(&db, lane, "unknown", 1, at);
            db.execute("INSERT INTO operations
                (id,kind,work_key,state,request,generation,revision,created_at,updated_at)
                SELECT 2,?1,'current-dispatch','dispatching','{}',generation,'fixture',?2,?2 FROM control",
                rusqlite::params![lane,at-10000]).unwrap();
            db.execute(
                "INSERT INTO operation_evidence(operation_id,http_deadline) VALUES(2,?1)",
                [at - 10000],
            )
            .unwrap();
            match intent {
                "paused" => {
                    db.execute("UPDATE control SET paused=1", []).unwrap();
                }
                "stopped" => {
                    db.execute("UPDATE runtime_state SET controller_stopped=1", [])
                        .unwrap();
                }
                "off" | "read_only" => {
                    let mode = if intent == "off" {
                        Mode::Off
                    } else {
                        Mode::ReadOnly
                    };
                    match lane {
                        "answer" => config.capabilities.answer.mode = mode,
                        "judge" => config.capabilities.judge.mode = mode,
                        _ => config.capabilities.mine.mode = mode,
                    }
                    persist_diagnostic_policy(&config, &db);
                }
                _ => {}
            }
            let report = diagnostic_health(&config);
            assert_eq!(report["healthy"], false, "{lane}/{intent}: {report}");
            assert_eq!(report["components"][lane]["state"], "degraded");
            assert!(
                report["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|issue| issue == "dispatch_outcome_uncertain")
            );
            assert_eq!(
                report["work"][lane]["intervention"]["next_action"],
                "inspect_operations"
            );
            assert_eq!(report["pending_work"][0]["state"], "unknown");
            assert_eq!(report["pending_work"][1]["state"], "dispatching");
            if lane != "mine" {
                db.execute("UPDATE operations SET state='generating' WHERE id=2", [])
                    .unwrap();
                db.execute("UPDATE operation_evidence SET model_deadline=?1,http_deadline=NULL WHERE operation_id=2",
                    [at-10000]).unwrap();
                let model = diagnostic_health(&config);
                assert_eq!(model["healthy"], false);
                assert_eq!(model["components"][lane]["state"], "degraded");
                assert!(
                    model["issues"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|issue| issue == "model_work_overdue")
                );
            }
        }
    }
}

#[test]
fn eligible_same_epoch_answer_retry_does_not_make_its_old_job_a_dependency() {
    use agmi::config::CountLimit;
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "answer", CountLimit::Bounded(4), at);
    config
        .capabilities
        .answer
        .participation
        .retry_uncertain_answers = true;
    config
        .capabilities
        .answer
        .participation
        .uncertain_answer_retry_seconds = 0;
    persist_diagnostic_policy(&config, &db);
    retained_remote(&db, "answer", "unknown", 2, at);
    let report = diagnostic_health(&config);
    assert_eq!(report["healthy"], true, "{report}");
    assert_eq!(report["work"]["answer"]["retry"]["policy_eligible"], true);
    assert_eq!(
        report["pending_work"][0]["nonblocking_for_fresh_work"],
        true
    );
    assert_eq!(
        report["work"]["answer"]["intervention"]["next_action"],
        "revalidate_challenge"
    );
    assert_eq!(
        report["work"]["answer"]["intervention"]["requires_fresh_eligibility"],
        true
    );
    config
        .capabilities
        .answer
        .participation
        .max_answer_attempts_per_epoch = 1;
    persist_diagnostic_policy(&config, &db);
    let exhausted = diagnostic_health(&config);
    assert_eq!(exhausted["healthy"], false);
    assert_eq!(
        exhausted["work"]["answer"]["retry"]["policy_eligible"],
        false
    );
    assert_eq!(
        exhausted["pending_work"][0]["nonblocking_for_fresh_work"],
        false
    );
    assert_eq!(exhausted["pending_work"][0]["state"], "unknown");
}

#[test]
fn confirmed_current_mine_is_completed_participation_with_retained_finality_followup() {
    use agmi::config::CountLimit;
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "mine", CountLimit::Bounded(4), at);
    retained_remote(&db, "mine", "confirmed", 2, at);
    let report = diagnostic_health(&config);
    assert_eq!(report["healthy"], true, "{report}");
    assert_eq!(report["work"]["mine"]["phase"], "completed");
    assert_eq!(report["work"]["mine"]["progress"], "complete");
    assert_eq!(
        report["work"]["mine"]["background_recovery"]["bound_count"],
        1
    );
    assert_eq!(report["pending_work"][0]["state"], "confirmed");
    assert_eq!(report["risk"]["attention_required"], true);
    db.execute(
        "UPDATE lane_observations SET observed_at=1 WHERE lane='mine'",
        [],
    )
    .unwrap();
    let stale = diagnostic_health(&config);
    assert_eq!(stale["healthy"], false);
    assert_eq!(stale["components"]["mine"]["state"], "unknown");
    assert_ne!(stale["work"]["mine"]["progress"], "complete");
}

#[test]
fn confirmed_current_judgment_is_accepted_with_nonblocking_finality_followup() {
    use agmi::config::CountLimit;
    use serde_json::json;
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "judge", CountLimit::Bounded(4), at);
    retained_remote(&db, "judge", "confirmed", 2, at);
    db.execute(
        "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.locally_judgeable',json('false'),
        '$.judge.assessment.eligible_candidates',0,
        '$.judge.assessment.exclusions',json('{\"already_attempted\":1}'),
        '$.judge.assessment.excluded_work',json('[{\"work_key\":\"2:retained\",\"reason\":\"already_attempted\"}]'),
        '$.judge.assessment.excluded_work_truncated',json('false'))",
        [],
    )
    .unwrap();
    let path = config
        .state_dir
        .parent()
        .unwrap()
        .join("diagnostic-config.toml");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let version: i64 = db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap();
    for command in ["status", "health", "doctor"] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_agmi"));
        process
            .arg("--config")
            .arg(&path)
            .args(["--json", command, "--verbose"]);
        if command == "health" {
            process.args(["--min-free-mib", "0"]);
        }
        let output = process.output().unwrap();
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        let report = &envelope["data"];
        assert!(output.status.success(), "{command}: {envelope}");
        assert_eq!(report["healthy"], true, "{command}: {report}");
        assert_eq!(report["operational"]["status"], "clear");
        assert_eq!(report["components"]["judge"]["state"], "ok");
        assert_eq!(report["work"]["judge"]["progress"], "idle");
        assert_eq!(
            report["work"]["judge"]["next_action"],
            "observe_assignments"
        );
        assert_eq!(
            report["work"]["judge"]["intervention"]["status"],
            "none_required"
        );
        assert_eq!(report["pending_work"][0]["state"], "confirmed");
        assert_eq!(
            report["pending_work"][0]["nonblocking_for_fresh_work"],
            true
        );
        assert_eq!(report["risk"]["background_remote_work"], 1);
        assert_eq!(report["risk"]["attention_required"], true);
        assert_eq!(
            report["work"]["judge"]["background_recovery"]["bound_count"],
            1
        );
        assert_eq!(
            report["components"]["api"]["resources"][0]["dependency"],
            "background_remote_work"
        );
        assert_eq!(
            report["components"]["api"]["resources"][0]["health"]["state"],
            "degraded"
        );
        assert_eq!(
            report["lane_participation"]["judge"]["finality"],
            "not_verified"
        );
        assert_eq!(report["issues"], json!([]));
    }
    let after: i64 = db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        after, version,
        "diagnostics mutated confirmed participation"
    );

    // Acceptance of this receipt cannot establish fresh assignment inventory.
    db.execute(
        "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.valid_until',0)",
        [],
    )
    .unwrap();
    for report in [
        diagnostic_health(&config),
        agmi::runtime::status(&config).unwrap(),
    ] {
        assert_eq!(report["healthy"], false, "{report}");
        assert_eq!(report["operational"]["status"], "unknown");
        assert_eq!(report["components"]["judge"]["state"], "unknown");
        assert_ne!(report["work"]["judge"]["progress"], "idle");
        assert_eq!(report["pending_work"][0]["state"], "confirmed");
        assert_eq!(
            report["pending_work"][0]["nonblocking_for_fresh_work"],
            true
        );
        assert_eq!(report["risk"]["background_remote_work"], 1);
    }

    // Another current unknown is still unresolved even beside accepted work.
    db.execute(
        "INSERT INTO operations
        (id,kind,work_key,state,request,generation,revision,created_at,updated_at)
        SELECT 2,'judge','other-current','unknown','{}',generation,'fixture',?1,?1 FROM control",
        [at],
    )
    .unwrap();
    db.execute(
        "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.valid_until',?1,
        '$.judge.assessment.exclusions',json('{\"already_attempted\":2}'),
        '$.judge.assessment.excluded_work',json('[{\"work_key\":\"2:retained\",\"reason\":\"already_attempted\"},{\"work_key\":\"other-current\",\"reason\":\"already_attempted\"}]'))",
        [at + 3600],
    )
    .unwrap();
    let blocked = diagnostic_health(&config);
    assert_eq!(blocked["healthy"], false, "{blocked}");
    assert_eq!(blocked["components"]["judge"]["state"], "blocked");
    assert_eq!(
        blocked["pending_work"][0]["nonblocking_for_fresh_work"],
        true
    );
    assert_eq!(
        blocked["pending_work"][1]["nonblocking_for_fresh_work"],
        false
    );
    assert_eq!(blocked["risk"]["background_remote_work"], 1);
    assert!(
        blocked["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue == "current_work_outcome_unresolved")
    );
}

#[test]
fn model_failure_categories_require_model_attempt_failure_evidence() {
    use agmi::config::CountLimit;
    use serde_json::json;
    for lane in ["answer", "judge"] {
        for (state, execution, outcome, code, diagnostic, category) in [
            (
                "confirmed",
                "completed",
                "captured",
                "captured",
                "included",
                None,
            ),
            ("final", "completed", "captured", "captured", "final", None),
            (
                "queued",
                "completed",
                "captured",
                "captured",
                "native_auth_unavailable",
                None,
            ),
            ("rejected", "", "", "", "invalid_model_output", None),
            (
                "model_unknown",
                "unknown",
                "unknown",
                "artifact_request_digest_mismatch",
                "included",
                Some("artifact_request_digest_mismatch"),
            ),
            (
                "prelaunch_failed",
                "not_started",
                "not_started",
                "native_auth_unavailable",
                "included",
                Some("native_auth_unavailable"),
            ),
            (
                "prelaunch_failed",
                "not_started",
                "not_started",
                "executable_unavailable",
                "included",
                Some("executable_unavailable"),
            ),
            (
                "rejected",
                "completed",
                "invalid",
                "native_artifact_invalid",
                "included",
                Some("native_artifact_invalid"),
            ),
        ] {
            let (_dir, mut config, db, at) = initialized_health_fixture();
            diagnostic_lane(&mut config, &db, lane, CountLimit::Bounded(4), at);
            let completion = (!outcome.is_empty()).then(|| json!({
                "phase":if execution == "not_started" {"preflight"} else {"artifact_validation"},
                "execution":execution,"outcome":outcome,"reason_code":code,
                "collected_at":at,"preflight_started_at":at,
                "inference_spawned_at":if execution == "not_started" {None} else {Some(at)},
                "reported":{},
                "cancellation":{"requested_at":null,"local_process_stop":"not_requested",
                    "remote_run_stop":"not_requested"}
            }));
            let attempt = completion.map(|completion| json!({
                "producer":{"requested":{"model":"fixture-model"}},
                "launch":if execution == "not_started" {Value::Null} else {json!({"admitted_at":at})},
                "completion":completion
            }));
            db.execute(
                "INSERT INTO operations
                (id,kind,work_key,state,request,payload,generation,revision,created_at,updated_at,txid,job_id,binding_revision)
                SELECT 1,?1,'2:attempt',?2,?3,?4,generation,'fixture',?5,?5,?6,?7,1 FROM control",
                rusqlite::params![
                    lane, state, json!({"solver":{"epoch":2}}).to_string(),
                    (outcome == "captured").then_some("{}"), at,
                    matches!(state, "confirmed" | "final").then(|| "a".repeat(64)),
                    (state == "queued").then_some("fixture-job")
                ],
            )
            .unwrap();
            db.execute(
                "INSERT INTO operation_evidence(operation_id,evidence,model_attempt)
                VALUES(1,?1,?2)",
                rusqlite::params![
                    json!({"reason":diagnostic}).to_string(),
                    attempt.as_ref().map(Value::to_string)
                ],
            )
            .unwrap();
            for report in [
                diagnostic_health(&config),
                agmi::runtime::status(&config).unwrap(),
            ] {
                let model = &report["work"][lane]["model"];
                assert_eq!(model["operation_id"], 1, "{lane}/{state}: {report}");
                assert_eq!(
                    model["failure_category"],
                    json!(category),
                    "{lane}/{state}: {report}"
                );
                assert_eq!(model["current_route"], true);
                assert_eq!(
                    model["budget_used"],
                    if execution == "not_started" { 0 } else { 1 }
                );
                assert_eq!(
                    model["unresolved_attempts"],
                    if execution == "unknown" || execution.is_empty() {
                        1
                    } else {
                        0
                    }
                );
                if code == "native_auth_unavailable" {
                    assert_eq!(
                        report["work"][lane]["intervention"]["reason"],
                        "model_authentication_failed"
                    );
                } else if code == "executable_unavailable" {
                    assert_eq!(
                        report["work"][lane]["intervention"]["reason"],
                        "model_configuration_failed"
                    );
                }
            }
            let retained: Option<String> = db
                .query_row(
                    "SELECT model_attempt FROM operation_evidence WHERE operation_id=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained, attempt.as_ref().map(Value::to_string));
        }
    }
}

#[test]
fn current_discovery_and_identity_faults_remain_separate_from_background_sibling_reads() {
    use agmi::config::{CountLimit, Mode};
    let (_dir, mut config, db, at) = initialized_health_fixture();
    for lane in ["answer", "judge", "mine"] {
        diagnostic_lane(&mut config, &db, lane, CountLimit::Bounded(4), at - 2);
    }
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.mine.mode = Mode::Active;
    persist_diagnostic_policy(&config, &db);
    retained_remote(&db, "judge", "queued", 1, at);
    assert_eq!(diagnostic_health(&config)["healthy"], true);
    for lane in ["answer", "judge", "mine"] {
        db.execute("UPDATE read_state SET last_failure_at=?1,failures=1,status=503,failure_category='transport'
            WHERE owner=?2 AND purpose='discovery'", rusqlite::params![at,lane]).unwrap();
        let report = diagnostic_health(&config);
        assert_eq!(report["healthy"], false);
        assert_eq!(report["components"][lane]["state"], "degraded", "{report}");
        assert_eq!(report["work"][lane]["operational"]["state"], "degraded");
        for sibling in ["answer", "judge", "mine"]
            .into_iter()
            .filter(|other| *other != lane)
        {
            assert_eq!(report["components"][sibling]["state"], "ok", "{report}");
        }
        db.execute(
            "UPDATE read_state SET last_failure_at=NULL,failures=0,status=200,failure_category=NULL
            WHERE owner=?1 AND purpose='discovery'",
            [lane],
        )
        .unwrap();
    }
    db.execute(
        "UPDATE hosted_identity_evidence SET rejection='authentication_failed'",
        [],
    )
    .unwrap();
    let identity = diagnostic_health(&config);
    assert_eq!(identity["healthy"], false);
    assert_eq!(identity["components"]["controller"]["state"], "blocked");
    assert_eq!(identity["work"]["judge"]["background_recovery"]["count"], 0);
    assert_eq!(identity["pending_work"][0]["state"], "queued");
}

#[test]
fn complete_inventory_excluding_uncertain_models_is_not_empty_healthy_inventory() {
    use agmi::config::CountLimit;
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "judge", CountLimit::Bounded(4), at);
    db.execute("INSERT INTO operations
        (id,kind,work_key,state,request,generation,revision,created_at,updated_at)
        SELECT 1,'judge','current-assignment','model_unknown','{}',generation,'fixture',?1,?1 FROM control",
        [at-10000]).unwrap();
    db.execute("UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.locally_judgeable',json('false'),'$.judge.assessment.eligible_candidates',0,
        '$.judge.assessment.exclusions',json('{\"model_uncertain_retry_disabled\":1}'))", []).unwrap();
    let report = diagnostic_health(&config);
    assert_eq!(report["healthy"], false, "{report}");
    assert_ne!(report["components"]["judge"]["state"], "ok");
    assert_eq!(report["risk"]["unresolved_model_attempts"], 1);
    assert_eq!(
        report["work"]["judge"]["intervention"]["status"],
        "operator_required"
    );
    assert_ne!(report["work"]["judge"]["progress"], "idle");
}

#[test]
fn judging_exclusion_witnesses_keep_unrelated_history_background_and_current_reads_actionable() {
    use agmi::config::CountLimit;
    use serde_json::json;
    let assignment_b = "b".repeat(64);
    for reason in [
        "assignment_read_backoff",
        "assignment_resource_restricted",
        "already_attempted",
    ] {
        let (_dir, mut config, db, at) = initialized_health_fixture();
        diagnostic_lane(&mut config, &db, "judge", CountLimit::Bounded(4), at);
        retained_remote(&db, "judge", "queued", 1, at);
        let witnesses = json!([{"work_key":assignment_b,"reason":reason}]);
        db.execute(
            "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
            '$.judge.assessment.locally_judgeable',json('false'),
            '$.judge.assessment.eligible_candidates',0,
            '$.judge.assessment.exclusions',json(?1),
            '$.judge.assessment.excluded_work',json(?2),
            '$.judge.assessment.excluded_work_truncated',json('false'))",
            rusqlite::params![json!({(reason):1}).to_string(), witnesses.to_string()],
        )
        .unwrap();
        if reason == "already_attempted" {
            db.execute(
                "INSERT INTO operations
                (id,kind,work_key,state,request,generation,revision,created_at,updated_at)
                SELECT 2,'judge',?1,'completed','{}',generation,'fixture',?2,?2 FROM control",
                rusqlite::params![assignment_b, at],
            )
            .unwrap();
        } else {
            db.execute("INSERT INTO read_state
                (owner,purpose,resource,failures,last_failure_at,failure_category,status,local_next_at)
                VALUES('judge','assignment',?1,1,?2,'http',404,?3)",
                rusqlite::params![assignment_b,at,at+300]).unwrap();
        }
        let report = diagnostic_health(&config);
        assert_eq!(
            report["pending_work"][0]["nonblocking_for_fresh_work"], true,
            "{report}"
        );
        assert_eq!(report["work"]["judge"]["background_recovery"]["count"], 1);
        assert_eq!(report["pending_work"][0]["state"], "queued");
        assert_eq!(report["healthy"], reason == "already_attempted", "{report}");
        if reason == "already_attempted" {
            assert_eq!(report["work"]["judge"]["progress"], "idle");
            assert_eq!(report["components"]["judge"]["state"], "ok");
        } else {
            assert_eq!(report["components"]["judge"]["state"], "degraded");
            assert_ne!(report["work"]["judge"]["progress"], "idle");
            assert_eq!(report["work"]["judge"]["read_key"]["purpose"], "assignment");
            assert_eq!(
                report["work"]["judge"]["read_key"]["resource"],
                assignment_b
            );
            assert!(
                report["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|issue| issue == "api_dependency_unavailable")
            );
            let (_config_dir, output) = run_health(&config, &["--min-free-mib", "0"]);
            assert!(!output.status.success());
            let cli: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                cli["data"]["work"]["judge"]["background_recovery"]["count"],
                1
            );
            assert_eq!(
                cli["data"]["work"]["judge"]["read_key"]["resource"],
                assignment_b
            );
            assert_ne!(cli["data"]["work"]["judge"]["progress"], "idle");
            assert!(
                cli["data"]["work"]["judge"]["next_actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|action| action["authorization_required"] != true)
            );
            // C offers a viable path despite B's still-failing hydration.
            db.execute(
                "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
                '$.judge.assessment.locally_judgeable',json('true'),
                '$.judge.assessment.eligible_candidates',1,
                '$.judge.assessment.observed_opportunities',2)",
                [],
            )
            .unwrap();
            let available = diagnostic_health(&config);
            assert_eq!(available["healthy"], true, "{available}");
            assert_eq!(available["components"]["judge"]["state"], "ok");
            assert_eq!(
                available["work"]["judge"]["read_key"]["purpose"],
                "discovery"
            );
            assert_eq!(
                available["work"]["judge"]["background_recovery"]["count"],
                1
            );
            assert!(
                available["components"]["api"]["resources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["purpose"] == "assignment"
                        && row["resource"] == assignment_b
                        && row["health"]["state"] == "degraded")
            );
            // The current assignment disappears; A's failed job cannot take its
            // place as an operational dependency or force replay.
            db.execute("UPDATE runtime_state SET lane_participation=json_set(lane_participation,
                '$.judge.assessment.observed_opportunities',0,'$.judge.assessment.exclusions',json('{}'),
                '$.judge.assessment.locally_judgeable',json('false'),'$.judge.assessment.eligible_candidates',0,
                '$.judge.assessment.excluded_work',json('[]'))", []).unwrap();
            let idle = diagnostic_health(&config);
            assert_eq!(idle["healthy"], true, "{idle}");
            assert_eq!(idle["work"]["judge"]["progress"], "idle");
            assert_eq!(idle["work"]["judge"]["background_recovery"]["count"], 1);
        }
    }
}

#[test]
fn judging_legacy_or_truncated_exclusions_do_not_invent_current_operation_identity() {
    use agmi::config::CountLimit;
    use serde_json::json;
    let (_dir, mut config, db, at) = initialized_health_fixture();
    diagnostic_lane(&mut config, &db, "judge", CountLimit::Bounded(4), at);
    retained_remote(&db, "judge", "queued", 1, at);
    db.execute(
        "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.locally_judgeable',json('false'),
        '$.judge.assessment.eligible_candidates',0,
        '$.judge.assessment.exclusions',json('{\"already_attempted\":1}'))",
        [],
    )
    .unwrap();
    for witnesses in [
        Value::Null,
        json!([{"work_key":"b".repeat(64),"reason":"already_attempted"}]),
    ] {
        db.execute(
            "UPDATE runtime_state SET lane_participation=json_set(lane_participation,
            '$.judge.assessment.excluded_work',json(?1),
            '$.judge.assessment.excluded_work_truncated',json('true'))",
            [witnesses.to_string()],
        )
        .unwrap();
        let unknown = diagnostic_health(&config);
        assert_eq!(
            unknown["pending_work"][0]["nonblocking_for_fresh_work"],
            Value::Null
        );
        assert_eq!(unknown["healthy"], false, "{unknown}");
        assert_eq!(unknown["components"]["judge"]["state"], "unknown");
        assert_ne!(unknown["work"]["judge"]["next_action"], "read_job");
        assert!(
            !unknown["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue == "api_dependency_unavailable")
        );
    }
    // A positive same-work witness is conclusive even if other witnesses were
    // truncated. Its original is still not replay authority.
    db.execute("UPDATE runtime_state SET lane_participation=json_set(lane_participation,
        '$.judge.assessment.excluded_work',json('[{\"work_key\":\"1:retained\",\"reason\":\"already_attempted\"}]'))", []).unwrap();
    db.execute("DELETE FROM read_state WHERE purpose='job'", [])
        .unwrap();
    let current = diagnostic_health(&config);
    assert_eq!(
        current["pending_work"][0]["nonblocking_for_fresh_work"],
        false
    );
    assert_eq!(current["components"]["judge"]["state"], "blocked");
    assert!(
        current["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue == "current_work_outcome_unresolved")
    );
    assert_eq!(current["pending_work"][0]["state"], "queued");
}

#[test]
fn unreadable_journal_evidence_does_not_claim_empty_history_or_assessed_filesystem() {
    let (_dir, config, db, _at) = initialized_health_fixture();
    drop(db);
    let path = config.state_dir.join("state.sqlite3");
    let corrupt = b"unreadable journal fixture";
    fs::write(&path, corrupt).unwrap();
    let report = diagnostic_health(&config);
    assert_eq!(report["healthy"], false);
    assert_eq!(report["operational"]["status"], "unknown");
    assert_eq!(
        report["assessment_scope"]["state_filesystem"],
        "not_assessed"
    );
    assert_eq!(report["risk"]["unresolved_effects"], Value::Null);
    for field in [
        "background_remote_work",
        "retained_uncertainty_nonblocking_lanes",
    ] {
        assert_eq!(report["risk"].get(field), Some(&Value::Null));
    }
    for lane in ["answer", "judge", "mine"] {
        assert_eq!(report["work"][lane]["operational"]["state"], "unknown");
        assert_eq!(
            report["work"][lane]["operational"]["reasons"],
            serde_json::json!(["local_evidence_unavailable"])
        );
        for field in [
            "count",
            "bound_count",
            "unbound_count",
            "required_for_participation",
        ] {
            assert_eq!(
                report["work"][lane]["background_recovery"].get(field),
                Some(&Value::Null)
            );
        }
    }
    assert_eq!(fs::read(&path).unwrap(), corrupt);
}
