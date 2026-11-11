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
        for kind in ["answer", "judge", "mine"] {
            assert_eq!(
                envelope["data"]["work"][kind]["intervention"]["status"],
                "undetermined"
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
    let (_config_dir, before) = run_health(&config, &["--min-free-mib", "0"]);
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
