use std::{fs, process::Command};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agmi"))
}

#[test]
fn diagnostics_expose_verbose_detail_explicitly() {
    for command in ["status", "health", "doctor"] {
        let output = binary().args([command, "--help"]).output().unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("--verbose")
        );
    }
}

#[test]
fn update_check_cannot_authorize_repair_or_mix_release_sources() {
    for args in [
        vec!["update", "--check", "--repair"],
        vec!["update", "--check", "--release", "r-private-value"],
        vec!["update", "--check", "--dry-run"],
    ] {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("untouched/config.toml");
        let output = binary()
            .args(["--json", "--config"])
            .arg(&config)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["details"]["reason"], "conflicting_fields");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("r-private-value"));
        assert!(!config.parent().unwrap().exists());
    }
}

#[cfg(unix)]
#[test]
fn update_repair_dry_run_preserves_user_files_and_never_executes_candidate() {
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    fs::create_dir_all(home.join(".config/agmi")).unwrap();
    fs::create_dir_all(home.join(".local/share/agmi")).unwrap();
    let files = [
        (
            ".config/agmi/config.toml",
            "operator config, not an update template",
        ),
        (".config/agmi/voice.md", "private user guidance"),
        (".config/agmi/core.md", "operator core guidance"),
        (".config/agmi/key", "private synthetic credential"),
        (
            ".local/share/agmi/state.sqlite3",
            "journal must not be touched",
        ),
    ];
    for (name, text) in files {
        fs::write(home.join(name), text).unwrap();
    }
    let candidate = root.path().join("candidate");
    let marker = root.path().join("executed");
    let contents = b"#!/bin/sh\n: > \"$AGMI_PREVIEW_MARKER\"\nexit 1\n";
    fs::write(&candidate, contents).unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = format!("{:x}", sha2::Sha256::digest(contents));
    let output = binary()
        .env("HOME", &home)
        .env("PATH", root.path())
        .env("AGMI_PREVIEW_MARKER", &marker)
        .args(["--json", "update", "--repair", "--dry-run", "--binary"])
        .arg(&candidate)
        .args(["--sha256", &digest])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(!marker.exists());
    for (name, text) in files {
        assert_eq!(fs::read_to_string(home.join(name)).unwrap(), text);
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["success"], true);
    assert!(value["data"]["readiness"].is_null());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private synthetic credential"));
}

#[test]
fn update_migration_flags_require_explicit_mode_and_release_pinned_approval() {
    let private = "private-approval-or-path-value";
    for json in [false, true] {
        for arguments in [
            vec!["update", "--migrate", "--repair"],
            vec!["update", "--migrate", "--migration-only", "--stopped"],
            vec!["update", "--proposal", private],
            vec!["update", "--migrate", "--expected-token", private],
            vec!["update", "--release", private, "--expected-token", private],
            vec!["update", "--migrate", "--accept-risk-change", private],
            vec![
                "update",
                "--migrate",
                "--binary",
                private,
                "--sha256",
                private,
                "--expected-token",
                private,
            ],
            vec![
                "update",
                "--migrate",
                "--check",
                "--release",
                private,
                "--expected-token",
                private,
            ],
        ] {
            let mut command = binary();
            if json {
                command.arg("--json");
            }
            let output = command.args(arguments).output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains(private));
        }
    }
    let output = binary()
        .args([
            "--json",
            "update",
            "--migrate",
            "--release",
            private,
            "--expected-token",
            private,
            "--accept-risk-change",
            "different-private-token",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!text.contains(private));
    assert!(!text.contains("different-private-token"));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "update_invalid_arguments");
}

#[test]
fn update_private_proposals_are_bounded_objects_and_errors_never_echo_inputs() {
    let root = tempfile::tempdir().unwrap();
    let marker = "private-migration-config-or-guidance";
    let proposal = root.path().join(format!("{marker}.json"));
    for contents in [
        format!("{{\"candidate_toml\":\"{marker}\""),
        format!("\"{marker}\""),
        format!(
            "{{\"candidate_toml\":\"{marker}{}\"}}",
            "x".repeat(64 * 1024)
        ),
    ] {
        fs::write(&proposal, &contents).unwrap();
        for json in [false, true] {
            let mut command = binary();
            if json {
                command.arg("--json");
            }
            let output = command
                .args(["update", "--migrate", "--dry-run", "--proposal"])
                .arg(&proposal)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
            assert_eq!(fs::read_to_string(&proposal).unwrap(), contents);
            if json {
                let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
                assert_eq!(error["error"]["code"], "update_invalid_proposal");
            }
        }
    }
    fs::remove_file(&proposal).unwrap();
    let output = binary()
        .args(["--json", "update", "--migrate", "--proposal"])
        .arg(&proposal)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
}

#[cfg(unix)]
#[test]
fn update_migration_dry_run_never_executes_or_transports_private_proposal() {
    use sha2::Digest;
    use std::{io::Write, os::unix::fs::PermissionsExt, process::Stdio};
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let temporary = root.path().join("temporary");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&temporary).unwrap();
    let candidate = root.path().join("candidate");
    let marker = root.path().join("executed");
    let script = b"#!/bin/sh\n: > \"$AGMI_PREVIEW_MARKER\"\nexit 1\n";
    fs::write(&candidate, script).unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = format!("{:x}", sha2::Sha256::digest(script));
    let secret = "private-proposal-body";
    let input = serde_json::json!({"candidate_toml":secret}).to_string();
    let proposal = root.path().join("proposal.json");
    fs::write(&proposal, &input).unwrap();
    for source in [
        None,
        Some(proposal.as_path()),
        Some(std::path::Path::new("-")),
    ] {
        let mut command = binary();
        command
            .env("HOME", &home)
            .env("TMPDIR", &temporary)
            .env("PATH", root.path())
            .env("AGMI_PREVIEW_MARKER", &marker)
            .args(["--json", "update", "--migrate", "--dry-run", "--binary"])
            .arg(&candidate)
            .args(["--sha256", &digest]);
        if let Some(source) = source {
            command.arg("--proposal").arg(source);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Supplying stdin alone is not permission to read it; explicit '-' is.
        let stdin = if source == Some(std::path::Path::new("-")) {
            input.as_bytes()
        } else {
            b"not-json-private-proposal-body".as_slice()
        };
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(!marker.exists());
        assert_eq!(fs::read_dir(&home).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["data"]["update"]["status"], "planned");
        assert_eq!(
            value["data"]["compatibility"]["classification"],
            "not_assessed"
        );
        assert_eq!(value["data"]["migration"]["phase"], "unknown");
        assert!(value["data"]["readiness"].is_null());
        assert!(value["data"].get("preview").is_none());
        assert!(value["data"]["update"].get("doctor_status").is_none());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}

#[test]
fn configuration_initialization_never_overwrites_existing_operator_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let original = "# operator-owned configuration\n";
    fs::write(&path, original).unwrap();
    let output = binary()
        .args([
            "--config",
            path.to_str().unwrap(),
            "--json",
            "config",
            "init",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["ok"], false);
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_configuration_does_not_echo_its_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let private_marker = "private-test-marker-not-a-credential";
    fs::write(&path, format!("invalid = \"{private_marker}\n")).unwrap();
    let output = binary()
        .args([
            "--config",
            path.to_str().unwrap(),
            "--json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(private_marker));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["code"], "config_invalid");
    assert_eq!(error["error"]["details"]["reason"], "parse_invalid");
    assert_eq!(
        error["error"]["next_actions"][0]["argv"],
        serde_json::json!(["agmi", "--config", path, "config", "schema"])
    );
}

#[test]
fn invalid_guidance_does_not_block_pause_or_local_diagnostics() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let guidance = dir.path().join("voice.md");
    let mut config = agmi::config::Config::default();
    config.state_dir = dir.path().join("state");
    config.network.chain = format!(
        "test-{}",
        dir.path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('.', "")
    );
    config.network.address = "poa111111111111111111111111111111111".into();
    config.network.credential_file = dir.path().join("api-key");
    config.capabilities.answer.model.guidance_file = Some(guidance.clone());
    config.capabilities.answer.mode = agmi::config::Mode::Active;
    config.capabilities.judge.mode = agmi::config::Mode::Active;
    let core = dir.path().join("answer-core.md");
    let judge_core = dir.path().join("judge-core.md");
    config.capabilities.answer.model.core_guidance_file = Some(core.clone());
    config.capabilities.judge.model.core_guidance_file = Some(judge_core.clone());
    fs::write(&core, "Produce an original mechanism.").unwrap();
    fs::write(&judge_core, "Evaluate the candidate independently.").unwrap();
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    fs::write(&guidance, "Prefer concrete mechanisms.").unwrap();
    let invoke = |args: &[&str]| {
        binary()
            .args(["--config", path.to_str().unwrap(), "--json"])
            .args(args)
            .output()
            .unwrap()
    };
    // Capture an effective policy without network/model work before guidance breaks.
    let mut stopped = config.clone();
    stopped.capabilities.answer.mode = agmi::config::Mode::Off;
    stopped.capabilities.judge.mode = agmi::config::Mode::Off;
    stopped.capabilities.mine.mode = agmi::config::Mode::Off;
    fs::write(&config.network.credential_file, "pk_local_fixture").unwrap();
    fs::set_permissions(
        &config.network.credential_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(&path, toml::to_string(&stopped).unwrap()).unwrap();
    let captured = invoke(&["run", "--once"]);
    assert!(
        captured.status.success(),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let resumed = invoke(&["resume"]);
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    fs::remove_file(&guidance).unwrap();
    for invalid in [
        guidance.clone(),
        "".into(),
        "~/voice.md".into(),
        "bad\npath".into(),
    ] {
        config.capabilities.answer.model.guidance_file = Some(invalid);
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(invoke(&["pause"]).status.success());
        let status = invoke(&["status"]);
        assert!(status.status.success());
        let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        assert_eq!(status["data"]["paused"], true);
        assert!(status["data"]["configured_revision"].is_null());
        for args in [&["logs"][..], &["agents"], &["config", "show"]] {
            assert!(invoke(args).status.success());
        }
        assert!(!invoke(&["resume"]).status.success());
        assert!(!invoke(&["config", "check"]).status.success());
    }
    config.capabilities.answer.model.guidance_file = Some(guidance.clone());
    fs::write(&guidance, "Restored user preferences.").unwrap();
    fs::remove_file(&core).unwrap();
    for invalid in [
        Some(core.clone()),
        None,
        Some("".into()),
        Some("~/core.md".into()),
    ] {
        config.capabilities.answer.model.core_guidance_file = invalid;
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(invoke(&["pause"]).status.success());
        for args in [&["status"][..], &["logs"], &["agents"], &["config", "show"]] {
            assert!(invoke(args).status.success());
        }
        assert!(!invoke(&["resume"]).status.success());
        assert!(!invoke(&["config", "check"]).status.success());
    }
    config.capabilities.answer.model.core_guidance_file = Some(core.clone());
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    fs::write(&core, " \n").unwrap();
    assert!(invoke(&["pause"]).status.success());
    assert!(!invoke(&["resume"]).status.success());
    fs::write(&core, "Restored core instructions.").unwrap();
    assert!(invoke(&["resume"]).status.success());
}

#[cfg(unix)]
#[test]
fn control_commands_preserve_live_writer_visibility() {
    use agmi::config::{Config, Mode};
    use std::{
        process::{Child, Stdio},
        time::{Duration, Instant},
    };

    struct Running(Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut config = Config::default();
    config.state_dir = dir.path().join("state");
    config.network.chain = format!(
        "test-{}",
        dir.path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('.', "")
    );
    config.network.address = format!("poa1{}", "1".repeat(32));
    config.network.credential_file = dir.path().join("key");
    fs::write(&config.network.credential_file, "pk_test_fixture").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        &config.network.credential_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    config.capabilities.answer.mode = Mode::Off;
    config.capabilities.judge.mode = Mode::Off;
    config.capabilities.mine.mode = Mode::Off;
    for schedule in [
        &mut config.capabilities.answer.schedule,
        &mut config.capabilities.judge.schedule,
    ] {
        schedule.poll_seconds = 1;
        schedule.jitter_seconds = 0;
    }
    config.capabilities.mine.schedule.poll_seconds = 1;
    config.capabilities.mine.schedule.jitter_seconds = 0;
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let mut writer = Running(
        binary()
            .args(["--config", path.to_str().unwrap(), "--json", "run"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let wait_revision = |config: &Config, expected: &str, writer: &mut Child| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(writer.try_wait().unwrap().is_none(), "writer exited");
            let status = agmi::runtime::status(config);
            if status
                .as_ref()
                .is_ok_and(|s| s["effective_runtime"]["revision"].as_str() == Some(expected))
            {
                return status.unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "writer updates are not visible: {status:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    };
    wait_revision(
        &config,
        &Config::load(&path).unwrap().revision().unwrap(),
        &mut writer.0,
    );
    let paused = binary()
        .args(["--config", path.to_str().unwrap(), "--json", "pause"])
        .output()
        .unwrap();
    assert!(paused.status.success(), "{paused:?}");
    config.capabilities.mine.schedule.interval_seconds += 1;
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let status = wait_revision(
        &config,
        &Config::load(&path).unwrap().revision().unwrap(),
        &mut writer.0,
    );
    assert_eq!(status["paused"], true);
    assert_eq!(status["operations"], serde_json::json!([]));
}

#[test]
fn missing_fields_are_named_without_values_and_actions_preserve_config_argv() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("spaces ; $(not-a-shell)/config.toml");
    let output = binary()
        .arg("--json")
        .arg("--config")
        .arg(&config)
        .args(["init", "--key-stdin"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_arguments");
    assert_eq!(
        error["error"]["details"]["reason"],
        "missing_required_fields"
    );
    assert!(
        error["error"]["details"]["missing_fields"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("--account"))
    );
    assert_eq!(
        error["error"]["next_actions"][0]["argv"],
        serde_json::json!(["agmi", "--config", config, "--help"])
    );
    assert!(!dir.path().join("spaces ; $(not-a-shell)").exists());
}

#[test]
fn parser_value_errors_never_echo_private_arguments_in_either_output_mode() {
    let marker = "private-key-provider-output-should-not-appear";
    for json in [false, true] {
        for args in [
            vec!["health", "--stale-seconds", marker],
            vec!["service", marker],
            vec!["--unknown-private-option", marker],
        ] {
            let mut command = binary();
            if json {
                command.arg("--json");
            }
            let output = command.args(args).output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let text = String::from_utf8_lossy(&output.stderr);
            assert!(!text.contains(marker));
            assert!(!text.contains("--unknown-private-option"));
            if json {
                let envelope: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
                assert_eq!(envelope["error"]["code"], "invalid_arguments");
                assert_eq!(
                    envelope["error"]["next_actions"][0]["authorization_required"],
                    false
                );
            }
        }
    }
}

#[test]
fn state_path_obeys_json_and_manifest_is_the_explicit_raw_exception() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let mut config = agmi::config::Config::default();
    config.state_dir = dir.path().join("uncreated-state");
    fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let plain = binary()
        .arg("--config")
        .arg(&config_path)
        .args(["config", "state-path"])
        .output()
        .unwrap();
    assert!(plain.status.success());
    assert_eq!(
        String::from_utf8(plain.stdout).unwrap().trim(),
        config.state_dir.to_str().unwrap()
    );
    let machine = binary()
        .arg("--config")
        .arg(&config_path)
        .args(["--json", "config", "state-path"])
        .output()
        .unwrap();
    assert!(machine.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(envelope["schema"], "agmi.cli.v1");
    assert_eq!(envelope["type"], "config_state_path");
    assert_eq!(
        envelope["data"]["path"],
        serde_json::json!(config.state_dir)
    );
    assert!(!config.state_dir.exists());
    let plain = binary()
        .args(["build-info", "--manifest"])
        .output()
        .unwrap();
    let machine = binary()
        .args(["--json", "build-info", "--manifest"])
        .output()
        .unwrap();
    assert!(plain.status.success() && machine.status.success());
    assert_eq!(plain.stdout, machine.stdout);
    assert!(serde_json::from_slice::<serde_json::Value>(&machine.stdout).is_err());
}

#[test]
fn installer_preflight_failure_reports_known_nonactivation_without_raw_values() {
    let marker = "private-digest-value";
    let output = binary()
        .args([
            "--json", "install", "--binary", "/missing", "--sha256", marker,
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_release_digest");
    assert_eq!(error["error"]["details"]["stage"], "preflight");
    assert_eq!(error["error"]["details"]["activation"], "not_started");
    assert_eq!(error["error"]["details"]["service"], "unknown");
    assert_eq!(
        error["error"]["next_actions"][0]["authorization_required"],
        false
    );
}

#[cfg(unix)]
#[test]
fn staging_preview_never_executes_candidate_or_creates_installation_state() {
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    fs::create_dir(&home).unwrap();
    let candidate = root.path().join("candidate");
    let contents = b"#!/bin/sh\n: > \"$AGMI_PREVIEW_MARKER\"\nexit 1\n";
    fs::write(&candidate, contents).unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = root.path().join("executed");
    let digest = format!("{:x}", sha2::Sha256::digest(contents));
    let output = binary()
        .env("HOME", &home)
        .env("PATH", root.path())
        .env("AGMI_PREVIEW_MARKER", &marker)
        .args(["--json", "install", "--stage-only", "--binary"])
        .arg(&candidate)
        .args(["--sha256", &digest, "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(!marker.exists(), "preview executed the supplied candidate");
    assert_eq!(fs::read_dir(&home).unwrap().count(), 0);
    assert_eq!(fs::read(&candidate).unwrap(), contents);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["data"]["installation"]["activation"], "not_started");
}

#[test]
fn discovery_labels_mutation_authorization_and_raw_output_contract() {
    let output = binary().args(["--json", "commands"]).output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let commands = value["data"]["commands"].as_array().unwrap();
    for name in [
        "resume",
        "pause",
        "recover authorize",
        "config apply",
        "install",
    ] {
        assert_eq!(
            commands
                .iter()
                .find(|command| command["name"] == name)
                .unwrap()["authorization_required"],
            true
        );
    }
    for name in ["status", "health", "reads"] {
        assert_eq!(
            commands
                .iter()
                .find(|command| command["name"] == name)
                .unwrap()["authorization_required"],
            false
        );
    }
    assert!(value["data"]["output_contract"]["raw_exception"].is_string());
}

#[test]
fn identity_plan_and_status_have_no_network_or_filesystem_effects() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-created/config.toml");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let output = binary()
        .args(["--config", path.to_str().unwrap(), "--json"])
        .args([
            "identity",
            "create",
            "--label",
            "isolated-cli-fixture",
            "--base-url",
            &origin,
            "--chain",
            "poa-mainnet-1",
            "--invited-by",
            "poa111111111111111111111111111111111",
            "--max-pow-bits",
            "24",
            "--max-pow-hashes",
            "67108864",
            "--pow-seconds",
            "30",
            "--http-seconds",
            "30",
            "--expected-pow-algo",
            "fixture-sha256",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["type"], "identity_create");
    assert_eq!(plan["data"]["authorization"]["confirmed"], false);
    assert_eq!(plan["data"]["authorization"]["dry_run"], true);
    assert!(!path.parent().unwrap().exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let output = binary()
        .args([
            "--config",
            path.to_str().unwrap(),
            "--json",
            "identity",
            "status",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["type"], "identity_status");
    assert_eq!(status["data"]["stage"], "clean");
    for data in [&plan["data"], &status["data"]] {
        for action in data["next_actions"].as_array().into_iter().flatten() {
            if action["kind"] == "command" {
                let argv = action["argv"].as_array().unwrap();
                assert!(argv.len() >= 4);
                assert_eq!(argv[0], "agmi");
                assert_eq!(argv[1], "--config");
                assert_eq!(argv[2], path.to_str().unwrap());
            }
        }
    }
    assert!(!path.parent().unwrap().exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn identity_policy_parser_errors_are_sanitized_and_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-created/config.toml");
    let private_marker = "private-parser-marker";
    for option in [
        "--max-pow-bits",
        "--max-pow-hashes",
        "--pow-seconds",
        "--http-seconds",
    ] {
        let output = binary()
            .args(["--config", path.to_str().unwrap(), "--json"])
            .args([
                "identity",
                "create",
                "--label",
                "fixture",
                option,
                private_marker,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(private_marker));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "invalid_arguments");
        assert_eq!(
            error["error"]["next_actions"][0]["argv"],
            serde_json::json!(["agmi", "--config", path, "--help"])
        );
        assert!(!path.parent().unwrap().exists());
    }
}

#[test]
fn rejected_registration_retry_requires_explicit_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-created/config.toml");
    let output = binary()
        .args(["--config", path.to_str().unwrap(), "--json"])
        .args([
            "identity",
            "create",
            "--label",
            "fixture",
            "--retry-rejected",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_arguments");
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn identity_discovery_distinguishes_confirmed_creation_from_local_status() {
    let output = binary().args(["--json", "commands"]).output().unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let commands = result["data"]["commands"].as_array().unwrap();
    let create = commands
        .iter()
        .find(|command| command["name"] == "identity create")
        .unwrap();
    assert_eq!(create["authorization_required"], true);
    assert_eq!(create["confirmation_flag"], "--confirm");
    let status = commands
        .iter()
        .find(|command| command["name"] == "identity status")
        .unwrap();
    assert_eq!(status["authorization_required"], false);
    assert_eq!(status["network_reads"], false);
    assert_eq!(status["network_writes"], false);
    assert_eq!(status["local_writes"], false);
}

#[test]
fn registration_origin_errors_never_echo_untrusted_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-created/config.toml");
    let private_marker = "private-origin-marker";
    let output = binary()
        .args(["--config", path.to_str().unwrap(), "--json"])
        .args([
            "identity",
            "create",
            "--label",
            "fixture",
            "--base-url",
            &format!("https://{private_marker}.invalid"),
            "--confirm",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(private_marker));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        error["error"]["code"]
            .as_str()
            .unwrap()
            .starts_with("registration_")
    );
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn suggested_actions_preserve_selected_config_across_working_directories() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first");
    let second = root.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("account.toml"), "invalid = [").unwrap();
    let mut config = agmi::config::Config::default();
    config.state_dir = second.join("state");
    fs::write(
        second.join("account.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let args = ["--json", "--config", "account.toml", "config", "check"];
    assert!(
        binary()
            .current_dir(&second)
            .args(args)
            .output()
            .unwrap()
            .status
            .success()
    );
    let failed = binary().current_dir(&first).args(args).output().unwrap();
    assert!(!failed.status.success());
    let error: serde_json::Value = serde_json::from_slice(&failed.stderr).unwrap();
    let argv = error["error"]["next_actions"][0]["argv"]
        .as_array()
        .unwrap();
    let selected = std::path::Path::new(argv[2].as_str().unwrap());
    assert!(selected.is_absolute());
    assert_eq!(
        fs::canonicalize(selected).unwrap(),
        fs::canonicalize(first.join("account.toml")).unwrap()
    );
    let replay = binary()
        .current_dir(&second)
        .arg("--json")
        .args(argv.iter().skip(1).map(|value| value.as_str().unwrap()))
        .output()
        .unwrap();
    assert!(replay.status.success());
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["ok"], true);
    assert!(!first.join("state").exists() && !second.join("state").exists());
}

#[test]
fn default_onboarding_path_matches_service_despite_xdg_override() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let xdg = root.path().join("different-config-root");
    fs::create_dir(&home).unwrap();
    let result = binary()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["--json", "config", "init"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(home.join(".config/agmi/config.toml").is_file());
    assert!(!xdg.exists());
}

#[test]
fn configuration_check_reports_safe_file_and_field_repairs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let marker = "private-config-diagnostic-canary";
    let mut config = agmi::config::Config::default();
    config.state_dir = dir.path().join("uncreated-state");
    let valid = toml::to_string(&config).unwrap();
    let mut cases = vec![
        (None, "file_missing", None),
        (Some(vec![0xff]), "file_not_utf8", None),
        (Some(vec![b' '; 65537]), "file_too_large", None),
        (
            Some(format!("{marker} = 'secret'\n").into_bytes()),
            "parse_invalid",
            None,
        ),
        (
            Some(
                format!("[capabilities.answer.timeouts]\nhttp_seconds = '{marker}'\n").into_bytes(),
            ),
            "parse_invalid",
            None,
        ),
    ];
    config.capabilities.answer.timeouts.model_seconds = 0;
    cases.push((
        Some(toml::to_string(&config).unwrap().into_bytes()),
        "field_invalid",
        Some("timeouts.model_seconds"),
    ));
    config.capabilities.answer.timeouts.model_seconds = u64::MAX;
    cases.push((
        Some(toml::to_string(&config).unwrap().into_bytes()),
        "field_invalid",
        Some("timeouts.model_seconds"),
    ));
    config = toml::from_str(&valid).unwrap();
    config.capabilities.answer.schedule.poll_seconds = 0;
    cases.push((
        Some(toml::to_string(&config).unwrap().into_bytes()),
        "field_invalid",
        Some("schedule.poll_seconds"),
    ));
    config = toml::from_str(&valid).unwrap();
    config.network.base_url = format!("https://{marker}:secret@example.invalid");
    cases.push((
        Some(toml::to_string(&config).unwrap().into_bytes()),
        "field_invalid",
        Some("network.base_url"),
    ));
    config = toml::from_str(&valid).unwrap();
    config.capabilities.judge.model.reasoning = format!("{marker}\n");
    cases.push((
        Some(toml::to_string(&config).unwrap().into_bytes()),
        "field_invalid",
        Some("reasoning"),
    ));
    for (bytes, reason, field) in cases {
        if let Some(bytes) = bytes {
            fs::write(&path, bytes).unwrap();
        }
        for json in [true, false] {
            let mut command = binary();
            command.args(["--config", path.to_str().unwrap()]);
            if json {
                command.arg("--json");
            }
            let output = command.args(["config", "check"]).output().unwrap();
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            let text = String::from_utf8_lossy(&output.stderr);
            assert!(!text.contains(marker));
            if json {
                let envelope: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
                let error = &envelope["error"];
                assert_eq!(
                    error["code"],
                    if reason == "file_missing" {
                        "config_missing"
                    } else {
                        "config_invalid"
                    }
                );
                assert_eq!(error["details"]["reason"], reason);
                assert_eq!(error["details"]["field"], serde_json::json!(field));
                let kind = match field {
                    Some("timeouts.model_seconds" | "schedule.poll_seconds") => Some("answer"),
                    Some("reasoning") => Some("judge"),
                    _ => None,
                };
                assert_eq!(error["details"]["kind"], serde_json::json!(kind));
                assert_eq!(error["next_actions"][0]["authorization_required"], false);
                assert!(
                    error["next_actions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|action| {
                            action["argv"].as_array().is_none_or(|argv| {
                                !argv.ends_with(&[
                                    serde_json::json!("config"),
                                    serde_json::json!("check"),
                                ])
                            })
                        })
                );
            }
        }
    }
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    let output = binary()
        .args([
            "--config",
            path.to_str().unwrap(),
            "--json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["details"]["reason"], "file_unreadable");
    assert!(!dir.path().join("uncreated-state").exists());
}

#[test]
fn configuration_check_identifies_guidance_route_and_layer_without_private_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let marker = "private-guidance-diagnostic-canary";
    let guidance = dir.path().join(marker);
    let mut config = agmi::config::Config::default();
    config.state_dir = dir.path().join("uncreated-state");
    config.network.address = "poa111111111111111111111111111111111".into();
    config.network.credential_file = dir.path().join(marker);
    for (kind, layer) in [
        ("answer", "core"),
        ("answer", "user"),
        ("judge", "core"),
        ("judge", "user"),
    ] {
        config.capabilities.answer.model.core_guidance_file = None;
        config.capabilities.answer.model.guidance_file = None;
        config.capabilities.judge.model.core_guidance_file = None;
        config.capabilities.judge.model.guidance_file = None;
        config.capabilities.answer.mode = agmi::config::Mode::ReadOnly;
        config.capabilities.judge.mode = agmi::config::Mode::ReadOnly;
        let reasons: &[&str] = if layer == "core" {
            &[
                "guidance_required",
                "guidance_missing",
                "guidance_empty",
                "guidance_not_utf8",
                "guidance_too_large",
                "guidance_not_regular",
                "guidance_path_invalid",
            ]
        } else {
            &[
                "guidance_missing",
                "guidance_not_utf8",
                "guidance_too_large",
                "guidance_not_regular",
                "guidance_path_invalid",
            ]
        };
        for &reason in reasons {
            let model = if kind == "answer" {
                &mut config.capabilities.answer.model
            } else {
                &mut config.capabilities.judge.model
            };
            let selected = if layer == "core" {
                &mut model.core_guidance_file
            } else {
                &mut model.guidance_file
            };
            *selected = Some(guidance.clone());
            match reason {
                "guidance_required" => *selected = None,
                "guidance_missing" => {
                    let _ = fs::remove_file(&guidance);
                }
                "guidance_empty" => fs::write(&guidance, " \n").unwrap(),
                "guidance_not_utf8" => fs::write(&guidance, [0xff]).unwrap(),
                "guidance_too_large" => fs::write(&guidance, vec![b'x'; 65537]).unwrap(),
                "guidance_not_regular" => *selected = Some(dir.path().to_path_buf()),
                "guidance_path_invalid" => *selected = Some(format!("~/{marker}").into()),
                _ => unreachable!(),
            }
            if layer == "core" {
                if kind == "answer" {
                    config.capabilities.answer.mode = agmi::config::Mode::Active;
                } else {
                    config.capabilities.judge.mode = agmi::config::Mode::Active;
                }
            }
            fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
            let output = binary()
                .args([
                    "--config",
                    path.to_str().unwrap(),
                    "--json",
                    "config",
                    "check",
                ])
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
            let envelope: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            let error = &envelope["error"];
            assert_eq!(error["code"], "config_invalid");
            assert_eq!(
                error["details"],
                serde_json::json!({"reason":reason,"kind":kind,"layer":layer})
            );
            assert_eq!(
                error["next_actions"][0]["argv"],
                serde_json::json!(["agmi", "--config", path, "config", "show"])
            );
            assert_eq!(
                error["next_actions"][2]["argv"],
                serde_json::json!([
                    "agmi", "--config", path, "guidance", "set", "--kind", kind, "--layer", layer,
                    "--help"
                ])
            );
        }
    }
    assert!(!dir.path().join("uncreated-state").exists());
}

#[test]
fn doctor_repairs_only_proven_refusals_without_resetting_uncertainty_or_pause() {
    use agmi::config::Config;
    use rusqlite::{Connection, params};
    use serde_json::{Value, json};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
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
    // Local diagnosis/recovery must not need to open this credential.
    config.network.credential_file = dir.path().join("nonexistent-credential");
    let original_config = toml::to_string(&config).unwrap();
    fs::write(&path, &original_config).unwrap();
    let invoke = |arguments: &[&str]| {
        binary()
            .args(["--config", path.to_str().unwrap(), "--json"])
            .args(arguments)
            .output()
            .unwrap()
    };
    let paused = invoke(&["pause"]);
    assert!(paused.status.success(), "{paused:?}");
    let db = Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
    for (id, state) in [(1, "unknown"), (2, "unknown"), (3, "model_unknown")] {
        db.execute("INSERT INTO operations(id,kind,work_key,state,request,result,payload,generation,revision,created_at,updated_at)
            VALUES(?1,'judge',?2,?3,'{\"private\":\"request-canary\"}','{\"private\":\"result-canary\"}',NULL,0,'fixture',1,1)",
            params![id,format!("work-{id}"),state]).unwrap();
    }
    db.execute(
        "INSERT INTO operation_evidence(operation_id,evidence,observed_at) VALUES(1,?1,1)",
        [
            json!({"stage":"submit","route":"judge","status":429,"reason":"route_result_unknown",
            "shape":"object","error_category":"rate_limited","retry_after_seconds":1})
            .to_string(),
        ],
    )
    .unwrap();
    db.execute(
        "INSERT INTO operation_evidence(operation_id,evidence,observed_at) VALUES(2,?1,1)",
        [
            json!({"stage":"submit","route":"judge","status":503,"reason":"route_result_unknown",
            "shape":"object","error_category":"unrecognized"})
            .to_string(),
        ],
    )
    .unwrap();
    let control = || {
        db.query_row("SELECT paused,generation FROM control", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })
        .unwrap()
    };
    let original_control = control();
    let before: i64 = db
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let preview = invoke(&["doctor"]);
    let preview: Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["data"]["repairs"]["eligible"][0]["operation_id"], 1);
    assert_eq!(
        preview["data"]["repairs"]["ineligible"][0]["operation_id"],
        2
    );
    assert_eq!(
        preview["data"]["repairs"]["eligible"][0]["classification"],
        "legacy_429_policy_refusal"
    );
    assert_eq!(
        db.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    assert!(!preview.to_string().contains("canary"));
    let repaired = invoke(&["doctor", "--repair"]);
    let repaired: Value = serde_json::from_slice(&repaired.stdout).unwrap();
    assert_eq!(repaired["data"]["repair_outcome"], "applied", "{repaired}");
    assert_eq!(repaired["data"]["repairs"]["applied"][0]["operation_id"], 1);
    assert_eq!(repaired["data"]["repairs"]["failure"], Value::Null);
    assert_eq!(control(), original_control);
    assert_eq!(fs::read_to_string(&path).unwrap(), original_config);
    let states: Vec<(i64, String)> = db
        .prepare("SELECT id,state FROM operations ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        states,
        vec![
            (1, "refused".into()),
            (2, "unknown".into()),
            (3, "model_unknown".into())
        ]
    );
    let retained: String = db
        .query_row("SELECT result FROM operations WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(retained, "{\"private\":\"result-canary\"}");
    let audit: String = db
        .query_row(
            "SELECT resolution FROM operation_evidence WHERE operation_id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let audit: Value = serde_json::from_str(&audit).unwrap();
    assert_eq!(audit["contract"], "retained_refusal_v2");
    assert_eq!(audit["historical_payload_retried"], false);
    let repeated = invoke(&["doctor", "--repair"]);
    let repeated: Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(repeated["data"]["repair_outcome"], "no_eligible_repairs");
    assert_eq!(control(), original_control);
}

#[test]
fn doctor_normalizes_legacy_identity_without_verifying_or_resetting_work() {
    use agmi::config::Config;
    use rusqlite::Connection;
    use serde_json::Value;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
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
    config.network.credential_file = dir.path().join("nonexistent-credential");
    let original_config = toml::to_string(&config).unwrap();
    fs::write(&path, &original_config).unwrap();
    let invoke = |arguments: &[&str]| {
        let output = binary()
            .args(["--config", path.to_str().unwrap(), "--json"])
            .args(arguments)
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    assert_eq!(invoke(&["pause"])["ok"], true);
    let db = Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
    db.execute_batch(
        "INSERT INTO health_evidence(singleton,hosted_identity_verified) VALUES(1,0)
         ON CONFLICT(singleton) DO UPDATE SET hosted_identity_verified=0;
         INSERT INTO read_state(owner,purpose,resource,failures,last_failure_at,failure_category,local_next_at,server_not_before,retained_conservative_floor)
         VALUES('account','identity','identity',3,1900000000,'timeout',2000000000,1999999999,2000000001);
         INSERT INTO operations(kind,work_key,state,request,result,generation,revision,created_at,updated_at)
         VALUES('judge','retained-model','model_unknown','{}','{\"private\":\"identity-canary\"}',0,'fixture',1,1);",
    ).unwrap();
    let preserved = || {
        let control: (i64, i64) = db
            .query_row("SELECT paused,generation FROM control", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let authority: (String, i64) = db
            .query_row(
                "SELECT database_id,dispatch_sequence FROM authority",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let timing: (i64, i64, i64, i64) = db
            .query_row(
                "SELECT failures,local_next_at,server_not_before,retained_conservative_floor
             FROM read_state WHERE owner='account' AND purpose='identity' AND resource='identity'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        let work: (String, String) = db
            .query_row(
                "SELECT state,result FROM operations WHERE work_key='retained-model'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        (control, authority, timing, work)
    };
    let before = preserved();
    let version: i64 = db
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let preview = invoke(&["doctor"]);
    assert!(
        preview["data"]["repairs"]["eligible"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["classification"] == "legacy_identity_evidence_normalization")
    );
    assert_eq!(
        db.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
    let repaired = invoke(&["doctor", "--repair"]);
    assert_eq!(repaired["data"]["repair_outcome"], "applied", "{repaired}");
    assert_eq!(
        repaired["data"]["hosted_identity"]["status"],
        "legacy_unknown"
    );
    assert_eq!(repaired["data"]["hosted_identity"]["legacy_failure"], true);
    assert!(repaired["data"]["hosted_identity_verified"].is_null());
    assert_eq!(
        db.query_row(
            "SELECT hosted_identity_verified FROM health_evidence",
            [],
            |r| r.get::<_, Option<bool>>(0)
        )
        .unwrap(),
        None
    );
    assert_eq!(preserved(), before);
    assert_eq!(fs::read_to_string(&path).unwrap(), original_config);
    assert!(!config.network.credential_file.exists());
    assert!(!repaired.to_string().contains("identity-canary"));
    let repeated = invoke(&["doctor", "--repair"]);
    assert_eq!(repeated["data"]["repair_outcome"], "no_eligible_repairs");
    assert_eq!(preserved(), before);
}

#[cfg(unix)]
fn lane_fixture() -> (tempfile::TempDir, std::path::PathBuf, agmi::config::Config) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut config = agmi::config::Config::default();
    config.state_dir = dir.path().join("state");
    config.network.chain = format!(
        "lane-{}",
        dir.path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('.', "")
    );
    config.network.address = format!("poa1{}", "1".repeat(32));
    config.network.credential_file = dir.path().join("key");
    config.capabilities.answer.mode = agmi::config::Mode::Off;
    config.capabilities.judge.mode = agmi::config::Mode::Off;
    config.capabilities.mine.mode = agmi::config::Mode::Off;
    fs::write(&config.network.credential_file, "pk_local_fixture").unwrap();
    fs::set_permissions(
        &config.network.credential_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let output = binary()
        .arg("--config")
        .arg(&path)
        .args(["--json", "run", "--once"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    (dir, path, config)
}

#[cfg(unix)]
#[test]
fn lane_control_cas_is_independent_metadata_only_and_never_implies_open() {
    let (_dir, path, mut config) = lane_fixture();
    // Broken sibling model inputs must not block local control or start a harness.
    config.capabilities.judge.model.guidance_file = Some(path.with_file_name("missing-guidance"));
    config.capabilities.judge.model.executable = path.with_file_name("missing-harness");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let invoke = |args: &[&str]| {
        let output = binary()
            .arg("--config")
            .arg(&path)
            .args(["--json"])
            .args(args)
            .output()
            .unwrap();
        let bytes = if output.status.success() {
            &output.stdout
        } else {
            &output.stderr
        };
        (
            output.status.success(),
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap(),
        )
    };
    let (ok, initial) = invoke(&["lane", "show", "answer"]);
    assert!(ok, "{initial}");
    let token = initial["data"]["desired"]["control_token"]
        .as_str()
        .unwrap();
    let (_, sibling) = invoke(&["lane", "show", "judge"]);
    let (ok, paused) = invoke(&["lane", "pause", "answer", "--expected-control", token]);
    assert!(ok, "{paused}");
    assert_eq!(paused["data"]["desired"]["paused"], true);
    assert_eq!(paused["data"]["fence_ack"]["acknowledged"], true);
    assert_eq!(paused["data"]["fence_ack"]["changed"], true);
    assert_eq!(paused["data"]["fence_ack"]["scope"], "local_admission");
    assert_eq!(paused["data"]["authoritative_closure"]["state"], "closed");
    assert_eq!(paused["data"]["observed_admission"]["state"], "unknown");
    let current = paused["data"]["desired"]["control_token"].as_str().unwrap();
    let (ok, noop) = invoke(&["lane", "pause", "answer", "--expected-control", current]);
    assert!(ok, "{noop}");
    assert_eq!(noop["data"]["desired"], paused["data"]["desired"]);
    assert_eq!(noop["data"]["fence_ack"]["changed"], false);
    let (ok, stale) = invoke(&["lane", "pause", "answer", "--expected-control", token]);
    assert!(!ok);
    assert_ne!(stale["error"]["code"], "operation_failed");
    let (ok, resumed) = invoke(&["lane", "resume", "answer", "--expected-control", current]);
    assert!(ok, "{resumed}");
    assert_eq!(resumed["data"]["desired"]["paused"], false);
    assert_eq!(resumed["data"]["authoritative_closure"]["state"], "closed"); // global pause remains
    assert_eq!(resumed["data"]["observed_admission"]["state"], "unknown");
    assert_eq!(
        resumed["data"]["authoritative_closure"]["account_generation"],
        initial["data"]["authoritative_closure"]["account_generation"]
    );
    let (_, sibling_after) = invoke(&["lane", "show", "judge"]);
    assert_eq!(sibling_after["data"]["desired"], sibling["data"]["desired"]);
    let (ok, agents) = invoke(&["agents"]);
    assert!(ok);
    assert!(agents["data"]["routes"]["mine"].is_null());
    assert_eq!(agents["data"]["configuration_state"], "desired_saved");
    assert_eq!(agents["data"]["fence_acknowledged"], false);
    assert!(!config.capabilities.judge.model.executable.exists());
}

#[cfg(unix)]
#[test]
fn lane_wait_deadline_includes_cross_process_configuration_lock() {
    let (_dir, path, _config) = lane_fixture();
    let show = binary()
        .arg("--config")
        .arg(&path)
        .args(["--json", "lane", "show", "mine"])
        .output()
        .unwrap();
    assert!(show.status.success());
    let initial: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    let token = initial["data"]["desired"]["control_token"]
        .as_str()
        .unwrap();
    let directory = fs::File::open(path.parent().unwrap()).unwrap();
    directory.lock().unwrap();
    let started = std::time::Instant::now();
    let output = binary()
        .arg("--config")
        .arg(&path)
        .args([
            "--json",
            "lane",
            "pause",
            "mine",
            "--expected-control",
            token,
            "--wait-seconds",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let failure: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(failure["error"]["code"], "admin_busy");
    drop(directory);
    let after = binary()
        .arg("--config")
        .arg(&path)
        .args(["--json", "lane", "show", "mine"])
        .output()
        .unwrap();
    assert!(after.status.success());
    let after: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(after["data"]["desired"], initial["data"]["desired"]);
}

#[test]
fn lane_parser_requires_token_and_bounded_wait_without_echoing_values() {
    let marker = "private-control-token-canary";
    for args in [
        vec!["lane", "pause", "answer"],
        vec![
            "lane",
            "resume",
            "judge",
            "--expected-control",
            marker,
            "--wait-seconds",
            "0",
        ],
        vec![
            "lane",
            "pause",
            "mine",
            "--expected-control",
            marker,
            "--wait-seconds",
            "301",
        ],
        vec!["guidance", "show", "--kind", "mine"],
    ] {
        let output = binary().args(["--json"]).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "invalid_arguments");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
    }
}

#[test]
fn lane_control_refuses_missing_journal_without_initializing_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut config = agmi::config::Config::default();
    config.state_dir = dir.path().join("absent-state");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    for args in [
        vec!["lane", "show", "answer"],
        vec![
            "lane",
            "pause",
            "judge",
            "--expected-control",
            "not-a-control-token",
        ],
        vec![
            "lane",
            "resume",
            "mine",
            "--expected-control",
            "not-a-control-token",
        ],
    ] {
        let output = binary()
            .arg("--config")
            .arg(&path)
            .args(["--json"])
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let failure: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_ne!(failure["error"]["code"], "operation_failed");
        assert!(!config.state_dir.exists());
    }
}
