use std::{fs, process::Command};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agmi"))
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
}

#[test]
fn invalid_guidance_does_not_block_pause_or_local_diagnostics() {
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
    config.solver.answer.guidance_file = Some(guidance.clone());
    config.capabilities.answer = agmi::config::Mode::Active;
    config.capabilities.judge = agmi::config::Mode::Active;
    let core = dir.path().join("answer-core.md");
    let judge_core = dir.path().join("judge-core.md");
    config.solver.answer.core_guidance_file = Some(core.clone());
    config.solver.judge.core_guidance_file = Some(judge_core.clone());
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
        config.solver.answer.guidance_file = Some(invalid);
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
    config.solver.answer.guidance_file = Some(guidance.clone());
    fs::write(&guidance, "Restored user preferences.").unwrap();
    fs::remove_file(&core).unwrap();
    for invalid in [
        Some(core.clone()),
        None,
        Some("".into()),
        Some("~/core.md".into()),
    ] {
        config.solver.answer.core_guidance_file = invalid;
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(invoke(&["pause"]).status.success());
        for args in [&["status"][..], &["logs"], &["agents"], &["config", "show"]] {
            assert!(invoke(args).status.success());
        }
        assert!(!invoke(&["resume"]).status.success());
        assert!(!invoke(&["config", "check"]).status.success());
    }
    config.solver.answer.core_guidance_file = Some(core.clone());
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
    config.capabilities.answer = Mode::Off;
    config.capabilities.judge = Mode::Off;
    config.capabilities.mine = Mode::Off;
    config.schedule.poll_seconds = 1;
    config.schedule.jitter_seconds = 0;
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
    config.schedule.mine_seconds += 1;
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
    assert!(!replay.status.success());
    let replay: serde_json::Value = serde_json::from_slice(&replay.stderr).unwrap();
    assert_eq!(replay["error"]["code"], "config_invalid");
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
