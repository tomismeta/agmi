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
