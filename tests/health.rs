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
    config.solver.answer.guidance_file = Some(dir.path().join("missing-guidance-canary"));
    let (_config_dir, output) = run_health(&config, &["--min-free-mib", "0"]);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "agmi.cli.v1");
    assert_eq!(value["type"], "health");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["healthy"], false);
    assert_eq!(value["data"]["thresholds"]["warn_free_mib"], 0);
    assert_eq!(value["data"]["admission_blocked"], false);
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
        assert!(envelope["data"]["risk"]["unresolved_effects"].is_null());
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
