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
