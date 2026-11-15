use std::{fs, process::Command};

// Refuse the local cache before any publisher request; tests never need an
// alternate production origin, config, journal, or a running service.
fn isolated_check(root: &std::path::Path, cache: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agmi"))
        .env("HOME", root)
        .env("XDG_CACHE_HOME", cache)
        .env("AGMI_UPDATE_CHECKS", "0")
        .args(["--json", "--config"])
        .arg(root.join("not-created/config.toml"))
        .args(["update", "--check"])
        .output()
        .unwrap()
}

#[test]
fn standalone_check_needs_no_account_and_reports_cache_failure_nonzero() {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("cache-file");
    fs::write(&cache, b"not a directory").unwrap();
    let output = isolated_check(root.path(), &cache);
    assert!(!output.status.success());
    assert!(!root.path().join("not-created").exists());
    assert_eq!(fs::read(&cache).unwrap(), b"not a directory");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("unknown"), "{text}");
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["type"], "update");
    let data = &report["data"];
    assert_eq!(data["success"], false);
    assert_eq!(data["update"]["check"], true);
    assert_eq!(data["update"]["reason"], "cache_unavailable");
    assert_eq!(
        data["release_advisory"]["next_action"]["kind"],
        "use_install_owner"
    );
    assert_eq!(data["next_actions"][0]["kind"], "instruction");
    assert!(data["next_actions"][0]["argv"].is_null());
    assert!(data.get("installation").is_none());
    assert!(data.get("readiness").is_none());
    assert!(!root.path().join(".local/state/agmi").exists());
}

#[test]
fn standalone_check_human_uses_install_owner_without_doctor_or_install_advice() {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("cache-file");
    fs::write(&cache, b"not a directory").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agmi"))
        .env("HOME", root.path())
        .env("XDG_CACHE_HOME", &cache)
        .env("AGMI_UPDATE_CHECKS", "0")
        .arg("--config")
        .arg(root.path().join("not-created/config.toml"))
        .args(["update", "--check"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Release: unknown"), "{text}");
    assert!(text.contains("use installation owner"), "{text}");
    assert!(text.contains("No activation or repair performed"), "{text}");
    assert!(!text.contains("agmi doctor"), "{text}");
    assert!(!text.contains("agmi update --check"), "{text}");
    assert!(!root.path().join("not-created").exists());
    assert_eq!(fs::read(cache).unwrap(), b"not a directory");
}

#[cfg(unix)]
#[test]
fn explicit_check_never_writes_through_cache_directory_symlink() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("cache");
    fs::create_dir(&cache).unwrap();
    let destination = root.path().join("untouched");
    fs::create_dir(&destination).unwrap();
    symlink(&destination, cache.join("agmi")).unwrap();
    let output = isolated_check(root.path(), &cache);
    assert!(!output.status.success());
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    assert!(!root.path().join("not-created").exists());
}
