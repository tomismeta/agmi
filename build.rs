use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(|value| value.trim_end().to_owned())
}

fn checksum(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read build input {path}: {error}"));
    format!("{:x}", Sha256::digest(bytes))
}

fn main() {
    // A packaged crate inside another checkout must not borrow that checkout's
    // identity. Source archives without their own Git metadata remain unknown.
    let checkout = git(&["rev-parse", "--show-toplevel"])
        .and_then(|path| fs::canonicalize(path).ok())
        .zip(
            env::current_dir()
                .ok()
                .and_then(|path| path.canonicalize().ok()),
        )
        .is_some_and(|(root, current)| root == current);
    let source_git = |args: &[&str]| checkout.then(|| git(args)).flatten();
    // Watch package inputs and Git identity, including a commit with unchanged
    // source. Dirty is a build-time observation, not source provenance proof.
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "src",
        "adapters",
        "deploy",
        "tests",
        "examples",
        ".github",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(files) = source_git(&["ls-files"]) {
        for path in files.lines() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    for name in ["HEAD", "index", "packed-refs", "refs"] {
        if let Some(path) = source_git(&["rev-parse", "--git-path", name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let commit = source_git(&["rev-parse", "--verify", "HEAD"])
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".into());
    let dirty = match source_git(&["status", "--porcelain", "--untracked-files=normal"]) {
        Some(value) if value.is_empty() => "clean",
        Some(_) => "dirty",
        None => "unknown",
    };
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let profile = env::var("PROFILE").expect("Cargo supplies PROFILE");
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo supplies package version");
    let mut manifest = format!(
        "build_format=1\npackage_version={version}\ncommit={commit}\nsource_dirty={dirty}\ntarget={target}\nprofile={profile}\njournal_schema=2\nstop_timeout=infinity\n"
    );
    for (key, path) in [
        ("unit_agmi_service_sha256", "deploy/agmi.service"),
        (
            "unit_agmi_health_service_sha256",
            "deploy/agmi-health.service",
        ),
        ("unit_agmi_health_timer_sha256", "deploy/agmi-health.timer"),
        ("adapter_hermes_sha256", "adapters/hermes.py"),
        ("adapter_openclaw_sha256", "adapters/openclaw.mjs"),
    ] {
        manifest.push_str(&format!("{key}={}\n", checksum(path)));
    }
    let path = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
        .join("agmi-build-manifest");
    fs::write(&path, manifest).expect("write build manifest");
    println!(
        "cargo:rustc-env=AGMI_BUILD_MANIFEST_PATH={}",
        path.display()
    );
    for (key, value) in [
        ("AGMI_BUILD_COMMIT", commit.as_str()),
        ("AGMI_BUILD_DIRTY", dirty),
        ("AGMI_BUILD_TARGET", target.as_str()),
        ("AGMI_BUILD_PROFILE", profile.as_str()),
        ("AGMI_JOURNAL_SCHEMA", "2"),
    ] {
        println!("cargo:rustc-env={key}={value}");
    }
}
