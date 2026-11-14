//! Release-set installation. Only host systemd integration is delegated to tools;
//! filesystem publication, integrity, rendering and cutover belong to this module.
use crate::journal::CURRENT_JOURNAL_FORMAT;
use crate::lifecycle::{
    InstallerError, RepairRuntimeError, installer_evidence, installer_preflight_error,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn pending_update_target(config_path: &Path) -> Result<Option<String>> {
    #[cfg(unix)]
    {
        native::pending_update_target(config_path)
    }
    #[cfg(not(unix))]
    {
        let _ = config_path;
        Ok(None)
    }
}

#[cfg(unix)]
pub(crate) fn managed_root(config_path: &Path) -> Result<Option<std::path::PathBuf>> {
    native::managed_root(config_path)
}
#[cfg(unix)]
pub(crate) fn guard_managed_run(config_path: &Path) -> Result<()> {
    native::guard_managed_run(config_path)
}

/// Read-only identity of the selected release, not the possibly stale caller.
pub(crate) struct InstalledIdentity {
    pub manifest: String,
    pub binary: std::path::PathBuf,
    pub release: String,
    pub digest: String,
}

pub(crate) fn installed_identity() -> Result<InstalledIdentity> {
    #[cfg(unix)]
    {
        native::installed_identity()
    }
    #[cfg(not(unix))]
    anyhow::bail!("managed installation requires Unix")
}

fn repair_restoration(reason: &'static str) -> Value {
    json!({
        "manager_action":"none","prior_runtime":"unknown","runtime":"caller_managed",
        "verified":false,"health_timer":"unchanged","enablement":"unchanged",
        "pause_state":"unchanged","reason":reason,"failure_code":"none",
        "hard_kill_limit":"SIGKILL, process abort, or host failure can prevent restoration"
    })
}

fn finish_repair(
    result: Result<Value>,
    restoration: Value,
    failure: Option<&'static str>,
) -> Result<Value> {
    match result {
        Ok(mut report) => {
            let Some(repairs) = report.get_mut("repairs").and_then(Value::as_object_mut) else {
                return Err(RepairRuntimeError {
                    code: failure.unwrap_or("repair_report_invalid"),
                    restoration,
                    report: Some(report),
                }
                .into());
            };
            repairs.insert("restoration".into(), restoration.clone());
            if let Some(code) = failure {
                return Err(RepairRuntimeError {
                    code,
                    restoration,
                    report: Some(report),
                }
                .into());
            }
            Ok(report)
        }
        Err(error) => Err(error.context(RepairRuntimeError {
            code: failure.unwrap_or("repair_action_failed"),
            restoration,
            report: None,
        })),
    }
}

fn caller_managed_repair(
    reason: &'static str,
    repair: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    finish_repair(repair(), repair_restoration(reason), None)
}

pub(crate) fn with_repair_runtime(
    config_path: &Path,
    repair: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    if !cfg!(target_os = "linux") {
        return caller_managed_repair("unsupported_host", repair);
    }
    #[cfg(unix)]
    {
        native::with_repair_runtime(config_path, repair)
    }
    #[cfg(not(unix))]
    {
        let _ = config_path;
        caller_managed_repair("unsupported_host", repair)
    }
}

pub(crate) fn run(arguments: &[String], dry_run: bool) -> Result<Value> {
    let mut plan = json!({"arguments":arguments,"dry_run":dry_run,"network_downloads":false,
        "trust":"Local operator-trusted binary and expected SHA256 only; hashes/build labels are not signed publisher or source provenance.",
        "pause_state":"preserve_original_intent","journal":"canonical_target_owned_conversion_only","preview":"plan only; operational preconditions are checked on execution",
        "stage":"preflight","staging":"not_started","activation":"not_started","service":"unknown","failure_code":"none"});
    if dry_run {
        plan["installation"] = installer_evidence(Some(&plan));
        return Ok(plan);
    }
    if !cfg!(target_os = "linux") {
        return Err(installer_preflight_error("unsupported_platform"));
    }
    #[cfg(unix)]
    {
        native::run(arguments, plan)
    }
    #[cfg(not(unix))]
    Err(installer_preflight_error("unsupported_platform"))
}

#[cfg(unix)]
mod native {
    use super::*;
    use crate::lifecycle::update_state::{self, Header, Record};
    use crate::store::migration::{self, UpgradeKind};
    type InstallLock = update_state::Lease;
    use sha2::{Digest, Sha256};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        },
        path::{Component, Path, PathBuf},
        process::{Command, Output, Stdio},
        sync::{
            Mutex, MutexGuard,
            atomic::{AtomicI32, AtomicU64, Ordering},
        },
        time::Duration,
    };

    const UNITS: [(&str, &str, &str); 3] = [
        (
            "agmi.service",
            "unit_agmi_service_sha256",
            include_str!("../deploy/agmi.service"),
        ),
        (
            "agmi-health.service",
            "unit_agmi_health_service_sha256",
            include_str!("../deploy/agmi-health.service"),
        ),
        (
            "agmi-health.timer",
            "unit_agmi_health_timer_sha256",
            include_str!("../deploy/agmi-health.timer"),
        ),
    ];
    const ARTIFACTS: [&str; 5] = [
        "agmi",
        "agmi.service",
        "agmi-health.service",
        "agmi-health.timer",
        "MANIFEST",
    ];
    const RESERVE_KIB: u64 = 262_144;
    const MARGIN_KIB: u64 = 4096;
    static CANCELLED: AtomicI32 = AtomicI32::new(0);
    static SIGNAL_OWNER: Mutex<()> = Mutex::new(());
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    // Scoped to the explicit lifecycle operation, never the runtime's signal policy.
    // The handler only stores an atomic; commands forward cancellation and wait for
    // their child before owned paths are removed. No allocation or cleanup in a handler.
    struct InstallerCancellation {
        previous: Vec<(libc::c_int, libc::sigaction)>,
        _owner: MutexGuard<'static, ()>,
    }
    impl InstallerCancellation {
        fn acquire() -> Result<Self> {
            let owner = SIGNAL_OWNER
                .try_lock()
                .map_err(|_| installer_preflight_error("installer_busy"))?;
            CANCELLED.store(0, Ordering::Relaxed);
            let mut guard = Self {
                previous: Vec::new(),
                _owner: owner,
            };
            extern "C" fn cancel(signal: libc::c_int) {
                CANCELLED.store(signal, Ordering::Relaxed);
            }
            for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                let mut previous = unsafe { std::mem::zeroed() };
                action.sa_sigaction = cancel as *const () as usize;
                unsafe {
                    libc::sigemptyset(&mut action.sa_mask);
                }
                ensure!(
                    unsafe { libc::sigaction(signal, &action, &mut previous) } == 0,
                    "cannot own installer cancellation"
                );
                guard.previous.push((signal, previous));
            }
            Ok(guard)
        }
    }
    impl Drop for InstallerCancellation {
        fn drop(&mut self) {
            for (signal, previous) in self.previous.iter().rev() {
                unsafe {
                    libc::sigaction(*signal, previous, std::ptr::null_mut());
                }
            }
        }
    }
    fn checkpoint() -> Result<()> {
        ensure!(
            CANCELLED.load(Ordering::Relaxed) == 0,
            "installer interrupted"
        );
        Ok(())
    }

    // Pipe readers drain concurrently. Preserve completed child evidence even
    // after cancellation: a delegated installer may already have selected a release.
    // Callers checkpoint before their next effect and before successful completion.
    fn capture(command: &mut Command, cancellable: bool) -> Result<Output> {
        if cancellable {
            checkpoint()?;
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdout = child.stdout.take().context("missing child stdout")?;
        let mut stderr = child.stderr.take().context("missing child stderr")?;
        std::thread::scope(|scope| {
            let out = scope.spawn(move || {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).map(|_| bytes)
            });
            let err = scope.spawn(move || {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).map(|_| bytes)
            });
            let mut forwarded = false;
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) => {}
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(error);
                    }
                }
                let signal = CANCELLED.load(Ordering::Relaxed);
                if cancellable && signal != 0 && !forwarded {
                    unsafe {
                        libc::kill(child.id() as libc::pid_t, signal);
                    }
                    forwarded = true;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let stdout = out
                .join()
                .map_err(|_| anyhow::anyhow!("child stdout reader failed"))??;
            let stderr = err
                .join()
                .map_err(|_| anyhow::anyhow!("child stderr reader failed"))??;
            Ok(Output {
                status: status?,
                stdout,
                stderr,
            })
        })
    }

    struct OwnedPath {
        path: PathBuf,
        identity: (u64, u64),
        directory: bool,
        armed: bool,
    }
    impl OwnedPath {
        fn record(path: PathBuf, directory: bool) -> Result<Self> {
            let metadata = fs::symlink_metadata(&path)?;
            Ok(Self {
                path,
                identity: (metadata.dev(), metadata.ino()),
                directory,
                armed: true,
            })
        }
        fn directory(parent: &Path, prefix: &str) -> Result<Self> {
            for _ in 0..1000 {
                checkpoint()?;
                let path = parent.join(format!(
                    "{prefix}.{}.{}",
                    std::process::id(),
                    TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        let owned = Self::record(path, true)?;
                        fs::set_permissions(&owned.path, fs::Permissions::from_mode(0o700))?;
                        return Ok(owned);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            anyhow::bail!("cannot allocate private installer directory")
        }
    }
    impl Drop for OwnedPath {
        fn drop(&mut self) {
            if self.armed
                && fs::symlink_metadata(&self.path)
                    .is_ok_and(|m| (m.dev(), m.ino()) == self.identity)
            {
                if self.directory {
                    let _ = fs::remove_dir_all(&self.path);
                } else {
                    let _ = fs::remove_file(&self.path);
                }
            }
        }
    }

    fn hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn valid_id(value: &str) -> bool {
        value.strip_prefix("r-").is_some_and(|hash| hex(hash, 64))
    }
    fn regular(path: &Path) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        ensure!(file.metadata()?.is_file(), "artifact is not a regular file");
        Ok(file)
    }
    fn digest(file: File) -> Result<String> {
        digest_cancellable(file, true)
    }
    fn digest_cancellable(mut file: File, cancellable: bool) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            if cancellable {
                checkpoint()?;
            }
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
    fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        checkpoint()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        file.write_all(contents)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        Ok(())
    }
    fn sync_directory(path: &Path) -> Result<()> {
        let file = File::open(path)?;
        file.sync_all()?;
        // Preserve sync -f's filesystem-wide durability, in addition to explicit
        // file/directory fsyncs. macOS filesystem tests exercise the latter.
        #[cfg(target_os = "linux")]
        ensure!(
            unsafe { libc::syncfs(file.as_raw_fd()) } == 0,
            "cannot sync installer filesystem"
        );
        Ok(())
    }
    fn copy_candidate(source: &Path, destination: &Path, expected: &str) -> Result<()> {
        let mut source =
            regular(source).map_err(|_| installer_preflight_error("candidate_unavailable"))?;
        ensure!(
            source.metadata()?.permissions().mode() & 0o111 != 0,
            installer_preflight_error("candidate_execution_unavailable")
        );
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(destination)?;
        target.set_permissions(fs::Permissions::from_mode(0o700))?;
        let mut buffer = [0_u8; 65536];
        loop {
            checkpoint()?;
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            target.write_all(&buffer[..count])?;
        }
        target.sync_all()?;
        drop(target); // An executable must have no writable descriptor at exec.
        ensure!(
            digest(regular(destination)?)? == expected,
            installer_preflight_error("digest_mismatch")
        );
        Ok(())
    }
    fn metadata<'a>(manifest: &'a str, key: &str) -> Result<&'a str> {
        let mut values = manifest
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter_map(|(name, value)| (name == key).then_some(value));
        let value = values.next().context("missing manifest field")?;
        ensure!(values.next().is_none(), "duplicate manifest field");
        Ok(value)
    }
    fn manifest_output(binary: &Path) -> Result<String> {
        let output = capture(
            Command::new(binary).args(["build-info", "--manifest"]),
            true,
        )?;
        ensure!(output.status.success(), "cannot read embedded identity");
        Ok(String::from_utf8(output.stdout)?
            .trim_end_matches('\n')
            .to_owned())
    }
    fn checksums(release: &Path) -> Result<String> {
        let mut sums = String::new();
        for name in ARTIFACTS {
            use std::fmt::Write;
            writeln!(
                &mut sums,
                "{}  {name}",
                digest(regular(&release.join(name))?)?
            )?;
        }
        Ok(sums)
    }
    fn validate_release(release: &Path, id: &str) -> Result<()> {
        validate_release_metadata(release, id, false)
    }

    // Legacy metadata is inspection-only for the retained current release.
    fn validate_release_metadata(release: &Path, id: &str, retained: bool) -> Result<()> {
        ensure!(valid_id(id), "invalid release identity");
        ensure!(
            fs::symlink_metadata(release)?.is_dir(),
            "release is not a directory"
        );
        for name in ARTIFACTS.into_iter().chain(["SHA256SUMS"]) {
            regular(&release.join(name))?;
        }
        ensure!(
            regular(&release.join("agmi"))?
                .metadata()?
                .permissions()
                .mode()
                & 0o111
                != 0,
            "release is not executable"
        );
        let manifest = fs::read_to_string(release.join("MANIFEST"))?;
        ensure!(
            checksums(release)?.trim_end_matches('\n')
                == fs::read_to_string(release.join("SHA256SUMS"))?.trim_end_matches('\n'),
            "release checksums changed"
        );
        ensure!(
            metadata(&manifest, "release_id")? == id
                && metadata(&manifest, "binary_sha256")? == &id[2..],
            "release identity mismatch"
        );
        ensure!(
            digest(regular(&release.join("agmi"))?)? == id[2..],
            "release executable changed"
        );
        ensure!(
            metadata(&manifest, "build_format")? == "1",
            "unsupported manifest format"
        );
        ensure!(
            hex(metadata(&manifest, "commit")?, 40),
            "unknown build commit"
        );
        ensure!(
            matches!(metadata(&manifest, "source_dirty")?, "clean" | "dirty"),
            "unknown source dirty marker"
        );
        ensure!(
            if retained {
                metadata(&manifest, "journal_schema")?.parse::<u32>()? > 0
            } else {
                metadata(&manifest, "journal_schema")?.parse::<i64>()? == CURRENT_JOURNAL_FORMAT
            },
            "incompatible journal schema"
        );
        ensure!(
            metadata(&manifest, "stop_timeout")? == "infinity",
            "incompatible shutdown policy"
        );
        let embedded = manifest_output(&release.join("agmi"))?;
        for (name, key, _) in UNITS {
            let rendered = fs::read_to_string(release.join(name))?;
            let template = rendered.replace(id, "@AGMI_RELEASE_ID@");
            ensure!(
                !rendered.contains("@AGMI_RELEASE_ID@")
                    && format!("{:x}", Sha256::digest(template.as_bytes()))
                        == metadata(&embedded, key)?,
                "release unit does not match embedded template"
            );
        }
        ensure!(
            manifest.trim_end_matches('\n')
                == format!("{embedded}\nrelease_id={id}\nbinary_sha256={}", &id[2..]),
            "embedded identity mismatch"
        );
        Ok(())
    }
    fn activation_schema(
        installed: &str,
        candidate: &str,
        migration_only: bool,
        stopped: bool,
    ) -> Result<()> {
        let installed: i64 = installed.parse()?;
        let candidate: i64 = candidate.parse()?;
        ensure!(
            candidate == CURRENT_JOURNAL_FORMAT
                && if migration_only {
                    stopped && matches!(installed, 2 | 3)
                } else {
                    installed == CURRENT_JOURNAL_FORMAT
                },
            "journal crossing requires explicit stopped format2/3-to-current migration-only activation; downgrades are forbidden"
        );
        Ok(())
    }

    struct Request<'a> {
        action: &'a str,
        target: &'a str,
        digest: Option<&'a str>,
        expected_release: Option<&'a str>,
        stopped: bool,
        migration_only: bool,
        migrate: bool,
        proposal: Option<&'a str>,
        expected_token: Option<&'a str>,
        accept_risk_change: Option<&'a str>,
    }
    impl<'a> Request<'a> {
        fn parse(arguments: &'a [String]) -> Result<Self> {
            let action = arguments.first().context("missing action")?.as_str();
            let target = arguments.get(1).context("missing target")?.as_str();
            let mut request = Self {
                action,
                target,
                digest: None,
                expected_release: None,
                stopped: action == "install",
                migration_only: false,
                migrate: false,
                proposal: None,
                expected_token: None,
                accept_risk_change: None,
            };
            let mut rest = arguments[2..].iter();
            let mut stopped_seen = false;
            while let Some(option) = rest.next() {
                match option.as_str() {
                    "--sha256"
                        if matches!(action, "stage" | "install" | "update")
                            && request.digest.is_none() =>
                    {
                        request.digest = Some(rest.next().context("missing digest")?);
                    }
                    "--expected-release"
                        if matches!(action, "update" | "activate")
                            && request.expected_release.is_none() =>
                    {
                        let expected = rest.next().context("missing expected release")?;
                        ensure!(valid_id(expected), "invalid expected release");
                        request.expected_release = Some(expected);
                    }
                    "--migration-only"
                        if matches!(action, "install" | "activate" | "update")
                            && !request.migration_only =>
                    {
                        request.migration_only = true;
                    }
                    "--migrate" if matches!(action, "update" | "activate") && !request.migrate => {
                        request.migrate = true;
                    }
                    "--proposal" if request.proposal.is_none() => {
                        request.proposal = Some(rest.next().context("missing proposal path")?);
                    }
                    "--expected-token" if request.expected_token.is_none() => {
                        let token = rest.next().context("missing expected token")?;
                        ensure!(
                            token
                                .strip_prefix("agmi.atomic-migration.v1:")
                                .is_some_and(|hash| hex(hash, 64)),
                            "invalid expected token"
                        );
                        request.expected_token = Some(token);
                    }
                    "--accept-risk-change" if request.accept_risk_change.is_none() => {
                        let token = rest.next().context("missing risk approval")?;
                        ensure!(
                            token
                                .strip_prefix("agmi.atomic-migration.v1:")
                                .is_some_and(|hash| hex(hash, 64)),
                            "invalid risk approval"
                        );
                        request.accept_risk_change = Some(token);
                    }
                    "--stopped" if matches!(action, "activate" | "update") && !stopped_seen => {
                        stopped_seen = true;
                        request.stopped = true;
                    }
                    _ => anyhow::bail!("invalid installer option"),
                }
            }
            match action {
                "stage" | "install" | "update" => ensure!(
                    Path::new(target).is_absolute()
                        && request.digest.is_some_and(|hash| hex(hash, 64)),
                    "invalid binary request"
                ),
                "activate" => ensure!(valid_id(target), "invalid release request"),
                "service" => ensure!(
                    matches!(
                        target,
                        "status" | "start" | "stop" | "restart" | "enable" | "disable"
                    ),
                    "invalid service request"
                ),
                _ => anyhow::bail!("invalid installer action"),
            }
            ensure!(
                !request.migration_only || request.stopped,
                "migration-only requires stopped activation"
            );
            ensure!(
                (!request.migrate || !request.migration_only)
                    && (request.expected_token.is_none() || action == "activate")
                    && request
                        .accept_risk_change
                        .is_none_or(|token| request.expected_token == Some(token)),
                "invalid migration request"
            );
            Ok(request)
        }
    }

    fn incoming(binary: &Path, request: &Request<'_>) -> Result<Value> {
        let action = match request.action {
            "stage" => "install",
            "activate" => "update",
            action => action,
        };
        let mut command = Command::new(binary);
        command.args(["--json", action]);
        if request.action == "activate" {
            command.args(["--release", request.target]);
        } else {
            command
                .arg("--binary")
                .arg(binary)
                .args(["--sha256", request.digest.context("missing digest")?]);
        }
        if request.action == "stage" {
            command.arg("--stage-only");
        }
        if request.stopped && matches!(request.action, "update" | "activate") {
            command.arg("--stopped");
        }
        if request.migration_only {
            command.arg("--migration-only");
        }
        if let Some(expected) = request.expected_release {
            command.args(["--expected-release", expected]);
        }
        if request.migrate {
            command.arg("--migrate");
        }
        for (flag, value) in [
            ("--proposal", request.proposal),
            ("--expected-token", request.expected_token),
            ("--accept-risk-change", request.accept_risk_change),
        ] {
            if let Some(value) = value {
                command.args([flag, value]);
            }
        }
        let output = capture(&mut command, true).map_err(|error| {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
            {
                installer_preflight_error("candidate_execution_unavailable")
            } else {
                InstallerError {
                    evidence: installer_evidence(None),
                }
                .into()
            }
        })?;
        if !output.status.success() {
            // Newer update commands preserve partial activation in their stdout
            // report even when subsequent diagnosis/repair exits unsuccessfully.
            if let Ok(envelope) = serde_json::from_slice::<Value>(&output.stdout)
                && action == "update"
                && envelope["schema"] == "agmi.cli.v1"
                && envelope["type"] == "update"
                && envelope["data"]["installation"].is_object()
            {
                let evidence = installer_evidence(Some(&envelope["data"]["installation"]));
                if evidence["failure_code"] == "decision_required" {
                    return Ok(envelope["data"].clone());
                }
                if evidence["stage"] == "complete" && evidence["failure_code"] == "none" {
                    return Ok(envelope["data"].clone());
                }
                return Err(InstallerError { evidence }.into());
            }
            let evidence = output
                .stderr
                .split(|byte| *byte == b'\n')
                .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                .find(|value| {
                    value["schema"] == "agmi.cli.v1" && value["error"]["code"] == "installer_failed"
                })
                .map(|value| installer_evidence(Some(&value["error"]["details"])))
                .unwrap_or_else(|| installer_evidence(None));
            return Err(InstallerError { evidence }.into());
        }
        let mut envelope: Value =
            serde_json::from_slice(&output.stdout).map_err(|_| InstallerError {
                evidence: installer_evidence(None),
            })?;
        ensure!(
            envelope["schema"] == "agmi.cli.v1"
                && envelope["ok"] == true
                && envelope["type"] == action
                && envelope.get("data").is_some(),
            InstallerError {
                evidence: installer_evidence(None)
            }
        );
        Ok(envelope["data"].take())
    }

    #[derive(serde::Serialize)]
    struct BootstrapRecovery {
        disable_command_succeeded: bool,
        definitions_restored: bool,
        manager_reload_succeeded: bool,
    }

    struct Installation {
        home: PathBuf,
        root: PathBuf,
        bin: PathBuf,
        units: PathBuf,
        config: PathBuf,
        state_dir: Option<PathBuf>,
        systemctl: PathBuf,
        analyze: PathBuf,
        phase: &'static str,
        staging: &'static str,
        activation: &'static str,
        service: &'static str,
        failure: &'static str,
        stop_on_failure: bool,
        migration_only: bool,
        migrate: bool,
        automatic: bool,
        already_current: bool,
        transaction: Option<Record>,
        restoration: Value,
        proposal: Value,
        expected_token: Option<String>,
        inspection: Option<crate::store::migration::UpgradeInspection>,
        compatibility: Value,
        migration: Value,
        preview: Option<Value>,
        lock: Option<InstallLock>,
        output: String,
        bootstrap_recovery: Option<BootstrapRecovery>,
        #[cfg(test)]
        proc_root: PathBuf,
    }
    impl Installation {
        fn new(home: PathBuf) -> Result<Self> {
            ensure!(home.is_absolute(), "HOME must be absolute");
            Ok(Self {
                root: home.join(".local/share/agmi/releases"),
                bin: home.join(".local/bin"),
                units: home.join(".config/systemd/user"),
                config: home.join(".config/agmi/config.toml"),
                state_dir: None,
                home,
                systemctl: "systemctl".into(),
                analyze: "systemd-analyze".into(),
                phase: "preflight",
                staging: "not_started",
                activation: "not_started",
                service: "unknown",
                failure: "preparation_failed",
                stop_on_failure: false,
                migration_only: false,
                migrate: false,
                automatic: false,
                already_current: false,
                transaction: None,
                restoration: json!({"status":"not_needed","runtime":"unknown","timer":"unknown","pause_state":"unknown","verified":false}),
                proposal: json!({}),
                expected_token: None,
                inspection: None,
                compatibility: Value::Null,
                migration: Value::Null,
                preview: None,
                lock: None,
                output: String::new(),
                bootstrap_recovery: None,
                #[cfg(test)]
                proc_root: "/proc".into(),
            })
        }
        fn evidence(&self, success: bool) -> Value {
            installer_evidence(Some(
                &json!({"stage":self.phase,"staging":self.staging,"activation":self.activation,
                "service":self.service,"failure_code":if success { "none" } else { self.failure },
                "bootstrap_recovery":self.bootstrap_recovery,
                "operation_mode":self.transaction.as_ref().map_or("unknown", |record| {
                    if record.payload["explicit_maintenance"] == true { "maintenance" } else { "standard" }
                }),
                "compatibility":self.compatibility,"migration":self.migration,"restoration":self.restoration}),
            ))
        }
        fn record_migration_failure(&mut self, status: Option<Value>, expected: Option<&str>) {
            let observed = status.filter(|status| {
                status["pending"] == true
                    || (status["phase"] == "complete"
                        && status["token"].as_str().is_some_and(|token| {
                            Some(token) == self.migration["token"].as_str().or(expected)
                        }))
            });
            if !matches!(
                self.migration["phase"].as_str(),
                Some("complete" | "recovery_required")
            ) {
                self.migration["phase"] = json!("failed");
            }
            if let Some(status) = observed {
                self.migration = json!({
                    "phase":if status["pending"] == true { "recovery_required" } else { "complete" },
                    "participation_resumed":self.migration["participation_resumed"].as_bool(),
                    "release_id":self.migration["release_id"],
                    "token":status["token"],"target_journal_format":status["target_journal_format"],
                    "recovery_supported":status["recovery_supported"],
                    "further_migration_required":status["further_migration_required"],
                    "pending":status["pending"],
                    "recovery_prerequisite":if status["recovery_prerequisite"].is_string() {
                        Some("authority_adoption")
                    } else { None }});
            }
        }

        fn maintenance(&self) -> bool {
            self.migrate
                && self.inspection.as_ref().is_some_and(|inspection| {
                    inspection.kind != UpgradeKind::Compatible || self.expected_token.is_some()
                })
        }

        fn inspect_upgrade(&mut self) -> Result<PathBuf> {
            let inspection = migration::inspect_upgrade(&self.config)?;
            let required = inspection.kind != UpgradeKind::Compatible;
            let classification = match inspection.kind {
                UpgradeKind::Compatible => "compatible",
                UpgradeKind::MarkerOnly => "marker_only",
                UpgradeKind::Conversion => "conversion",
                UpgradeKind::Pending => "pending",
            };
            self.compatibility = json!({"classification":classification,
                "migration_required":required,"target_journal_format":CURRENT_JOURNAL_FORMAT});
            self.migration = json!({"phase":if required { "required" } else { "not_required" },
                "participation_resumed":false});
            self.failure = "migration_conflict";
            if let Some(previous) = &self.inspection {
                ensure!(
                    previous.source_sha256 == inspection.source_sha256,
                    "configuration changed during upgrade"
                );
                ensure!(
                    previous.state_dir == inspection.state_dir,
                    "state location changed during upgrade"
                );
            }
            if required && !self.migrate && !self.migration_only {
                self.migrate = true;
            }
            if required
                && inspection.kind != UpgradeKind::Pending
                && self.proposal == json!({})
                && self.expected_token.is_none()
                && self
                    .transaction
                    .as_ref()
                    .is_none_or(|r| r.payload["authorization"] == "preserving")
            {
                match migration::automatic_upgrade(&self.config)? {
                    migration::AutomaticUpgrade::Preserving => self.automatic = true,
                    migration::AutomaticUpgrade::DecisionRequired(reason) => {
                        self.failure = "decision_required";
                        self.migration["phase"] = json!("decision_required");
                        self.migration["decision_reason"] = json!(reason);
                        anyhow::bail!(
                            "canonical migration requires an explicit policy or authority decision"
                        );
                    }
                }
            }
            if inspection.kind == UpgradeKind::Pending
                || (inspection.kind == UpgradeKind::Compatible && self.expected_token.is_some())
            {
                let status = match &inspection.pending {
                    Some(status) => status.clone(),
                    None => migration::status(&inspection.state_dir)?,
                };
                self.migration = json!({"phase":"recovery_required","participation_resumed":false,
                    "token":status["token"],"target_journal_format":status["target_journal_format"],
                    "recovery_supported":status["recovery_supported"],
                    "further_migration_required":status["further_migration_required"],
                    "pending":status["pending"],
                    "recovery_prerequisite":if status["recovery_prerequisite"].is_string() {
                        Some("authority_adoption")
                    } else { None }});
                if inspection.kind == UpgradeKind::Pending {
                    self.failure = "migration_conflict";
                    ensure!(
                        self.proposal == json!({}),
                        "pending recovery does not accept a new proposal"
                    );
                    ensure!(
                        status["recovery_supported"] == true,
                        "sealed recovery is unsupported"
                    );
                }
                if self.expected_token.is_some()
                    && matches!(
                        inspection.kind,
                        UpgradeKind::Pending | UpgradeKind::Compatible
                    )
                {
                    ensure!(
                        status["token"].as_str() == self.expected_token.as_deref(),
                        "sealed continuation token changed"
                    );
                    if inspection.kind == UpgradeKind::Compatible {
                        ensure!(
                            status["phase"] == "complete" && inspection.paused == Some(true),
                            "completed migration no longer has its stopped intent"
                        );
                    }
                }
            }
            if required && inspection.kind != UpgradeKind::Pending {
                migration::validate_upgrade_proposal(&self.config, &self.proposal)?;
                if inspection.kind == UpgradeKind::MarkerOnly {
                    ensure!(
                        self.proposal == json!({}) && self.expected_token.is_none(),
                        "marker-only migration does not accept a policy or external approval"
                    );
                }
                if self.expected_token.is_some()
                    && inspection.journal_format.is_some_and(|v| v >= 3)
                {
                    ensure!(
                        inspection.paused == Some(true),
                        "approved pause intent changed"
                    );
                }
            }
            let state = inspection.state_dir.clone();
            self.inspection = Some(inspection);
            Ok(state)
        }

        fn systemctl(&self, arguments: &[&str], cancellable: bool) -> Result<Output> {
            capture(
                Command::new(&self.systemctl).arg("--user").args(arguments),
                cancellable,
            )
        }
        fn control(&self, arguments: &[&str]) -> Result<()> {
            ensure!(
                self.systemctl(arguments, true)?.status.success(),
                "systemd operation failed"
            );
            Ok(())
        }
        fn property(&self, unit: &str, property: &str, cancellable: bool) -> Result<String> {
            let output = self.systemctl(
                &["show", unit, &format!("--property={property}"), "--value"],
                cancellable,
            )?;
            ensure!(output.status.success(), "cannot inspect loaded unit");
            Ok(String::from_utf8(output.stdout)?
                .trim_end_matches('\n')
                .to_owned())
        }
        fn account_context(&self) -> Result<()> {
            ensure!(
                resolve_missing(&self.home)? == resolve_missing(&crate::store::account_home()?)?,
                "HOME differs from the operating-system account home"
            );
            Ok(())
        }
        fn manager_context(&self) -> Result<()> {
            self.manager_search_context()?;
            self.manager_loaded_context()
        }
        fn manager_search_context(&self) -> Result<()> {
            let output = self.systemctl(&["show", "--property=UnitPath", "--value"], true)?;
            ensure!(output.status.success(), "cannot inspect manager unit paths");
            let paths = String::from_utf8(output.stdout)?;
            let units = resolve_missing(&self.units)?;
            ensure!(
                paths.split_whitespace().any(|path| {
                    resolve_missing(Path::new(path)).is_ok_and(|path| path == units)
                }),
                "manager does not load this installation's unit directory"
            );
            Ok(())
        }
        fn manager_loaded_context(&self) -> Result<()> {
            for (unit, _, _) in UNITS {
                if self.property(unit, "LoadState", true)? != "not-found" {
                    self.unit_path(unit)?;
                }
            }
            Ok(())
        }
        fn unit_path(&self, unit: &str) -> Result<()> {
            self.unit_path_cancellable(unit, true)
        }
        fn unit_path_cancellable(&self, unit: &str, cancellable: bool) -> Result<()> {
            let loaded = self.property(unit, "FragmentPath", cancellable)?;
            ensure!(!loaded.is_empty(), "loaded unit has no file identity");
            ensure!(
                fs::canonicalize(loaded)? == fs::canonicalize(self.units.join(unit))?,
                "loaded unit belongs to another installation"
            );
            Ok(())
        }
        fn active(&self, unit: &str) -> Result<bool> {
            match self.property(unit, "LoadState", true)?.as_str() {
                "not-found" => Ok(false),
                "loaded" => match self.property(unit, "ActiveState", true)?.as_str() {
                    "active" | "reloading" => Ok(true),
                    "inactive" | "failed" => Ok(false),
                    _ => anyhow::bail!("service intent is transitional or unavailable"),
                },
                _ => anyhow::bail!("service load state is unavailable"),
            }
        }
        fn stop_units(&self, cancellable: bool) -> Result<()> {
            let mut failed = false;
            for (unit, _, _) in UNITS.iter().rev() {
                match self.property(unit, "LoadState", cancellable) {
                    Ok(load) if load == "not-found" => {}
                    Ok(_) => {
                        if !self
                            .systemctl(&["stop", unit], cancellable)
                            .is_ok_and(|o| o.status.success())
                        {
                            failed = true;
                        }
                    }
                    Err(_) => failed = true,
                }
            }
            ensure!(!failed, "cannot stop every unit");
            Ok(())
        }
        fn verify_stopped(&self) -> Result<()> {
            for unit in ["agmi.service", "agmi-health.service", "agmi-health.timer"] {
                let state = self.property(unit, "ActiveState", true)?;
                ensure!(
                    matches!(state.as_str(), "inactive" | "failed"),
                    "unit did not stop"
                );
            }
            ensure!(
                self.property("agmi.service", "MainPID", true)? == "0",
                "stopped runtime still owns a process"
            );
            Ok(())
        }
        fn verify_upgrade_stopped(&self) -> Result<()> {
            self.verify_stopped()?;
            for unit in ["agmi.service", "agmi-health.service"] {
                let group = self.property(unit, "ControlGroup", true)?;
                if !group.is_empty() {
                    Self::verify_empty_cgroup(Path::new("/sys/fs/cgroup"), &group)?;
                }
            }
            Ok(())
        }

        fn verify_empty_cgroup(root: &Path, group: &str) -> Result<()> {
            let group = Path::new(group);
            ensure!(
                group.is_absolute()
                    && group
                        .components()
                        .all(|part| { matches!(part, Component::RootDir | Component::Normal(_)) }),
                "invalid unit cgroup location"
            );
            let directory = root.join(group.strip_prefix("/")?);
            match fs::read_to_string(directory.join("cgroup.events")) {
                Ok(events) => ensure!(
                    events
                        .lines()
                        .any(|line| { line.split_whitespace().eq(["populated", "0"]) }),
                    "stopped unit still owns descendants"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    ensure!(!directory.try_exists()?, "cannot verify unit descendants");
                }
                Err(error) => return Err(error.into()),
            }
            Ok(())
        }
        fn verify_autostart_disabled(&self) -> Result<()> {
            for unit in ["agmi.service", "agmi-health.timer"] {
                ensure!(
                    matches!(
                        self.property(unit, "UnitFileState", true)?.as_str(),
                        "disabled" | "linked" | "linked-runtime"
                    ),
                    "boot activation remains enabled"
                );
            }
            Ok(())
        }
        fn definition_targets(&self) -> Result<[Option<PathBuf>; UNITS.len()]> {
            let mut targets: [Option<PathBuf>; UNITS.len()] = Default::default();
            for ((unit, _, _), target) in UNITS.iter().zip(&mut targets) {
                let definition = self.units.join(unit);
                *target = match fs::symlink_metadata(&definition) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        Some(fs::read_link(&definition)?)
                    }
                    Ok(_) => None,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
            }
            Ok(targets)
        }
        fn disable_autostart(&mut self) -> Result<()> {
            let targets = self.definition_targets()?;
            let runtime_enabled = self.property("agmi.service", "UnitFileState", true)?
                == "enabled-runtime"
                || self.property("agmi-health.timer", "UnitFileState", true)? == "enabled-runtime";
            // Remove runtime links while persistent definitions still exist for lookup.
            let disabled = (if runtime_enabled {
                self.control(&["disable", "--runtime", "agmi.service", "agmi-health.timer"])
            } else {
                Ok(())
            })
            .and_then(|()| self.control(&["disable", "agmi.service", "agmi-health.timer"]));
            // systemd can remove definition links even when disable fails.
            // Restore their original targets before reporting failure or cancellation.
            let mut restored = Ok(());
            for ((unit, _, _), target) in UNITS.iter().zip(&targets) {
                let Some(target) = target else {
                    continue;
                };
                let definition = self.units.join(unit);
                let result = match fs::symlink_metadata(&definition) {
                    Ok(metadata)
                        if metadata.file_type().is_symlink()
                            && fs::read_link(&definition).as_ref().ok() == Some(target) =>
                    {
                        Ok(())
                    }
                    Ok(_) => Err(std::io::Error::other(
                        "unit definition changed during disable",
                    )),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        symlink(target, &definition)
                    }
                    Err(error) => Err(error),
                };
                restored = restored.and(result.map_err(anyhow::Error::from));
            }
            restored = restored.and(sync_directory(&self.units));
            let reloaded = self.systemctl(&["daemon-reload"], false);
            let reload_succeeded = reloaded
                .as_ref()
                .is_ok_and(|output| output.status.success());
            for ((unit, _, _), target) in UNITS.iter().zip(&targets) {
                if let Some(target) = target
                    && fs::read_link(self.units.join(unit)).as_ref().ok() != Some(target)
                {
                    restored = Err(anyhow::anyhow!("unit definition changed during reload"));
                }
            }
            self.bootstrap_recovery = Some(BootstrapRecovery {
                disable_command_succeeded: disabled.is_ok(),
                definitions_restored: restored.is_ok(),
                manager_reload_succeeded: reload_succeeded,
            });
            if restored.is_err() || !reload_succeeded {
                self.failure = "bootstrap_recovery_failed";
            }
            disabled?;
            restored?;
            ensure!(reload_succeeded, "cannot reload restored unit definitions");
            self.verify_autostart_disabled()
        }
        fn loaded(&self, id: &str) -> Result<()> {
            self.loaded_cancellable(id, true)
        }
        fn loaded_cancellable(&self, id: &str, cancellable: bool) -> Result<()> {
            for (unit, _, _) in UNITS {
                self.unit_path_cancellable(unit, cancellable)?;
                ensure!(
                    self.property(unit, "Description", cancellable)?
                        .ends_with(&format!("[release={id}]")),
                    "loaded identity mismatch"
                );
                ensure!(
                    self.property(unit, "DropInPaths", cancellable)?.is_empty(),
                    "unsupported loaded overrides"
                );
            }
            ensure!(
                self.property("agmi.service", "TimeoutStopUSec", cancellable)? == "infinity",
                "incompatible loaded stop deadline"
            );
            Ok(())
        }
        fn verify_units(&mut self, release: &Path) -> Result<()> {
            self.failure = "unit_invalid";
            let mut command = Command::new(&self.analyze);
            command.args(["--user", "verify"]);
            for (unit, _, _) in UNITS {
                command.arg(release.join(unit));
            }
            ensure!(
                capture(&mut command, true)?.status.success(),
                "invalid release units"
            );
            Ok(())
        }
        fn prepare(&mut self, activation: bool) -> Result<InstallLock> {
            for path in std::iter::once(&self.root)
                .chain(activation.then_some(&self.bin))
                .chain(activation.then_some(&self.units))
            {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(path)?;
            }
            ensure!(
                !fs::symlink_metadata(&self.root)?.file_type().is_symlink(),
                "linked releases directory"
            );
            InstallLock::acquire_or_reuse(&self.root)
        }
        fn fresh(&self) -> Result<()> {
            for path in [self.root.join("current"), self.bin.join("agmi")]
                .into_iter()
                .chain(UNITS.iter().map(|(unit, _, _)| self.units.join(unit)))
            {
                ensure!(!exists(&path)?, "installation already exists; use update");
            }
            Ok(())
        }
        fn legacy_size(&self) -> Result<u64> {
            let mut total = 0;
            for path in [self.bin.join("agmi")]
                .into_iter()
                .chain(UNITS.iter().map(|(unit, _, _)| self.units.join(unit)))
            {
                match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.is_file() => total += metadata.blocks().div_ceil(2),
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(total)
        }
        fn space_at(path: &Path, required: u64, label: &str, output: &mut String) -> Result<()> {
            use std::fmt::Write;
            let path = CString::new(path.as_os_str().as_bytes())?;
            let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::statvfs(path.as_ptr(), &mut space) } == 0,
                "cannot inspect free space"
            );
            let available = (u128::from(space.f_bavail) * u128::from(space.f_frsize) / 1024)
                .min(u128::from(u64::MAX)) as u64;
            writeln!(
                output,
                "space_{label}_available_kib={available} required_kib={required}"
            )?;
            ensure!(
                available >= required,
                installer_preflight_error("insufficient_space")
            );
            Ok(())
        }
        fn space_checks(
            &mut self,
            binary: &Path,
            incoming_kib: u64,
            activation: bool,
        ) -> Result<()> {
            use std::fmt::Write;
            self.failure = "configuration_invalid";
            let state =
                if self.migrate || (!self.migration_only && exists(&self.root.join("current"))?) {
                    self.inspect_upgrade()?
                } else {
                    // Only the retained binary interprets its legacy config, and only
                    // to report the state path. No runtime or journal command is run.
                    let retained_binary;
                    let binary = if self.migration_only {
                        let selected = fs::read_link(self.root.join("current"))?;
                        let id = selected.to_str().context("invalid retained release")?;
                        let release = self.root.join(id);
                        validate_release_metadata(&release, id, true)?;
                        ensure!(
                            matches!(
                                metadata(
                                    &fs::read_to_string(release.join("MANIFEST"))?,
                                    "journal_schema"
                                )?,
                                "2" | "3"
                            ),
                            "migration-only requires a retained format2 or format3 release"
                        );
                        retained_binary = release.join("agmi");
                        retained_binary.as_path()
                    } else {
                        binary
                    };
                    let result = capture(
                        Command::new(binary)
                            .arg("--config")
                            .arg(&self.config)
                            .args(["config", "state-path"]),
                        true,
                    )
                    .map_err(|error| {
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
                        {
                            installer_preflight_error("candidate_execution_unavailable")
                        } else {
                            error
                        }
                    })?;
                    if !result.status.success() {
                        // The ordinary parser stays strict. Recognized historical state
                        // gets actionable refusal, never an implicit migration.
                        let _ = self.inspect_upgrade();
                        anyhow::bail!("cannot inspect configured state path");
                    }
                    PathBuf::from(String::from_utf8(result.stdout)?.trim_end_matches('\n'))
                };
            ensure!(state.is_absolute(), "state path must be absolute");
            let canonical_state = resolve_missing(&state)?;
            let canonical_root = fs::canonicalize(&self.root)?;
            ensure!(
                !canonical_state.starts_with(canonical_root),
                "state must remain outside releases"
            );
            let mut parent = canonical_state.as_path();
            while !parent.is_dir() {
                parent = parent.parent().context("cannot locate state filesystem")?;
            }
            self.failure = "preparation_failed";
            let retained = allocated_kib(&self.root)?;
            let legacy = self.legacy_size()?;
            writeln!(
                &mut self.output,
                "retained_release_kib={retained} incoming_release_kib={incoming_kib} legacy_backup_kib={legacy} journal_wal_reserve_kib={RESERVE_KIB}"
            )?;
            Self::space_at(
                &self.root,
                incoming_kib + legacy + RESERVE_KIB + MARGIN_KIB,
                "releases",
                &mut self.output,
            )?;
            Self::space_at(parent, RESERVE_KIB + MARGIN_KIB, "state", &mut self.output)?;
            Self::space_at(
                &self.home,
                RESERVE_KIB + MARGIN_KIB,
                "binding",
                &mut self.output,
            )?;
            // Bin/unit headroom belongs to activation alone; staging checks
            // only the release store, state and binding headroom.
            if activation {
                Self::space_at(&self.bin, RESERVE_KIB + MARGIN_KIB, "cli", &mut self.output)?;
                Self::space_at(
                    &self.units,
                    RESERVE_KIB + MARGIN_KIB,
                    "units",
                    &mut self.output,
                )?;
            }
            self.state_dir = Some(canonical_state);
            Ok(())
        }
        fn verify_journal_activation(&mut self) -> Result<()> {
            let state = self
                .state_dir
                .as_deref()
                .context("configured state path not inspected")?;
            if let Some((format, complete)) =
                crate::store::migration::activation_journal_format(state)?
            {
                if !self.migration_only
                    && !self.maintenance()
                    && (!complete || format != CURRENT_JOURNAL_FORMAT)
                {
                    self.inspect_upgrade()?;
                }
                ensure!(
                    if self.maintenance() {
                        (1..=CURRENT_JOURNAL_FORMAT).contains(&format)
                    } else if self.migration_only {
                        matches!(format, 1..=3)
                    } else {
                        complete && format == CURRENT_JOURNAL_FORMAT
                    },
                    "existing journal requires explicit stopped migration-only activation and local migration; it is not a fresh installation"
                );
            }
            Ok(())
        }
        fn stage(&mut self, binary: &Path, expected: &str) -> Result<String> {
            self.phase = "staging";
            self.staging = "in_progress";
            self.failure = "release_invalid";
            let id = format!("r-{expected}");
            let release = self.root.join(&id);
            if exists(&release)? {
                validate_release(&release, &id)?;
                self.verify_units(&release)?;
            } else {
                // The source is already privately copied and trusted, but a second
                // digest check still gates every execution from the final stage.
                let binary_kib = regular(binary)?.metadata()?.len().div_ceil(1024);
                let units_kib: u64 = UNITS
                    .iter()
                    .map(|(_, _, text)| (text.len() as u64).div_ceil(1024))
                    .sum();
                Self::space_at(
                    &self.root,
                    binary_kib + units_kib + RESERVE_KIB + MARGIN_KIB,
                    "staging",
                    &mut self.output,
                )?;
                let mut staging = OwnedPath::directory(&self.root, ".stage")?;
                let staged_binary = staging.path.join("agmi");
                copy_candidate(binary, &staged_binary, expected)?;
                fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755))?;
                self.space_checks(&staged_binary, units_kib, false)?;
                self.failure = "release_invalid";
                let embedded = manifest_output(&staged_binary).map_err(|error| {
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
                    {
                        installer_preflight_error("candidate_execution_unavailable")
                    } else {
                        error
                    }
                })?;
                ensure!(
                    metadata(&embedded, "build_format")? == "1",
                    "unsupported binary identity"
                );
                for (name, key, template) in UNITS {
                    ensure!(
                        format!("{:x}", Sha256::digest(template.as_bytes()))
                            == metadata(&embedded, key)?,
                        "unit template does not match incoming binary"
                    );
                    write_file(
                        &staging.path.join(name),
                        template.replace("@AGMI_RELEASE_ID@", &id).as_bytes(),
                        0o644,
                    )?;
                }
                write_file(
                    &staging.path.join("MANIFEST"),
                    format!("{embedded}\nrelease_id={id}\nbinary_sha256={expected}\n").as_bytes(),
                    0o600,
                )?;
                write_file(
                    &staging.path.join("SHA256SUMS"),
                    checksums(&staging.path)?.as_bytes(),
                    0o600,
                )?;
                validate_release(&staging.path, &id)?;
                regular(&staged_binary)?.sync_all()?;
                sync_directory(&staging.path)?;
                checkpoint()?;
                self.staging = "unknown";
                // The exclusive installer lock protects cooperative publication;
                // do not overwrite even an empty directory supplied by an operator.
                ensure!(!exists(&release)?, "release appeared during staging");
                fs::rename(&staging.path, &release)?;
                staging.armed = false;
                self.staging = "published";
                sync_directory(&self.root)?;
                self.verify_units(&release)?;
            }
            self.staging = "complete";
            self.output.push_str(&format!("staged_release={id}\nNo pointer, loaded unit, running process, state, credential or pause setting changed.\n"));
            Ok(id)
        }
        fn backup_legacy(&self) -> Result<()> {
            let mut backup: Option<OwnedPath> = None;
            for path in [self.bin.join("agmi")]
                .into_iter()
                .chain(UNITS.iter().map(|(unit, _, _)| self.units.join(unit)))
            {
                if !exists(&path)? || fs::symlink_metadata(&path)?.file_type().is_symlink() {
                    continue;
                }
                if backup.is_none() {
                    let directory = OwnedPath::directory(&self.root, "legacy-unversioned")?;
                    write_file(&directory.path.join("INCOMPATIBLE"), b"Inspection only: predates journal schema 2; never activate or restore its journal.\n", 0o600)?;
                    backup = Some(directory);
                }
                let directory = backup.as_ref().context("missing legacy backup")?;
                let source = regular(&path)?;
                let metadata = source.metadata()?;
                let destination = directory
                    .path
                    .join(path.file_name().context("missing legacy name")?);
                let mut source = source;
                let mut target = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(metadata.permissions().mode())
                    .open(destination)?;
                std::io::copy(&mut source, &mut target)?;
                target.set_permissions(metadata.permissions())?;
                target.set_times(
                    fs::FileTimes::new()
                        .set_accessed(metadata.accessed()?)
                        .set_modified(metadata.modified()?),
                )?;
                target.sync_all()?;
            }
            if let Some(mut backup) = backup {
                sync_directory(&backup.path)?;
                backup.armed = false;
                sync_directory(&self.root)?;
            }
            Ok(())
        }
        fn activate(&mut self, id: &str, request: &Request<'_>) -> Result<()> {
            self.bootstrap_recovery = None;
            self.phase = "activation_preflight";
            self.failure = "release_invalid";
            // Held by run's InstallLock through staging and cutover. A release
            // discovered before downloading must not replace a concurrent update.
            if let Some(expected) = request.expected_release {
                ensure!(
                    fs::read_link(self.root.join("current"))? == Path::new(expected),
                    "selected release changed before activation"
                );
            }
            let release = self.root.join(id);
            validate_release(&release, id)?;
            self.space_checks(&release.join("agmi"), 0, true)?;
            self.failure = "journal_incompatible";
            self.verify_journal_activation()?;
            self.verify_units(&release)?;
            self.failure = "release_invalid";
            let current = self.root.join("current");
            if exists(&current)? {
                let previous = fs::read_link(&current)?;
                let previous = previous.to_str().context("invalid current release")?;
                ensure!(
                    valid_id(previous),
                    "current is not a versioned release pointer"
                );
                validate_release_metadata(&self.root.join(previous), previous, true)?;
                let old = fs::read_to_string(self.root.join(previous).join("MANIFEST"))?;
                let new = fs::read_to_string(release.join("MANIFEST"))?;
                if self.inspection.is_some() && !request.migration_only {
                    ensure!(
                        metadata(&old, "journal_schema")?.parse::<u32>()? > 0
                            && metadata(&new, "journal_schema")?
                                == CURRENT_JOURNAL_FORMAT.to_string(),
                        "unsupported target identity"
                    );
                } else {
                    activation_schema(
                        metadata(&old, "journal_schema")?,
                        metadata(&new, "journal_schema")?,
                        request.migration_only,
                        request.stopped,
                    )?;
                }
                self.output
                    .push_str(&format!("retained_previous_release={previous}\n"));
            } else {
                ensure!(
                    !request.migration_only && !self.maintenance(),
                    "migration-only requires an installed format2 or format3 release"
                );
            }
            self.failure = "unit_invalid";
            for (unit, _, _) in UNITS {
                ensure!(
                    !self.units.join(format!("{unit}.d")).is_dir(),
                    "unsupported unit overrides"
                );
            }
            self.failure = "service_state_unavailable";
            let runtime_active = self.active("agmi.service")?;
            let timer_active = self.active("agmi-health.timer")?;
            checkpoint()?;
            self.phase = "stopping";
            self.failure = "stop_failed";
            self.activation = "in_progress";
            self.stop_on_failure = true;
            self.stop_units(true)?;
            self.verify_stopped()?;
            self.failure = "journal_incompatible";
            self.verify_journal_activation()?;
            self.service = "stopped";
            self.phase = "switching";
            self.failure = "switch_failed";
            self.backup_legacy()?;
            for (name, destination) in std::iter::once(("agmi", self.bin.join("agmi"))).chain(
                UNITS
                    .iter()
                    .map(|(name, _, _)| (*name, self.units.join(name))),
            ) {
                let target = self.root.join("current").join(name);
                if fs::read_link(&destination).ok().as_ref() != Some(&target) {
                    replace_link(&target, &destination)?;
                }
            }
            sync_directory(&self.bin)?;
            sync_directory(&self.units)?;
            if request.migration_only {
                self.phase = "stopping";
                self.failure = "stop_failed";
                self.disable_autostart()?;
                self.phase = "switching";
                self.failure = "switch_failed";
            }
            checkpoint()?;
            self.activation = "unknown";
            replace_link(Path::new(id), &current)?;
            self.activation = "selected";
            sync_directory(&self.root)?;
            self.phase = "reloading";
            self.failure = "reload_failed";
            self.control(&["daemon-reload"])?;
            self.loaded(id)?;
            self.activation = "loaded_verified";
            if request.stopped {
                if request.migration_only {
                    self.failure = "stop_failed";
                    self.verify_autostart_disabled()?;
                    self.output.push_str("Migration bootstrap disabled boot activation. After local migration, explicitly enable/start services; participation still requires resume.\n");
                } else if request.action == "install" {
                    self.control(&["enable", "agmi.service", "agmi-health.timer"])?;
                }
                self.verify_stopped()?;
            } else {
                self.phase = "starting";
                self.failure = "start_failed";
                self.service = "unknown";
                if runtime_active {
                    self.control(&["start", "agmi.service"])?;
                    self.control(&["is-active", "--quiet", "agmi.service"])?;
                    let pid = self.property("agmi.service", "MainPID", true)?;
                    ensure!(
                        pid.parse::<u32>().is_ok_and(|pid| pid > 0),
                        "no runtime process identity"
                    );
                    ensure!(
                        digest(File::open(format!("/proc/{pid}/exe"))?)? == id[2..],
                        "runtime binary identity mismatch"
                    );
                }
                if timer_active {
                    self.control(&["start", "agmi-health.timer"])?;
                    self.control(&["is-active", "--quiet", "agmi-health.timer"])?;
                }
                self.service = "previous_intent_restored";
            }
            self.status()?;
            checkpoint()?;
            self.phase = "complete";
            self.output.push_str("Activated without changing pause/admission, credentials, native harnesses, or journal history.\nAfter one-way state migration, use compatible releases, roll forward, or stop; never restore an older journal.\n");
            Ok(())
        }
        fn service(&mut self, action: &str) -> Result<()> {
            self.phase = "service";
            self.failure = "service_failed";
            match action {
                "stop" => self.stop_units(true)?,
                "disable" => self.disable_autostart()?,
                "start" | "restart" | "enable" => {
                    let id = fs::read_link(self.root.join("current"))?;
                    let id = id.to_str().context("invalid installed release")?;
                    validate_release(&self.root.join(id), id)?;
                    self.loaded(id)?;
                    self.control(&[action, "agmi.service", "agmi-health.timer"])?;
                    if action != "enable" {
                        self.control(&[
                            "is-active",
                            "--quiet",
                            "agmi.service",
                            "agmi-health.timer",
                        ])?;
                    }
                }
                _ => anyhow::bail!("invalid service action"),
            }
            self.service = "command_completed";
            Ok(())
        }
        fn status(&mut self) -> Result<()> {
            let installed = fs::read_link(self.root.join("current"))
                .ok()
                .and_then(|p| p.to_str().map(str::to_owned));
            if let Some(id) = &installed {
                self.output.push_str(&format!("installed_release={id}\n"));
                if valid_id(id) && self.root.join(id).join("MANIFEST").is_file() {
                    self.output
                        .push_str(&fs::read_to_string(self.root.join(id).join("MANIFEST"))?);
                    self.output.push_str(&format!(
                        "installed_binary_sha256={}\n",
                        digest(regular(&self.root.join(id).join("agmi"))?)?
                    ));
                }
            } else {
                self.output
                    .push_str("installed_release=unversioned_or_absent\n");
            }
            for (unit, _, _) in UNITS {
                self.output.push_str(&format!("loaded_unit={unit}\n"));
                let output = self.systemctl(
                    &[
                        "show",
                        unit,
                        "--property=Description",
                        "--property=LoadState",
                        "--property=ActiveState",
                        "--property=SubState",
                        "--property=MainPID",
                        "--property=InvocationID",
                        "--property=ExecMainStartTimestamp",
                        "--property=TimeoutStopUSec",
                    ],
                    true,
                );
                match output {
                    Ok(output) if output.status.success() => self
                        .output
                        .push_str(&String::from_utf8_lossy(&output.stdout)),
                    _ => self.output.push_str("loaded_identity=unavailable\n"),
                }
            }
            let pid = self
                .property("agmi.service", "MainPID", true)
                .unwrap_or_default();
            if pid.parse::<u32>().is_ok_and(|pid| pid > 0) {
                match File::open(format!("/proc/{pid}/exe")).map_err(anyhow::Error::from).and_then(digest) {
                    Ok(hash) => self.output.push_str(&format!("running_pid={pid}\nrunning_binary_sha256={hash}\nrunning_matches_installed={}\n", installed.as_deref().and_then(|id| id.strip_prefix("r-")) == Some(hash.as_str()))),
                    Err(_) => self.output.push_str("running_binary_sha256=unavailable\n"),
                }
            } else {
                self.output
                    .push_str("running_binary_sha256=none_or_unavailable\n");
            }
            self.output.push_str(
                "identity_evidence=checksums_and_build_labels_not_signed_source_provenance\n",
            );
            checkpoint()
        }
    }

    fn repair_unavailable(error: anyhow::Error) -> anyhow::Error {
        let mut restoration = repair_restoration("canonical_installation_unverified");
        restoration["runtime"] = json!("unknown");
        restoration["failure_code"] = json!("preflight_failed");
        error.context(RepairRuntimeError {
            code: "repair_runtime_unavailable",
            restoration,
            report: None,
        })
    }

    fn account_owned(path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o022 == 0,
            "installation path is not exclusively account-owned"
        );
        Ok(())
    }

    fn account_owned_ancestors(path: &Path, home: &Path) -> Result<()> {
        ensure!(
            path.starts_with(home),
            "installation path leaves account home"
        );
        for ancestor in path.ancestors() {
            account_owned(ancestor)?;
            if ancestor == home {
                return Ok(());
            }
        }
        anyhow::bail!("installation path has no account home")
    }

    fn validate_update_payload(payload: &Value) -> Result<()> {
        ensure!(payload.is_object(), "invalid target update payload");
        ensure!(
            matches!(
                payload["phase"].as_str(),
                Some(
                    "prepared"
                        | "quiescing"
                        | "converting"
                        | "runtime_ready"
                        | "restoring"
                        | "complete"
                )
            ),
            "unsupported update phase"
        );
        for key in [
            "runtime",
            "timer",
            "conversion",
            "explicit_maintenance",
            "decision",
            "pause_pending",
        ] {
            ensure!(payload[key].is_boolean(), "missing update intent flag");
        }
        for key in ["paused", "original_pause"] {
            ensure!(
                payload
                    .get(key)
                    .is_some_and(|v| v.is_null() || v.is_boolean()),
                "invalid update pause intent"
            );
        }
        ensure!(
            payload["generation"].is_null()
                || payload["generation"].as_i64().is_some_and(|v| v >= 0),
            "invalid update control generation"
        );
        ensure!(
            payload["database_id"].is_null()
                || payload["database_id"]
                    .as_str()
                    .is_some_and(|id| hex(id, 32)),
            "invalid update database identity"
        );
        ensure!(
            payload["inputs"].as_str().is_some_and(|hash| hex(hash, 64)),
            "missing update input identity"
        );
        ensure!(
            matches!(
                payload["authorization"].as_str(),
                Some("preserving" | "explicit")
            ),
            "unknown update authorization"
        );
        ensure!(
            payload["enablement"]
                .as_array()
                .is_some_and(|values| values.len() == 3
                    && values.iter().all(|v| matches!(
                        v.as_str(),
                        Some(
                            "enabled"
                                | "enabled-runtime"
                                | "disabled"
                                | "static"
                                | "indirect"
                                | "linked"
                                | "linked-runtime"
                        )
                    ))),
            "invalid boot intent"
        );
        ensure!(
            payload["definitions"].as_array().is_some_and(|values| {
                values.len() == UNITS.len()
                    && values.iter().all(|v| {
                        v.is_null() || v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 4096)
                    })
            }),
            "invalid captured unit definitions"
        );
        ensure!(
            payload["boot"].as_str().is_some_and(
                |v| v.len() == 36 && v.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
            ),
            "invalid captured boot identity"
        );
        ensure!(
            payload.get("resume").is_some_and(|v| v.is_null()
                || (v["generation"].as_i64().is_some_and(|g| g >= 0)
                    && v["paused"].is_boolean()
                    && v["desired"].is_boolean())),
            "invalid conditional resume transition"
        );
        ensure!(
            payload["token"].is_null()
                || payload["token"].as_str().is_some_and(|v| v
                    .strip_prefix("agmi.atomic-migration.v1:")
                    .is_some_and(|v| hex(v, 64))),
            "invalid pinned migration token"
        );
        if matches!(
            payload["phase"].as_str(),
            Some("runtime_ready" | "restoring" | "complete")
        ) {
            ensure!(
                payload["revision"].as_str().is_some_and(|v| hex(v, 64)),
                "missing approved runtime revision"
            );
        }
        Ok(())
    }

    fn boot_identity() -> Result<String> {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot = boot.trim();
        ensure!(
            boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "boot identity unavailable"
        );
        Ok(boot.to_owned())
    }

    // Hash only local inputs; never retain configuration or guidance bodies.
    fn upgrade_inputs(config: &Path) -> Result<String> {
        fn guidance(value: &toml::Value, base: &Path, hash: &mut Sha256) -> Result<()> {
            if let Some(table) = value.as_table() {
                for (key, value) in table {
                    if matches!(key.as_str(), "guidance_file" | "core_guidance_file") {
                        let path = value.as_str().context("invalid guidance path")?;
                        let path = base.join(path);
                        hash.update(path.as_os_str().as_bytes());
                        hash.update(digest_cancellable(regular(&path)?, false)?.as_bytes());
                    } else {
                        guidance(value, base, hash)?;
                    }
                }
            }
            Ok(())
        }
        let bytes = fs::read(config)?;
        ensure!(bytes.len() <= 65536, "configuration exceeds bound");
        let value: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
        let mut hash = Sha256::new();
        hash.update(&bytes);
        guidance(
            &value,
            config.parent().context("missing config parent")?,
            &mut hash,
        )?;
        Ok(format!("{:x}", hash.finalize()))
    }

    impl Installation {
        fn persist_transaction(&self) -> Result<()> {
            ensure!(
                update_state::read(&self.root)?.is_some_and(|saved| self
                    .transaction
                    .as_ref()
                    .is_some_and(|record| saved.header.nonce == record.header.nonce)),
                "update record disappeared or was replaced"
            );
            update_state::save(
                &self.root,
                self.transaction
                    .as_ref()
                    .context("missing update transaction")?,
            )
        }
        fn transaction_phase(&mut self, phase: &str) -> Result<()> {
            self.transaction
                .as_mut()
                .context("missing update transaction")?
                .payload["phase"] = json!(phase);
            self.persist_transaction()
        }
        fn observed_restoration(&mut self, status: &str, verified: bool) {
            let runtime = self.repair_runtime_state(false).ok();
            let timer = self
                .property("agmi-health.timer", "ActiveState", false)
                .ok();
            let pause = migration::inspect_upgrade(&self.config).ok();
            self.restoration = json!({"status":status,
                "runtime":match runtime.as_deref() { Some("active") => "running", Some("inactive" | "failed") => "stopped", _ => "unknown" },
                "timer":match timer.as_deref() { Some("active") => "active", Some("inactive" | "failed") => "stopped", _ => "unknown" },
                "pause_state":match pause { Some(i) => match i.paused { Some(true) => "paused", Some(false) => "unpaused", None => "absent" }, None => "unknown" },
                "verified":verified});
        }
        fn verify_transaction_inputs(&self) -> Result<()> {
            let record = self
                .transaction
                .as_ref()
                .context("missing update transaction")?;
            ensure!(
                upgrade_inputs(&self.config)?
                    == record.payload["inputs"]
                        .as_str()
                        .context("missing input identity")?,
                "configuration or guidance changed during update"
            );
            let observed = migration::inspect_upgrade(&self.config)?;
            ensure!(
                serde_json::to_value(&observed.database_id)? == record.payload["database_id"],
                "database identity changed during update"
            );
            ensure!(
                observed
                    .dispatch_sequence
                    .zip(record.payload["dispatch_sequence"].as_i64())
                    .is_none_or(|(actual, before)| actual >= before),
                "dispatch authority regressed during update"
            );
            ensure!(
                serde_json::to_value(observed.generation)? == record.payload["generation"]
                    && serde_json::to_value(observed.paused)? == record.payload["paused"],
                "control intent changed during update"
            );
            Ok(())
        }
        fn recover_update_definitions(&self) -> Result<()> {
            let Some(record) = update_state::read(&self.root)? else {
                return Ok(());
            };
            if record.header.payload_format != 1 || record.payload["phase"] != "quiescing" {
                return Ok(());
            }
            validate_update_payload(&record.payload)?;
            validate_release_metadata(
                &self.root.join(&record.header.source),
                &record.header.source,
                true,
            )?;
            for (index, (unit, _, _)) in UNITS.iter().enumerate() {
                let Some(target) = record.payload["definitions"][index].as_str() else {
                    continue;
                };
                let resolved = fs::canonicalize(self.units.join(target))?;
                ensure!(
                    resolved == fs::canonicalize(self.root.join(&record.header.source).join(unit))?
                        || resolved
                            == fs::canonicalize(self.root.join(&record.header.target).join(unit))?,
                    "captured definition is outside the pinned releases"
                );
                let definition = self.units.join(unit);
                match fs::symlink_metadata(&definition) {
                    Ok(metadata) => ensure!(
                        metadata.file_type().is_symlink()
                            && fs::read_link(&definition)? == Path::new(target),
                        "unit definition changed during interrupted disable"
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        symlink(target, &definition)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            sync_directory(&self.units)?;
            self.control(&["daemon-reload"])
        }
        fn capture_transaction(&mut self, id: &str, request: &Request<'_>) -> Result<()> {
            let intent = self.repair_intent()?;
            self.loaded(
                fs::read_link(self.root.join("current"))?
                    .to_str()
                    .context("invalid selected release")?,
            )?;
            self.repair_loaded(true)?;
            let inspection = self
                .inspection
                .as_ref()
                .context("missing source inspection")?;
            let source = fs::read_link(self.root.join("current"))?
                .to_str()
                .context("invalid source release")?
                .to_owned();
            validate_release_metadata(&self.root.join(&source), &source, true)?;
            if intent.runtime == "active" {
                self.repair_runtime_identity(&source, true)?;
            }
            let definitions = serde_json::to_value(self.definition_targets()?)?;
            let embedded = manifest_output(&self.root.join(id).join("agmi"))?;
            let mut random = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut random)?;
            let nonce = format!("{:x}", Sha256::digest(random));
            let maintenance = request.migrate && self.maintenance();
            self.transaction = Some(Record {
                header: Header {
                    format: 1,
                    protocol: 1,
                    nonce,
                    root: fs::canonicalize(&self.root)?,
                    config: fs::canonicalize(&self.config)?,
                    source,
                    target: id.to_owned(),
                    digest: id[2..].to_owned(),
                    embedded_sha256: format!("{:x}", Sha256::digest(embedded.as_bytes())),
                    payload_format: 1,
                },
                cancelled: false,
                payload: json!({"phase":"prepared","runtime":intent.runtime == "active" && !request.stopped && !maintenance,
                    "timer":intent.timer == "active" && !request.stopped && !maintenance,
                    "enablement":intent.enablement,"definitions":definitions,"boot":boot_identity()?,"original_pause":inspection.paused,
                    "paused":inspection.paused,"generation":inspection.generation,"database_id":inspection.database_id,
                    "dispatch_sequence":inspection.dispatch_sequence,"inputs":upgrade_inputs(&self.config)?,
                    "conversion":self.maintenance(),"explicit_maintenance":maintenance,
                    "authorization":if self.automatic || (inspection.kind == UpgradeKind::Pending && request.proposal.is_none()) { "preserving" } else { "explicit" },
                    "token":inspection.pending.as_ref().and_then(|p| p["token"].as_str()),
                    "decision":false,"pause_pending":false,"resume":null}),
            });
            update_state::save(&self.root, self.transaction.as_ref().unwrap())?;
            self.restoration["status"] = json!("pending");
            Ok(())
        }
        fn pause_transaction(&mut self) -> Result<()> {
            let inspection = migration::inspect_upgrade(&self.config)?;
            let record = self
                .transaction
                .as_ref()
                .context("missing update transaction")?;
            if record.payload["pause_pending"] == true {
                let before = record.payload["generation"]
                    .as_i64()
                    .context("missing source generation")?;
                if inspection.paused == Some(false) && inspection.generation == Some(before) {
                    self.verify_transaction_inputs()?;
                    self.transaction.as_mut().unwrap().payload["pause_pending"] = json!(false);
                    self.persist_transaction()?;
                    return self.pause_transaction();
                }
                ensure!(
                    inspection.paused == Some(true)
                        && inspection.generation == before.checked_add(1)
                        && serde_json::to_value(&inspection.database_id)?
                            == record.payload["database_id"],
                    "interrupted source pause has no exact owned post-state"
                );
            } else {
                self.verify_transaction_inputs()?;
                if inspection.kind == UpgradeKind::Pending
                    || inspection.journal_format.is_none_or(|v| v < 3)
                    || inspection.paused != Some(false)
                {
                    return Ok(());
                }
                ensure!(
                    inspection.generation.is_some() && inspection.database_id.is_some(),
                    "source pause lacks continuity evidence"
                );
                self.transaction.as_mut().unwrap().payload["pause_pending"] = json!(true);
                self.persist_transaction()?;
                let record = self.transaction.as_ref().unwrap();
                let release = self.root.join(&record.header.source);
                validate_release_metadata(&release, &record.header.source, true)?;
                let mut command = Command::new(release.join("agmi"));
                command
                    .arg("--config")
                    .arg(&self.config)
                    .args(["--json", "pause"]);
                self.lock
                    .as_ref()
                    .context("missing update lease")?
                    .inherit(&mut command, &record.header.nonce)?;
                let output = capture(&mut command, true)?;
                ensure!(
                    output.status.success(),
                    "retained runtime could not persist pause"
                );
                let after = migration::inspect_upgrade(&self.config)?;
                ensure!(
                    after.paused == Some(true)
                        && after.generation
                            == inspection
                                .generation
                                .and_then(|generation| generation.checked_add(1))
                        && after.database_id == inspection.database_id,
                    "source pause did not produce its exact expected transition"
                );
                return self.pause_transaction();
            }
            let record = self.transaction.as_mut().unwrap();
            record.payload["pause_pending"] = json!(false);
            record.payload["paused"] = json!(inspection.paused);
            record.payload["generation"] = json!(inspection.generation);
            self.persist_transaction()
        }
        fn config_only_complete(&self, inspection: &migration::UpgradeInspection) -> Result<bool> {
            let record = self.transaction.as_ref().context("missing transaction")?;
            Ok(inspection.kind == UpgradeKind::Compatible
                && inspection.journal_format.is_none()
                && record.payload["database_id"].is_null()
                && record.payload["token"].is_string()
                && inspection.source_sha256 == record.payload["candidate_sha256"]
                && crate::config::Config::load(&self.config)?.revision()?
                    == record.payload["candidate_revision"])
        }
        fn convert_transaction(&mut self, id: &str, request: &Request<'_>) -> Result<bool> {
            self.phase = "migration";
            self.failure = "migration_conflict";
            let inspection = migration::inspect_upgrade(&self.config)?;
            let record = self.transaction.as_ref().context("missing transaction")?;
            let token = record.payload["token"].as_str().map(str::to_owned);
            if record.payload["decision"] == true && request.proposal.is_none() {
                self.migration = json!({"phase":"decision_required","release_id":id,"token":token,
                    "approval_required":true,"participation_resumed":false,"decision_reason":record.payload["decision_reason"],"target_journal_format":CURRENT_JOURNAL_FORMAT});
                self.failure = "decision_required";
                return Ok(false);
            }
            let sealed = migration::status(&inspection.state_dir)?;
            let completed = if inspection.kind == UpgradeKind::Pending {
                let sealed_token = sealed["token"].as_str().context("missing sealed token")?;
                ensure!(
                    token.as_deref().is_none_or(|token| token == sealed_token),
                    "canonical seal differs from update authorization"
                );
                migration::resume(&self.config, &inspection.state_dir, sealed_token)?
            } else if inspection.kind == UpgradeKind::Compatible {
                if let Some(token) = token {
                    if inspection.journal_format.is_none() {
                        ensure!(
                            self.config_only_complete(&inspection)?,
                            "config-only conversion completion cannot be proven"
                        );
                        json!({"phase":"complete","branch":"config_only","token":token})
                    } else {
                        ensure!(
                            sealed["token"] == token && sealed["phase"] == "complete",
                            "conversion completion cannot be proven"
                        );
                        if record.cancelled {
                            sealed.clone()
                        } else {
                            migration::resume(&self.config, &inspection.state_dir, &token)?
                        }
                    }
                } else {
                    anyhow::bail!("conversion completion lacks exact recorded approval")
                }
            } else {
                self.verify_transaction_inputs()?;
                let preserving = record.payload["authorization"] == "preserving";
                if preserving
                    && let migration::AutomaticUpgrade::DecisionRequired(reason) =
                        migration::automatic_upgrade(&self.config)?
                {
                    let record = self.transaction.as_mut().unwrap();
                    record.payload["authorization"] = json!("explicit");
                    record.payload["decision"] = json!(true);
                    record.payload["decision_reason"] = json!(reason);
                    self.persist_transaction()?;
                    self.migration = json!({"phase":"decision_required","release_id":id,"approval_required":true,
                        "participation_resumed":false,"decision_reason":reason,"target_journal_format":CURRENT_JOURNAL_FORMAT});
                    self.failure = "decision_required";
                    return Ok(false);
                }
                let preview = if preserving {
                    migration::automatic_preview(&self.config)?
                } else {
                    migration::preview(&self.config, &self.proposal)?
                };
                let preview_token = preview["token"]
                    .as_str()
                    .context("missing canonical token")?;
                if let Some(token) = token.as_deref() {
                    ensure!(token == preview_token, "approved migration inputs changed");
                }
                if !preserving
                    && (request.expected_token != Some(preview_token)
                        || (preview["risk_change_required"] == true
                            && request.accept_risk_change != Some(preview_token)))
                {
                    ensure!(
                        request
                            .expected_token
                            .is_none_or(|token| token == preview_token),
                        "approval token differs from exact preview"
                    );
                    let record = self.transaction.as_mut().unwrap();
                    record.payload["token"] = json!(preview_token);
                    record.payload["decision"] = json!(true);
                    self.persist_transaction()?;
                    self.migration = json!({"phase":"decision_required","release_id":id,"token":preview_token,
                        "approval_required":true,"risk_change_required":preview["risk_change_required"],"participation_resumed":false,
                        "target_journal_format":CURRENT_JOURNAL_FORMAT});
                    self.preview = Some(preview);
                    self.failure = "decision_required";
                    return Ok(false);
                }
                self.transaction.as_mut().unwrap().payload["token"] = json!(preview_token);
                self.transaction.as_mut().unwrap().payload["decision"] = json!(false);
                self.transaction.as_mut().unwrap().payload["candidate_sha256"] =
                    preview["seal"]["candidate_sha256"].clone();
                self.transaction.as_mut().unwrap().payload["candidate_revision"] =
                    preview["seal"]["effective_revision"].clone();
                self.persist_transaction()?;
                migration::apply(
                    &self.config,
                    &preview["request"],
                    preview_token,
                    request.accept_risk_change,
                )?
            };
            ensure!(
                completed["recovery_prerequisite"].is_null(),
                "canonical authority prerequisite blocks activation"
            );
            let after = migration::inspect_upgrade(&self.config)?;
            if after.kind != UpgradeKind::Compatible {
                ensure!(
                    !self.transaction.as_ref().unwrap().cancelled,
                    "cancelled historical recovery requires a new conversion decision"
                );
                // Historical completed seals may require a distinct current conversion.
                ensure!(
                    completed["further_migration_required"] == true,
                    "conversion remains incomplete"
                );
                self.transaction.as_mut().unwrap().payload["token"] = Value::Null;
                self.transaction.as_mut().unwrap().payload["inputs"] =
                    json!(upgrade_inputs(&self.config)?);
                self.transaction.as_mut().unwrap().payload["paused"] = json!(after.paused);
                self.transaction.as_mut().unwrap().payload["generation"] = json!(after.generation);
                self.persist_transaction()?;
                return self.convert_transaction(id, request);
            }
            let record = self.transaction.as_mut().unwrap();
            record.payload["inputs"] = json!(upgrade_inputs(&self.config)?);
            record.payload["paused"] = json!(after.paused);
            record.payload["generation"] = json!(after.generation);
            record.payload["database_id"] = json!(after.database_id);
            record.payload["revision"] =
                json!(crate::config::Config::load(&self.config)?.revision()?);
            self.migration = json!({"phase":"complete","release_id":id,"token":completed["token"],
                "target_journal_format":CURRENT_JOURNAL_FORMAT,"participation_resumed":false,
                "paused":after.paused,"generation":after.generation,"pending":false});
            self.transaction_phase("runtime_ready")?;
            Ok(true)
        }

        fn verify_update_runtime(&self, id: &str, revision: &str) -> Result<()> {
            for _ in 0..100 {
                checkpoint()?;
                ensure!(
                    self.repair_runtime_state(true)? == "active",
                    "requested runtime did not remain active"
                );
                if self.repair_runtime_identity(id, true).is_err() {
                    // Type=simple may acknowledge the fork before its exec. Never
                    // accept that process until both executable and policy agree.
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                let pid = self
                    .property("agmi.service", "MainPID", true)?
                    .parse::<u32>()?;
                let invocation = self.property("agmi.service", "InvocationID", true)?;
                ensure!(
                    hex(&invocation, 32),
                    "runtime invocation identity unavailable"
                );
                let config = crate::config::Config::load(&self.config)?;
                ensure!(
                    config.revision()? == revision,
                    "effective configuration changed"
                );
                let status = crate::runtime::status_evidence(&config)?;
                let effective = &status["effective_runtime"];
                if effective["policy"]["process"]["pid"].as_u64() == Some(u64::from(pid))
                    && effective["policy"]["process"]["invocation_id"] == invocation
                    && effective["revision"] == revision
                    && effective["reload_blocked"] == false
                {
                    ensure!(
                        self.property("agmi.service", "InvocationID", true)? == invocation
                            && self.property("agmi.service", "MainPID", true)? == pid.to_string(),
                        "runtime invocation changed"
                    );
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            anyhow::bail!("current invocation has not published the approved effective policy")
        }
        fn restoration_enablement(payload: &Value, index: usize, same_boot: bool) -> Result<&str> {
            let before = payload["enablement"][index]
                .as_str()
                .context("missing boot intent")?;
            Ok(if before == "enabled-runtime" && !same_boot {
                "disabled"
            } else {
                before
            })
        }
        // Completed prior-boot work verifies durable state, not old transient activity.
        fn verify_restored_transaction(&self, id: &str) -> Result<bool> {
            let record = self
                .transaction
                .as_ref()
                .context("missing update transaction")?;
            let revision = record.payload["revision"]
                .as_str()
                .context("missing ready revision")?;
            ensure!(
                fs::read_link(self.root.join("current"))? == Path::new(id),
                "selected target changed"
            );
            self.loaded(id)?;
            self.repair_loaded(true)?;
            ensure!(
                crate::config::Config::load(&self.config)?.revision()? == revision,
                "configuration changed during restoration"
            );
            let same_boot = record.payload["boot"] == boot_identity()?;
            let runtime = record.payload["runtime"] == true;
            let timer = record.payload["timer"] == true;
            let completed_after_boot = record.payload["phase"] == "complete"
                && !same_boot
                && record.payload["explicit_maintenance"] != true;
            let actual_runtime = self.repair_runtime_state(true)? == "active";
            ensure!(
                completed_after_boot || actual_runtime == runtime,
                "runtime intent was not restored"
            );
            if actual_runtime {
                self.verify_update_runtime(id, revision)?;
            }
            let actual_timer = self.active("agmi-health.timer")?;
            ensure!(
                completed_after_boot || actual_timer == timer,
                "timer intent was not restored"
            );
            if record.payload["explicit_maintenance"] == true {
                self.verify_autostart_disabled()?;
            } else {
                for (index, unit) in [(0, "agmi.service"), (2, "agmi-health.timer")] {
                    let desired = Self::restoration_enablement(&record.payload, index, same_boot)?;
                    let actual = self.property(unit, "UnitFileState", true)?;
                    ensure!(
                        actual == desired
                            || (!matches!(desired, "enabled" | "enabled-runtime")
                                && matches!(
                                    actual.as_str(),
                                    "disabled"
                                        | "linked"
                                        | "linked-runtime"
                                        | "static"
                                        | "indirect"
                                )),
                        "boot intent was not restored"
                    );
                }
            }
            let final_control = migration::inspect_upgrade(&self.config)?;
            ensure!(
                final_control.kind == UpgradeKind::Compatible,
                "canonical data is not runtime-ready"
            );
            if !record.payload["database_id"].is_null() {
                ensure!(
                    serde_json::to_value(&final_control.database_id)?
                        == record.payload["database_id"],
                    "database changed during restoration"
                );
                let resume = &record.payload["resume"];
                let (paused, generation) = if resume.is_null() {
                    (
                        record.payload["paused"].as_bool(),
                        record.payload["generation"].as_i64(),
                    )
                } else {
                    (
                        resume["desired"].as_bool(),
                        resume["generation"].as_i64().and_then(|g| {
                            g.checked_add(i64::from(resume["desired"] != resume["paused"]))
                        }),
                    )
                };
                ensure!(
                    final_control.paused == paused && final_control.generation == generation,
                    "control changed during restoration"
                );
            }
            Ok(!completed_after_boot)
        }
        fn finish_cancelled_transaction(&mut self, id: &str) -> Result<()> {
            self.failure = "recovery_required";
            ensure!(
                fs::read_link(self.root.join("current"))? == Path::new(id),
                "cancelled update has not selected its pinned target"
            );
            self.loaded(id)?;
            self.repair_loaded(true)?;
            let current = migration::inspect_upgrade(&self.config)?;
            ensure!(
                current.kind == UpgradeKind::Compatible,
                "cancelled update still requires canonical conversion"
            );
            let record = self.transaction.as_ref().context("missing transaction")?;
            ensure!(record.cancelled, "restoration was not cancelled");
            ensure!(
                serde_json::to_value(&current.database_id)? == record.payload["database_id"],
                "cancelled update database identity changed"
            );
            let nonce = record.header.nonce.clone();
            self.stop_on_failure = false;
            self.observed_restoration("cancelled", false);
            self.transaction_phase("complete")?;
            update_state::remove(&self.root, &nonce)?;
            self.activation = "loaded_verified";
            self.phase = "complete";
            self.output.push_str("Pinned conversion is complete. Later operator intent cancelled automatic restoration; no historical activity, boot or pause intent was replayed.\n");
            Ok(())
        }

        fn restore_transaction(&mut self, id: &str) -> Result<()> {
            self.phase = "restoring";
            self.failure = "restoration_incomplete";
            let record = self
                .transaction
                .as_ref()
                .context("missing transaction")?
                .clone();
            if record.cancelled {
                return self.finish_cancelled_transaction(id);
            }
            let same_boot = record.payload["boot"] == boot_identity()?;
            let runtime = record.payload["runtime"] == true;
            let timer = record.payload["timer"] == true;
            let config = crate::config::Config::load(&self.config)?;
            let revision = record.payload["revision"]
                .as_str()
                .context("missing ready configuration revision")?;
            ensure!(
                config.revision()? == revision,
                "ready configuration changed"
            );
            self.loaded(id)?;
            self.repair_loaded(true)?;
            ensure!(
                fs::read_link(self.root.join("current"))? == Path::new(id),
                "selected target changed"
            );
            let inspection = migration::inspect_upgrade(&self.config)?;
            ensure!(
                inspection.kind == UpgradeKind::Compatible,
                "canonical data is not runtime-ready"
            );
            // A recorded resume transition is reconciled by the canonical helper below,
            // not by comparing its post-state to a stale pre-state.
            if record.payload["resume"].is_null() {
                self.verify_transaction_inputs()?;
            }
            self.transaction_phase("restoring")?;
            if runtime {
                if self.repair_runtime_state(true)? != "active" {
                    self.control(&["start", "agmi.service"])?;
                }
                self.verify_update_runtime(id, revision)?;
            } else {
                ensure!(
                    self.repair_runtime_state(true)? != "active",
                    "runtime activity conflicts with recorded stopped intent"
                );
            }
            if record.payload["conversion"] == true
                && record.payload["explicit_maintenance"] != true
                && let Some(desired) = record.payload["original_pause"].as_bool()
            {
                if record.payload["resume"].is_null() {
                    self.transaction.as_mut().unwrap().payload["resume"] = json!({
                            "generation":record.payload["generation"],"paused":record.payload["paused"],"desired":desired});
                    self.persist_transaction()?;
                }
                let resume = &self.transaction.as_ref().unwrap().payload["resume"];
                let evidence = crate::runtime::restore_update_pause(
                    &config,
                    record.payload["database_id"]
                        .as_str()
                        .context("missing database identity")?,
                    resume["generation"]
                        .as_i64()
                        .context("missing expected generation")?,
                    resume["paused"]
                        .as_bool()
                        .context("missing expected pause")?,
                    desired,
                )?;
                if !desired {
                    self.migration["participation_resumed"] = json!(true);
                }
                self.migration["paused"] = evidence["paused"].clone();
                self.migration["generation"] = evidence["generation"].clone();
            }
            // Once participation is restored, diagnostics or a timer failure must
            // not trigger the old blanket failure-stop cleanup.
            self.stop_on_failure = false;
            if record.payload["explicit_maintenance"] == true {
                self.verify_autostart_disabled()?;
            }
            if record.payload["explicit_maintenance"] != true {
                for (index, unit) in [(0, "agmi.service"), (2, "agmi-health.timer")] {
                    let desired = Self::restoration_enablement(&record.payload, index, same_boot)?;
                    let actual = self.property(unit, "UnitFileState", true)?;
                    if actual != desired {
                        ensure!(
                            matches!(actual.as_str(), "disabled" | "linked" | "linked-runtime"),
                            "boot enablement changed outside the update"
                        );
                        match desired {
                            "enabled" => self.control(&["enable", unit])?,
                            "enabled-runtime" => self.control(&["enable", "--runtime", unit])?,
                            "disabled" | "linked" | "linked-runtime" | "static" | "indirect" => {
                                ensure!(
                                    !matches!(actual.as_str(), "enabled" | "enabled-runtime"),
                                    "unexpected boot enablement conflicts with intent"
                                );
                            }
                            _ => anyhow::bail!("unsupported boot intent"),
                        }
                    }
                }
            }
            if timer {
                if !self.active("agmi-health.timer")? {
                    self.control(&["start", "agmi-health.timer"])?;
                }
                ensure!(
                    self.active("agmi-health.timer")?,
                    "health timer did not restore"
                );
            } else {
                ensure!(
                    !self.active("agmi-health.timer")?,
                    "timer activity conflicts with recorded intent"
                );
            }
            self.verify_restored_transaction(id)?;
            let maintenance = record.payload["explicit_maintenance"] == true;
            self.observed_restoration(
                if maintenance {
                    "not_needed"
                } else {
                    "restored"
                },
                !maintenance,
            );
            self.transaction_phase("complete")?;
            self.service = if record.payload["explicit_maintenance"] == true {
                "stopped"
            } else {
                "previous_intent_restored"
            };
            update_state::remove(&self.root, &record.header.nonce)?;
            self.phase = "complete";
            self.output.push_str(if record.payload["explicit_maintenance"] == true {
                "Explicit migration maintenance completed with services stopped and boot activation disabled.\n"
            } else {
                "Activated the pinned target and restored the recorded independent runtime, timer, boot and pause intent.\n"
            });
            Ok(())
        }

        fn managed_update(&mut self, id: &str, request: &Request<'_>) -> Result<()> {
            self.failure = "recovery_required";
            if let Some(record) = update_state::read(&self.root)? {
                ensure!(
                    pending_update_target(&self.config)?.as_deref() == Some(id),
                    "update must recover its exact pinned target"
                );
                ensure!(
                    record.header.payload_format == 1,
                    "unsupported update payload format"
                );
                validate_update_payload(&record.payload)?;
                ensure!(
                    !request.stopped
                        || (record.payload["runtime"] != true && record.payload["timer"] != true),
                    "pending update would restore activity; use a canonical service stop to cancel it"
                );
                ensure!(
                    !request.migrate || record.payload["explicit_maintenance"] == true,
                    "pending update cannot change to a different maintenance mode"
                );
                self.migrate = record.payload["conversion"] == true;
                self.automatic = record.payload["authorization"] == "preserving";
                self.state_dir = Some(migration::inspect_upgrade(&self.config)?.state_dir);
                if record.payload["conversion"] == true {
                    let resumed = if record.payload["resume"].is_null()
                        || record.payload["resume"]["desired"] == true
                    {
                        Some(false)
                    } else if record.payload["phase"] == "complete" {
                        Some(true)
                    } else {
                        None
                    };
                    self.migration = json!({"phase":if matches!(record.payload["phase"].as_str(), Some("runtime_ready" | "restoring" | "complete")) { "complete" } else { "recovery_required" },
                        "release_id":id,"token":record.payload["token"],"target_journal_format":CURRENT_JOURNAL_FORMAT,"participation_resumed":resumed});
                } else {
                    self.migration = json!({"phase":"not_required","participation_resumed":false});
                }
                self.transaction = Some(record);
                self.restoration["status"] = json!("pending");
            } else {
                validate_release(&self.root.join(id), id)?;
                self.space_checks(&self.root.join(id).join("agmi"), 0, true)?;
                self.verify_units(&self.root.join(id))?;
                if fs::read_link(self.root.join("current"))? == Path::new(id)
                    && !self.maintenance()
                    && !request.stopped
                {
                    self.phase = "complete";
                    self.activation = "loaded_verified";
                    self.loaded(id)?;
                    self.already_current = true;
                    return Ok(());
                }
                self.capture_transaction(id, request)?;
                self.migrate = self.transaction.as_ref().unwrap().payload["conversion"] == true;
            }
            let record = self.transaction.as_ref().unwrap().clone();
            let phase = record.payload["phase"]
                .as_str()
                .context("missing transaction phase")?;
            ensure!(
                matches!(
                    phase,
                    "prepared"
                        | "quiescing"
                        | "converting"
                        | "runtime_ready"
                        | "restoring"
                        | "complete"
                ),
                "unknown update phase"
            );
            validate_release(&self.root.join(id), id)?;
            ensure!(
                digest(File::open(std::env::current_exe()?)?)? == id[2..],
                "transaction must execute its pinned target"
            );
            if phase == "complete" {
                if record.cancelled {
                    return self.finish_cancelled_transaction(id);
                }
                self.failure = "restoration_incomplete";
                let activity_verified = self.verify_restored_transaction(id)?;
                let maintenance = record.payload["explicit_maintenance"] == true;
                self.observed_restoration(
                    if maintenance || !activity_verified {
                        "not_needed"
                    } else {
                        "restored"
                    },
                    !maintenance && activity_verified,
                );
                if record.payload["conversion"] == true
                    && record.payload["resume"]["desired"] == false
                {
                    self.migration["participation_resumed"] = json!(true);
                }
                update_state::remove(&self.root, &record.header.nonce)?;
                self.service = if maintenance {
                    "stopped"
                } else if !activity_verified {
                    "unchanged"
                } else {
                    "previous_intent_restored"
                };
                self.already_current = !activity_verified;
                self.phase = "complete";
                return Ok(());
            }
            if record.cancelled && matches!(phase, "runtime_ready" | "restoring") {
                return self.finish_cancelled_transaction(id);
            }
            if record.cancelled && phase != "converting" {
                self.observed_restoration("cancelled", false);
                anyhow::bail!("newer operator intent requires an explicit restoration decision");
            }
            if record.cancelled {
                let current = migration::inspect_upgrade(&self.config)?;
                if !self.config_only_complete(&current)? {
                    let seal = migration::status(&current.state_dir)?;
                    ensure!(
                        record.payload["token"].is_string()
                            && seal["token"] == record.payload["token"]
                            && (current.kind == UpgradeKind::Pending
                                || (current.kind == UpgradeKind::Compatible
                                    && seal["phase"] == "complete")),
                        "cancelled pre-conversion intent requires an explicit recovery decision"
                    );
                }
            }
            if matches!(phase, "prepared" | "quiescing") {
                self.phase = "stopping";
                self.failure = "migration_conflict";
                if record.payload["pause_pending"] != true {
                    self.verify_transaction_inputs()?;
                }
                self.transaction_phase("quiescing")?;
                self.stop_on_failure = true;
                if self.migrate || record.payload["explicit_maintenance"] == true {
                    self.disable_autostart()?;
                }
                self.stop_units(true)?;
                self.verify_upgrade_stopped()?;
                self.service = "stopped";
                if self.migrate {
                    self.pause_transaction()?;
                }
                self.transaction_phase("converting")?;
            }
            if self.transaction.as_ref().unwrap().payload["phase"] == "converting" {
                self.verify_upgrade_stopped()?;
                self.phase = "switching";
                self.failure = "switch_failed";
                for (name, destination) in std::iter::once(("agmi", self.bin.join("agmi"))).chain(
                    UNITS
                        .iter()
                        .map(|(name, _, _)| (*name, self.units.join(name))),
                ) {
                    let target = self.root.join("current").join(name);
                    if fs::read_link(&destination).ok().as_ref() != Some(&target) {
                        replace_link(&target, &destination)?;
                    }
                }
                sync_directory(&self.bin)?;
                sync_directory(&self.units)?;
                replace_link(Path::new(id), &self.root.join("current"))?;
                sync_directory(&self.root)?;
                self.activation = "selected";
                self.phase = "reloading";
                self.failure = "reload_failed";
                self.control(&["daemon-reload"])?;
                self.loaded(id)?;
                self.activation = "loaded_verified";
                if self.migrate {
                    self.verify_autostart_disabled()?;
                    if !self.convert_transaction(id, request)? {
                        self.observed_restoration("pending", false);
                        self.stop_on_failure = false;
                        return Ok(());
                    }
                } else {
                    self.verify_transaction_inputs()?;
                    self.transaction.as_mut().unwrap().payload["revision"] =
                        json!(crate::config::Config::load(&self.config)?.revision()?);
                    self.transaction_phase("runtime_ready")?;
                }
            }
            self.restore_transaction(id)
        }
    }

    pub(super) fn managed_root(config_path: &Path) -> Result<Option<PathBuf>> {
        let home = crate::store::account_home()?;
        let selected = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(config_path)
        };
        if resolve_missing(&selected)? != resolve_missing(&home.join(".config/agmi/config.toml"))? {
            return Ok(None);
        }
        let root = home.join(".local/share/agmi/releases");
        if !exists(&root)? {
            return Ok(None);
        }
        ensure!(
            fs::symlink_metadata(&root)?.is_dir(),
            "invalid release root"
        );
        account_owned_ancestors(&root, &home)?;
        if !exists(&root.join("current"))? && update_state::read(&root)?.is_none() {
            return Ok(None);
        }
        Ok(Some(root))
    }

    pub(super) fn pending_update_target(config_path: &Path) -> Result<Option<String>> {
        let Some(root) = managed_root(config_path)? else {
            return Ok(None);
        };
        let Some(record) = update_state::read(&root)? else {
            return Ok(None);
        };
        let h = &record.header;
        ensure!(
            h.config == fs::canonicalize(config_path)?,
            "update configuration identity changed"
        );
        let selected = fs::read_link(root.join("current"))?;
        ensure!(
            selected == Path::new(&h.source) || selected == Path::new(&h.target),
            "selected release conflicts with pending update"
        );
        let release = root.join(&h.target);
        ensure!(
            fs::symlink_metadata(&release)?.is_dir(),
            "pinned release is missing"
        );
        account_owned_ancestors(&release, &crate::store::account_home()?)?;
        let binary = release.join("agmi");
        account_owned(&binary)?;
        ensure!(
            digest_cancellable(regular(&binary)?, false)? == h.digest,
            "pinned executable changed"
        );
        let mut manifest = String::new();
        regular(&release.join("MANIFEST"))?
            .take(16385)
            .read_to_string(&mut manifest)?;
        ensure!(
            manifest.len() <= 16384,
            "pinned manifest exceeds protocol bound"
        );
        ensure!(
            metadata(&manifest, "update_protocol")? == "1"
                && metadata(&manifest, "release_id")? == h.target
                && metadata(&manifest, "binary_sha256")? == h.digest,
            "pinned release identity changed"
        );
        let suffix = format!("\nrelease_id={}\nbinary_sha256={}", h.target, h.digest);
        let embedded = manifest
            .trim_end_matches('\n')
            .strip_suffix(&suffix)
            .context("invalid pinned identity envelope")?;
        ensure!(
            format!("{:x}", Sha256::digest(embedded.as_bytes())) == h.embedded_sha256,
            "pinned embedded identity changed"
        );
        Ok(Some(h.target.clone()))
    }

    pub(super) fn guard_managed_run(config_path: &Path) -> Result<()> {
        let Some(root) = managed_root(config_path)? else {
            return Ok(());
        };
        let Some(record) = update_state::read(&root)? else {
            return Ok(());
        };
        pending_update_target(config_path)?;
        ensure!(
            record.header.payload_format == 1,
            "unsupported target update payload"
        );
        validate_update_payload(&record.payload)?;
        ensure!(
            matches!(
                record.payload["phase"].as_str(),
                Some("runtime_ready" | "restoring" | "complete")
            ),
            "pending update fences runtime startup"
        );
        ensure!(
            fs::read_link(root.join("current"))? == Path::new(&record.header.target)
                && digest_cancellable(File::open(std::env::current_exe()?)?, false)?
                    == record.header.digest,
            "only the pinned update target may start"
        );
        Ok(())
    }

    pub(super) fn installed_identity() -> Result<InstalledIdentity> {
        let installation =
            Installation::new(std::env::var_os("HOME").context("HOME unavailable")?.into())?;
        installation.account_context()?;
        let selected = fs::read_link(installation.root.join("current"))?;
        let id = selected.to_str().context("invalid selected release")?;
        ensure!(valid_id(id), "invalid selected release");
        let release = installation.root.join(id);
        account_owned_ancestors(&release, &installation.home)?;
        ensure!(
            fs::symlink_metadata(&release)?.is_dir(),
            "selected release is not a real directory"
        );
        let binary = release.join("agmi");
        let manifest_path = release.join("MANIFEST");
        account_owned(&binary)?;
        account_owned(&manifest_path)?;
        let mut manifest = String::new();
        regular(&manifest_path)?
            .take(16_385)
            .read_to_string(&mut manifest)?;
        ensure!(manifest.len() <= 16_384, "manifest too large");
        let hash = digest_cancellable(regular(&binary)?, false)?;
        ensure!(
            hash == id[2..]
                && metadata(&manifest, "release_id")? == id
                && metadata(&manifest, "binary_sha256")? == hash,
            "selected release identity changed"
        );
        ensure!(
            fs::read_link(installation.bin.join("agmi"))? == installation.root.join("current/agmi"),
            "executable is not a canonical release link"
        );
        Ok(InstalledIdentity {
            manifest,
            binary,
            release: id.to_owned(),
            digest: hash,
        })
    }

    struct RepairIntent {
        runtime: String,
        timer: String,
        enablement: [String; 3],
    }

    impl Installation {
        fn repair_release(&self) -> Result<String> {
            let id = fs::read_link(self.root.join("current"))?;
            let id = id.to_str().context("invalid selected release")?;
            ensure!(valid_id(id), "invalid selected release");
            let release = self.root.join(id);
            for path in [&self.root, &release, &self.bin, &self.units, &self.config] {
                account_owned_ancestors(path, &self.home)?;
            }
            regular(&self.config)?;
            // Validate ownership before validate_release executes the selected
            // binary's embedded-manifest query.
            for name in ARTIFACTS.into_iter().chain(["SHA256SUMS"]) {
                account_owned(&release.join(name))?;
            }
            validate_release(&release, id)?;
            for (name, destination) in std::iter::once(("agmi", self.bin.join("agmi"))).chain(
                UNITS
                    .iter()
                    .map(|(name, _, _)| (*name, self.units.join(name))),
            ) {
                ensure!(
                    fs::read_link(&destination)? == self.root.join("current").join(name),
                    "installation entry is not a canonical release link"
                );
            }
            for (unit, _, template) in UNITS {
                ensure!(
                    !exists(&self.units.join(format!("{unit}.d")))?,
                    "unsupported unit overrides"
                );
                ensure!(
                    fs::read_to_string(release.join(unit))?
                        == template.replace("@AGMI_RELEASE_ID@", id),
                    "unsupported canonical runtime template"
                );
            }
            self.manager_context()?;
            self.loaded(id)?;
            self.repair_loaded(true)?;
            Ok(id.to_owned())
        }

        fn repair_loaded(&self, cancellable: bool) -> Result<()> {
            for (unit, _, _) in UNITS {
                ensure!(
                    self.property(unit, "LoadState", cancellable)? == "loaded"
                        && self.property(unit, "NeedDaemonReload", cancellable)? == "no",
                    "installed units are not coherently loaded"
                );
            }
            Ok(())
        }

        fn repair_runtime_state(&self, cancellable: bool) -> Result<String> {
            let state = self.property("agmi.service", "ActiveState", cancellable)?;
            ensure!(
                matches!(state.as_str(), "active" | "inactive" | "failed"),
                "runtime state is transitional"
            );
            let job = self.property("agmi.service", "Job", cancellable)?;
            ensure!(job.is_empty() || job == "0", "runtime has a pending job");
            ensure!(
                self.property("agmi.service", "ControlPID", cancellable)? == "0",
                "runtime has an active control process"
            );
            if state == "active" {
                ensure!(
                    self.property("agmi.service", "SubState", cancellable)? == "running",
                    "runtime is not stably running"
                );
            } else {
                ensure!(
                    self.property("agmi.service", "MainPID", cancellable)? == "0",
                    "stopped runtime still owns a process"
                );
            }
            Ok(state)
        }

        fn repair_intent(&self) -> Result<RepairIntent> {
            let runtime = self.repair_runtime_state(true)?;
            let timer = self.property("agmi-health.timer", "ActiveState", true)?;
            ensure!(
                matches!(timer.as_str(), "active" | "inactive" | "failed"),
                "health timer state is transitional"
            );
            let mut enablement = [String::new(), String::new(), String::new()];
            for ((unit, _, _), state) in UNITS.into_iter().zip(&mut enablement) {
                *state = self.property(unit, "UnitFileState", true)?;
                ensure!(
                    matches!(
                        state.as_str(),
                        "enabled"
                            | "enabled-runtime"
                            | "disabled"
                            | "static"
                            | "indirect"
                            | "linked"
                            | "linked-runtime"
                    ),
                    "unit enablement is unsupported"
                );
            }
            Ok(RepairIntent {
                runtime,
                timer,
                enablement,
            })
        }

        fn repair_runtime_identity(&self, id: &str, cancellable: bool) -> Result<()> {
            let pid = self.property("agmi.service", "MainPID", cancellable)?;
            ensure!(
                pid.parse::<u32>().is_ok_and(|pid| pid > 0),
                "runtime has no process identity"
            );
            #[cfg(test)]
            let proc_root = self.proc_root.as_path();
            #[cfg(not(test))]
            let proc_root = Path::new("/proc");
            let process = proc_root.join(&pid);
            ensure!(
                fs::metadata(&process)?.uid() == unsafe { libc::geteuid() },
                "runtime process belongs to another account"
            );
            let binary = self.root.join(id).join("agmi");
            ensure!(
                fs::canonicalize(process.join("exe"))? == fs::canonicalize(&binary)?
                    && digest_cancellable(File::open(process.join("exe"))?, cancellable)?
                        == id[2..],
                "runtime binary does not match the selected release"
            );
            let command = fs::read(process.join("cmdline"))?;
            let mut arguments = command.split(|byte| *byte == 0);
            ensure!(
                arguments.next() == Some(binary.as_os_str().as_bytes())
                    && arguments.next() == Some(b"--config".as_slice())
                    && arguments.next() == Some(self.config.as_os_str().as_bytes())
                    && arguments.next() == Some(b"run".as_slice())
                    && arguments.next() == Some(b"".as_slice())
                    && arguments.next().is_none(),
                "runtime arguments do not own the canonical configuration"
            );
            ensure!(
                self.property("agmi.service", "MainPID", cancellable)? == pid,
                "runtime identity changed during inspection"
            );
            Ok(())
        }

        fn restore_repair_runtime(
            &self,
            id: &str,
            intent: &RepairIntent,
            stop_attempted: bool,
            restoration: &mut Value,
        ) -> Result<()> {
            // Recovery is deliberately non-cancellable. A handled signal cannot
            // interrupt the commands or identity checks needed to restore intent.
            self.loaded_cancellable(id, false)?;
            self.repair_loaded(false)?;
            ensure!(
                fs::read_link(self.root.join("current"))? == Path::new(id),
                "selected release changed during repair"
            );
            let state = self.repair_runtime_state(false)?;
            if stop_attempted {
                if state != "active" {
                    ensure!(
                        self.systemctl(&["start", "agmi.service"], false)?
                            .status
                            .success(),
                        "runtime restoration start failed"
                    );
                }
                ensure!(
                    self.repair_runtime_state(false)? == "active",
                    "restored runtime is not active"
                );
                self.repair_runtime_identity(id, false)?;
                restoration["runtime"] = json!("restored");
            } else {
                ensure!(
                    state == intent.runtime,
                    "runtime intent changed during repair"
                );
                if state == "active" {
                    self.repair_runtime_identity(id, false)?;
                }
                restoration["runtime"] = json!("unchanged");
            }
            ensure!(
                self.property("agmi-health.timer", "ActiveState", false)? == intent.timer,
                "health timer state changed during repair"
            );
            restoration["health_timer"] = json!("unchanged");
            for ((unit, _, _), expected) in UNITS.into_iter().zip(&intent.enablement) {
                ensure!(
                    self.property(unit, "UnitFileState", false)? == *expected,
                    "unit enablement changed during repair"
                );
            }
            restoration["enablement"] = json!("unchanged");
            restoration["verified"] = json!(true);
            Ok(())
        }

        fn repair_runtime(&self, repair: impl FnOnce() -> Result<Value>) -> Result<Value> {
            let (id, intent) = (|| {
                ensure!(self.lock.is_some(), "repair requires the installer lock");
                let id = self.repair_release()?;
                let intent = self.repair_intent()?;
                if intent.runtime == "active" {
                    self.repair_runtime_identity(&id, true)?;
                }
                checkpoint()?;
                Ok::<_, anyhow::Error>((id, intent))
            })()
            .map_err(repair_unavailable)?;
            let mut restoration = repair_restoration("canonical_user_systemd");
            restoration["prior_runtime"] = json!(intent.runtime);
            restoration["runtime"] = json!("unknown");
            restoration["health_timer"] = json!("unverified");
            restoration["enablement"] = json!("unverified");
            let mut stop_attempted = false;
            let mut failure = None;
            let result = (|| {
                checkpoint()?;
                if intent.runtime == "active" {
                    stop_attempted = true;
                    restoration["manager_action"] = json!("runtime_stop_attempted");
                    failure = Some("repair_runtime_stop_failed");
                    // Let systemctl finish the stop job even when a handled
                    // cancellation arrives; then skip the action and restore.
                    ensure!(
                        self.systemctl(&["stop", "agmi.service"], false)?
                            .status
                            .success(),
                        "runtime stop failed"
                    );
                    ensure!(
                        self.repair_runtime_state(false)? == "inactive",
                        "runtime did not stop"
                    );
                    restoration["manager_action"] = json!("runtime_stop");
                }
                failure = None;
                checkpoint()?;
                repair()
            })();
            let restored =
                self.restore_repair_runtime(&id, &intent, stop_attempted, &mut restoration);
            if restored.is_err() {
                restoration["failure_code"] = json!("restoration_failed");
                restoration["verified"] = json!(false);
                // Never publish raw systemctl/proc/config failure text.
                return finish_repair(result, restoration, Some("repair_runtime_restore_failed"));
            }
            if CANCELLED.load(Ordering::Relaxed) != 0 {
                failure = Some("repair_interrupted");
            }
            restoration["failure_code"] = json!(failure.unwrap_or("none"));
            finish_repair(result, restoration, failure)
        }
    }

    pub(super) fn with_repair_runtime(
        config_path: &Path,
        repair: impl FnOnce() -> Result<Value>,
    ) -> Result<Value> {
        let account_home = crate::store::account_home().map_err(repair_unavailable)?;
        let selected = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| repair_unavailable(error.into()))?
                .join(config_path)
        };
        let canonical = account_home.join(".config/agmi/config.toml");
        if resolve_missing(&selected).map_err(repair_unavailable)?
            != resolve_missing(&canonical).map_err(repair_unavailable)?
        {
            return caller_managed_repair("noncanonical_config", repair);
        }
        let mut installation = Installation::new(
            std::env::var_os("HOME")
                .context("HOME unavailable")
                .map_err(repair_unavailable)?
                .into(),
        )
        .map_err(repair_unavailable)?;
        installation.account_context().map_err(repair_unavailable)?;
        if !prerequisite(&installation.systemctl) {
            return caller_managed_repair("unsupported_host", repair);
        }
        if !exists(&installation.root).map_err(repair_unavailable)? {
            return caller_managed_repair("installation_absent", repair);
        }
        let cancellation = InstallerCancellation::acquire().map_err(repair_unavailable)?;
        (|| {
            ensure!(
                fs::symlink_metadata(&installation.root)?.is_dir(),
                "release root is not a real directory"
            );
            account_owned_ancestors(&installation.root, &installation.home)?;
            installation.lock = Some(InstallLock::acquire(&installation.root)?);
            if let Some(mut record) = update_state::read(&installation.root)? {
                record.cancelled = true;
                update_state::save(&installation.root, &record)?;
            }
            Ok::<_, anyhow::Error>(())
        })()
        .map_err(repair_unavailable)?;
        if !exists(&installation.root.join("current")).map_err(repair_unavailable)? {
            let absent = (|| {
                for path in std::iter::once(installation.bin.join("agmi")).chain(
                    UNITS
                        .iter()
                        .map(|(unit, _, _)| installation.units.join(unit)),
                ) {
                    ensure!(!exists(&path)?, "installation has no selected release");
                }
                Ok::<_, anyhow::Error>(())
            })();
            absent.map_err(repair_unavailable)?;
            drop(cancellation);
            return caller_managed_repair("installation_absent", repair);
        }
        installation.repair_runtime(repair)
    }
    impl Drop for Installation {
        fn drop(&mut self) {
            // A panic also fails closed. The normal error path records whether
            // stopping succeeded before returning sanitized machine evidence.
            if self.stop_on_failure {
                let _ = self.stop_units(false);
            }
        }
    }
    fn exists(path: &Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn allocated_kib(path: &Path) -> Result<u64> {
        let metadata = fs::symlink_metadata(path)?;
        let mut blocks = metadata.blocks();
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                checkpoint()?;
                blocks += allocated_kib(&entry?.path())? * 2;
            }
        }
        Ok(blocks.div_ceil(2))
    }
    // Resolve symlinks before '..', including a missing final suffix, as readlink
    // -m did. A lexical-only normalizer could let a state symlink enter releases.
    fn resolve_missing(path: &Path) -> Result<PathBuf> {
        fn walk(path: &Path, resolved: &mut PathBuf, links: &mut usize) -> Result<()> {
            for component in path.components() {
                match component {
                    Component::RootDir => *resolved = PathBuf::from("/"),
                    Component::CurDir => {}
                    Component::ParentDir => {
                        resolved.pop();
                    }
                    Component::Normal(name) => {
                        resolved.push(name);
                        match fs::symlink_metadata(&resolved) {
                            Ok(metadata) if metadata.file_type().is_symlink() => {
                                *links += 1;
                                ensure!(*links <= 40, "too many state symlinks");
                                let target = fs::read_link(&resolved)?;
                                resolved.pop();
                                walk(&target, resolved, links)?;
                            }
                            Ok(_) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Component::Prefix(_) => anyhow::bail!("unsupported path prefix"),
                }
            }
            Ok(())
        }
        let mut resolved = PathBuf::new();
        walk(path, &mut resolved, &mut 0)?;
        Ok(resolved)
    }
    fn replace_link(target: &Path, destination: &Path) -> Result<()> {
        checkpoint()?;
        let parent = destination.parent().context("missing link parent")?;
        let temporary = parent.join(format!(
            ".agmi-link.{}.{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        symlink(target, &temporary)?;
        let mut owned = OwnedPath::record(temporary, false)?;
        checkpoint()?;
        fs::rename(&owned.path, destination)?;
        owned.armed = false;
        Ok(())
    }
    fn prerequisite(program: &Path) -> bool {
        let executable = |path: &Path| {
            fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        };
        if program.components().count() > 1 {
            return executable(program);
        }
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|path| executable(&path.join(program)))
        })
    }
    pub(super) fn run(arguments: &[String], plan: Value) -> Result<Value> {
        let request = Request::parse(arguments)
            .map_err(|_| installer_preflight_error("invalid_arguments"))?;
        let _cancellation = InstallerCancellation::acquire()?;
        let mut installation =
            Installation::new(std::env::var_os("HOME").context("HOME unavailable")?.into())?;
        installation.migration_only = request.migration_only;
        installation.migrate = request.migrate;
        installation.expected_token = request.expected_token.map(str::to_owned);
        // Keep all owned input and lock paths alive until post-switch cleanup is done.
        let mut private = None;
        let result = (|| -> Result<Option<Value>> {
            if request.action != "service"
                && let Some(pending) = pending_update_target(&installation.config)?
            {
                let requested = request
                    .digest
                    .map(|hash| format!("r-{hash}"))
                    .unwrap_or_else(|| request.target.to_owned());
                ensure!(
                    requested == pending && !request.migration_only,
                    "pending update cannot be retargeted or changed to bootstrap mode"
                );
            }
            if request.action == "activate" {
                let target = installation.root.join(request.target).join("agmi");
                ensure!(
                    digest_cancellable(regular(&target)?, false)? == request.target[2..],
                    "retained target executable changed"
                );
                if digest_cancellable(File::open(std::env::current_exe()?)?, false)?
                    != request.target[2..]
                {
                    return incoming(&target, &request).map(Some);
                }
            }
            let candidate = if let Some(expected) = request.digest {
                let directory = OwnedPath::directory(&std::env::temp_dir(), "agmi-installer")?;
                let candidate = directory.path.join("incoming-agmi");
                copy_candidate(Path::new(request.target), &candidate, expected)?;
                private = Some(directory);
                let running = digest(File::open("/proc/self/exe")?)?;
                if running != expected {
                    return incoming(&candidate, &request).map(Some);
                }
                Some(candidate)
            } else {
                None
            };
            if let Some(path) = request.proposal {
                installation.failure = "invalid_arguments";
                let bytes = crate::admin::read_optional(Path::new(path), true)?
                    .context("private proposal missing")?;
                ensure!(bytes.len() <= 64 * 1024, "proposal too large");
                installation.proposal = serde_json::from_slice(&bytes)?;
                ensure!(
                    installation.proposal.is_object(),
                    "proposal must be an object"
                );
            }
            if request.action != "stage" {
                installation.failure = "manager_context_mismatch";
                installation.account_context()?;
            }
            if request.action == "service" && request.target == "status" {
                installation.failure = "missing_prerequisite";
                ensure!(prerequisite(&installation.systemctl), "missing systemctl");
                installation.failure = "manager_context_mismatch";
                installation.manager_context()?;
                installation.phase = "status";
                installation.status()?;
                return Ok(None);
            }
            // Stage never needs a user manager, only the unit verifier. Other
            // actions still require both systemd tools before taking the lock.
            if !prerequisite(&installation.analyze)
                || (request.action != "stage" && !prerequisite(&installation.systemctl))
            {
                installation.failure = "missing_prerequisite";
                anyhow::bail!("missing systemd prerequisite");
            }
            if request.action != "stage" {
                installation.failure = "manager_context_mismatch";
                installation.manager_search_context()?;
            }
            installation.lock = Some(installation.prepare(request.action != "stage")?);
            if request.action == "service"
                && !installation
                    .lock
                    .as_ref()
                    .is_some_and(|lock| lock.inherited)
                && let Some(mut record) = update_state::read(&installation.root)?
            {
                record.cancelled = true;
                update_state::save(&installation.root, &record)?;
            }
            if let Some(pending) = pending_update_target(&installation.config)? {
                let requested = request
                    .digest
                    .map(|hash| format!("r-{hash}"))
                    .unwrap_or_else(|| request.target.to_owned());
                ensure!(
                    request.action == "service" || requested == pending,
                    "pending update cannot be retargeted"
                );
            }
            if request.action != "stage" {
                installation.failure = "manager_context_mismatch";
                installation.recover_update_definitions()?;
                installation.manager_loaded_context()?;
            }
            if let Some(expected) = request.expected_release {
                installation.failure = "release_invalid";
                ensure!(
                    fs::read_link(installation.root.join("current"))? == Path::new(expected),
                    "selected release changed before staging"
                );
            }
            if request.expected_token.is_some() {
                installation.failure = "migration_conflict";
                ensure!(
                    fs::read_link(installation.root.join("current"))? == Path::new(request.target),
                    "continuation must use the prepared selected release"
                );
            }
            if request.action == "install" && !request.migration_only {
                installation.fresh()?;
            }
            if request.action == "service" {
                installation.service(request.target)?;
                return Ok(None);
            }
            let id = if let Some(record) = update_state::read(&installation.root)? {
                record.header.target
            } else if let Some(candidate) = candidate {
                installation.stage(&candidate, request.digest.context("missing digest")?)?
            } else {
                request.target.to_owned()
            };
            if request.action != "stage" {
                if matches!(request.action, "update" | "activate") && !request.migration_only {
                    installation.managed_update(&id, &request)?;
                } else {
                    installation.activate(&id, &request)?;
                }
            }
            checkpoint()?;
            installation.stop_on_failure = false;
            Ok(None)
        })();
        match result {
            Ok(Some(delegated)) => {
                if CANCELLED.load(Ordering::Relaxed) != 0 {
                    // Cancellation can arrive after the child completed. Preserve
                    // its observed cutover instead of implying rollback or success.
                    let mut evidence = installer_evidence(Some(&delegated["installation"]));
                    evidence["failure_code"] = json!("interrupted");
                    Err(InstallerError { evidence }.into())
                } else {
                    Ok(delegated)
                }
            }
            Ok(None) => {
                let decision = installation.migration["phase"] == "decision_required";
                let evidence = installation.evidence(!decision);
                let mut result =
                    json!({"plan":plan,"installation":evidence,"output":installation.output});
                if decision {
                    result["status"] = json!("decision_required");
                }
                if installation.already_current {
                    result["status"] = json!("current");
                }
                for key in ["compatibility", "migration", "restoration"] {
                    if !result["installation"][key].is_null() {
                        result[key] = result["installation"][key].clone();
                    }
                }
                if let Some(preview) = installation.preview.take() {
                    result["private"] = json!(true);
                    result["preview"] = preview;
                }
                Ok(result)
            }
            Err(error) => {
                if installation.stop_on_failure {
                    installation.service = if installation.stop_units(false).is_ok()
                        && (!installation.maintenance()
                            || installation.verify_upgrade_stopped().is_ok())
                    {
                        "stopped"
                    } else {
                        "unknown"
                    };
                    installation.stop_on_failure = false;
                }
                if installation.phase == "migration" {
                    let status = installation
                        .state_dir
                        .as_ref()
                        .and_then(|state| migration::status(state).ok());
                    installation.record_migration_failure(status, request.expected_token);
                }
                if installation.transaction.is_some() {
                    let cancelled = installation
                        .transaction
                        .as_ref()
                        .is_some_and(|r| r.cancelled);
                    installation.observed_restoration(
                        if cancelled { "cancelled" } else { "failed" },
                        false,
                    );
                }
                // Private-copy errors precede staging, but failures at a later
                // boundary must retain that boundary's actual machine evidence.
                if let Some(error) = error.downcast_ref::<InstallerError>() {
                    if installation.phase == "preflight" {
                        return Err(InstallerError {
                            evidence: error.evidence.clone(),
                        }
                        .into());
                    }
                    if let Some(code) = error.evidence["failure_code"].as_str() {
                        installation.failure = match code {
                            "digest_mismatch" => "digest_mismatch",
                            "candidate_unavailable" => "candidate_unavailable",
                            "candidate_execution_unavailable" => "candidate_execution_unavailable",
                            "insufficient_space" => "insufficient_space",
                            _ => installation.failure,
                        };
                    }
                }
                Err(InstallerError {
                    evidence: installation.evidence(false),
                }
                .into())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        static TEST_SERIAL: Mutex<()> = Mutex::new(());

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
                                activation_schema(installed, candidate, migration_only, stopped)
                                    .is_ok(),
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
            completed.migration =
                json!({"phase":"complete","token":token,"participation_resumed":true});
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
            let _serial = TEST_SERIAL.lock().unwrap();
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
            installation.service("disable")?;
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
                assert!(installation.service("disable").is_err());
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
            let _serial = TEST_SERIAL.lock().unwrap();
            let _cancellation = InstallerCancellation::acquire()?;
            let temporary =
                OwnedPath::directory(&std::env::temp_dir(), "agmi-native-installer-test")?;
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
            let overlapping_hash =
                candidate(&overlapping, &state_alias.join("missing/journal"), "clean")?;
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
            assert!(
                copy_candidate(&linked, &temporary.path.join("linked-copy"), &expected).is_err()
            );
            let mut space_output = String::new();
            let reserve =
                Installation::space_at(&home, u64::MAX, "test", &mut space_output).unwrap_err();
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
            let _serial = TEST_SERIAL.lock().unwrap();
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
            let _serial = TEST_SERIAL.lock().unwrap();
            let _cancellation = InstallerCancellation::acquire()?;
            let temporary =
                OwnedPath::directory(&std::env::temp_dir(), "agmi-repair-failure-test")?;
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
            let _serial = TEST_SERIAL.lock().unwrap();
            let _cancellation = InstallerCancellation::acquire()?;
            let temporary =
                OwnedPath::directory(&std::env::temp_dir(), "agmi-repair-preflight-test")?;
            let directory = &temporary.path;
            let installation =
                repair_fixture(directory).context("prepare repair preflight fixture")?;
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
    }
}
