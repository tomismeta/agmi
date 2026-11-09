//! Release-set installation. Only host systemd integration is delegated to tools;
//! filesystem publication, integrity, rendering and cutover belong to this module.
use crate::lifecycle::{InstallerError, installer_evidence, installer_preflight_error};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub(crate) fn run(arguments: &[String], dry_run: bool) -> Result<Value> {
    let mut plan = json!({"arguments":arguments,"dry_run":dry_run,"network_downloads":false,
        "trust":"Local operator-trusted binary and expected SHA256 only; hashes/build labels are not signed publisher or source provenance.",
        "pause_state":"unchanged","journal":"never copied, restored or migrated by installer","preview":"plan only; operational preconditions are checked on execution",
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
    struct InstallLock(OwnedPath);
    impl InstallLock {
        fn acquire(root: &Path) -> Result<Self> {
            let path = root.join(".install-lock");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| installer_preflight_error("installer_busy"))?;
            let lock = Self(OwnedPath::record(path, true)?);
            write_file(
                &lock.0.path.join("owner"),
                format!("{}\n", std::process::id()).as_bytes(),
                0o600,
            )?;
            sync_directory(&lock.0.path)?;
            sync_directory(root)?;
            Ok(lock)
        }
    }
    impl Drop for InstallLock {
        fn drop(&mut self) {
            // Never recursively remove a lock, reclaim a stale owner, or remove
            // a replacement directory. Unknown contents require operator inspection.
            self.0.armed = false;
            if fs::symlink_metadata(&self.0.path)
                .is_ok_and(|m| (m.dev(), m.ino()) == self.0.identity)
            {
                let _ = fs::remove_file(self.0.path.join("owner"));
                let _ = fs::remove_dir(&self.0.path);
                if let Some(parent) = self.0.path.parent() {
                    let _ = sync_directory(parent);
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
    fn digest(mut file: File) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            checkpoint()?;
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
            metadata(&manifest, "journal_schema")? == "2",
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

    struct Request<'a> {
        action: &'a str,
        target: &'a str,
        digest: Option<&'a str>,
        stopped: bool,
    }
    impl<'a> Request<'a> {
        fn parse(arguments: &'a [String]) -> Result<Self> {
            let action = arguments.first().context("missing action")?.as_str();
            let target = arguments.get(1).context("missing target")?.as_str();
            let mut request = Self {
                action,
                target,
                digest: None,
                stopped: action == "install",
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
            Ok(request)
        }
    }

    fn incoming(binary: &Path, request: &Request<'_>) -> Result<Value> {
        let action = if request.action == "stage" {
            "install"
        } else {
            request.action
        };
        let mut command = Command::new(binary);
        command
            .args(["--json", action, "--binary"])
            .arg(binary)
            .args(["--sha256", request.digest.context("missing digest")?]);
        if request.action == "stage" {
            command.arg("--stage-only");
        }
        if request.stopped && request.action == "update" {
            command.arg("--stopped");
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

    struct Installation {
        home: PathBuf,
        root: PathBuf,
        bin: PathBuf,
        units: PathBuf,
        config: PathBuf,
        systemctl: PathBuf,
        analyze: PathBuf,
        phase: &'static str,
        staging: &'static str,
        activation: &'static str,
        service: &'static str,
        failure: &'static str,
        stop_on_failure: bool,
        lock: Option<InstallLock>,
        output: String,
    }
    impl Installation {
        fn new(home: PathBuf) -> Result<Self> {
            ensure!(home.is_absolute(), "HOME must be absolute");
            Ok(Self {
                root: home.join(".local/share/agmi/releases"),
                bin: home.join(".local/bin"),
                units: home.join(".config/systemd/user"),
                config: home.join(".config/agmi/config.toml"),
                home,
                systemctl: "systemctl".into(),
                analyze: "systemd-analyze".into(),
                phase: "preflight",
                staging: "not_started",
                activation: "not_started",
                service: "unknown",
                failure: "preparation_failed",
                stop_on_failure: false,
                lock: None,
                output: String::new(),
            })
        }
        fn evidence(&self, success: bool) -> Value {
            installer_evidence(Some(
                &json!({"stage":self.phase,"staging":self.staging,"activation":self.activation,
                "service":self.service,"failure_code":if success { "none" } else { self.failure }}),
            ))
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
            for (unit, _, _) in UNITS {
                if self.property(unit, "LoadState", true)? != "not-found" {
                    self.unit_path(unit)?;
                }
            }
            Ok(())
        }
        fn unit_path(&self, unit: &str) -> Result<()> {
            let loaded = self.property(unit, "FragmentPath", true)?;
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
        fn loaded(&self, id: &str) -> Result<()> {
            for (unit, _, _) in UNITS {
                self.unit_path(unit)?;
                ensure!(
                    self.property(unit, "Description", true)?
                        .ends_with(&format!("[release={id}]")),
                    "loaded identity mismatch"
                );
                ensure!(
                    self.property(unit, "DropInPaths", true)?.is_empty(),
                    "unsupported loaded overrides"
                );
            }
            ensure!(
                self.property("agmi.service", "TimeoutStopUSec", true)? == "infinity",
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
        fn prepare(&mut self) -> Result<InstallLock> {
            for path in [&self.root, &self.bin, &self.units] {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(path)?;
            }
            ensure!(
                !fs::symlink_metadata(&self.root)?.file_type().is_symlink(),
                "linked releases directory"
            );
            InstallLock::acquire(&self.root)
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
        fn space_checks(&mut self, binary: &Path, incoming_kib: u64) -> Result<()> {
            use std::fmt::Write;
            self.failure = "configuration_invalid";
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
            ensure!(
                result.status.success(),
                "cannot inspect configured state path"
            );
            let state = PathBuf::from(String::from_utf8(result.stdout)?.trim_end_matches('\n'));
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
            Self::space_at(&self.bin, RESERVE_KIB + MARGIN_KIB, "cli", &mut self.output)?;
            Self::space_at(
                &self.units,
                RESERVE_KIB + MARGIN_KIB,
                "units",
                &mut self.output,
            )?;
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
                self.space_checks(&staged_binary, units_kib)?;
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
            self.phase = "activation_preflight";
            self.failure = "release_invalid";
            let release = self.root.join(id);
            validate_release(&release, id)?;
            self.space_checks(&release.join("agmi"), 0)?;
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
                validate_release(&self.root.join(previous), previous)?;
                let old = fs::read_to_string(self.root.join(previous).join("MANIFEST"))?;
                let new = fs::read_to_string(release.join("MANIFEST"))?;
                ensure!(
                    metadata(&old, "journal_schema")? == metadata(&new, "journal_schema")?,
                    "journal migration is incompatible"
                );
                self.output
                    .push_str(&format!("retained_previous_release={previous}\n"));
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
            let pid = self.property("agmi.service", "MainPID", true)?;
            ensure!(
                pid.is_empty() || pid == "0",
                "previous runtime did not stop"
            );
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
                if request.action == "install" {
                    self.control(&["enable", "agmi.service", "agmi-health.timer"])?;
                }
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
                "disable" => self.control(&["disable", "agmi.service", "agmi-health.timer"])?,
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
        // Keep all owned input and lock paths alive until post-switch cleanup is done.
        let mut private = None;
        let result = (|| -> Result<Option<Value>> {
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
                installation.manager_context()?;
            }
            installation.lock = Some(installation.prepare()?);
            if request.action == "install" {
                installation.fresh()?;
            }
            if request.action == "service" {
                installation.service(request.target)?;
                return Ok(None);
            }
            let id = if let Some(candidate) = candidate {
                installation.stage(&candidate, request.digest.context("missing digest")?)?
            } else {
                request.target.to_owned()
            };
            if request.action != "stage" {
                installation.activate(&id, &request)?;
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
            Ok(None) => Ok(
                json!({"plan":plan,"installation":installation.evidence(true),"output":installation.output}),
            ),
            Err(error) => {
                if installation.stop_on_failure {
                    installation.service = if installation.stop_units(false).is_ok() {
                        "stopped"
                    } else {
                        "unknown"
                    };
                    installation.stop_on_failure = false;
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

        fn quoted(path: &Path) -> String {
            format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
        }
        fn candidate(path: &Path, state: &Path, dirty: &str) -> Result<String> {
            let mut manifest = format!(
                "build_format=1\ncommit={}\nsource_dirty={dirty}\njournal_schema=2\nstop_timeout=infinity\n",
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

        /// Native staging/cutover coverage on both Darwin and Linux. Only the
        /// external systemd boundary is replaced; real hashes, private copies,
        /// manifest validation, publication, fsync and RAII run unchanged.
        #[test]
        fn filesystem_publication_and_failure_boundaries() -> Result<()> {
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
            installation.lock = Some(installation.prepare()?);
            let owner = fs::read_to_string(installation.root.join(".install-lock/owner"))?;
            assert_eq!(owner.trim(), std::process::id().to_string());
            let busy = InstallLock::acquire(&installation.root)
                .err()
                .context("lock unexpectedly shared")?;
            assert_eq!(
                busy.downcast_ref::<InstallerError>().unwrap().evidence["failure_code"],
                "installer_busy"
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
            assert!(!exists(&installation.bin.join("agmi"))?);
            assert!(fs::read_dir(&installation.units)?.next().is_none());
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
            let events = temporary.path.join("systemd-events");
            let control = temporary.path.join("systemctl-fixture");
            let lock_path = installation.root.join(".install-lock/owner");
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
                stopped: true,
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
            assert!(!root.join(".install-lock").exists());
            assert!(release.is_dir() && second_release.is_dir());
            assert!(!state.exists());
            assert_eq!(
                fs::read(&private_input)?,
                b"credential and journal sentinel"
            );
            no_temporary_paths(&root)?;
            no_temporary_paths(&bin)?;
            no_temporary_paths(&units)?;

            // A stale, ownerless lock is not automatically reclaimed.
            fs::create_dir(root.join(".install-lock"))?;
            assert!(InstallLock::acquire(&root).is_err());
            assert!(root.join(".install-lock").is_dir());
            Ok(())
        }
    }
}
