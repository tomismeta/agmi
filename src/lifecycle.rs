//! Explicit local lifecycle operations. Credentials never enter arguments or output.
//! Release checksums establish integrity, not publisher/source provenance.
use crate::{
    admin,
    config::Config,
    protocol::Protocol,
    store::{AccountLock, AdmissionGuard, Store, admin_identity_initialized},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

/// Public errors carry static diagnostic text, not credentials or provider output.
#[derive(Debug)]
pub struct LifecycleError {
    pub code: &'static str,
    pub message: &'static str,
}
impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for LifecycleError {}

fn safe_lifecycle_error(
    error: anyhow::Error,
    code: &'static str,
    message: &'static str,
) -> anyhow::Error {
    if error.downcast_ref::<LifecycleError>().is_some() || admin::error_code(&error).is_some() {
        error
    } else {
        LifecycleError { code, message }.into()
    }
}

pub fn credential_input(path: Option<&Path>, stdin: bool) -> Result<Vec<u8>> {
    credential_input_inner(path, stdin).map_err(|error| safe_lifecycle_error(error,
        "credential_input_unavailable", "Cannot read a bounded private credential. Use a private file, stdin or a controlling terminal; never put a key in arguments."))
}

fn credential_input_inner(path: Option<&Path>, stdin: bool) -> Result<Vec<u8>> {
    if let Some(path) = path {
        let bytes = admin::read_optional(path, true)?.context("credential file is missing")?;
        ensure!(bytes.len() <= 4096, "credential exceeds 4096 bytes");
        return Ok(bytes);
    }
    if !stdin {
        return prompt_credential();
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(4097)
        .read_to_end(&mut bytes)
        .context("cannot read credential from stdin")?;
    ensure!(bytes.len() <= 4096, "credential exceeds 4096 bytes");
    Ok(bytes)
}

#[cfg(unix)]
fn prompt_credential() -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    extern "C" fn interrupted(_: libc::c_int) {
        INTERRUPTED.store(true, Ordering::Relaxed);
    }
    struct Terminal {
        file: fs::File,
        original: libc::termios,
        signals: Vec<(libc::c_int, libc::sigaction)>,
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original);
            }
            for (signal, action) in &self.signals {
                unsafe {
                    libc::sigaction(*signal, action, std::ptr::null_mut());
                }
            }
            let _ = self.file.write_all(b"\n");
        }
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/tty")
        .context("hidden input requires a controlling terminal; use --key-stdin for automation")?;
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    ensure!(
        unsafe { libc::tcgetattr(file.as_raw_fd(), &mut original) } == 0,
        "cannot inspect terminal settings"
    );
    ensure!(
        file.as_raw_fd() >= 0 && (file.as_raw_fd() as usize) < libc::FD_SETSIZE,
        "credential terminal descriptor exceeds the portable select limit"
    );
    let mut terminal = Terminal {
        file,
        original,
        signals: Vec::new(),
    };
    INTERRUPTED.store(false, Ordering::Relaxed);
    for signal in [
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGTSTP,
    ] {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        let mut previous = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = interrupted as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }
        ensure!(
            unsafe { libc::sigaction(signal, &action, &mut previous) } == 0,
            "cannot protect hidden terminal input"
        );
        terminal.signals.push((signal, previous));
    }
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    ensure!(
        unsafe { libc::tcsetattr(terminal.file.as_raw_fd(), libc::TCSAFLUSH, &hidden) } == 0,
        "cannot disable credential echo"
    );
    terminal
        .file
        .write_all(b"Existing hosted API key (hidden): ")?;
    terminal.file.flush()?;
    let mut bytes = Vec::new();
    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Err(LifecycleError {
                code: "credential_input_interrupted",
                message: "Credential entry was interrupted; no credential was saved.",
            }
            .into());
        }
        // macOS can reject polling the /dev/tty alias even while its underlying
        // controlling terminal is connected. select supports this descriptor on
        // both supported Unix platforms and still bounds signal-flag latency.
        let mut readable = unsafe { std::mem::zeroed::<libc::fd_set>() };
        unsafe {
            libc::FD_ZERO(&mut readable);
            libc::FD_SET(terminal.file.as_raw_fd(), &mut readable);
        }
        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        let ready = unsafe {
            libc::select(
                terminal.file.as_raw_fd() + 1,
                &mut readable,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            anyhow::bail!("cannot read hidden credential");
        }
        let mut byte = [0];
        let count = match terminal.file.read(&mut byte) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error).context("cannot read hidden credential"),
        };
        ensure!(
            count != 0,
            "credential terminal disconnected or input ended"
        );
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        ensure!(bytes.len() <= 4096, "credential exceeds 4096 bytes");
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn prompt_credential() -> Result<Vec<u8>> {
    anyhow::bail!("hidden input requires Unix; use --key-stdin")
}

async fn verify(config: &Config, bytes: &[u8]) -> Result<()> {
    let protocol = Protocol::with_credential(config, bytes).map_err(|_| LifecycleError {
        code: "identity_verification_prerequisite",
        message: "Cannot prepare identity verification; inspect the network configuration and private credential input.",
    })?;
    let response = protocol
        .get(crate::endpoints::Endpoint::Identity, None)
        .await
        .map_err(|_| LifecycleError {
            code: "identity_verification_unavailable",
            message: "Identity verification is unavailable; no credential was changed.",
        })?;
    if !((200..300).contains(&response.status)
        && response.read_failure.is_none()
        && ["ok", "success"].iter().all(|field| {
            response
                .body
                .get(field)
                .is_none_or(|v| v.as_bool() == Some(true))
        })
        && response.body.get("address").and_then(Value::as_str)
            == Some(config.network.address.as_str())
        && response
            .body
            .get("chain_id")
            .is_none_or(|v| v.as_str() == Some(config.network.chain.as_str())))
    {
        return Err(LifecycleError {
            code: "credential_identity_unverified",
            message: "Credential did not verify the configured chain/account; no credential was changed.",
        }.into());
    }
    Ok(())
}

pub struct InitOptions<'a> {
    pub account: &'a str,
    pub network: crate::config::NetworkConfig,
    pub credential_file: Option<&'a Path>,
    pub state_dir: Option<&'a Path>,
    pub dry_run: bool,
}

/// Creates private configuration/guidance only; never registers or initializes a journal.
pub async fn init(path: &Path, options: InitOptions<'_>, bytes: &[u8]) -> Result<Value> {
    init_inner(path, options, bytes).await.map_err(|error| safe_lifecycle_error(error,
        "initialization_failed", "Initialization did not complete. Private files may already exist; inspect configuration before retrying."))
}

async fn init_inner(path: &Path, options: InitOptions<'_>, bytes: &[u8]) -> Result<Value> {
    let path = absolute(path)?;
    if !fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Err(LifecycleError {
            code: "configuration_exists",
            message: "Configuration exists or cannot be inspected; initialization never overwrites it.",
        }.into());
    }
    let parent = path.parent().context("configuration parent missing")?;
    let mut config = Config {
        network: options.network,
        ..Config::default()
    };
    config.network.address = options.account.into();
    config.network.credential_file = match options.credential_file {
        Some(file) => absolute(file)?,
        None => parent.join("credential"),
    };
    if let Some(state) = options.state_dir {
        config.state_dir = absolute(state)?;
    }
    let guidance = [
        (
            parent.join("answer/core-guidance.md"),
            include_str!("../examples/answer/core-guidance.md"),
        ),
        (
            parent.join("answer/user-guidance.md"),
            include_str!("../examples/answer/user-guidance.md"),
        ),
        (
            parent.join("judge/core-guidance.md"),
            include_str!("../examples/judge/core-guidance.md"),
        ),
        (
            parent.join("judge/user-guidance.md"),
            include_str!("../examples/judge/user-guidance.md"),
        ),
    ];
    config.solver.answer.core_guidance_file = Some(guidance[0].0.clone());
    config.solver.answer.guidance_file = Some(guidance[1].0.clone());
    config.solver.judge.core_guidance_file = Some(guidance[2].0.clone());
    config.solver.judge.guidance_file = Some(guidance[3].0.clone());
    ensure!(
        config.network.credential_file != path
            && !config
                .network
                .credential_file
                .starts_with(&config.state_dir)
            && guidance
                .iter()
                .all(|(target, _)| target != &config.network.credential_file
                    && !target.starts_with(&config.state_dir)),
        "configuration, guidance and credentials must be outside durable state and use distinct files"
    );
    for (target, contents) in &guidance {
        if let Some(existing) = admin::read_optional(target, true)? {
            ensure!(
                existing == contents.as_bytes(),
                "onboarding guidance already exists with different contents; existing files are never overwritten"
            );
        }
    }
    config.validate()?;
    ensure!(
        !admin_identity_initialized(&config)?,
        "existing account state requires its existing configuration; onboarding never replaces identity/history"
    );
    verify(&config, bytes).await?;
    if !options.dry_run {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(parent)
            .context("cannot create configuration directory")?;
        let _directory = admin::lock_config_directory(&path)?;
        let _credential_directory = _directory.additional(&config.network.credential_file)?;
        ensure!(
            admin::read_optional(&path, false)?.is_none(),
            "configuration already exists; it is never overwritten"
        );
        // Lock all guidance directories before publishing any file. Existing matching
        // templates can be reused after an interrupted init, but never overwritten.
        for directory in [parent.join("answer"), parent.join("judge")] {
            builder
                .create(directory)
                .context("cannot create private guidance directory")?;
        }
        let credential_parent = fs::canonicalize(
            config
                .network
                .credential_file
                .parent()
                .context("credential parent missing")?,
        )?;
        let mut guidance_guards = [None, None];
        for (guard, (target, _)) in guidance_guards.iter_mut().zip([&guidance[0], &guidance[2]]) {
            if fs::canonicalize(target.parent().context("guidance parent missing")?)?
                != credential_parent
            {
                *guard = _directory.additional(target)?;
            }
        }
        let _admission = AdmissionGuard::acquire(&config)?;
        ensure!(
            !admin_identity_initialized(&config)?,
            "account became initialized; keep its existing configuration"
        );
        for (target, contents) in &guidance {
            if let Some(existing) = admin::read_optional(target, true)? {
                ensure!(
                    existing == contents.as_bytes(),
                    "onboarding guidance changed; existing files are never overwritten"
                );
            }
        }
        let existing_credential = admin::read_optional(&config.network.credential_file, true)?;
        if options.credential_file.is_none() {
            ensure!(
                existing_credential
                    .as_deref()
                    .is_none_or(|existing| existing == bytes),
                "managed credential differs from verified input; existing credentials are never overwritten"
            );
        } else {
            ensure!(
                existing_credential.as_deref() == Some(bytes),
                "credential changed during verification; retry"
            );
        }
        for (target, contents) in &guidance {
            if admin::read_optional(target, true)?.is_none() {
                admin::persist(target, contents.as_bytes())?;
            }
        }
        if options.credential_file.is_none() && existing_credential.is_none() {
            admin::persist(&config.network.credential_file, bytes)?;
        }
        admin::persist(&path, toml::to_string_pretty(&config)?.as_bytes())?;
    }
    Ok(
        json!({"path":path,"dry_run":options.dry_run,"identity_verified":true,"paused":true,
        "journal_initialized":false,"credential_referenced":options.credential_file.is_some(),
        "ready_for_participation":false,"capabilities":config.capabilities,"service_state":"not_inspected",
        "note":"No account was registered. Configuration alone does not initialize the journal, configure native model authentication, start a controller or authorize participation."}),
    )
}

pub async fn rotate(path: &Path, bytes: &[u8], dry_run: bool) -> Result<Value> {
    rotate_inner(path, bytes, dry_run).await.map_err(|error| safe_lifecycle_error(error,
        "credential_rotation_failed", "Credential rotation did not complete. Inspect current configuration and credential state before retrying; keep the controller stopped."))
}

async fn rotate_inner(path: &Path, bytes: &[u8], dry_run: bool) -> Result<Value> {
    // Runtime reload never takes the directory lock. Admission blocks dispatch;
    // stopped() fails fast if a writer still holds its permanent inode.
    let _directory = admin::lock_config_directory(path)?;
    let config = Config::load_metadata(path)?;
    ensure!(
        !config.network.credential_file.as_os_str().is_empty(),
        "configuration has no credential reference"
    );
    let _credential_directory = _directory.additional(&config.network.credential_file)?;
    let _admission = AccountLock::rotation_admission(&config)?;
    let _writer = AccountLock::stopped(&config).map_err(|error| {
        if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
        {
            LifecycleError {
                code: "credential_rotation_requires_stop",
                message: "Stop the controller before rotating this credential; no replacement was saved.",
            }.into()
        } else { error }
    })?;
    let store = Store::read_only(&config)?
        .context("initialize and pause the account before credential rotation")?;
    if !store.control()?.paused {
        return Err(LifecycleError {
            code: "credential_rotation_requires_pause",
            message: "Pause participation before rotating this credential; no replacement was saved.",
        }.into());
    }
    let old = admin::read_optional(&config.network.credential_file, true)?
        .context("existing credential is missing")?;
    // Reject paths that could overwrite configuration or durable state.
    let target = fs::canonicalize(&config.network.credential_file)
        .context("cannot resolve credential target")?;
    let config_target = fs::canonicalize(path).context("cannot resolve configuration target")?;
    let state = fs::canonicalize(&config.state_dir).context("cannot resolve state directory")?;
    ensure!(
        target != config_target && !target.starts_with(state),
        "credential target overlaps configuration or durable state"
    );
    for model in [&config.solver.answer, &config.solver.judge] {
        for guidance in [&model.guidance_file, &model.core_guidance_file]
            .into_iter()
            .flatten()
        {
            ensure!(
                fs::canonicalize(guidance).ok().as_ref() != Some(&target),
                "credential target overlaps model guidance"
            );
        }
    }
    verify(&config, bytes).await?;
    ensure!(
        admin::read_optional(&target, true)?.as_deref() == Some(old.as_slice()),
        "credential changed during verification; retry with the current file"
    );
    if !dry_run {
        admin::persist(&target, bytes)?;
    }
    Ok(
        json!({"dry_run":dry_run,"identity_verified":true,"paused":true,"state_preserved":true,
        "note":"Only the local credential is replaced. Start the service and explicitly resume; remote key issuance/revocation is outside this command."}),
    )
}

struct InstallerDirectory(PathBuf);
impl Drop for InstallerDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary_digest(mut file: fs::File) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .context("cannot hash local executable")?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Safe, bounded evidence from the canonical installer, never child output text.
#[derive(Debug)]
pub struct InstallerError {
    pub evidence: Value,
}
impl std::fmt::Display for InstallerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("installer did not complete; inspect installation before retrying")
    }
}
impl std::error::Error for InstallerError {}

fn installer_evidence(value: Option<&Value>) -> Value {
    let mut result = json!({"stage":"unknown","staging":"unknown","activation":"unknown","service":"unknown",
        "evidence":"this_invocation_only","installation_state":"not_inspected"});
    for (key, allowed) in [
        (
            "stage",
            &[
                "preflight",
                "staging",
                "activation_preflight",
                "stopping",
                "switching",
                "reloading",
                "starting",
                "service",
                "status",
                "complete",
            ][..],
        ),
        (
            "staging",
            &[
                "not_started",
                "in_progress",
                "published",
                "complete",
                "unknown",
            ][..],
        ),
        (
            "activation",
            &[
                "not_started",
                "in_progress",
                "selected",
                "loaded_verified",
                "unknown",
            ][..],
        ),
        (
            "service",
            &[
                "unknown",
                "stopped",
                "command_completed",
                "previous_intent_restored",
            ][..],
        ),
    ] {
        if let Some(text) = value
            .and_then(|value| value[key].as_str())
            .filter(|text| allowed.contains(text))
        {
            result[key] = json!(text);
        }
    }
    result
}

/// Let a verified incoming release supply its own embedded installer and units.
/// The child sees its own digest, so delegation ends after exactly one hop.
fn incoming_installer(binary: &Path, action: &str, digest: &str, stopped: bool) -> Result<Value> {
    let mut command = Command::new(binary);
    command
        .args(["--json", action, "--binary"])
        .arg(binary)
        .args(["--sha256", digest]);
    if stopped {
        command.arg("--stopped");
    }
    let result = command
        .stdin(Stdio::null())
        .output()
        .map_err(|_| InstallerError {
            evidence: installer_evidence(None),
        })?;
    if !result.status.success() {
        let evidence = result
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
        serde_json::from_slice(&result.stdout).map_err(|_| InstallerError {
            evidence: installer_evidence(None),
        })?;
    if !(envelope["schema"] == "agmi.cli.v1"
        && envelope["ok"] == true
        && envelope["type"] == action
        && envelope.get("data").is_some())
    {
        return Err(InstallerError {
            evidence: installer_evidence(None),
        }
        .into());
    }
    Ok(envelope["data"].take())
}

/// The embedded script is the canonical installer, not a second cutover implementation.
pub fn installer(arguments: &[String], dry_run: bool) -> Result<Value> {
    installer_inner(arguments, dry_run).map_err(|error| {
        if error.downcast_ref::<InstallerError>().is_some() {
            error
        } else {
            InstallerError {
                evidence: json!({"stage":"preflight","staging":"not_started",
            "activation":"not_started","service":"unknown","evidence":"this_invocation_only",
            "installation_state":"not_inspected"}),
            }
            .into()
        }
    })
}

fn installer_inner(arguments: &[String], dry_run: bool) -> Result<Value> {
    let mut plan = json!({"arguments":arguments,"dry_run":dry_run,"network_downloads":false,
        "trust":"Local operator-trusted binary and expected SHA256 only; hashes/build labels are not signed publisher or source provenance.",
        "pause_state":"unchanged","journal":"never copied, restored or migrated by installer","preview":"plan only; operational preconditions are checked on execution",
        "stage":"preflight","staging":"not_started","activation":"not_started","service":"unknown"});
    if dry_run {
        plan["installation"] = installer_evidence(Some(&plan));
        return Ok(plan);
    }
    ensure!(
        cfg!(target_os = "linux"),
        "service installation requires Linux user-systemd"
    );
    let root = std::env::temp_dir();
    let directory = (0..1000)
        .find_map(|n| {
            let path = root.join(format!("agmi-installer-{}-{n}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => Some(Ok(InstallerDirectory(path))),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(_) => Some(Err(anyhow::anyhow!(
                    "cannot prepare private installer directory"
                ))),
            }
        })
        .context("cannot allocate private installer directory")??;
    let mut canonical_arguments = std::borrow::Cow::Borrowed(arguments);
    if arguments
        .first()
        .is_some_and(|action| matches!(action.as_str(), "install" | "update"))
    {
        let action = &arguments[0];
        let source = Path::new(
            arguments
                .get(1)
                .context("local release binary is required")?,
        );
        ensure!(
            arguments.get(2).map(String::as_str) == Some("--sha256"),
            "expected trusted SHA256 argument is missing"
        );
        let expected = arguments
            .get(3)
            .context("expected trusted SHA256 digest is missing")?;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let mut source = options
            .open(source)
            .context("cannot open local release binary")?;
        let metadata = source
            .metadata()
            .context("cannot inspect local release binary")?;
        ensure!(
            metadata.is_file(),
            "local release binary must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "local release binary is not executable"
            );
        }
        let candidate = directory.0.join("incoming-agmi");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut copied = options
            .open(&candidate)
            .context("cannot stage private incoming executable")?;
        std::io::copy(&mut source, &mut copied).context("cannot copy incoming executable")?;
        copied
            .sync_all()
            .context("cannot sync incoming executable")?;
        drop(copied); // Close the writable descriptor before exec (ETXTBSY).
        let actual = binary_digest(
            fs::File::open(&candidate).context("cannot inspect copied incoming executable")?,
        )?;
        ensure!(
            &actual == expected,
            "incoming executable does not match the operator-supplied trusted SHA256; nothing was executed"
        );
        // Linux /proc pins the running image even if its installation path changed.
        let running = binary_digest(
            fs::File::open("/proc/self/exe")
                .context("cannot inspect running executable identity")?,
        )?;
        if actual != running {
            return incoming_installer(
                &candidate,
                action,
                expected,
                arguments.iter().any(|argument| argument == "--stopped"),
            );
        }
        canonical_arguments.to_mut()[1] = candidate.to_string_lossy().into_owned();
    }
    for (name, contents) in [
        ("install-user.sh", include_str!("../deploy/install-user.sh")),
        ("agmi.service", include_str!("../deploy/agmi.service")),
        (
            "agmi-health.service",
            include_str!("../deploy/agmi-health.service"),
        ),
        (
            "agmi-health.timer",
            include_str!("../deploy/agmi-health.timer"),
        ),
    ] {
        fs::write(directory.0.join(name), contents).context("cannot prepare installer artifact")?;
    }
    // Capture child streams: neither raw systemd output nor subprocess errors are
    // part of the machine error contract. The script remains the only cutover owner.
    let result = Command::new("sh")
        .arg(directory.0.join("install-user.sh"))
        .args(canonical_arguments.as_ref())
        .stdin(Stdio::null())
        .output()
        .map_err(|_| InstallerError {
            evidence: installer_evidence(None),
        })?;
    let marker = result
        .stdout
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .rfind(|value| value["schema"] == "agmi.installer.v1");
    let evidence = installer_evidence(marker.as_ref());
    if !result.status.success() {
        return Err(InstallerError { evidence }.into());
    }
    Ok(
        json!({"plan":plan,"installation":evidence,"output":String::from_utf8_lossy(&result.stdout)}),
    )
}
