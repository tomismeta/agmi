//! Explicit local lifecycle operations. Credentials never enter arguments or output.
//! Release checksums establish integrity, not publisher/source provenance.
use crate::{
    admin,
    config::Config,
    protocol::Protocol,
    store::{AccountAdmissionGuard, AccountLock, Store, admin_identity_initialized},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
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
    if error.downcast_ref::<LifecycleError>().is_some()
        || error
            .downcast_ref::<crate::config::ConfigDiagnostic>()
            .is_some()
        || admin::error_code(&error).is_some()
    {
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
        .get(
            crate::endpoints::Endpoint::Identity,
            None,
            crate::protocol::ReadDeadline::seconds(config.identity.read_http_seconds)?,
            crate::protocol::RequestMeta {
                request_id: format!(
                    "credential-verification-{}-{}",
                    std::process::id(),
                    protocol.credential_instance()
                ),
                // Administrative verification establishes no journal or dispatch permit.
                database_id: String::new(),
                authority_epoch: 0,
                owner: None,
                operation_id: None,
                read_key: None,
                binding_revision: None,
                dispatch_sequence: None,
            },
        )
        .await
        .map_err(|_| LifecycleError {
            code: "identity_verification_unavailable",
            message: "Identity verification is unavailable; no credential was changed.",
        })?
        .response;
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
    config.capabilities.answer.model.core_guidance_file = Some(guidance[0].0.clone());
    config.capabilities.answer.model.guidance_file = Some(guidance[1].0.clone());
    config.capabilities.judge.model.core_guidance_file = Some(guidance[2].0.clone());
    config.capabilities.judge.model.guidance_file = Some(guidance[3].0.clone());
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
    config.validate().context(LifecycleError {
        code: "initialization_invalid",
        message: "Initialization inputs are invalid; no identity verification was requested and no onboarding files were written.",
    })?;
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
        let _admission = AccountAdmissionGuard::for_provisioning(&config)?;
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
    crate::store::migration::ensure_no_pending(&config)?;
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
    for model in [
        &config.capabilities.answer.model,
        &config.capabilities.judge.model,
    ] {
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

#[cfg(unix)]
pub(crate) mod update_state;

/// Owns the managed installation lease until the operator mutation completes.
pub struct ManagedMutationGuard {
    #[cfg(unix)]
    _lease: update_state::Lease,
}

pub fn guard_managed_mutation(config_path: &Path) -> Result<Option<ManagedMutationGuard>> {
    #[cfg(unix)]
    {
        let Some(root) = crate::installer::managed_root(config_path)? else {
            return Ok(None);
        };
        crate::installer::pending_update_target(config_path)?;
        let lease = update_state::Lease::acquire(&root)?;
        if !lease.inherited
            && let Some(mut record) = update_state::read(&root)?
        {
            record.cancelled = true;
            update_state::save(&root, &record)?;
        }
        Ok(Some(ManagedMutationGuard { _lease: lease }))
    }
    #[cfg(not(unix))]
    {
        let _ = config_path;
        Ok(None)
    }
}

/// The runtime never owns the updater lease: its parent waits for startup evidence.
pub fn guard_managed_run(config_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        crate::installer::guard_managed_run(config_path)?;
    }
    #[cfg(not(unix))]
    let _ = config_path;
    Ok(())
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

pub(crate) fn installer_preflight_error(code: &'static str) -> anyhow::Error {
    InstallerError {
        evidence: installer_evidence(Some(&json!({
            "stage":"preflight","staging":"not_started","activation":"not_started",
            "service":"unknown","failure_code":code
        }))),
    }
    .into()
}

pub(crate) fn installer_evidence(value: Option<&Value>) -> Value {
    let mut result = json!({"stage":"unknown","staging":"unknown","activation":"unknown","service":"unknown",
        "failure_code":"unknown","evidence":"this_invocation_only","installation_state":"not_inspected",
        "bootstrap_recovery":null,"operation_mode":"unknown"});
    for (key, allowed) in [
        (
            "operation_mode",
            &["unknown", "standard", "maintenance"][..],
        ),
        (
            "failure_code",
            &[
                "unknown",
                "none",
                "interrupted",
                "unsupported_platform",
                "invalid_arguments",
                "missing_prerequisite",
                "candidate_unavailable",
                "candidate_execution_unavailable",
                "digest_mismatch",
                "installer_busy",
                "update_in_progress",
                "legacy_install_lock",
                "decision_required",
                "recovery_required",
                "restoration_incomplete",
                "preparation_failed",
                "release_invalid",
                "configuration_invalid",
                "journal_incompatible",
                "manager_context_mismatch",
                "service_state_unavailable",
                "insufficient_space",
                "unit_invalid",
                "stop_failed",
                "bootstrap_recovery_failed",
                "switch_failed",
                "reload_failed",
                "start_failed",
                "service_failed",
                "migration_required",
                "migration_pending",
                "migration_conflict",
                "migration_failed",
                "migration_pause_failed",
            ][..],
        ),
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
                "migration",
                "restoring",
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
                "unchanged",
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
    if let Some(recovery) = value.and_then(|value| value.get("bootstrap_recovery"))
        && let (Some(disable), Some(definitions), Some(reload)) = (
            recovery["disable_command_succeeded"].as_bool(),
            recovery["definitions_restored"].as_bool(),
            recovery["manager_reload_succeeded"].as_bool(),
        )
    {
        result["bootstrap_recovery"] = json!({
            "disable_command_succeeded": disable,
            "definitions_restored": definitions,
            "manager_reload_succeeded": reload
        });
    }
    if let Some(compatibility) = value.and_then(|value| value.get("compatibility"))
        && let Some(classification) = compatibility["classification"].as_str().filter(|value| {
            matches!(
                *value,
                "compatible" | "marker_only" | "conversion" | "pending" | "not_assessed"
            )
        })
    {
        result["compatibility"] = json!({
            "classification":classification,
            "migration_required":compatibility["migration_required"].as_bool(),
            "target_journal_format":compatibility["target_journal_format"].as_i64()
                .filter(|format| (1..=i64::from(u32::MAX)).contains(format))
        });
    }
    if let Some(migration) = value.and_then(|value| value.get("migration"))
        && let Some(phase) = migration["phase"].as_str().filter(|value| {
            matches!(
                *value,
                "not_required"
                    | "required"
                    | "prepared"
                    | "complete"
                    | "journal_ready"
                    | "recovery_required"
                    | "decision_required"
                    | "failed"
                    | "unknown"
            )
        })
    {
        let mut bounded = json!({"phase":phase,"participation_resumed":migration["participation_resumed"].as_bool()});
        for key in ["release_id", "token"] {
            if let Some(text) = migration[key].as_str()
                && match key {
                    "release_id" => text.strip_prefix("r-"),
                    _ => text.strip_prefix("agmi.atomic-migration.v1:"),
                }
                .is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            {
                bounded[key] = json!(text);
            }
        }
        if let Some(reason) = migration["decision_reason"].as_str().filter(|reason| {
            matches!(
                *reason,
                "lane_limits_required" | "authority_adoption_required" | "risk_review_required"
            )
        }) {
            bounded["decision_reason"] = json!(reason);
        }
        for key in [
            "approval_required",
            "risk_change_required",
            "recovery_supported",
            "further_migration_required",
            "paused",
            "pending",
        ] {
            if let Some(value) = migration[key].as_bool() {
                bounded[key] = json!(value);
            }
        }
        if migration["recovery_prerequisite"] == "authority_adoption" {
            bounded["recovery_prerequisite"] = json!("authority_adoption");
        } else if migration
            .get("recovery_prerequisite")
            .is_some_and(Value::is_null)
        {
            bounded["recovery_prerequisite"] = Value::Null;
        }
        for key in ["target_journal_format", "generation"] {
            if let Some(value) = migration[key].as_i64().filter(|value| {
                if key == "target_journal_format" {
                    (1..=i64::from(u32::MAX)).contains(value)
                } else {
                    *value >= 0
                }
            }) {
                bounded[key] = json!(value);
            }
        }
        result["migration"] = bounded;
    }
    if let Some(restoration) = value.and_then(|v| v.get("restoration")) {
        let mut bounded = json!({"status":"pending","runtime":"unknown","timer":"unknown","pause_state":"unknown","verified":false});
        for (key, allowed) in [
            (
                "status",
                &["not_needed", "restored", "pending", "cancelled", "failed"][..],
            ),
            ("runtime", &["running", "stopped", "unknown"][..]),
            ("timer", &["active", "stopped", "unknown"][..]),
            (
                "pause_state",
                &["paused", "unpaused", "absent", "unknown"][..],
            ),
        ] {
            if let Some(text) = restoration[key]
                .as_str()
                .filter(|text| allowed.contains(text))
            {
                bounded[key] = json!(text);
            }
        }
        bounded["verified"] = json!(restoration["verified"].as_bool().unwrap_or(false));
        result["restoration"] = bounded;
    }
    result
}

/// Execute the incoming-release-owned native Rust installer.
pub fn installer(arguments: &[String], dry_run: bool) -> Result<Value> {
    crate::installer::run(arguments, dry_run).map_err(|error| {
        if error.downcast_ref::<InstallerError>().is_some() {
            error
        } else {
            installer_preflight_error("preparation_failed")
        }
    })
}

/// Sanitized lifecycle evidence survives both a failed repair and a failed
/// restoration. The original callback error remains downcastable through the
/// anyhow context; `report` retains completed repair evidence on restore failure.
#[derive(Debug)]
pub(crate) struct RepairRuntimeError {
    pub(crate) code: &'static str,
    pub(crate) restoration: Value,
    pub(crate) report: Option<Value>,
}
impl std::fmt::Display for RepairRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("doctor repair did not complete; inspect runtime restoration evidence")
    }
}
impl std::error::Error for RepairRuntimeError {}

/// Stop only a validated canonical user-systemd runtime, run the locked repair,
/// then restore and verify its previous intent. No pause state or timer
/// enablement is changed. Other configurations remain caller-managed: the
/// callback must acquire the account/config/admission locks before mutating.
///
/// Result errors and handled HUP/INT/TERM restore intent before returning.
/// A hard kill, process abort, or host failure cannot guarantee restoration.
pub(crate) fn with_repair_runtime(
    config_path: &Path,
    repair: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    crate::installer::with_repair_runtime(config_path, repair)
}

#[cfg(test)]
mod repair_tests {
    use super::*;

    #[test]
    fn caller_managed_repair_retains_report_and_typed_failure() -> Result<()> {
        let config = std::env::temp_dir().join("agmi-caller-managed-repair/config.toml");
        let report = with_repair_runtime(&config, || {
            Ok(json!({"repairs":{"applied":2},"sentinel":"preserved"}))
        })?;
        assert_eq!(report["sentinel"], "preserved");
        assert_eq!(report["repairs"]["applied"], 2);
        assert_eq!(report["repairs"]["restoration"]["manager_action"], "none");
        assert_eq!(
            report["repairs"]["restoration"]["runtime"],
            "caller_managed"
        );

        let error = with_repair_runtime(&config, || {
            Err(LifecycleError {
                code: "repair_refused",
                message: "sanitized refusal",
            }
            .into())
        })
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<LifecycleError>().unwrap().code,
            "repair_refused"
        );
        let evidence = error.downcast_ref::<RepairRuntimeError>().unwrap();
        assert_eq!(evidence.code, "repair_action_failed");
        assert_eq!(evidence.restoration["manager_action"], "none");
        assert!(evidence.report.is_none());

        let error = with_repair_runtime(&config, || Ok(json!({"not_a_report":true}))).unwrap_err();
        assert_eq!(
            error.downcast_ref::<RepairRuntimeError>().unwrap().code,
            "repair_report_invalid"
        );
        Ok(())
    }
}
