use crate::config::{
    Config, HistoricalAnswerCapacity, Mode, Participation, ParticipationMode, WorkKind,
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct RoutingProfileError;
impl std::fmt::Display for RoutingProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("API routing differs while unresolved or reusable work remains; restore the prior network.api profile before continuing")
    }
}
impl std::error::Error for RoutingProfileError {}

#[derive(Debug)]
pub struct RefusalRecoveryError(pub &'static str);
impl std::fmt::Display for RefusalRecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for RefusalRecoveryError {}

/// Local-only extension of recover resolve. A preview never opens a writer;
/// application requires its exact snapshot token and excludes a live controller.
pub fn recovery_refusal(config_path: &Path, operation: i64, apply: Option<&str>) -> Result<Value> {
    let _configuration = crate::admin::lock_config_directory(config_path)?;
    let config = Config::load_metadata(config_path)?;
    let store = Store::read_only(&config)?.context("journal not initialized")?;
    if store.schema_version()? != 2 {
        return Err(RefusalRecoveryError("refusal_recovery_schema").into());
    }
    store.routing_change_allowed(&config)?;
    // Bind approval to file bytes, including metadata-only configuration changes.
    let revision = digest(fs::read(config_path)?);
    if let Some(token) = apply {
        drop(store);
        let (_account, mut store) = AccountLock::acquire(&config)?;
        let _gate = AdmissionGuard::acquire(&config)?;
        store.resolve_refusal(operation, &revision, token)
    } else {
        let snapshot = store.db.unchecked_transaction()?;
        let (preview, _) = Store::refusal_preview(&snapshot, operation, &revision)?;
        snapshot.commit()?;
        Ok(preview)
    }
}

/// Local doctor repairs share the stopped-writer guards. Identity normalization
/// also requires the original preview, so new observations cannot be overwritten.
pub(crate) fn doctor_repairs(config_path: &Path, apply: Option<&Value>) -> Result<Value> {
    let _configuration = crate::admin::lock_config_directory(config_path)?;
    let config = Config::load_metadata(config_path)?;
    let revision = digest(fs::read(config_path)?);
    if apply.is_some_and(|expected| expected["config_revision"].as_str() != Some(revision.as_str()))
    {
        return Err(RefusalRecoveryError("refusal_recovery_conflict").into());
    }
    let mut report = json!({"config_revision":revision,"eligible":[],"ineligible":[],
        "applied":[],"skipped":[],"failure":null,
        "restoration":{"manager_action":"none","runtime":"unchanged"}});
    let Some(store) = Store::read_only(&config)? else {
        return Ok(report);
    };
    if store.schema_version()? != 2 {
        return Err(RefusalRecoveryError("refusal_recovery_schema").into());
    }
    store.routing_change_allowed(&config)?;
    if apply.is_none() {
        let snapshot = store.db.unchecked_transaction()?;
        let (mut eligible, ineligible) = Store::refusal_candidates(&snapshot, &revision)?;
        let (identity, _) = Store::identity_normalization_preview(&snapshot, &revision)?;
        if identity["eligible"] == true {
            eligible.push(identity);
        }
        report["eligible"] = json!(eligible);
        report["ineligible"] = json!(ineligible);
        snapshot.commit()?;
        return Ok(report);
    }
    // Writer acquisition may bind a new routing profile. That must not reset
    // observations as a side effect of local identity normalization.
    if apply
        .and_then(|preview| preview["eligible"].as_array())
        .is_some_and(|rows| rows.iter().any(|row| row["kind"] == "identity"))
        && store.routing_status(&config)?["matches_config"] != true
    {
        return Err(RefusalRecoveryError("identity_evidence_changed").into());
    }
    drop(store);
    let (_account, mut store) = AccountLock::acquire(&config)
        .map_err(|error| error.context(RefusalRecoveryError("doctor_account_unavailable")))?;
    let _gate = AdmissionGuard::acquire(&config)?;
    let (mut eligible, ineligible) = Store::refusal_candidates(&store.db, &revision)?;
    if let Some(identity) = apply
        .and_then(|preview| preview["eligible"].as_array())
        .and_then(|rows| {
            rows.iter().find(|row| {
                row["kind"] == "identity"
                    && row["classification"] == "legacy_identity_evidence_normalization"
            })
        })
    {
        eligible.push(identity.clone());
    }
    report["ineligible"] = json!(ineligible);
    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    for preview in &eligible {
        if preview["kind"] == "identity" {
            let mut skipped_row = preview.clone();
            if !report["failure"].is_null() {
                skipped_row["reason"] = json!("earlier_repair_failed");
                skipped.push(skipped_row);
                continue;
            }
            let token = preview["preview_token"]
                .as_str()
                .context("missing identity token")?;
            match store.normalize_legacy_identity(&revision, token) {
                Ok(result) if result["applied"] == true => applied.push(result),
                Ok(result) => skipped.push(result),
                Err(error) => {
                    let code = error
                        .downcast_ref::<RefusalRecoveryError>()
                        .map_or("identity_normalization_failed", |error| error.0);
                    if code != "identity_evidence_changed" {
                        report["failure"] = json!(code);
                    }
                    skipped_row["eligible"] = json!(false);
                    skipped_row["reason"] = json!(code);
                    skipped.push(skipped_row);
                }
            }
            continue;
        }
        let id = preview["operation_id"]
            .as_i64()
            .context("invalid refusal operation")?;
        if !report["failure"].is_null() {
            skipped.push(json!({"operation_id":id,"reason":"earlier_repair_failed"}));
            continue;
        }
        let token = preview["preview_token"]
            .as_str()
            .context("missing refusal token")?;
        match store.resolve_refusal(id, &revision, token) {
            Ok(result) => applied.push(result),
            Err(error) => {
                let code = error
                    .downcast_ref::<RefusalRecoveryError>()
                    .map_or("refusal_recovery_failed", |error| error.0);
                report["failure"] = json!(code);
                skipped.push(json!({"operation_id":id,"reason":code}));
            }
        }
    }
    report["eligible"] = json!(eligible);
    report["applied"] = json!(applied);
    report["skipped"] = json!(skipped);
    Ok(report)
}

// SQLite may see a new inode only after its raw creation descriptor is closed.
static DATABASE_OPEN: Mutex<()> = Mutex::new(());

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Durable observations are diagnostics, never a submission permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostedIdentityOutcome {
    Verified,
    Unavailable,
    AuthenticationFailed,
    IdentityMismatch,
    InvalidResponse,
}

impl HostedIdentityOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unavailable => "unavailable",
            Self::AuthenticationFailed => "authentication_failed",
            Self::IdentityMismatch => "identity_mismatch",
            Self::InvalidResponse => "invalid_response",
        }
    }

    fn rejection(self) -> Option<&'static str> {
        match self {
            Self::AuthenticationFailed | Self::IdentityMismatch => Some(self.as_str()),
            _ => None,
        }
    }
}
/// Persisted second-resolution deadlines must never expire a fractional second
/// before Retry-After. Rounding upward is conservative across process restarts.
pub(crate) fn not_before(seconds: u64) -> i64 {
    now()
        .saturating_add(seconds.min(i64::MAX as u64) as i64)
        .saturating_add(1)
}

pub(crate) fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .context("cannot create private state directory")?;
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("state and lock directories must be real directories");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            bail!("state and lock directories must be owned by this user and private (0700)");
        }
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<File> {
    private_dir(path.parent().context("private file parent missing")?)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .context("cannot open private state or lock file")?;
    validate_private_file(&file.metadata()?)?;
    Ok(file)
}

fn validate_private_file(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        bail!("state and lock files must be regular files");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!("state and lock files must be private, owned by this user, and not hardlinked");
        }
    }
    Ok(())
}

fn prepare_database(path: &Path) -> Result<()> {
    // Closing any extra descriptor for an existing SQLite inode releases that
    // process's POSIX locks. Only create a new file; inspect existing files by stat.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match options.open(path) {
        Ok(file) => validate_private_file(&file.metadata()?)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_private_file(&fs::symlink_metadata(path)?)?;
        }
        Err(error) => return Err(error).context("cannot create private database"),
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn account_home() -> Result<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 65536];
    let error = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if error != 0 || result.is_null() {
        bail!("cannot resolve canonical OS account home");
    }
    let record = unsafe { record.assume_init() };
    if record.pw_dir.is_null() {
        bail!("OS account has no home directory");
    }
    let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    if !home.is_absolute() {
        bail!("OS account home must be absolute");
    }
    Ok(home)
}

/// Deliberately independent of state_dir, endpoint, XDG paths and working directory.
/// One OS user cannot run two writers for an account by selecting another database.
fn lock_path(config: &Config, suffix: &str) -> Result<PathBuf> {
    #[cfg(unix)]
    let root = account_home()?.join(".agmi-account-locks");
    #[cfg(not(unix))]
    let root = dirs::home_dir()
        .context("home directory unavailable")?
        .join(".agmi-account-locks");
    let key = digest(format!(
        "{}\n{}",
        config.network.chain, config.network.address
    ));
    Ok(root.join(format!("{key}.{suffix}")))
}

pub(crate) struct AccountLock(File);
const WRITER_MARKER: &[u8] = b"agmi-authority-v2\n";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Binding {
    location: String,
    identity: String,
    database_id: String,
    dispatch_sequence: i64,
}

fn read_binding(config: &Config) -> Result<Option<Binding>> {
    let path = lock_path(config, "binding")?;
    if !path.exists() {
        let writer = lock_path(config, "writer")?;
        if writer.exists() {
            let metadata = fs::symlink_metadata(&writer)?;
            validate_private_file(&metadata)?;
            if metadata.len() > 64 {
                bail!("invalid stable writer marker");
            }
            if fs::read(&writer)? == WRITER_MARKER {
                bail!("independent account binding is missing; authoritative recovery required");
            }
        }
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(&path)?;
    validate_private_file(&metadata)?;
    if metadata.len() > 4096 {
        bail!("invalid account binding");
    }
    let bytes = fs::read(path)?;
    if bytes.len() > 4096 {
        bail!("invalid account binding");
    }
    Ok(Some(
        serde_json::from_slice(&bytes).context("invalid account binding")?,
    ))
}

pub(crate) fn validate_page(before: Option<i64>, limit: usize) -> Result<()> {
    if !(1..=1000).contains(&limit) || before.is_some_and(|id| id <= 0) {
        bail!("pagination requires limit 1..1000 and a positive before ID");
    }
    Ok(())
}

/// Metadata-only initialization probe for CLI configuration updates.
pub(crate) fn admin_identity_initialized(config: &Config) -> Result<bool> {
    for path in [
        config.state_dir.join("state.sqlite3"),
        lock_path(config, "binding")?,
        lock_path(config, "writer")?,
    ] {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => validate_private_file(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("cannot inspect configuration identity anchors"),
        }
    }
    let writer = lock_path(config, "writer")?;
    if let Ok(metadata) = fs::symlink_metadata(&writer) {
        if metadata.len() > 64 {
            bail!("invalid stable writer marker");
        }
        let marker = fs::read(writer)?;
        if !marker.is_empty() && marker != WRITER_MARKER {
            bail!("invalid stable writer marker");
        }
    }
    Ok(Store::read_only(config)?.is_some())
}

fn write_binding(path: &Path, binding: &Binding) -> Result<()> {
    let temporary = path.with_extension("binding-next");
    let mut file = private_file(&temporary)?;
    file.set_len(0)?;
    file.write_all(&serde_json::to_vec(binding)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(path.parent().context("binding parent missing")?)?.sync_all()?;
    Ok(())
}

impl AccountLock {
    fn rotation_lock_file(config: &Config, suffix: &str) -> Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = options
            .open(lock_path(config, suffix)?)
            .context("initialize and pause the account before credential rotation")?;
        validate_private_file(&file.metadata()?)?;
        Ok(file)
    }

    /// Existing gate only: even previews must not create lock/state artifacts.
    pub(crate) fn rotation_admission(config: &Config) -> Result<AdmissionGuard> {
        let file = Self::rotation_lock_file(config, "admission")?;
        file.lock()
            .context("cannot acquire credential rotation admission gate")?;
        Ok(AdmissionGuard(file))
    }

    /// Caller must hold admission first. Never opens or changes a journal/binding.
    pub(crate) fn stopped(config: &Config) -> Result<Self> {
        let file = Self::rotation_lock_file(config, "writer")?;
        file.try_lock()
            .map_err(std::io::Error::from)
            .context("stop the runtime before credential rotation")?;
        Ok(Self(file))
    }

    pub(crate) fn acquire(config: &Config) -> Result<(Self, Store)> {
        Self::acquire_with_migration(config, false)
    }

    pub(crate) fn adopt(config: &Config) -> Result<(Self, Store)> {
        Self::acquire_with_migration(config, true)
    }

    fn acquire_with_migration(config: &Config, migration_allowed: bool) -> Result<(Self, Store)> {
        let _gate = AdmissionGuard::acquire(config)?;
        let mut file = private_file(&lock_path(config, "writer")?)?;
        file.try_lock()
            .map_err(std::io::Error::from)
            .context("another runtime already owns this account")?;
        let store = Self::open_bound_store(&mut file, config, migration_allowed)?;
        Ok((Self(file), store))
    }

    fn open_bound_store(
        file: &mut File,
        config: &Config,
        migration_allowed: bool,
    ) -> Result<Store> {
        if config.network.address.is_empty()
            || config.network.credential_file.as_os_str().is_empty()
        {
            bail!("durable control requires a configured account and credential file");
        }
        let length = file.metadata()?.len();
        if length > 64 {
            bail!("invalid stable writer marker");
        }
        let mut bytes = vec![0; length as usize];
        file.read_exact(&mut bytes)?;
        let marked = bytes == WRITER_MARKER;
        let legacy = length != 0 && !marked;
        if legacy && !migration_allowed {
            bail!("journal adoption requires an explicit stopped-writer recover adopt");
        }
        if legacy
            && (length != 64
                || bytes != digest(config.state_dir.as_os_str().as_encoded_bytes()).as_bytes())
        {
            bail!("account is bound to a different durable state directory");
        }
        let binding = read_binding(config)?;
        let database = config.state_dir.join("state.sqlite3");
        if migration_allowed && !database.exists() {
            bail!("adoption requires an existing initialized journal");
        }
        if legacy || binding.is_some() || database.exists() {
            if !migration_allowed && !legacy && binding.is_none() {
                bail!("unanchored journal requires explicit stopped-writer adoption");
            }
            // Never create or initialize a missing/replaced bound database.
            if !database.exists() {
                bail!("bound journal is missing; authoritative recovery required");
            }
            let existing = Store::read_only(config)?.context("bound journal is missing")?;
            if existing.control().is_err() {
                bail!("bound journal is uninitialized");
            }
            if existing.schema_version()? != 2 {
                if !legacy || binding.is_some() {
                    bail!("legacy journal authority is missing or inconsistent; writes blocked");
                }
                if !migration_allowed {
                    bail!("journal adoption requires a stopped writer; run recover adopt first");
                }
            } else {
                let (database_id, sequence) = existing
                    .database_identity()
                    .context("existing journal authority is missing or malformed")?;
                if database_id.len() != 32
                    || !database_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || sequence < 0
                {
                    bail!("existing journal authority is invalid");
                }
            }
        }
        let mut store = Store::open(config)?;
        store.bind_routing(config)?;
        let location = fs::canonicalize(&config.state_dir)?
            .to_string_lossy()
            .into_owned();
        let (database_id, sequence) = store.database_identity()?;
        let expected_identity = digest(identity(config)?);
        let binding = match binding {
            Some(binding) => {
                if binding.location != location
                    || binding.identity != expected_identity
                    || binding.database_id != database_id
                    || binding.dispatch_sequence > sequence
                {
                    bail!("journal identity or dispatch witness mismatch; writes blocked");
                }
                // Journal-ahead gaps happened before the network boundary. Preserve
                // dispatch intent as uncertain; advancing the witness never replays it.
                Binding {
                    dispatch_sequence: sequence,
                    ..binding
                }
            }
            None => Binding {
                location,
                identity: expected_identity,
                database_id,
                dispatch_sequence: sequence,
            },
        };
        let binding_path = lock_path(config, "binding")?;
        write_binding(&binding_path, &binding)?;
        if !marked {
            // Never replace the locked inode. The permanent marker only detects
            // deleted binding metadata; all changing identity/witness data lives separately.
            file.rewind()?;
            file.write_all(WRITER_MARKER)?;
            file.set_len(WRITER_MARKER.len() as u64)?;
            file.sync_all()?;
            File::open(
                lock_path(config, "writer")?
                    .parent()
                    .context("lock parent missing")?,
            )?
            .sync_all()?;
        }
        store.binding = Some((binding_path, binding));
        store.writer_path = Some((lock_path(config, "writer")?, file.metadata()?));
        Ok(store)
    }

    /// Controls share the admission gate but never migrate beneath a live writer.
    pub(crate) fn control_store(config: &Config) -> Result<Store> {
        let mut file = private_file(&lock_path(config, "writer")?)?;
        let stopped = file.try_lock().is_ok();
        let result = Self::open_bound_store(&mut file, config, false);
        if stopped {
            let _ = file.unlock();
        }
        result
    }
}
impl Drop for AccountLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Pause commits under the same gate used for admission. HTTP dispatch holds this
/// gate until its bounded response completes; a pause acknowledgment cannot race it.
pub(crate) struct AdmissionGuard(File);
impl AdmissionGuard {
    pub(crate) fn acquire(config: &Config) -> Result<Self> {
        let file = private_file(&lock_path(config, "admission")?)?;
        file.lock()
            .context("cannot acquire account admission gate")?;
        Ok(Self(file))
    }
    pub(crate) fn try_acquire(config: &Config) -> Result<Self> {
        let file = private_file(&lock_path(config, "admission")?)?;
        file.try_lock()
            .map_err(std::io::Error::from)
            .context("account admission is busy")?;
        Ok(Self(file))
    }
}
impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Control {
    pub paused: bool,
    pub generation: i64,
}

#[derive(Clone)]
pub(crate) struct Operation {
    pub id: i64,
    pub kind: WorkKind,
    pub key: String,
    pub state: String,
    pub request: Value,
    pub result: Option<Value>,
    pub payload: Option<Value>,
    pub job_id: Option<String>,
    pub txid: Option<String>,
    pub next_at: i64,
    persisted_state: std::cell::RefCell<String>,
    pub generation: i64,
}

/// Only retained transition events establish phase starts; updated_at is
/// intentionally not treated as historical phase evidence.
#[derive(Default)]
struct WaitEvidence {
    generating: Option<i64>,
    captured: Option<i64>,
    queued: Option<i64>,
    dispatch: Option<i64>,
}

impl WaitEvidence {
    fn projection(&self, state: &str, effect_since: Option<i64>, current: i64) -> Value {
        let valid = |at: Option<i64>| at.filter(|at| *at >= 0 && *at <= current);
        let generating = valid(self.generating).filter(|_| state == "generating");
        let captured = valid(self.captured).filter(|_| {
            matches!(state, "generated" | "prepared")
                && self.dispatch.is_none()
                && effect_since.is_none()
        });
        let queued = valid(self.queued).filter(|_| state == "queued");
        let effect = valid(effect_since.or(self.dispatch)).filter(|_| {
            matches!(
                state,
                "dispatching" | "queued" | "unknown" | "included_pending"
            )
        });
        let age = |at: Option<i64>| at.map(|at| current.saturating_sub(at));
        json!({
            "observed_at":current,
            "generation_started_at":generating,"generation_age_seconds":age(generating),
            "model_captured_at":captured,"unsent_since_capture_seconds":age(captured),
            "queued_since":queued,"queued_age_seconds":age(queued),
            "effect_since":effect,"effect_age_seconds":age(effect),
            "basis":"durable_transition_evidence"
        })
    }
}

/// Read failures are independent of normal work cadence and shared by callers
/// of the same endpoint class, including answer/mine challenge observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadScope {
    Challenge,
    Identity,
    Assignments,
    AssignmentEvidence,
    Job,
    Receipt,
}

impl ReadScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Identity => "identity",
            Self::Assignments => "assignments",
            Self::AssignmentEvidence => "assignment_evidence",
            Self::Job => "job",
            Self::Receipt => "receipt",
        }
    }

    pub(crate) const ALL: [Self; 6] = [
        Self::Challenge,
        Self::Identity,
        Self::Assignments,
        Self::AssignmentEvidence,
        Self::Job,
        Self::Receipt,
    ];
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadBackoff {
    pub failures: u32,
    pub next_at: i64,
}

fn read_delay(failures: u32, base: u64, cap: u64, jitter: u64) -> u64 {
    base.saturating_mul(
        1_u64
            .checked_shl(failures.saturating_sub(1))
            .unwrap_or(u64::MAX),
    )
    .min(cap.max(base))
    .saturating_add(jitter)
}

pub(crate) fn safe_read_category(category: &str) -> &'static str {
    match category {
        "timeout" => "timeout",
        "connect" => "connect",
        "request" => "request",
        "body_interrupted" => "body_interrupted",
        "response_too_large" => "response_too_large",
        "invalid_json" => "invalid_json",
        "credential_echo_redacted" => "credential_echo_redacted",
        "http_status" => "http_status",
        "authentication_rejected" => "authentication_rejected",
        "permission_denied" => "permission_denied",
        "endpoint_halted" => "endpoint_halted",
        "redirect_refused" => "redirect_refused",
        "not_found" => "not_found",
        "request_timeout" => "request_timeout",
        "gone" => "gone",
        "rate_limited" => "rate_limited",
        "request_rejected" => "request_rejected",
        "bad_gateway" => "bad_gateway",
        "service_unavailable" => "service_unavailable",
        "gateway_timeout" => "gateway_timeout",
        "upstream_error" => "upstream_error",
        "upstream_rejected" => "upstream_rejected",
        _ => "unusable_response",
    }
}

pub(crate) struct Store {
    db: Connection,
    binding: Option<(PathBuf, Binding)>,
    writer_path: Option<(PathBuf, fs::Metadata)>,
    database_file: Option<(PathBuf, fs::Metadata)>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct JournalEvent {
    pub id: i64,
    pub at: i64,
    pub event: String,
    pub kind: Option<String>,
}

#[derive(Debug)]
struct EventJournal {
    database_id: String,
    dispatch_sequence: i64,
    file: fs::Metadata,
}

#[derive(Debug, Default)]
pub(crate) struct EventCursor {
    journal: Option<EventJournal>,
    after: i64,
    observed_through: i64,
}

#[derive(Debug)]
pub(crate) struct EventPage {
    pub cursor: EventCursor,
    pub events: Vec<JournalEvent>,
    pub more: bool,
}

#[derive(Debug)]
pub(crate) enum EventCursorError {
    Replaced,
    Regressed,
    Gap,
}

impl std::fmt::Display for EventCursorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Replaced => "journal identity changed while following logs",
            Self::Regressed => "journal cursor regressed while following logs",
            Self::Gap => "retained journal history no longer covers the log cursor",
        })
    }
}

impl std::error::Error for EventCursorError {}

fn same_journal_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        // database_id and the durable sequence remain authoritative everywhere.
        let _ = (left, right);
        true
    }
}

#[derive(serde::Serialize)]
struct HistoricalAnswer {
    operation_id: i64,
    accepted_answer_id: i64,
}

struct RiskDecision {
    accounting: UncertaintyAccounting,
    retry_of: Option<i64>,
    grant: Option<i64>,
}

const HISTORICAL_EXAMPLE_LIMIT: usize = 20;

// Operations and direct retry linkage remain authoritative; this query never
// resolves an original or treats age/same-epoch similarity as acceptance.
const HISTORICAL_ANSWERS: &str = "
    SELECT original.id AS operation_id,MIN(accepted.id) AS accepted_answer_id
    FROM operations original
    JOIN operation_evidence evidence ON evidence.operation_id=original.id
    JOIN operation_links link ON link.retry_of=original.id
    JOIN operations accepted ON accepted.id=link.operation_id
    WHERE original.kind='answer' AND original.state='unknown'
    AND original.job_id IS NULL AND original.txid IS NULL
    AND evidence.dispatch_sequence IS NOT NULL
    AND accepted.id>original.id AND accepted.kind='answer' AND accepted.txid IS NOT NULL
    AND accepted.state IN ('included_pending','confirmed','final')
    AND json_extract(original.request,'$.solver.epoch')=
        json_extract(accepted.request,'$.solver.epoch')
    GROUP BY original.id";

#[derive(Default)]
struct UncertaintyAccounting {
    total: u64,
    eligible: u64,
    exempt: u64,
    historical: Vec<HistoricalAnswer>,
    blockers: Vec<i64>,
    writing: bool,
    retry_not_before: i64,
    grace_until: i64,
    retry_grace_until: i64,
    writing_operation: Option<i64>,
    floor_operation: Option<i64>,
    grace_operation: Option<i64>,
    retry_operation: Option<i64>,
}

impl UncertaintyAccounting {
    fn active(&self) -> u64 {
        self.total - self.exempt
    }

    fn blocking_operation(&self, reason: &str) -> Option<i64> {
        match reason {
            "effect_in_flight" => self.writing_operation,
            "retained_retry_minimum" => self.floor_operation,
            "uncertainty_grace" => self.grace_operation,
            "uncertain_answer_retry_delay" => self.retry_operation,
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct AnswerRetryReservation {
    original_operation_id: i64,
    ready_at: i64,
    same_operation: bool,
}

fn identity(config: &Config) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "chain": config.network.chain,
        "address": config.network.address,
        "base_url": config.network.base_url,
        "credential_file": config.network.credential_file,
    }))?)
}

impl Store {
    fn schema_version(&self) -> Result<i64> {
        Ok(self
            .db
            .query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
                r.get(0)
            })?)
    }

    fn database_identity(&self) -> Result<(String, i64)> {
        Ok(self.db.query_row(
            "SELECT database_id,dispatch_sequence FROM authority WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    fn check_binding(&self, config: &Config) -> Result<()> {
        if let Some(binding) = read_binding(config)? {
            let (id, sequence) = self.database_identity()?;
            if id != binding.database_id
                || sequence < binding.dispatch_sequence
                || binding.identity != digest(identity(config)?)
                || binding.location != fs::canonicalize(&config.state_dir)?.to_string_lossy()
            {
                bail!("bound journal identity or dispatch witness mismatch");
            }
        }
        Ok(())
    }

    pub(crate) fn continuity(&self) -> Result<()> {
        if let Some((path, expected)) = &self.database_file {
            let current = fs::symlink_metadata(path).context("bound journal disappeared")?;
            validate_private_file(&current)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if current.dev() != expected.dev() || current.ino() != expected.ino() {
                    bail!("bound journal inode changed");
                }
            }
        }
        if let Some((path, expected)) = &self.writer_path {
            let current = fs::symlink_metadata(path).context("writer lock disappeared")?;
            validate_private_file(&current)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if current.dev() != expected.dev() || current.ino() != expected.ino() {
                    bail!("writer lock inode changed; stopping authority");
                }
            }
        }
        if let Some((path, expected)) = &self.binding {
            let current: Binding = serde_json::from_slice(&fs::read(path)?)?;
            let (id, sequence) = self.database_identity()?;
            if current.database_id != id
                || current.database_id != expected.database_id
                || current.dispatch_sequence > sequence
                || current.identity != expected.identity
                || current.dispatch_sequence < expected.dispatch_sequence
                || current.location != expected.location
            {
                bail!("account binding continuity lost");
            }
            let disk = Path::new(&expected.location).join("state.sqlite3");
            let db_path: String = self.db.query_row(
                "SELECT file FROM pragma_database_list WHERE name='main'",
                [],
                |r| r.get(0),
            )?;
            if !disk.exists() || fs::canonicalize(disk)? != Path::new(&db_path) {
                bail!("bound journal path disappeared");
            }
        }
        Ok(())
    }
    pub(crate) fn read_only(config: &Config) -> Result<Option<Self>> {
        let path = config.state_dir.join("state.sqlite3");
        if !path.exists() {
            if read_binding(config)?.is_some()
                || fs::metadata(lock_path(config, "writer")?).is_ok_and(|m| m.len() != 0)
            {
                bail!("bound journal is missing");
            }
            return Ok(None);
        }
        validate_private_dir(&config.state_dir)?;
        let path = fs::canonicalize(&config.state_dir)?.join("state.sqlite3");
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("state must be a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                bail!("state must be private and owned by this user");
            }
        }
        let db = {
            let _opening = DATABASE_OPEN
                .lock()
                .map_err(|_| anyhow::anyhow!("database opening lock poisoned"))?;
            Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 =
            db.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if !matches!(version, 1 | 2) {
            bail!("unsupported state schema");
        }
        let store = Self {
            db,
            binding: None,
            writer_path: None,
            database_file: None,
        };
        store.check_binding(config)?;
        Ok(Some(store))
    }

    pub(crate) fn open(config: &Config) -> Result<Self> {
        if read_binding(config)?.is_some() {
            Self::read_only(config)?.context("bound journal missing")?;
        }
        private_dir(&config.state_dir)?;
        let path = fs::canonicalize(&config.state_dir)?.join("state.sqlite3");
        let mut db = {
            let _opening = DATABASE_OPEN
                .lock()
                .map_err(|_| anyhow::anyhow!("database opening lock poisoned"))?;
            prepare_database(&path)?;
            Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .context("cannot open local state")?
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS control (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                paused INTEGER NOT NULL, generation INTEGER NOT NULL,
                identity TEXT NOT NULL, version INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY, kind TEXT NOT NULL, work_key TEXT NOT NULL,
                state TEXT NOT NULL, request TEXT NOT NULL, result TEXT, payload TEXT,
                job_id TEXT, txid TEXT, generation INTEGER NOT NULL, revision TEXT NOT NULL,
                next_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS operations_key ON operations(kind,work_key);
             CREATE INDEX IF NOT EXISTS operations_state ON operations(state,kind,updated_at);
             CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, at INTEGER NOT NULL, code TEXT NOT NULL,
                kind TEXT, operation_id INTEGER);
             CREATE TABLE IF NOT EXISTS schedule (kind TEXT PRIMARY KEY, next_at INTEGER NOT NULL, cursor TEXT);
             CREATE TABLE IF NOT EXISTS read_backoff (
                scope TEXT PRIMARY KEY, failures INTEGER NOT NULL, next_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS read_observations (
                scope TEXT PRIMARY KEY, in_flight INTEGER NOT NULL DEFAULT 0,
                started_at INTEGER, finished_at INTEGER, last_http_success_at INTEGER,
                last_success_at INTEGER, last_failure_at INTEGER, failure_category TEXT,
                status INTEGER, local_next_at INTEGER NOT NULL DEFAULT 0,
                server_not_before INTEGER NOT NULL DEFAULT 0,
                retained_conservative_floor INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS assignment_selection (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                revision TEXT NOT NULL, generation INTEGER NOT NULL, observed_at INTEGER NOT NULL,
                observed_count INTEGER NOT NULL, inventory_complete INTEGER NOT NULL,
                eligible INTEGER NOT NULL);
             INSERT OR IGNORE INTO read_observations(scope,retained_conservative_floor)
                SELECT scope,next_at FROM read_backoff;
             CREATE TABLE IF NOT EXISTS observation (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                epoch INTEGER NOT NULL, observed_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS runtime_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                effective_revision TEXT NOT NULL, reload_blocked INTEGER NOT NULL,
                capabilities TEXT NOT NULL, observed_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS health_evidence (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                hosted_identity_verified INTEGER CHECK(hosted_identity_verified IN (0,1)),
                epoch INTEGER, first_observed_at INTEGER,
                answered INTEGER CHECK(answered IN (0,1)));
             CREATE TABLE IF NOT EXISTS hosted_identity_evidence (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                status TEXT NOT NULL CHECK(status IN ('verified','unavailable','authentication_failed',
                    'identity_mismatch','invalid_response','legacy_unknown')),
                observed_at INTEGER, last_verified_at INTEGER,
                rejection TEXT CHECK(rejection IN ('authentication_failed','identity_mismatch')),
                legacy_failure INTEGER NOT NULL CHECK(legacy_failure IN (0,1)));
             CREATE TABLE IF NOT EXISTS identity_normalizations (
                id INTEGER PRIMARY KEY, preview_token TEXT NOT NULL UNIQUE, audit TEXT NOT NULL);"
        )?;
        let expected = identity(config)?;
        let existing: Option<(String, i64)> = tx
            .query_row(
                "SELECT identity,version FROM control WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match existing {
            Some((stored, version)) => {
                if !matches!(version, 1 | 2) {
                    bail!("unsupported state schema; do not downgrade this database");
                }
                if stored != expected {
                    bail!("state belongs to a different immutable network identity");
                }
            }
            None => {
                tx.execute("INSERT INTO control VALUES (1,1,0,?1,1)", [&expected])?;
                tx.execute(
                    "INSERT INTO events(at,code) VALUES (?1,'initialized_paused')",
                    [now()],
                )?;
            }
        }
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS authority (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                database_id TEXT NOT NULL, dispatch_sequence INTEGER NOT NULL);
             INSERT OR IGNORE INTO authority VALUES (1,lower(hex(randomblob(16))),0);
             CREATE TABLE IF NOT EXISTS operation_evidence (
                operation_id INTEGER PRIMARY KEY REFERENCES operations(id),
                policy TEXT, model_deadline INTEGER, http_deadline INTEGER,
                dispatch_sequence INTEGER, blocked_since INTEGER, evidence TEXT,
                observed_at INTEGER, safety_observed_at INTEGER, resolution TEXT);
             CREATE TABLE IF NOT EXISTS operation_candidates (
                operation_id INTEGER PRIMARY KEY REFERENCES operations(id),
                candidates TEXT NOT NULL, truncated INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS runtime_policy (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS routing_profile (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS operation_links (
                operation_id INTEGER PRIMARY KEY REFERENCES operations(id),
                retry_of INTEGER NOT NULL REFERENCES operations(id), payload_reused INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS operation_timing (
                operation_id INTEGER PRIMARY KEY REFERENCES operations(id), retry_not_before INTEGER NOT NULL);
             INSERT OR IGNORE INTO operation_timing
                SELECT id,next_at FROM operations WHERE state IN ('dispatching','queued','unknown','included_pending');
             CREATE TABLE IF NOT EXISTS manual_grants (
                id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, kind TEXT NOT NULL,
                generation INTEGER NOT NULL, created_at INTEGER NOT NULL, consumed_by INTEGER REFERENCES operations(id));
             CREATE TABLE IF NOT EXISTS manual_grant_revocations (
                grant_id INTEGER PRIMARY KEY REFERENCES manual_grants(id), revoked_at INTEGER NOT NULL);
             DROP INDEX IF EXISTS manual_grants_pending;
             CREATE TABLE IF NOT EXISTS risk_admissions (
                dispatch_sequence INTEGER PRIMARY KEY, operation_id INTEGER NOT NULL REFERENCES operations(id),
                policy TEXT NOT NULL, revision TEXT NOT NULL, blocker_ids TEXT NOT NULL,
                retry_of INTEGER REFERENCES operations(id), manual_grant_id INTEGER REFERENCES manual_grants(id),
                admitted_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS risk_historical_answers (
                dispatch_sequence INTEGER NOT NULL REFERENCES risk_admissions(dispatch_sequence),
                operation_id INTEGER NOT NULL REFERENCES operations(id),
                accepted_answer_id INTEGER NOT NULL REFERENCES operations(id),
                PRIMARY KEY(dispatch_sequence,operation_id));
             CREATE INDEX IF NOT EXISTS operation_links_retry_of ON operation_links(retry_of);
             CREATE TABLE IF NOT EXISTS historical_answer_accounting_events (
                revision INTEGER PRIMARY KEY, original_id INTEGER NOT NULL REFERENCES operations(id),
                accepted_answer_id INTEGER REFERENCES operations(id), observed_at INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS historical_answer_accounting_original
                ON historical_answer_accounting_events(original_id,revision DESC);
             CREATE TABLE IF NOT EXISTS risk_accounting_snapshots (
                dispatch_sequence INTEGER PRIMARY KEY REFERENCES risk_admissions(dispatch_sequence),
                witness_revision INTEGER NOT NULL, unresolved_count INTEGER NOT NULL,
                eligible_count INTEGER NOT NULL, exempt_count INTEGER NOT NULL);
             UPDATE operations SET work_key=lower(work_key)
                WHERE kind='judge' AND length(work_key)=64 AND work_key<>lower(work_key);
             UPDATE operations SET txid=lower(txid) WHERE length(txid)=64 AND txid<>lower(txid);
             UPDATE control SET version=2 WHERE singleton=1;"
        )?;
        tx.commit()?;
        let database_path = fs::canonicalize(&config.state_dir)?.join("state.sqlite3");
        let database_metadata = fs::symlink_metadata(&database_path)?;
        Ok(Self {
            db,
            binding: None,
            writer_path: None,
            database_file: Some((database_path, database_metadata)),
        })
    }

    fn routing_profile(&self) -> Result<Option<String>> {
        let exists: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='routing_profile')",
            [], |row| row.get(0))?;
        if !exists {
            return Ok(None);
        }
        Ok(self
            .db
            .query_row(
                "SELECT profile FROM routing_profile WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn routing_busy(&self, config: &Config) -> Result<bool> {
        // Read-only inspection of an older schema cannot prove its retry lane drained.
        if !self.has_table("operation_links")? {
            return Ok(true);
        }
        // Keep this retry predicate aligned with retry_models and model_budget_used.
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE state IN
            ('generating','model_unknown','generated','prepared','retry','dispatching','queued','unknown','included_pending','confirmed')
            OR (state IN ('rejected','retry_model','superseded_model_unknown')
                AND payload IS NULL AND job_id IS NULL AND txid IS NULL
                AND (SELECT COUNT(*) FROM operations b WHERE b.kind=operations.kind
                    AND b.work_key=operations.work_key COLLATE NOCASE
                    AND b.state NOT IN ('prelaunch_failed','abandoned_model')
                    AND NOT EXISTS(SELECT 1 FROM operation_links l WHERE l.operation_id=b.id AND l.payload_reused=1)) < ?1))",
            [config.preparation.max_attempts_per_work], |row| row.get(0))?)
    }

    pub(crate) fn routing_change_allowed(&self, config: &Config) -> Result<()> {
        let profile = serde_json::to_string(&config.network.api)?;
        let previous = self.routing_profile()?;
        let matches = previous.as_deref().map_or(
            digest(&profile) == crate::endpoints::LEGACY_API_FINGERPRINT,
            |previous| previous == profile,
        );
        if !matches && self.routing_busy(config)? {
            return Err(RoutingProfileError.into());
        }
        Ok(())
    }

    /// Called only under the account writer and admission guards, before any HTTP.
    fn bind_routing(&mut self, config: &Config) -> Result<()> {
        self.routing_change_allowed(config)?;
        let profile = serde_json::to_string(&config.network.api)?;
        let previous = self.routing_profile()?;
        if previous.as_deref() == Some(profile.as_str()) {
            return Ok(());
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if previous.is_some() || digest(&profile) != crate::endpoints::LEGACY_API_FINGERPRINT {
            tx.execute_batch("DELETE FROM observation;
                UPDATE control SET generation=generation+1 WHERE singleton=1;
                UPDATE health_evidence SET hosted_identity_verified=NULL,epoch=NULL,first_observed_at=NULL,answered=NULL;
                DELETE FROM hosted_identity_evidence;
                UPDATE read_observations SET in_flight=0,started_at=NULL,last_success_at=NULL,last_http_success_at=NULL;")?;
        }
        tx.execute(
            "INSERT INTO routing_profile VALUES(1,?1)
            ON CONFLICT(singleton) DO UPDATE SET profile=excluded.profile",
            [&profile],
        )?;
        tx.execute(
            "INSERT INTO events(at,code) VALUES(?1,'routing_profile_bound')",
            [now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn routing_status(&self, config: &Config) -> Result<Value> {
        let profile = self.routing_profile()?;
        let configured = serde_json::to_string(&config.network.api)?;
        let matches = profile.as_deref().map_or(
            digest(&configured) == crate::endpoints::LEGACY_API_FINGERPRINT,
            |profile| profile == configured,
        );
        Ok(json!({
            "matches_config":matches,
            "change_allowed_when_stopped":matches || !self.routing_busy(config)?,
            "bound":profile.is_some(),
            "configured_fingerprint":config.network.api.fingerprint()?,
            "bound_fingerprint":profile.as_ref().map(digest),
            "bound_api":profile.as_deref().map(serde_json::from_str::<Value>).transpose()?,
            "changes_require":"stopped_and_drained"
        }))
    }

    pub(crate) fn control(&self) -> Result<Control> {
        Ok(self.db.query_row(
            "SELECT paused,generation FROM control WHERE singleton=1",
            [],
            |row| {
                Ok(Control {
                    paused: row.get(0)?,
                    generation: row.get(1)?,
                })
            },
        )?)
    }

    pub(crate) fn set_paused(&mut self, paused: bool) -> Result<()> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE control SET paused=?1,generation=generation+1 WHERE singleton=1",
            [paused],
        )?;
        tx.execute(
            "INSERT INTO events(at,code) VALUES (?1,?2)",
            params![now(), if paused { "paused" } else { "resumed" }],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn recover(&mut self) -> Result<()> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE read_observations SET in_flight=0,finished_at=?1 WHERE in_flight!=0",
            [now()],
        )?;
        for (from, to) in [("generating", "model_unknown"), ("dispatching", "unknown")] {
            tx.execute(
                "INSERT INTO events(at,code,kind,operation_id)
                SELECT ?1,?2,kind,id FROM operations WHERE state=?3",
                params![now(), to, from],
            )?;
            tx.execute(
                "UPDATE operations SET state=?1,updated_at=?2 WHERE state=?3",
                params![to, now(), from],
            )?;
        }
        // Older writers could commit the response before its timing row.
        // Reconstruct only captured submit minima, never a fresh delay from now.
        {
            let mut statement = tx.prepare(
                "SELECT operation_id,evidence,observed_at FROM operation_evidence
                 WHERE evidence IS NOT NULL",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })?;
            for row in rows {
                let (id, text, observed_at) = row?;
                let Ok(evidence) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                if evidence["stage"] != "submit" {
                    continue;
                }
                let floor = Self::captured_retry_floor(&evidence, observed_at);
                if floor > 0 {
                    tx.execute(
                        "INSERT INTO operation_timing VALUES (?1,?2)
                         ON CONFLICT(operation_id) DO UPDATE SET
                         retry_not_before=MAX(retry_not_before,excluded.retry_not_before)",
                        params![id, floor],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn abandon_models(&mut self) -> Result<usize> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Only inference with no dispatch artifact is eligible. Network uncertainty
        // remains untouched, even if the operator invokes this command repeatedly.
        tx.execute(
            "INSERT INTO events(at,code,kind,operation_id)
             SELECT ?1,'model_abandoned',kind,id FROM operations
             WHERE state='model_unknown' AND payload IS NULL AND job_id IS NULL AND txid IS NULL",
            [now()],
        )?;
        let count = tx.execute(
            "UPDATE operations SET state='abandoned_model',updated_at=?1
             WHERE state='model_unknown' AND payload IS NULL AND job_id IS NULL AND txid IS NULL",
            [now()],
        )?;
        tx.commit()?;
        Ok(count)
    }

    pub(crate) fn begin(
        &mut self,
        kind: WorkKind,
        key: &str,
        state: &str,
        request: &Value,
        control: Control,
        revision: &str,
    ) -> Result<Operation> {
        self.begin_linked(kind, key, (state, request), control, revision, None)
    }

    pub(crate) fn begin_linked(
        &mut self,
        kind: WorkKind,
        key: &str,
        intent: (&str, &Value),
        control: Control,
        revision: &str,
        retry: Option<(&Operation, bool)>,
    ) -> Result<Operation> {
        let (state, request) = intent;
        self.continuity()?;
        if !matches!(state, "generating" | "prepared") {
            bail!("invalid initial operation state");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = tx.query_row(
            "SELECT paused,generation FROM control WHERE singleton=1",
            [],
            |row| {
                Ok(Control {
                    paused: row.get(0)?,
                    generation: row.get(1)?,
                })
            },
        )?;
        if current.paused || current != control {
            bail!("admission generation changed");
        }
        let unresolved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE kind=?1 AND state IN
            ('generating','generated','prepared','retry'))",
            [kind.as_str()],
            |row| row.get(0),
        )?;
        if unresolved {
            bail!("preparation capacity is already occupied");
        }
        // Mining has no model payload; publish its complete prepared intent atomically.
        let payload = (kind == WorkKind::Mine && state == "prepared").then_some("{}");
        tx.execute("INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at,payload)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?7,?8)", params![kind.as_str(),key,state,serde_json::to_string(request)?,control.generation,revision,now(),payload])?;
        let id = tx.last_insert_rowid();
        if let Some((original, reuse)) = retry {
            if kind != WorkKind::Answer || original.kind != WorkKind::Answer {
                bail!("only answer attempts may link an uncertain retry");
            }
            let eligible: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 AND kind='answer'
                AND state IN ('queued','unknown') AND txid IS NULL AND payload IS NOT NULL)",
                [original.id],
                |r| r.get(0),
            )?;
            if !eligible {
                bail!("retry origin is no longer an uncertain answer");
            }
            tx.execute(
                "INSERT INTO operation_links VALUES (?1,?2,?3)",
                params![id, original.id, reuse],
            )?;
            if reuse {
                if state != "prepared"
                    || original.payload.is_none()
                    || original.key != key
                    || request != &original.request
                {
                    bail!("captured retry requires matching complete answer");
                }
                tx.execute(
                    "UPDATE operations SET
                    payload=(SELECT payload FROM operations WHERE id=?1),
                    result=(SELECT result FROM operations WHERE id=?1) WHERE id=?2",
                    params![original.id, id],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO events(at,code,kind,operation_id) VALUES (?1,?2,?3,?4)",
            params![now(), state, kind.as_str(), id],
        )?;
        tx.commit()?;
        self.operation(id)?.context("durable operation missing")
    }

    pub(crate) fn save(&mut self, op: &Operation, event: &str) -> Result<()> {
        self.save_admitted(op, event, None)
    }

    pub(crate) fn dispatch_intent(&mut self, op: &mut Operation, config: &Config) -> Result<bool> {
        let previous = op.state.clone();
        op.state = "dispatching".into();
        if !self.admission_allowed(config, op)? {
            op.state = previous;
            return Ok(false);
        }
        self.save_admitted(op, "dispatch_intent", Some(config))?;
        Ok(true)
    }

    fn save_admitted(
        &mut self,
        op: &Operation,
        event: &str,
        config: Option<&Config>,
    ) -> Result<()> {
        self.continuity()?;
        let predecessor = op.persisted_state.borrow().clone();
        let was_effect = matches!(
            predecessor.as_str(),
            "dispatching" | "queued" | "unknown" | "included_pending"
        );
        if matches!(op.state.as_str(), "queued" | "unknown" | "included_pending") && !was_effect {
            bail!("effect transition requires durable dispatch intent");
        }
        // Only local static codes enter the public event stream.
        if !event.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            bail!("invalid local event code");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if op.state == "dispatching" && predecessor != "dispatching" {
            if !matches!(predecessor.as_str(), "generated" | "prepared" | "retry") {
                bail!("invalid dispatch predecessor");
            }
            let decision = if let Some(config) = config {
                if config.mode(op.kind) != Mode::Active {
                    bail!("dispatch capability is not active");
                }
                Some(
                    Self::risk_decision(&tx, config, op)?
                        .context("participation admission closed")?,
                )
            } else {
                let occupied: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM operations WHERE id!=?1
                    AND state IN ('dispatching','queued','unknown','included_pending'))",
                    [op.id],
                    |r| r.get(0),
                )?;
                if occupied {
                    bail!("wallet effect slot is occupied");
                }
                None
            };
            let (paused, generation): (bool, i64) = tx.query_row(
                "SELECT paused,generation FROM control WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if paused || generation != op.generation {
                bail!("dispatch generation changed");
            }
            tx.execute(
                "UPDATE authority SET dispatch_sequence=dispatch_sequence+1 WHERE singleton=1",
                [],
            )?;
            tx.execute("INSERT INTO operation_evidence(operation_id,dispatch_sequence,blocked_since)
                VALUES (?1,(SELECT dispatch_sequence FROM authority WHERE singleton=1),?2)
                ON CONFLICT(operation_id) DO UPDATE SET dispatch_sequence=excluded.dispatch_sequence,
                blocked_since=excluded.blocked_since", params![op.id,now()])?;
            // Local polling cadence is not a server-imposed admission minimum.
            // Keep an explicit zero so reopening cannot inherit op.next_at.
            tx.execute(
                "INSERT OR IGNORE INTO operation_timing VALUES (?1,0)",
                [op.id],
            )?;
            if let (Some(config), Some(decision)) = (config, decision) {
                if decision.accounting.total > 0 || decision.retry_of.is_some() {
                    tx.execute(
                        "INSERT INTO risk_admissions
                        VALUES ((SELECT dispatch_sequence FROM authority WHERE singleton=1),?1,?2,?3,?4,?5,?6,?7)",
                        params![op.id,serde_json::to_string(&config.participation)?,config.revision()?,
                            serde_json::to_string(&decision.accounting.blockers)?,decision.retry_of,decision.grant,now()],
                    )?;
                    if config.participation.historical_unknown_answer_capacity
                        == HistoricalAnswerCapacity::AcceptedLinked
                    {
                        let revision = Self::capture_historical_revision(&tx)?;
                        tx.execute(
                            "INSERT INTO risk_accounting_snapshots VALUES
                             ((SELECT dispatch_sequence FROM authority WHERE singleton=1),?1,?2,?3,?4)",
                            params![revision,decision.accounting.total,
                                decision.accounting.eligible,decision.accounting.exempt],
                        )?;
                    } else if decision.accounting.exempt > 0 {
                        // Legacy bounded admissions retain their original representation.
                        tx.execute(
                            &format!(
                                "INSERT INTO risk_historical_answers
                             SELECT (SELECT dispatch_sequence FROM authority WHERE singleton=1),
                                operation_id,accepted_answer_id FROM ({HISTORICAL_ANSWERS})
                             WHERE operation_id!=?1 ORDER BY operation_id LIMIT ?2"
                            ),
                            params![op.id, decision.accounting.exempt],
                        )?;
                    }
                    if let Some(grant) = decision.grant {
                        let consumed = tx.execute(
                            "UPDATE manual_grants SET consumed_by=?1 WHERE id=?2 AND consumed_by IS NULL
                            AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=?2)",
                            params![op.id,grant],
                        )?;
                        if consumed != 1 {
                            bail!("manual participation grant already consumed");
                        }
                    }
                    tx.execute("INSERT INTO events(at,code,kind,operation_id) VALUES (?1,'participation_risk_admitted',?2,?3)",
                        params![now(),op.kind.as_str(),op.id])?;
                }
                let captured: Option<String> = tx
                    .query_row(
                        "SELECT policy FROM operation_evidence WHERE operation_id=?1",
                        [op.id],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                let mut captured: Value = captured
                    .map(|p| serde_json::from_str(&p))
                    .transpose()?
                    .unwrap_or_else(|| json!({}));
                captured["dispatch_policy"] = json!({"participation":config.participation,
                    "revision":config.revision()?,"http_seconds":config.timeouts.http_seconds,
                    "mine_each_epoch":config.schedule.mine_each_epoch});
                tx.execute(
                    "INSERT INTO operation_evidence(operation_id,policy,http_deadline) VALUES (?1,?2,?3)
                    ON CONFLICT(operation_id) DO UPDATE SET policy=excluded.policy,http_deadline=excluded.http_deadline",
                    params![op.id,serde_json::to_string(&captured)?,not_before(config.timeouts.http_seconds)],
                )?;
            }
        }
        let changed = tx.execute(
            "UPDATE operations SET state=?1,result=?2,payload=?3,job_id=?4,txid=?5,next_at=?6,
            updated_at=CASE WHEN state!=?1 THEN ?7 ELSE updated_at END WHERE id=?8 AND state=?9",
            params![
                op.state,
                op.result.as_ref().map(serde_json::to_string).transpose()?,
                op.payload.as_ref().map(serde_json::to_string).transpose()?,
                op.job_id,
                op.txid,
                op.next_at,
                now(),
                op.id,
                predecessor
            ],
        )?;
        if changed != 1 {
            bail!("stale operation transition");
        }
        if predecessor != op.state {
            if matches!(
                predecessor.as_str(),
                "dispatching" | "queued" | "unknown" | "included_pending"
            ) && !matches!(
                op.state.as_str(),
                "dispatching" | "queued" | "unknown" | "included_pending"
            ) {
                tx.execute(
                    "INSERT INTO operation_evidence(operation_id,resolution) VALUES (?1,?2)
                    ON CONFLICT(operation_id) DO UPDATE SET resolution=excluded.resolution",
                    params![
                        op.id,
                        serde_json::to_string(
                            &json!({"source":"bound_protocol_result","state":op.state,"at":now()})
                        )?
                    ],
                )?;
            }
            tx.execute(
                "INSERT INTO events(at,code,kind,operation_id) VALUES (?1,?2,?3,?4)",
                params![now(), event, op.kind.as_str(), op.id],
            )?;
        }
        tx.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )?;
        tx.commit()?;
        *op.persisted_state.borrow_mut() = op.state.clone();
        if op.state == "dispatching" && predecessor != "dispatching" {
            let (_, sequence) = self.database_identity()?;
            if let Some((path, binding)) = &mut self.binding {
                binding.dispatch_sequence = sequence;
                // SQLite FULL commit precedes witness fsync+rename+directory fsync;
                // only then may Runtime poll the prepared network future.
                write_binding(path, binding)?;
            }
        }
        Ok(())
    }

    pub(crate) fn event(&mut self, code: &str, kind: Option<WorkKind>) -> Result<()> {
        if !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            bail!("invalid local event code");
        }
        self.db.execute(
            "INSERT INTO events(at,code,kind) VALUES (?1,?2,?3)",
            params![now(), code, kind.map(|k| k.as_str())],
        )?;
        self.db.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )?;
        Ok(())
    }

    pub(crate) fn operation(&self, id: i64) -> Result<Option<Operation>> {
        let row = self
            .db
            .query_row(
                "SELECT id,kind,work_key,state,request,result,payload,job_id,txid,next_at,generation
            FROM operations WHERE id=?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, Option<String>>(8)?,
                        r.get::<_, i64>(9)?,
                        r.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()?;
        row.map(|r| {
            Ok(Operation {
                id: r.0,
                kind: match r.1.as_str() {
                    "answer" => WorkKind::Answer,
                    "judge" => WorkKind::Judge,
                    "mine" => WorkKind::Mine,
                    _ => bail!("invalid operation kind in state"),
                },
                key: r.2,
                persisted_state: std::cell::RefCell::new(r.3.clone()),
                generation: r.10,
                state: r.3,
                request: serde_json::from_str(&r.4)?,
                result: r.5.map(|s| serde_json::from_str(&s)).transpose()?,
                payload: r.6.map(|s| serde_json::from_str(&s)).transpose()?,
                job_id: r.7,
                txid: r.8,
                next_at: r.9,
            })
        })
        .transpose()
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> Result<Option<Operation>> {
        let id: Option<i64> = self.db.query_row("SELECT id FROM operations WHERE state IN
            ('generating','generated','prepared','dispatching','queued','unknown','included_pending','retry') ORDER BY id LIMIT 1", [], |r| r.get(0)).optional()?;
        match id {
            Some(id) => self.operation(id),
            None => Ok(None),
        }
    }

    fn has_table(&self, name: &str) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [name],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn record_retry_minimum(&self, id: i64, seconds: u64) -> Result<()> {
        self.record_retry_deadline(id, not_before(seconds))
    }

    pub(crate) fn record_retry_deadline(&self, id: i64, deadline: i64) -> Result<()> {
        self.db.execute(
            "INSERT INTO operation_timing VALUES (?1,?2)
            ON CONFLICT(operation_id) DO UPDATE SET retry_not_before=MAX(retry_not_before,excluded.retry_not_before)",
            params![id,deadline],
        )?;
        Ok(())
    }

    pub(crate) fn record_scope_retry_minimum(&self, scope: ReadScope, seconds: u64) -> Result<()> {
        let selector = match scope {
            ReadScope::Job => "job_id IS NOT NULL AND txid IS NULL",
            ReadScope::Receipt => "txid IS NOT NULL",
            _ => return Ok(()),
        };
        self.db.execute(
            &format!(
                "INSERT INTO operation_timing(operation_id,retry_not_before)
                SELECT id,?1 FROM operations WHERE state IN ('queued','unknown','included_pending')
                AND {selector} ON CONFLICT(operation_id) DO UPDATE SET
                retry_not_before=MAX(retry_not_before,excluded.retry_not_before)"
            ),
            [not_before(seconds)],
        )?;
        Ok(())
    }

    /// Shared by preparation, transactional admission, and read-only status.
    /// Stream narrow evidence columns; never load historical operation payloads.
    fn uncertainty_accounting(
        db: &Connection,
        config: &Config,
        excluding: Option<i64>,
        retry_of: Option<i64>,
        capture_blockers: bool,
    ) -> Result<UncertaintyAccounting> {
        let policy = &config.participation;
        let has_table = |name: &str| -> Result<bool> {
            Ok(db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [name],
                |r| r.get(0),
            )?)
        };
        let has_evidence = has_table("operation_evidence")?;
        let eligible = if has_evidence && has_table("operation_links")? {
            HISTORICAL_ANSWERS
        } else {
            "SELECT NULL AS operation_id,NULL AS accepted_answer_id WHERE 0"
        };
        let (evidence, blocked_since) = if has_evidence {
            (
                "LEFT JOIN operation_evidence e ON e.operation_id=o.id",
                "COALESCE(e.blocked_since,o.created_at)",
            )
        } else {
            ("", "o.created_at")
        };
        let (timing, floor) = if has_table("operation_timing")? {
            (
                "LEFT JOIN operation_timing t ON t.operation_id=o.id",
                "COALESCE(t.retry_not_before,o.next_at)",
            )
        } else {
            ("", "o.next_at")
        };
        let mut statement = db.prepare(&format!(
            "WITH historical AS ({eligible})
             SELECT o.id,o.state='dispatching',{blocked_since},{floor},h.accepted_answer_id
             FROM operations o {evidence} {timing}
             LEFT JOIN historical h ON h.operation_id=o.id
             WHERE o.id!=?1 AND o.state IN ('dispatching','queued','unknown','included_pending')
             ORDER BY o.id"
        ))?;
        let mut rows = statement.query([excluding.unwrap_or(-1)])?;
        let mut result = UncertaintyAccounting::default();
        let accepted_linked =
            policy.historical_unknown_answer_capacity == HistoricalAnswerCapacity::AcceptedLinked;
        let blocker_limit = u64::from(policy.max_unresolved_operations)
            + if accepted_linked {
                0
            } else {
                u64::from(policy.max_historical_unknown_answers)
            };
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let dispatched: bool = row.get(1)?;
            let since: i64 = row.get(2)?;
            let floor: i64 = row.get(3)?;
            let witness: Option<i64> = row.get(4)?;
            result.total += 1;
            result.eligible += u64::from(witness.is_some());
            let exempt = witness.is_some()
                && policy.mode == ParticipationMode::ParticipationFirst
                && (accepted_linked
                    || result.exempt < u64::from(policy.max_historical_unknown_answers));
            if exempt {
                result.exempt += 1;
                if result.historical.len() < HISTORICAL_EXAMPLE_LIMIT {
                    result.historical.push(HistoricalAnswer {
                        operation_id: id,
                        accepted_answer_id: witness.context("historical witness missing")?,
                    });
                }
            }
            if capture_blockers
                && (!accepted_linked || !exempt)
                && (result.blockers.len() as u64) < blocker_limit
            {
                result.blockers.push(id);
            }
            // Exemption affects capacity only, never floors or grace.
            result.writing |= dispatched;
            if dispatched {
                result.writing_operation = Some(id);
            }
            if floor > result.retry_not_before {
                result.retry_not_before = floor;
                result.floor_operation = Some(id);
            }
            let retry = Some(id) == retry_of;
            let retry_grace =
                i64::try_from(policy.uncertain_answer_retry_seconds).unwrap_or(i64::MAX);
            if retry {
                result.retry_operation = Some(id);
                result.retry_grace_until = result
                    .retry_grace_until
                    .max(since.saturating_add(retry_grace));
            }
            let grace = if retry {
                policy
                    .uncertainty_grace_seconds
                    .max(policy.uncertain_answer_retry_seconds)
            } else {
                policy.uncertainty_grace_seconds
            };
            let until = since.saturating_add(i64::try_from(grace).unwrap_or(i64::MAX));
            if until > result.grace_until {
                result.grace_until = until;
                result.grace_operation = Some(id);
            }
        }
        if has_evidence {
            // A proven refusal is not an uncertain effect, but Retry-After
            // remains an account admission floor even if rollover discards its
            // reusable payload. Do not add it to capacity, blockers, or grace.
            let refusal_floor: Option<(i64, i64)> = db.query_row(
                &format!(
                    "SELECT o.id,{floor} FROM operations o {evidence} {timing}
                     WHERE o.id!=?1 AND o.state NOT IN ('dispatching','queued','unknown','included_pending')
                     AND CASE WHEN json_valid(e.evidence) THEN
                        json_extract(e.evidence,'$.stage')='submit'
                        AND json_extract(e.evidence,'$.reason')='proven_not_accepted'
                     ELSE 0 END
                     ORDER BY {floor} DESC,o.id LIMIT 1"
                ),
                [excluding.unwrap_or(-1)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            if let Some((id, floor)) = refusal_floor
                && floor > result.retry_not_before
            {
                result.retry_not_before = floor;
                result.floor_operation = Some(id);
            }
        }
        Ok(result)
    }

    /// Append only changed direct witnesses. A NULL witness revokes eligibility.
    /// Called inside the dispatch transaction; captured revisions are immutable.
    fn capture_historical_revision(db: &Connection) -> Result<i64> {
        db.execute(&format!(
            "WITH eligible AS MATERIALIZED ({HISTORICAL_ANSWERS}),
             latest AS MATERIALIZED (
                SELECT e.* FROM historical_answer_accounting_events e
                WHERE NOT EXISTS(SELECT 1 FROM historical_answer_accounting_events newer
                    WHERE newer.original_id=e.original_id AND newer.revision>e.revision))
             INSERT INTO historical_answer_accounting_events(original_id,accepted_answer_id,observed_at)
             SELECT h.operation_id,h.accepted_answer_id,?1 FROM eligible h
             LEFT JOIN latest l ON l.original_id=h.operation_id
             WHERE l.accepted_answer_id IS NOT h.accepted_answer_id
             UNION ALL
             SELECT l.original_id,NULL,?1 FROM latest l
             WHERE l.accepted_answer_id IS NOT NULL
             AND NOT EXISTS(SELECT 1 FROM eligible h WHERE h.operation_id=l.original_id)"
        ), [now()])?;
        Ok(db.query_row(
            "SELECT COALESCE(MAX(revision),0) FROM historical_answer_accounting_events",
            [],
            |r| r.get(0),
        )?)
    }

    fn risk_decision(
        db: &Connection,
        config: &Config,
        op: &Operation,
    ) -> Result<Option<RiskDecision>> {
        // Retrying this operation must honor its own server floor, not only
        // the floors of other uncertain operations in the accounting below.
        let retry_not_before: i64 = db.query_row(
            "SELECT COALESCE((SELECT retry_not_before FROM operation_timing WHERE operation_id=?1),0)",
            [op.id],
            |row| row.get(0),
        )?;
        if retry_not_before > now() {
            return Ok(None);
        }
        let reload_blocked: bool = db.query_row(
            "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)",
            [],
            |r| r.get(0),
        )?;
        if reload_blocked {
            return Ok(None);
        }
        if op.kind != WorkKind::Answer && Self::answer_retry_reservation(db, config)?.is_some() {
            return Ok(None);
        }
        let policy = &config.participation;
        let epoch = op.request["solver"]["epoch"].as_u64();
        let retry_of: Option<i64> = db
            .query_row(
                "SELECT retry_of FROM operation_links WHERE operation_id=?1",
                [op.id],
                |r| r.get(0),
            )
            .optional()?;
        let accounting = Self::uncertainty_accounting(db, config, Some(op.id), retry_of, true)?;
        if accounting.active() + 1 > u64::from(policy.unresolved_limit(op.kind))
            || accounting.writing
            || accounting.retry_not_before > now()
        {
            return Ok(None);
        }
        if op.kind == WorkKind::Answer {
            let Some(epoch) = epoch else { return Ok(None) };
            let pattern = format!("{epoch}:%");
            let (attempts, accepted, uncertain): (u32, bool, bool) = db.query_row(
                "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0),
                COALESCE(MAX(o.state IN ('dispatching','queued','unknown','included_pending')),0)
                FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
                WHERE o.kind='answer' AND o.work_key LIKE ?1 AND o.id!=?2
                AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
                params![pattern,op.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            )?;
            if accepted
                || attempts >= policy.max_answer_attempts_per_epoch
                || (uncertain && retry_of.is_none())
            {
                return Ok(None);
            }
            if let Some(origin) = retry_of {
                let eligible: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 AND kind='answer'
                    AND work_key LIKE ?2 AND state IN ('queued','unknown') AND txid IS NULL AND payload IS NOT NULL)",
                    params![origin,pattern], |r| r.get(0),
                )?;
                if !eligible || !policy.retry_uncertain_answers {
                    return Ok(None);
                }
            }
        }
        if op.kind == WorkKind::Mine && config.schedule.mine_each_epoch {
            let Some(epoch) = epoch else { return Ok(None) };
            if Self::mine_epoch_attempted_in(db, epoch, Some(op.id))? {
                return Ok(None);
            }
        }
        let mut decision = RiskDecision {
            accounting,
            retry_of,
            grant: None,
        };
        if decision.accounting.total == 0 && retry_of.is_none() {
            return Ok(Some(decision));
        }
        if policy.mode == ParticipationMode::Strict || !policy.allows(op.kind) {
            return Ok(None);
        }
        if decision.accounting.retry_grace_until > now() {
            return Ok(None);
        }
        if policy.mode == ParticipationMode::Manual {
            let Some(epoch) = epoch else { return Ok(None) };
            decision.grant = db.query_row(
                "SELECT id FROM manual_grants WHERE epoch=?1 AND kind=?2 AND generation=?3 AND consumed_by IS NULL
                AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id)",
                params![i64::try_from(epoch)?,op.kind.as_str(),op.generation], |r| r.get(0),
            ).optional()?;
            if decision.grant.is_none() {
                return Ok(None);
            }
        } else if decision.accounting.grace_until > now() {
            return Ok(None);
        }
        Ok(Some(decision))
    }

    pub(crate) fn admission_allowed(&self, config: &Config, op: &Operation) -> Result<bool> {
        let control = self.control()?;
        Ok(!control.paused
            && control.generation == op.generation
            && config.mode(op.kind) == Mode::Active
            && op.next_at <= now()
            && Self::risk_decision(&self.db, config, op)?.is_some())
    }

    pub(crate) fn authorize(
        &mut self,
        config: &Config,
        epoch: u64,
        kind: WorkKind,
    ) -> Result<Value> {
        self.continuity()?;
        if config.participation.mode != ParticipationMode::Manual
            || !config.participation.allows(kind)
            || config.mode(kind) != Mode::Active
        {
            bail!(
                "manual authorization requires manual participation mode and an allowed active capability"
            );
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (paused, generation): (bool, i64) = tx.query_row(
            "SELECT paused,generation FROM control WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if paused {
            bail!("manual authorization requires resumed state");
        }
        let unresolved: u64 = tx.query_row(
            "SELECT COUNT(*) FROM operations WHERE state IN ('dispatching','queued','unknown','included_pending')",
            [], |r| r.get(0),
        )?;
        if unresolved + 1 > u64::from(config.participation.unresolved_limit(kind)) {
            bail!("manual authorization exceeds unresolved operation limit");
        }
        let (attempts,accepted,uncertain): (u32,bool,bool) = tx.query_row(
            "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0),
            COALESCE(MAX(o.state IN ('dispatching','queued','unknown','included_pending')),0)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind=?1 AND o.work_key LIKE ?2
            AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
            params![kind.as_str(),format!("{epoch}:%")], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        if kind == WorkKind::Answer
            && (accepted
                || attempts >= config.participation.max_answer_attempts_per_epoch
                || (uncertain && !config.participation.retry_uncertain_answers))
        {
            bail!("manual authorization cannot authorize a duplicate or exhausted answer attempt");
        }
        if kind == WorkKind::Mine && config.schedule.mine_each_epoch && attempts > 0 {
            bail!("manual authorization cannot authorize another mine in the same epoch");
        }
        let pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind=?2 AND generation=?3
            AND consumed_by IS NULL AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
            params![i64::try_from(epoch)?,kind.as_str(),generation], |r| r.get(0),
        )?;
        if pending {
            bail!("a pending grant already exists for this epoch, kind and generation");
        }
        tx.execute(
            "INSERT INTO manual_grants(epoch,kind,generation,created_at) VALUES (?1,?2,?3,?4)",
            params![i64::try_from(epoch)?, kind.as_str(), generation, now()],
        )
        .context("a grant already exists for this epoch, kind and generation")?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO events(at,code,kind) VALUES (?1,'participation_authorized',?2)",
            params![now(), kind.as_str()],
        )?;
        tx.commit()?;
        Ok(
            json!({"grant_id":id,"epoch":epoch,"kind":kind,"generation":generation,"one_dispatch":true}),
        )
    }

    pub(crate) fn uncertain_answer(&self, epoch: u64) -> Result<Option<Operation>> {
        let id: Option<i64> = self.db.query_row(
            "SELECT id FROM operations WHERE kind='answer' AND work_key LIKE ?1
            AND state IN ('queued','unknown') AND txid IS NULL AND payload IS NOT NULL ORDER BY id DESC LIMIT 1",
            [format!("{epoch}:%")], |r| r.get(0),
        ).optional()?;
        id.map(|id| self.operation(id))
            .transpose()
            .map(Option::flatten)
    }

    pub(crate) fn answer_retry_allowed(
        &self,
        config: &Config,
        original: &Operation,
    ) -> Result<bool> {
        Ok(self.answer_retry_blocker(config, original)?.is_none())
    }

    fn answer_retry_blocker(
        &self,
        config: &Config,
        original: &Operation,
    ) -> Result<Option<(&'static str, Option<i64>)>> {
        let epoch = original.request["solver"]["epoch"]
            .as_u64()
            .context("answer epoch missing")?;
        if let Some(blocker) = Self::answer_retry_policy_blocker(&self.db, config, epoch, None)? {
            return Ok(Some((blocker, None)));
        }
        let accounting =
            Self::uncertainty_accounting(&self.db, config, None, Some(original.id), false)?;
        self.uncertainty_blocker_with(config, WorkKind::Answer, Some(epoch), &accounting)
    }

    // Policy intent is shared by retry preparation and priority admission. Other
    // operations' temporary grace/floors must not erase an intended retry.
    fn answer_retry_policy_blocker(
        db: &Connection,
        config: &Config,
        epoch: u64,
        reusing: Option<i64>,
    ) -> Result<Option<&'static str>> {
        if config.participation.mode == ParticipationMode::Strict {
            return Ok(Some("strict_uncertainty"));
        }
        if !config.participation.retry_uncertain_answers {
            return Ok(Some("uncertain_retry_disabled"));
        }
        if !config.participation.allow_answer {
            return Ok(Some("participation_disabled"));
        }
        if db.query_row("SELECT paused FROM control WHERE singleton=1", [], |r| {
            r.get(0)
        })? {
            return Ok(Some("admission_paused"));
        }
        if config.mode(WorkKind::Answer) != Mode::Active {
            return Ok(Some("capability_not_active"));
        }
        let (attempts,accepted): (u32,bool) = db.query_row(
            "SELECT COUNT(CASE WHEN o.id!=COALESCE(?2,-1) THEN 1 END),
            COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind='answer' AND o.work_key LIKE ?1
            AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
            params![format!("{epoch}:%"),reusing], |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        if accepted {
            return Ok(Some("answer_already_accepted"));
        }
        if attempts >= config.participation.max_answer_attempts_per_epoch {
            return Ok(Some("answer_attempt_budget_exhausted"));
        }
        Ok(None)
    }

    /// A standalone answer refused before enqueue retries the same operation,
    /// not an uncertain original. Mirror risk_decision's policy gates without
    /// treating other operations' transient grace/floors/capacity as lost intent.
    fn refused_answer_reservation(
        db: &Connection,
        config: &Config,
        epoch: u64,
        generation: i64,
    ) -> Result<Option<AnswerRetryReservation>> {
        let candidate: Option<(i64, i64)> = db
            .query_row(
                "SELECT o.id,MAX(o.next_at,COALESCE(t.retry_not_before,o.next_at))
             FROM operations o JOIN operation_evidence e ON e.operation_id=o.id
             LEFT JOIN operation_timing t ON t.operation_id=o.id
             WHERE o.kind='answer' AND o.state='retry' AND o.generation=?1
             AND o.work_key LIKE ?2 AND json_extract(o.request,'$.solver.epoch')=?3
             AND o.payload IS NOT NULL AND o.job_id IS NULL AND o.txid IS NULL
             AND e.dispatch_sequence IS NOT NULL
             AND NOT EXISTS(SELECT 1 FROM operation_links WHERE operation_id=o.id)
             AND NOT EXISTS(SELECT 1 FROM operation_candidates WHERE operation_id=o.id)
             AND CASE WHEN json_valid(e.evidence) THEN
                json_extract(e.evidence,'$.stage')='submit'
                AND json_extract(e.evidence,'$.route')='answer'
                AND json_extract(e.evidence,'$.reason')='proven_not_accepted'
             ELSE 0 END
             ORDER BY o.id LIMIT 1",
                params![generation, format!("{epoch}:%"), epoch],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((id, ready_at)) = candidate else {
            return Ok(None);
        };
        if ready_at > now() {
            return Ok(None);
        }
        let (attempts, accepted, uncertain): (u32, bool, bool) = db.query_row(
            "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0),
             COALESCE(MAX(o.state IN ('dispatching','queued','unknown','included_pending')),0)
             FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
             WHERE o.kind='answer' AND o.work_key LIKE ?1 AND o.id!=?2
             AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN
                ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
            params![format!("{epoch}:%"),id],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        if accepted || uncertain || attempts >= config.participation.max_answer_attempts_per_epoch {
            return Ok(None);
        }
        let other_effect: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id!=?1
             AND state IN ('dispatching','queued','unknown','included_pending'))",
            [id],
            |r| r.get(0),
        )?;
        if other_effect {
            if config.participation.mode == ParticipationMode::Strict
                || !config.participation.allow_answer
            {
                return Ok(None);
            }
            if config.participation.mode == ParticipationMode::Manual {
                let granted: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind='answer'
                     AND generation=?2 AND consumed_by IS NULL AND NOT EXISTS(
                        SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
                    params![epoch, generation],
                    |r| r.get(0),
                )?;
                if !granted {
                    return Ok(None);
                }
            }
        }
        Ok(Some(AnswerRetryReservation {
            original_operation_id: id,
            ready_at,
            same_operation: true,
        }))
    }

    /// A derived, restart-safe priority fence, not permission to submit. Start
    /// only at the original's own retry point; retain every other admission gate.
    fn answer_retry_reservation(
        db: &Connection,
        config: &Config,
    ) -> Result<Option<AnswerRetryReservation>> {
        let epoch: Option<u64> = db
            .query_row(
                "SELECT epoch FROM health_evidence WHERE singleton=1 AND answered=0",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(epoch) = epoch else { return Ok(None) };
        let (generation, reload_blocked, paused): (i64, bool, bool) = db.query_row(
            "SELECT generation,COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0),paused
             FROM control WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if reload_blocked || paused || config.mode(WorkKind::Answer) != Mode::Active {
            return Ok(None);
        }
        if let Some(reservation) = Self::refused_answer_reservation(db, config, epoch, generation)?
        {
            return Ok(Some(reservation));
        }
        if config.participation.mode == ParticipationMode::Manual {
            let granted: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind='answer'
                 AND generation=?2 AND consumed_by IS NULL AND NOT EXISTS(
                    SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
                params![epoch, generation],
                |r| r.get(0),
            )?;
            if !granted {
                return Ok(None);
            }
        }
        let pattern = format!("{epoch}:%");
        let candidate: Option<(i64, i64, i64)> = db.query_row(
            "SELECT o.id,COALESCE(e.blocked_since,o.created_at),COALESCE(t.retry_not_before,o.next_at)
             FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
             LEFT JOIN operation_timing t ON t.operation_id=o.id
             WHERE o.kind='answer' AND o.work_key LIKE ?1
             AND o.state IN ('queued','unknown') AND o.txid IS NULL AND o.payload IS NOT NULL
             ORDER BY o.id DESC LIMIT 1",
            [&pattern], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        let Some((id, since, floor)) = candidate else {
            return Ok(None);
        };
        // A linked operation refused before enqueue can retry its own payload
        // without consuming a third operation. Match transactional admission's
        // exclusion of that operation, but never discount stale or bound work.
        // Fresh retry preparation still calls the policy check with no exclusion.
        let reusing: Option<i64> = db
            .query_row(
                "SELECT o.id FROM operations o JOIN operation_links l ON l.operation_id=o.id
             WHERE l.retry_of=?1 AND o.kind='answer' AND o.work_key LIKE ?2
             AND o.generation=?3 AND o.state IN ('prepared','generated','retry')
             AND o.payload IS NOT NULL AND o.job_id IS NULL AND o.txid IS NULL
             AND json_extract(o.request,'$.solver.epoch')=?4
             ORDER BY o.id LIMIT 1",
                params![id, pattern, generation, epoch],
                |r| r.get(0),
            )
            .optional()?;
        if Self::answer_retry_policy_blocker(db, config, epoch, reusing)?.is_some() {
            return Ok(None);
        }
        // Only unsent preparation failures close intent. A stale discarded
        // draft or a dispatched rejection may still permit another retry.
        let preparation_closed: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=(
                SELECT MAX(id) FROM operations WHERE kind='answer' AND work_key LIKE ?1)
             AND id>?2 AND generation=?3
             AND state IN ('rejected','model_unknown','locally_rejected')
             AND job_id IS NULL AND txid IS NULL
             AND NOT EXISTS(SELECT 1 FROM operation_evidence e
                WHERE e.operation_id=operations.id AND e.dispatch_sequence IS NOT NULL))",
            params![pattern, id, generation],
            |r| r.get(0),
        )?;
        if preparation_closed {
            return Ok(None);
        }
        let delay = if config.participation.mode == ParticipationMode::Manual {
            config.participation.uncertain_answer_retry_seconds
        } else {
            config
                .participation
                .uncertain_answer_retry_seconds
                .max(config.participation.uncertainty_grace_seconds)
        };
        let ready_at = floor.max(since.saturating_add(i64::try_from(delay).unwrap_or(i64::MAX)));
        Ok((ready_at <= now()).then_some(AnswerRetryReservation {
            original_operation_id: id,
            ready_at,
            same_operation: false,
        }))
    }

    #[cfg(test)]
    fn uncertainty_open(
        &self,
        config: &Config,
        kind: WorkKind,
        epoch: Option<u64>,
        retry_of: Option<i64>,
    ) -> Result<bool> {
        let accounting = Self::uncertainty_accounting(&self.db, config, None, retry_of, false)?;
        self.uncertainty_open_with(config, kind, epoch, &accounting)
    }

    fn uncertainty_open_with(
        &self,
        config: &Config,
        kind: WorkKind,
        epoch: Option<u64>,
        accounting: &UncertaintyAccounting,
    ) -> Result<bool> {
        Ok(self
            .uncertainty_blocker_with(config, kind, epoch, accounting)?
            .is_none())
    }

    fn manual_authorized(&self, kind: WorkKind, epoch: Option<u64>) -> Result<Option<bool>> {
        let Some(epoch) = epoch else { return Ok(None) };
        if !self.has_table("manual_grants")? || !self.has_table("manual_grant_revocations")? {
            return Ok(None);
        }
        Ok(Some(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind=?2 AND generation=?3 AND consumed_by IS NULL
             AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
            params![i64::try_from(epoch)?,kind.as_str(),self.control()?.generation],
            |r| r.get(0),
        )?))
    }

    fn uncertainty_blocker_with(
        &self,
        config: &Config,
        kind: WorkKind,
        epoch: Option<u64>,
        accounting: &UncertaintyAccounting,
    ) -> Result<Option<(&'static str, Option<i64>)>> {
        let policy = &config.participation;
        if accounting.total == 0 {
            return Ok((accounting.retry_not_before > now())
                .then_some(("retained_retry_minimum", Some(accounting.retry_not_before))));
        }
        if policy.mode == ParticipationMode::Strict {
            return Ok(Some(("strict_uncertainty", None)));
        }
        if !policy.allows(kind) {
            return Ok(Some(("participation_disabled", None)));
        }
        if accounting.active() + 1 > u64::from(policy.unresolved_limit(kind)) {
            let reason = if kind != WorkKind::Answer
                && accounting.active() < u64::from(policy.max_unresolved_operations)
            {
                "answer_capacity_reserved"
            } else {
                "unresolved_capacity"
            };
            return Ok(Some((reason, None)));
        }
        if accounting.writing {
            return Ok(Some(("effect_in_flight", None)));
        }
        let current = now();
        if accounting.retry_not_before > current {
            return Ok(Some((
                "retained_retry_minimum",
                Some(accounting.retry_not_before),
            )));
        }
        if accounting.retry_grace_until > current {
            return Ok(Some((
                "uncertain_answer_retry_delay",
                Some(accounting.retry_grace_until),
            )));
        }
        if policy.mode == ParticipationMode::Manual {
            let granted = self.manual_authorized(kind, epoch)?.unwrap_or(false);
            if !granted {
                return Ok(Some(("manual_authorization_required", None)));
            }
        } else if accounting.grace_until > current {
            return Ok(Some(("uncertainty_grace", Some(accounting.grace_until))));
        }
        Ok(None)
    }

    pub(crate) fn mine_epoch_attempted(&self, epoch: u64) -> Result<bool> {
        Self::mine_epoch_attempted_in(&self.db, epoch, None)
    }

    fn mine_epoch_attempted_in(
        db: &Connection,
        epoch: u64,
        excluding: Option<i64>,
    ) -> Result<bool> {
        // Adopted journals lack dispatch sequences. A retained creation event
        // proves complete later history; missing/pruned history is conservative.
        Ok(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind='mine' AND o.work_key LIKE ?1 AND (?2 IS NULL OR o.id!=?2)
            AND (e.dispatch_sequence IS NOT NULL OR o.state IN
            ('dispatching','retry','queued','unknown','included_pending','confirmed','final','completed','rejected','stale','refused')
            OR (o.state='discarded' AND e.operation_id IS NULL AND
                (EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code='dispatch_intent')
                OR NOT EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code='prepared')))))",
            params![format!("{epoch}:%"),excluding], |r| r.get(0),
        )?)
    }

    /// At most two bound candidates per cycle; selection does not consume fairness.
    pub(crate) fn reconciliation_batch(&self) -> Result<Vec<Operation>> {
        let cursor: i64 = self.db.query_row(
            "SELECT COALESCE(CAST(cursor AS INTEGER),0) FROM schedule WHERE kind='reconciliation'",
            [], |r| r.get(0),
        ).optional()?.unwrap_or(0);
        let mut statement = self.db.prepare(
            "SELECT o.id FROM operations o
            LEFT JOIN read_backoff r ON r.scope=CASE WHEN o.txid IS NOT NULL THEN 'receipt' ELSE 'job' END
            LEFT JOIN operation_timing t ON t.operation_id=o.id
            WHERE o.state IN ('queued','unknown','included_pending')
            AND (o.job_id IS NOT NULL OR o.txid IS NOT NULL) AND o.next_at<=?1
            AND COALESCE(r.next_at,0)<=?1
            AND (o.txid IS NOT NULL OR COALESCE(t.retry_not_before,o.next_at)<=?1)
            ORDER BY CASE WHEN o.id>?2 THEN 0 ELSE 1 END,o.id LIMIT 2",
        )?;
        let ids = statement
            .query_map(params![now(), cursor], |r| r.get::<_, i64>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                self.operation(id)?
                    .context("reconciliation operation missing")
            })
            .collect()
    }

    pub(crate) fn reconciliation_attempted(&self, operation: i64) -> Result<()> {
        self.db.execute(
            "INSERT INTO schedule(kind,next_at,cursor) VALUES ('reconciliation',0,?1)
             ON CONFLICT(kind) DO UPDATE SET cursor=excluded.cursor",
            [operation.to_string()],
        )?;
        Ok(())
    }

    pub(crate) fn effect(&self) -> Result<Option<Operation>> {
        let id: Option<i64> = self
            .db
            .query_row(
                "SELECT id FROM operations WHERE state IN
            ('dispatching','queued','unknown','included_pending') ORDER BY id LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        id.map(|id| self.operation(id))
            .transpose()
            .map(Option::flatten)
    }

    pub(crate) fn preparation(&self, kind: WorkKind) -> Result<Option<Operation>> {
        let id: Option<i64> = self
            .db
            .query_row(
                "SELECT id FROM operations WHERE kind=?1 AND state IN
            ('generating','generated','prepared','retry') ORDER BY id LIMIT 1",
                [kind.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        id.map(|id| self.operation(id))
            .transpose()
            .map(Option::flatten)
    }

    pub(crate) fn capture_policy(
        &self,
        id: i64,
        policy: &Value,
        model_seconds: Option<u64>,
        http_seconds: Option<u64>,
    ) -> Result<()> {
        self.db.execute(
            "INSERT INTO operation_evidence(operation_id,policy,model_deadline,http_deadline)
            VALUES (?1,?2,?3,?4) ON CONFLICT(operation_id) DO UPDATE SET
            policy=COALESCE(operation_evidence.policy,excluded.policy),
            model_deadline=COALESCE(operation_evidence.model_deadline,excluded.model_deadline),
            http_deadline=COALESCE(excluded.http_deadline,operation_evidence.http_deadline)",
            params![
                id,
                serde_json::to_string(policy)?,
                model_seconds.map(not_before),
                http_seconds.map(not_before)
            ],
        )?;
        Ok(())
    }

    pub(crate) fn record_evidence(&self, id: i64, evidence: &Value) -> Result<()> {
        let text = serde_json::to_string(evidence)?;
        if text.len() > 4096 {
            bail!("diagnostic evidence exceeds bound");
        }
        self.db.execute("INSERT INTO operation_evidence(operation_id,evidence,observed_at) VALUES (?1,?2,?3)
            ON CONFLICT(operation_id) DO UPDATE SET evidence=excluded.evidence,observed_at=excluded.observed_at",
            params![id,text,now()])?;
        Ok(())
    }

    fn captured_retry_floor(evidence: &Value, observed_at: Option<i64>) -> i64 {
        evidence["retry_after_seconds"]
            .as_u64()
            .map(|seconds| {
                observed_at
                    .filter(|at| *at >= 0)
                    .map(|at| {
                        at.saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX))
                            .saturating_add(1)
                    })
                    .unwrap_or(i64::MAX)
            })
            .unwrap_or(0)
    }

    pub(crate) fn record_submission_evidence(
        &self,
        id: i64,
        evidence: &Value,
        candidates: &Value,
    ) -> Result<()> {
        // No response-derived evidence may commit without its server floor.
        let tx = self.db.unchecked_transaction()?;
        self.record_candidates(id, candidates)?;
        self.record_evidence(id, evidence)?;
        if let Some(seconds) = evidence["retry_after_seconds"].as_u64() {
            self.record_retry_minimum(id, seconds)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn record_candidates(&self, id: i64, candidates: &Value) -> Result<()> {
        if candidates["job_id"].is_null()
            && candidates["transaction_ids"]
                .as_array()
                .is_none_or(Vec::is_empty)
        {
            return Ok(());
        }
        let text = serde_json::to_string(candidates)?;
        if text.len() > 4096 {
            bail!("private candidate evidence exceeds bound");
        }
        // Preserve the first nonempty set; differing later sets mark incomplete
        // coverage rather than turning polling into another unbounded journal.
        self.db.execute(
            "INSERT INTO operation_candidates(operation_id,candidates) VALUES (?1,?2)
            ON CONFLICT(operation_id) DO UPDATE SET truncated=CASE
            WHEN candidates!=excluded.candidates THEN 1 ELSE truncated END",
            params![id, text],
        )?;
        Ok(())
    }

    pub(crate) fn attempt_count(&self, kind: WorkKind, key: &str) -> Result<u32> {
        Ok(self.db.query_row(
            "SELECT COUNT(*) FROM operations WHERE kind=?1 AND work_key=?2 COLLATE NOCASE",
            params![kind.as_str(), key],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn model_budget_used(&self, kind: WorkKind, key: &str) -> Result<u32> {
        Ok(self.db.query_row(
            "SELECT COUNT(*) FROM operations WHERE kind=?1 AND work_key=?2 COLLATE NOCASE
            AND state NOT IN ('prelaunch_failed','abandoned_model')
            AND NOT EXISTS(SELECT 1 FROM operation_links l WHERE l.operation_id=operations.id AND l.payload_reused=1)",
            params![kind.as_str(), key],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn retry_models(&mut self, config: &Config) -> Result<()> {
        self.db.execute("UPDATE operations SET state=CASE WHEN state='model_unknown'
            THEN 'superseded_model_unknown' ELSE 'retry_model' END,updated_at=?1
            WHERE (state='rejected' OR (state='model_unknown' AND ?3))
            AND payload IS NULL AND job_id IS NULL AND txid IS NULL
            AND (SELECT COUNT(*) FROM operations b WHERE b.kind=operations.kind AND b.work_key=operations.work_key
                AND b.state NOT IN ('prelaunch_failed','abandoned_model')
                AND NOT EXISTS(SELECT 1 FROM operation_links l WHERE l.operation_id=b.id AND l.payload_reused=1)) < ?2",
            params![now(),config.preparation.max_attempts_per_work,config.preparation.retry_uncertain])?;
        Ok(())
    }

    pub(crate) fn awaiting_finality(&self, kind: WorkKind) -> Result<Option<Operation>> {
        let id:Option<i64> = self.db.query_row("SELECT id FROM operations WHERE state='confirmed' AND kind=?1 AND next_at<=?2 ORDER BY next_at,id LIMIT 1",
            params![kind.as_str(),now()],|r|r.get(0)).optional()?;
        match id {
            Some(id) => self.operation(id),
            None => Ok(None),
        }
    }

    pub(crate) fn attempted(&self, kind: WorkKind, key: &str) -> Result<bool> {
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE kind=?1 AND work_key=?2 COLLATE NOCASE AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model','retry_model','superseded_model_unknown'))",
            params![kind.as_str(),key], |r| r.get(0))?)
    }

    fn answer_epoch_accepted(&self, epoch: u64) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE kind='answer' AND work_key LIKE ?1
            AND txid IS NOT NULL AND state IN ('included_pending','confirmed','final'))",
            [format!("{epoch}:%")],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn answer_epoch_attempted(&self, epoch: u64) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE kind='answer' AND work_key LIKE ?1
            AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model','retry_model','superseded_model_unknown'))",
            [format!("{epoch}:%")],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn next_at(&self, kind: WorkKind) -> Result<i64> {
        Ok(self
            .db
            .query_row(
                "SELECT next_at FROM schedule WHERE kind=?1",
                [kind.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }
    pub(crate) fn defer(&self, kind: WorkKind, seconds: u64) -> Result<()> {
        self.db.execute("INSERT INTO schedule(kind,next_at) VALUES (?1,?2) ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at",
            params![kind.as_str(),not_before(seconds)])?;
        Ok(())
    }

    pub(crate) fn work_revision(&self) -> Result<i64> {
        Ok(self.db.query_row(
            "SELECT COALESCE(MAX(id),0) FROM events WHERE operation_id IS NOT NULL",
            [],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn wake_delay(&self, config: &Config, fallback: u64) -> Result<u64> {
        let current = now();
        let mut deadline = current.saturating_add(fallback.min(i64::MAX as u64) as i64);
        for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
            if config.mode(kind) == Mode::Off {
                continue;
            }
            let scope = if kind == WorkKind::Judge {
                ReadScope::Assignments
            } else {
                ReadScope::Challenge
            };
            let next = self.next_at(kind)?.max(self.read_backoff(scope)?.next_at);
            if next > current {
                deadline = deadline.min(next);
            }
        }
        let mut job_not_before = 0;
        for scope in ReadScope::ALL {
            let next = self.read_backoff(scope)?.next_at;
            if scope == ReadScope::Job {
                job_not_before = next;
            }
            if next > current {
                deadline = deadline.min(next);
            }
        }
        // Only opted-in bound queued jobs contribute already-due deadlines.
        // Their endpoint and durable retry fences prevent a wake/read busy loop.
        let operation: Option<i64> = self.db.query_row(
            "SELECT MIN(CASE WHEN ?3 AND o.state='queued' AND o.job_id IS NOT NULL AND o.txid IS NULL
                THEN MAX(o.next_at,COALESCE(t.retry_not_before,o.next_at),?2) ELSE o.next_at END)
             FROM operations o LEFT JOIN operation_timing t ON t.operation_id=o.id
             WHERE o.state IN ('prepared','generated','retry','queued','unknown','included_pending')
                AND (o.next_at>?1 OR (?3 AND o.state='queued' AND o.job_id IS NOT NULL AND o.txid IS NULL))",
            params![current,job_not_before,config.schedule.queued_job_polling.is_some()],
            |r|r.get(0))?;
        if let Some(next) = operation {
            deadline = deadline.min(next);
        }
        Ok(deadline.saturating_sub(current).max(1) as u64)
    }

    pub(crate) fn defer_until(&self, kind: WorkKind, deadline: i64) -> Result<()> {
        self.db.execute(
            "INSERT INTO schedule(kind,next_at) VALUES (?1,?2)
            ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at",
            params![kind.as_str(), deadline],
        )?;
        Ok(())
    }

    pub(crate) fn record_assignment_selection(
        &self,
        revision: &str,
        generation: i64,
        observed_count: usize,
        inventory_complete: bool,
        eligible: bool,
    ) -> Result<()> {
        self.db.execute(
            "INSERT INTO assignment_selection SELECT 1,?1,?2,?3,?4,?5,?6
            WHERE EXISTS (SELECT 1 FROM control WHERE singleton=1 AND generation=?2)
            ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,
            generation=excluded.generation,observed_at=excluded.observed_at,
            observed_count=excluded.observed_count,inventory_complete=excluded.inventory_complete,
            eligible=excluded.eligible",
            params![
                revision,
                generation,
                now(),
                observed_count as u64,
                inventory_complete,
                eligible
            ],
        )?;
        Ok(())
    }

    pub(crate) fn cancel_read(&self, scope: ReadScope) -> Result<()> {
        // Cancellation is neither an HTTP failure nor validated observation.
        // Preserve prior success/failure evidence and all retained retry floors.
        self.db.execute(
            "UPDATE read_observations SET in_flight=0,finished_at=?2
            WHERE scope=?1 AND in_flight=1",
            params![scope.as_str(), now()],
        )?;
        Ok(())
    }

    pub(crate) fn read_started(&self, scope: ReadScope) -> Result<()> {
        if scope == ReadScope::Assignments {
            self.db.execute("DELETE FROM assignment_selection", [])?;
        }
        self.db.execute(
            "INSERT INTO read_observations(scope,in_flight,started_at) VALUES (?1,1,?2)
            ON CONFLICT(scope) DO UPDATE SET in_flight=1,started_at=excluded.started_at",
            params![scope.as_str(), now()],
        )?;
        Ok(())
    }

    pub(crate) fn read_finished(
        &self,
        scope: ReadScope,
        status: Option<u16>,
        category: Option<&str>,
    ) -> Result<()> {
        self.db.execute("UPDATE read_observations SET in_flight=0,finished_at=?2,status=?3,
            failure_category=?4,last_http_success_at=CASE WHEN ?3>=200 AND ?3<300 THEN ?2 ELSE last_http_success_at END
            WHERE scope=?1", params![scope.as_str(),now(),status,category])?;
        Ok(())
    }

    pub(crate) fn reschedule_read(
        &self,
        scope: ReadScope,
        base: u64,
        cap: u64,
        jitter: u64,
    ) -> Result<()> {
        let old = self.read_backoff(scope)?;
        if old.failures == 0 {
            return Ok(());
        }
        let timing: Option<(Option<i64>, i64, i64)> = self
            .db
            .query_row(
                "SELECT last_failure_at,server_not_before,retained_conservative_floor FROM read_observations WHERE scope=?1",
                [scope.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((Some(failed_at), floor, legacy_floor)) = timing else {
            return Ok(());
        };
        let local = failed_at
            .saturating_add(read_delay(old.failures, base, cap, jitter).min(i64::MAX as u64) as i64)
            .saturating_add(1);
        let next = local.max(floor).max(legacy_floor);
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE read_observations SET local_next_at=?2 WHERE scope=?1",
            params![scope.as_str(), local],
        )?;
        tx.execute(
            "UPDATE read_backoff SET next_at=?2 WHERE scope=?1",
            params![scope.as_str(), next],
        )?;
        if scope == ReadScope::Challenge {
            tx.execute(
                "UPDATE schedule SET next_at=?2 WHERE kind IN ('answer','mine') AND next_at=?1",
                params![old.next_at, next],
            )?;
        } else if scope == ReadScope::Assignments {
            tx.execute(
                "UPDATE schedule SET next_at=?2 WHERE kind='judge' AND next_at=?1",
                params![old.next_at, next],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn reads(&self) -> Result<Value> {
        let mut rows = Vec::with_capacity(ReadScope::ALL.len());
        let has_backoff = self.has_table("read_backoff")?;
        let has_observations = self.has_table("read_observations")?;
        for scope in ReadScope::ALL {
            let backoff = if has_backoff {
                self.read_backoff(scope)?
            } else {
                ReadBackoff::default()
            };
            let detail = if has_observations {
                self.db.query_row("SELECT in_flight,started_at,finished_at,last_http_success_at,last_success_at,
                    last_failure_at,failure_category,status,local_next_at,server_not_before,retained_conservative_floor
                    FROM read_observations WHERE scope=?1",[scope.as_str()],|r| {
                    let category: Option<String> = r.get(6)?;
                    Ok(json!({"state":if r.get::<_,bool>(0)? {"in_flight"} else {"idle"},
                        "started_at":r.get::<_,Option<i64>>(1)?,"finished_at":r.get::<_,Option<i64>>(2)?,
                        "last_http_success_at":r.get::<_,Option<i64>>(3)?,"last_success_at":r.get::<_,Option<i64>>(4)?,
                        "last_failure_at":r.get::<_,Option<i64>>(5)?,"failure_category":category.as_deref().map(safe_read_category),
                        "status":r.get::<_,Option<u16>>(7)?,"local_next_at":r.get::<_,i64>(8)?,
                        "server_not_before":r.get::<_,i64>(9)?,
                        "retained_conservative_floor":r.get::<_,i64>(10)?}))
                }).optional()?
            } else {
                None
            };
            let mut detail = detail.unwrap_or_else(|| {
                json!({"state":"idle","started_at":null,"finished_at":null,
                "last_http_success_at":null,"last_success_at":null,"last_failure_at":null,
                "failure_category":null,"status":null,"local_next_at":0,"server_not_before":0,
                "retained_conservative_floor":backoff.next_at})
            });
            detail["scope"] = json!(scope.as_str());
            detail["failures"] = json!(backoff.failures);
            detail["next_at"] = json!(backoff.next_at);
            detail["due_in_seconds"] = json!(backoff.next_at.saturating_sub(now()).max(0));
            rows.push(detail);
        }
        Ok(json!(rows))
    }

    pub(crate) fn read_backoff(&self, scope: ReadScope) -> Result<ReadBackoff> {
        Ok(self
            .db
            .query_row(
                "SELECT failures,next_at FROM read_backoff WHERE scope=?1",
                [scope.as_str()],
                |row| {
                    Ok(ReadBackoff {
                        failures: row.get(0)?,
                        next_at: row.get(1)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }

    pub(crate) fn fail_read(
        &self,
        scope: ReadScope,
        retry_seconds: u64,
        cap_seconds: u64,
        jitter_seconds: u64,
        server_minimum: Option<u64>,
    ) -> Result<ReadBackoff> {
        let tx = self.db.unchecked_transaction()?;
        let state = self.fail_read_in(
            &tx,
            scope,
            retry_seconds,
            cap_seconds,
            jitter_seconds,
            server_minimum,
        )?;
        tx.commit()?;
        Ok(state)
    }

    fn fail_read_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        scope: ReadScope,
        retry_seconds: u64,
        cap_seconds: u64,
        jitter_seconds: u64,
        server_minimum: Option<u64>,
    ) -> Result<ReadBackoff> {
        let failures = self.read_backoff(scope)?.failures.saturating_add(1);
        let local = not_before(read_delay(
            failures,
            retry_seconds,
            cap_seconds,
            jitter_seconds,
        ));
        let (prior_floor, legacy_floor): (i64, i64) = self.db.query_row(
            "SELECT server_not_before,retained_conservative_floor FROM read_observations WHERE scope=?1",
            [scope.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?.unwrap_or_default();
        // The old API included jitter after the server minimum. Keep that conservative rule.
        let floor = prior_floor.max(server_minimum.map_or(0, |seconds| {
            not_before(seconds.saturating_add(jitter_seconds))
        }));
        let state = ReadBackoff {
            failures,
            next_at: local.max(floor).max(legacy_floor),
        };
        tx.execute(
            "INSERT INTO read_backoff(scope,failures,next_at) VALUES (?1,?2,?3)
            ON CONFLICT(scope) DO UPDATE SET failures=excluded.failures,next_at=excluded.next_at",
            params![scope.as_str(), state.failures, state.next_at],
        )?;
        tx.execute("INSERT INTO read_observations(scope,last_failure_at,failure_category,local_next_at,server_not_before)
            VALUES (?1,?2,'unusable_response',?3,?4) ON CONFLICT(scope) DO UPDATE SET
            last_failure_at=excluded.last_failure_at,local_next_at=excluded.local_next_at,
            server_not_before=excluded.server_not_before,
            failure_category=COALESCE(read_observations.failure_category,'unusable_response')",
            params![scope.as_str(),now(),local,floor])?;
        Ok(state)
    }

    pub(crate) fn reset_read(&self, scope: ReadScope) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        Self::reset_read_in(&tx, scope)?;
        tx.commit()?;
        Ok(())
    }

    fn reset_read_in(tx: &rusqlite::Transaction<'_>, scope: ReadScope) -> Result<()> {
        tx.execute("DELETE FROM read_backoff WHERE scope=?1", [scope.as_str()])?;
        tx.execute(
            "INSERT INTO read_observations(scope,last_success_at) VALUES (?1,?2)
            ON CONFLICT(scope) DO UPDATE SET last_success_at=excluded.last_success_at,
            local_next_at=0,server_not_before=0,retained_conservative_floor=0,failure_category=NULL",
            params![scope.as_str(), now()],
        )?;
        Ok(())
    }
    pub(crate) fn observe(&self, epoch: u64, answered: bool) -> Result<()> {
        let epoch = i64::try_from(epoch).context("epoch out of range")?;
        let tx = self.db.unchecked_transaction()?;
        let (previous_epoch, previous_answered): (Option<i64>, Option<bool>) = tx
            .query_row(
                "SELECT epoch,answered FROM health_evidence WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((None, None));
        let observed_at = now();
        let evidence = if answered {
            "challenge_answered"
        } else {
            "challenge_unanswered"
        };
        // Epoch transitions, not repeated polls, start the grace clock. Legacy
        // observations acquire evidence on their first new authenticated read.
        if previous_epoch != Some(epoch) {
            tx.execute(
                "INSERT INTO events(at,code) VALUES (?1,'epoch_observed')",
                [observed_at],
            )?;
        }
        if previous_epoch != Some(epoch) || previous_answered != Some(answered) {
            tx.execute(
                "INSERT INTO events(at,code) VALUES (?1,?2)",
                params![observed_at, evidence],
            )?;
        }
        tx.execute(
            "INSERT INTO health_evidence(singleton,epoch,first_observed_at,answered)
             VALUES (1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET
             first_observed_at=CASE WHEN health_evidence.epoch=excluded.epoch
                 THEN health_evidence.first_observed_at ELSE excluded.first_observed_at END,
             epoch=excluded.epoch,answered=excluded.answered",
            params![epoch, observed_at, answered],
        )?;
        tx.execute("INSERT INTO observation VALUES (1,?1,?2) ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,observed_at=excluded.observed_at",
            params![epoch,observed_at])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn history(&self) -> Result<Vec<String>> {
        let mut stmt = self.db.prepare("SELECT payload FROM operations WHERE kind='answer' AND payload IS NOT NULL
            AND state IN ('queued','unknown','included_pending','confirmed','final') ORDER BY id DESC LIMIT 8")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut answers = Vec::new();
        for row in rows {
            let payload: Value = serde_json::from_str(&row?)?;
            if let Some(answer) = payload.get("answer").and_then(Value::as_str) {
                answers.push(answer.to_owned());
            }
        }
        answers.reverse();
        Ok(answers)
    }

    pub(crate) fn runtime_state(&self, config: &Config, reload_blocked: bool) -> Result<()> {
        self.continuity()?;
        let tx = self.db.unchecked_transaction()?;
        tx.execute("INSERT INTO runtime_policy VALUES (1,?1) ON CONFLICT(singleton) DO UPDATE SET policy=excluded.policy",
            [serde_json::to_string(&json!({"timeouts":config.timeouts,"schedule":config.schedule,
                "preparation":config.preparation,"participation":config.participation,
                "build":crate::runtime::build_info()}))?])?;
        tx.execute(
            "INSERT INTO runtime_state VALUES (1,?1,?2,?3,?4) ON CONFLICT(singleton) DO UPDATE SET
            effective_revision=excluded.effective_revision,reload_blocked=excluded.reload_blocked,
            capabilities=excluded.capabilities,observed_at=excluded.observed_at",
            params![
                config.revision()?,
                reload_blocked,
                serde_json::to_string(&config.capabilities)?,
                now()
            ],
        )?;
        tx.execute(
            "INSERT INTO events(at,code) SELECT ?1,'controller_running'
             WHERE COALESCE((SELECT code FROM events WHERE code IN
             ('controller_running','runtime_stopped') ORDER BY id DESC LIMIT 1),'') != 'controller_running'",
            [now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn heartbeat(&self) -> Result<()> {
        self.db.execute(
            "UPDATE runtime_state SET observed_at=?1 WHERE singleton=1 AND observed_at<?1",
            [now()],
        )?;
        Ok(())
    }

    /// Persist the completed read, identity evidence and retry floor together.
    /// A failed write must never leave a durable rejection paired with old identity.
    pub(crate) fn complete_identity_read(
        &self,
        status: Option<u16>,
        category: Option<&str>,
        outcome: HostedIdentityOutcome,
        retry: (u64, u64, u64),
        minimum: Option<u64>,
    ) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        self.read_finished(ReadScope::Identity, status, category)?;
        Self::write_identity_outcome(&tx, outcome)?;
        if outcome == HostedIdentityOutcome::Verified {
            Self::reset_read_in(&tx, ReadScope::Identity)?;
        } else {
            self.fail_read_in(&tx, ReadScope::Identity, retry.0, retry.1, retry.2, minimum)?;
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_identity_outcome(&self, outcome: HostedIdentityOutcome) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        Self::write_identity_outcome(&tx, outcome)?;
        tx.commit()?;
        Ok(())
    }

    // Skipped/cancelled reads never call this; only a match clears rejection.
    fn write_identity_outcome(
        tx: &rusqlite::Transaction<'_>,
        outcome: HostedIdentityOutcome,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO hosted_identity_evidence VALUES(1,?1,?2,
                CASE WHEN ?1='verified' THEN ?2 ELSE
                    (SELECT last_success_at FROM read_observations WHERE scope='identity'
                     AND (SELECT hosted_identity_verified FROM health_evidence WHERE singleton=1)=1)
                END,?3,
                CASE WHEN ?1='verified' THEN 0 ELSE
                    COALESCE((SELECT hosted_identity_verified=0 FROM health_evidence WHERE singleton=1),0)
                END)
             ON CONFLICT(singleton) DO UPDATE SET status=excluded.status,
                observed_at=excluded.observed_at,
                last_verified_at=CASE WHEN excluded.status='verified' THEN excluded.observed_at
                    ELSE hosted_identity_evidence.last_verified_at END,
                rejection=CASE WHEN excluded.status='verified' THEN NULL
                    ELSE COALESCE(excluded.rejection,hosted_identity_evidence.rejection) END,
                legacy_failure=CASE WHEN excluded.status='verified' THEN 0
                    ELSE hosted_identity_evidence.legacy_failure END",
            params![outcome.as_str(), now(), outcome.rejection()],
        )?;
        // The legacy column is a migration input only, not a second classifier.
        tx.execute(
            "UPDATE health_evidence SET hosted_identity_verified=NULL WHERE singleton=1",
            [],
        )?;
        Ok(())
    }

    fn hosted_identity(db: &Connection) -> Result<Value> {
        let has_table = |name: &str| -> Result<bool> {
            Ok(db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [name],
                |row| row.get(0),
            )?)
        };
        if has_table("hosted_identity_evidence")?
            && let Some(evidence) = db
                .query_row(
                    "SELECT status,observed_at,last_verified_at,rejection,legacy_failure
                 FROM hosted_identity_evidence WHERE singleton=1",
                    [],
                    |row| {
                        Ok(json!({
                            "status":row.get::<_,String>(0)?,
                            "observed_at":row.get::<_,Option<i64>>(1)?,
                            "last_verified_at":row.get::<_,Option<i64>>(2)?,
                            "rejection":row.get::<_,Option<String>>(3)?,
                            "legacy_failure":row.get::<_,bool>(4)?
                        }))
                    },
                )
                .optional()?
        {
            return Ok(evidence);
        }
        let legacy: Option<bool> = if has_table("health_evidence")? {
            db.query_row(
                "SELECT hosted_identity_verified FROM health_evidence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .flatten()
        } else {
            None
        };
        let last_verified_at: Option<i64> =
            if legacy == Some(true) && has_table("read_observations")? {
                db.query_row(
                    "SELECT last_success_at FROM read_observations WHERE scope='identity'",
                    [],
                    |row| row.get(0),
                )
                .optional()?
                .flatten()
            } else {
                None
            };
        Ok(
            json!({"status":if legacy.is_some() {"legacy_unknown"} else {"unobserved"},
            "observed_at":null,"last_verified_at":last_verified_at,"rejection":null,
            "legacy_failure":legacy == Some(false)}),
        )
    }

    pub(crate) fn safety_observed(&self, id: i64) -> Result<()> {
        self.db.execute(
            "INSERT INTO operation_evidence(operation_id,safety_observed_at) VALUES (?1,?2)
            ON CONFLICT(operation_id) DO UPDATE SET safety_observed_at=excluded.safety_observed_at",
            params![id, now()],
        )?;
        Ok(())
    }

    fn wait_evidence(&self) -> Result<std::collections::BTreeMap<i64, WaitEvidence>> {
        // Bound work even on legacy databases whose diagnostic pruning lagged.
        // Filtering happens after LIMIT so absent evidence remains unknown.
        let mut statement = self.db.prepare(
            "SELECT operation_id,code,at FROM
             (SELECT id,operation_id,code,at FROM events ORDER BY id DESC LIMIT 2000)
             WHERE operation_id IS NOT NULL AND code IN
             ('generating','model_result_captured','submission_queued','job_pending','dispatch_intent')
             ORDER BY id DESC",
        )?;
        let mut rows = statement.query([])?;
        let mut evidence = std::collections::BTreeMap::<i64, WaitEvidence>::new();
        while let Some(row) = rows.next()? {
            let entry = evidence.entry(row.get(0)?).or_default();
            let code = row.get_ref(1)?.as_str()?;
            let slot = match code {
                "generating" => &mut entry.generating,
                "model_result_captured" => &mut entry.captured,
                "submission_queued" | "job_pending" => &mut entry.queued,
                _ => &mut entry.dispatch,
            };
            if slot.is_none() {
                *slot = Some(row.get(2)?);
            }
        }
        Ok(evidence)
    }

    pub(crate) fn operation_poll_timing(&self, id: i64) -> Result<(Option<i64>, i64)> {
        let (queued_since, minimum): (Option<i64>, i64) = self.db.query_row(
            "SELECT
             (SELECT at FROM
              (SELECT id,operation_id,code,at FROM events ORDER BY id DESC LIMIT 2000)
              WHERE operation_id=o.id AND o.state='queued'
              AND code IN ('submission_queued','job_pending') ORDER BY id DESC LIMIT 1),
             COALESCE((SELECT retry_not_before FROM operation_timing WHERE operation_id=o.id),o.next_at)
             FROM operations o WHERE o.id=?1",
            [id], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let current = now();
        Ok((
            queued_since.filter(|at| *at >= 0 && *at <= current),
            minimum,
        ))
    }

    fn work_projection(
        &self,
        config: &Config,
        reads: &Value,
        epoch: Option<u64>,
        answered: Option<bool>,
        stopped: bool,
        reload_blocked: bool,
    ) -> Result<Value> {
        let control = self.control()?;
        let current = now();
        let waits = self.wait_evidence()?;
        let has_evidence = self.has_table("operation_evidence")?;
        let selection = if self.has_table("assignment_selection")? {
            self.db
                .query_row(
                    "SELECT s.observed_at,s.observed_count,s.inventory_complete,s.eligible
                FROM assignment_selection s JOIN runtime_state r
                    ON r.effective_revision=s.revision
                WHERE s.generation=?1",
                    [control.generation],
                    |row| {
                        Ok(json!({"observed_at":row.get::<_,i64>(0)?,
                    "observed_count":row.get::<_,u64>(1)?,
                    "inventory_complete":row.get::<_,bool>(2)?,
                    "eligible":row.get::<_,bool>(3)?,
                    "evidence":"observed_inventory_only"}))
                    },
                )
                .optional()?
        } else {
            None
        };
        let reservation = if has_evidence
            && self.has_table("operation_timing")?
            && self.has_table("health_evidence")?
            && self.has_table("manual_grants")?
            && self.has_table("manual_grant_revocations")?
        {
            Self::answer_retry_reservation(&self.db, config)?
        } else {
            None
        };
        let mut work = json!({});
        for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
            let prepared = self.preparation(kind)?;
            let retry_original = if kind == WorkKind::Answer && prepared.is_some() {
                epoch
                    .map(|epoch| self.uncertain_answer(epoch))
                    .transpose()?
                    .flatten()
            } else {
                None
            };
            let operation = if prepared.is_some() {
                prepared
            } else if kind != WorkKind::Judge {
                let id: Option<i64> = self.db.query_row(
                    "SELECT id FROM operations WHERE kind=?1 AND work_key LIKE ?2
                    AND state IN ('dispatching','queued','unknown','included_pending','confirmed','final','completed','model_unknown')
                    ORDER BY id DESC LIMIT 1",
                    params![kind.as_str(),format!("{}:%",epoch.unwrap_or(u64::MAX))],|r| r.get(0)).optional()?;
                id.map(|id| self.operation(id)).transpose()?.flatten()
            } else {
                None
            };
            let op = operation.as_ref();
            let scope = if kind == WorkKind::Judge {
                ReadScope::Assignments
            } else {
                ReadScope::Challenge
            };
            let read = reads
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["scope"] == scope.as_str()));
            let read_at = read.and_then(|row| row["next_at"].as_i64()).unwrap_or(0);
            let mut next_at = Some(self.next_at(kind)?.max(read_at).max(current));
            let mut phase = "observing";
            let mut reason = "observation_due";
            let mut action = if kind == WorkKind::Judge {
                "observe_assignments"
            } else {
                "observe_challenge"
            };
            let accounting =
                Self::uncertainty_accounting(&self.db, config, op.map(|op| op.id), None, false)?;
            let capacity = accounting.active().saturating_add(1)
                > u64::from(config.participation.unresolved_limit(kind));
            if read.is_some_and(|row| row["state"] == "in_flight") {
                phase = "observing";
                reason = "read_in_flight";
                action = if kind == WorkKind::Judge {
                    "await_assignments"
                } else {
                    "await_challenge"
                };
                next_at = None;
            } else if read_at > current {
                reason = "read_backoff";
            } else if next_at.is_some_and(|at| at > current) {
                reason = "cadence";
            }
            if kind == WorkKind::Judge
                && op.is_none()
                && selection
                    .as_ref()
                    .is_some_and(|value| value["eligible"] == false)
                && !read.is_some_and(|row| row["state"] == "in_flight")
                && read_at <= current
            {
                reason = "no_eligible_in_observed_inventory";
            }
            if kind == WorkKind::Answer && answered == Some(true) {
                phase = "answered";
                reason = "hosted_answer_observed";
            }
            if capacity {
                phase = "blocked";
                reason = if kind != WorkKind::Answer
                    && config.participation.answer_reserved_slots > 0
                    && accounting.active()
                        < u64::from(config.participation.max_unresolved_operations)
                {
                    "answer_capacity_reserved"
                } else {
                    "unresolved_capacity"
                };
                action = "await_reconciliation";
                next_at = None;
            }
            if let Some(op) = op {
                match op.state.as_str() {
                    "generating" => {
                        phase = "preparing";
                        reason = if op.request["solver"]["epoch"].as_u64() != epoch
                            && kind == WorkKind::Answer
                        {
                            "model_capacity"
                        } else {
                            "model_running"
                        };
                        action = "await_model";
                        next_at = if self.has_table("operation_evidence")? {
                            self.db.query_row("SELECT model_deadline FROM operation_evidence WHERE operation_id=?1",
                                [op.id],|r| r.get::<_,Option<i64>>(0)).optional()?.flatten()
                        } else {
                            None
                        };
                    }
                    "prepared" | "generated" | "retry" => {
                        if !capacity {
                            phase = "prepared";
                            reason = "fresh_evidence_required";
                            action = if kind == WorkKind::Judge {
                                "revalidate_assignment"
                            } else {
                                "revalidate_challenge"
                            };
                            next_at = Some(op.next_at.max(read_at).max(current));
                            if op.next_at > current {
                                reason = "operation_backoff";
                            } else if read_at > current {
                                reason = "read_backoff";
                            } else if self.has_table("operation_timing")?
                                && !self.admission_allowed(config, op)?
                            {
                                phase = "blocked";
                                action = "await_reconciliation";
                                next_at = None;
                                let (writing, floor, grace): (bool,i64,i64) = self.db.query_row(
                                    "SELECT COALESCE(MAX(o.state='dispatching'),0),
                                    COALESCE(MAX(COALESCE(t.retry_not_before,o.next_at)),0),
                                    COALESCE(MAX(COALESCE(e.blocked_since,o.created_at)),0)
                                    FROM operations o LEFT JOIN operation_timing t ON t.operation_id=o.id
                                    LEFT JOIN operation_evidence e ON e.operation_id=o.id
                                    WHERE o.id!=?1 AND o.state IN ('dispatching','queued','unknown','included_pending')",
                                    [op.id],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
                                let floor = floor.max(accounting.retry_not_before);
                                if writing {
                                    reason = "effect_in_flight";
                                    action = "await_effect";
                                } else if floor > current {
                                    reason = "retained_retry_minimum";
                                    next_at = Some(floor);
                                } else if accounting.total == 0 {
                                    reason = "request_eligibility";
                                    action = "revalidate_request";
                                    next_at = Some(current);
                                } else if config.participation.mode == ParticipationMode::Strict {
                                    reason = "strict_uncertainty";
                                } else if !config.participation.allows(kind) {
                                    reason = "participation_disabled";
                                } else if config.participation.mode == ParticipationMode::Manual {
                                    reason = "manual_authorization_required";
                                    action = "authorize";
                                } else {
                                    let until = grace.saturating_add(
                                        config
                                            .participation
                                            .uncertainty_grace_seconds
                                            .min(i64::MAX as u64)
                                            as i64,
                                    );
                                    if until > current {
                                        reason = "uncertainty_grace";
                                        next_at = Some(until);
                                    } else {
                                        reason = "request_eligibility";
                                        action = "revalidate_request";
                                    }
                                }
                            }
                            if phase == "prepared" {
                                let identity = reads.as_array().and_then(|rows| {
                                    rows.iter().find(|row| row["scope"] == "identity")
                                });
                                let identity_at = identity
                                    .and_then(|row| row["next_at"].as_i64())
                                    .unwrap_or(0);
                                if identity_at > current {
                                    reason = "identity_backoff";
                                    next_at = Some(next_at.unwrap_or(current).max(identity_at));
                                }
                                if read.is_some_and(|row| row["state"] == "in_flight") {
                                    reason = "freshness_in_flight";
                                    action = if kind == WorkKind::Judge {
                                        "await_assignments"
                                    } else {
                                        "await_challenge"
                                    };
                                    next_at = None;
                                } else if identity.is_some_and(|row| row["state"] == "in_flight") {
                                    reason = "identity_in_flight";
                                    action = "await_identity";
                                    next_at = None;
                                }
                            }
                        }
                    }
                    "dispatching" => {
                        phase = "dispatching";
                        reason = "effect_in_flight";
                        action = "await_effect";
                        next_at = None;
                    }
                    "queued" | "unknown" | "included_pending" => {
                        phase = match op.state.as_str() {
                            "queued" => "queued",
                            "included_pending" => "included_pending",
                            _ => "unknown",
                        };
                        reason = "authoritative_evidence_required";
                        let bound_scope = if op.txid.is_some() {
                            Some(ReadScope::Receipt)
                        } else if op.job_id.is_some() {
                            Some(ReadScope::Job)
                        } else {
                            None
                        };
                        action = match bound_scope {
                            Some(ReadScope::Receipt) => "read_receipt",
                            Some(_) => "read_job",
                            None => "authoritative_recovery",
                        };
                        next_at = bound_scope.map(|scope| {
                            reads
                                .as_array()
                                .and_then(|rows| {
                                    rows.iter().find(|row| row["scope"] == scope.as_str())
                                })
                                .and_then(|row| row["next_at"].as_i64())
                                .unwrap_or(0)
                                .max(op.next_at)
                                .max(current)
                        });
                    }
                    "model_unknown" => {
                        phase = "blocked";
                        reason = "model_uncertain";
                        action = if config.preparation.retry_uncertain {
                            "retry_model"
                        } else {
                            "recover_model"
                        };
                        next_at = None;
                    }
                    "confirmed" | "final" => {
                        phase = "included";
                        reason = if op.state == "final" {
                            "checkpoint_reported"
                        } else {
                            "receipt_included"
                        };
                        action = "observe_challenge";
                    }
                    "completed" => {
                        phase = "completed";
                        reason = "mine_completed";
                    }
                    _ => {}
                }
                if op.generation != control.generation
                    && matches!(op.state.as_str(), "prepared" | "generated" | "retry")
                {
                    phase = "blocked";
                    reason = "generation_changed";
                    action = "discard_unsent";
                    next_at = Some(current);
                }
            }
            if kind != WorkKind::Answer
                && reservation.is_some()
                && phase == "blocked"
                && op.is_some_and(|op| {
                    op.generation == control.generation
                        && matches!(op.state.as_str(), "prepared" | "generated" | "retry")
                })
            {
                phase = "blocked";
                reason = "answer_retry_reserved";
                action = "await_answer_retry";
                next_at = None;
            }
            if config.mode(kind) == Mode::ReadOnly {
                phase = "read_only";
                reason = "capability_read_only";
                action = if kind == WorkKind::Judge {
                    "observe_assignments"
                } else {
                    "observe_challenge"
                };
                next_at = Some(self.next_at(kind)?.max(read_at).max(current));
            }
            if stopped {
                phase = "stopped";
                reason = "controller_stopped";
                action = "start_controller";
                next_at = None;
            }
            if reload_blocked {
                phase = "blocked";
                reason = "config_reload_rejected";
                action = "repair_config";
                next_at = None;
            }
            if control.paused {
                phase = "paused";
                reason = "admission_paused";
                action = "resume";
                next_at = None;
            }
            if config.mode(kind) == Mode::Off {
                phase = "off";
                reason = "capability_off";
                action = "enable_capability";
                next_at = None;
            }
            work[kind.as_str()] = json!({"phase":phase,"reason":reason,"next_action":action,
                "next_at":next_at,"epoch":epoch,"operation_id":op.map(|op| op.id),
                "operation_epoch":op.and_then(|op| op.request["solver"]["epoch"].as_u64())});
            work[kind.as_str()]["admission"] = if self.has_table("operation_timing")?
                && self.has_table("manual_grants")?
                && self.has_table("manual_grant_revocations")?
            {
                json!(
                    self.uncertainty_blocker_with(config, kind, epoch, &accounting)?
                        .map(|(reason, next_at)| json!({"reason":reason,"next_at":next_at}))
                )
            } else {
                Value::Null
            };
            let manual_authorized = self.manual_authorized(kind, epoch)?;
            work[kind.as_str()]["manual_authorized"] = json!(manual_authorized);
            if has_evidence && self.has_table("operation_links")? && kind != WorkKind::Mine {
                let latest = self.db.query_row(
                    "SELECT o.id,o.work_key,o.state,e.evidence,
                     o.revision=(SELECT effective_revision FROM runtime_state WHERE singleton=1) FROM operations o
                     LEFT JOIN operation_evidence e ON e.operation_id=o.id
                     WHERE o.id=(SELECT id FROM operations WHERE kind=?1 AND generation=?2
                        AND (?1='judge' OR work_key LIKE ?3) ORDER BY id DESC LIMIT 1)
                     AND o.payload IS NULL AND o.job_id IS NULL AND o.txid IS NULL
                     AND o.state IN ('model_unknown','superseded_model_unknown','rejected','retry_model','prelaunch_failed')",
                    params![kind.as_str(),control.generation,format!("{}:%",epoch.unwrap_or(u64::MAX))],
                    |r| Ok((r.get::<_, i64>(0)?,r.get::<_, String>(1)?,r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,r.get::<_, Option<bool>>(4)?)),
                ).optional()?;
                let empty_inventory = kind == WorkKind::Judge
                    && selection.as_ref().is_some_and(|selection| {
                        selection["inventory_complete"] == true && selection["observed_count"] == 0
                    });
                if !empty_inventory
                    && let Some((id, key, state, diagnostic, current_route)) = latest
                {
                    let used = self.model_budget_used(kind, &key)?;
                    let limit = config.preparation.max_attempts_per_work;
                    let retry_eligible = used < limit
                        && (state != "model_unknown" || config.preparation.retry_uncertain);
                    let diagnostic = diagnostic
                        .as_deref()
                        .and_then(|value| serde_json::from_str::<Value>(value).ok());
                    let failure = diagnostic
                        .as_ref()
                        .filter(|value| value["stage"] == "model")
                        .and_then(|value| value["reason"].as_str())
                        .filter(|code| {
                            matches!(
                                *code,
                                "native_auth_unavailable"
                                    | "native_route_mismatch"
                                    | "native_api_unsupported"
                                    | "executable_unavailable"
                                    | "invalid_solver_setup"
                                    | "core_guidance_missing"
                                    | "unsupported_harness_version"
                                    | "invalid_model_deadline"
                                    | "model_admission_closed"
                                    | "model_launch_unknown"
                                    | "model_execution_unknown"
                            )
                        });
                    work[kind.as_str()]["model"] = json!({"operation_id":id,
                        "state":state,"retry_eligible":retry_eligible,"budget_used":used,
                        "budget_limit":limit,"failure_category":failure,
                        "scope":if kind == WorkKind::Answer { "current_work" } else { "historical_assignment" },
                        "current_route":current_route,
                        "evidence":"latest_model_only_attempt_in_current_generation"});
                }
            }
            if let Some(reservation) = reservation {
                work[kind.as_str()]["admission_reservation"] = json!({
                    "original_operation_id":reservation.original_operation_id,
                    "active":true,
                    "same_operation":reservation.same_operation,
                    "basis":if reservation.same_operation { "proven_refusal_retry" } else { "uncertain_answer_retry" },
                    "retry_not_before":reservation.ready_at,
                    "requires_fresh_eligibility":true
                });
            }
            if kind == WorkKind::Judge {
                work[kind.as_str()]["selection"] = json!(selection);
            }
            if kind == WorkKind::Answer
                && let Some(original) = op
                    .filter(|op| {
                        matches!(op.state.as_str(), "queued" | "unknown")
                            && op.txid.is_none()
                            && op.payload.is_some()
                    })
                    .or(retry_original.as_ref())
            {
                // Recovery of the original and admission of a distinct risk-opted
                // retry are separate. Neither this projection nor elapsed time
                // supplies fresh challenge evidence or resolves the original.
                let blocker = if has_evidence
                    && self.has_table("operation_timing")?
                    && self.has_table("manual_grants")?
                    && self.has_table("manual_grant_revocations")?
                    && original.request["solver"]["epoch"].as_u64().is_some()
                {
                    self.answer_retry_blocker(config, original)?
                } else {
                    Some(("retry_evidence_unavailable", None))
                };
                let retry_accounting =
                    Self::uncertainty_accounting(&self.db, config, None, Some(original.id), false)?;
                let blocking_operation =
                    blocker.and_then(|(reason, _)| retry_accounting.blocking_operation(reason));
                let (mut retry_reason, mut retry_at) = match blocker {
                    Some(blocker) => blocker,
                    None => (
                        "fresh_evidence_required",
                        Some(self.next_at(kind)?.max(read_at).max(current)),
                    ),
                };
                let mut retry_action = if blocker.is_none() {
                    "revalidate_challenge"
                } else if retry_reason == "manual_authorization_required" {
                    "authorize"
                } else {
                    "await_retry_eligibility"
                };
                if blocker.is_none() {
                    if read.is_some_and(|row| row["state"] == "in_flight") {
                        retry_reason = "freshness_in_flight";
                        retry_action = "await_challenge";
                        retry_at = None;
                    } else if read_at > current {
                        retry_reason = "read_backoff";
                    }
                }
                if blocker.is_none() && answered == Some(true) {
                    retry_reason = "hosted_answer_observed";
                    retry_action = "observe_challenge";
                    retry_at = Some(self.next_at(kind)?.max(read_at).max(current));
                }
                if stopped || reload_blocked || control.paused || config.mode(kind) != Mode::Active
                {
                    retry_reason = reason;
                    retry_action = action;
                    retry_at = next_at;
                }
                work[kind.as_str()]["retry"] = json!({
                    "original_operation_id":original.id,
                    "policy_eligible":blocker.is_none(),
                    "reason":retry_reason,"next_action":retry_action,"next_at":retry_at,
                    "requires_fresh_eligibility":true,
                    "blocking_operation_id":blocking_operation,
                    "reservation_active":reservation.is_some_and(|r| r.original_operation_id == original.id),
                    "manual_authorized":manual_authorized,
                    "reservation_retry_not_before":reservation.map(|r| r.ready_at)
                });
            }
            let effect_since = if let Some(op) = op.filter(|op| {
                has_evidence
                    && matches!(
                        op.state.as_str(),
                        "dispatching" | "queued" | "unknown" | "included_pending"
                    )
            }) {
                self.db
                    .query_row(
                        "SELECT blocked_since FROM operation_evidence WHERE operation_id=?1",
                        [op.id],
                        |row| row.get::<_, Option<i64>>(0),
                    )
                    .optional()?
                    .flatten()
            } else {
                None
            };
            let empty = WaitEvidence::default();
            work[kind.as_str()]["wait"] = waits
                .get(&op.map_or(-1, |op| op.id))
                .unwrap_or(&empty)
                .projection(op.map_or("", |op| op.state.as_str()), effect_since, current);
        }
        Ok(work)
    }

    pub(crate) fn status(&self, config: &Config) -> Result<Value> {
        // Keep heartbeat, epoch and answer evidence in one read snapshot.
        let snapshot = self.db.unchecked_transaction()?;
        let control = self.control()?;
        let mut stmt = self.db.prepare(
            "SELECT kind,state,COUNT(*) FROM operations GROUP BY kind,state ORDER BY kind,state",
        )?;
        let counts = stmt.query_map([], |r| Ok(json!({"kind":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"count":r.get::<_,i64>(2)?})))?
            .collect::<std::result::Result<Vec<_>,_>>()?;
        let mut pending: Option<Value> = self.db.query_row(
            "SELECT kind,state,next_at,revision,generation,created_at,updated_at,id FROM operations
             WHERE state IN ('generating','generated','prepared','dispatching','queued','unknown','included_pending','retry')
             ORDER BY CASE WHEN state IN ('dispatching','queued','unknown','included_pending') THEN 0 ELSE 1 END,id LIMIT 1", [], |r| {
                Ok(json!({"kind":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,
                    "next_at":r.get::<_,i64>(2)?,"captured_revision":r.get::<_,String>(3)?,
                    "captured_generation":r.get::<_,i64>(4)?,"created_at":r.get::<_,i64>(5)?,
                    "updated_at":r.get::<_,i64>(6)?,"operation_id":r.get::<_,i64>(7)?}))
            },
        ).optional()?;
        if self.schema_version()? == 2
            && let Some(pending) = pending.as_mut()
        {
            struct PendingEvidence {
                blocked_since: Option<i64>,
                model_deadline: Option<i64>,
                http_deadline: Option<i64>,
                diagnostic: Option<String>,
            }
            let detail = self.db.query_row(
                "SELECT blocked_since,model_deadline,http_deadline,evidence FROM operation_evidence WHERE operation_id=?1",
                [pending["operation_id"].as_i64().unwrap_or_default()],
                |row| Ok(PendingEvidence {
                    blocked_since: row.get(0)?,
                    model_deadline: row.get(1)?,
                    http_deadline: row.get(2)?,
                    diagnostic: row.get(3)?,
                }),
            ).optional()?;
            if let Some(detail) = detail {
                pending["blocked_since"] = json!(detail.blocked_since);
                pending["model_deadline"] = json!(detail.model_deadline);
                pending["http_deadline"] = json!(detail.http_deadline);
                pending["diagnostic"] = detail
                    .diagnostic
                    .map(|value| serde_json::from_str::<Value>(&value))
                    .transpose()?
                    .unwrap_or(Value::Null);
            }
        }
        let observed: Option<Value> = self
            .db
            .query_row(
                "SELECT epoch,observed_at FROM observation WHERE singleton=1",
                [],
                |r| Ok(json!({"epoch":r.get::<_,i64>(0)?,"observed_at":r.get::<_,i64>(1)?})),
            )
            .optional()?;
        let mut effective: Option<Value> = self.db.query_row("SELECT effective_revision,reload_blocked,capabilities,observed_at FROM runtime_state WHERE singleton=1", [], |r| {
            Ok(json!({"revision":r.get::<_,String>(0)?,"reload_blocked":r.get::<_,bool>(1)?,
                "capabilities":r.get::<_,String>(2)?,"observed_at":r.get::<_,i64>(3)?}))
        }).optional()?;
        if let Some(effective) = effective.as_mut() {
            let capabilities: Value = serde_json::from_str(
                effective["capabilities"]
                    .as_str()
                    .context("invalid stored capabilities")?,
            )?;
            effective["capabilities"] = capabilities;
            if self.schema_version()? == 2 {
                let policy: Option<String> = self
                    .db
                    .query_row(
                        "SELECT policy FROM runtime_policy WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .optional()?;
                effective["policy"] = policy
                    .map(|s| serde_json::from_str::<Value>(&s))
                    .transpose()?
                    .unwrap_or(Value::Null);
            }
        }
        let stored_identity: String =
            self.db
                .query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let stored: Value = serde_json::from_str(&stored_identity)?;
        let last_event: Option<String> = self
            .db
            .query_row(
                "SELECT code FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let controller_stopped: bool = self.db.query_row(
            "SELECT COALESCE((SELECT code='runtime_stopped' FROM events WHERE code IN
             ('controller_running','runtime_stopped') ORDER BY id DESC LIMIT 1),0)",
            [],
            |r| r.get(0),
        )?;
        // Older databases remain readable without migrating or writing to them.
        let has_health_evidence: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type='table' AND name='health_evidence')",
            [],
            |r| r.get(0),
        )?;
        let (first_observed_at, answered): (Option<i64>, Option<bool>) = if has_health_evidence {
            self.db
                .query_row(
                    "SELECT first_observed_at,answered
                     FROM health_evidence WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .unwrap_or((None, None))
        } else {
            (None, None)
        };
        let hosted_identity = Self::hosted_identity(&self.db)?;
        let hosted_identity_verified = if !hosted_identity["rejection"].is_null() {
            Some(false)
        } else if hosted_identity["status"] == "verified" {
            Some(true)
        } else {
            None
        };
        let epoch_evidence = json!({"first_observed_at":first_observed_at,"answered":answered});
        let effect = self.effect()?;
        let stored_policy = effective.as_ref().and_then(|e| {
            serde_json::from_value::<Participation>(e["policy"]["participation"].clone()).ok()
        });
        let policy_source = if stored_policy.is_some() {
            "effective"
        } else {
            "unavailable"
        };
        let mut policy_config = config.clone();
        policy_config.participation = stored_policy.unwrap_or_default();
        if let Some(capabilities) = effective
            .as_ref()
            .and_then(|e| serde_json::from_value(e["capabilities"].clone()).ok())
        {
            policy_config.capabilities = capabilities;
        }
        if let Some(policy) = effective.as_ref().map(|e| &e["policy"]) {
            if let Ok(schedule) = serde_json::from_value(policy["schedule"].clone()) {
                policy_config.schedule = schedule;
            }
            if let Ok(preparation) = serde_json::from_value(policy["preparation"].clone()) {
                policy_config.preparation = preparation;
            }
        }
        let risk_admissions: u64 = if self.has_table("risk_admissions")? {
            self.db
                .query_row("SELECT COUNT(*) FROM risk_admissions", [], |r| r.get(0))?
        } else {
            0
        };
        let epoch = observed.as_ref().and_then(|o| o["epoch"].as_u64());
        let accounting = Self::uncertainty_accounting(&self.db, &policy_config, None, None, false)?;
        let unresolved_count = accounting.total;
        let mut uncertainty_blocks = json!({});
        let mut affected = Vec::new();
        for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
            let mut blocked = if self.has_table("operation_timing")?
                && self.has_table("manual_grants")?
                && self.has_table("manual_grant_revocations")?
            {
                !self.uncertainty_open_with(&policy_config, kind, epoch, &accounting)?
            } else {
                unresolved_count > 0
            };
            if !blocked
                && unresolved_count > 0
                && kind == WorkKind::Answer
                && let Some(epoch) = epoch
                && self.answer_epoch_attempted(epoch)?
                && !self.answer_epoch_accepted(epoch)?
            {
                blocked = match self.uncertain_answer(epoch)? {
                    Some(original) => !self.answer_retry_allowed(&policy_config, &original)?,
                    // Accepted or model-only work is eligibility, not an uncertainty fence.
                    None => false,
                };
            }
            uncertainty_blocks[kind.as_str()] = json!(blocked);
            if !blocked
                && kind != WorkKind::Answer
                && self.has_table("operation_evidence")?
                && self.has_table("operation_timing")?
                && self.has_table("health_evidence")?
                && self.has_table("manual_grants")?
                && self.has_table("manual_grant_revocations")?
            {
                blocked = Self::answer_retry_reservation(&self.db, &policy_config)?.is_some();
            }
            if blocked {
                affected.push(kind.as_str());
            }
        }
        let blocked = !affected.is_empty();
        let participation = json!({"policy":policy_config.participation,"policy_source":policy_source,
            "unresolved_count":unresolved_count,"risk_admissions":risk_admissions,
            "active_unresolved_count":accounting.active(),
            "historical_eligible_count":accounting.eligible,
            "capacity_exempt_count":accounting.exempt,
            "historical_unknown_answer_count":accounting.exempt,
            "historical_unknown_answers":accounting.historical,
            "historical_unknown_answers_truncated":accounting.exempt > accounting.historical.len() as u64,
            "observation_epoch":epoch,"uncertainty_blocks":uncertainty_blocks});
        let oldest_unresolved_operation = effect.as_ref().map(|op| op.id);
        let oldest_unresolved_since = if self.schema_version()? == 2 {
            effect.as_ref().map(|op| self.db.query_row(
                "SELECT COALESCE((SELECT blocked_since FROM operation_evidence WHERE operation_id=?1),created_at)
                FROM operations WHERE id=?1", [op.id], |r| r.get::<_,i64>(0))).transpose()?
        } else {
            effect
                .as_ref()
                .map(|op| {
                    self.db.query_row(
                        "SELECT created_at FROM operations WHERE id=?1",
                        [op.id],
                        |row| row.get::<_, i64>(0),
                    )
                })
                .transpose()?
        };
        let last_progress: Option<i64> = self.db.query_row(
            "SELECT MAX(updated_at) FROM operations
            WHERE state IN ('confirmed','final','completed')",
            [],
            |r| r.get(0),
        )?;
        let mut captured_work = Vec::new();
        let last_safety_observation: Option<i64> = if self.schema_version()? == 2 {
            let mut statement = self.db.prepare("SELECT o.id,o.kind,o.state,o.revision,o.generation,
                e.model_deadline,e.http_deadline,e.policy,o.created_at FROM operations o
                LEFT JOIN operation_evidence e ON e.operation_id=o.id
                WHERE o.state IN ('generating','generated','prepared','retry') ORDER BY o.id LIMIT 3")?;
            let rows = statement.query_map([],|r| Ok((json!({"operation_id":r.get::<_,i64>(0)?,
                "kind":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,
                "captured_revision":r.get::<_,String>(3)?,"captured_generation":r.get::<_,i64>(4)?,
                "model_deadline":r.get::<_,Option<i64>>(5)?,"http_deadline":r.get::<_,Option<i64>>(6)?,
                "created_at":r.get::<_,i64>(8)?}),
                r.get::<_,Option<String>>(7)?)))?;
            for row in rows {
                let (mut work, policy) = row?;
                if let Some(policy) = policy {
                    let policy: Value = serde_json::from_str(&policy)?;
                    work["captured_policy"] = json!({"model":policy["model"]["model"],
                        "harness":policy["model"]["harness"],"reasoning":policy["model"]["reasoning"],
                        "model_seconds":policy["model_seconds"],"attempt":policy["attempt"]});
                }
                captured_work.push(work);
            }
            self.db.query_row(
                "SELECT MAX(safety_observed_at) FROM operation_evidence",
                [],
                |r| r.get(0),
            )?
        } else {
            None
        };
        let timing = self.has_table("operation_timing")?;
        let (evidence_join, deadlines) = if self.schema_version()? == 2 {
            (
                "LEFT JOIN operation_evidence e ON e.operation_id=o.id",
                "e.http_deadline,e.model_deadline",
            )
        } else {
            ("", "NULL,NULL")
        };
        let timing_join = if timing {
            "LEFT JOIN operation_timing t ON t.operation_id=o.id"
        } else {
            ""
        };
        let floor = if timing {
            "COALESCE(t.retry_not_before,o.next_at)"
        } else {
            "o.next_at"
        };
        let mut statement = self.db.prepare(&format!(
            "SELECT o.id,o.state,o.created_at,o.updated_at,{deadlines},o.kind,o.next_at,{floor},
             CASE WHEN o.txid IS NOT NULL THEN 'receipt' WHEN o.job_id IS NOT NULL THEN 'job' END
             FROM operations o {evidence_join} {timing_join}
             WHERE o.state IN ('generating','generated','prepared','retry','dispatching','queued','unknown','included_pending')
             ORDER BY o.id"))?;
        let pending_work = statement
            .query_map([], |r| {
                let id: i64 = r.get(0)?;
                let state: String = r.get(1)?;
                let kind: String = r.get(6)?;
                let effect = matches!(
                    state.as_str(),
                    "dispatching" | "queued" | "unknown" | "included_pending"
                );
                let capacity_counted = if !effect
                    || accounting
                        .historical
                        .iter()
                        .any(|row| row.operation_id == id)
                {
                    Some(false)
                } else if kind != "answer"
                    || accounting.exempt == accounting.historical.len() as u64
                {
                    Some(true)
                } else {
                    None
                };
                Ok(json!({"operation_id":id,"state":state,
                "created_at":r.get::<_,i64>(2)?,"updated_at":r.get::<_,i64>(3)?,
                "http_deadline":r.get::<_,Option<i64>>(4)?,
                "model_deadline":r.get::<_,Option<i64>>(5)?,"kind":kind,
                "next_at":r.get::<_,i64>(7)?,"retry_not_before":r.get::<_,i64>(8)?,
                "reconciliation_scope":r.get::<_,Option<String>>(9)?,
                "capacity_counted":capacity_counted}))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let reads = self.reads()?;
        let work = self.work_projection(
            &policy_config,
            &reads,
            epoch,
            answered,
            controller_stopped,
            effective
                .as_ref()
                .is_some_and(|e| e["reload_blocked"] == true),
        )?;
        let status = json!({"initialized":true,"paused":control.paused,"generation":control.generation,
            "identity_fingerprint":digest(format!("{}\n{}",stored["chain"].as_str().unwrap_or_default(),stored["address"].as_str().unwrap_or_default())),
            "chain":stored["chain"],"capabilities":config.capabilities,"observation":observed,
            "configured_revision":config.optional_revision()?,"effective_runtime":effective,
            "network_routing":self.routing_status(config)?,
            "controller_stopped":controller_stopped,"epoch_evidence":epoch_evidence,
            "identity_matches_config":stored_identity==identity(config)?,"last_event":last_event,
            "hosted_identity_verified":hosted_identity_verified,
            "hosted_identity":hosted_identity,
            "reads":reads,"work":work,
            "pending":pending,"operations":counts,"evidence":"authenticated_hosted_response",
            "admission_blocked":blocked,"oldest_unresolved_operation":oldest_unresolved_operation,
            "oldest_unresolved_since":oldest_unresolved_since,
            "affected_capabilities":affected,"participation":participation,
            "last_progress_at":last_progress,"last_reported_build":effective.as_ref().map(|e| &e["policy"]["build"]),
            "process_identity":"unverified",
            "captured_work":captured_work,"last_safety_observation_at":last_safety_observation,
            "pending_work":pending_work,
            "finality":"node_reported_only","paid":"not_verified"});
        snapshot.commit()?;
        Ok(status)
    }

    fn identity_normalization_preview(db: &Connection, revision: &str) -> Result<(Value, Value)> {
        let exists = |name: &str| -> Result<bool> {
            Ok(db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [name],
                |row| row.get(0),
            )?)
        };
        let legacy: Option<bool> = if exists("health_evidence")? {
            db.query_row(
                "SELECT hosted_identity_verified FROM health_evidence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .flatten()
        } else {
            None
        };
        let structured = exists("hosted_identity_evidence")?
            && db.query_row(
                "SELECT EXISTS(SELECT 1 FROM hosted_identity_evidence WHERE singleton=1)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
        let mut observation = if exists("read_observations")? {
            db.query_row(
                "SELECT in_flight,started_at,finished_at,last_http_success_at,last_success_at,
                 last_failure_at,failure_category,status,local_next_at,server_not_before,
                 retained_conservative_floor FROM read_observations WHERE scope='identity'",
                [], |row| Ok(json!({
                    "in_flight":row.get::<_,bool>(0)?, "started_at":row.get::<_,Option<i64>>(1)?,
                    "finished_at":row.get::<_,Option<i64>>(2)?,
                    "last_http_success_at":row.get::<_,Option<i64>>(3)?,
                    "last_success_at":row.get::<_,Option<i64>>(4)?,
                    "last_failure_at":row.get::<_,Option<i64>>(5)?,
                    "failure_category":row.get::<_,Option<String>>(6)?,
                    "status":row.get::<_,Option<i64>>(7)?,
                    "local_next_at":row.get::<_,i64>(8)?,
                    "server_not_before":row.get::<_,i64>(9)?,
                    "retained_conservative_floor":row.get::<_,i64>(10)?
                })),
            ).optional()?.unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        let backoff = db
            .query_row(
                "SELECT failures,next_at FROM read_backoff WHERE scope='identity'",
                [],
                |row| Ok(json!({"failures":row.get::<_,i64>(0)?,"next_at":row.get::<_,i64>(1)?})),
            )
            .optional()?
            .unwrap_or(Value::Null);
        // Opening an old journal materializes this default row from backoff.
        // Bind the preview to its meaning, not the presence of migration metadata.
        if observation.is_null() && !backoff.is_null() {
            observation = json!({"in_flight":false,"started_at":null,"finished_at":null,
                "last_http_success_at":null,"last_success_at":null,"last_failure_at":null,
                "failure_category":null,"status":null,"local_next_at":0,"server_not_before":0,
                "retained_conservative_floor":backoff["next_at"]});
        }
        let binding = db.query_row(
            "SELECT a.database_id,a.dispatch_sequence,c.generation,c.paused
             FROM authority a,control c WHERE a.singleton=1 AND c.singleton=1",
            [],
            |row| {
                Ok(json!({"database_id":row.get::<_,String>(0)?,
                "dispatch_sequence":row.get::<_,i64>(1)?,"generation":row.get::<_,i64>(2)?,
                "paused":row.get::<_,bool>(3)?}))
            },
        )?;
        let routing: Option<String> = if exists("routing_profile")? {
            db.query_row(
                "SELECT profile FROM routing_profile WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
        } else {
            None
        };
        let captured = json!({"hosted_identity_verified":legacy,
            "structured_evidence_present":structured,"read_observation":observation,
            "read_backoff":backoff,"binding":binding,
            "routing_fingerprint":routing.map(digest)
                .unwrap_or_else(|| crate::endpoints::LEGACY_API_FINGERPRINT.to_owned())});
        let eligible = legacy == Some(false) && !structured;
        let token = eligible.then(|| {
            digest(
                json!({"contract":"legacy_identity_normalization_v1",
            "config_revision":revision,"captured":captured})
                .to_string(),
            )
        });
        Ok((
            json!({"kind":"identity","classification":"legacy_identity_evidence_normalization",
            "eligible":eligible,"reason":if eligible {"eligible"} else {"not_legacy_identity_failure"},
            "target_status":"legacy_unknown","legacy_failure":true,
            "preview_token":token,"config_revision":revision,
            "dry_run":true,"resolved":false,"applied":false,"already_resolved":false,
            "network_requests_reset":false,"historical_payload_retried":false,
            "evidence_limit":"Local normalization of an ambiguous legacy failure. Its cause is unknown; this is neither credential repair nor identity verification."}),
            captured,
        ))
    }

    fn normalize_legacy_identity(&mut self, revision: &str, token: &str) -> Result<Value> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut preview, captured) = Self::identity_normalization_preview(&tx, revision)?;
        let previous_audit: Option<String> = tx
            .query_row(
                "SELECT audit FROM identity_normalizations WHERE preview_token=?1",
                [token],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(audit) = previous_audit {
            let audit: Value = serde_json::from_str(&audit)?;
            if captured["hosted_identity_verified"].is_null()
                && Self::hosted_identity(&tx)? == audit["normalized_evidence"]
            {
                preview["dry_run"] = json!(false);
                preview["resolved"] = json!(true);
                preview["already_resolved"] = json!(true);
                preview["reason"] = json!("already_resolved");
                tx.commit()?;
                return Ok(preview);
            }
        }
        if preview["eligible"] != true || preview["preview_token"].as_str() != Some(token) {
            return Err(RefusalRecoveryError("identity_evidence_changed").into());
        }
        let normalized = json!({"status":"legacy_unknown","observed_at":null,
            "last_verified_at":null,"rejection":null,"legacy_failure":true});
        let audit = json!({"source":"doctor_legacy_identity_normalization",
            "contract":"legacy_identity_normalization_v1","at":now(),
            "preview_token":token,"config_revision":revision,
            "classification":preview["classification"],"previous_evidence":captured,
            "normalized_evidence":normalized,"evidence_limit":preview["evidence_limit"]});
        tx.execute(
            "INSERT INTO identity_normalizations(preview_token,audit) VALUES(?1,?2)",
            params![token, serde_json::to_string(&audit)?],
        )?;
        tx.execute(
            "INSERT INTO hosted_identity_evidence VALUES(1,'legacy_unknown',NULL,NULL,NULL,1)",
            [],
        )?;
        let changed = tx.execute(
            "UPDATE health_evidence SET hosted_identity_verified=NULL
             WHERE singleton=1 AND hosted_identity_verified=0",
            [],
        )?;
        if changed != 1 {
            return Err(RefusalRecoveryError("identity_evidence_changed").into());
        }
        tx.execute(
            "INSERT INTO events(at,code) VALUES(?1,'legacy_identity_evidence_normalized')",
            [now()],
        )?;
        tx.commit()?;
        preview["eligible"] = json!(false);
        preview["reason"] = json!("legacy_identity_evidence_normalized");
        preview["dry_run"] = json!(false);
        preview["resolved"] = json!(true);
        preview["applied"] = json!(true);
        Ok(preview)
    }

    fn refusal_candidates(db: &Connection, revision: &str) -> Result<(Vec<Value>, Vec<Value>)> {
        let mut statement =
            db.prepare("SELECT id FROM operations WHERE state='unknown' ORDER BY id")?;
        let mut rows = statement.query([])?;
        let mut eligible = Vec::new();
        let mut ineligible = Vec::new();
        while let Some(row) = rows.next()? {
            let (preview, _) = Self::refusal_preview(db, row.get(0)?, revision)?;
            if preview["eligible"] == true {
                eligible.push(preview);
            } else {
                ineligible.push(preview);
            }
        }
        Ok((eligible, ineligible))
    }

    fn refusal_preview(db: &Connection, id: i64, revision: &str) -> Result<(Value, Option<Value>)> {
        let row = db
            .query_row(
                "SELECT o.kind,o.state,o.job_id IS NOT NULL,o.txid IS NOT NULL,
                e.evidence,e.resolution,
                EXISTS(SELECT 1 FROM operation_candidates WHERE operation_id=o.id),
                EXISTS(SELECT 1 FROM operation_links WHERE operation_id=o.id OR retry_of=o.id),
                EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code IN
                    ('submission_queued','job_pending','job_binding_mismatch',
                     'transaction_included_unconfirmed','processed_submission_rejected',
                     'queued_job_expired','unbound_job_expiry','mine_completed',
                     'receipt_included','receipt_rejected','checkpoint_coverage_reported')),
                o.request,o.result,o.payload,o.work_key,o.next_at,o.generation,o.revision,
                o.created_at,o.updated_at,e.dispatch_sequence,e.observed_at,
                (SELECT retry_not_before FROM operation_timing WHERE operation_id=o.id)
             FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id WHERE o.id=?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, bool>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, bool>(6)?,
                        r.get::<_, bool>(7)?,
                        r.get::<_, bool>(8)?,
                        json!({
                            "request":r.get::<_,String>(9)?,
                            "result":r.get::<_,Option<String>>(10)?,
                            "payload":r.get::<_,Option<String>>(11)?,
                            "work_key":r.get::<_,String>(12)?,
                            "next_at":r.get::<_,i64>(13)?,
                            "generation":r.get::<_,i64>(14)?,
                            "revision":r.get::<_,String>(15)?,
                            "created_at":r.get::<_,i64>(16)?,
                            "updated_at":r.get::<_,i64>(17)?,
                            "dispatch_sequence":r.get::<_,Option<i64>>(18)?,
                            "observed_at":r.get::<_,Option<i64>>(19)?,
                            "retry_not_before":r.get::<_,Option<i64>>(20)?
                        }),
                    ))
                },
            )
            .optional()?
            .context("operation not found")?;
        let (
            kind,
            state,
            job,
            transaction,
            evidence,
            resolution,
            candidates,
            linked,
            accepted,
            captured,
        ) = row;
        let evidence_value = evidence
            .as_deref()
            .and_then(|text| serde_json::from_str::<Value>(text).ok());
        let diagnostic = evidence_value.as_ref().and_then(|value| {
            serde_json::from_value::<crate::protocol::DiagnosticEvidence>(value.clone()).ok()
        });
        let classification = diagnostic.as_ref().and_then(|e| {
            if e.stage != crate::protocol::ResponseSource::Submit
                || e.route.as_str() != kind
                || e.shape != "object"
                || !matches!(
                    e.reason.as_str(),
                    "route_result_unknown" | "proven_not_accepted"
                )
            {
                return None;
            }
            match (e.status, e.error_category.as_deref()) {
                (
                    Some(429),
                    Some(
                        "rate_limited"
                        | "accept_queue_full"
                        | "grade_queue_full"
                        | "answer_global_ceiling",
                    ),
                ) => Some(if e.reason == "proven_not_accepted" {
                    "submit_429_pre_enqueue"
                } else {
                    "legacy_429_policy_refusal"
                }),
                // Old endpoint_halted also represented broad paused/halted flags
                // and prefix matches. Only the exact middleware category is proof.
                (Some(503), Some("halt_middleware"))
                    if e.route != WorkKind::Mine && e.reason == "proven_not_accepted" =>
                {
                    Some("submit_503_halt_middleware")
                }
                _ => None,
            }
        });
        let evidence_limit = match classification {
            Some("legacy_429_policy_refusal") => {
                "Applies the developer's all-429 pre-enqueue refusal contract to retained legacy classification. The original response body was not retained; hidden body contradictions cannot be ruled out. No new network verification."
            }
            Some(_) => {
                "Retained positive submit-refusal classification; original response body not retained and no new network verification."
            }
            None => {
                "Retained evidence does not establish an eligible refusal. Generic or legacy endpoint_halted 503 is insufficient; exact halt503 also requires a positive proven_not_accepted classification."
            }
        };
        // Unknown diagnostic fields may carry newer contradictory evidence. Do
        // not silently discard them when interpreting an older retained record.
        let known_fields = evidence_value
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(|fields| {
                fields.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "stage"
                            | "route"
                            | "status"
                            | "reason"
                            | "retry_after_seconds"
                            | "shape"
                            | "error_category"
                    )
                })
            });
        let audit: Option<Value> = resolution
            .as_deref()
            .and_then(|text| serde_json::from_str(text).ok());
        // Retirement removes this row from uncertainty accounting. Never make
        // an unexpired server (or legacy conservative) floor inert that way.
        let retained_floor = captured["retry_not_before"]
            .as_i64()
            .or_else(|| captured["next_at"].as_i64())
            .unwrap_or(i64::MAX);
        // Older writers could commit diagnostics before their timing update.
        let diagnostic_floor = evidence_value
            .as_ref()
            .map(|evidence| Self::captured_retry_floor(evidence, captured["observed_at"].as_i64()))
            .unwrap_or(0);
        let retry_not_before = retained_floor.max(diagnostic_floor);
        let reason = if state != "unknown" {
            "not_unknown"
        } else if retry_not_before > now() {
            "retry_after_pending"
        } else if job || transaction || candidates || linked || accepted {
            "acceptance_or_linkage_evidence"
        } else if resolution.is_some() {
            "existing_resolution"
        } else if classification.is_none() || !known_fields {
            "retained_refusal_not_proven"
        } else {
            "eligible"
        };
        let eligible = reason == "eligible";
        let (database_id, dispatch_sequence, generation, paused): (String, i64, i64, bool) = db.query_row(
            "SELECT a.database_id,a.dispatch_sequence,c.generation,c.paused FROM authority a,control c
             WHERE a.singleton=1 AND c.singleton=1", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        )?;
        let token =
            eligible.then(|| {
                digest(json!({
            "contract":"retained_refusal_v2","database_id":database_id,
            "dispatch_sequence":dispatch_sequence,"generation":generation,"paused":paused,
            "config_revision":revision,"operation_id":id,"kind":kind,"state":state,
            "evidence":evidence,"captured":captured,
            "classification":classification,"evidence_limit":evidence_limit
        }).to_string())
            });
        Ok((
            json!({
                "operation_id":id,"kind":kind,"state":state,"eligible":eligible,
                "reason":reason,"classification":classification,"target_state":"refused",
                "preview_token":token,"config_revision":revision,"generation":generation,
                "retry_not_before":retry_not_before,
                "dry_run":true,"resolved":false,"applied":false,"already_resolved":false,
                "network_requests_reset":false,"historical_payload_retried":false,
                "evidence_limit":evidence_limit,
            }),
            audit,
        ))
    }

    fn resolve_refusal(&mut self, id: i64, revision: &str, token: &str) -> Result<Value> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut preview, audit) = Self::refusal_preview(&tx, id, revision)?;
        if preview["state"] == "refused"
            && audit.as_ref().is_some_and(|audit| {
                audit["source"] == "operator_retained_refusal"
                    && audit["preview_token"].as_str() == Some(token)
            })
        {
            preview["dry_run"] = json!(false);
            preview["resolved"] = json!(true);
            preview["already_resolved"] = json!(true);
            preview["reason"] = json!("already_resolved");
            tx.commit()?;
            return Ok(preview);
        }
        if preview["eligible"] != true {
            return Err(RefusalRecoveryError("refusal_recovery_ineligible").into());
        }
        if preview["preview_token"].as_str() != Some(token) {
            return Err(RefusalRecoveryError("refusal_recovery_conflict").into());
        }
        let at = now();
        let resolution = json!({
            "source":"operator_retained_refusal","contract":"retained_refusal_v2",
            "state":"refused","previous_state":"unknown","at":at,
            "authorization":"explicit_preview_token","preview_token":token,
            "config_revision":revision,"generation":preview["generation"],
            "classification":preview["classification"],
            "evidence_limit":preview["evidence_limit"],
            "network_requests_reset":false,"historical_payload_retried":false,
        });
        let changed = tx.execute(
            "UPDATE operation_evidence SET resolution=?1 WHERE operation_id=?2 AND resolution IS NULL",
            params![serde_json::to_string(&resolution)?, id],
        )?;
        if changed != 1 {
            return Err(RefusalRecoveryError("refusal_recovery_conflict").into());
        }
        let changed = tx.execute(
            "UPDATE operations SET state='refused',updated_at=?1 WHERE id=?2 AND state='unknown'
             AND job_id IS NULL AND txid IS NULL",
            params![at, id],
        )?;
        if changed != 1 {
            return Err(RefusalRecoveryError("refusal_recovery_conflict").into());
        }
        tx.execute(
            "INSERT INTO events(at,code,kind,operation_id) VALUES(?1,'historical_refusal_retired',?2,?3)",
            params![at,preview["kind"].as_str(),id],
        )?;
        tx.commit()?;
        preview["state"] = json!("refused");
        preview["eligible"] = json!(false);
        preview["reason"] = json!("historical_refusal_retired");
        preview["dry_run"] = json!(false);
        preview["resolved"] = json!(true);
        preview["applied"] = json!(true);
        Ok(preview)
    }

    pub(crate) fn inspect(&self, id: i64) -> Result<Value> {
        let op = self.operation(id)?.context("operation not found")?;
        let policy = if self.schema_version()? == 2 {
            self.db.query_row("SELECT policy,evidence,dispatch_sequence,blocked_since,resolution FROM operation_evidence WHERE operation_id=?1",
                [id], |r| Ok(json!({"captured_policy":r.get::<_,Option<String>>(0)?,
                    "evidence":r.get::<_,Option<String>>(1)?,"dispatch_sequence":r.get::<_,Option<i64>>(2)?,
                    "blocked_since":r.get::<_,Option<i64>>(3)?,"resolution":r.get::<_,Option<String>>(4)?}))).optional()?
        } else {
            None
        };
        let candidates = if self.schema_version()? == 2 {
            self.db
                .query_row(
                    "SELECT candidates,truncated FROM operation_candidates WHERE operation_id=?1",
                    [id],
                    |r| {
                        Ok(json!({"untrusted":true,"candidates":r.get::<_,String>(0)?,
                    "truncated":r.get::<_,bool>(1)?}))
                    },
                )
                .optional()?
        } else {
            None
        };
        let window: (i64, i64) = self.db.query_row(
            "SELECT created_at,updated_at FROM operations WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let identity_text: String =
            self.db
                .query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let identity: Value = serde_json::from_str(&identity_text)?;
        let mut admissions = if self.has_table("risk_admissions")? {
            let mut statement = self.db.prepare(
                "SELECT dispatch_sequence,policy,revision,blocker_ids,retry_of,manual_grant_id,admitted_at
                FROM risk_admissions WHERE operation_id=?1 ORDER BY dispatch_sequence",
            )?;
            statement.query_map([id], |r| Ok(json!({
                "dispatch_sequence":r.get::<_,i64>(0)?,"policy":r.get::<_,String>(1)?,
                "revision":r.get::<_,String>(2)?,"blocker_ids":r.get::<_,String>(3)?,
                "retry_of":r.get::<_,Option<i64>>(4)?,"manual_grant_id":r.get::<_,Option<i64>>(5)?,
                "admitted_at":r.get::<_,i64>(6)?,
            })))?.collect::<std::result::Result<Vec<_>,_>>()?
        } else {
            Vec::new()
        };
        if self.has_table("risk_historical_answers")? {
            let mut query = self.db.prepare(
                "SELECT operation_id,accepted_answer_id FROM risk_historical_answers
                WHERE dispatch_sequence=?1 ORDER BY operation_id",
            )?;
            for admission in &mut admissions {
                let links = query
                    .query_map(
                        [admission["dispatch_sequence"]
                            .as_i64()
                            .context("risk sequence missing")?],
                        |row| {
                            Ok(HistoricalAnswer {
                                operation_id: row.get(0)?,
                                accepted_answer_id: row.get(1)?,
                            })
                        },
                    )?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                admission["historical_unknown_answers"] = serde_json::to_value(links)?;
            }
        }
        if self.has_table("risk_accounting_snapshots")? {
            for admission in &mut admissions {
                let sequence = admission["dispatch_sequence"]
                    .as_i64()
                    .context("risk sequence missing")?;
                let snapshot: Option<(i64, u64, u64, u64)> = self
                    .db
                    .query_row(
                        "SELECT witness_revision,unresolved_count,eligible_count,exempt_count
                     FROM risk_accounting_snapshots WHERE dispatch_sequence=?1",
                        [sequence],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                if let Some((revision, total, eligible, exempt)) = snapshot {
                    let mut query = self.db.prepare(
                        "SELECT e.original_id,e.accepted_answer_id
                         FROM historical_answer_accounting_events e
                         WHERE e.revision<=?1 AND e.accepted_answer_id IS NOT NULL AND ?2>0
                         AND NOT EXISTS(SELECT 1 FROM historical_answer_accounting_events newer
                            WHERE newer.original_id=e.original_id
                            AND newer.revision>e.revision AND newer.revision<=?1)
                         ORDER BY e.original_id LIMIT ?3",
                    )?;
                    let examples = query
                        .query_map(
                            params![revision, exempt, HISTORICAL_EXAMPLE_LIMIT as i64],
                            |r| {
                                Ok(HistoricalAnswer {
                                    operation_id: r.get(0)?,
                                    accepted_answer_id: r.get(1)?,
                                })
                            },
                        )?
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    admission["accounting"] = json!({
                        "witness_revision":revision,"unresolved_count":total,
                        "historical_eligible_count":eligible,"capacity_exempt_count":exempt,
                        "active_unresolved_count":total-exempt,"blocker_ids_scope":"active",
                    });
                    admission["historical_unknown_answers_truncated"] =
                        json!(exempt > examples.len() as u64);
                    admission["historical_unknown_answer_count"] = json!(exempt);
                    admission["historical_unknown_answers"] = serde_json::to_value(examples)?;
                }
            }
        }
        let linkage: Option<(i64, bool)> = if self.has_table("operation_links")? {
            self.db
                .query_row(
                    "SELECT retry_of,payload_reused FROM operation_links WHERE operation_id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
        } else {
            None
        };
        Ok(
            json!({"private":true,"operation_id":id,"kind":op.kind,"state":op.state,
            "identity":{"chain":identity["chain"],"address":identity["address"],"origin":identity["base_url"]},
            "input_digest":digest(serde_json::to_vec(&op.request)?),
            "work_key":op.key,"request":op.request,"result":op.result,"payload":op.payload,
            "payload_digest":op.payload.as_ref().map(serde_json::to_vec).transpose()?.map(digest),
            "job_id":op.job_id,"txid":op.txid,"attempt_started_at":window.0,"last_transition_at":window.1,
            "untrusted_identifier_candidates":candidates,
            "risk_admissions":admissions,"retry_of":linkage.map(|l| l.0),
            "payload_reused":linkage.map(|l| l.1).unwrap_or(false),
            "details":policy,"binding_requirement":"persisted request identifier and authoritative terminal response; similarity is insufficient"}),
        )
    }

    pub(crate) fn operations_list(
        &self,
        kind: Option<WorkKind>,
        state: Option<&str>,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Value> {
        validate_page(before, limit)?;
        if state.is_some_and(|state| {
            state.is_empty()
                || state.len() > 64
                || !state.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        }) {
            bail!("invalid operation state filter");
        }
        let snapshot = self.db.unchecked_transaction()?;
        let current = now();
        let waits = self.wait_evidence()?;
        let (link_columns, link_join) = if self.has_table("operation_links")? {
            (
                "l.retry_of,COALESCE(l.payload_reused,0)",
                "LEFT JOIN operation_links l ON l.operation_id=o.id",
            )
        } else {
            ("NULL,0", "")
        };
        let (evidence_columns, evidence_join) = if self.has_table("operation_evidence")? {
            (
                "e.blocked_since,e.model_deadline,e.http_deadline",
                "LEFT JOIN operation_evidence e ON e.operation_id=o.id",
            )
        } else {
            ("NULL,NULL,NULL", "")
        };
        let (timing_column, timing_join) = if self.has_table("operation_timing")? {
            (
                "t.retry_not_before",
                "LEFT JOIN operation_timing t ON t.operation_id=o.id",
            )
        } else {
            ("NULL", "")
        };
        let mut statement = self.db.prepare(&format!(
            "SELECT o.id,o.kind,o.state,o.request,o.created_at,o.updated_at,o.next_at,o.generation,
                o.job_id IS NOT NULL,o.txid IS NOT NULL,{link_columns},{evidence_columns},{timing_column}
            FROM operations o {link_join} {evidence_join} {timing_join}
            WHERE (?1 IS NULL OR o.kind=?1) AND (?2 IS NULL OR o.state=?2)
                AND (?3 IS NULL OR o.id<?3) ORDER BY o.id DESC LIMIT ?4",
        ))?;
        let rows = statement.query_map(
            params![kind.map(|k| k.as_str()),state,before,(limit+1) as i64],
            |r| Ok((json!({
                "operation_id":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,
                "state":r.get::<_,String>(2)?,"created_at":r.get::<_,i64>(4)?,
                "updated_at":r.get::<_,i64>(5)?,"next_at":r.get::<_,i64>(6)?,
                "generation":r.get::<_,i64>(7)?,"has_job_id":r.get::<_,bool>(8)?,
                "has_txid":r.get::<_,bool>(9)?,"retry_of":r.get::<_,Option<i64>>(10)?,
                "payload_reused":r.get::<_,bool>(11)?,"blocked_since":r.get::<_,Option<i64>>(12)?,
                "model_deadline":r.get::<_,Option<i64>>(13)?,"http_deadline":r.get::<_,Option<i64>>(14)?,
                "retry_not_before":r.get::<_,Option<i64>>(15)?,
            }),r.get::<_,String>(3)?)),
        )?;
        let mut operations = Vec::with_capacity(limit.min(100));
        let mut more = false;
        for row in rows {
            let (mut operation, request) = row?;
            if operations.len() == limit {
                more = true;
                break;
            }
            let request: Value = serde_json::from_str(&request)?;
            operation["epoch"] = request["solver"]["epoch"]
                .as_u64()
                .map_or(Value::Null, Value::from);
            let empty = WaitEvidence::default();
            operation["wait"] = waits
                .get(&operation["operation_id"].as_i64().unwrap_or(-1))
                .unwrap_or(&empty)
                .projection(
                    operation["state"].as_str().unwrap_or_default(),
                    operation["blocked_since"].as_i64(),
                    current,
                );
            operations.push(operation);
        }
        let next_before = more
            .then(|| operations.last().and_then(|op| op["operation_id"].as_i64()))
            .flatten();
        snapshot.commit()?;
        Ok(json!({"operations":operations,"next_before":next_before}))
    }

    pub(crate) fn grants(&self, before: Option<i64>, limit: usize) -> Result<Value> {
        validate_page(before, limit)?;
        if !self.has_table("manual_grants")? {
            return Ok(json!({"grants":[],"next_before":null}));
        }
        let snapshot = self.db.unchecked_transaction()?;
        let control = self.control()?;
        let (revoked_column, revoked_join) = if self.has_table("manual_grant_revocations")? {
            (
                "r.revoked_at",
                "LEFT JOIN manual_grant_revocations r ON r.grant_id=g.id",
            )
        } else {
            ("NULL", "")
        };
        let mut statement = self.db.prepare(&format!(
            "SELECT g.id,g.epoch,g.kind,g.generation,g.created_at,g.consumed_by,{revoked_column}
            FROM manual_grants g {revoked_join} WHERE (?1 IS NULL OR g.id<?1) ORDER BY g.id DESC LIMIT ?2",
        ))?;
        let mut grants = statement.query_map(params![before,(limit+1) as i64], |r| {
            let generation: i64 = r.get(3)?;
            let consumed_by: Option<i64> = r.get(5)?;
            let revoked_at: Option<i64> = r.get(6)?;
            Ok(json!({"grant_id":r.get::<_,i64>(0)?,"epoch":r.get::<_,u64>(1)?,
                "kind":r.get::<_,String>(2)?,"generation":generation,"created_at":r.get::<_,i64>(4)?,
                "consumed_by":consumed_by,"revoked_at":revoked_at,
                "state":if revoked_at.is_some() {"revoked"} else if consumed_by.is_some() {"consumed"}
                    else if generation!=control.generation {"expired"} else {"pending"},
                "current_generation":generation==control.generation}))
        })?.collect::<std::result::Result<Vec<_>,_>>()?;
        let more = grants.len() > limit;
        grants.truncate(limit);
        let next_before = more
            .then(|| grants.last().and_then(|g| g["grant_id"].as_i64()))
            .flatten();
        snapshot.commit()?;
        Ok(json!({"grants":grants,"next_before":next_before}))
    }

    pub(crate) fn revoke_grant(&mut self, grant_id: i64) -> Result<Value> {
        self.continuity()?;
        if grant_id <= 0 {
            bail!("grant ID must be positive");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed: Option<Option<i64>> = tx
            .query_row(
                "SELECT consumed_by FROM manual_grants WHERE id=?1",
                [grant_id],
                |r| r.get(0),
            )
            .optional()?;
        if consumed.context("manual grant not found")?.is_some() {
            bail!("a consumed manual grant cannot be revoked");
        }
        let changed = tx.execute(
            "INSERT OR IGNORE INTO manual_grant_revocations VALUES (?1,?2)",
            params![grant_id, now()],
        )?;
        if changed == 1 {
            tx.execute(
                "INSERT INTO events(at,code) VALUES (?1,'participation_authorization_revoked')",
                [now()],
            )?;
        }
        let revoked_at: i64 = tx.query_row(
            "SELECT revoked_at FROM manual_grant_revocations WHERE grant_id=?1",
            [grant_id],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(json!({"grant_id":grant_id,"revoked":true,"revoked_at":revoked_at}))
    }

    /// Every page owns a short read snapshot, never a transaction across output
    /// or polling. An absent journal is itself a cursor: its first events must
    /// be read from ID 1 rather than taking another, potentially lossy tail.
    pub(crate) fn follow_events(
        config: &Config,
        cursor: Option<&EventCursor>,
        initial_limit: usize,
    ) -> Result<EventPage> {
        const PAGE_SIZE: i64 = 1000;
        let path = config.state_dir.join("state.sqlite3");
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(journal) = cursor.and_then(|cursor| cursor.journal.as_ref())
            && !before
                .as_ref()
                .is_some_and(|metadata| same_journal_file(&journal.file, metadata))
        {
            return Err(EventCursorError::Replaced.into());
        }
        let Some(store) = Self::read_only(config)? else {
            if before.is_some() {
                return Err(EventCursorError::Replaced.into());
            }
            return Ok(EventPage {
                cursor: EventCursor::default(),
                events: Vec::new(),
                more: false,
            });
        };
        let before = before.ok_or(EventCursorError::Replaced)?;
        let snapshot = store.db.unchecked_transaction()?;
        let (database_id, dispatch_sequence) = store.database_identity()?;
        if database_id.len() != 32
            || !database_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || dispatch_sequence < 0
        {
            bail!("invalid journal authority");
        }
        let high_water: i64 =
            snapshot.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |row| {
                row.get(0)
            })?;
        if high_water < 0 {
            return Err(EventCursorError::Regressed.into());
        }
        if let Some(cursor) = cursor {
            if let Some(journal) = &cursor.journal {
                if database_id != journal.database_id {
                    return Err(EventCursorError::Replaced.into());
                }
                if dispatch_sequence < journal.dispatch_sequence {
                    return Err(EventCursorError::Regressed.into());
                }
            }
            if high_water < cursor.observed_through {
                return Err(EventCursorError::Regressed.into());
            }
        }
        let after = match cursor {
            Some(cursor) => cursor.after,
            None if initial_limit == 0 => high_water,
            None => snapshot.query_row(
                "SELECT COALESCE(
                    (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?1),
                    (SELECT MIN(id) FROM events),1)-1",
                [initial_limit.min(i64::MAX as usize) as i64 - 1],
                |row| row.get(0),
            )?,
        };
        let events = {
            let mut statement = snapshot.prepare(
                "SELECT id,at,code,kind FROM events
                 WHERE id>?1 AND id<=?2 ORDER BY id LIMIT ?3",
            )?;
            statement
                .query_map(params![after, high_water, PAGE_SIZE], |row| {
                    Ok(JournalEvent {
                        id: row.get(0)?,
                        at: row.get(1)?,
                        event: row.get(2)?,
                        kind: row.get(3)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut after = after;
        for event in &events {
            if after.checked_add(1) != Some(event.id) {
                return Err(EventCursorError::Gap.into());
            }
            after = event.id;
        }
        if events.is_empty() && after < high_water {
            return Err(EventCursorError::Gap.into());
        }
        snapshot.commit()?;
        let current = fs::symlink_metadata(&path).map_err(|_| EventCursorError::Replaced)?;
        if !same_journal_file(&before, &current) {
            return Err(EventCursorError::Replaced.into());
        }
        Ok(EventPage {
            cursor: EventCursor {
                journal: Some(EventJournal {
                    database_id,
                    dispatch_sequence,
                    file: before,
                }),
                after,
                observed_through: high_water,
            },
            events,
            more: after < high_water,
        })
    }

    pub(crate) fn events(&self, limit: usize) -> Result<Value> {
        let mut stmt = self
            .db
            .prepare("SELECT at,code,kind FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit.min(1000) as i64], |r| {
            Ok(json!({"at":r.get::<_,i64>(0)?,"event":r.get::<_,String>(1)?,"kind":r.get::<_,Option<String>>(2)?}))
        })?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!(rows))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal_evidence(kind: WorkKind, status: u16, category: Option<&str>) -> Value {
        json!({
            "stage":"submit","route":kind.as_str(),"status":status,
            "reason":"route_result_unknown","retry_after_seconds":3600,
            "shape":"object","error_category":category
        })
    }

    #[test]
    fn doctor_batch_preserves_partial_progress_and_fences_configuration_and_writer() {
        let (temp, mut config) = fixture();
        config.network.chain = format!(
            "test-{}",
            temp.path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replace('.', "")
        );
        config.network.address = format!("poa1{}", "1".repeat(32));
        config.network.credential_file = temp.path().join("unused-credential");
        let path = temp.path().join("config.toml");
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let (account, mut store) = AccountLock::acquire(&config).unwrap();
        store.set_paused(false).unwrap();
        for epoch in 1..=3 {
            let op = prepared_epoch(&mut store, WorkKind::Judge, epoch, "historical");
            // Seed legacy retained outcomes; do not ask today's dispatcher to
            // reproduce historical concurrent writes or ignore refusal floors.
            store
                .db
                .execute("UPDATE operations SET state='unknown' WHERE id=?1", [op.id])
                .unwrap();
            store
                .record_evidence(op.id, &refusal_evidence(op.kind, 429, Some("rate_limited")))
                .unwrap();
            age_refusal_evidence(&store, op.id);
        }
        store.set_paused(true).unwrap();
        let preview = doctor_repairs(&path, None).unwrap();
        assert!(doctor_repairs(&path, Some(&preview)).is_err());
        drop(account);
        assert!(
            doctor_repairs(
                &path,
                Some(&json!({"config_revision":"stale-configuration"}))
            )
            .is_err()
        );
        assert_eq!(store.operation(1).unwrap().unwrap().state, "unknown");
        store
            .db
            .execute_batch(
                "CREATE TRIGGER reject_second_audit BEFORE INSERT ON events
             WHEN NEW.code='historical_refusal_retired' AND NEW.operation_id=2
             BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;",
            )
            .unwrap();
        drop(store);
        let result = doctor_repairs(&path, Some(&preview)).unwrap();
        assert_eq!(result["failure"], "refusal_recovery_failed");
        assert_eq!(result["applied"][0]["operation_id"], 1);
        assert_eq!(result["skipped"][0]["operation_id"], 2);
        assert_eq!(result["skipped"][1]["operation_id"], 3);
        let store = Store::read_only(&config).unwrap().unwrap();
        assert_eq!(store.operation(1).unwrap().unwrap().state, "refused");
        assert_eq!(store.operation(2).unwrap().unwrap().state, "unknown");
        assert_eq!(store.operation(3).unwrap().unwrap().state, "unknown");
        assert!(store.control().unwrap().paused);
    }

    #[test]
    fn work_diagnostics_preserve_bound_recovery_and_effective_model_budget() {
        let (_temp, mut config, mut store) = participation_fixture();
        let mut judge = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        judge.job_id = Some("private-job-canary".into());
        store.save(&judge, "dispatch_outcome_unknown").unwrap();
        store.observe(2, false).unwrap();
        config.participation.mode = ParticipationMode::Manual;
        config.preparation.retry_uncertain = true;
        config.preparation.max_attempts_per_work = 1;
        let mut model = store
            .begin(
                WorkKind::Answer,
                "2:words",
                "generating",
                &json!({"solver":{"epoch":2}}),
                store.control().unwrap(),
                "fixture",
            )
            .unwrap();
        model.state = "model_unknown".into();
        store.save(&model, "model_launch_unknown").unwrap();
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["pending_work"][0]["reconciliation_scope"], "job");
        assert_eq!(status["pending_work"][0]["capacity_counted"], true);
        assert!(!status.to_string().contains("private-job-canary"));
        assert_eq!(status["work"]["answer"]["model"]["retry_eligible"], false);
        assert_eq!(status["work"]["answer"]["model"]["budget_used"], 1);
        assert_eq!(status["work"]["answer"]["manual_authorized"], false);
        assert_eq!(
            status["work"]["answer"]["admission"]["reason"],
            "manual_authorization_required"
        );
        config.preparation.max_attempts_per_work = 2;
        // Desired configuration alone must not make the old loaded budget larger.
        assert_eq!(
            store.status(&config).unwrap()["work"]["answer"]["model"]["retry_eligible"],
            false
        );
        store.runtime_state(&config, false).unwrap();
        store.authorize(&config, 2, WorkKind::Answer).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["model"]["retry_eligible"], true);
        assert_eq!(status["work"]["answer"]["manual_authorized"], true);
    }

    #[test]
    fn refusal_recovery_excludes_actual_contradictory_response_diagnostics_without_candidates() {
        use crate::protocol::{
            Outcome, Response, ResponseSource, classify_source, response_candidates,
            response_evidence,
        };
        for (kind, status) in [
            (WorkKind::Answer, 429),
            (WorkKind::Judge, 429),
            (WorkKind::Mine, 429),
            (WorkKind::Answer, 503),
            (WorkKind::Judge, 503),
        ] {
            for (field, value) in [
                ("state", json!("done")),
                ("state", Value::Null),
                ("txid", Value::Null),
                ("id", Value::Null),
                ("challenge_txid", Value::Null),
            ] {
                let (_temp, config, mut store) = participation_fixture();
                let op = dispatched_unknown(&mut store, &config, kind, 1);
                let mut body = if status == 503 {
                    json!({"error":"endpoint temporarily halted — API hardening in progress"})
                } else {
                    json!({})
                };
                body[field] = value;
                let response = Response {
                    status,
                    body,
                    retry_after_seconds: None,
                    read_failure: None,
                };
                assert!(matches!(
                    classify_source(kind, &response, ResponseSource::Submit),
                    Outcome::Unknown { .. },
                ));
                let diagnostic = response_evidence(kind, ResponseSource::Submit, Some(&response));
                assert!(!matches!(
                    diagnostic.reason.as_str(),
                    "route_result_unknown" | "proven_not_accepted",
                ));
                let candidates = response_candidates(&response);
                assert!(candidates.job_id.is_none());
                assert!(candidates.transaction_ids.is_empty());
                store
                    .record_candidates(op.id, &serde_json::to_value(candidates).unwrap())
                    .unwrap();
                store
                    .record_evidence(op.id, &serde_json::to_value(diagnostic).unwrap())
                    .unwrap();
                let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
                assert_eq!(preview["eligible"], false, "{kind:?} {status} {field}");
                assert_eq!(preview["reason"], "retained_refusal_not_proven");
                assert!(preview["preview_token"].is_null());
                assert!(
                    store
                        .resolve_refusal(op.id, "revision", "unapproved")
                        .is_err()
                );
                assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
            }
        }
    }

    fn age_refusal_evidence(store: &Store, id: i64) {
        // Historical fixtures advertise a one-hour delay. Their observations
        // must actually predate that floor rather than relying on missing timing.
        store
            .db
            .execute(
                "UPDATE operation_evidence SET observed_at=?1 WHERE operation_id=?2",
                params![now() - 7200, id],
            )
            .unwrap();
    }

    #[test]
    fn refusal_preview_preserves_retry_after_across_diagnostic_before_timing_crash() {
        use crate::protocol::{Response, ResponseSource, response_evidence};
        for missing_timing in [false, true] {
            let (_temp, config, mut store) = participation_fixture();
            let op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            let response = Response {
                status: 429,
                body: json!({"error":"accept queue full"}),
                retry_after_seconds: Some(3600),
                read_failure: None,
            };
            let diagnostic = response_evidence(op.kind, ResponseSource::Submit, Some(&response));
            assert_eq!(diagnostic.reason, "proven_not_accepted");
            let mut evidence = serde_json::to_value(diagnostic).unwrap();
            store.record_evidence(op.id, &evidence).unwrap();
            if missing_timing {
                store
                    .db
                    .execute(
                        "DELETE FROM operation_timing WHERE operation_id=?1",
                        [op.id],
                    )
                    .unwrap();
            }
            let observed_at: i64 = store
                .db
                .query_row(
                    "SELECT observed_at FROM operation_evidence WHERE operation_id=?1",
                    [op.id],
                    |row| row.get(0),
                )
                .unwrap();
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], false);
            assert_eq!(preview["reason"], "retry_after_pending");
            assert_eq!(preview["retry_not_before"], observed_at + 3601);
            assert!(
                store
                    .resolve_refusal(op.id, "revision", "unapproved")
                    .is_err()
            );
            age_refusal_evidence(&store, op.id);
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], true);
            let expired_token = preview["preview_token"].as_str().unwrap();
            store
                .db
                .execute(
                    "UPDATE operation_evidence SET observed_at=NULL WHERE operation_id=?1",
                    [op.id],
                )
                .unwrap();
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], false);
            assert_eq!(preview["retry_not_before"], i64::MAX);
            assert!(
                store
                    .resolve_refusal(op.id, "revision", expired_token)
                    .is_err()
            );
            evidence["retry_after_seconds"] = json!(u64::MAX);
            store.record_evidence(op.id, &evidence).unwrap();
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], false);
            assert_eq!(preview["retry_not_before"], i64::MAX);
            assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
        }
    }

    #[test]
    fn retained_refusal_preview_requires_exact_authority_and_no_contradictions() {
        for (status, category, eligible) in [
            (429, Some("rate_limited"), true),
            (429, Some("grade_queue_full"), true),
            (429, Some("answer_global_ceiling"), true),
            (429, None, false),
            (503, Some("halt_middleware"), false),
            (503, Some("endpoint_halted"), false),
            (503, Some("service_unavailable"), false),
            (503, None, false),
            (502, Some("bad_gateway"), false),
            (504, Some("gateway_timeout"), false),
            (400, Some("request_rejected"), false),
        ] {
            let (_temp, config, mut store) = participation_fixture();
            let op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            store
                .record_evidence(op.id, &refusal_evidence(op.kind, status, category))
                .unwrap();
            age_refusal_evidence(&store, op.id);
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], eligible, "{status} {category:?}");
            assert_eq!(preview["preview_token"].is_string(), eligible);
            assert_eq!(preview["resolved"], false);
            assert!(!preview.to_string().contains("captured answer"));
            assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
        }
        for (status, category, reason, classification) in [
            (
                429,
                "rate_limited",
                "route_result_unknown",
                "legacy_429_policy_refusal",
            ),
            (
                429,
                "rate_limited",
                "proven_not_accepted",
                "submit_429_pre_enqueue",
            ),
            (
                503,
                "halt_middleware",
                "proven_not_accepted",
                "submit_503_halt_middleware",
            ),
        ] {
            let (_temp, config, mut store) = participation_fixture();
            let op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            let mut evidence = refusal_evidence(op.kind, status, Some(category));
            evidence["reason"] = json!(reason);
            store.record_evidence(op.id, &evidence).unwrap();
            age_refusal_evidence(&store, op.id);
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], true);
            assert_eq!(preview["classification"], classification);
            if reason == "route_result_unknown" {
                let limit = preview["evidence_limit"].as_str().unwrap();
                assert!(limit.contains("all-429 pre-enqueue refusal contract"));
                assert!(limit.contains("hidden body contradictions cannot be ruled out"));
            } else {
                assert!(
                    preview["evidence_limit"]
                        .as_str()
                        .unwrap()
                        .contains("positive submit-refusal")
                );
            }
            let token = preview["preview_token"].as_str().unwrap();
            store.resolve_refusal(op.id, "revision", token).unwrap();
            let (_, audit) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            let audit = audit.unwrap();
            assert_eq!(audit["classification"], classification);
            assert_eq!(audit["evidence_limit"], preview["evidence_limit"]);
        }
        {
            let (_temp, config, mut store) = participation_fixture();
            let op = dispatched_unknown(&mut store, &config, WorkKind::Mine, 1);
            let mut evidence = refusal_evidence(op.kind, 503, Some("halt_middleware"));
            evidence["reason"] = json!("proven_not_accepted");
            store.record_evidence(op.id, &evidence).unwrap();
            age_refusal_evidence(&store, op.id);
            assert_eq!(
                Store::refusal_preview(&store.db, op.id, "revision")
                    .unwrap()
                    .0["eligible"],
                false
            );
        }
        for (field, value) in [
            ("stage", json!("bound_job")),
            ("route", json!("answer")),
            ("shape", json!("unavailable")),
            ("reason", json!("contradictory_acceptance")),
            ("reason", json!("conflicting_error_codes")),
            ("reason", json!("job_state_unknown")),
            ("reason", json!("route_transaction_missing")),
            ("reason", json!("transport_unknown")),
            ("accepted", json!(true)),
        ] {
            let (_temp, config, mut store) = participation_fixture();
            let op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            let mut evidence = refusal_evidence(op.kind, 429, Some("rate_limited"));
            evidence[field] = value;
            store.record_evidence(op.id, &evidence).unwrap();
            age_refusal_evidence(&store, op.id);
            assert_eq!(
                Store::refusal_preview(&store.db, op.id, "revision")
                    .unwrap()
                    .0["eligible"],
                false
            );
        }
        for contradiction in [
            "UPDATE operations SET job_id='private-job' WHERE id=?1",
            "UPDATE operations SET txid='private-tx' WHERE id=?1",
            "UPDATE operations SET state='queued' WHERE id=?1",
            "UPDATE operation_evidence SET resolution='{}' WHERE operation_id=?1",
            "INSERT INTO operation_candidates VALUES(?1,'{}',1)",
            "INSERT INTO operation_links VALUES(?1,?1,0)",
            "INSERT INTO events(at,code,kind,operation_id) VALUES(1,'submission_queued','judge',?1)",
            "INSERT INTO events(at,code,kind,operation_id) VALUES(1,'processed_submission_rejected','judge',?1)",
        ] {
            let (_temp, config, mut store) = participation_fixture();
            let op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            store
                .record_evidence(op.id, &refusal_evidence(op.kind, 429, Some("rate_limited")))
                .unwrap();
            age_refusal_evidence(&store, op.id);
            store.db.execute(contradiction, [op.id]).unwrap();
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], false, "{contradiction}");
            assert!(!preview.to_string().contains("private-"));
            assert!(
                store
                    .resolve_refusal(op.id, "revision", "unapproved")
                    .is_err()
            );
        }
    }

    #[test]
    fn historical_refusal_retirement_is_atomic_audited_idempotent_and_never_replays() {
        for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
            for payload in [None, Some(json!({"private":"historical-payload-canary"}))] {
                let (_temp, config, mut store) = participation_fixture();
                let mut op = dispatched_unknown(&mut store, &config, kind, 1);
                op.payload = payload;
                op.result = Some(json!({"private":"historical-model-canary"}));
                op.next_at = now() - 1;
                store.save(&op, "dispatch_outcome_unknown").unwrap();
                store.record_retry_deadline(op.id, now() - 1).unwrap();
                let evidence = refusal_evidence(kind, 429, Some("rate_limited"));
                store.record_evidence(op.id, &evidence).unwrap();
                age_refusal_evidence(&store, op.id);
                let timing = store.operation_poll_timing(op.id).unwrap();
                let control = store.control().unwrap();
                let identity = store.database_identity().unwrap();
                let budget = store.model_budget_used(kind, &op.key).unwrap();
                let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
                let token = preview["preview_token"].as_str().unwrap();
                let applied = store.resolve_refusal(op.id, "revision", token).unwrap();
                assert_eq!(applied["state"], "refused");
                assert_eq!(applied["resolved"], true);
                assert_eq!(applied["applied"], true);
                let repeated = store.resolve_refusal(op.id, "revision", token).unwrap();
                assert_eq!(repeated["already_resolved"], true);
                assert_eq!(repeated["applied"], false);
                assert!(
                    store
                        .resolve_refusal(op.id, "revision", "different-token")
                        .is_err()
                );
                store.retry_models(&config).unwrap();
                let retired = store.operation(op.id).unwrap().unwrap();
                assert_eq!(retired.state, "refused");
                assert_eq!(retired.request, op.request);
                assert_eq!(retired.payload, op.payload);
                assert_eq!(retired.result, op.result);
                assert_eq!(retired.next_at, op.next_at);
                assert_eq!(retired.generation, op.generation);
                assert_eq!(store.operation_poll_timing(op.id).unwrap(), timing);
                assert_eq!(store.control().unwrap(), control);
                assert_eq!(store.database_identity().unwrap(), identity);
                assert_eq!(store.model_budget_used(kind, &op.key).unwrap(), budget);
                assert!(store.attempted(kind, &op.key).unwrap());
                assert!(store.preparation(kind).unwrap().is_none());
                assert!(store.effect().unwrap().is_none());
                assert!(store.reconciliation_batch().unwrap().is_empty());
                assert!(store.uncertain_answer(1).unwrap().is_none());
                assert!(!store.routing_busy(&config).unwrap());
                if kind == WorkKind::Answer {
                    assert!(store.answer_epoch_attempted(1).unwrap());
                }
                if kind == WorkKind::Mine {
                    assert!(store.mine_epoch_attempted(1).unwrap());
                }
                assert_eq!(
                    store
                        .operations_list(None, Some("refused"), None, 10)
                        .unwrap()["operations"][0]["state"],
                    "refused"
                );
                let (retained, audit): (String, String) = store
                    .db
                    .query_row(
                        "SELECT evidence,resolution FROM operation_evidence WHERE operation_id=?1",
                        [op.id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(serde_json::from_str::<Value>(&retained).unwrap(), evidence);
                let audit: Value = serde_json::from_str(&audit).unwrap();
                assert_eq!(audit["source"], "operator_retained_refusal");
                assert_eq!(audit["preview_token"], token);
                assert!(!audit.to_string().contains("canary"));
                let events: i64 = store.db.query_row(
                    "SELECT COUNT(*) FROM events WHERE operation_id=?1 AND code='historical_refusal_retired'",
                    [op.id], |r| r.get(0),
                ).unwrap();
                assert_eq!(events, 1);
                // Retirement does not grant stale work a retry; ordinary new
                // work is still eligible under the unchanged control policy.
                let next = prepared_epoch(&mut store, kind, 2, "fresh");
                assert!(store.admission_allowed(&config, &next).unwrap());
            }
        }
    }

    #[test]
    fn historical_refusal_preview_tokens_detect_changes_and_audit_failure_rolls_back() {
        let (_temp, config, mut store) = participation_fixture();
        let op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        store
            .record_evidence(op.id, &refusal_evidence(op.kind, 429, Some("rate_limited")))
            .unwrap();
        age_refusal_evidence(&store, op.id);
        let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
        let token = preview["preview_token"].as_str().unwrap();
        assert!(
            store
                .resolve_refusal(op.id, "changed-config", token)
                .is_err()
        );
        store.record_retry_deadline(op.id, now() - 1).unwrap();
        assert!(store.resolve_refusal(op.id, "revision", token).is_err());
        let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
        let token = preview["preview_token"].as_str().unwrap();
        store.set_paused(true).unwrap();
        assert!(store.resolve_refusal(op.id, "revision", token).is_err());
        let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
        let token = preview["preview_token"].as_str().unwrap();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER refusal_audit_failure BEFORE INSERT ON events
             WHEN NEW.code='historical_refusal_retired'
             BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;",
            )
            .unwrap();
        assert!(store.resolve_refusal(op.id, "revision", token).is_err());
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
        let resolution: Option<String> = store
            .db
            .query_row(
                "SELECT resolution FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(resolution.is_none());
        store
            .db
            .execute_batch("DROP TRIGGER refusal_audit_failure")
            .unwrap();
        assert_eq!(
            store.resolve_refusal(op.id, "revision", token).unwrap()["resolved"],
            true
        );
    }

    #[test]
    fn historical_refusal_cannot_retire_an_unexpired_server_or_legacy_floor() {
        for legacy in [false, true] {
            let (_temp, config, mut store) = participation_fixture();
            let mut op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            store
                .record_evidence(op.id, &refusal_evidence(op.kind, 429, Some("rate_limited")))
                .unwrap();
            age_refusal_evidence(&store, op.id);
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            let token = preview["preview_token"].as_str().unwrap();
            if legacy {
                op.next_at = not_before(3600);
                store.save(&op, "dispatch_outcome_unknown").unwrap();
                store
                    .db
                    .execute(
                        "DELETE FROM operation_timing WHERE operation_id=?1",
                        [op.id],
                    )
                    .unwrap();
            } else {
                store.record_retry_minimum(op.id, 3600).unwrap();
            }
            let (preview, _) = Store::refusal_preview(&store.db, op.id, "revision").unwrap();
            assert_eq!(preview["eligible"], false);
            assert_eq!(preview["reason"], "retry_after_pending");
            assert!(preview["preview_token"].is_null());
            assert!(store.resolve_refusal(op.id, "revision", token).is_err());
            assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
        }
    }

    #[test]
    fn proven_refusal_floor_gates_other_work_without_uncertainty_even_after_rollover() {
        for mode in [
            ParticipationMode::Strict,
            ParticipationMode::ParticipationFirst,
        ] {
            for refused_kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
                let (_temp, mut config, mut store) = participation_fixture();
                let mut refused = dispatched_unknown(&mut store, &config, refused_kind, 1);
                refused.state = "retry".into();
                refused.next_at = 0;
                store.save(&refused, "submission_backoff").unwrap();
                let mut evidence = refusal_evidence(refused_kind, 429, Some("rate_limited"));
                evidence["reason"] = json!("proven_not_accepted");
                store.record_evidence(refused.id, &evidence).unwrap();
                let floor = not_before(3600);
                store.record_retry_deadline(refused.id, floor).unwrap();
                config.participation.mode = mode;
                let other_kind = if refused_kind == WorkKind::Answer {
                    WorkKind::Judge
                } else {
                    WorkKind::Answer
                };
                let mut other = prepared_epoch(&mut store, other_kind, 2, "fresh");
                for discarded in [false, true] {
                    if discarded {
                        refused.state = "discarded".into();
                        store.save(&refused, "request_no_longer_current").unwrap();
                    }
                    let accounting = Store::uncertainty_accounting(
                        &store.db,
                        &config,
                        Some(other.id),
                        None,
                        true,
                    )
                    .unwrap();
                    assert_eq!(accounting.total, 0);
                    assert_eq!(accounting.active(), 0);
                    assert_eq!(accounting.grace_until, 0);
                    assert!(accounting.blockers.is_empty());
                    assert_eq!(accounting.retry_not_before, floor);
                    assert_eq!(accounting.floor_operation, Some(refused.id));
                    assert_eq!(
                        store
                            .uncertainty_blocker_with(&config, other_kind, Some(2), &accounting)
                            .unwrap(),
                        Some(("retained_retry_minimum", Some(floor))),
                    );
                    assert!(!store.admission_allowed(&config, &other).unwrap());
                    assert!(!store.dispatch_intent(&mut other, &config).unwrap());
                    other.state = "dispatching".into();
                    assert!(
                        store
                            .save_admitted(&other, "dispatch_intent", Some(&config))
                            .is_err()
                    );
                    other.state = "prepared".into();
                }
                // Expire only the fixture clock. No stale payload is revived.
                store
                    .db
                    .execute(
                        "UPDATE operation_timing SET retry_not_before=0 WHERE operation_id=?1",
                        [refused.id],
                    )
                    .unwrap();
                assert!(store.dispatch_intent(&mut other, &config).unwrap());
                assert_eq!(
                    store.operation(refused.id).unwrap().unwrap().state,
                    "discarded"
                );
            }
        }
    }

    #[test]
    fn non_refusal_terminal_diagnostics_do_not_create_refusal_floor_authority() {
        let (_temp, config, mut store) = participation_fixture();
        let mut old = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        old.state = "discarded".into();
        store.save(&old, "request_no_longer_current").unwrap();
        store
            .record_evidence(
                old.id,
                &refusal_evidence(old.kind, 503, Some("service_unavailable")),
            )
            .unwrap();
        store.record_retry_minimum(old.id, 3600).unwrap();
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, None, None, true).unwrap();
        assert_eq!(accounting.total, 0);
        assert_eq!(accounting.retry_not_before, 0);
    }

    #[test]
    fn retry_dispatch_honors_own_retained_server_floor_even_if_local_due_time_changes() {
        let (_temp, config, mut store) = participation_fixture();
        let mut op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        op.state = "retry".into();
        op.next_at = 0;
        store.save(&op, "submission_backoff").unwrap();
        store.record_retry_minimum(op.id, 3600).unwrap();
        assert!(!store.admission_allowed(&config, &op).unwrap());
        assert!(!store.dispatch_intent(&mut op, &config).unwrap());
        // Also guard the transactional entry point against stale prechecks.
        op.state = "dispatching".into();
        assert!(
            store
                .save_admitted(&op, "dispatch_intent", Some(&config))
                .is_err()
        );
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "retry");
    }

    fn fixture() -> (tempfile::TempDir, Config) {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: temp.path().join("state"),
            ..Config::default()
        };
        (temp, config)
    }

    fn append_follow_events(store: &Store, count: i64) {
        store
            .db
            .execute(
                "WITH RECURSIVE n(i) AS (
                    VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?1)
                 INSERT INTO events(at,code,kind)
                 SELECT 123,'poll_completed','answer' FROM n",
                [count],
            )
            .unwrap();
    }

    #[test]
    fn follow_tail_and_bursts_drain_ascending_pages_without_timestamp_cursors() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        append_follow_events(&store, 2505);
        let snapshot = store.events(5000).unwrap();
        assert_eq!(snapshot.as_array().unwrap().len(), 1000);
        assert!(snapshot[0].get("id").is_none());

        let first = Store::follow_events(&config, None, 1500).unwrap();
        assert_eq!(first.events.len(), 1000);
        assert_eq!(first.events.first().unwrap().id, 1007);
        assert_eq!(first.events.last().unwrap().id, 2006);
        assert!(first.more);
        // Writers can append between pages without changing the initial tail
        // boundary. All timestamps deliberately collide.
        append_follow_events(&store, 1505);
        let mut ids: Vec<_> = first.events.iter().map(|event| event.id).collect();
        let mut cursor = first.cursor;
        loop {
            let page = Store::follow_events(&config, Some(&cursor), 1500).unwrap();
            assert!(page.events.len() <= 1000);
            assert!(page.events.iter().all(|event| event.at == 123));
            ids.extend(page.events.iter().map(|event| event.id));
            cursor = page.cursor;
            if !page.more {
                break;
            }
        }
        assert_eq!(ids, (1007..=4011).collect::<Vec<_>>());
        assert!(
            Store::follow_events(&config, Some(&cursor), 1500)
                .unwrap()
                .events
                .is_empty()
        );
        // The reader has not pinned a WAL snapshot between pages.
        let busy: i64 = store
            .db
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy, 0);
    }

    #[test]
    fn follow_missing_journal_cursor_does_not_retail_or_initialize_state() {
        let (_temp, config) = fixture();
        let absent = Store::follow_events(&config, None, 0).unwrap();
        assert!(absent.events.is_empty());
        assert!(absent.cursor.journal.is_none());
        assert!(!config.state_dir.exists());
        let still_absent = Store::follow_events(&config, Some(&absent.cursor), 0).unwrap();
        assert!(!config.state_dir.exists());

        let store = Store::open(&config).unwrap();
        append_follow_events(&store, 1205);
        let first = Store::follow_events(&config, Some(&still_absent.cursor), 0).unwrap();
        assert_eq!(first.events.len(), 1000);
        assert_eq!(first.events[0].id, 1);
        let rest = Store::follow_events(&config, Some(&first.cursor), 0).unwrap();
        assert_eq!(
            rest.events.iter().map(|event| event.id).collect::<Vec<_>>(),
            (1001..=1206).collect::<Vec<_>>()
        );
        assert!(!rest.more);
    }

    #[test]
    fn follow_zero_limit_captures_boundary_and_empty_journal_keeps_authority() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        append_follow_events(&store, 5);
        let tail = Store::follow_events(&config, None, 0).unwrap();
        assert!(tail.events.is_empty());
        assert_eq!(tail.cursor.after, 6);
        append_follow_events(&store, 2);
        let next = Store::follow_events(&config, Some(&tail.cursor), 0).unwrap();
        assert_eq!(
            next.events.iter().map(|event| event.id).collect::<Vec<_>>(),
            [7, 8]
        );

        store.db.execute("DELETE FROM events", []).unwrap();
        let empty = Store::follow_events(&config, None, 100).unwrap();
        assert!(empty.events.is_empty());
        assert!(empty.cursor.journal.is_some());
        append_follow_events(&store, 1);
        let next = Store::follow_events(&config, Some(&empty.cursor), 100).unwrap();
        assert_eq!(next.events[0].id, 1);
        store
            .db
            .execute(
                "UPDATE authority SET database_id=lower(hex(randomblob(16)))",
                [],
            )
            .unwrap();
        let error = Store::follow_events(&config, Some(&empty.cursor), 100).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Replaced)
        ));
    }

    #[test]
    fn follow_rejects_regression_of_unprinted_high_water_and_dispatch_witness() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        append_follow_events(&store, 2000);
        let first = Store::follow_events(&config, None, 2001).unwrap();
        assert_eq!(first.cursor.after, 1000);
        assert_eq!(first.cursor.observed_through, 2001);
        store
            .db
            .execute("DELETE FROM events WHERE id>1000", [])
            .unwrap();
        let error = Store::follow_events(&config, Some(&first.cursor), 2001).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Regressed)
        ));

        store
            .db
            .execute("UPDATE authority SET dispatch_sequence=2", [])
            .unwrap();
        let first = Store::follow_events(&config, None, 0).unwrap();
        store
            .db
            .execute("UPDATE authority SET dispatch_sequence=1", [])
            .unwrap();
        let error = Store::follow_events(&config, Some(&first.cursor), 0).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Regressed)
        ));
    }

    #[test]
    fn follow_rejects_pruned_and_interior_gaps_instead_of_silently_skipping() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        let first = Store::follow_events(&config, None, 0).unwrap();
        append_follow_events(&store, 2000);
        store.event("poll_completed", None).unwrap();
        let error = Store::follow_events(&config, Some(&first.cursor), 0).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Gap)
        ));

        let first = Store::follow_events(&config, None, 0).unwrap();
        append_follow_events(&store, 3);
        store
            .db
            .execute("DELETE FROM events WHERE id=?1", [first.cursor.after + 2])
            .unwrap();
        let error = Store::follow_events(&config, Some(&first.cursor), 0).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Gap)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn follow_rejects_file_replacement_even_with_the_same_database_authority() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        let first = Store::follow_events(&config, None, 0).unwrap();
        drop(store);
        let path = config.state_dir.join("state.sqlite3");
        let saved = config.state_dir.join("saved.sqlite3");
        fs::rename(&path, &saved).unwrap();
        fs::copy(&saved, &path).unwrap();
        let error = Store::follow_events(&config, Some(&first.cursor), 0).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Replaced)
        ));
        fs::remove_file(&path).unwrap();
        let error = Store::follow_events(&config, Some(&first.cursor), 0).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EventCursorError>(),
            Some(EventCursorError::Replaced)
        ));
        assert!(!path.exists());
    }

    fn begin(store: &mut Store, kind: WorkKind, key: &str, state: &str) -> Operation {
        let control = store.control().unwrap();
        let initial = if state == "generating" {
            "generating"
        } else {
            "prepared"
        };
        let mut op = store
            .begin(
                kind,
                key,
                initial,
                &json!({"private":"request-canary"}),
                control,
                "revision",
            )
            .unwrap();
        if matches!(
            state,
            "queued" | "unknown" | "included_pending" | "confirmed" | "final"
        ) {
            op.state = "dispatching".into();
            store.save(&op, "dispatch_intent").unwrap();
        }
        if state != initial {
            op.state = state.into();
            store.save(&op, "test_transition").unwrap();
        }
        op
    }

    fn participation_fixture() -> (tempfile::TempDir, Config, Store) {
        let (temp, mut config) = fixture();
        config.capabilities.answer = Mode::Active;
        config.capabilities.judge = Mode::Active;
        config.capabilities.mine = Mode::Active;
        config.participation.mode = ParticipationMode::ParticipationFirst;
        config.participation.uncertainty_grace_seconds = 0;
        config.participation.uncertain_answer_retry_seconds = 0;
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        (temp, config, store)
    }

    fn prepared_epoch(
        store: &mut Store,
        kind: WorkKind,
        epoch: u64,
        fingerprint: &str,
    ) -> Operation {
        let mut op = store
            .begin(
                kind,
                &format!("{epoch}:{fingerprint}"),
                "prepared",
                &json!({"solver":{"epoch":epoch},"challenge_fingerprint":fingerprint}),
                store.control().unwrap(),
                "prepared_revision",
            )
            .unwrap();
        op.payload = Some(json!({"answer":"captured answer"}));
        store.save(&op, "prepared").unwrap();
        op
    }

    fn dispatched_unknown(
        store: &mut Store,
        config: &Config,
        kind: WorkKind,
        epoch: u64,
    ) -> Operation {
        let mut op = prepared_epoch(store, kind, epoch, "fingerprint");
        assert!(store.dispatch_intent(&mut op, config).unwrap());
        op.state = "unknown".into();
        store.save(&op, "dispatch_outcome_unknown").unwrap();
        op
    }

    fn accepted_linked_answer(
        store: &mut Store,
        config: &Config,
        original: &Operation,
    ) -> Operation {
        let mut accepted = store
            .begin_linked(
                WorkKind::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "linked_revision",
                Some((original, true)),
            )
            .unwrap();
        assert!(store.dispatch_intent(&mut accepted, config).unwrap());
        accepted.txid = Some("b".repeat(64));
        accepted.state = "confirmed".into();
        store.save(&accepted, "receipt_included").unwrap();
        accepted
    }

    #[test]
    fn accepted_linked_capacity_and_witness_growth_survive_restart_and_tightening() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.historical_unknown_answer_capacity =
            HistoricalAnswerCapacity::AcceptedLinked;
        config.participation.max_unresolved_operations = 2;
        config.participation.retry_uncertain_answers = true;
        let mut originals = Vec::new();
        let mut accepted = Vec::new();
        for epoch in 1..=24 {
            let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, epoch);
            assert!(store.answer_retry_allowed(&config, &original).unwrap());
            accepted.push(accepted_linked_answer(&mut store, &config, &original));
            originals.push(original);
            drop(store);
            store = Store::open(&config).unwrap();
            let accounting =
                Store::uncertainty_accounting(&store.db, &config, None, None, false).unwrap();
            assert_eq!(
                (
                    accounting.total,
                    accounting.eligible,
                    accounting.exempt,
                    accounting.active()
                ),
                (epoch, epoch, epoch, 0)
            );
        }
        let mut next = prepared_epoch(&mut store, WorkKind::Answer, 25, "next");
        config.participation.max_unresolved_operations = 1;
        assert!(store.admission_allowed(&config, &next).unwrap());
        for mode in [ParticipationMode::Strict, ParticipationMode::Manual] {
            config.participation.mode = mode;
            assert!(!store.admission_allowed(&config, &next).unwrap());
            let accounting =
                Store::uncertainty_accounting(&store.db, &config, None, None, false).unwrap();
            assert_eq!(
                (accounting.eligible, accounting.exempt, accounting.active()),
                (24, 0, 24)
            );
        }
        config.participation.mode = ParticipationMode::ParticipationFirst;
        config.participation.historical_unknown_answer_capacity = HistoricalAnswerCapacity::Bounded;
        config.participation.max_historical_unknown_answers = 2;
        assert!(!store.admission_allowed(&config, &next).unwrap());
        config.participation.historical_unknown_answer_capacity =
            HistoricalAnswerCapacity::AcceptedLinked;
        store.record_retry_minimum(originals[0].id, 3600).unwrap();
        drop(store);
        store = Store::open(&config).unwrap();
        assert!(!store.admission_allowed(&config, &next).unwrap());
        assert!(
            !store
                .uncertainty_open(&config, WorkKind::Answer, Some(25), None)
                .unwrap()
        );
        // Expire only the fixture's wall-clock floor; no operation is retired.
        store
            .db
            .execute("UPDATE operation_timing SET retry_not_before=0", [])
            .unwrap();
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
        next.state = "unknown".into();
        store.save(&next, "dispatch_outcome_unknown").unwrap();
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["unresolved_count"], 25);
        assert_eq!(status["participation"]["historical_eligible_count"], 24);
        assert_eq!(status["participation"]["capacity_exempt_count"], 24);
        assert_eq!(status["participation"]["active_unresolved_count"], 1);
        assert_eq!(
            status["participation"]["historical_unknown_answers"]
                .as_array()
                .unwrap()
                .len(),
            20
        );
        assert_eq!(
            status["participation"]["historical_unknown_answers_truncated"],
            true
        );
        let inspection = store.inspect(next.id).unwrap();
        let risk = &inspection["risk_admissions"][0];
        assert_eq!(risk["accounting"]["capacity_exempt_count"], 24);
        assert_eq!(risk["blocker_ids"], "[]");
        assert_eq!(risk["historical_unknown_answers_truncated"], true);
        let counts: (u64, u64, u64) = store
            .db
            .query_row(
                "SELECT (SELECT COUNT(*) FROM historical_answer_accounting_events),
                (SELECT COUNT(*) FROM risk_accounting_snapshots),
                (SELECT COUNT(*) FROM risk_historical_answers)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (24, 48, 0));
        let blocker_count: u64 = store
            .db
            .query_row(
                "SELECT SUM(json_array_length(blocker_ids)) FROM risk_admissions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(blocker_count, 24);
        for original in &originals {
            assert_eq!(
                store.operation(original.id).unwrap().unwrap().state,
                "unknown"
            );
        }
        assert!(
            !store
                .uncertainty_open(&config, WorkKind::Answer, Some(26), None)
                .unwrap()
        );
        config.participation.max_unresolved_operations = 3;
        accepted[0].state = "rejected".into();
        store.save(&accepted[0], "receipt_rejected").unwrap();
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, None, None, false).unwrap();
        assert_eq!((accounting.exempt, accounting.active()), (23, 2));
        let mut later = prepared_epoch(&mut store, WorkKind::Answer, 26, "later");
        assert!(store.dispatch_intent(&mut later, &config).unwrap());
        let revoked: u64 = store.db.query_row(
            "SELECT COUNT(*) FROM historical_answer_accounting_events WHERE accepted_answer_id IS NULL",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(revoked, 1);
        // A historical snapshot remains reconstructable after its witness is revoked.
        assert_eq!(
            store.inspect(next.id).unwrap()["risk_admissions"][0]["accounting"]["capacity_exempt_count"],
            24
        );
    }

    #[test]
    fn accepted_linked_requires_direct_same_epoch_dispatched_identifierless_unknown() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.historical_unknown_answer_capacity =
            HistoricalAnswerCapacity::AcceptedLinked;
        config.participation.retry_uncertain_answers = true;
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        let accepted = accepted_linked_answer(&mut store, &config, &original);
        for (change, restore) in [
            (
                "UPDATE operations SET job_id='job' WHERE id=?1",
                "UPDATE operations SET job_id=NULL WHERE id=?1",
            ),
            (
                "UPDATE operations SET txid='tx' WHERE id=?1",
                "UPDATE operations SET txid=NULL WHERE id=?1",
            ),
            (
                "UPDATE operations SET state='queued' WHERE id=?1",
                "UPDATE operations SET state='unknown' WHERE id=?1",
            ),
            (
                "UPDATE operations SET kind='judge' WHERE id=?1",
                "UPDATE operations SET kind='answer' WHERE id=?1",
            ),
            (
                "UPDATE operations SET kind='mine' WHERE id=?1",
                "UPDATE operations SET kind='answer' WHERE id=?1",
            ),
            (
                "UPDATE operations SET request=json_set(request,'$.solver.epoch',8) WHERE id=?1",
                "UPDATE operations SET request=json_set(request,'$.solver.epoch',7) WHERE id=?1",
            ),
            (
                "UPDATE operation_evidence SET dispatch_sequence=NULL WHERE operation_id=?1",
                "UPDATE operation_evidence SET dispatch_sequence=1 WHERE operation_id=?1",
            ),
        ] {
            store.db.execute(change, [original.id]).unwrap();
            let accounting =
                Store::uncertainty_accounting(&store.db, &config, None, None, false).unwrap();
            assert_eq!(
                (accounting.eligible, accounting.exempt, accounting.active()),
                (0, 0, 1),
                "{change}"
            );
            store.db.execute(restore, [original.id]).unwrap();
        }
        for (state, active, eligible) in [
            ("included_pending", 1, 1),
            ("confirmed", 0, 1),
            ("final", 0, 1),
            ("unknown", 2, 0),
            ("queued", 2, 0),
            ("rejected", 1, 0),
        ] {
            store
                .db
                .execute(
                    "UPDATE operations SET state=?1 WHERE id=?2",
                    params![state, accepted.id],
                )
                .unwrap();
            let accounting =
                Store::uncertainty_accounting(&store.db, &config, None, None, false).unwrap();
            assert_eq!(
                (accounting.active(), accounting.eligible),
                (active, eligible),
                "{state}"
            );
        }
        store
            .db
            .execute(
                "UPDATE operations SET state='confirmed',txid=NULL WHERE id=?1",
                [accepted.id],
            )
            .unwrap();
        assert_eq!(
            Store::uncertainty_accounting(&store.db, &config, None, None, false)
                .unwrap()
                .eligible,
            0
        );
        store
            .db
            .execute(
                "UPDATE operations SET txid=?1 WHERE id=?2",
                params!["b".repeat(64), accepted.id],
            )
            .unwrap();
        store
            .db
            .execute(
                "DELETE FROM operation_links WHERE operation_id=?1",
                [accepted.id],
            )
            .unwrap();
        assert_eq!(
            Store::uncertainty_accounting(&store.db, &config, None, None, false)
                .unwrap()
                .eligible,
            0
        );
        // An accepted grandchild does not qualify an ancestor without a direct accepted retry.
        let mut retry = store
            .begin_linked(
                WorkKind::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "retry",
                Some((&original, true)),
            )
            .unwrap();
        config.participation.max_answer_attempts_per_epoch = 4;
        store
            .db
            .execute(
                "UPDATE operations SET state='rejected',txid=NULL WHERE id=?1",
                [accepted.id],
            )
            .unwrap();
        assert!(store.dispatch_intent(&mut retry, &config).unwrap());
        retry.state = "unknown".into();
        store.save(&retry, "dispatch_outcome_unknown").unwrap();
        accepted_linked_answer(&mut store, &config, &retry);
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, None, None, false).unwrap();
        assert_eq!(
            (
                accounting.total,
                accounting.eligible,
                accounting.exempt,
                accounting.active()
            ),
            (2, 1, 1, 1)
        );
        assert_eq!(accounting.historical[0].operation_id, retry.id);
    }

    #[test]
    fn historical_accounting_reads_old_journals_without_migration() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.retry_uncertain_answers = true;
        dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        store.observe(7, false).unwrap();
        store.runtime_state(&config, false).unwrap();
        store
            .db
            .execute_batch(
                "DROP TABLE risk_accounting_snapshots;
             DROP TABLE historical_answer_accounting_events;
             DROP TABLE operation_links; DROP TABLE operation_timing;",
            )
            .unwrap();
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["unresolved_count"], 1);
        assert_eq!(status["participation"]["historical_eligible_count"], 0);
        assert_eq!(status["participation"]["active_unresolved_count"], 1);
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "retry_evidence_unavailable"
        );
        assert_eq!(status["work"]["answer"]["phase"], "unknown");
        assert!(
            !store
                .has_table("historical_answer_accounting_events")
                .unwrap()
        );
    }

    #[test]
    fn pending_routes_bind_only_legacy_defaults_and_survive_restart() {
        for state in ["generating", "prepared", "unknown"] {
            let (_temp, config, mut store) = participation_fixture();
            let op = begin(&mut store, WorkKind::Answer, "7:pending", state);
            let mut changed = config.clone();
            changed.network.api.routes.insert(
                crate::endpoints::Endpoint::Challenge,
                "/new-challenge".into(),
            );
            assert!(
                store
                    .bind_routing(&changed)
                    .unwrap_err()
                    .is::<RoutingProfileError>()
            );
            assert!(store.routing_profile().unwrap().is_none());
            store.bind_routing(&config).unwrap();
            drop(store);
            let mut store = Store::open(&config).unwrap();
            assert!(
                store
                    .bind_routing(&changed)
                    .unwrap_err()
                    .is::<RoutingProfileError>()
            );
            assert_eq!(store.operation(op.id).unwrap().unwrap().state, state);
            assert!(
                !store.routing_status(&changed).unwrap()["matches_config"]
                    .as_bool()
                    .unwrap()
            );
            store.bind_routing(&config).unwrap();
        }
    }

    #[test]
    fn confirmed_receipts_keep_the_original_routing_profile_until_final() {
        let (_temp, config, mut store) = participation_fixture();
        store.bind_routing(&config).unwrap();
        let mut op = begin(&mut store, WorkKind::Answer, "7:included", "confirmed");
        op.txid = Some("a".repeat(64));
        store.save(&op, "receipt_included").unwrap();
        let mut changed = config.clone();
        changed.network.api.routes.insert(
            crate::endpoints::Endpoint::Receipt,
            "/different-receipts/{id}".into(),
        );
        drop(store);
        let mut store = Store::open(&config).unwrap();
        assert!(
            store
                .bind_routing(&changed)
                .unwrap_err()
                .is::<RoutingProfileError>()
        );
        assert_eq!(
            store
                .awaiting_finality(WorkKind::Answer)
                .unwrap()
                .unwrap()
                .id,
            op.id
        );
        op.state = "final".into();
        store.save(&op, "node_reported_final").unwrap();
        store.bind_routing(&changed).unwrap();
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "final");
    }

    #[test]
    fn first_custom_binding_revokes_legacy_grants_and_observations() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.mode = ParticipationMode::Manual;
        config.participation.allow_answer = true;
        store.observe(9, false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let grant = store.authorize(&config, 9, WorkKind::Answer).unwrap();
        config.network.api.routes.insert(
            crate::endpoints::Endpoint::Challenge,
            "/different-challenge".into(),
        );
        store.bind_routing(&config).unwrap();
        assert!(store.control().unwrap().generation > grant["generation"].as_i64().unwrap());
        let observations: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM observation", [], |row| row.get(0))
            .unwrap();
        assert_eq!(observations, 0);
        let identity: Option<bool> = store
            .db
            .query_row(
                "SELECT hosted_identity_verified FROM health_evidence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(identity, None);
        assert_eq!(
            store.status(&config).unwrap()["hosted_identity"],
            json!({"status":"unobserved","observed_at":null,"last_verified_at":null,
                "rejection":null,"legacy_failure":false})
        );
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 8);
        let mut answer = prepared_epoch(&mut store, WorkKind::Answer, 9, "fresh");
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
    }

    #[test]
    fn reusable_model_attempts_hold_routing_until_their_budget_is_exhausted() {
        for initial in ["rejected", "model_unknown"] {
            for convert in [false, true] {
                let (_temp, mut config, mut store) = participation_fixture();
                config.preparation.max_attempts_per_work = 2;
                config.preparation.retry_uncertain = true;
                store.bind_routing(&config).unwrap();
                let op = begin(&mut store, WorkKind::Answer, "7:retry", initial);
                if convert {
                    store.retry_models(&config).unwrap();
                }
                let mut changed = config.clone();
                changed.network.api.routes.insert(
                    crate::endpoints::Endpoint::Challenge,
                    "/different-challenge".into(),
                );
                assert!(
                    store
                        .bind_routing(&changed)
                        .unwrap_err()
                        .is::<RoutingProfileError>()
                );
                // A still-unknown model invocation is never a drained lane.
                if initial == "model_unknown" && !convert {
                    continue;
                }
                changed.preparation.max_attempts_per_work = 1;
                store.bind_routing(&changed).unwrap();
                assert_eq!(
                    store.model_budget_used(WorkKind::Answer, &op.key).unwrap(),
                    1
                );
            }
        }
    }

    #[test]
    fn historical_allowance_preserves_unknowns_and_records_dispatch_witnesses() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.retry_uncertain_answers = true;
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        let accepted = accepted_linked_answer(&mut store, &config, &original);
        store.observe(7, true).unwrap();
        store.runtime_state(&config, false).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["participation"]["uncertainty_blocks"]["answer"],
            false
        );
        config.participation.max_unresolved_operations = 1;
        let mut next = prepared_epoch(&mut store, WorkKind::Answer, 8, "next");
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        config.participation.max_historical_unknown_answers = 1;
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
        next.state = "unknown".into();
        store.save(&next, "dispatch_outcome_unknown").unwrap();
        let risk = store.inspect(next.id).unwrap();
        assert_eq!(
            risk["risk_admissions"][0]["historical_unknown_answers"],
            json!([{"operation_id":original.id,"accepted_answer_id":accepted.id}])
        );
        let blockers: Vec<i64> =
            serde_json::from_str(risk["risk_admissions"][0]["blocker_ids"].as_str().unwrap())
                .unwrap();
        assert_eq!(blockers, vec![original.id]);
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["unresolved_count"], 2);
        assert_eq!(status["participation"]["active_unresolved_count"], 1);
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        let mut third = prepared_epoch(&mut store, WorkKind::Answer, 9, "third");
        assert!(!store.dispatch_intent(&mut third, &config).unwrap());
    }

    #[test]
    fn historical_allowance_never_weakens_policy_floors_or_binding_evidence() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.retry_uncertain_answers = true;
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        let mut accepted = accepted_linked_answer(&mut store, &config, &original);
        config.participation.max_unresolved_operations = 1;
        config.participation.max_historical_unknown_answers = 1;
        let next = prepared_epoch(&mut store, WorkKind::Answer, 8, "next");
        assert!(store.admission_allowed(&config, &next).unwrap());
        for mode in [ParticipationMode::Strict, ParticipationMode::Manual] {
            config.participation.mode = mode;
            assert!(!store.admission_allowed(&config, &next).unwrap());
        }
        config.participation.mode = ParticipationMode::ParticipationFirst;
        config.participation.max_historical_unknown_answers = 0;
        assert!(!store.admission_allowed(&config, &next).unwrap());
        config.participation.max_historical_unknown_answers = 1;
        accepted.state = "rejected".into();
        store.save(&accepted, "receipt_rejected").unwrap();
        assert!(!store.admission_allowed(&config, &next).unwrap());
        accepted.state = "confirmed".into();
        store.save(&accepted, "receipt_included").unwrap();
        let mut bound = store.operation(original.id).unwrap().unwrap();
        bound.job_id = Some("a".repeat(32));
        store.save(&bound, "job_bound").unwrap();
        assert!(!store.admission_allowed(&config, &next).unwrap());
        bound.job_id = None;
        store.save(&bound, "fixture_unbound").unwrap();
        assert!(store.admission_allowed(&config, &next).unwrap());
        store.record_retry_minimum(original.id, 3600).unwrap();
        assert!(!store.admission_allowed(&config, &next).unwrap());
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
    }

    #[test]
    fn answer_reservation_survives_answered_epoch_and_manual_admission() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.max_unresolved_operations = 8;
        config.participation.answer_reserved_slots = 2;
        config.participation.allow_judge = true;
        for epoch in 1..=6 {
            dispatched_unknown(&mut store, &config, WorkKind::Judge, epoch);
        }
        store.observe(40, true).unwrap();
        store.runtime_state(&config, false).unwrap();
        let mut grade = prepared_epoch(&mut store, WorkKind::Judge, 40, "seventh");
        let mut mine = prepared_epoch(&mut store, WorkKind::Mine, 40, "mine");
        assert!(!store.dispatch_intent(&mut grade, &config).unwrap());
        assert!(!store.dispatch_intent(&mut mine, &config).unwrap());
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["judge"]["reason"],
            "answer_capacity_reserved"
        );
        assert_eq!(status["work"]["mine"]["reason"], "answer_capacity_reserved");
        config.participation.mode = ParticipationMode::Manual;
        assert!(store.authorize(&config, 40, WorkKind::Judge).is_err());
        assert!(store.authorize(&config, 40, WorkKind::Mine).is_err());
        store.authorize(&config, 41, WorkKind::Answer).unwrap();
        let first = dispatched_unknown(&mut store, &config, WorkKind::Answer, 41);
        store.authorize(&config, 42, WorkKind::Answer).unwrap();
        let second = dispatched_unknown(&mut store, &config, WorkKind::Answer, 42);
        assert_ne!(first.id, second.id);
        assert!(store.authorize(&config, 43, WorkKind::Answer).is_err());
        let mut third = prepared_epoch(&mut store, WorkKind::Answer, 43, "third");
        assert!(!store.dispatch_intent(&mut third, &config).unwrap());
        assert_eq!(third.state, "prepared");
    }

    #[test]
    fn read_policy_retimes_local_failure_but_preserves_server_and_legacy_minima() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store.read_started(ReadScope::Challenge).unwrap();
        store
            .read_finished(ReadScope::Challenge, Some(503), Some("http_status"))
            .unwrap();
        let old = store
            .fail_read(ReadScope::Challenge, 180, 900, 0, None)
            .unwrap();
        assert_eq!(store.reads().unwrap()[0]["server_not_before"], 0);
        store.defer_until(WorkKind::Answer, old.next_at).unwrap();
        store
            .reschedule_read(ReadScope::Challenge, 1, 2, 0)
            .unwrap();
        assert!(store.read_backoff(ReadScope::Challenge).unwrap().next_at < old.next_at);
        assert_eq!(
            store.next_at(WorkKind::Answer).unwrap(),
            store.read_backoff(ReadScope::Challenge).unwrap().next_at
        );
        let floored = store
            .fail_read(ReadScope::Challenge, 1, 2, 0, Some(90))
            .unwrap();
        store
            .reschedule_read(ReadScope::Challenge, 1, 1, 0)
            .unwrap();
        assert_eq!(
            store.read_backoff(ReadScope::Challenge).unwrap().next_at,
            floored.next_at
        );
        store
            .db
            .execute("DROP TABLE read_observations", [])
            .unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        store
            .reschedule_read(ReadScope::Challenge, 1, 1, 0)
            .unwrap();
        assert_eq!(store.read_backoff(ReadScope::Challenge).unwrap(), floored);
        let diagnostics = store.reads().unwrap();
        assert_eq!(diagnostics[0]["server_not_before"], 0);
        assert_eq!(
            diagnostics[0]["retained_conservative_floor"],
            floored.next_at
        );
        assert_eq!(store.reads().unwrap()[0]["last_failure_at"], Value::Null);
    }

    #[test]
    fn read_diagnostics_distinguish_http_success_from_usable_evidence_and_bound_codes() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store.read_started(ReadScope::Challenge).unwrap();
        assert_eq!(store.reads().unwrap()[0]["state"], "in_flight");
        store
            .read_finished(ReadScope::Challenge, Some(200), Some("invalid_json"))
            .unwrap();
        store
            .fail_read(ReadScope::Challenge, 10, 30, 0, None)
            .unwrap();
        let failed = store.reads().unwrap();
        assert!(failed[0]["last_http_success_at"].is_i64());
        assert!(failed[0]["last_success_at"].is_null());
        assert_eq!(failed[0]["failure_category"], "invalid_json");
        store
            .db
            .execute(
                "UPDATE read_observations SET failure_category='https://private.invalid/secret'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.reads().unwrap()[0]["failure_category"],
            "unusable_response"
        );
        store.reset_read(ReadScope::Challenge).unwrap();
        let recovered = store.reads().unwrap();
        assert!(recovered[0]["last_success_at"].is_i64());
        assert_eq!(
            recovered[0]["last_failure_at"],
            failed[0]["last_failure_at"]
        );
        assert_eq!(recovered[0]["failures"], 0);
    }

    #[test]
    fn participation_admission_is_bounded_durable_and_never_resolves_blockers() {
        let (_temp, mut config, mut store) = participation_fixture();
        let old = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        let mut answer = prepared_epoch(&mut store, WorkKind::Answer, 2, "new");
        config.participation.mode = ParticipationMode::Strict;
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        config.participation.mode = ParticipationMode::ParticipationFirst;
        config.participation.uncertainty_grace_seconds = 300;
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        config.participation.uncertainty_grace_seconds = 0;
        config.participation.max_unresolved_operations = 1;
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        config.participation.max_unresolved_operations = 2;
        config.participation.allow_answer = false;
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        config.participation.allow_answer = true;
        store.runtime_state(&config, true).unwrap();
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        store.runtime_state(&config, false).unwrap();
        assert!(store.dispatch_intent(&mut answer, &config).unwrap());
        answer.state = "queued".into();
        answer.job_id = Some("bound-new-job".into());
        store.save(&answer, "submission_queued").unwrap();
        let inspection = store.inspect(answer.id).unwrap();
        assert_eq!(inspection["risk_admissions"].as_array().unwrap().len(), 1);
        assert_eq!(store.operation(old.id).unwrap().unwrap().state, "unknown");
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        let mut mine = prepared_epoch(&mut store, WorkKind::Mine, 2, "new");
        assert!(!store.dispatch_intent(&mut mine, &config).unwrap());
        config.participation.max_unresolved_operations = 3;
        assert!(store.dispatch_intent(&mut mine, &config).unwrap());
        assert_eq!(store.operation(old.id).unwrap().unwrap().state, "unknown");
        assert_eq!(store.reconciliation_batch().unwrap()[0].id, answer.id);
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["unresolved_count"], 3);
        assert_eq!(status["participation"]["risk_admissions"], 2);
    }

    #[test]
    fn live_dispatch_and_retry_minimum_cannot_be_overridden() {
        let (_temp, mut config, mut store) = participation_fixture();
        let mut old = prepared_epoch(&mut store, WorkKind::Judge, 1, "old");
        assert!(store.dispatch_intent(&mut old, &config).unwrap());
        let mut next = prepared_epoch(&mut store, WorkKind::Answer, 2, "new");
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        old.state = "unknown".into();
        store.save(&old, "dispatch_outcome_unknown").unwrap();
        config.participation.mode = ParticipationMode::Manual;
        store.authorize(&config, 2, WorkKind::Answer).unwrap();
        store.record_retry_minimum(old.id, 600).unwrap();
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT COUNT(*) FROM manual_grants WHERE consumed_by IS NULL",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        config.participation.mode = ParticipationMode::ParticipationFirst;
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
    }

    #[test]
    fn risk_history_rolls_back_with_stale_cas_and_closed_capabilities() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        let mut next = prepared_epoch(&mut store, WorkKind::Answer, 2, "new");
        for mode in [Mode::Off, Mode::ReadOnly] {
            config.capabilities.answer = mode;
            assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        }
        config.capabilities.answer = Mode::Active;
        let mut stale = next.clone();
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
        next.state = "unknown".into();
        store.save(&next, "dispatch_outcome_unknown").unwrap();
        assert!(store.dispatch_intent(&mut stale, &config).is_err());
        assert_eq!(
            store.inspect(next.id).unwrap()["risk_admissions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.operation(next.id).unwrap().unwrap().state, "unknown");
        config.participation.mode = ParticipationMode::Manual;
        config.participation.max_unresolved_operations = 2;
        assert!(store.authorize(&config, 3, WorkKind::Mine).is_err());
        config.participation.max_unresolved_operations = 4;
        config.participation.max_answer_attempts_per_epoch = 1;
        config.participation.retry_uncertain_answers = true;
        assert!(store.authorize(&config, 2, WorkKind::Answer).is_err());
    }

    #[test]
    fn manual_grants_are_one_dispatch_and_generation_and_epoch_scoped() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        config.participation.mode = ParticipationMode::Manual;
        config.participation.uncertainty_grace_seconds = 600;
        let mut next = prepared_epoch(&mut store, WorkKind::Answer, 2, "new");
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        store.authorize(&config, 3, WorkKind::Answer).unwrap();
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        let grant = store.authorize(&config, 2, WorkKind::Answer).unwrap();
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
        next.state = "unknown".into();
        store.save(&next, "dispatch_outcome_unknown").unwrap();
        assert_eq!(
            store.inspect(next.id).unwrap()["risk_admissions"][0]["manual_grant_id"],
            grant["grant_id"]
        );
        let mut another = prepared_epoch(&mut store, WorkKind::Mine, 2, "new");
        assert!(!store.dispatch_intent(&mut another, &config).unwrap());
        store.authorize(&config, 2, WorkKind::Mine).unwrap();
        store.set_paused(true).unwrap();
        assert!(store.authorize(&config, 2, WorkKind::Mine).is_err());
        store.set_paused(false).unwrap();
        assert!(!store.dispatch_intent(&mut another, &config).unwrap());
        another.state = "discarded".into();
        store.save(&another, "unsent_admission_closed").unwrap();
        let mut after_resume = prepared_epoch(&mut store, WorkKind::Mine, 2, "new");
        assert!(!store.dispatch_intent(&mut after_resume, &config).unwrap());
        store.authorize(&config, 2, WorkKind::Mine).unwrap();
        assert!(store.dispatch_intent(&mut after_resume, &config).unwrap());
    }

    fn standalone_refused_answer(store: &mut Store, config: &Config) -> Operation {
        let mut op = dispatched_unknown(store, config, WorkKind::Answer, 7);
        op.state = "retry".into();
        op.next_at = 0;
        store.save(&op, "submission_backoff").unwrap();
        let mut evidence = refusal_evidence(WorkKind::Answer, 429, Some("rate_limited"));
        evidence["reason"] = json!("proven_not_accepted");
        evidence["retry_after_seconds"] = Value::Null;
        store.record_evidence(op.id, &evidence).unwrap();
        op
    }

    #[test]
    fn standalone_refusal_priority_matches_strict_and_manual_risk_policy() {
        for mode in [
            ParticipationMode::Strict,
            ParticipationMode::Manual,
            ParticipationMode::ParticipationFirst,
        ] {
            for other_effect in [false, true] {
                let (_temp, mut config, mut store) = participation_fixture();
                config.participation.retry_uncertain_answers = false;
                config.participation.max_answer_attempts_per_epoch = 1;
                let retry = standalone_refused_answer(&mut store, &config);
                let existing = other_effect
                    .then(|| dispatched_unknown(&mut store, &config, WorkKind::Judge, 7));
                let mut lower = prepared_epoch(&mut store, WorkKind::Judge, 7, "next");
                config.participation.mode = mode;
                store.observe(7, false).unwrap();
                if other_effect && mode == ParticipationMode::Manual {
                    assert!(
                        Store::answer_retry_reservation(&store.db, &config)
                            .unwrap()
                            .is_none()
                    );
                    assert!(!store.admission_allowed(&config, &retry).unwrap());
                    store
                        .db
                        .execute(
                            "INSERT INTO manual_grants(epoch,kind,generation,created_at)
                         VALUES(7,'answer',?1,?2)",
                            params![store.control().unwrap().generation, now()],
                        )
                        .unwrap();
                }
                let reserved = !other_effect || mode != ParticipationMode::Strict;
                assert_eq!(
                    Store::answer_retry_reservation(&store.db, &config)
                        .unwrap()
                        .is_some(),
                    reserved
                );
                if !other_effect {
                    // Ordinary same-operation retry needs neither uncertain
                    // retry opt-in nor a manual risk grant when no effects exist.
                    assert!(store.admission_allowed(&config, &retry).unwrap());
                }
                if let Some(existing) = existing {
                    store.record_retry_minimum(existing.id, 3600).unwrap();
                    config.participation.uncertainty_grace_seconds = 7200;
                    assert_eq!(
                        Store::answer_retry_reservation(&store.db, &config)
                            .unwrap()
                            .is_some(),
                        reserved
                    );
                    assert!(!store.admission_allowed(&config, &retry).unwrap());
                }
                if reserved {
                    assert!(!store.dispatch_intent(&mut lower, &config).unwrap());
                    store.runtime_state(&config, false).unwrap();
                    let status = store.status(&config).unwrap();
                    for kind in ["answer", "judge", "mine"] {
                        let reservation = &status["work"][kind]["admission_reservation"];
                        assert_eq!(reservation["active"], true);
                        assert_eq!(reservation["same_operation"], true);
                        assert_eq!(reservation["basis"], "proven_refusal_retry");
                        assert_eq!(reservation["original_operation_id"], retry.id);
                    }
                    assert!(status["work"]["answer"]["retry"].is_null());
                    if !other_effect {
                        assert_eq!(status["participation"]["unresolved_count"], 0);
                        assert_eq!(
                            status["participation"]["uncertainty_blocks"]["judge"],
                            false
                        );
                        assert_eq!(status["participation"]["uncertainty_blocks"]["mine"], false);
                        assert_eq!(status["admission_blocked"], true);
                    }
                }
                if other_effect {
                    config.participation.allow_answer = false;
                    assert!(
                        Store::answer_retry_reservation(&store.db, &config)
                            .unwrap()
                            .is_none()
                    );
                }
            }
        }
    }

    #[test]
    fn standalone_refusal_reservation_waits_for_own_deadlines_and_releases_invalid_intent() {
        for fence in [
            "local_delay",
            "server_floor",
            "discarded",
            "stale_generation",
            "paused",
            "off",
            "read_only",
            "reload",
            "rollover",
            "answered",
            "payload_missing",
            "unproven",
            "candidate",
            "accepted",
            "other_accepted",
            "other_uncertain",
            "budget",
        ] {
            let (_temp, mut config, mut store) = participation_fixture();
            config.participation.max_answer_attempts_per_epoch = 1;
            let mut retry = standalone_refused_answer(&mut store, &config);
            store.observe(7, false).unwrap();
            assert!(
                Store::answer_retry_reservation(&store.db, &config)
                    .unwrap()
                    .is_some()
            );
            match fence {
                "local_delay" => {
                    retry.next_at = not_before(3600);
                    store.save(&retry, "submission_backoff").unwrap();
                }
                "server_floor" => store.record_retry_minimum(retry.id, 3600).unwrap(),
                "discarded" => {
                    retry.state = "discarded".into();
                    store.save(&retry, "request_no_longer_current").unwrap();
                }
                "stale_generation" => {
                    store.set_paused(true).unwrap();
                    store.set_paused(false).unwrap();
                }
                "paused" => store.set_paused(true).unwrap(),
                "off" => config.capabilities.answer = Mode::Off,
                "read_only" => config.capabilities.answer = Mode::ReadOnly,
                "reload" => store.runtime_state(&config, true).unwrap(),
                "rollover" => store.observe(8, false).unwrap(),
                "answered" => store.observe(7, true).unwrap(),
                "payload_missing" => {
                    store
                        .db
                        .execute("UPDATE operations SET payload=NULL WHERE id=?1", [retry.id])
                        .unwrap();
                }
                "unproven" => {
                    store
                        .record_evidence(
                            retry.id,
                            &refusal_evidence(WorkKind::Answer, 429, Some("rate_limited")),
                        )
                        .unwrap();
                }
                "candidate" => {
                    store
                        .record_candidates(
                            retry.id,
                            &json!({"job_id":"untrusted","transaction_ids":[]}),
                        )
                        .unwrap();
                }
                "accepted" => {
                    store
                        .db
                        .execute(
                            "UPDATE operations SET state='confirmed',txid=?2 WHERE id=?1",
                            params![retry.id, "a".repeat(64)],
                        )
                        .unwrap();
                }
                "other_accepted" | "other_uncertain" | "budget" => {
                    let state = match fence {
                        "other_accepted" => "confirmed",
                        "other_uncertain" => "unknown",
                        _ => "refused",
                    };
                    store.db.execute(
                        "INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at)
                         SELECT kind,work_key,?2,request,generation,revision,created_at,updated_at FROM operations WHERE id=?1",
                        params![retry.id,state],
                    ).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                Store::answer_retry_reservation(&store.db, &config)
                    .unwrap()
                    .is_none(),
                "{fence}"
            );
        }
    }

    #[test]
    fn linked_refusal_same_operation_retry_keeps_priority_without_a_third_attempt_budget() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.allow_judge = true;
        config.participation.retry_uncertain_answers = true;
        config.participation.max_answer_attempts_per_epoch = 2;
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        store.observe(7, false).unwrap();
        let mut retry = store
            .begin_linked(
                WorkKind::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "retry_revision",
                Some((&original, true)),
            )
            .unwrap();
        assert!(store.dispatch_intent(&mut retry, &config).unwrap());
        retry.state = "retry".into();
        retry.next_at = 0;
        store.save(&retry, "submission_backoff").unwrap();
        let mut evidence = refusal_evidence(WorkKind::Answer, 429, Some("rate_limited"));
        evidence["reason"] = json!("proven_not_accepted");
        store.record_evidence(retry.id, &evidence).unwrap();
        let mut lower = prepared_epoch(&mut store, WorkKind::Judge, 7, "next");
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        assert_eq!(
            Store::answer_retry_policy_blocker(&store.db, &config, 7, None).unwrap(),
            Some("answer_attempt_budget_exhausted"),
        );
        assert_eq!(
            Store::answer_retry_reservation(&store.db, &config)
                .unwrap()
                .unwrap()
                .original_operation_id,
            original.id,
        );
        assert!(!store.dispatch_intent(&mut lower, &config).unwrap());
        assert!(store.admission_allowed(&config, &retry).unwrap());
        // The same operation may cross dispatch again; its identity/budget and
        // the unresolved original are preserved rather than minting attempt 3.
        assert!(store.dispatch_intent(&mut retry, &config).unwrap());
        retry.state = "retry".into();
        store.save(&retry, "submission_backoff").unwrap();
        assert_eq!(
            store
                .attempt_count(WorkKind::Answer, &original.key)
                .unwrap(),
            2
        );
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        assert!(!store.dispatch_intent(&mut lower, &config).unwrap());

        config.participation.max_answer_attempts_per_epoch = 1;
        assert!(
            Store::answer_retry_reservation(&store.db, &config)
                .unwrap()
                .is_none()
        );
        assert!(!store.admission_allowed(&config, &retry).unwrap());
        config.participation.max_answer_attempts_per_epoch = 2;
        store.set_paused(true).unwrap();
        store.set_paused(false).unwrap();
        assert!(
            Store::answer_retry_reservation(&store.db, &config)
                .unwrap()
                .is_none()
        );
        assert!(!store.admission_allowed(&config, &retry).unwrap());
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
    }

    #[test]
    fn answer_retry_reservation_drains_existing_grace_without_admitting_new_effects() {
        for queued in [false, true] {
            let (_temp, mut config, mut store) = participation_fixture();
            config.participation.allow_judge = true;
            let mut original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
            if queued {
                original.state = "queued".into();
                original.job_id = Some("private-answer-job".into());
                store.save(&original, "submission_queued").unwrap();
            }
            let mut existing = dispatched_unknown(&mut store, &config, WorkKind::Judge, 7);
            existing.state = "queued".into();
            existing.job_id = Some("private-judge-job".into());
            store.save(&existing, "submission_queued").unwrap();
            let mut lower = prepared_epoch(&mut store, WorkKind::Judge, 7, "next");
            store.observe(7, false).unwrap();
            config.participation.retry_uncertain_answers = true;
            config.participation.uncertainty_grace_seconds = 300;
            config.participation.uncertain_answer_retry_seconds = 600;
            let ready_since = now() - 7200;
            store
                .db
                .execute(
                    "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
                    params![ready_since, original.id],
                )
                .unwrap();
            store.runtime_state(&config, false).unwrap();
            let status = store.status(&config).unwrap();
            assert_eq!(status["work"]["judge"]["reason"], "answer_retry_reserved");
            assert_eq!(
                status["work"]["judge"]["admission_reservation"]["original_operation_id"],
                original.id
            );
            assert_eq!(
                status["work"]["answer"]["retry"]["blocking_operation_id"],
                existing.id
            );
            assert_eq!(
                status["work"]["answer"]["retry"]["reason"],
                "uncertainty_grace"
            );
            assert!(
                status["work"]["answer"]["retry"]["next_at"]
                    .as_i64()
                    .unwrap()
                    > now()
            );
            assert!(!store.dispatch_intent(&mut lower, &config).unwrap());
            assert!(!store.answer_retry_allowed(&config, &original).unwrap());
            assert!(
                store
                    .reconciliation_batch()
                    .unwrap()
                    .iter()
                    .any(|op| op.id == existing.id)
            );
            store.read_started(ReadScope::Challenge).unwrap();
            store
                .read_finished(ReadScope::Challenge, Some(200), None)
                .unwrap();
            store.observe(7, false).unwrap();

            // Move only fixture clocks, never sleep for the production delays.
            store
                .db
                .execute(
                    "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
                    params![ready_since, existing.id],
                )
                .unwrap();
            let floor = now() + 3600;
            store.record_retry_deadline(existing.id, floor).unwrap();
            assert!(!store.answer_retry_allowed(&config, &original).unwrap());
            let status = store.status(&config).unwrap();
            assert_eq!(
                status["work"]["answer"]["retry"]["blocking_operation_id"],
                existing.id
            );
            assert_eq!(status["work"]["answer"]["retry"]["next_at"], floor);
            store
                .db
                .execute("UPDATE operation_timing SET retry_not_before=0", [])
                .unwrap();
            config.participation.max_unresolved_operations = 2;
            assert!(!store.answer_retry_allowed(&config, &original).unwrap());
            config.participation.max_unresolved_operations = 4;
            assert!(store.answer_retry_allowed(&config, &original).unwrap());
            assert!(!store.dispatch_intent(&mut lower, &config).unwrap());
            let accepted = accepted_linked_answer(&mut store, &config, &original);
            assert!(store.dispatch_intent(&mut lower, &config).unwrap());
            assert_eq!(
                store.operation(original.id).unwrap().unwrap().state,
                if queued { "queued" } else { "unknown" }
            );
            assert!(accepted.id > original.id);
            assert!(!status.to_string().contains("private-"));
            assert!(!status.to_string().contains("captured answer"));
        }
    }

    #[test]
    fn answer_retry_reservation_survives_stale_drafts_and_dispatched_rejections() {
        for dispatched in [false, true] {
            let (_temp, mut config, mut store) = participation_fixture();
            config.participation.allow_judge = true;
            config.participation.retry_uncertain_answers = true;
            config.participation.max_answer_attempts_per_epoch = 3;
            let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
            store.observe(7, false).unwrap();
            store.runtime_state(&config, false).unwrap();
            store.read_started(ReadScope::Assignments).unwrap();
            let status = store.status(&config).unwrap();
            assert_eq!(status["work"]["judge"]["phase"], "observing");
            assert_eq!(status["work"]["judge"]["reason"], "read_in_flight");
            assert_eq!(
                status["work"]["judge"]["admission_reservation"]["original_operation_id"],
                original.id
            );

            let mut previous = store
                .begin_linked(
                    WorkKind::Answer,
                    &original.key,
                    ("prepared", &original.request),
                    store.control().unwrap(),
                    "retry_revision",
                    Some((&original, true)),
                )
                .unwrap();
            if dispatched {
                assert!(store.dispatch_intent(&mut previous, &config).unwrap());
                previous.state = "rejected".into();
                store.save(&previous, "submission_rejected").unwrap();
            } else {
                previous.state = "discarded".into();
                store.save(&previous, "request_no_longer_current").unwrap();
            }
            let mut lower = prepared_epoch(&mut store, WorkKind::Judge, 7, "next");
            lower.next_at = now() + 60;
            store.save(&lower, "operation_backoff").unwrap();
            let status = store.status(&config).unwrap();
            assert_eq!(status["work"]["judge"]["reason"], "freshness_in_flight");
            assert_eq!(
                status["work"]["judge"]["admission_reservation"]["original_operation_id"],
                original.id
            );
            lower.next_at = 0;
            store.save(&lower, "operation_ready").unwrap();
            assert!(store.answer_retry_allowed(&config, &original).unwrap());
            assert!(!store.dispatch_intent(&mut lower, &config).unwrap());
            let accepted = accepted_linked_answer(&mut store, &config, &original);
            assert!(accepted.id > previous.id);
            assert!(store.dispatch_intent(&mut lower, &config).unwrap());
            assert_eq!(
                store.operation(original.id).unwrap().unwrap().state,
                "unknown"
            );
        }
    }

    #[test]
    fn answer_retry_reservation_requires_live_authorized_retry_intent() {
        for fence in [
            "disabled",
            "answer_disabled",
            "off",
            "paused",
            "exhausted",
            "answered",
            "accepted",
            "rollover",
            "strict",
            "manual",
            "floor",
            "delay",
            "model_failed",
        ] {
            let (_temp, mut config, mut store) = participation_fixture();
            config.participation.allow_judge = true;
            config.participation.retry_uncertain_answers = true;
            let mut original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
            let lower = prepared_epoch(&mut store, WorkKind::Judge, 7, "next");
            store.observe(7, false).unwrap();
            assert!(
                Store::answer_retry_reservation(&store.db, &config)
                    .unwrap()
                    .is_some()
            );
            assert!(!store.admission_allowed(&config, &lower).unwrap());
            match fence {
                "disabled" => config.participation.retry_uncertain_answers = false,
                "answer_disabled" => config.participation.allow_answer = false,
                "off" => config.capabilities.answer = Mode::Off,
                "paused" => {
                    store.set_paused(true).unwrap();
                }
                "exhausted" => config.participation.max_answer_attempts_per_epoch = 1,
                "answered" => store.observe(7, true).unwrap(),
                "accepted" => {
                    original.state = "included_pending".into();
                    original.txid = Some("b".repeat(64));
                    store.save(&original, "submission_included").unwrap();
                }
                "rollover" => store.observe(8, false).unwrap(),
                "strict" => config.participation.mode = ParticipationMode::Strict,
                "manual" => config.participation.mode = ParticipationMode::Manual,
                "floor" => store
                    .record_retry_deadline(original.id, now() + 3600)
                    .unwrap(),
                "delay" => config.participation.uncertain_answer_retry_seconds = 3600,
                "model_failed" => {
                    let mut failed = store
                        .begin_linked(
                            WorkKind::Answer,
                            "7:changed",
                            ("generating", &original.request),
                            store.control().unwrap(),
                            "test_revision",
                            Some((&original, false)),
                        )
                        .unwrap();
                    failed.state = "model_unknown".into();
                    store.save(&failed, "model_launch_unknown").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                Store::answer_retry_reservation(&store.db, &config)
                    .unwrap()
                    .is_none(),
                "{fence}"
            );
            if !matches!(fence, "paused" | "strict" | "manual" | "floor") {
                assert!(store.admission_allowed(&config, &lower).unwrap(), "{fence}");
            }
            if fence == "manual" {
                store.authorize(&config, 7, WorkKind::Judge).unwrap();
                assert!(store.admission_allowed(&config, &lower).unwrap());
                store.authorize(&config, 7, WorkKind::Answer).unwrap();
                assert!(!store.admission_allowed(&config, &lower).unwrap());
                accepted_linked_answer(&mut store, &config, &original);
                assert!(store.admission_allowed(&config, &lower).unwrap());
            }
        }
    }

    #[test]
    fn uncertain_answer_reuses_payload_with_distinct_bounded_durable_attempts() {
        let (_temp, mut config, mut store) = participation_fixture();
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        config.participation.retry_uncertain_answers = true;
        config.participation.uncertain_answer_retry_seconds = 600;
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        config.participation.uncertain_answer_retry_seconds = 0;
        assert!(store.answer_retry_allowed(&config, &original).unwrap());
        let retry = store
            .begin_linked(
                WorkKind::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "retry_revision",
                Some((&original, true)),
            )
            .unwrap();
        assert_ne!(retry.id, original.id);
        assert_eq!(retry.payload, original.payload);
        assert_eq!(
            store
                .model_budget_used(WorkKind::Answer, &original.key)
                .unwrap(),
            1
        );
        drop(store);
        let mut store = Store::open(&config).unwrap();
        let mut retry = store.operation(retry.id).unwrap().unwrap();
        config.participation.mode = ParticipationMode::Strict;
        assert!(!store.dispatch_intent(&mut retry, &config).unwrap());
        config.participation.mode = ParticipationMode::ParticipationFirst;
        config.participation.retry_uncertain_answers = false;
        assert!(!store.dispatch_intent(&mut retry, &config).unwrap());
        config.participation.retry_uncertain_answers = true;
        assert!(store.dispatch_intent(&mut retry, &config).unwrap());
        retry.state = "unknown".into();
        store.save(&retry, "dispatch_outcome_unknown").unwrap();
        assert!(!store.answer_retry_allowed(&config, &retry).unwrap());
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        let inspection = store.inspect(retry.id).unwrap();
        assert_eq!(inspection["retry_of"], original.id);
        assert_eq!(inspection["payload_reused"], true);
        let mut rotated = store
            .begin_linked(
                WorkKind::Answer,
                "7:rotated",
                ("prepared", &original.request),
                store.control().unwrap(),
                "rotated_revision",
                Some((&retry, false)),
            )
            .unwrap();
        assert!(!store.dispatch_intent(&mut rotated, &config).unwrap());
    }

    #[test]
    fn uncertain_answer_retry_projection_separates_floors_freshness_and_budget() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.retry_uncertain_answers = true;
        config.participation.max_answer_attempts_per_epoch = 2;
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 62);
        store.observe(62, false).unwrap();
        store.runtime_state(&config, false).unwrap();
        let floor = now() + 3600;
        store.record_retry_deadline(original.id, floor).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["phase"], "unknown");
        assert_eq!(
            status["work"]["answer"]["next_action"],
            "authoritative_recovery"
        );
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "retained_retry_minimum"
        );
        assert_eq!(status["work"]["answer"]["retry"]["next_at"], floor);
        assert_eq!(status["work"]["answer"]["retry"]["policy_eligible"], false);
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());

        store
            .db
            .execute(
                "UPDATE operation_timing SET retry_not_before=0 WHERE operation_id=?1",
                [original.id],
            )
            .unwrap();
        let status = store.status(&config).unwrap();
        assert!(store.answer_retry_allowed(&config, &original).unwrap());
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "fresh_evidence_required"
        );
        assert_eq!(status["work"]["answer"]["retry"]["policy_eligible"], true);
        assert_eq!(
            status["work"]["answer"]["retry"]["requires_fresh_eligibility"],
            true
        );
        store
            .fail_read(ReadScope::Challenge, 90, 300, 0, None)
            .unwrap();
        drop(store);
        let readonly = Store::read_only(&config).unwrap().unwrap();
        let status = readonly.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["retry"]["reason"], "read_backoff");
        assert_eq!(
            status["work"]["answer"]["retry"]["next_at"],
            readonly.read_backoff(ReadScope::Challenge).unwrap().next_at
        );
        assert_eq!(
            readonly.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        assert_eq!(
            readonly
                .attempt_count(WorkKind::Answer, &original.key)
                .unwrap(),
            1
        );
        drop(readonly);
        let mut store = Store::open(&config).unwrap();
        store.read_started(ReadScope::Challenge).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "freshness_in_flight"
        );
        assert!(status["work"]["answer"]["retry"]["next_at"].is_null());
        store
            .read_finished(ReadScope::Challenge, Some(200), None)
            .unwrap();
        store.reset_read(ReadScope::Challenge).unwrap();

        store.observe(62, true).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "hosted_answer_observed"
        );
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        store.observe(62, false).unwrap();
        let mut retry = store
            .begin_linked(
                WorkKind::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "retry_revision",
                Some((&original, true)),
            )
            .unwrap();
        // A prepared linked retry must not hide the original's newly retained
        // server floor or replace its identity with the unsent operation.
        store.record_retry_deadline(original.id, floor).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["operation_id"], retry.id);
        assert_eq!(
            status["work"]["answer"]["retry"]["original_operation_id"],
            original.id
        );
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "retained_retry_minimum"
        );
        assert_eq!(status["work"]["answer"]["retry"]["next_at"], floor);
        assert!(!store.dispatch_intent(&mut retry, &config).unwrap());
        store
            .db
            .execute(
                "UPDATE operation_timing SET retry_not_before=0 WHERE operation_id=?1",
                [original.id],
            )
            .unwrap();
        assert!(store.dispatch_intent(&mut retry, &config).unwrap());
        retry.state = "unknown".into();
        store.save(&retry, "dispatch_outcome_unknown").unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "answer_attempt_budget_exhausted"
        );
        assert_eq!(status["work"]["answer"]["retry"]["policy_eligible"], false);
        assert!(!store.answer_retry_allowed(&config, &retry).unwrap());
        store.observe(62, true).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "answer_attempt_budget_exhausted"
        );
        assert_eq!(status["work"]["answer"]["retry"]["policy_eligible"], false);
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        assert!(!status.to_string().contains("captured answer"));
    }

    #[test]
    fn uncertain_answer_retry_projection_uses_effective_policy_and_preserves_fences() {
        let (_temp, mut config, mut store) = participation_fixture();
        let original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 62);
        store.observe(62, false).unwrap();
        for (mode, enabled, capacity, delay, expected) in [
            (ParticipationMode::Strict, true, 8, 0, "strict_uncertainty"),
            (
                ParticipationMode::ParticipationFirst,
                false,
                8,
                0,
                "uncertain_retry_disabled",
            ),
            (
                ParticipationMode::ParticipationFirst,
                true,
                1,
                0,
                "unresolved_capacity",
            ),
            (
                ParticipationMode::ParticipationFirst,
                true,
                8,
                3600,
                "uncertain_answer_retry_delay",
            ),
            (
                ParticipationMode::Manual,
                true,
                8,
                0,
                "manual_authorization_required",
            ),
        ] {
            config.participation.mode = mode;
            config.participation.retry_uncertain_answers = enabled;
            config.participation.max_unresolved_operations = capacity;
            config.participation.uncertain_answer_retry_seconds = delay;
            store.runtime_state(&config, false).unwrap();
            let status = store.status(&Config::default()).unwrap();
            assert_eq!(status["work"]["answer"]["retry"]["reason"], expected);
            assert_eq!(status["work"]["answer"]["retry"]["policy_eligible"], false);
            assert!(!store.answer_retry_allowed(&config, &original).unwrap());
            assert_eq!(
                store.operation(original.id).unwrap().unwrap().state,
                "unknown"
            );
        }
    }

    #[test]
    fn accepted_answer_blocks_every_same_epoch_duplicate_even_prepared_retry() {
        for state in ["included_pending", "confirmed", "final"] {
            let (_temp, mut config, mut store) = participation_fixture();
            config.participation.retry_uncertain_answers = true;
            let mut original = dispatched_unknown(&mut store, &config, WorkKind::Answer, 9);
            let mut retry = store
                .begin_linked(
                    WorkKind::Answer,
                    &original.key,
                    ("prepared", &original.request),
                    store.control().unwrap(),
                    "revision",
                    Some((&original, true)),
                )
                .unwrap();
            original.state = state.into();
            original.txid = Some("a".repeat(64));
            store.save(&original, "receipt_included").unwrap();
            assert!(!store.answer_retry_allowed(&config, &original).unwrap());
            assert!(!store.dispatch_intent(&mut retry, &config).unwrap());
        }
    }

    #[test]
    fn mine_each_epoch_and_safe_same_operation_retry_are_distinct() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.schedule.mine_each_epoch = true;
        let mut mine = dispatched_unknown(&mut store, &config, WorkKind::Mine, 10);
        mine.state = "retry".into();
        store.save(&mine, "submission_backoff").unwrap();
        assert!(store.dispatch_intent(&mut mine, &config).unwrap());
        mine.state = "completed".into();
        store.save(&mine, "mine_completed").unwrap();
        assert!(store.mine_epoch_attempted(10).unwrap());
        let mut duplicate = prepared_epoch(&mut store, WorkKind::Mine, 10, "rotated");
        assert!(!store.dispatch_intent(&mut duplicate, &config).unwrap());
        duplicate.state = "discarded".into();
        store.save(&duplicate, "request_no_longer_current").unwrap();
        let mut next = prepared_epoch(&mut store, WorkKind::Mine, 11, "new");
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
    }

    #[test]
    fn reconciliation_scope_floors_do_not_hide_other_due_scopes() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.max_unresolved_operations = 8;
        let mut jobs = Vec::new();
        for epoch in 1..3 {
            let mut op = dispatched_unknown(&mut store, &config, WorkKind::Mine, epoch);
            op.job_id = Some(format!("blocked-job-{epoch}"));
            op.state = "queued".into();
            store.save(&op, "submission_queued").unwrap();
            jobs.push(op.id);
        }
        let mut receipt = dispatched_unknown(&mut store, &config, WorkKind::Mine, 3);
        receipt.txid = Some("a".repeat(64));
        receipt.state = "included_pending".into();
        store.save(&receipt, "receipt_included").unwrap();
        store.fail_read(ReadScope::Job, 60, 60, 0, None).unwrap();
        let selected = store.reconciliation_batch().unwrap();
        assert_eq!(
            selected.iter().map(|op| op.id).collect::<Vec<_>>(),
            vec![receipt.id]
        );
        store.reset_read(ReadScope::Job).unwrap();
        for id in jobs {
            store.record_retry_minimum(id, 60).unwrap();
        }
        let selected = store.reconciliation_batch().unwrap();
        assert_eq!(
            selected.iter().map(|op| op.id).collect::<Vec<_>>(),
            vec![receipt.id]
        );
    }

    #[test]
    fn pending_work_keeps_later_queue_evidence_in_current_and_legacy_journals() {
        for legacy in [false, true] {
            let (_temp, config, mut store) = participation_fixture();
            let old = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
            let later = begin(&mut store, WorkKind::Mine, "later", "prepared");
            store
                .db
                .execute(
                    "UPDATE operations SET state='queued',created_at=1 WHERE id=?1",
                    [later.id],
                )
                .unwrap();
            if legacy {
                store
                    .db
                    .execute_batch(
                        "UPDATE control SET version=1;
                     DROP TABLE authority; DROP TABLE operation_evidence;
                     DROP TABLE runtime_policy; DROP TABLE operation_timing;",
                    )
                    .unwrap();
            }
            let status = store.status(&config).unwrap();
            assert_eq!(status["pending"]["operation_id"], old.id);
            let work = status["pending_work"]
                .as_array()
                .unwrap()
                .iter()
                .find(|work| work["operation_id"] == later.id)
                .unwrap();
            assert_eq!(work["state"], "queued");
            assert_eq!(work["created_at"], 1);
            assert!(work["http_deadline"].is_null());
        }
    }

    #[test]
    fn legacy_oldest_uncertainty_requires_an_effect() {
        let (_temp, config, mut store) = participation_fixture();
        let op = begin(&mut store, WorkKind::Mine, "legacy", "prepared");
        store
            .db
            .execute_batch(
                "UPDATE control SET version=1;
             DROP TABLE authority; DROP TABLE operation_evidence; DROP TABLE runtime_policy;
             DROP TABLE operation_timing;",
            )
            .unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["pending"]["operation_id"], op.id);
        assert!(status["oldest_unresolved_operation"].is_null());
        assert!(status["oldest_unresolved_since"].is_null());
        store
            .db
            .execute(
                "UPDATE operations SET state='unknown',created_at=100 WHERE id=?1",
                [op.id],
            )
            .unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["oldest_unresolved_operation"], op.id);
        assert_eq!(status["oldest_unresolved_since"], 100);
    }

    #[test]
    fn bounded_reconciliation_rotates_past_identifierless_oldest_across_restart() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.max_unresolved_operations = 8;
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        let mut ids = Vec::new();
        for epoch in 2..6 {
            let mut op = dispatched_unknown(&mut store, &config, WorkKind::Mine, epoch);
            op.job_id = Some(format!("bound-job-{epoch}"));
            op.state = "queued".into();
            store.save(&op, "submission_queued").unwrap();
            ids.push(op.id);
        }
        assert_eq!(
            store
                .reconciliation_batch()
                .unwrap()
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            ids[..2]
        );
        // A failed first request can impose a scope floor that skips the second.
        store.reconciliation_attempted(ids[0]).unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store
                .reconciliation_batch()
                .unwrap()
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            ids[1..3]
        );
        store.reconciliation_attempted(ids[2]).unwrap();
        assert_eq!(
            store
                .reconciliation_batch()
                .unwrap()
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            vec![ids[3], ids[0]]
        );
    }

    #[test]
    fn status_uses_effective_policy_without_mutating_legacy_auxiliary_tables() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        store.observe(2, false).unwrap();
        store.runtime_state(&config, false).unwrap();
        let mut accepted = dispatched_unknown(&mut store, &config, WorkKind::Answer, 2);
        accepted.state = "final".into();
        accepted.txid = Some("a".repeat(64));
        store.save(&accepted, "receipt_final").unwrap();
        config.participation.mode = ParticipationMode::Strict;
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["participation"]["policy"]["mode"],
            "participation_first"
        );
        assert_eq!(
            status["participation"]["uncertainty_blocks"]["answer"],
            false
        );
        assert_eq!(status["participation"]["uncertainty_blocks"]["judge"], true);
        assert_eq!(status["participation"]["uncertainty_blocks"]["mine"], false);
        store.db.execute_batch(
            "DROP TABLE risk_admissions; DROP TABLE operation_links; DROP TABLE operation_timing;
            DROP TABLE manual_grants; DELETE FROM runtime_policy;",
        ).unwrap();
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["policy_source"], "unavailable");
        assert_eq!(status["participation"]["policy"]["mode"], "strict");
        assert_eq!(status["participation"]["unresolved_count"], 1);
        assert!(!store.has_table("risk_admissions").unwrap());
    }

    #[test]
    fn proven_nonacceptance_allows_new_fingerprint_within_distinct_attempt_budget() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.mode = ParticipationMode::Strict;
        let mut old = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        old.state = "retry".into();
        store.save(&old, "submission_backoff").unwrap();
        old.state = "discarded".into();
        store.save(&old, "request_no_longer_current").unwrap();
        assert!(!store.answer_epoch_attempted(7).unwrap());
        let mut current = prepared_epoch(&mut store, WorkKind::Answer, 7, "rotated");
        config.participation.max_answer_attempts_per_epoch = 1;
        assert!(!store.dispatch_intent(&mut current, &config).unwrap());
        config.participation.max_answer_attempts_per_epoch = 2;
        assert!(store.dispatch_intent(&mut current, &config).unwrap());
        assert!(
            store.inspect(current.id).unwrap()["risk_admissions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.operation(old.id).unwrap().unwrap().state, "discarded");
    }

    #[test]
    fn bound_legacy_stale_answer_retains_epoch_dispatch_budget() {
        let (_temp, mut config, mut store) = participation_fixture();
        let mut old = dispatched_unknown(&mut store, &config, WorkKind::Answer, 7);
        old.job_id = Some("legacy-bound-job".into());
        old.state = "stale".into();
        store.save(&old, "processed_submission_rejected").unwrap();
        // Adopted schema-v1 operations have no per-operation dispatch witness.
        store
            .db
            .execute(
                "UPDATE operation_evidence SET dispatch_sequence=NULL WHERE operation_id=?1",
                [old.id],
            )
            .unwrap();
        store.db.execute("DELETE FROM events", []).unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        let mut current = prepared_epoch(&mut store, WorkKind::Answer, 7, "rotated");
        config.participation.max_answer_attempts_per_epoch = 1;
        assert!(!store.dispatch_intent(&mut current, &config).unwrap());
        config.participation.max_answer_attempts_per_epoch = 2;
        assert!(store.dispatch_intent(&mut current, &config).unwrap());
    }

    #[test]
    fn oldest_unresolved_is_not_the_current_grace_blocker() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.allow_judge = true;
        config.participation.allow_mine = true;
        config.participation.max_unresolved_operations = 4;
        let old = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        let old_since = now() - 86400;
        store
            .db
            .execute(
                "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
                params![old_since, old.id],
            )
            .unwrap();
        let recent = dispatched_unknown(&mut store, &config, WorkKind::Mine, 2);
        let prepared = prepared_epoch(&mut store, WorkKind::Answer, 3, "current");
        store.observe(3, false).unwrap();
        config.participation.uncertainty_grace_seconds = 300;
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["oldest_unresolved_operation"], old.id);
        assert_eq!(status["oldest_unresolved_since"], old_since);
        assert_eq!(status["admission_blocked"], true);
        assert_eq!(status["work"]["answer"]["reason"], "uncertainty_grace");
        assert!(status["work"]["answer"]["next_at"].as_i64().unwrap() >= now() + 299);
        assert!(!store.admission_allowed(&config, &prepared).unwrap());
        assert!(status.get("blocking_operation").is_none());
        assert!(status.get("blocked_since").is_none());

        config.participation.uncertainty_grace_seconds = 0;
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["admission_blocked"], false);
        assert_eq!(status["oldest_unresolved_operation"], old.id);
        assert_eq!(
            store.operation(recent.id).unwrap().unwrap().state,
            "unknown"
        );
        assert!(store.admission_allowed(&config, &prepared).unwrap());
    }

    #[test]
    fn inventory_selection_is_durable_bounded_evidence_not_admission_or_global_absence() {
        let (_temp, mut config, store) = participation_fixture();
        store.runtime_state(&config, false).unwrap();
        let revision = config.revision().unwrap();
        let generation = store.control().unwrap().generation;
        store
            .record_assignment_selection(&revision, generation, 2, false, false)
            .unwrap();
        store.defer(WorkKind::Judge, 120).unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        let work = store.status(&config).unwrap()["work"]["judge"].clone();
        assert_eq!(work["reason"], "no_eligible_in_observed_inventory");
        assert_eq!(work["selection"]["observed_count"], 2);
        assert_eq!(work["selection"]["inventory_complete"], false);
        assert_eq!(work["selection"]["evidence"], "observed_inventory_only");
        assert!(work["next_at"].as_i64().unwrap() > now());
        store
            .fail_read(ReadScope::Assignments, 1, 10, 0, Some(600))
            .unwrap();
        let floor = store.read_backoff(ReadScope::Assignments).unwrap().next_at;
        let work = store.status(&config).unwrap()["work"]["judge"].clone();
        assert_eq!(work["reason"], "read_backoff");
        assert!(work["next_at"].as_i64().unwrap() >= floor);
        store.read_started(ReadScope::Assignments).unwrap();
        assert!(store.status(&config).unwrap()["work"]["judge"]["selection"].is_null());
        store.cancel_read(ReadScope::Assignments).unwrap();
        assert_eq!(
            store.read_backoff(ReadScope::Assignments).unwrap().next_at,
            floor
        );
        store
            .record_assignment_selection(&revision, generation, 0, true, false)
            .unwrap();
        config.preparation.max_attempts_per_work += 1;
        store.runtime_state(&config, false).unwrap();
        assert!(store.status(&config).unwrap()["work"]["judge"]["selection"].is_null());
        store.set_paused(true).unwrap();
        store.set_paused(false).unwrap();
        let revision = config.revision().unwrap();
        store
            .record_assignment_selection(
                &revision,
                store.control().unwrap().generation,
                1,
                true,
                true,
            )
            .unwrap();
        store
            .record_assignment_selection(&revision, generation, 0, true, false)
            .unwrap();
        let selection = store.status(&config).unwrap()["work"]["judge"]["selection"].clone();
        assert_eq!(selection["observed_count"], 1);
        assert_eq!(selection["eligible"], true);
    }

    #[test]
    fn restart_restores_captured_legacy_submission_floor_without_renewing_it() {
        for observation in [Some(now() - 60), None] {
            let (_temp, mut config, mut store) = participation_fixture();
            config.participation.uncertainty_grace_seconds = 0;
            let mut op = prepared_epoch(&mut store, WorkKind::Judge, 1, "legacy");
            assert!(store.dispatch_intent(&mut op, &config).unwrap());
            store
                .record_evidence(
                    op.id,
                    &refusal_evidence(WorkKind::Judge, 429, Some("rate_limited")),
                )
                .unwrap();
            store
                .db
                .execute(
                    "UPDATE operation_evidence SET observed_at=?1 WHERE operation_id=?2",
                    params![observation, op.id],
                )
                .unwrap();
            assert_eq!(store.operation_poll_timing(op.id).unwrap().1, 0);
            drop(store);
            let mut store = Store::open(&config).unwrap();
            store.recover().unwrap();
            let expected = observation.map(|at| at + 3601).unwrap_or(i64::MAX);
            assert_eq!(store.operation_poll_timing(op.id).unwrap().1, expected);
            let mut answer = prepared_epoch(&mut store, WorkKind::Answer, 2, "fresh");
            assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
            store.recover().unwrap();
            assert_eq!(store.operation_poll_timing(op.id).unwrap().1, expected);
        }
    }

    #[test]
    fn submission_capture_atomically_retains_floor_across_restart() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.participation.uncertainty_grace_seconds = 0;
        let mut op = prepared_epoch(&mut store, WorkKind::Judge, 1, "limited");
        assert!(store.dispatch_intent(&mut op, &config).unwrap());
        let before: Option<String> = store
            .db
            .query_row(
                "SELECT evidence FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |row| row.get(0),
            )
            .unwrap();
        let evidence = refusal_evidence(WorkKind::Judge, 429, Some("rate_limited"));
        store
            .db
            .execute_batch(
                "CREATE TEMP TRIGGER deny_response_floor BEFORE UPDATE ON operation_timing
             BEGIN SELECT RAISE(ABORT,'synthetic timing failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .record_submission_evidence(op.id, &evidence, &json!({"job_id":"candidate"}))
                .is_err()
        );
        let after: Option<String> = store
            .db
            .query_row(
                "SELECT evidence FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            after, before,
            "diagnostic committed without its server floor"
        );
        store
            .db
            .execute_batch("DROP TRIGGER deny_response_floor")
            .unwrap();
        assert_eq!(
            store
                .db
                .query_row(
                    "SELECT COUNT(*) FROM operation_candidates WHERE operation_id=?1",
                    [op.id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        store
            .record_submission_evidence(op.id, &evidence, &json!({"job_id":"candidate"}))
            .unwrap();
        let floor = store.operation_poll_timing(op.id).unwrap().1;
        assert!(floor >= now() + 3600);
        // Simulate stopping after response capture, before outcome() saves retry.
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
        assert_eq!(store.operation_poll_timing(op.id).unwrap().1, floor);
        let mut answer = prepared_epoch(&mut store, WorkKind::Answer, 2, "fresh");
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        store
            .db
            .execute(
                "UPDATE operation_timing SET retry_not_before=0 WHERE operation_id=?1",
                [op.id],
            )
            .unwrap();
        assert!(store.dispatch_intent(&mut answer, &config).unwrap());
    }

    #[test]
    fn safe_retry_redispatch_restarts_uncertainty_grace_without_resetting_work_age() {
        let (_temp, mut config, mut store) = participation_fixture();
        let mut old = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        old.state = "retry".into();
        store.save(&old, "submission_backoff").unwrap();
        store
            .db
            .execute(
                "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
                params![now() - 3600, old.id],
            )
            .unwrap();
        config.participation.uncertainty_grace_seconds = 300;
        assert!(store.dispatch_intent(&mut old, &config).unwrap());
        old.state = "unknown".into();
        store.save(&old, "dispatch_outcome_unknown").unwrap();
        let mut answer = prepared_epoch(&mut store, WorkKind::Answer, 2, "new");
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        let blocked_since = store.inspect(old.id).unwrap()["details"]["blocked_since"]
            .as_i64()
            .unwrap();
        assert!(blocked_since >= now() - 1);
        drop(store);
        let mut store = Store::open(&config).unwrap();
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
    }

    #[test]
    fn queued_wake_accounts_for_overdue_work_without_bypassing_floors() {
        let (_temp, mut config, mut store) = participation_fixture();
        let mut op = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        op.state = "queued".into();
        op.job_id = Some("bound-job".into());
        op.next_at = now() + 60;
        store.save(&op, "submission_queued").unwrap();
        config.capabilities.answer = Mode::Off;
        config.capabilities.judge = Mode::Off;
        config.capabilities.mine = Mode::Off;
        config.schedule.queued_job_polling = Some(crate::config::QueuedJobPolling {
            initial_seconds: 15,
            max_seconds: 120,
        });
        let future = store.wake_delay(&config, 600).unwrap();
        assert!(future > 1 && future <= 60);
        // A deadline may pass while other work runs after the reconciliation batch.
        op.next_at = 0;
        store.save(&op, "job_pending").unwrap();
        assert_eq!(store.wake_delay(&config, 600).unwrap(), 1);
        store.record_retry_minimum(op.id, 90).unwrap();
        assert!(store.wake_delay(&config, 600).unwrap() >= 60);
        store.fail_read(ReadScope::Job, 180, 900, 0, None).unwrap();
        assert!(store.wake_delay(&config, 600).unwrap() >= 120);
        store.reset_read(ReadScope::Job).unwrap();
        config.schedule.queued_job_polling = None;
        assert_eq!(store.wake_delay(&config, 600).unwrap(), 600);
    }

    #[test]
    fn wait_ages_are_state_scoped_and_reject_future_or_missing_evidence() {
        let evidence = WaitEvidence {
            generating: Some(10),
            captured: Some(30),
            queued: Some(50),
            dispatch: Some(40),
        };
        let generating = evidence.projection("generating", None, 100);
        assert_eq!(generating["generation_age_seconds"], 90);
        assert!(generating["unsent_since_capture_seconds"].is_null());
        let unsent = WaitEvidence {
            captured: Some(30),
            ..WaitEvidence::default()
        };
        for state in ["generated", "prepared"] {
            let wait = unsent.projection(state, None, 100);
            assert_eq!(wait["unsent_since_capture_seconds"], 70);
            assert!(wait["generation_age_seconds"].is_null());
            assert!(wait["effect_age_seconds"].is_null());
        }
        for state in ["generated", "prepared", "retry"] {
            assert!(
                evidence.projection(state, Some(40), 100)["unsent_since_capture_seconds"].is_null()
            );
        }
        assert!(unsent.projection("retry", None, 100)["unsent_since_capture_seconds"].is_null());
        let queued = evidence.projection("queued", Some(45), 100);
        assert_eq!(queued["queued_age_seconds"], 50);
        assert_eq!(queued["effect_age_seconds"], 55);
        assert!(queued["unsent_since_capture_seconds"].is_null());
        for state in ["unknown", "included_pending", "dispatching"] {
            let wait = evidence.projection(state, None, 100);
            assert_eq!(wait["effect_age_seconds"], 60);
            assert!(wait["queued_age_seconds"].is_null());
        }
        for state in [
            "confirmed",
            "final",
            "completed",
            "discarded",
            "model_unknown",
        ] {
            let wait = evidence.projection(state, Some(40), 100);
            for field in [
                "generation_age_seconds",
                "unsent_since_capture_seconds",
                "queued_age_seconds",
                "effect_age_seconds",
            ] {
                assert!(wait[field].is_null(), "{state}: {field}");
            }
        }
        assert_eq!(
            evidence.projection("queued", None, 50)["queued_age_seconds"],
            0
        );
        assert!(evidence.projection("queued", None, 49)["queued_age_seconds"].is_null());
        assert!(WaitEvidence::default().projection("generated", None, 100)
            ["unsent_since_capture_seconds"].is_null());
        assert!(
            WaitEvidence {
                generating: Some(-1),
                ..WaitEvidence::default()
            }
            .projection("generating", None, 100)["generation_age_seconds"]
                .is_null()
        );
        assert_eq!(
            WaitEvidence {
                generating: Some(0),
                ..WaitEvidence::default()
            }
            .projection("generating", None, i64::MAX)["generation_age_seconds"],
            i64::MAX
        );
    }

    #[test]
    fn wait_reporting_reuses_current_effective_cause_without_attributing_elapsed_age() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        let mut answer = begin(&mut store, WorkKind::Answer, "2:wait", "generating");
        let started = now() - 120;
        store
            .db
            .execute(
                "UPDATE events SET at=?1 WHERE operation_id=?2 AND code='generating'",
                params![started, answer.id],
            )
            .unwrap();
        let generating = store.status(&config).unwrap();
        assert_eq!(
            generating["work"]["answer"]["wait"]["generation_started_at"],
            started
        );
        answer.state = "generated".into();
        answer.payload = Some(json!({"answer":"private-wait-canary"}));
        store.save(&answer, "model_result_captured").unwrap();
        let captured = now() - 80;
        store
            .db
            .execute(
                "UPDATE events SET at=?1 WHERE operation_id=?2 AND code='model_result_captured'",
                params![captured, answer.id],
            )
            .unwrap();
        store
            .db
            .execute(
                "UPDATE operations SET updated_at=1 WHERE id=?1",
                [answer.id],
            )
            .unwrap();
        config.participation.mode = ParticipationMode::Strict;
        store.runtime_state(&config, false).unwrap();
        config.participation.mode = ParticipationMode::ParticipationFirst;
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["reason"], "strict_uncertainty");
        assert_eq!(
            status["work"]["answer"]["next_action"],
            "await_reconciliation"
        );
        assert_eq!(
            status["work"]["answer"]["wait"]["model_captured_at"],
            captured
        );
        assert!(
            status["work"]["answer"]["wait"]["unsent_since_capture_seconds"]
                .as_i64()
                .unwrap()
                >= 80
        );
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        let inventory = store
            .operations_list(Some(WorkKind::Answer), None, None, 1)
            .unwrap();
        assert_eq!(
            inventory["operations"][0]["wait"]["model_captured_at"],
            captured
        );
        assert!(inventory["operations"][0]["wait"]["generation_age_seconds"].is_null());
        assert!(!inventory.to_string().contains("private-wait-canary"));
        assert!(
            inventory["operations"][0]["wait"]
                .get("blocked_seconds")
                .is_none()
        );
    }

    #[test]
    fn wait_evidence_is_bounded_and_never_falls_back_to_mutable_timestamps() {
        let (_temp, _config, mut store) = participation_fixture();
        let mut op = begin(&mut store, WorkKind::Answer, "1:wait", "generating");
        op.state = "generated".into();
        store.save(&op, "model_result_captured").unwrap();
        store
            .db
            .execute_batch(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<2000)
             INSERT INTO events(at,code) SELECT 1,'diagnostic' FROM n;",
            )
            .unwrap();
        let inventory = store.operations_list(None, None, None, 1).unwrap();
        assert!(inventory["operations"][0]["wait"]["model_captured_at"].is_null());
        assert!(inventory["operations"][0]["wait"]["unsent_since_capture_seconds"].is_null());
        store.db.execute("DELETE FROM events", []).unwrap();
        store
            .db
            .execute("DROP TABLE operation_evidence", [])
            .unwrap();
        let legacy = store.operations_list(None, None, None, 1).unwrap();
        assert!(legacy["operations"][0]["wait"]["unsent_since_capture_seconds"].is_null());
        assert!(legacy["operations"][0]["wait"]["effect_age_seconds"].is_null());
    }

    #[test]
    fn queued_transition_timing_survives_polling_and_preserves_retry_minima() {
        let (_temp, config, mut store) = participation_fixture();
        let mut op = prepared_epoch(&mut store, WorkKind::Mine, 1, "queued");
        assert!(store.dispatch_intent(&mut op, &config).unwrap());
        op.state = "queued".into();
        op.next_at = now() + 300;
        store.save(&op, "submission_queued").unwrap();
        let queued = now() - 120;
        store
            .db
            .execute(
                "UPDATE events SET at=?1 WHERE operation_id=?2 AND code='submission_queued'",
                params![queued, op.id],
            )
            .unwrap();
        store.save(&op, "job_pending").unwrap();
        assert_eq!(
            store.operation_poll_timing(op.id).unwrap(),
            (Some(queued), 0)
        );
        store
            .db
            .execute("UPDATE operations SET updated_at=1 WHERE id=?1", [op.id])
            .unwrap();
        let inventory = store.operations_list(None, None, None, 1).unwrap();
        assert_eq!(inventory["operations"][0]["wait"]["queued_since"], queued);
        assert!(
            inventory["operations"][0]["wait"]["queued_age_seconds"]
                .as_i64()
                .unwrap()
                >= 120
        );
        op.state = "unknown".into();
        store.save(&op, "dispatch_outcome_unknown").unwrap();
        assert_eq!(store.operation_poll_timing(op.id).unwrap().0, None);
        op.state = "queued".into();
        store.save(&op, "job_pending").unwrap();
        let requeued = store.operation_poll_timing(op.id).unwrap().0.unwrap();
        assert!(requeued > queued);
        store
            .db
            .execute(
                "DELETE FROM operation_timing WHERE operation_id=?1",
                [op.id],
            )
            .unwrap();
        assert_eq!(store.operation_poll_timing(op.id).unwrap().1, op.next_at);
        store
            .db
            .execute("DELETE FROM events WHERE operation_id=?1", [op.id])
            .unwrap();
        assert_eq!(
            store.operation_poll_timing(op.id).unwrap(),
            (None, op.next_at)
        );
        let pruned = store.operations_list(None, None, None, 1).unwrap();
        assert!(pruned["operations"][0]["wait"]["queued_since"].is_null());
        assert!(pruned["operations"][0]["wait"]["effect_since"].is_i64());
    }

    #[test]
    fn operation_inventory_is_sanitized_filtered_and_completely_paginated() {
        let (_temp, config, mut store) = participation_fixture();
        let mut old = dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        old.job_id = Some("private-bearer-job-canary".into());
        old.txid = Some("private-bound-tx-canary".into());
        store.save(&old, "bound_identifiers").unwrap();
        let answer = dispatched_unknown(&mut store, &config, WorkKind::Answer, 2);
        dispatched_unknown(&mut store, &config, WorkKind::Mine, 3);
        let retry = store
            .begin_linked(
                WorkKind::Answer,
                &answer.key,
                ("prepared", &answer.request),
                store.control().unwrap(),
                "revision",
                Some((&answer, true)),
            )
            .unwrap();
        let first = store.operations_list(None, None, None, 2).unwrap();
        assert_eq!(first["operations"].as_array().unwrap().len(), 2);
        assert_eq!(first["operations"][0]["operation_id"], retry.id);
        assert_eq!(first["operations"][0]["retry_of"], answer.id);
        assert_eq!(first["operations"][0]["payload_reused"], true);
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        let second = store
            .operations_list(None, None, first["next_before"].as_i64(), 2)
            .unwrap();
        assert_eq!(second["operations"].as_array().unwrap().len(), 2);
        assert!(second["next_before"].is_null());
        assert_eq!(second["operations"][1]["operation_id"], old.id);
        assert_eq!(second["operations"][1]["has_job_id"], true);
        assert_eq!(second["operations"][1]["has_txid"], true);
        assert_eq!(second["operations"][1]["epoch"], 1);
        let serialized = format!("{first}{second}");
        for secret in [
            "private-bearer-job-canary",
            "private-bound-tx-canary",
            "captured answer",
            "fingerprint",
        ] {
            assert!(!serialized.contains(secret));
        }
        let filtered = store
            .operations_list(Some(WorkKind::Answer), Some("unknown"), None, 100)
            .unwrap();
        assert_eq!(filtered["operations"].as_array().unwrap().len(), 1);
        assert_eq!(filtered["operations"][0]["operation_id"], answer.id);
        assert!(store.operations_list(None, None, None, 1001).is_err());
        assert!(store.operations_list(None, None, Some(0), 1).is_err());
        assert!(
            store
                .operations_list(None, Some("unknown' OR 1"), None, 1)
                .is_err()
        );
    }

    #[test]
    fn grant_inventory_and_revocation_preserve_history_without_authority() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, WorkKind::Judge, 1);
        config.participation.mode = ParticipationMode::Manual;
        config.participation.uncertainty_grace_seconds = 600;
        let older = store.authorize(&config, 2, WorkKind::Answer).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        let revoked = store.authorize(&config, 3, WorkKind::Answer).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        let newest = store.authorize(&config, 4, WorkKind::Mine).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        let first = store.grants(None, 1).unwrap();
        assert_eq!(first["grants"][0]["grant_id"], newest);
        assert_eq!(first["next_before"], newest);
        let second = store.grants(first["next_before"].as_i64(), 1).unwrap();
        assert_eq!(second["grants"][0]["grant_id"], revoked);
        let third = store.grants(second["next_before"].as_i64(), 1).unwrap();
        assert_eq!(third["grants"][0]["grant_id"], older);
        assert!(third["next_before"].is_null());
        let result = store.revoke_grant(revoked).unwrap();
        assert_eq!(store.revoke_grant(revoked).unwrap(), result);
        let mut answer = prepared_epoch(&mut store, WorkKind::Answer, 3, "new");
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        let replacement = store.authorize(&config, 3, WorkKind::Answer).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        assert_ne!(replacement, revoked);
        assert!(store.dispatch_intent(&mut answer, &config).unwrap());
        assert!(store.revoke_grant(replacement).is_err());
        store.set_paused(true).unwrap();
        store.set_paused(false).unwrap();
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        let grants = store.grants(None, 100).unwrap();
        let grants = grants["grants"].as_array().unwrap();
        assert_eq!(
            grants.iter().find(|g| g["grant_id"] == revoked).unwrap()["state"],
            "revoked"
        );
        assert_eq!(
            grants
                .iter()
                .find(|g| g["grant_id"] == replacement)
                .unwrap()["state"],
            "consumed"
        );
        assert_eq!(
            grants.iter().find(|g| g["grant_id"] == older).unwrap()["state"],
            "expired"
        );
        assert!(store.grants(None, 0).is_err());
    }

    #[test]
    fn administration_initialization_probe_never_initializes_state() {
        let (_temp, config) = fixture();
        assert!(!config.state_dir.exists());
        assert!(!admin_identity_initialized(&config).unwrap());
        assert!(!config.state_dir.exists());
        let store = Store::open(&config).unwrap();
        assert!(admin_identity_initialized(&config).unwrap());
        drop(store);
    }

    #[test]
    fn prepared_mining_survives_restart_before_any_followup_save() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let op = begin(&mut store, WorkKind::Mine, "epoch:8", "prepared");
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        let recovered = store.operation(op.id).unwrap().unwrap();
        assert_eq!(recovered.state, "prepared");
        assert_eq!(recovered.payload, Some(json!({})));
        assert!(recovered.job_id.is_none() && recovered.txid.is_none());
    }

    #[test]
    fn read_backoff_is_capped_durable_and_independent_of_work_schedule() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.defer(WorkKind::Answer, 300).unwrap();
        let work_at = store.next_at(WorkKind::Answer).unwrap();
        for (failures, seconds) in [(1, 12), (2, 22), (3, 27), (4, 27)] {
            let before = now();
            let state = store
                .fail_read(ReadScope::Challenge, 10, 25, 2, None)
                .unwrap();
            assert_eq!(state.failures, failures);
            assert!(state.next_at > before + seconds);
            assert!(state.next_at <= now() + seconds + 1);
            assert_eq!(store.next_at(WorkKind::Answer).unwrap(), work_at);
            drop(store);
            store = Store::open(&config).unwrap();
            assert_eq!(store.read_backoff(ReadScope::Challenge).unwrap(), state);
        }
        let before = now();
        let state = store
            .fail_read(ReadScope::Challenge, 10, 25, 2, Some(90))
            .unwrap();
        assert!(state.next_at >= before + 91);
        store
            .fail_read(ReadScope::Identity, 10, 25, 2, None)
            .unwrap();
        store.reset_read(ReadScope::Identity).unwrap();
        assert_eq!(store.read_backoff(ReadScope::Challenge).unwrap(), state);
        store.reset_read(ReadScope::Challenge).unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store.read_backoff(ReadScope::Challenge).unwrap(),
            ReadBackoff::default()
        );
        let restarted = store
            .fail_read(ReadScope::Challenge, 10, 25, 2, Some(1))
            .unwrap();
        assert_eq!(restarted.failures, 1);
        assert!(restarted.next_at >= now() + 12);
    }

    #[test]
    fn read_backoff_migrates_legacy_state_and_saturates_large_delays() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store.db.execute("DROP TABLE read_backoff", []).unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store.read_backoff(ReadScope::Receipt).unwrap(),
            ReadBackoff::default()
        );
        store
            .db
            .execute(
                "INSERT INTO read_backoff VALUES ('receipt',?1,0)",
                [u32::MAX],
            )
            .unwrap();
        let state = store
            .fail_read(ReadScope::Receipt, u64::MAX, 900, u64::MAX, Some(u64::MAX))
            .unwrap();
        assert_eq!(state.failures, u32::MAX);
        assert_eq!(state.next_at, i64::MAX);
    }

    #[test]
    fn read_backoff_cap_never_shortens_configured_base_delay() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        for failures in 1..=3 {
            let before = now();
            let state = store
                .fail_read(ReadScope::Job, 900, 100, 30, Some(1))
                .unwrap();
            assert_eq!(state.failures, failures);
            assert!(state.next_at >= before + 931);
            assert!(state.next_at <= now() + 931);
        }
    }

    #[test]
    fn account_state_binding_survives_writer_shutdown() {
        let (_temp, mut config) = fixture();
        config.network.address = digest(config.state_dir.as_os_str().as_encoded_bytes());
        config.network.credential_file = config.state_dir.with_file_name("key");
        let owner = AccountLock::acquire(&config).unwrap();
        let mut alternate = config.clone();
        alternate.state_dir = config.state_dir.with_file_name("other");
        {
            let _gate = AdmissionGuard::acquire(&config).unwrap();
            AccountLock::control_store(&config).unwrap();
            assert!(AccountLock::control_store(&alternate).is_err());
        }
        drop(owner);
        assert!(AccountLock::acquire(&alternate).is_err());
        let _gate = AdmissionGuard::acquire(&alternate).unwrap();
        assert!(AccountLock::control_store(&alternate).is_err());
        AccountLock::control_store(&config).unwrap();
    }

    #[test]
    fn failed_initial_state_open_does_not_reserve_the_account() {
        let (temp, mut config) = fixture();
        config.network.address = digest(temp.path().as_os_str().as_encoded_bytes());
        config.network.credential_file = temp.path().join("key");
        fs::write(&config.state_dir, "not a directory").unwrap();
        assert!(AccountLock::acquire(&config).is_err());
        config.state_dir = temp.path().join("valid-state");
        let (_owner, store) = AccountLock::acquire(&config).unwrap();
        assert!(store.control().unwrap().paused);
    }

    #[test]
    fn fresh_state_is_paused_and_control_survives_reopen() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        assert_eq!(
            store.control().unwrap(),
            Control {
                paused: true,
                generation: 0
            }
        );
        store.set_paused(false).unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        assert_eq!(
            store.control().unwrap(),
            Control {
                paused: false,
                generation: 1
            }
        );
        store.set_paused(true).unwrap();
        drop(store);
        assert_eq!(
            Store::open(&config).unwrap().control().unwrap(),
            Control {
                paused: true,
                generation: 2
            }
        );
    }

    #[test]
    fn readonly_absent_state_does_not_create_anything() {
        let (_temp, config) = fixture();
        assert!(Store::read_only(&config).unwrap().is_none());
        assert!(!config.state_dir.exists());
    }

    #[test]
    fn identity_completion_rolls_back_read_evidence_and_retry_floor_together() {
        for (fail_at, outcome, http) in [
            (
                "BEFORE INSERT ON hosted_identity_evidence",
                HostedIdentityOutcome::AuthenticationFailed,
                401,
            ),
            (
                "BEFORE INSERT ON read_backoff",
                HostedIdentityOutcome::AuthenticationFailed,
                403,
            ),
            (
                "BEFORE DELETE ON read_backoff",
                HostedIdentityOutcome::Verified,
                200,
            ),
        ] {
            let (_temp, config) = fixture();
            let store = Store::open(&config).unwrap();
            store.read_started(ReadScope::Identity).unwrap();
            let prior = if outcome == HostedIdentityOutcome::Verified {
                HostedIdentityOutcome::AuthenticationFailed
            } else {
                HostedIdentityOutcome::Verified
            };
            store
                .complete_identity_read(
                    Some(if prior == HostedIdentityOutcome::Verified {
                        200
                    } else {
                        401
                    }),
                    None,
                    prior,
                    (10, 60, 0),
                    Some(100),
                )
                .unwrap();
            store.read_started(ReadScope::Identity).unwrap();
            let before = store.status(&config).unwrap()["hosted_identity"].clone();
            let reads = store.reads().unwrap();
            let before_read = reads
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["scope"] == "identity")
                .unwrap()
                .clone();
            store
                .db
                .execute_batch(&format!(
                    "CREATE TRIGGER reject_identity_write {fail_at}
                 BEGIN SELECT RAISE(ABORT,'injected identity write failure'); END;"
                ))
                .unwrap();
            assert!(
                store
                    .complete_identity_read(
                        Some(http),
                        Some("http_status"),
                        outcome,
                        (10, 60, 0),
                        Some(300),
                    )
                    .is_err()
            );
            drop(store);
            let reader = Store::read_only(&config).unwrap().unwrap();
            assert_eq!(reader.status(&config).unwrap()["hosted_identity"], before);
            let reads = reader.reads().unwrap();
            let after_read = reads
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["scope"] == "identity")
                .unwrap();
            for field in [
                "state",
                "status",
                "failure_category",
                "failures",
                "next_at",
                "last_failure_at",
                "last_success_at",
                "server_not_before",
            ] {
                assert_eq!(after_read[field], before_read[field], "{fail_at}: {field}");
            }
            drop(reader);
            let store = Store::open(&config).unwrap();
            store
                .db
                .execute_batch("DROP TRIGGER reject_identity_write;")
                .unwrap();
            let started = now();
            store
                .complete_identity_read(
                    Some(http),
                    Some("http_status"),
                    outcome,
                    (10, 60, 0),
                    Some(300),
                )
                .unwrap();
            drop(store);
            let reader = Store::read_only(&config).unwrap().unwrap();
            let status = reader.status(&config).unwrap();
            assert_eq!(status["hosted_identity"]["status"], outcome.as_str());
            assert_eq!(
                status["hosted_identity_verified"],
                outcome == HostedIdentityOutcome::Verified
            );
            let backoff = reader.read_backoff(ReadScope::Identity).unwrap();
            if outcome == HostedIdentityOutcome::Verified {
                assert_eq!(backoff.failures, 0);
            } else {
                assert!(backoff.next_at >= started + 300);
                assert_eq!(
                    status["hosted_identity"]["rejection"],
                    "authentication_failed"
                );
            }
        }
    }

    #[test]
    fn identity_rejection_and_last_verification_survive_transient_outcomes_and_reopen() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let verified = store.status(&config).unwrap()["hosted_identity"].clone();
        for rejection in [
            HostedIdentityOutcome::AuthenticationFailed,
            HostedIdentityOutcome::IdentityMismatch,
        ] {
            store.record_identity_outcome(rejection).unwrap();
            for outcome in [
                HostedIdentityOutcome::Unavailable,
                HostedIdentityOutcome::InvalidResponse,
            ] {
                store.record_identity_outcome(outcome).unwrap();
                let reader = Store::read_only(&config).unwrap().unwrap();
                let status = reader.status(&config).unwrap();
                assert_eq!(status["hosted_identity"]["status"], outcome.as_str());
                assert_eq!(status["hosted_identity"]["rejection"], rejection.as_str());
                assert_eq!(
                    status["hosted_identity"]["last_verified_at"],
                    verified["last_verified_at"]
                );
                assert_eq!(status["hosted_identity_verified"], false);
            }
        }
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["hosted_identity"]["rejection"],
            "identity_mismatch"
        );
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["hosted_identity_verified"], true);
        assert!(status["hosted_identity"]["rejection"].is_null());
        assert_eq!(status["hosted_identity"]["legacy_failure"], false);
    }

    #[test]
    fn readonly_legacy_identity_flags_remain_uncertain_without_schema_migration() {
        for legacy in [false, true] {
            let (_temp, config) = fixture();
            let store = Store::open(&config).unwrap();
            store
                .db
                .execute("DROP TABLE hosted_identity_evidence", [])
                .unwrap();
            store
                .db
                .execute(
                    "INSERT INTO health_evidence(singleton,hosted_identity_verified) VALUES(1,?1)",
                    [legacy],
                )
                .unwrap();
            store.db.execute(
                "INSERT INTO read_observations(scope,last_success_at,last_failure_at,failure_category)
                 VALUES('identity',123,456,'timeout')", [],
            ).unwrap();
            let before = store.db.total_changes();
            let reader = Store::read_only(&config).unwrap().unwrap();
            let status = reader.status(&config).unwrap();
            assert_eq!(
                status["hosted_identity"],
                json!({"status":"legacy_unknown","observed_at":null,
                    "last_verified_at":if legacy {Some(123)} else {None},
                    "rejection":null,"legacy_failure":!legacy})
            );
            assert!(status["hosted_identity_verified"].is_null());
            assert_eq!(reader.db.total_changes(), 0);
            assert!(!reader.has_table("hosted_identity_evidence").unwrap());
            assert_eq!(store.db.total_changes(), before);
        }
    }

    #[test]
    fn legacy_identity_normalization_is_audited_idempotent_and_preserves_other_evidence() {
        let (_temp, config, mut store) = participation_fixture();
        store.observe(42, false).unwrap();
        store
            .db
            .execute("UPDATE health_evidence SET hosted_identity_verified=0", [])
            .unwrap();
        store.read_started(ReadScope::Identity).unwrap();
        store
            .read_finished(ReadScope::Identity, None, Some("timeout"))
            .unwrap();
        store
            .fail_read(ReadScope::Identity, 30, 120, 0, Some(900))
            .unwrap();
        let op = prepared_epoch(&mut store, WorkKind::Judge, 42, "captured");
        let control = store.control().unwrap();
        let operation = store.inspect(op.id).unwrap();
        let reads = store.reads().unwrap();
        let before = store.status(&config).unwrap();
        let (preview, captured) =
            Store::identity_normalization_preview(&store.db, "config").unwrap();
        assert!(preview.get("operation_id").is_none());
        assert_eq!(preview["kind"], "identity");
        assert_eq!(preview["eligible"], true);
        let token = preview["preview_token"].as_str().unwrap();
        let applied = store.normalize_legacy_identity("config", token).unwrap();
        assert_eq!(applied["applied"], true);
        assert_eq!(store.control().unwrap(), control);
        assert_eq!(store.inspect(op.id).unwrap(), operation);
        assert_eq!(store.reads().unwrap(), reads);
        let after = store.status(&config).unwrap();
        assert_eq!(before["hosted_identity"], after["hosted_identity"]);
        assert_eq!(before["epoch_evidence"], after["epoch_evidence"]);
        assert!(after["hosted_identity_verified"].is_null());
        let audit: String = store
            .db
            .query_row("SELECT audit FROM identity_normalizations", [], |row| {
                row.get(0)
            })
            .unwrap();
        let audit: Value = serde_json::from_str(&audit).unwrap();
        assert_eq!(audit["previous_evidence"], captured);
        assert_eq!(audit["normalized_evidence"], after["hosted_identity"]);
        let changes = store.db.total_changes();
        assert_eq!(
            store.normalize_legacy_identity("config", token).unwrap()["already_resolved"],
            true
        );
        assert_eq!(store.db.total_changes(), changes);
        assert_eq!(
            Store::identity_normalization_preview(&store.db, "config")
                .unwrap()
                .0["eligible"],
            false
        );
        store
            .record_identity_outcome(HostedIdentityOutcome::Unavailable)
            .unwrap();
        assert_eq!(
            store.status(&config).unwrap()["hosted_identity"]["legacy_failure"],
            true
        );
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        assert_eq!(
            store.status(&config).unwrap()["hosted_identity"]["legacy_failure"],
            false
        );
        assert!(store.normalize_legacy_identity("config", token).is_err());
        drop(store);
        let reader = Store::read_only(&config).unwrap().unwrap();
        assert_eq!(
            reader
                .db
                .query_row("SELECT COUNT(*) FROM identity_normalizations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }

    #[test]
    fn legacy_identity_normalization_refuses_changed_evidence_and_rolls_back_failed_audit() {
        for outcome in [
            None,
            Some(HostedIdentityOutcome::AuthenticationFailed),
            Some(HostedIdentityOutcome::Verified),
        ] {
            let (_temp, config) = fixture();
            let mut store = Store::open(&config).unwrap();
            store
                .db
                .execute(
                    "INSERT INTO health_evidence(singleton,hosted_identity_verified) VALUES(1,0)",
                    [],
                )
                .unwrap();
            let (preview, _) = Store::identity_normalization_preview(&store.db, "config").unwrap();
            if let Some(outcome) = outcome {
                store.record_identity_outcome(outcome).unwrap();
            } else {
                store.read_started(ReadScope::Identity).unwrap();
            }
            let before = store.status(&config).unwrap()["hosted_identity"].clone();
            let error = store
                .normalize_legacy_identity("config", preview["preview_token"].as_str().unwrap())
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<RefusalRecoveryError>().unwrap().0,
                "identity_evidence_changed"
            );
            assert_eq!(store.status(&config).unwrap()["hosted_identity"], before);
            assert_eq!(
                store
                    .db
                    .query_row("SELECT COUNT(*) FROM identity_normalizations", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0
            );
        }
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store
            .db
            .execute(
                "INSERT INTO health_evidence(singleton,hosted_identity_verified) VALUES(1,0)",
                [],
            )
            .unwrap();
        let (preview, _) = Store::identity_normalization_preview(&store.db, "config").unwrap();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER reject_identity_audit BEFORE INSERT ON events
            WHEN NEW.code='legacy_identity_evidence_normalized'
            BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .normalize_legacy_identity("config", preview["preview_token"].as_str().unwrap())
                .is_err()
        );
        assert_eq!(
            Store::identity_normalization_preview(&store.db, "config")
                .unwrap()
                .0,
            preview
        );
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM identity_normalizations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn hosted_identity_failure_survives_event_pruning_and_reopen_until_verified() {
        use crate::health::{self, Options};
        let (_temp, mut config) = fixture();
        config.capabilities.answer = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        assert!(store.status(&config).unwrap()["hosted_identity_verified"].is_null());
        store.set_paused(false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::IdentityMismatch)
            .unwrap();
        store.event("identity_mismatch", None).unwrap();
        store
            .db
            .execute(
                "WITH RECURSIVE sequence(n) AS (
                 SELECT 1 UNION ALL SELECT n+1 FROM sequence WHERE n<2000)
                 INSERT INTO events(at,code) SELECT ?1,'poll_completed' FROM sequence",
                [now()],
            )
            .unwrap();
        store.event("poll_completed", None).unwrap();
        let mismatch_event: bool = store
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE code='identity_mismatch')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!mismatch_event);
        drop(store);
        let reader = Store::read_only(&config).unwrap().unwrap();
        assert_eq!(
            reader.status(&config).unwrap()["hosted_identity_verified"],
            false
        );
        drop(reader);
        let store = Store::open(&config).unwrap();
        store.runtime_state(&config, false).unwrap();
        store.observe(54, true).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["identity_matches_config"],
            true
        );
        let options = Options {
            min_free_mib: 0,
            ..Options::default()
        };
        let health = health::check(&config, options).unwrap();
        assert_eq!(health["healthy"], false);
        assert_eq!(health["hosted_identity"]["rejection"], "identity_mismatch");
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        assert_eq!(health::check(&config, options).unwrap()["healthy"], true);
        drop(store);
        let reader = Store::read_only(&config).unwrap().unwrap();
        assert_eq!(
            reader.status(&config).unwrap()["hosted_identity_verified"],
            true
        );
    }

    #[test]
    fn readonly_legacy_state_reports_unknown_hosted_identity_without_writes() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store.observe(54, true).unwrap();
        store.db.execute("DROP TABLE health_evidence", []).unwrap();
        let schema_version: i64 = store
            .db
            .query_row("PRAGMA schema_version", [], |r| r.get(0))
            .unwrap();
        let data_version: i64 = store
            .db
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();
        let events = store.events(1000).unwrap();
        let reader = Store::read_only(&config).unwrap().unwrap();
        let status = reader.status(&config).unwrap();
        assert!(status["hosted_identity_verified"].is_null());
        assert_eq!(
            status["epoch_evidence"],
            json!({"first_observed_at":null,"answered":null})
        );
        assert_eq!(status["observation"]["epoch"], 54);
        assert_eq!(status["identity_matches_config"], true);
        assert_eq!(reader.db.total_changes(), 0);
        assert!(
            reader
                .record_identity_outcome(HostedIdentityOutcome::Unavailable)
                .is_err()
        );
        drop(reader);
        assert_eq!(
            store
                .db
                .query_row("PRAGMA schema_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            schema_version
        );
        assert_eq!(
            store
                .db
                .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            data_version
        );
        assert_eq!(store.events(1000).unwrap(), events);
        let has_table: bool = store
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                 WHERE type='table' AND name='health_evidence')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!has_table);
        drop(store);
        let store = Store::open(&config).unwrap();
        assert!(store.status(&config).unwrap()["hosted_identity_verified"].is_null());
        assert!(store.status(&config).unwrap()["epoch_evidence"]["answered"].is_null());
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        assert_eq!(
            store.status(&config).unwrap()["hosted_identity_verified"],
            true
        );
    }

    #[test]
    fn pause_generation_closes_admission_even_after_resume() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        assert!(
            store
                .begin(
                    WorkKind::Answer,
                    "1:word",
                    "generating",
                    &json!({}),
                    store.control().unwrap(),
                    "rev"
                )
                .is_err()
        );
        store.set_paused(false).unwrap();
        let stale = store.control().unwrap();
        store.set_paused(true).unwrap();
        store.set_paused(false).unwrap();
        assert!(
            store
                .begin(
                    WorkKind::Answer,
                    "1:word",
                    "generating",
                    &json!({}),
                    stale,
                    "rev"
                )
                .is_err()
        );
    }

    #[test]
    fn crash_after_model_intent_never_automatically_relaunches() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        begin(&mut store, WorkKind::Answer, "1:word", "generating");
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        assert!(store.pending().unwrap().is_none());
        assert!(store.answer_epoch_attempted(1).unwrap());
        assert!(store.attempted(WorkKind::Answer, "1:word").unwrap());
        // A model cannot submit on its own; unrelated protocol work remains live.
        let op = begin(&mut store, WorkKind::Mine, "2:word", "dispatching");
        store.recover().unwrap();
        assert_eq!(store.abandon_models().unwrap(), 1);
        assert!(!store.answer_epoch_attempted(1).unwrap());
        let pending = store.pending().unwrap().unwrap();
        assert_eq!(pending.id, op.id);
        assert_eq!(pending.state, "unknown");
        assert_eq!(store.abandon_models().unwrap(), 0);
    }

    #[test]
    fn crash_after_http_intent_retains_unknown_payload_and_boundary() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Answer, "1:word", "prepared");
        op.payload = Some(json!({"answer":"answer-canary"}));
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        let pending = store.pending().unwrap().unwrap();
        assert_eq!(pending.state, "unknown");
        assert_eq!(pending.payload.unwrap()["answer"], "answer-canary");
        assert!(store.answer_epoch_attempted(1).unwrap());
    }

    #[test]
    fn queue_receipt_and_captured_output_survive_restart_privately() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Answer, "2:word", "generated");
        op.result = Some(json!({"answer":"result-canary"}));
        op.payload = Some(json!({"answer":"payload-canary"}));
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        op.job_id = Some("job-bearer-canary".into());
        op.state = "queued".into();
        op.next_at = now() + 100;
        store.save(&op, "submission_queued").unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        let recovered = store.pending().unwrap().unwrap();
        assert_eq!(recovered.job_id, op.job_id);
        assert_eq!(recovered.next_at, op.next_at);
        assert_eq!(recovered.result, op.result);
        let public = format!(
            "{}{}",
            store.status(&config).unwrap(),
            store.events(100).unwrap()
        );
        for private in [
            "request-canary",
            "result-canary",
            "payload-canary",
            "job-bearer-canary",
        ] {
            assert!(!public.contains(private));
        }
    }

    #[test]
    fn included_receipt_releases_lane_before_finality() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Answer, "3:word", "prepared");
        op.payload = Some(json!({"answer":"verified-history"}));
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        op.state = "included_pending".into();
        store.save(&op, "transaction_included_unconfirmed").unwrap();
        assert_eq!(store.history().unwrap(), vec!["verified-history"]);
        assert!(store.effect().unwrap().is_some());
        op.state = "confirmed".into();
        store.save(&op, "receipt_included").unwrap();
        assert!(store.pending().unwrap().is_none());
        assert_eq!(store.history().unwrap(), vec!["verified-history"]);
        assert!(store.awaiting_finality(WorkKind::Answer).unwrap().is_some());
        begin(&mut store, WorkKind::Judge, "assignment", "generating");
        assert!(store.answer_epoch_attempted(3).unwrap());
    }

    #[test]
    fn proven_prelaunch_failure_is_retryable_but_unknown_is_not() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Answer, "4:word", "generating");
        op.state = "prelaunch_failed".into();
        store.save(&op, "executable_unavailable").unwrap();
        assert!(!store.answer_epoch_attempted(4).unwrap());
        let mut next = begin(&mut store, WorkKind::Answer, "4:word", "generating");
        next.state = "model_unknown".into();
        store.save(&next, "model_launch_unknown").unwrap();
        assert!(store.answer_epoch_attempted(4).unwrap());
    }

    #[test]
    fn normalized_assignment_attempt_survives_restart() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Judge, &"A".repeat(64), "prepared");
        op.state = "abstained".into();
        store.save(&op, "assignment_evidence_insufficient").unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        assert!(store.attempted(WorkKind::Judge, &"a".repeat(64)).unwrap());
        assert!(!store.attempted(WorkKind::Judge, &"b".repeat(64)).unwrap());
    }

    #[test]
    fn identity_is_case_sensitive_and_existing_state_cannot_be_rebound() {
        let (_temp, mut config) = fixture();
        config.network.address = "CaseSensitiveAccount".into();
        drop(Store::open(&config).unwrap());
        config.network.address = "casesensitiveaccount".into();
        assert!(Store::open(&config).is_err());
        let status = Store::read_only(&config)
            .unwrap()
            .unwrap()
            .status(&config)
            .unwrap();
        assert_eq!(status["identity_matches_config"], false);
    }

    #[test]
    fn account_lock_is_independent_of_database_and_endpoint() {
        let (temp, mut config) = fixture();
        config.network.address = digest(temp.path().to_string_lossy().as_bytes());
        config.network.credential_file = temp.path().join("key");
        let path = lock_path(&config, "writer").unwrap();
        let first = AccountLock::acquire(&config).unwrap();
        let mut other = config.clone();
        other.state_dir = temp.path().join("different");
        other.network.base_url = "https://different.invalid".into();
        assert_eq!(path, lock_path(&other, "writer").unwrap());
        assert!(AccountLock::acquire(&other).is_err());
        drop(first);
        assert!(AccountLock::acquire(&other).is_err());
        drop(AccountLock::acquire(&config).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn epoch_evidence_survives_polls_and_resets_only_on_transition() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store.observe(54, false).unwrap();
        store
            .db
            .execute("UPDATE health_evidence SET first_observed_at=1", [])
            .unwrap();
        store.observe(54, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["epoch_evidence"]["first_observed_at"], 1);
        assert_eq!(status["epoch_evidence"]["answered"], false);
        store.observe(54, true).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["epoch_evidence"]["answered"],
            true
        );
        store.observe(55, false).unwrap();
        let status = store.status(&config).unwrap();
        assert!(
            status["epoch_evidence"]["first_observed_at"]
                .as_i64()
                .unwrap()
                > 1
        );
        assert_eq!(status["epoch_evidence"]["answered"], false);
        assert_eq!(status["observation"]["epoch"], 55);
    }

    #[test]
    fn epoch_grace_and_answer_state_survive_log_rotation_and_reopen() {
        use crate::health::{self, Options};
        let (_temp, mut config) = fixture();
        config.capabilities.answer = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Unavailable)
            .unwrap();
        store.observe(54, false).unwrap();
        store
            .db
            .execute("UPDATE health_evidence SET first_observed_at=1", [])
            .unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let options = Options {
            min_free_mib: 0,
            ..Options::default()
        };
        for answered in [false, true] {
            store.observe(54, answered).unwrap();
            store
                .db
                .execute(
                    "WITH RECURSIVE sequence(n) AS (
                     SELECT 1 UNION ALL SELECT n+1 FROM sequence WHERE n<2001)
                     INSERT INTO events(at,code) SELECT ?1,'poll_completed' FROM sequence",
                    [now()],
                )
                .unwrap();
            store.event("poll_completed", None).unwrap();
            let epoch_events: i64 = store
                .db
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE code IN
                     ('epoch_observed','challenge_answered','challenge_unanswered')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(epoch_events, 0);
            drop(store);
            let reader = Store::read_only(&config).unwrap().unwrap();
            assert_eq!(
                reader.status(&config).unwrap()["epoch_evidence"],
                json!({"first_observed_at":1,"answered":answered})
            );
            drop(reader);
            store = Store::open(&config).unwrap();
            store.runtime_state(&config, false).unwrap();
            store.observe(54, answered).unwrap();
            let status = store.status(&config).unwrap();
            assert_eq!(
                status["epoch_evidence"],
                json!({"first_observed_at":1,"answered":answered})
            );
            assert_eq!(status["hosted_identity_verified"], true);
            let health = health::check(&config, options).unwrap();
            assert_eq!(health["healthy"], answered);
            assert_eq!(
                health["issues"],
                if answered {
                    json!([])
                } else {
                    json!(["current_epoch_unanswered"])
                }
            );
        }
        store.observe(55, false).unwrap();
        let status = store.status(&config).unwrap();
        assert!(
            status["epoch_evidence"]["first_observed_at"]
                .as_i64()
                .unwrap()
                > 1
        );
        assert_eq!(status["epoch_evidence"]["answered"], false);
        assert_eq!(status["observation"]["epoch"], 55);
        assert_eq!(status["hosted_identity_verified"], true);
        assert_eq!(health::check(&config, options).unwrap()["healthy"], true);
    }

    #[test]
    fn health_is_read_only_and_current_lifecycle_overrides_old_stop() {
        use crate::health::{self, Options};
        let (_temp, mut config) = fixture();
        config.capabilities.answer = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        store.runtime_state(&config, false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        store.observe(54, true).unwrap();
        store.event("runtime_stopped", None).unwrap();
        assert_eq!(store.status(&config).unwrap()["controller_stopped"], true);
        store.runtime_state(&config, false).unwrap();
        assert_eq!(store.status(&config).unwrap()["controller_stopped"], false);
        let before = store.events(1000).unwrap();
        let changes = store.db.total_changes();
        let options = Options {
            min_free_mib: 0,
            ..Options::default()
        };
        assert_eq!(health::check(&config, options).unwrap()["healthy"], true);
        assert_eq!(store.events(1000).unwrap(), before);
        assert_eq!(store.db.total_changes(), changes);
        let read_only = Store::read_only(&config).unwrap().unwrap();
        assert!(read_only.db.execute("DELETE FROM events", []).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_state_permissions_are_rejected_without_repair() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, config) = fixture();
        fs::create_dir(&config.state_dir).unwrap();
        fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open(&config).is_err());
        assert_eq!(
            fs::metadata(&config.state_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    fn bound_fixture() -> (tempfile::TempDir, Config) {
        let (dir, mut config) = fixture();
        config.network.address = digest(dir.path().as_os_str().as_encoded_bytes());
        config.network.credential_file = dir.path().join("key");
        (dir, config)
    }

    fn remove_anchors(config: &Config) {
        for suffix in ["writer", "admission", "binding", "binding-next"] {
            let _ = fs::remove_file(lock_path(config, suffix).unwrap());
        }
    }

    #[test]
    fn preparation_is_not_an_effect_and_stale_transitions_cannot_win() {
        let (_dir, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut answer = begin(&mut store, WorkKind::Answer, "1:words", "prepared");
        let mut judge = begin(&mut store, WorkKind::Judge, &"a".repeat(64), "prepared");
        assert!(store.effect().unwrap().is_none());
        let stale = answer.clone();
        answer.state = "dispatching".into();
        store.save(&answer, "dispatch_intent").unwrap();
        judge.state = "dispatching".into();
        assert!(store.save(&judge, "dispatch_intent").is_err());
        assert!(store.save(&stale, "stale_transition").is_err());
        assert_eq!(store.effect().unwrap().unwrap().id, answer.id);
    }

    #[test]
    fn bound_missing_and_replaced_journals_fail_closed_everywhere() {
        let (_dir, config) = bound_fixture();
        let (lock, store) = AccountLock::acquire(&config).unwrap();
        store
            .db
            .execute("UPDATE authority SET database_id='replacement'", [])
            .unwrap();
        drop(store);
        drop(lock);
        assert!(AccountLock::acquire(&config).is_err());
        assert!(Store::read_only(&config).is_err());
        fs::remove_file(config.state_dir.join("state.sqlite3")).unwrap();
        assert!(crate::runtime::pause(&config).is_err());
        assert!(AccountLock::control_store(&config).is_err());
        assert!(Store::open(&config).is_err());
        assert!(Store::read_only(&config).is_err());
        assert!(!config.state_dir.join("state.sqlite3").exists());
        remove_anchors(&config);
    }

    #[test]
    fn independent_dispatch_witness_detects_database_only_rollback() {
        let (dir, config) = bound_fixture();
        let (lock, mut store) = AccountLock::acquire(&config).unwrap();
        store.set_paused(false).unwrap();
        let backup = fs::canonicalize(dir.path()).unwrap().join("before.sqlite3");
        store
            .db
            .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
            .unwrap();
        let mut op = begin(&mut store, WorkKind::Mine, "1", "prepared");
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        let binding = read_binding(&config).unwrap().unwrap();
        assert_eq!(binding.dispatch_sequence, 1);
        drop(store);
        drop(lock);
        fs::copy(backup, config.state_dir.join("state.sqlite3")).unwrap();
        assert!(AccountLock::acquire(&config).is_err());
        assert!(AccountLock::control_store(&config).is_err());
        remove_anchors(&config);
    }

    #[test]
    fn journal_ahead_crash_gap_preserves_unknown_and_advances_witness() {
        let (_dir, config) = bound_fixture();
        drop(AccountLock::acquire(&config).unwrap());
        // A Store without attached binding simulates death after SQLite commit,
        // before witness advancement; production dispatch cannot cross that gap.
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Mine, "1", "prepared");
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        assert_eq!(read_binding(&config).unwrap().unwrap().dispatch_sequence, 0);
        drop(store);
        let (lock, mut adopted) = AccountLock::acquire(&config).unwrap();
        adopted.recover().unwrap();
        assert_eq!(adopted.effect().unwrap().unwrap().state, "unknown");
        assert_eq!(read_binding(&config).unwrap().unwrap().dispatch_sequence, 1);
        drop(adopted);
        drop(lock);
        remove_anchors(&config);
    }

    #[test]
    fn legacy_binding_adopts_intact_unknown_and_detects_lock_replacement() {
        let (_dir, mut config) = bound_fixture();
        config.schedule.mine_each_epoch = true;
        config.capabilities.mine = Mode::Active;
        config.participation.mode = ParticipationMode::ParticipationFirst;
        config.participation.uncertainty_grace_seconds = 0;
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut completed = begin(&mut store, WorkKind::Mine, "2:legacy", "prepared");
        completed.state = "dispatching".into();
        store.save(&completed, "dispatch_intent").unwrap();
        completed.state = "completed".into();
        store.save(&completed, "mine_completed").unwrap();
        let mut discarded = begin(&mut store, WorkKind::Mine, "3:legacy", "prepared");
        discarded.state = "dispatching".into();
        store.save(&discarded, "dispatch_intent").unwrap();
        discarded.state = "retry".into();
        store.save(&discarded, "submission_backoff").unwrap();
        discarded.state = "discarded".into();
        store.save(&discarded, "request_no_longer_current").unwrap();
        let mut unsent = begin(&mut store, WorkKind::Mine, "4:legacy", "prepared");
        unsent.state = "discarded".into();
        store.save(&unsent, "request_no_longer_current").unwrap();
        let mut pruned = begin(&mut store, WorkKind::Mine, "5:legacy", "prepared");
        pruned.state = "discarded".into();
        store.save(&pruned, "request_no_longer_current").unwrap();
        let mut op = begin(&mut store, WorkKind::Mine, "1:legacy", "prepared");
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        op.state = "unknown".into();
        store.save(&op, "dispatch_outcome_unknown").unwrap();
        store
            .db
            .execute_batch(
                "UPDATE control SET version=1; DROP TABLE authority;
            DROP TABLE operation_evidence; DROP TABLE runtime_policy;",
            )
            .unwrap();
        drop(store);
        let writer = lock_path(&config, "writer").unwrap();
        let mut legacy = private_file(&writer).unwrap();
        legacy
            .write_all(digest(config.state_dir.as_os_str().as_encoded_bytes()).as_bytes())
            .unwrap();
        legacy.sync_all().unwrap();
        drop(legacy);
        assert!(AccountLock::acquire(&config).is_err());
        assert!(AccountLock::control_store(&config).is_err());
        let (lock, mut adopted) = AccountLock::adopt(&config).unwrap();
        assert_eq!(adopted.effect().unwrap().unwrap().id, op.id);
        assert_eq!(adopted.effect().unwrap().unwrap().state, "unknown");
        for epoch in [1, 2, 3] {
            assert!(adopted.mine_epoch_attempted(epoch).unwrap());
            let mut duplicate = prepared_epoch(&mut adopted, WorkKind::Mine, epoch, "new");
            assert!(!adopted.dispatch_intent(&mut duplicate, &config).unwrap());
            duplicate.state = "discarded".into();
            adopted
                .save(&duplicate, "request_no_longer_current")
                .unwrap();
        }
        assert!(!adopted.mine_epoch_attempted(4).unwrap());
        let mut replacement = prepared_epoch(&mut adopted, WorkKind::Mine, 4, "new");
        assert!(adopted.dispatch_intent(&mut replacement, &config).unwrap());
        assert!(!adopted.mine_epoch_attempted(5).unwrap());
        adopted
            .db
            .execute(
                "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events WHERE operation_id=?1)",
                [pruned.id],
            )
            .unwrap();
        assert!(adopted.mine_epoch_attempted(5).unwrap());
        assert!(adopted.mine_epoch_attempted(3).unwrap());
        let old = writer.with_extension("fixture-old-lock");
        fs::rename(&writer, &old).unwrap();
        drop(private_file(&writer).unwrap());
        assert!(adopted.continuity().is_err());
        drop(adopted);
        drop(lock);
        fs::remove_file(old).unwrap();
        remove_anchors(&config);
    }

    #[test]
    fn unmarked_legacy_journal_is_not_implicitly_adopted() {
        let (_dir, config) = bound_fixture();
        let store = Store::open(&config).unwrap();
        store
            .db
            .execute_batch(
                "UPDATE control SET version=1; DROP TABLE authority;
                 DROP TABLE operation_evidence; DROP TABLE runtime_policy;",
            )
            .unwrap();
        drop(store);
        let acquired = AccountLock::acquire(&config).is_ok();
        let controlled = AccountLock::control_store(&config).is_ok();
        let adopted = AccountLock::adopt(&config).is_ok();
        let schema = Store::read_only(&config)
            .unwrap()
            .unwrap()
            .schema_version()
            .unwrap();
        remove_anchors(&config);
        assert!(!acquired && !controlled && !adopted);
        assert_eq!(schema, 1);
    }

    #[test]
    fn adoption_requires_an_existing_initialized_journal() {
        let (_dir, config) = bound_fixture();
        let adopted = AccountLock::adopt(&config).is_ok();
        let initialized = config.state_dir.join("state.sqlite3").exists();
        remove_anchors(&config);
        assert!(!adopted);
        assert!(!initialized);
    }

    #[test]
    fn unanchored_schema2_requires_explicit_adoption() {
        let (_dir, config) = bound_fixture();
        let store = Store::open(&config).unwrap();
        let identity = store.database_identity().unwrap();
        drop(store);
        let acquired = AccountLock::acquire(&config).is_ok();
        let controlled = AccountLock::control_store(&config).is_ok();
        remove_anchors(&config);
        assert!(!acquired && !controlled);
        let (lock, adopted) = AccountLock::adopt(&config).unwrap();
        assert_eq!(adopted.database_identity().unwrap(), identity);
        drop(adopted);
        drop(lock);
        remove_anchors(&config);
    }

    #[test]
    fn missing_schema2_authority_is_not_recreated() {
        for explicit in [false, true] {
            let (_dir, config) = bound_fixture();
            let store = Store::open(&config).unwrap();
            store.db.execute("DROP TABLE authority", []).unwrap();
            let accepted = if explicit {
                AccountLock::adopt(&config).is_ok()
            } else {
                AccountLock::acquire(&config).is_ok()
            };
            let recreated: bool = store
                .db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            drop(store);
            remove_anchors(&config);
            assert!(!accepted);
            assert!(!recreated);
        }
    }

    #[test]
    fn bounded_model_retry_never_changes_effect_uncertainty() {
        let (_dir, mut config) = fixture();
        config.preparation.max_attempts_per_work = 2;
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut model = begin(&mut store, WorkKind::Answer, "1:word", "generating");
        model.state = "model_unknown".into();
        store.save(&model, "model_launch_unknown").unwrap();
        let mut effect = begin(&mut store, WorkKind::Judge, &"A".repeat(64), "prepared");
        effect.state = "dispatching".into();
        store.save(&effect, "dispatch_intent").unwrap();
        effect.state = "unknown".into();
        store.save(&effect, "dispatch_outcome_unknown").unwrap();
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(model.id).unwrap().unwrap().state,
            "model_unknown"
        );
        config.preparation.retry_uncertain = true;
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(model.id).unwrap().unwrap().state,
            "superseded_model_unknown"
        );
        assert_eq!(store.effect().unwrap().unwrap().id, effect.id);
        assert!(store.attempted(WorkKind::Judge, &"a".repeat(64)).unwrap());
        let mut retry = begin(&mut store, WorkKind::Answer, "1:word", "generating");
        retry.state = "model_unknown".into();
        store.save(&retry, "model_launch_unknown").unwrap();
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(retry.id).unwrap().unwrap().state,
            "model_unknown"
        );
    }

    #[test]
    fn completed_model_retry_budget_survives_restart_without_retrying_uncertain_work() {
        let (_temp, config, mut store) = participation_fixture();
        assert_eq!(config.preparation.max_attempts_per_work, 2);
        assert!(!config.preparation.retry_uncertain);
        let mut first = begin(&mut store, WorkKind::Answer, "7:words", "generating");
        first.result = Some(json!({"answer":"invalid completed draft"}));
        first.state = "rejected".into();
        store.save(&first, "model_output_invalid").unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(first.id).unwrap().unwrap().state,
            "retry_model"
        );
        assert!(!store.answer_epoch_attempted(7).unwrap());
        assert_eq!(
            store
                .model_budget_used(WorkKind::Answer, "7:words")
                .unwrap(),
            1
        );

        let mut second = begin(&mut store, WorkKind::Answer, "7:words", "generating");
        second.result = first.result.clone();
        second.state = "rejected".into();
        store.save(&second, "model_output_invalid").unwrap();
        let mut uncertain = begin(&mut store, WorkKind::Judge, "uncertain-model", "generating");
        uncertain.state = "model_unknown".into();
        store.save(&uncertain, "model_launch_unknown").unwrap();
        let mut dispatched = dispatched_unknown(&mut store, &config, WorkKind::Answer, 9);
        dispatched.state = "rejected".into();
        store.save(&dispatched, "submission_rejected").unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.retry_models(&config).unwrap();
        assert_eq!(
            store
                .model_budget_used(WorkKind::Answer, "7:words")
                .unwrap(),
            2
        );
        assert!(store.answer_epoch_attempted(7).unwrap());
        assert_eq!(
            store.operation(second.id).unwrap().unwrap().state,
            "rejected"
        );
        assert_eq!(
            store.operation(uncertain.id).unwrap().unwrap().state,
            "model_unknown"
        );
        let retained = store.operation(dispatched.id).unwrap().unwrap();
        assert_eq!(retained.state, "rejected");
        assert_eq!(retained.payload, dispatched.payload);
        assert_eq!(store.attempt_count(WorkKind::Answer, "7:words").unwrap(), 2);
        assert!(store.effect().unwrap().is_none());
    }

    #[test]
    fn missing_independent_binding_is_not_silently_readopted() {
        let (_dir, config) = bound_fixture();
        drop(AccountLock::acquire(&config).unwrap());
        fs::remove_file(lock_path(&config, "binding").unwrap()).unwrap();
        assert!(AccountLock::acquire(&config).is_err());
        assert!(AccountLock::control_store(&config).is_err());
        assert!(Store::read_only(&config).is_err());
        remove_anchors(&config);
    }

    #[test]
    fn unchanged_observation_retains_transition_age_and_private_candidates() {
        let (_dir, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused(false).unwrap();
        let mut op = begin(&mut store, WorkKind::Mine, "1", "prepared");
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        op.state = "unknown".into();
        store.save(&op, "dispatch_outcome_unknown").unwrap();
        store
            .record_candidates(
                op.id,
                &json!({"job_id":"private-job-canary","transaction_ids":[]}),
            )
            .unwrap();
        let before = store.events(100).unwrap();
        store.save(&op, "receipt_unresolved").unwrap();
        assert_eq!(store.events(100).unwrap(), before);
        store
            .record_candidates(op.id, &json!({"job_id":null,"transaction_ids":[]}))
            .unwrap();
        for _ in 0..2010 {
            store.event("test_ring_rotation", None).unwrap();
        }
        assert!(
            store
                .inspect(op.id)
                .unwrap()
                .to_string()
                .contains("private-job-canary")
        );
        assert!(
            !store
                .status(&config)
                .unwrap()
                .to_string()
                .contains("private-job-canary")
        );
        assert!(
            !store
                .events(1000)
                .unwrap()
                .to_string()
                .contains("private-job-canary")
        );
    }
}
