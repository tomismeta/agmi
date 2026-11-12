use crate::capability::LaneId;
use crate::config::{
    Config, CountLimit, HistoricalAnswerCapacity, Mode, Participation, ParticipationMode,
};
use crate::journal::CURRENT_JOURNAL_FORMAT;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

mod accounting;
mod admission;
mod lane_control;
mod model_attempt;
mod model_retry;
pub(crate) use admission::{
    AdmissionStampSnapshot, EffectCandidate, OperationBinding, PreparationInputs,
};
pub(crate) use lane_control::{AdmissionObservation, LaneAdmissionGuard};
pub use lane_control::{LaneControlError, lane_control_status, set_lane_paused};
use lane_control::{
    LaneGateSet, initialize_lane_state, open_required_lane_gates, provision_lane_gates,
    validate_required_lane_state,
};
pub(crate) use model_attempt::{ModelProducerDraft, ModelProducerProvenance};
pub mod migration;
mod projection;
mod reads;
mod schema;
pub(crate) use reads::{DiscoverySource, LaneObservation, LaneObservationStamp, ReadKey};
use schema::initialize_schema;
#[cfg(test)]
mod atomic_tests;
#[cfg(test)]
mod writer_continuity_tests;

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
    if store.schema_version()? != CURRENT_JOURNAL_FORMAT {
        return Err(RefusalRecoveryError("refusal_recovery_schema").into());
    }
    store.routing_change_allowed(&config)?;
    // Bind approval to file bytes, including metadata-only configuration changes.
    let revision = digest(fs::read(config_path)?);
    if let Some(token) = apply {
        drop(store);
        let (_account, mut store) = AccountLock::acquire(&config)?;
        let _gate = AccountAdmissionGuard::acquire(&config)?;
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
    if store.schema_version()? != CURRENT_JOURNAL_FORMAT {
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
    let _gate = AccountAdmissionGuard::acquire(&config)?;
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
    account_lock_path(&config.network.chain, &config.network.address, suffix)
}

fn account_lock_path(chain: &str, address: &str, suffix: &str) -> Result<PathBuf> {
    #[cfg(unix)]
    let root = account_home()?.join(".agmi-account-locks");
    #[cfg(not(unix))]
    let root = dirs::home_dir()
        .context("home directory unavailable")?
        .join(".agmi-account-locks");
    let key = digest(format!("{chain}\n{address}"));
    Ok(root.join(format!("{key}.{suffix}")))
}

pub(crate) struct AccountLock(File);
const WRITER_MARKER: &[u8] = b"agmi-authority-v2\n";

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    location: String,
    identity: String,
    database_id: String,
    dispatch_sequence: i64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_writer_inode"
    )]
    writer_inode: Option<WriterInode>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_writer_inode"
    )]
    admission_inode: Option<WriterInode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WriterInode {
    device: u64,
    inode: u64,
}

fn deserialize_writer_inode<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<WriterInode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Only absence is legacy. A present null/partial/malformed anchor is not.
    <WriterInode as serde::Deserialize>::deserialize(deserializer).map(Some)
}

impl WriterInode {
    fn from_metadata(metadata: &fs::Metadata) -> Result<Self> {
        validate_private_file(metadata)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            bail!("writer authority requires stable operating-system file identities")
        }
    }
}

impl Binding {
    fn validate(&self) -> Result<()> {
        if self.database_id.len() != 32
            || !self
                .database_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.dispatch_sequence < 0
            || self.identity.len() != 64
            || !self.identity.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !Path::new(&self.location).is_absolute()
            || self
                .writer_inode
                .is_some_and(|identity| identity.inode == 0)
            || self
                .admission_inode
                .is_some_and(|identity| identity.inode == 0)
        {
            bail!("invalid account binding");
        }
        Ok(())
    }

    fn check_writer(&self, path: &Path, metadata: &fs::Metadata) -> Result<()> {
        let anchor = self.writer_inode.context(
            "writer authority is unanchored; stop all controllers and native work, then explicitly recover adopt",
        )?;
        if WriterInode::from_metadata(metadata)? != anchor {
            bail!(
                "writer inode differs from immutable account binding; authoritative recovery required"
            );
        }
        lane_control::check_file_identity(path, metadata)?;
        Ok(())
    }

    fn check_admission(&self, path: &Path, metadata: &fs::Metadata) -> Result<()> {
        let anchor = self.admission_inode.context(
            "account admission authority is unanchored; stop all controllers and native work, then explicitly recover adopt",
        )?;
        if WriterInode::from_metadata(metadata)? != anchor {
            bail!(
                "account admission inode differs from immutable account binding; authoritative recovery required"
            );
        }
        lane_control::check_file_identity(path, metadata)
    }

    fn check_context(&self, config: &Config) -> Result<()> {
        if self.identity != digest(identity(config)?)
            || self.location != fs::canonicalize(&config.state_dir)?.to_string_lossy()
        {
            bail!("account admission binding context differs from configuration");
        }
        Ok(())
    }

    fn same_authority(&self, other: &Self) -> bool {
        self.location == other.location
            && self.identity == other.identity
            && self.database_id == other.database_id
            && self.writer_inode == other.writer_inode
            && self.admission_inode == other.admission_inode
    }
}

fn read_private_bytes(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let mut file = lane_control::opened_file(path, false, false)?;
    if file.metadata()?.len() > limit {
        bail!("authority document exceeds its size limit");
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("authority document exceeds its size limit");
    }
    lane_control::check_opened_path(path, &file)?;
    Ok(Some(bytes))
}

fn binding_at(path: &Path) -> Result<Option<Binding>> {
    read_private_bytes(path, 4096)?
        .map(|bytes| {
            let binding: Binding =
                serde_json::from_slice(&bytes).context("invalid account binding")?;
            binding.validate()?;
            Ok(binding)
        })
        .transpose()
}

fn read_binding(config: &Config) -> Result<Option<Binding>> {
    read_account_binding(&lock_path(config, "binding")?)
}

fn read_account_binding(path: &Path) -> Result<Option<Binding>> {
    let binding = binding_at(path)?;
    if binding.is_none()
        && read_private_bytes(&path.with_extension("writer"), 64)?
            .is_some_and(|marker| marker == WRITER_MARKER)
    {
        bail!("independent account binding is missing; authoritative recovery required");
    }
    Ok(binding)
}

fn writer_marker(file: &File) -> Result<Vec<u8>> {
    let mut reader = file;
    reader.rewind()?;
    let mut bytes = Vec::new();
    reader.take(65).read_to_end(&mut bytes)?;
    if bytes.len() > 64 {
        bail!("invalid stable writer marker");
    }
    Ok(bytes)
}

pub(crate) fn validate_page(before: Option<i64>, limit: usize) -> Result<()> {
    if !(1..=1000).contains(&limit) || before.is_some_and(|id| id <= 0) {
        bail!("pagination requires limit 1..1000 and a positive before ID");
    }
    Ok(())
}

/// Metadata-only initialization probe for CLI configuration updates.
pub(crate) fn admin_identity_initialized(config: &Config) -> Result<bool> {
    // Resolve authority from stored identity, not an edited config's lock namespace.
    Ok(Store::read_only(config)?.is_some())
}

fn write_binding(path: &Path, binding: &Binding) -> Result<()> {
    binding.validate()?;
    write_binding_bytes(path, &serde_json::to_vec(binding)?)
}

fn write_binding_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("binding-next");
    let mut file = lane_control::opened_file(&temporary, true, true)?;
    file.set_len(0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(path.parent().context("binding parent missing")?)?.sync_all()?;
    Ok(())
}

impl AccountLock {
    fn rotation_lock_file(config: &Config, suffix: &str) -> Result<File> {
        lane_control::opened_file(&lock_path(config, suffix)?, true, false)
            .context("initialize and pause the account before stopped maintenance")
    }

    /// Existing gate only: even previews must not create lock/state artifacts.
    pub(crate) fn rotation_admission(config: &Config) -> Result<AccountAdmissionGuard> {
        AccountAdmissionGuard::acquire(config)
    }

    /// Caller holds admission. Migration validates its own approved historical snapshot.
    fn stopped_for_migration(config: &Config) -> Result<Self> {
        let file = Self::rotation_lock_file(config, "writer")?;
        file.try_lock()
            .map_err(std::io::Error::from)
            .context("stop the runtime before account maintenance")?;
        lane_control::check_opened_path(&lock_path(config, "writer")?, &file)?;
        Ok(Self(file))
    }

    /// Ordinary stopped maintenance requires current, independently anchored authority.
    pub(crate) fn stopped(config: &Config) -> Result<Self> {
        let lock = Self::stopped_for_migration(config)?;
        let binding = read_binding(config)?.context("independent account binding missing")?;
        binding.check_writer(&lock_path(config, "writer")?, &lock.0.metadata()?)?;
        let admission_path = lock_path(config, "admission")?;
        binding.check_admission(&admission_path, &fs::symlink_metadata(&admission_path)?)?;
        if writer_marker(&lock.0)? != WRITER_MARKER {
            bail!("permanent writer marker missing; explicit stopped adoption required");
        }
        let store = Store::read_only(config)?.context("bound journal missing")?;
        migration::ensure_complete(&store.db)?;
        store.check_config_identity(config)?;
        Ok(lock)
    }

    pub(crate) fn acquire(config: &Config) -> Result<(Self, Store)> {
        Self::acquire_with_migration(config, false)
    }

    pub(crate) fn adopt(config: &Config) -> Result<(Self, Store)> {
        Self::acquire_with_migration(config, true)
    }

    fn open_writer(config: &Config, adopt: bool) -> Result<File> {
        let binding = read_binding(config)?;
        let database_exists = config.state_dir.join("state.sqlite3").try_exists()?;
        if adopt && !database_exists {
            bail!("adoption requires an existing initialized journal");
        }
        if database_exists && binding.is_none() && !adopt {
            bail!("unanchored journal requires explicit stopped-writer adoption");
        }
        // An existing Binding always requires its original existing writer.
        // Only genuinely fresh or explicitly unbound initialization may create one.
        let create = binding.is_none() && (!database_exists || adopt);
        lane_control::opened_file(&lock_path(config, "writer")?, true, create)
            .context("writer authority missing or unsafe; authoritative recovery required")
    }

    fn acquire_with_migration(config: &Config, adopt: bool) -> Result<(Self, Store)> {
        migration::ensure_no_pending(config)?;
        let gate = AccountAdmissionGuard::for_initialization(config, adopt)?;
        let mut file = Self::open_writer(config, adopt)?;
        file.try_lock()
            .map_err(std::io::Error::from)
            .context("another runtime already owns this account")?;
        let store = Self::open_bound_store(&mut file, config, &gate, adopt, true)?;
        Ok((Self(file), store))
    }

    fn open_bound_store(
        file: &mut File,
        config: &Config,
        gate: &AccountAdmissionGuard,
        adopt: bool,
        stopped: bool,
    ) -> Result<Store> {
        if config.network.address.is_empty()
            || config.network.credential_file.as_os_str().is_empty()
        {
            bail!("durable control requires a configured account and credential file");
        }
        gate.check_acquired(config)?;
        let admission_path = lock_path(config, "admission")?;
        let admission_metadata = gate.0.metadata()?;
        let admission_anchor = WriterInode::from_metadata(&admission_metadata)?;
        let writer_path = lock_path(config, "writer")?;
        lane_control::check_opened_path(&writer_path, file)?;
        let writer_metadata = file.metadata()?;
        let anchor = WriterInode::from_metadata(&writer_metadata)?;
        let bytes = writer_marker(file)?;
        let marked = bytes == WRITER_MARKER;
        let binding_path = lock_path(config, "binding")?;
        let mut binding = read_binding(config)?;
        let database_exists = config.state_dir.join("state.sqlite3").try_exists()?;
        let fresh = !database_exists && binding.is_none() && bytes.is_empty();
        if fresh && (!stopped || adopt) {
            bail!("initialization requires exclusive writer ownership");
        }
        if !fresh && !database_exists {
            bail!("bound journal is missing; authoritative recovery required");
        }
        if let Some(binding) = &binding {
            if binding.admission_inode.is_some() {
                binding.check_admission(&admission_path, &admission_metadata)?;
            } else if !(adopt && stopped) {
                bail!("account admission authority requires explicit stopped adoption");
            }
            if binding.writer_inode.is_some() {
                binding.check_writer(&writer_path, &writer_metadata)?;
                if !(marked || adopt && stopped && bytes.is_empty()) {
                    bail!("permanent writer marker missing; explicit stopped adoption required");
                }
            } else if !(adopt && stopped && marked) {
                bail!(
                    "unanchored established writer requires its intact permanent marker and explicit stopped adoption"
                );
            }
        } else if !fresh
            && (!(adopt && stopped)
                || !(bytes.is_empty()
                    || bytes == digest(config.state_dir.as_os_str().as_encoded_bytes()).as_bytes()))
        {
            bail!("unbound journal requires intact evidence and explicit stopped adoption");
        }
        if !fresh {
            // All authority checks precede writable SQLite setup, routing and recovery.
            let existing = Store::read_only(config)?.context("bound journal is missing")?;
            migration::ensure_complete(&existing.db)?;
            existing.check_config_identity(config)?;
            let (database_id, sequence) = existing.database_identity()?;
            let candidate = binding.get_or_insert(Binding {
                location: fs::canonicalize(&config.state_dir)?
                    .to_string_lossy()
                    .into_owned(),
                identity: digest(identity(config)?),
                database_id,
                dispatch_sequence: sequence,
                writer_inode: None,
                admission_inode: None,
            });
            candidate.validate()?;
            if adopt && existing.routing_status(config)?["matches_config"] != true {
                bail!("adoption requires matching existing routing evidence");
            }
            if !stopped && existing.routing_status(config)?["matches_config"] != true {
                bail!("stop the runtime before changing API routing");
            }
        }
        if !fresh && adopt {
            let binding = binding.as_mut().context("adoption binding missing")?;
            binding.writer_inode = Some(anchor); // absent or already checked identical
            binding.admission_inode = Some(admission_anchor);
            lane_control::check_opened_path(&admission_path, &gate.0)?;
            gate.0.sync_all()?;
            lane_control::check_opened_path(&writer_path, file)?;
            file.sync_all()?;
            gate.check_acquired(config)?;
            File::open(writer_path.parent().context("writer parent missing")?)?.sync_all()?;
            write_binding(&binding_path, binding)?;
        }
        if !fresh && !marked {
            lane_control::check_opened_path(&writer_path, file)?;
            Self::mark_writer(file, &writer_path)?;
        }
        if fresh {
            lane_control::check_opened_path(&admission_path, &gate.0)?;
            lane_control::check_opened_path(&writer_path, file)?;
            gate.0.sync_all()?;
            file.sync_all()?;
            File::open(writer_path.parent().context("writer parent missing")?)?.sync_all()?;
        } else {
            gate.validate(config)?;
        }
        let authority = binding.map(|binding| {
            (
                (binding_path.clone(), binding),
                (writer_path.clone(), writer_metadata),
            )
        });
        let mut store = Store::open_inner(config, authority)?;
        if fresh {
            lane_control::check_opened_path(&admission_path, &gate.0)?;
            lane_control::check_opened_path(&writer_path, file)?;
            file.sync_all()?;
            File::open(writer_path.parent().context("writer parent missing")?)?.sync_all()?;
            let (database_id, sequence) = store.database_identity()?;
            let binding = Binding {
                location: fs::canonicalize(&config.state_dir)?
                    .to_string_lossy()
                    .into_owned(),
                identity: digest(identity(config)?),
                database_id,
                dispatch_sequence: sequence,
                writer_inode: Some(anchor),
                admission_inode: Some(admission_anchor),
            };
            gate.check_acquired(config)?;
            write_binding(&binding_path, &binding)?;
            lane_control::check_opened_path(&writer_path, file)?;
            Self::mark_writer(file, &writer_path)?;
            store.binding = Some((binding_path, binding));
            store.writer_path = Some((writer_path, file.metadata()?));
        }
        gate.validate(config)?;
        store.continuity()?;
        store.bind_routing(config)?;
        if !adopt {
            // A journal-ahead gap remains uncertain; advancing its witness never replays it.
            store.publish_dispatch_witness()?;
        }
        store.continuity()?;
        gate.validate(config)?;
        Ok(store)
    }

    fn mark_writer(file: &mut File, path: &Path) -> Result<()> {
        file.rewind()?;
        file.write_all(WRITER_MARKER)?;
        file.set_len(WRITER_MARKER.len() as u64)?;
        file.sync_all()?;
        File::open(path.parent().context("writer parent missing")?)?.sync_all()?;
        Ok(())
    }

    /// Caller holds admission. A live-control branch requires an actual lock-busy result.
    pub(crate) fn control_store(config: &Config, gate: &AccountAdmissionGuard) -> Result<Store> {
        migration::ensure_no_pending(config)?;
        let mut file = Self::open_writer(config, false)?;
        let stopped = match file.try_lock() {
            Ok(()) => true,
            Err(error) => {
                let error = std::io::Error::from(error);
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                false
            }
        };
        let result = Self::open_bound_store(&mut file, config, gate, false, stopped);
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
pub(crate) struct AccountAdmissionGuard(File, PathBuf, Option<Binding>);
impl AccountAdmissionGuard {
    pub(crate) fn acquire(config: &Config) -> Result<Self> {
        Self::ordinary(config, false)
    }

    pub(crate) fn try_acquire(config: &Config) -> Result<Self> {
        Self::ordinary(config, true)
    }

    fn ordinary(config: &Config, nonblocking: bool) -> Result<Self> {
        let binding = read_binding(config)?.context("independent account binding missing")?;
        binding.check_context(config)?;
        if binding.writer_inode.is_none() || binding.admission_inode.is_none() {
            bail!(
                "account authority is unanchored; stop all controllers and native work, then explicitly recover adopt"
            );
        }
        let path = lock_path(config, "admission")?;
        let file = lane_control::opened_file(&path, true, false)?;
        binding.check_admission(&path, &file.metadata()?)?;
        if nonblocking {
            file.try_lock()
                .map_err(std::io::Error::from)
                .context("account admission is busy")?;
        } else {
            file.lock()
                .context("cannot acquire account admission gate")?;
        }
        let guard = Self(file, path, Some(binding));
        guard.validate(config)?;
        Ok(guard)
    }

    /// Config-only fencing never adopts or initializes an existing journal.
    pub(crate) fn for_provisioning(config: &Config) -> Result<Self> {
        if read_binding(config)?.is_some() {
            return Self::acquire(config);
        }
        Self::for_initialization(config, false)
    }

    pub(crate) fn for_control(config: &Config) -> Result<Self> {
        Self::for_initialization(config, false)
    }

    fn for_initialization(config: &Config, adopt: bool) -> Result<Self> {
        let binding = read_binding(config)?;
        if binding.is_some() && !adopt {
            return Self::acquire(config);
        }
        let database_exists = config.state_dir.join("state.sqlite3").try_exists()?;
        if database_exists != adopt && binding.is_none() {
            bail!(
                "existing journals require explicit stopped adoption; adoption requires an initialized journal"
            );
        }
        let marker = read_private_bytes(&lock_path(config, "writer")?, 64)?;
        if binding.is_none() && !adopt && marker.as_ref().is_some_and(|bytes| !bytes.is_empty()) {
            bail!("established writer authority cannot be provisioned as a fresh account");
        }
        let guard = Self::raw(config, binding.is_none(), binding)?;
        if config.state_dir.join("state.sqlite3").try_exists()? != database_exists
            || read_private_bytes(&lock_path(config, "writer")?, 64)? != marker
        {
            bail!("account initialization authority changed while acquiring admission");
        }
        Ok(guard)
    }

    /// Isolated stopped migration acquisition; absence is not ordinary authority.
    fn for_migration(config: &Config, create: bool) -> Result<Self> {
        let binding = read_binding(config)?;
        Self::raw(config, create, binding)
    }

    fn raw(config: &Config, create: bool, binding: Option<Binding>) -> Result<Self> {
        let path = lock_path(config, "admission")?;
        if let Some(binding) = &binding {
            binding.check_context(config)?;
        }
        let file = lane_control::opened_file(
            &path,
            true,
            create
                && binding
                    .as_ref()
                    .is_none_or(|binding| binding.admission_inode.is_none()),
        )?;
        if let Some(binding) = &binding
            && binding.admission_inode.is_some()
        {
            binding.check_admission(&path, &file.metadata()?)?;
        }
        file.lock()
            .context("cannot acquire account admission gate")?;
        let guard = Self(file, path, binding);
        guard.check_acquired(config)?;
        Ok(guard)
    }

    fn check_acquired(&self, config: &Config) -> Result<()> {
        lane_control::check_opened_path(&self.1, &self.0)?;
        let current = read_binding(config)?;
        match (&self.2, &current) {
            (None, None) => {}
            (Some(expected), Some(current))
                if expected.same_authority(current)
                    && current.dispatch_sequence >= expected.dispatch_sequence =>
            {
                current.check_context(config)?;
                if current.admission_inode.is_some() {
                    current.check_admission(&self.1, &self.0.metadata()?)?;
                }
            }
            _ => bail!("account admission authority changed while acquiring the gate"),
        }
        Ok(())
    }

    fn validated_binding(&self) -> Result<Binding> {
        let current = read_account_binding(&self.1.with_extension("binding"))?
            .context("independent account binding missing")?;
        current.check_admission(&self.1, &self.0.metadata()?)?;
        let writer = self.1.with_extension("writer");
        current.check_writer(&writer, &fs::symlink_metadata(&writer)?)?;
        if read_private_bytes(&writer, 64)?.as_deref() != Some(WRITER_MARKER) {
            bail!("permanent writer marker missing; explicit stopped adoption required");
        }
        if let Some(expected) = &self.2 {
            // Only an explicit stopped publication may fill previously absent fields.
            // Every recorded identity remains fixed, including the held gate itself.
            if current.location != expected.location
                || current.identity != expected.identity
                || current.database_id != expected.database_id
                || current.dispatch_sequence < expected.dispatch_sequence
                || expected
                    .writer_inode
                    .is_some_and(|inode| current.writer_inode != Some(inode))
                || expected
                    .admission_inode
                    .is_some_and(|inode| current.admission_inode != Some(inode))
            {
                bail!("accepted account admission authority changed");
            }
        }
        Ok(current)
    }

    pub(super) fn validate(&self, config: &Config) -> Result<()> {
        if self.1 != lock_path(config, "admission")? {
            bail!("account admission guard belongs to another account");
        }
        self.validated_binding()?.check_context(config)
    }
}
impl Drop for AccountAdmissionGuard {
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
    pub kind: LaneId,
    pub key: String,
    pub state: String,
    pub request: Value,
    pub result: Option<Value>,
    pub payload: Option<Value>,
    pub job_id: Option<String>,
    pub txid: Option<String>,
    pub next_at: i64,
    pub binding_revision: i64,
    persisted_binding_revision: std::cell::Cell<i64>,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadBackoff {
    pub failures: u32,
    pub next_at: i64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AdmissionCutoff {
    pub at: i64,
    pub grant_id: i64,
}
impl AdmissionCutoff {
    fn current() -> Self {
        Self {
            at: now(),
            grant_id: i64::MAX,
        }
    }
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
        let _ = (left, right);
        false
    }
}

#[derive(Clone, serde::Serialize)]
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

#[derive(Clone, Default)]
struct UncertaintyAccounting {
    total: u64,
    /// False when cumulative historical counts and account-wide grace were
    /// deliberately not evaluated (unbounded participation-first fresh work).
    /// Counts read as zero then; evidence must say so instead of implying it.
    history_evaluated: bool,
    own_total: u64,
    own_exempt: u64,
    own_blockers: Vec<i64>,
    legacy_floor: bool,
    eligible: u64,
    exempt: u64,
    historical: Vec<HistoricalAnswer>,
    blockers: Vec<i64>,
    writing: bool,
    retry_not_before: i64,
    grace_until: i64,
    retry_grace_until: i64,
    restriction_scope: Option<String>,
    retry_origin_floor: i64,
}

impl UncertaintyAccounting {
    fn active(&self) -> u64 {
        self.own_total - self.own_exempt
    }
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

    pub(crate) fn database_identity(&self) -> Result<(String, i64)> {
        Ok(self.db.query_row(
            "SELECT database_id,dispatch_sequence FROM authority WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    fn check_config_identity(&self, config: &Config) -> Result<()> {
        let stored: String = self.db.query_row(
            "SELECT identity FROM control WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if stored != identity(config)? {
            bail!("state belongs to a different immutable network identity");
        }
        Ok(())
    }

    fn check_binding(&self, config: &Config) -> Result<()> {
        let stored: String = self.db.query_row(
            "SELECT identity FROM control WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let account: Value = serde_json::from_str(&stored)?;
        let path = account_lock_path(
            account["chain"]
                .as_str()
                .context("stored account chain missing")?,
            account["address"]
                .as_str()
                .context("stored account address missing")?,
            "binding",
        )?;
        if let Some(binding) = read_account_binding(&path)? {
            let (id, sequence) = self.database_identity()?;
            if id != binding.database_id
                || sequence < binding.dispatch_sequence
                || binding.identity != digest(&stored)
                || binding.location != fs::canonicalize(&config.state_dir)?.to_string_lossy()
            {
                bail!("bound journal identity or dispatch witness mismatch");
            }
            // Unanchored metadata is inspectable, but never grants mutation.
            if binding.writer_inode.is_some() {
                let writer_path = path.with_extension("writer");
                let writer = lane_control::opened_file(&writer_path, false, false)?;
                binding.check_writer(&writer_path, &writer.metadata()?)?;
            }
            if binding.admission_inode.is_some() {
                let admission_path = path.with_extension("admission");
                let admission = lane_control::opened_file(&admission_path, false, false)?;
                binding.check_admission(&admission_path, &admission.metadata()?)?;
            }
        }
        Ok(())
    }

    pub(super) fn writer_authority_status(&self) -> Result<Value> {
        let stored: String = self.db.query_row(
            "SELECT identity FROM control WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let account: Value = serde_json::from_str(&stored)?;
        let path = account_lock_path(
            account["chain"]
                .as_str()
                .context("stored account chain missing")?,
            account["address"]
                .as_str()
                .context("stored account address missing")?,
            "binding",
        )?;
        let binding = read_account_binding(&path)?;
        let marker = read_private_bytes(&path.with_extension("writer"), 64)?;
        let unanchored_admission_intact = binding.as_ref().is_none_or(|binding| {
            binding.admission_inode.is_some()
                || lane_control::opened_file(&path.with_extension("admission"), false, false)
                    .is_ok()
        });
        if let Some(binding) = &binding
            && binding.admission_inode.is_some()
        {
            let admission_path = path.with_extension("admission");
            binding.check_admission(&admission_path, &fs::symlink_metadata(&admission_path)?)?;
        }
        let (state, prerequisite) = match binding {
            Some(_) if !unanchored_admission_intact => (
                "authority_incomplete",
                Some(
                    "Established account-admission gate is missing or unsafe; authoritative recovery is required, not first-anchor adoption.",
                ),
            ),
            Some(binding) if binding.writer_inode.is_some() => {
                let writer_path = path.with_extension("writer");
                let writer = lane_control::opened_file(&writer_path, false, false)?;
                binding.check_writer(&writer_path, &writer.metadata()?)?;
                if marker.as_deref() == Some(WRITER_MARKER) && binding.admission_inode.is_none() {
                    (
                        "admission_unanchored",
                        Some(
                            "Stop all controllers and native work; explicit recover adopt must establish account-admission continuity before ordinary use.",
                        ),
                    )
                } else if marker.as_deref() == Some(WRITER_MARKER) {
                    ("anchored", None)
                } else if marker.as_deref() == Some(b"") {
                    (
                        "initialization_interrupted",
                        Some(
                            "Stop all controllers and native work; explicit recover adopt may finish the marker only on this same anchored inode.",
                        ),
                    )
                } else {
                    bail!("permanent writer marker changed; authoritative recovery required");
                }
            }
            Some(binding)
                if binding.admission_inode.is_some()
                    && marker.as_deref() == Some(WRITER_MARKER) =>
            {
                (
                    "writer_unanchored",
                    Some(
                        "Stop all controllers and native work; explicit recover adopt requires the intact writer and matching admission anchor.",
                    ),
                )
            }
            Some(_) if marker.as_deref() == Some(WRITER_MARKER) => (
                "unanchored",
                Some(
                    "Stop all controllers and native work, then use explicit recover adopt to establish first-inode continuity; pre-adoption history is not proved.",
                ),
            ),
            Some(_) => (
                "authority_incomplete",
                Some(
                    "Established writer marker is missing or changed; authoritative recovery is required, not lock deletion or re-adoption.",
                ),
            ),
            None => (
                "unbound",
                Some(
                    "Explicit stopped recover adopt requires intact initialized journal and lane evidence.",
                ),
            ),
        };
        Ok(json!({"state":state,"recovery_prerequisite":prerequisite}))
    }

    pub(crate) fn continuity(&self) -> Result<()> {
        Self::continuity_in(
            &self.db,
            &self.binding,
            &self.writer_path,
            &self.database_file,
        )
    }

    fn continuity_in(
        db: &Connection,
        binding: &Option<(PathBuf, Binding)>,
        writer_path: &Option<(PathBuf, fs::Metadata)>,
        database_file: &Option<(PathBuf, fs::Metadata)>,
    ) -> Result<()> {
        migration::ensure_complete(db)?;
        if let Some((path, expected)) = database_file {
            lane_control::check_file_identity(path, expected)
                .context("bound journal continuity lost")?;
        }
        if let Some((path, expected)) = writer_path {
            lane_control::check_file_identity(path, expected)
                .context("writer lock inode changed; stopping authority")?;
        }
        if let Some((path, expected)) = binding {
            let current = binding_at(path)?.context("independent account binding disappeared")?;
            let (id, sequence): (String, i64) = db.query_row(
                "SELECT database_id,dispatch_sequence FROM authority WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if current.database_id != id
                || current.database_id != expected.database_id
                || current.dispatch_sequence > sequence
                || current.identity != expected.identity
                || current.dispatch_sequence < expected.dispatch_sequence
                || current.location != expected.location
                || current.writer_inode != expected.writer_inode
                || current.admission_inode != expected.admission_inode
            {
                bail!("account binding continuity lost");
            }
            let (writer, metadata) = writer_path
                .as_ref()
                .context("bound store lacks writer authority")?;
            expected.check_writer(writer, metadata)?;
            current.check_writer(writer, metadata)?;
            let admission_path = path.with_extension("admission");
            let admission_metadata = fs::symlink_metadata(&admission_path)?;
            expected.check_admission(&admission_path, &admission_metadata)?;
            current.check_admission(&admission_path, &admission_metadata)?;
            if read_private_bytes(writer, 64)?.as_deref() != Some(WRITER_MARKER) {
                bail!("permanent writer marker changed");
            }
            let disk = Path::new(&expected.location).join("state.sqlite3");
            let db_path: String = db.query_row(
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
        if version != CURRENT_JOURNAL_FORMAT {
            bail!("unsupported state schema; stop the runtime and use explicit migration");
        }
        let store = Self {
            db,
            binding: None,
            writer_path: None,
            database_file: None,
        };
        store.check_binding(config)?;
        validate_required_lane_state(&store.db)?;
        Ok(Some(store))
    }

    /// Unbound construction is only a unit-fixture convenience, not lifetime authority.
    #[cfg(test)]
    pub(crate) fn open(config: &Config) -> Result<Self> {
        Self::open_inner(config, None)
    }

    fn open_inner(
        config: &Config,
        authority: Option<((PathBuf, Binding), (PathBuf, fs::Metadata))>,
    ) -> Result<Self> {
        migration::ensure_no_pending(config)?;
        // Existing journals are inspected before WAL, DDL, normalization or any write.
        let existing = Self::read_only(config)?;
        if let Some(existing) = &existing {
            migration::ensure_complete(&existing.db)?;
            existing.check_config_identity(config)?;
            existing
                .database_identity()
                .context("journal authority is missing or malformed")?;
        }
        if let Some((binding, writer)) = &authority {
            let existing = existing
                .as_ref()
                .context("bound journal disappeared before open")?;
            let accepted = binding_at(&binding.0)?.context("independent binding disappeared")?;
            if accepted != binding.1 {
                bail!("account binding changed before writable open");
            }
            accepted.check_writer(&writer.0, &writer.1)?;
            let admission_path = binding.0.with_extension("admission");
            accepted.check_admission(&admission_path, &fs::symlink_metadata(&admission_path)?)?;
            existing.check_binding(config)?;
        }
        let fresh = existing.is_none();
        drop(existing);
        private_dir(&config.state_dir)?;
        let path = fs::canonicalize(&config.state_dir)?.join("state.sqlite3");
        let mut db = {
            let _opening = DATABASE_OPEN
                .lock()
                .map_err(|_| anyhow::anyhow!("database opening lock poisoned"))?;
            if fresh {
                prepare_database(&path)?;
            }
            Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        if !fresh {
            migration::ensure_complete(&db)?;
        }
        if let Some((binding, writer)) = &authority {
            binding.1.check_writer(&writer.0, &writer.1)?;
            let admission_path = binding.0.with_extension("admission");
            binding
                .1
                .check_admission(&admission_path, &fs::symlink_metadata(&admission_path)?)?;
        }
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        if fresh {
            let database_id: String =
                db.query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))?;
            let gates = lane_control::provision_unbound_lane_gates(config, &database_id)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            initialize_schema(&tx)?;
            tx.execute(
                "INSERT INTO control(singleton,paused,generation,identity,version) VALUES (1,1,0,?1,?2)",
                params![identity(config)?, CURRENT_JOURNAL_FORMAT],
            )?;
            tx.execute("INSERT INTO authority VALUES (1,?1,0)", [database_id])?;
            initialize_lane_state(&tx, &gates)?;
            tx.execute(
                "INSERT INTO events(at,code) VALUES (?1,'initialized_paused')",
                [now()],
            )?;
            tx.commit()?;
        }
        let metadata = fs::symlink_metadata(&path)?;
        let (binding, writer_path) = match authority {
            Some((binding, writer)) => (Some(binding), Some(writer)),
            None => (None, None),
        };
        let mut store = Self {
            db,
            binding,
            writer_path,
            database_file: Some((path, metadata)),
        };
        store.continuity()?;
        if !fresh {
            let tx = store
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            schema::initialize_query_indexes(&tx)?;
            Self::continuity_in(
                &tx,
                &store.binding,
                &store.writer_path,
                &store.database_file,
            )?;
            tx.commit()?;
        }
        Ok(store)
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
        // Retained unresolved native work stays busy independent of eligibility.
        let unresolved: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE state IN
            ('generating','model_unknown','generated','prepared','retry','dispatching','queued','unknown','included_pending','confirmed'))",
            [],
            |row| row.get(0),
        )?;
        if unresolved {
            return Ok(true);
        }
        // Reusable payloadless attempts use the canonical model retry assessment.
        let mut statement = self.db.prepare(
            "SELECT kind,work_key FROM operations
            WHERE state IN ('rejected','retry_model','superseded_model_unknown')
            AND payload IS NULL AND job_id IS NULL AND txid IS NULL",
        )?;
        let mut reusable: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        for row in statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (kind, key) = row?;
            reusable.insert((kind, key.to_lowercase()));
        }
        drop(statement);
        let at = now();
        for (kind, key) in reusable {
            let lane = match kind.as_str() {
                "answer" => LaneId::Answer,
                "judge" => LaneId::Judge,
                _ => continue,
            };
            if Self::model_retry_assessment_in(&self.db, lane, &key, config, at, None)?
                .retry_eligible
            {
                return Ok(true);
            }
        }
        Ok(false)
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
        self.continuity()?;
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
            tx.execute_batch("DELETE FROM lane_observations;
                UPDATE control SET generation=generation+1 WHERE singleton=1;
                UPDATE health_evidence SET hosted_identity_verified=NULL,epoch=NULL,first_observed_at=NULL,answered=NULL;
                DELETE FROM hosted_identity_evidence;
                UPDATE read_state SET in_flight=0,started_at=NULL,last_success_at=NULL,last_http_success_at=NULL;")?;
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
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        self.continuity()
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

    pub(crate) fn set_paused(
        &mut self,
        paused: bool,
        account: &AccountAdmissionGuard,
    ) -> Result<()> {
        self.check_pause_guard(account)?;
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        account.validated_binding()?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        Self::write_pause(&tx, paused)?;
        account.validated_binding()?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit().context(
            "global control commit uncertain; reread pause state and generation before retrying",
        )?;
        self.check_pause_guard(account)
            .and_then(|()| self.continuity())
            .context("global control commit uncertain; reread pause state and generation before retrying")
    }

    fn check_pause_guard(&self, account: &AccountAdmissionGuard) -> Result<()> {
        let (path, expected) = self
            .binding
            .as_ref()
            .context("global control requires bound authority")?;
        let accepted = account.validated_binding()?;
        if account.1.with_extension("binding") != *path || !expected.same_authority(&accepted) {
            bail!("global control guard differs from accepted account authority");
        }
        Ok(())
    }

    fn write_pause(tx: &Connection, paused: bool) -> Result<()> {
        tx.execute(
            "UPDATE control SET paused=?1,generation=generation+1 WHERE singleton=1",
            [paused],
        )?;
        tx.execute(
            "INSERT INTO events(at,code) VALUES (?1,?2)",
            params![now(), if paused { "paused" } else { "resumed" }],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn set_paused_unbound(&mut self, paused: bool) -> Result<()> {
        assert!(
            self.binding.is_none(),
            "bound fixtures must hold account admission"
        );
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::write_pause(&tx, paused)?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        self.continuity()
    }

    pub(crate) fn recover(&mut self) -> Result<()> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::recover_interrupted_model(&tx)?;
        tx.execute(
            "UPDATE read_state SET in_flight=0,finished_at=?1 WHERE in_flight!=0",
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
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        self.continuity()
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
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        self.continuity()?;
        Ok(count)
    }

    #[cfg(test)]
    fn begin(
        &mut self,
        kind: LaneId,
        key: &str,
        state: &str,
        request: &Value,
        control: Control,
        revision: &str,
    ) -> Result<Operation> {
        self.begin_linked(kind, key, (state, request), control, revision, None)
    }

    #[cfg(test)]
    fn begin_linked(
        &mut self,
        kind: LaneId,
        key: &str,
        intent: (&str, &Value),
        control: Control,
        revision: &str,
        retry: Option<(&Operation, bool)>,
    ) -> Result<Operation> {
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = Self::begin_linked_in(&tx, kind, key, intent, control, revision, retry)?;
        tx.commit()?;
        self.operation(id)?.context("durable operation missing")
    }

    fn begin_linked_in(
        tx: &Connection,
        kind: LaneId,
        key: &str,
        intent: (&str, &Value),
        control: Control,
        revision: &str,
        retry: Option<(&Operation, bool)>,
    ) -> Result<i64> {
        let (state, request) = intent;
        if !matches!(state, "generating" | "prepared") {
            bail!("invalid initial operation state");
        }
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
        let payload = (kind == LaneId::Mine && state == "prepared").then_some("{}");
        tx.execute("INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at,payload)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?7,?8)", params![kind.as_str(),key,state,serde_json::to_string(request)?,control.generation,revision,now(),payload])?;
        let id = tx.last_insert_rowid();
        if let Some((original, reuse)) = retry {
            if kind != LaneId::Answer || original.kind != LaneId::Answer {
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
                let (canonical_key, canonical_request): (String, String) = tx.query_row(
                    "SELECT work_key,request FROM operations WHERE id=?1",
                    [original.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if state != "prepared"
                    || key != canonical_key
                    || request != &serde_json::from_str::<Value>(&canonical_request)?
                {
                    bail!("captured retry requires matching complete answer");
                }
                tx.execute(
                    "UPDATE operations SET (work_key,request,payload,result)=
                    (SELECT work_key,request,payload,result FROM operations WHERE id=?1)
                    WHERE id=?2",
                    params![original.id, id],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO events(at,code,kind,operation_id) VALUES (?1,?2,?3,?4)",
            params![now(), state, kind.as_str(), id],
        )?;
        // Prepared intent alone proves no model capture. An explicit captured
        // retry retains the original capture time (including unknown), never now.
        let reused_model = retry
            .filter(|(_, reuse)| *reuse)
            .map(|(original, _)| original.id);
        tx.execute("INSERT INTO operation_timing(operation_id,retry_not_before,generation_started_at,model_captured_at)
            VALUES(?1,0,CASE WHEN ?2='generating' THEN ?3 END,
                (SELECT model_captured_at FROM operation_timing WHERE operation_id=?4))",
            params![id,state,now(),reused_model])?;
        Ok(id)
    }

    #[cfg(test)]
    fn save(&mut self, op: &Operation, event: &str) -> Result<()> {
        self.save_admitted(op, event, None)
    }

    #[cfg(test)]
    fn dispatch_intent(&mut self, op: &mut Operation, config: &Config) -> Result<bool> {
        let previous = op.state.clone();
        op.state = "dispatching".into();
        if !self.admission_allowed(config, op)? {
            op.state = previous;
            return Ok(false);
        }
        self.save_admitted(op, "dispatch_intent", Some(config))?;
        Ok(true)
    }

    #[cfg(test)]
    fn save_admitted(
        &mut self,
        op: &Operation,
        event: &str,
        config: Option<&Config>,
    ) -> Result<()> {
        self.continuity()?;
        let dispatch = op.state == "dispatching" && *op.persisted_state.borrow() != "dispatching";
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let binding = Self::save_transition_in(&tx, op, event, &op.state, config)?;
        tx.commit()?;
        Self::transition_committed(op, &op.state, binding);
        if dispatch {
            self.publish_dispatch_witness()?;
        }
        Ok(())
    }

    fn transition_committed(op: &Operation, state: &str, binding_revision: i64) {
        *op.persisted_state.borrow_mut() = state.to_owned();
        op.persisted_binding_revision.set(binding_revision);
    }

    fn publish_dispatch_witness(&mut self) -> Result<()> {
        self.continuity()?;
        let (_, sequence) = self.database_identity()?;
        if let Some((path, binding)) = &mut self.binding {
            binding.dispatch_sequence = sequence;
            write_binding(path, binding)?;
        }
        self.continuity()
    }

    fn save_transition_in(
        tx: &Connection,
        op: &Operation,
        event: &str,
        target_state: &str,
        config: Option<&Config>,
    ) -> Result<i64> {
        let predecessor = op.persisted_state.borrow().clone();
        let was_effect = matches!(
            predecessor.as_str(),
            "dispatching" | "queued" | "unknown" | "included_pending"
        );
        if matches!(target_state, "queued" | "unknown" | "included_pending") && !was_effect {
            bail!("effect transition requires durable dispatch intent");
        }
        // Only local static codes enter the public event stream.
        if !event.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            bail!("invalid local event code");
        }
        if target_state == "dispatching" && predecessor != "dispatching" {
            if !matches!(predecessor.as_str(), "generated" | "prepared" | "retry") {
                bail!("invalid dispatch predecessor");
            }
            let decision = if let Some(config) = config {
                if config.mode(op.kind) != Mode::Active {
                    bail!("dispatch capability is not active");
                }
                Some(
                    Self::risk_decision(tx, config, op)?
                        .context("participation admission closed")?,
                )
            } else {
                #[cfg(not(test))]
                bail!("dispatch requires guarded participation admission");
                #[cfg(test)]
                {
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
                }
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
            if let Some(config) = config
                && op.kind == LaneId::Mine
                && !config.capabilities.mine.schedule.each_epoch
            {
                // Unsent drafts can fail fresh challenge validation. Consume the
                // interval only with their first durable dispatch, not a retry.
                tx.execute(
                    "INSERT INTO schedule(kind,next_at)
                    SELECT 'mine:participation',?1 WHERE NOT EXISTS(
                        SELECT 1 FROM operation_evidence
                        WHERE operation_id=?2 AND dispatch_sequence IS NOT NULL)
                    ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at",
                    params![
                        not_before(config.capabilities.mine.schedule.interval_seconds),
                        op.id
                    ],
                )?;
            }
            tx.execute("INSERT INTO operation_evidence(operation_id,dispatch_sequence,blocked_since)
                VALUES (?1,(SELECT dispatch_sequence FROM authority WHERE singleton=1),?2)
                ON CONFLICT(operation_id) DO UPDATE SET dispatch_sequence=excluded.dispatch_sequence,
                blocked_since=excluded.blocked_since", params![op.id,now()])?;
            // Local polling cadence is not a server-imposed admission minimum.
            // Keep an explicit zero so reopening cannot inherit op.next_at.
            tx.execute(
                "INSERT OR IGNORE INTO operation_timing(operation_id,retry_not_before) VALUES (?1,0)",
                [op.id],
            )?;
            if let (Some(config), Some(decision)) = (config, decision) {
                let lane_revision = config.lane_revision(op.kind)?;
                let participation = if op.kind == LaneId::Answer {
                    serde_json::to_value(config.capabilities.answer.participation)?
                } else {
                    serde_json::to_value(config.participation(op.kind))?
                };
                if decision.accounting.total > 0
                    || decision.retry_of.is_some()
                    || !decision.accounting.history_evaluated
                {
                    // A skipped historical scan must not present zero as a
                    // measured count: null counts with history_evaluated=false
                    // say the scan did not run and did not limit this dispatch.
                    let evaluated = decision.accounting.history_evaluated;
                    let own_count = evaluated.then(|| decision.accounting.active());
                    let account_unresolved = evaluated.then_some(decision.accounting.total);
                    tx.execute(
                        "INSERT INTO risk_admissions
                        VALUES ((SELECT dispatch_sequence FROM authority WHERE singleton=1),?1,?2,?3,?4,?5,?6,?7)",
                        params![op.id,serde_json::to_string(&json!({"schema_version":2,"lane":op.kind,
                            "participation":participation,"history_evaluated":evaluated,
                            "own_count":own_count,
                            "own_limit":config.participation(op.kind).max_unresolved_operations,
                            "account_unresolved":account_unresolved,
                            "blocker_ids_truncated":decision.accounting.total>decision.accounting.blockers.len() as u64}))?,lane_revision,
                            serde_json::to_string(&decision.accounting.blockers)?,decision.retry_of,decision.grant,now()],
                    )?;
                    // Snapshots record evaluated counts only. A skipped scan
                    // reports zeros that would fabricate absence of history.
                    if decision.accounting.history_evaluated
                        && op.kind == LaneId::Answer
                        && config
                            .capabilities
                            .answer
                            .participation
                            .historical_unknown_answer_capacity
                            == HistoricalAnswerCapacity::AcceptedLinked
                    {
                        let revision = Self::capture_historical_revision(tx)?;
                        tx.execute(
                            "INSERT INTO risk_accounting_snapshots VALUES
                             ((SELECT dispatch_sequence FROM authority WHERE singleton=1),?1,?2,?3,?4)",
                            params![revision,decision.accounting.own_total,
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
                            AND kind=?3 AND generation=(SELECT generation FROM control WHERE singleton=1)
                            AND lane_control_revision=(SELECT control_revision FROM lane_control WHERE lane=manual_grants.kind)
                            AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=?2)",
                            params![op.id,grant,op.kind.as_str()],
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
                captured["dispatch_policy"] = json!({"schema_version":2,"lane":op.kind,
                    "participation":participation,"revision":lane_revision,
                    "http_seconds":config.timeouts(op.kind).http_seconds,
                    "mine_each_epoch":config.capabilities.mine.schedule.each_epoch});
                tx.execute(
                    "INSERT INTO operation_evidence(operation_id,policy,http_deadline) VALUES (?1,?2,?3)
                    ON CONFLICT(operation_id) DO UPDATE SET policy=excluded.policy,http_deadline=excluded.http_deadline",
                    params![op.id,serde_json::to_string(&captured)?,not_before(config.timeouts(op.kind).http_seconds)],
                )?;
            }
        }
        let changed = tx.execute(
            "UPDATE operations SET state=?1,result=?2,payload=?3,job_id=?4,txid=?5,next_at=?6,
            binding_revision=binding_revision+CASE WHEN job_id IS NOT ?4 OR txid IS NOT ?5
                OR (state IN ('queued','unknown','included_pending','confirmed')) !=
                   (?1 IN ('queued','unknown','included_pending','confirmed')) THEN 1 ELSE 0 END,
            updated_at=CASE WHEN state!=?1 THEN ?7 ELSE updated_at END
            WHERE id=?8 AND state=?9 AND binding_revision=?10",
            params![
                target_state,
                op.result.as_ref().map(serde_json::to_string).transpose()?,
                op.payload.as_ref().map(serde_json::to_string).transpose()?,
                op.job_id,
                op.txid,
                op.next_at,
                now(),
                op.id,
                predecessor,
                op.persisted_binding_revision.get()
            ],
        )?;
        if changed != 1 {
            bail!("stale operation transition");
        }
        let binding_revision: i64 = tx.query_row(
            "SELECT binding_revision FROM operations WHERE id=?1",
            [op.id],
            |r| r.get(0),
        )?;
        if binding_revision != op.persisted_binding_revision.get() {
            tx.execute(
                "UPDATE read_state SET retired=1,in_flight=0
                WHERE operation_id=?1 AND binding_revision!=?2 AND retired=0",
                params![op.id, binding_revision],
            )?;
        }
        if predecessor != target_state {
            if matches!(
                predecessor.as_str(),
                "dispatching" | "queued" | "unknown" | "included_pending"
            ) && !matches!(
                target_state,
                "dispatching" | "queued" | "unknown" | "included_pending"
            ) {
                tx.execute(
                    "INSERT INTO operation_evidence(operation_id,resolution) VALUES (?1,?2)
                    ON CONFLICT(operation_id) DO UPDATE SET resolution=excluded.resolution",
                    params![
                        op.id,
                        serde_json::to_string(
                            &json!({"source":"bound_protocol_result","state":target_state,"at":now()})
                        )?
                    ],
                )?;
            }
            tx.execute(
                "INSERT INTO events(at,code,kind,operation_id) VALUES (?1,?2,?3,?4)",
                params![now(), event, op.kind.as_str(), op.id],
            )?;
            let timing = match target_state {
                "generating" => Some("generation_started_at"),
                "generated" => Some("model_captured_at"),
                "queued" => Some("queued_since"),
                "dispatching" => Some("dispatch_started_at"),
                _ => None,
            };
            if let Some(column) = timing {
                tx.execute(&format!("INSERT INTO operation_timing(operation_id,retry_not_before,{column}) VALUES(?1,0,?2)
                    ON CONFLICT(operation_id) DO UPDATE SET {column}=excluded.{column}"), params![op.id,now()])?;
            }
        }
        Self::capture_work_revision(tx)?;
        tx.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )?;
        Ok(binding_revision)
    }

    pub(crate) fn event(&mut self, code: &str, kind: Option<LaneId>) -> Result<()> {
        self.continuity()?;
        if !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            bail!("invalid local event code");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO events(at,code,kind) VALUES (?1,?2,?3)",
            params![now(), code, kind.map(|k| k.as_str())],
        )?;
        if matches!(code, "runtime_stopped" | "controller_running") {
            tx.execute(
                "UPDATE runtime_state SET controller_stopped=?1 WHERE singleton=1",
                [code == "runtime_stopped"],
            )?;
        }
        Self::capture_work_revision(&tx)?;
        tx.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn operation(&self, id: i64) -> Result<Option<Operation>> {
        let row = self
            .db
            .query_row(
                "SELECT id,kind,work_key,state,request,result,payload,job_id,txid,next_at,generation,binding_revision
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
                        r.get::<_, i64>(11)?,
                    ))
                },
            )
            .optional()?;
        row.map(|r| {
            Ok(Operation {
                id: r.0,
                kind: match r.1.as_str() {
                    "answer" => LaneId::Answer,
                    "judge" => LaneId::Judge,
                    "mine" => LaneId::Mine,
                    _ => bail!("invalid operation kind in state"),
                },
                key: r.2,
                persisted_state: std::cell::RefCell::new(r.3.clone()),
                generation: r.10,
                binding_revision: r.11,
                persisted_binding_revision: std::cell::Cell::new(r.11),
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

    /// Shared by preparation, transactional admission, and read-only status.
    /// Stream narrow evidence columns; never load historical operation payloads.
    /// Explicit unbounded participation-first skips the cumulative historical
    /// scan for fresh work; the skip path keeps one local effect, server
    /// floors, and the same-work retry ceiling on indexed point lookups.
    fn uncertainty_accounting(
        db: &Connection,
        config: &Config,
        kind: LaneId,
        excluding: Option<i64>,
        retry_of: Option<i64>,
        capture_blockers: bool,
    ) -> Result<UncertaintyAccounting> {
        let policy = config.participation(kind);
        if policy.mode == ParticipationMode::ParticipationFirst
            && policy.max_unresolved_operations == CountLimit::Unbounded
        {
            return accounting::uncertainty_accounting_unbounded(
                db, config, kind, excluding, retry_of,
            );
        }
        accounting::uncertainty_accounting(db, config, kind, excluding, retry_of, capture_blockers)
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
        Self::risk_decision_at(db, config, op, AdmissionCutoff::current())
    }

    fn risk_decision_at(
        db: &Connection,
        config: &Config,
        op: &Operation,
        cutoff: AdmissionCutoff,
    ) -> Result<Option<RiskDecision>> {
        accounting::risk_decision_at(db, config, op, cutoff)
    }

    pub(crate) fn admission_allowed(&self, config: &Config, op: &Operation) -> Result<bool> {
        self.admission_allowed_at(config, op, AdmissionCutoff::current())
    }

    pub(crate) fn admission_cutoff(&self) -> Result<AdmissionCutoff> {
        Ok(self.db.query_row(
            "SELECT CAST(strftime('%s','now') AS INTEGER),COALESCE(MAX(id),0) FROM manual_grants",
            [],
            |r| {
                Ok(AdmissionCutoff {
                    at: r.get(0)?,
                    grant_id: r.get(1)?,
                })
            },
        )?)
    }

    pub(crate) fn operation_ready_at(&self, id: i64) -> Result<i64> {
        Ok(self.db.query_row(
            "SELECT CASE WHEN next_at>0 THEN next_at ELSE created_at END
            FROM operations WHERE id=?1",
            [id],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn admission_allowed_at(
        &self,
        config: &Config,
        op: &Operation,
        cutoff: AdmissionCutoff,
    ) -> Result<bool> {
        let control = self.control()?;
        Ok(!control.paused
            && control.generation == op.generation
            && config.mode(op.kind) == Mode::Active
            && op.next_at <= cutoff.at
            && Self::risk_decision_at(&self.db, config, op, cutoff)?.is_some())
    }

    pub(crate) fn authorize(&mut self, config: &Config, epoch: u64, kind: LaneId) -> Result<Value> {
        self.continuity()?;
        if config.participation(kind).mode != ParticipationMode::Manual
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
        let lane_control = Self::lane_control_in(&tx, kind)?;
        if lane_control.paused {
            bail!("manual authorization requires resumed lane control");
        }
        let fenced: bool = tx.query_row(
            "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)
            OR EXISTS(SELECT 1 FROM hosted_identity_evidence WHERE rejection IS NOT NULL)",
            [],
            |r| r.get(0),
        )?;
        if fenced {
            bail!("manual authorization blocked by shared authority");
        }
        let retry_of: Option<i64> = if kind == LaneId::Answer {
            tx.query_row(
                "SELECT id FROM operations WHERE kind='answer' AND work_key LIKE ?1
                AND state IN ('queued','unknown') AND txid IS NULL AND payload IS NOT NULL
                ORDER BY id DESC LIMIT 1",
                [format!("{epoch}:%")],
                |r| r.get(0),
            )
            .optional()?
        } else {
            None
        };
        let accounting = Self::uncertainty_accounting(&tx, config, kind, None, retry_of, true)?;
        if let Some((reason, _)) =
            Self::account_blocker(config.participation(kind), &accounting, true)
        {
            bail!("manual authorization blocked: {reason}");
        }
        let (attempts,accepted,uncertain): (u32,bool,bool) = tx.query_row(
            "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0),
            COALESCE(MAX(o.state IN ('dispatching','queued','unknown','included_pending')),0)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind=?1 AND o.work_key LIKE ?2
            AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
            params![kind.as_str(),format!("{epoch}:%")], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        if kind == LaneId::Answer
            && (accepted
                || attempts
                    >= config
                        .capabilities
                        .answer
                        .participation
                        .max_answer_attempts_per_epoch
                || (uncertain
                    && !config
                        .capabilities
                        .answer
                        .participation
                        .retry_uncertain_answers))
        {
            bail!("manual authorization cannot authorize a duplicate or exhausted answer attempt");
        }
        if kind == LaneId::Mine && config.capabilities.mine.schedule.each_epoch && attempts > 0 {
            bail!("manual authorization cannot authorize another mine in the same epoch");
        }
        let pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind=?2 AND generation=?3
            AND lane_control_revision=?4 AND consumed_by IS NULL
            AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
            params![i64::try_from(epoch)?,kind.as_str(),generation,lane_control.control_revision], |r| r.get(0),
        )?;
        if pending {
            bail!("a pending grant already exists for this epoch, kind and generation");
        }
        tx.execute(
            "INSERT INTO manual_grants(epoch,kind,generation,created_at,lane_control_revision) VALUES (?1,?2,?3,?4,?5)",
            params![i64::try_from(epoch)?, kind.as_str(), generation, now(), lane_control.control_revision],
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

    pub(crate) fn answer_retry_allowed_at(
        &self,
        config: &Config,
        original: &Operation,
        cutoff: AdmissionCutoff,
    ) -> Result<bool> {
        Ok(self
            .answer_retry_blocker_at(config, original, cutoff)?
            .is_none())
    }

    fn answer_retry_blocker(
        &self,
        config: &Config,
        original: &Operation,
    ) -> Result<Option<(&'static str, Option<i64>)>> {
        self.answer_retry_blocker_at(config, original, AdmissionCutoff::current())
    }

    fn answer_retry_blocker_at(
        &self,
        config: &Config,
        original: &Operation,
        cutoff: AdmissionCutoff,
    ) -> Result<Option<(&'static str, Option<i64>)>> {
        let epoch = original.request["solver"]["epoch"]
            .as_u64()
            .context("answer epoch missing")?;
        if let Some(blocker) = Self::answer_retry_policy_blocker(&self.db, config, epoch, None)? {
            return Ok(Some((blocker, None)));
        }
        let accounting = Self::uncertainty_accounting(
            &self.db,
            config,
            LaneId::Answer,
            None,
            Some(original.id),
            false,
        )?;
        self.uncertainty_blocker_with_at(config, LaneId::Answer, Some(epoch), &accounting, cutoff)
    }

    // Domain retry policy is shared by preparation and transactional admission.
    fn answer_retry_policy_blocker(
        db: &Connection,
        config: &Config,
        epoch: u64,
        reusing: Option<i64>,
    ) -> Result<Option<&'static str>> {
        if config.participation(LaneId::Answer).mode == ParticipationMode::Strict {
            return Ok(Some("account_uncertainty"));
        }
        if !config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers
        {
            return Ok(Some("uncertain_retry_disabled"));
        }
        if db.query_row("SELECT paused FROM control WHERE singleton=1", [], |r| {
            r.get(0)
        })? {
            return Ok(Some("admission_paused"));
        }
        if config.mode(LaneId::Answer) != Mode::Active {
            return Ok(Some("capability_not_active"));
        }
        let (attempts,accepted): (u32,bool) = db.query_row(
            "SELECT COUNT(CASE WHEN o.id!=COALESCE(?2,-1) THEN 1 END),
            COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind='answer' AND o.work_key>=?1 AND o.work_key<?3
            AND (e.dispatch_sequence IS NOT NULL OR o.job_id IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final','refused'))",
            params![format!("{epoch}:"),reusing,format!("{epoch};")], |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        if accepted {
            return Ok(Some("answer_already_accepted"));
        }
        if attempts
            >= config
                .capabilities
                .answer
                .participation
                .max_answer_attempts_per_epoch
        {
            return Ok(Some("answer_attempt_budget_exhausted"));
        }
        Ok(None)
    }

    #[cfg(test)]
    fn uncertainty_open(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
        retry_of: Option<i64>,
    ) -> Result<bool> {
        let accounting =
            Self::uncertainty_accounting(&self.db, config, kind, None, retry_of, false)?;
        Ok(self
            .uncertainty_blocker_with(config, kind, epoch, &accounting)?
            .is_none())
    }

    fn manual_authorized(&self, kind: LaneId, epoch: Option<u64>) -> Result<Option<bool>> {
        self.manual_authorized_at(kind, epoch, AdmissionCutoff::current())
    }

    fn manual_authorized_at(
        &self,
        kind: LaneId,
        epoch: Option<u64>,
        cutoff: AdmissionCutoff,
    ) -> Result<Option<bool>> {
        let Some(epoch) = epoch else { return Ok(None) };
        if !self.has_table("manual_grants")? || !self.has_table("manual_grant_revocations")? {
            return Ok(None);
        }
        Ok(Some(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind=?2 AND generation=?3
             AND id<=?4 AND created_at<=?5 AND consumed_by IS NULL
             AND lane_control_revision=(SELECT control_revision FROM lane_control WHERE lane=manual_grants.kind AND paused=0)
             AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
            params![i64::try_from(epoch)?,kind.as_str(),self.control()?.generation,cutoff.grant_id,cutoff.at],
            |r| r.get(0),
        )?))
    }

    fn account_blocker(
        policy: Participation,
        accounting: &UncertaintyAccounting,
        granted: bool,
    ) -> Option<(&'static str, Option<i64>)> {
        Self::account_blocker_at(policy, accounting, granted, AdmissionCutoff::current())
    }

    fn account_blocker_at(
        policy: Participation,
        accounting: &UncertaintyAccounting,
        granted: bool,
        cutoff: AdmissionCutoff,
    ) -> Option<(&'static str, Option<i64>)> {
        if accounting.writing {
            return Some(("effect_in_flight", None));
        }
        if accounting.retry_origin_floor > cutoff.at {
            return Some((
                "operation_retry_minimum",
                Some(accounting.retry_origin_floor),
            ));
        }
        if accounting.retry_not_before > cutoff.at {
            return Some((
                if accounting.legacy_floor {
                    "retained_legacy_floor"
                } else {
                    "shared_server_restriction"
                },
                Some(accounting.retry_not_before),
            ));
        }
        // Unbounded participation-first never charges cumulative history against
        // distinct fresh work: allows() admits any active count, while a finite
        // cap keeps the previous active()+1<=limit admission boundary.
        if !policy.max_unresolved_operations.allows(accounting.active()) {
            return Some(("lane_unresolved_capacity", None));
        }
        // The same-work retry ceiling binds even when cumulative history was
        // not evaluated: a skipped scan always reports total zero, so the
        // grace must be checked before the empty-history fast path. Evaluated
        // histories keep the previous strict-first precedence below.
        if !accounting.history_evaluated && accounting.retry_grace_until > cutoff.at {
            return Some((
                "uncertain_answer_retry_delay",
                Some(accounting.retry_grace_until),
            ));
        }
        if accounting.total == 0 {
            return None;
        }
        if policy.mode == ParticipationMode::Strict {
            return Some(("account_uncertainty", None));
        }
        if accounting.retry_grace_until > cutoff.at {
            return Some((
                "uncertain_answer_retry_delay",
                Some(accounting.retry_grace_until),
            ));
        }
        if policy.mode == ParticipationMode::Manual {
            if !granted {
                return Some(("manual_authorization_required", None));
            }
        } else if policy.max_unresolved_operations.finite().is_some()
            && accounting.grace_until > cutoff.at
        {
            return Some(("account_uncertainty_grace", Some(accounting.grace_until)));
        }
        None
    }

    fn uncertainty_blocker_with(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
        accounting: &UncertaintyAccounting,
    ) -> Result<Option<(&'static str, Option<i64>)>> {
        self.uncertainty_blocker_with_at(
            config,
            kind,
            epoch,
            accounting,
            AdmissionCutoff::current(),
        )
    }

    fn uncertainty_blocker_with_at(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
        accounting: &UncertaintyAccounting,
        cutoff: AdmissionCutoff,
    ) -> Result<Option<(&'static str, Option<i64>)>> {
        Ok(Self::account_blocker_at(
            config.participation(kind),
            accounting,
            self.manual_authorized_at(kind, epoch, cutoff)?
                .unwrap_or(false),
            cutoff,
        ))
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
            WHERE o.kind='mine' AND o.work_key>=?1 AND o.work_key<?3 AND (?2 IS NULL OR o.id!=?2)
            AND (e.dispatch_sequence IS NOT NULL OR o.state IN
            ('dispatching','retry','queued','unknown','included_pending','confirmed','final','completed','rejected','stale','refused')
            OR (o.state='discarded' AND e.operation_id IS NULL AND
                (EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code='dispatch_intent')
                OR NOT EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code='prepared')))))",
            params![format!("{epoch}:"),excluding,format!("{epoch};")], |r| r.get(0),
        )?)
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

    pub(crate) fn preparation(&self, kind: LaneId) -> Result<Option<Operation>> {
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

    pub(crate) fn record_evidence(&self, id: i64, evidence: &Value) -> Result<()> {
        self.continuity()?;
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
        // Request-bound restrictions are ingested before this local evidence CAS.
        let tx = self.db.unchecked_transaction()?;
        self.record_candidates(id, candidates)?;
        self.record_evidence(id, evidence)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn record_candidates(&self, id: i64, candidates: &Value) -> Result<()> {
        self.continuity()?;
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

    pub(crate) fn attempt_count(&self, kind: LaneId, key: &str) -> Result<u32> {
        Ok(self.db.query_row(
            "SELECT COUNT(*) FROM operations WHERE kind=?1 AND work_key=?2 COLLATE NOCASE",
            params![kind.as_str(), key],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn attempted(&self, kind: LaneId, key: &str) -> Result<bool> {
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE kind=?1 AND work_key=?2 COLLATE NOCASE AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model','retry_model','superseded_model_unknown'))",
            params![kind.as_str(),key], |r| r.get(0))?)
    }

    pub(crate) fn answer_epoch_attempted(&self, epoch: u64) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE kind='answer' AND work_key LIKE ?1
            AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model','retry_model','superseded_model_unknown'))",
            [format!("{epoch}:%")],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn next_at(&self, kind: LaneId) -> Result<i64> {
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
    pub(crate) fn defer(&self, kind: LaneId, seconds: u64) -> Result<()> {
        self.continuity()?;
        self.db.execute("INSERT INTO schedule(kind,next_at) VALUES (?1,?2) ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at",
            params![kind.as_str(),not_before(seconds)])?;
        Ok(())
    }

    pub(crate) fn judge_inventory_offset(&self) -> Result<u64> {
        self.db
            .query_row(
                "SELECT cursor FROM schedule WHERE kind='judge:inventory'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .map(|cursor| cursor.parse().context("invalid judge inventory cursor"))
            .transpose()
            .map(|cursor| cursor.unwrap_or(0))
    }

    pub(crate) fn set_judge_inventory_offset(&self, offset: u64) -> Result<()> {
        self.continuity()?;
        self.db.execute(
            "INSERT INTO schedule(kind,next_at,cursor) VALUES ('judge:inventory',0,?1)
             ON CONFLICT(kind) DO UPDATE SET cursor=excluded.cursor
             WHERE schedule.cursor IS NOT excluded.cursor",
            [offset.to_string()],
        )?;
        Ok(())
    }

    pub(crate) fn participation_next_at(&self, kind: LaneId) -> Result<i64> {
        Ok(self
            .db
            .query_row(
                "SELECT next_at FROM schedule WHERE kind=?1",
                [format!("{}:participation", kind.as_str())],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    fn capture_work_revision(db: &Connection) -> Result<()> {
        db.execute("UPDATE control SET work_revision=MAX(work_revision,
            COALESCE((SELECT MAX(id) FROM events WHERE operation_id IS NOT NULL),0)) WHERE singleton=1", [])?;
        Ok(())
    }

    pub(crate) fn work_revision(&self) -> Result<i64> {
        Ok(self.db.query_row(
            "SELECT MAX(work_revision,
            COALESCE((SELECT MAX(id) FROM events WHERE operation_id IS NOT NULL),0))
            FROM control WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn defer_until(&self, kind: LaneId, deadline: i64) -> Result<()> {
        self.continuity()?;
        self.db.execute(
            "INSERT INTO schedule(kind,next_at) VALUES (?1,?2)
            ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at",
            params![kind.as_str(), deadline],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn record_assignment_selection(
        &self,
        revision: &str,
        generation: i64,
        observed_count: usize,
        inventory_complete: bool,
        eligible: bool,
    ) -> Result<()> {
        self.db
            .execute("INSERT OR IGNORE INTO runtime_authority VALUES(1,0)", [])?;
        let authority_epoch = self.db.query_row(
            "SELECT authority_epoch FROM runtime_authority WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let stamp = AdmissionStampSnapshot {
            account_generation: generation,
            lane_control_revision: self.lane_control(LaneId::Judge)?.control_revision,
            authority_epoch,
            lane_config_revision: revision.to_owned(),
        };
        self.record_lane_participation(
            LaneId::Judge,
            &stamp,
            &json!({
            "source":"validated_assignment_inventory","observed_at":now(),"valid_until":now()+60,
            "completeness":if inventory_complete{"complete"}else{"bounded_partial"},
            "observed_opportunities":observed_count,"eligible_candidates":u64::from(eligible),
            "locally_judgeable":eligible,"assessment_reason":null,
            "assessment_creates_model_work":false,"outcome":"unobserved"}),
        )
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
        let mut policy = json!({"schema_version":2,"capabilities":config.capabilities,
            "identity":config.identity,"runtime":config.runtime,"build":crate::runtime::build_info()});
        let mut revisions = serde_json::Map::new();
        for lane in LaneId::ALL {
            revisions.insert(
                lane.as_str().into(),
                Value::String(config.lane_revision(lane)?),
            );
        }
        policy["lane_revisions"] = Value::Object(revisions);
        tx.execute("INSERT INTO runtime_policy VALUES (1,?1) ON CONFLICT(singleton) DO UPDATE SET policy=excluded.policy",
            [serde_json::to_string(&policy)?])?;
        tx.execute(
            "INSERT INTO runtime_state(singleton,effective_revision,reload_blocked,capabilities,observed_at,controller_stopped)
             VALUES (1,?1,?2,?3,?4,0) ON CONFLICT(singleton) DO UPDATE SET
            effective_revision=excluded.effective_revision,reload_blocked=excluded.reload_blocked,
            capabilities=excluded.capabilities,observed_at=excluded.observed_at,controller_stopped=0",
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
        self.continuity()?;
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
        self.read_finished(&ReadKey::Identity, status, category)?;
        Self::write_identity_outcome(&tx, outcome)?;
        if outcome == HostedIdentityOutcome::Verified {
            self.reset_read_in(&tx, &ReadKey::Identity)?;
        } else {
            self.fail_read_in(&tx, &ReadKey::Identity, retry.0, retry.1, retry.2, minimum)?;
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
                    (SELECT last_success_at FROM read_state WHERE owner='account' AND purpose='identity' AND resource='identity'
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

    pub(crate) fn identity_refresh_needed(&self) -> Result<bool> {
        Ok(self
            .db
            .query_row(
                "SELECT rejection IS NULL AND status IN
                 ('legacy_unknown','unavailable','invalid_response')
                 FROM hosted_identity_evidence WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(true))
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
        let last_verified_at: Option<i64> = if legacy == Some(true) && has_table("read_state")? {
            db.query_row(
                    "SELECT last_success_at FROM read_state WHERE owner='account' AND purpose='identity' AND resource='identity'",
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
        self.continuity()?;
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
        let mut statement = self.db.prepare("SELECT t.operation_id,t.generation_started_at,t.model_captured_at,t.queued_since,t.dispatch_started_at
            FROM operations o JOIN operation_timing t ON t.operation_id=o.id
            WHERE o.state IN ('generating','generated','prepared','dispatching','queued','unknown','included_pending')")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let entry = evidence.entry(row.get(0)?).or_default();
            entry.generating = row.get::<_, Option<i64>>(1)?.or(entry.generating);
            entry.captured = row.get::<_, Option<i64>>(2)?.or(entry.captured);
            entry.queued = row.get::<_, Option<i64>>(3)?.or(entry.queued);
            entry.dispatch = row.get::<_, Option<i64>>(4)?.or(entry.dispatch);
        }
        Ok(evidence)
    }

    pub(crate) fn operation_poll_timing(&self, id: i64) -> Result<(Option<i64>, i64)> {
        let (queued_since, minimum): (Option<i64>, i64) = self.db.query_row(
            "SELECT
             COALESCE((SELECT queued_since FROM operation_timing WHERE operation_id=o.id AND o.state='queued'),
              (SELECT at FROM
              (SELECT id,operation_id,code,at FROM events ORDER BY id DESC LIMIT 2000)
              WHERE operation_id=o.id AND o.state='queued'
              AND code IN ('submission_queued','job_pending') ORDER BY id DESC LIMIT 1)),
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
        let observation = if exists("read_state")? {
            db.query_row(
                "SELECT in_flight,started_at,finished_at,last_http_success_at,last_success_at,
                 last_failure_at,failure_category,status,local_next_at,server_not_before,
                 retained_conservative_floor FROM read_state WHERE owner='account' AND purpose='identity' AND resource='identity'",
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
                "SELECT failures,MAX(local_next_at,server_not_before,retained_conservative_floor)
                 FROM read_state WHERE owner='account' AND purpose='identity' AND resource='identity'",
                [],
                |row| Ok(json!({"failures":row.get::<_,i64>(0)?,"next_at":row.get::<_,i64>(1)?})),
            )
            .optional()?
            .unwrap_or(Value::Null);
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
                    if e.route != LaneId::Mine && e.reason == "proven_not_accepted" =>
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
        let policy = if self.schema_version()? == CURRENT_JOURNAL_FORMAT {
            self.db.query_row("SELECT policy,evidence,dispatch_sequence,blocked_since,resolution FROM operation_evidence WHERE operation_id=?1",
                [id], |r| Ok(json!({"captured_policy":r.get::<_,Option<String>>(0)?,
                    "evidence":r.get::<_,Option<String>>(1)?,"dispatch_sequence":r.get::<_,Option<i64>>(2)?,
                    "blocked_since":r.get::<_,Option<i64>>(3)?,"resolution":r.get::<_,Option<String>>(4)?}))).optional()?
        } else {
            None
        };
        let candidates = if self.schema_version()? == CURRENT_JOURNAL_FORMAT {
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
                        "own_charged_count":total-exempt,"blocker_ids_scope":"account_uncertainty",
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
        kind: Option<LaneId>,
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
        let (evidence_columns, evidence_join, model_column) =
            if self.has_table("operation_evidence")? {
                (
                    "e.blocked_since,e.model_deadline,e.http_deadline",
                    "LEFT JOIN operation_evidence e ON e.operation_id=o.id",
                    "e.model_attempt",
                )
            } else {
                ("NULL,NULL,NULL", "", "NULL")
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
                o.job_id IS NOT NULL,o.txid IS NOT NULL,{link_columns},{evidence_columns},{timing_column},{model_column}
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
            }),r.get::<_,String>(3)?,r.get::<_,Option<String>>(16)?)),
        )?;
        let mut operations = Vec::with_capacity(limit.min(100));
        let mut more = false;
        for row in rows {
            let (mut operation, request, model_attempt) = row?;
            if operations.len() == limit {
                more = true;
                break;
            }
            let request: Value = serde_json::from_str(&request)?;
            operation["model_attempt"] = model_attempt
                .map(|value| serde_json::from_str::<Value>(&value))
                .transpose()?
                .unwrap_or(Value::Null);
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
            "SELECT g.id,g.epoch,g.kind,g.generation,g.created_at,g.consumed_by,{revoked_column},
                g.lane_control_revision,COALESCE(g.lane_control_revision=l.control_revision,0)
            FROM manual_grants g LEFT JOIN lane_control l ON l.lane=g.kind {revoked_join}
            WHERE (?1 IS NULL OR g.id<?1) ORDER BY g.id DESC LIMIT ?2",
        ))?;
        let mut grants = statement.query_map(params![before,(limit+1) as i64], |r| {
            let generation: i64 = r.get(3)?;
            let consumed_by: Option<i64> = r.get(5)?;
            let revoked_at: Option<i64> = r.get(6)?;
            let current_lane_control: bool = r.get(8)?;
            Ok(json!({"grant_id":r.get::<_,i64>(0)?,"epoch":r.get::<_,u64>(1)?,
                "kind":r.get::<_,String>(2)?,"generation":generation,"created_at":r.get::<_,i64>(4)?,
                "consumed_by":consumed_by,"revoked_at":revoked_at,
                "state":if revoked_at.is_some() {"revoked"} else if consumed_by.is_some() {"consumed"}
                    else if generation!=control.generation || !current_lane_control {"expired"} else {"pending"},
                "lane_control_revision":r.get::<_,Option<i64>>(7)?,"current_lane_control":current_lane_control,
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
        let opened = Self::read_only(config).map_err(|error| {
            if cursor.and_then(|cursor| cursor.journal.as_ref()).is_some()
                && error.downcast_ref::<LaneControlError>().is_some()
            {
                error.context(EventCursorError::Replaced)
            } else {
                error
            }
        })?;
        let Some(store) = opened else {
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

    // Explicit retained legacy minima for repair/admission fixtures only.
    impl Store {
        fn record_retry_minimum(&self, id: i64, seconds: u64) -> Result<()> {
            self.record_retry_deadline(id, not_before(seconds))
        }
        fn record_retry_deadline(&self, id: i64, deadline: i64) -> Result<()> {
            self.db.execute("INSERT INTO operation_timing(operation_id,retry_not_before) VALUES(?1,?2)
                ON CONFLICT(operation_id) DO UPDATE SET retry_not_before=MAX(retry_not_before,excluded.retry_not_before)",
                params![id,deadline])?;
            Ok(())
        }
    }

    fn refusal_evidence(kind: LaneId, status: u16, category: Option<&str>) -> Value {
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
        store
            .set_paused(false, &AccountAdmissionGuard::acquire(&config).unwrap())
            .unwrap();
        for epoch in 1..=3 {
            let op = prepared_epoch(&mut store, LaneId::Judge, epoch, "historical");
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
        store
            .set_paused(true, &AccountAdmissionGuard::acquire(&config).unwrap())
            .unwrap();
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
        let mut judge = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        judge.job_id = Some("private-job-canary".into());
        store.save(&judge, "dispatch_outcome_unknown").unwrap();
        observe(&store, 2, false).unwrap();
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
        config.capabilities.answer.preparation.retry_uncertain = true;
        config.capabilities.answer.preparation.max_attempts_per_work = CountLimit::Bounded(1);
        let mut model = store
            .begin(
                LaneId::Answer,
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
        config.capabilities.answer.preparation.max_attempts_per_work = CountLimit::Bounded(2);
        // Desired configuration alone must not make the old loaded budget larger.
        assert_eq!(
            store.status(&config).unwrap()["work"]["answer"]["model"]["retry_eligible"],
            false
        );
        store.runtime_state(&config, false).unwrap();
        store.authorize(&config, 2, LaneId::Answer).unwrap();
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
            (LaneId::Answer, 429),
            (LaneId::Judge, 429),
            (LaneId::Mine, 429),
            (LaneId::Answer, 503),
            (LaneId::Judge, 503),
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
            let op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
            let op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
            let op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
            let op = dispatched_unknown(&mut store, &config, LaneId::Mine, 1);
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
            let op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
            let op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
        for kind in [LaneId::Answer, LaneId::Judge, LaneId::Mine] {
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
                assert!(store.reconciliation_batch(kind).unwrap().is_empty());
                assert!(store.uncertain_answer(1).unwrap().is_none());
                assert!(!store.routing_busy(&config).unwrap());
                if kind == LaneId::Answer {
                    assert!(store.answer_epoch_attempted(1).unwrap());
                }
                if kind == LaneId::Mine {
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
        let op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
        store.set_paused_unbound(true).unwrap();
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
            let mut op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
    fn non_refusal_terminal_diagnostics_do_not_create_refusal_floor_authority() {
        let (_temp, config, mut store) = participation_fixture();
        let mut old = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, true)
                .unwrap();
        assert_eq!(accounting.total, 0);
        assert_eq!(accounting.retry_not_before, 0);
    }

    #[test]
    fn retry_dispatch_honors_own_retained_server_floor_even_if_local_due_time_changes() {
        let (_temp, config, mut store) = participation_fixture();
        let mut op = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
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

    fn begin(store: &mut Store, kind: LaneId, key: &str, state: &str) -> Operation {
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
        config.capabilities.answer.mode = Mode::Active;
        config.capabilities.judge.mode = Mode::Active;
        config.capabilities.mine.mode = Mode::Active;
        config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 0;
        config
            .capabilities
            .answer
            .participation
            .uncertain_answer_retry_seconds = 0;
        config.capabilities.judge.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .judge
            .participation
            .uncertainty_grace_seconds = 0;
        config.capabilities.mine.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .mine
            .participation
            .uncertainty_grace_seconds = 0;
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        (temp, config, store)
    }

    fn observe(store: &Store, epoch: u64, answered: bool) -> Result<()> {
        store.set_authority_epoch(1)?;
        let sequence = store
            .lane_observation(LaneId::Answer)?
            .and_then(|value| value["request_sequence"].as_u64())
            .unwrap_or(0)
            + 1;
        store.seed_lane_observation_for_test(
            LaneId::Answer,
            LaneObservationStamp {
                authority_epoch: 1,
                generation: store.control()?.generation,
                request_sequence: sequence,
                started_at: now(),
                completed_at: now(),
            },
            LaneObservation {
                epoch,
                answered,
                fingerprint: "test",
                challenge: &json!({}),
            },
        )?;
        // Tests of historical identity repair explicitly retain legacy evidence.
        store.db.execute(
            "INSERT OR IGNORE INTO health_evidence(singleton) VALUES (1)",
            [],
        )?;
        Ok(())
    }

    fn observe_read_only_lanes(store: &Store) -> Result<()> {
        for (lane, source) in [
            (LaneId::Judge, DiscoverySource::Assignments),
            (LaneId::Mine, DiscoverySource::Challenge),
        ] {
            let key = ReadKey::Discovery { lane, source };
            assert!(store.read_started(&key)?);
            store.read_finished(&key, Some(200), None)?;
            store.reset_read(&key)?;
        }
        Ok(())
    }

    fn shared_floor(store: &Store, config: &Config, deadline: i64) {
        store.db.execute("INSERT INTO request_restrictions VALUES
            (?1,?2,'account_authenticated','*','server_retry_after',?3,?4,'test','job',1,1,3600,NULL)
            ON CONFLICT(authority,origin,scope,target,basis) DO UPDATE SET not_before=excluded.not_before",
            params![format!("{}\n{}",config.network.chain,config.network.address),
                reqwest::Url::parse(&config.network.base_url).unwrap().origin().ascii_serialization(),deadline,now()]).unwrap();
    }

    fn prepared_epoch(store: &mut Store, kind: LaneId, epoch: u64, fingerprint: &str) -> Operation {
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
        kind: LaneId,
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
                LaneId::Answer,
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
        config
            .capabilities
            .answer
            .participation
            .historical_unknown_answer_capacity = HistoricalAnswerCapacity::AcceptedLinked;
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(2);
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        let mut originals = Vec::new();
        let mut accepted = Vec::new();
        for epoch in 1..=24 {
            let original = dispatched_unknown(&mut store, &config, LaneId::Answer, epoch);
            assert!(store.answer_retry_allowed(&config, &original).unwrap());
            accepted.push(accepted_linked_answer(&mut store, &config, &original));
            originals.push(original);
            drop(store);
            store = Store::open(&config).unwrap();
            let accounting = Store::uncertainty_accounting(
                &store.db,
                &config,
                LaneId::Answer,
                None,
                None,
                false,
            )
            .unwrap();
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
        let mut next = prepared_epoch(&mut store, LaneId::Answer, 25, "next");
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(1);
        assert!(store.admission_allowed(&config, &next).unwrap());
        for mode in [ParticipationMode::Strict, ParticipationMode::Manual] {
            config.capabilities.answer.participation.mode = mode;
            assert!(!store.admission_allowed(&config, &next).unwrap());
            let accounting = Store::uncertainty_accounting(
                &store.db,
                &config,
                LaneId::Answer,
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                (accounting.eligible, accounting.exempt, accounting.active()),
                (24, 0, 24)
            );
        }
        config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .answer
            .participation
            .historical_unknown_answer_capacity = HistoricalAnswerCapacity::Bounded;
        config
            .capabilities
            .answer
            .participation
            .max_historical_unknown_answers = 2;
        assert!(!store.admission_allowed(&config, &next).unwrap());
        config
            .capabilities
            .answer
            .participation
            .historical_unknown_answer_capacity = HistoricalAnswerCapacity::AcceptedLinked;
        shared_floor(&store, &config, now() + 3600);
        drop(store);
        store = Store::open(&config).unwrap();
        assert!(!store.admission_allowed(&config, &next).unwrap());
        assert!(
            !store
                .uncertainty_open(&config, LaneId::Answer, Some(25), None)
                .unwrap()
        );
        // Expire only the fixture's wall-clock floor; no operation is retired.
        store
            .db
            .execute("UPDATE request_restrictions SET not_before=0", [])
            .unwrap();
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
        next.state = "unknown".into();
        store.save(&next, "dispatch_outcome_unknown").unwrap();
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["unresolved_count"], 25);
        assert_eq!(
            status["participation"]["lanes"]["answer"]["historical_eligible_count"],
            24
        );
        assert_eq!(
            status["participation"]["lanes"]["answer"]["capacity_exempt_count"],
            24
        );
        assert_eq!(status["participation"]["lanes"]["answer"]["own_count"], 1);
        assert_eq!(
            status["participation"]["lanes"]["answer"]["historical_unknown_answers"]
                .as_array()
                .unwrap()
                .len(),
            20
        );
        assert_eq!(
            status["participation"]["lanes"]["answer"]["historical_unknown_answers_truncated"],
            true
        );
        let inspection = store.inspect(next.id).unwrap();
        let risk = &inspection["risk_admissions"][0];
        assert_eq!(risk["accounting"]["capacity_exempt_count"], 24);
        assert_eq!(
            serde_json::from_str::<Vec<i64>>(risk["blocker_ids"].as_str().unwrap())
                .unwrap()
                .len(),
            HISTORICAL_EXAMPLE_LIMIT
        );
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
        assert!(blocker_count >= 24);
        for original in &originals {
            assert_eq!(
                store.operation(original.id).unwrap().unwrap().state,
                "unknown"
            );
        }
        assert!(
            !store
                .uncertainty_open(&config, LaneId::Answer, Some(26), None)
                .unwrap()
        );
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(3);
        accepted[0].state = "rejected".into();
        store.save(&accepted[0], "receipt_rejected").unwrap();
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
                .unwrap();
        assert_eq!((accounting.exempt, accounting.active()), (23, 2));
        let mut later = prepared_epoch(&mut store, LaneId::Answer, 26, "later");
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
    fn unbounded_first_admits_fresh_work_without_measuring_history() {
        let (_temp, mut config, mut store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(4);
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 3600;
        // Thousands of recent unknowns block every bounded policy by count
        // and by account-wide grace alike.
        for epoch in 1..=1500u64 {
            store
                .db
                .execute(
                    "INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at)
                     VALUES('answer',?1,'unknown',?2,1,'bulk',?3,?3)",
                    params![
                        format!("{epoch}:bulk"),
                        json!({"solver":{"epoch":epoch}}).to_string(),
                        now()
                    ],
                )
                .unwrap();
        }
        let mut fresh = prepared_epoch(&mut store, LaneId::Answer, 999_999, "fresh");
        assert!(!store.dispatch_intent(&mut fresh, &config).unwrap());
        // Explicit unbounded participation-first skips the cumulative count
        // and the account-wide grace for distinct new work.
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Unbounded;
        let skipped =
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
                .unwrap();
        assert!(!skipped.history_evaluated);
        assert_eq!(skipped.total, 0);
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["lanes"]["answer"]["allowed"], true);
        assert_eq!(
            status["participation"]["lanes"]["answer"]["own_count"],
            1500
        );
        assert_eq!(status["work"]["answer"]["admission"]["allowed"], true);
        assert!(store.dispatch_intent(&mut fresh, &config).unwrap());
        let policy: Value = serde_json::from_str(
            store.inspect(fresh.id).unwrap()["risk_admissions"][0]["policy"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(policy["history_evaluated"], false);
        assert!(policy["own_count"].is_null());
        assert!(policy["account_unresolved"].is_null());
        assert_eq!(policy["own_limit"], "unbounded");
        // No zero-count snapshot may fabricate absence of historical exposure.
        let snapshots: u64 = store
            .db
            .query_row("SELECT COUNT(*) FROM risk_accounting_snapshots", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(snapshots, 0);
        // Same-work and epoch fences still bind under the skip.
        fresh.state = "unknown".into();
        store.save(&fresh, "dispatch_outcome_unknown").unwrap();
        let mut same_epoch = prepared_epoch(&mut store, LaneId::Answer, 999_999, "second");
        assert!(!store.dispatch_intent(&mut same_epoch, &config).unwrap());
    }

    #[test]
    fn unbounded_first_preserves_effect_floor_and_retry_ceiling() {
        let (_temp, mut config, store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Unbounded;
        let policy = config.participation(LaneId::Answer);
        let cutoff = AdmissionCutoff::current();
        let evaluate = |store: &Store| {
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
                .unwrap()
        };
        // One locally dispatching effect still blocks distinct fresh work.
        store
            .db
            .execute(
                "INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at)
                 VALUES('answer','1:effect','dispatching','{}',1,'bulk',0,0)",
                [],
            )
            .unwrap();
        let accounting = evaluate(&store);
        assert!(!accounting.history_evaluated);
        assert!(accounting.writing);
        assert_eq!(
            Store::account_blocker_at(policy, &accounting, false, cutoff),
            Some(("effect_in_flight", None))
        );
        store
            .db
            .execute("DELETE FROM operations WHERE state='dispatching'", [])
            .unwrap();
        // A retained server floor still binds.
        shared_floor(&store, &config, now() + 300);
        let accounting = evaluate(&store);
        assert!(accounting.retry_not_before > cutoff.at);
        assert_eq!(
            Store::account_blocker_at(policy, &accounting, false, cutoff),
            Some((
                "shared_server_restriction",
                Some(accounting.retry_not_before)
            ))
        );
        // The same-work retry ceiling binds even though history was not
        // evaluated: the skipped scan reports total zero.
        let mut ceiling = UncertaintyAccounting::default();
        assert!(!ceiling.history_evaluated);
        ceiling.retry_grace_until = now() + 60;
        assert_eq!(
            Store::account_blocker_at(policy, &ceiling, false, cutoff),
            Some((
                "uncertain_answer_retry_delay",
                Some(ceiling.retry_grace_until)
            ))
        );
        ceiling.retry_grace_until = now() - 60;
        assert_eq!(
            Store::account_blocker_at(policy, &ceiling, false, cutoff),
            None
        );
    }

    #[test]
    fn accepted_linked_requires_direct_same_epoch_dispatched_identifierless_unknown() {
        let (_temp, mut config, mut store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .historical_unknown_answer_capacity = HistoricalAnswerCapacity::AcceptedLinked;
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 7);
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
            let owner = store.operation(original.id).unwrap().unwrap().kind;
            let accounting = Store::uncertainty_accounting(
                &store.db,
                &config,
                LaneId::Answer,
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                (accounting.eligible, accounting.exempt, accounting.active()),
                (0, 0, u64::from(owner == LaneId::Answer)),
                "{change}"
            );
            assert_eq!(accounting.total, 1, "{change}");
            if owner != LaneId::Answer {
                let owning_lane =
                    Store::uncertainty_accounting(&store.db, &config, owner, None, None, true)
                        .unwrap();
                assert_eq!(
                    (
                        owning_lane.eligible,
                        owning_lane.exempt,
                        owning_lane.active()
                    ),
                    (0, 0, 1),
                    "{change}"
                );
                assert_eq!(owning_lane.own_blockers, vec![original.id], "{change}");
            }
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
            let accounting = Store::uncertainty_accounting(
                &store.db,
                &config,
                LaneId::Answer,
                None,
                None,
                false,
            )
            .unwrap();
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
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
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
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
                .unwrap()
                .eligible,
            0
        );
        // An accepted grandchild does not qualify an ancestor without a direct accepted retry.
        let mut retry = store
            .begin_linked(
                LaneId::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "retry",
                Some((&original, true)),
            )
            .unwrap();
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 4;
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
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
                .unwrap();
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
    fn pending_routes_bind_only_legacy_defaults_and_survive_restart() {
        for state in ["generating", "prepared", "unknown"] {
            let (_temp, config, mut store) = participation_fixture();
            let op = begin(&mut store, LaneId::Answer, "7:pending", state);
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
        let mut op = begin(&mut store, LaneId::Answer, "7:included", "confirmed");
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
        assert!(
            store
                .reconciliation_batch(LaneId::Answer)
                .unwrap()
                .iter()
                .any(|pending| pending.id == op.id)
        );
        op.state = "final".into();
        store.save(&op, "node_reported_final").unwrap();
        store.bind_routing(&changed).unwrap();
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "final");
    }

    #[test]
    fn first_custom_binding_revokes_legacy_grants_and_observations() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
        observe(&store, 9, false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let grant = store.authorize(&config, 9, LaneId::Answer).unwrap();
        config.network.api.routes.insert(
            crate::endpoints::Endpoint::Challenge,
            "/different-challenge".into(),
        );
        store.bind_routing(&config).unwrap();
        assert!(store.control().unwrap().generation > grant["generation"].as_i64().unwrap());
        let observations: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM lane_observations", [], |row| {
                row.get(0)
            })
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
        dispatched_unknown(&mut store, &config, LaneId::Judge, 8);
        let mut answer = prepared_epoch(&mut store, LaneId::Answer, 9, "fresh");
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
    }

    #[test]
    fn reusable_model_attempts_hold_routing_until_their_budget_is_exhausted() {
        for initial in ["rejected", "model_unknown"] {
            for convert in [false, true] {
                let (_temp, mut config, mut store) = participation_fixture();
                config.capabilities.answer.preparation.max_attempts_per_work =
                    CountLimit::Bounded(2);
                config.capabilities.answer.preparation.retry_uncertain = true;
                store.bind_routing(&config).unwrap();
                let op = begin(&mut store, LaneId::Answer, "7:retry", initial);
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
                changed
                    .capabilities
                    .answer
                    .preparation
                    .max_attempts_per_work = CountLimit::Bounded(1);
                store.bind_routing(&changed).unwrap();
                assert_eq!(store.model_budget_used(LaneId::Answer, &op.key).unwrap(), 1);
            }
        }
    }

    #[test]
    fn historical_allowance_preserves_unknowns_and_records_dispatch_witnesses() {
        let (_temp, mut config, mut store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 7);
        let accepted = accepted_linked_answer(&mut store, &config, &original);
        observe(&store, 7, true).unwrap();
        store.runtime_state(&config, false).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["participation"]["lanes"]["answer"]["allowed"],
            true
        );
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(1);
        let mut next = prepared_epoch(&mut store, LaneId::Answer, 8, "next");
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        config
            .capabilities
            .answer
            .participation
            .max_historical_unknown_answers = 1;
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
        assert_eq!(status["participation"]["lanes"]["answer"]["own_count"], 1);
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        let mut third = prepared_epoch(&mut store, LaneId::Answer, 9, "third");
        assert!(!store.dispatch_intent(&mut third, &config).unwrap());
    }

    #[test]
    fn historical_allowance_never_weakens_policy_floors_or_binding_evidence() {
        let (_temp, mut config, mut store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 7);
        let mut accepted = accepted_linked_answer(&mut store, &config, &original);
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(1);
        config
            .capabilities
            .answer
            .participation
            .max_historical_unknown_answers = 1;
        let next = prepared_epoch(&mut store, LaneId::Answer, 8, "next");
        assert!(store.admission_allowed(&config, &next).unwrap());
        for mode in [ParticipationMode::Strict, ParticipationMode::Manual] {
            config.capabilities.answer.participation.mode = mode;
            assert!(!store.admission_allowed(&config, &next).unwrap());
        }
        config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .answer
            .participation
            .max_historical_unknown_answers = 0;
        assert!(!store.admission_allowed(&config, &next).unwrap());
        config
            .capabilities
            .answer
            .participation
            .max_historical_unknown_answers = 1;
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
        shared_floor(&store, &config, now() + 3600);
        assert!(!store.admission_allowed(&config, &next).unwrap());
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
    }

    #[test]
    fn read_diagnostics_distinguish_http_success_from_usable_evidence_and_bound_codes() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        store
            .read_started(&ReadKey::Discovery {
                lane: LaneId::Answer,
                source: DiscoverySource::Challenge,
            })
            .unwrap();
        assert_eq!(
            store.reads_projection().unwrap()["reads"][0]["state"],
            "in_flight"
        );
        store
            .read_finished(
                &ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge,
                },
                Some(200),
                Some("invalid_json"),
            )
            .unwrap();
        store
            .fail_read(
                &ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge,
                },
                10,
                30,
                0,
                None,
            )
            .unwrap();
        let failed = store.reads_projection().unwrap()["reads"].take();
        assert!(failed[0]["last_http_success_at"].is_i64());
        assert!(failed[0]["last_success_at"].is_null());
        assert_eq!(failed[0]["failure_category"], "invalid_json");
        store
            .db
            .execute(
                "UPDATE read_state SET failure_category='https://private.invalid/secret'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.reads_projection().unwrap()["reads"][0]["failure_category"],
            "unusable_response"
        );
        store
            .reset_read(&ReadKey::Discovery {
                lane: LaneId::Answer,
                source: DiscoverySource::Challenge,
            })
            .unwrap();
        let recovered = store.reads_projection().unwrap()["reads"].take();
        assert!(recovered[0]["last_success_at"].is_i64());
        assert_eq!(
            recovered[0]["last_failure_at"],
            failed[0]["last_failure_at"]
        );
        assert_eq!(recovered[0]["failures"], 0);
    }

    #[test]
    fn risk_history_rolls_back_with_stale_cas_and_closed_capabilities() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        let mut next = prepared_epoch(&mut store, LaneId::Answer, 2, "new");
        for mode in [Mode::Off, Mode::ReadOnly] {
            config.capabilities.answer.mode = mode;
            assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        }
        config.capabilities.answer.mode = Mode::Active;
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
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(2);
        assert!(store.authorize(&config, 3, LaneId::Mine).is_err());
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(4);
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 1;
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        assert!(store.authorize(&config, 2, LaneId::Answer).is_err());
    }

    #[test]
    fn manual_grants_are_one_dispatch_and_generation_and_epoch_scoped() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
        config.capabilities.mine.participation.mode = ParticipationMode::Manual;
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 600;
        let mut next = prepared_epoch(&mut store, LaneId::Answer, 2, "new");
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        store.authorize(&config, 3, LaneId::Answer).unwrap();
        assert!(!store.dispatch_intent(&mut next, &config).unwrap());
        let grant = store.authorize(&config, 2, LaneId::Answer).unwrap();
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
        next.state = "unknown".into();
        store.save(&next, "dispatch_outcome_unknown").unwrap();
        assert_eq!(
            store.inspect(next.id).unwrap()["risk_admissions"][0]["manual_grant_id"],
            grant["grant_id"]
        );
        let mut another = prepared_epoch(&mut store, LaneId::Mine, 2, "new");
        assert!(!store.dispatch_intent(&mut another, &config).unwrap());
        store.authorize(&config, 2, LaneId::Mine).unwrap();
        store.set_paused_unbound(true).unwrap();
        assert!(store.authorize(&config, 2, LaneId::Mine).is_err());
        store.set_paused_unbound(false).unwrap();
        assert!(!store.dispatch_intent(&mut another, &config).unwrap());
        another.state = "discarded".into();
        store.save(&another, "unsent_admission_closed").unwrap();
        let mut after_resume = prepared_epoch(&mut store, LaneId::Mine, 2, "new");
        assert!(!store.dispatch_intent(&mut after_resume, &config).unwrap());
        store.authorize(&config, 2, LaneId::Mine).unwrap();
        assert!(store.dispatch_intent(&mut after_resume, &config).unwrap());
    }

    #[test]
    fn captured_retry_validates_canonical_input_and_copies_canonical_artifacts() {
        let (_temp, config, mut store) = participation_fixture();
        let mut original = store
            .begin(
                LaneId::Answer,
                "7:original",
                "prepared",
                &json!({"solver":{"id":"captured-request","epoch":7,"words":["burn"],
                    "min_chars":4,"max_chars":100},"challenge_fingerprint":"original"}),
                store.control().unwrap(),
                "original_revision",
            )
            .unwrap();
        original.payload = Some(json!({"answer":"captured burning"}));
        original.result = Some(json!({"answer":"captured burning","model":"original-model"}));
        assert!(store.dispatch_intent(&mut original, &config).unwrap());
        original.state = "unknown".into();
        store.save(&original, "dispatch_outcome_unknown").unwrap();
        let original = store.operation(original.id).unwrap().unwrap();

        for changed in [
            "request",
            "fingerprint",
            "words",
            "constraints",
            "key",
            "all",
        ] {
            let mut detached = original.clone();
            if matches!(changed, "request" | "all") {
                detached.request["solver"]["id"] = json!("changed-request");
            }
            if matches!(changed, "fingerprint" | "all") {
                detached.request["challenge_fingerprint"] = json!("changed");
            }
            if matches!(changed, "words" | "all") {
                detached.request["solver"]["words"] = json!(["water"]);
            }
            if matches!(changed, "constraints" | "all") {
                detached.request["solver"]["min_chars"] = json!(5);
                detached.request["solver"]["max_chars"] = json!(80);
            }
            if matches!(changed, "key" | "all") {
                detached.key = "7:changed".into();
            }
            assert_eq!(detached.request["solver"]["epoch"], 7);
            let error = store
                .begin_linked(
                    LaneId::Answer,
                    &detached.key,
                    ("prepared", &detached.request),
                    store.control().unwrap(),
                    "retry_revision",
                    Some((&detached, true)),
                )
                .err()
                .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("captured retry requires matching complete answer"),
                "{changed}: {error}"
            );
            assert!(store.preparation(LaneId::Answer).unwrap().is_none());
            let counts: (i64, i64) = store
                .db
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM operations),(SELECT COUNT(*) FROM operation_links)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(counts, (1, 0), "{changed}");
        }

        let mut detached = original.clone();
        detached.request["solver"]["words"] = json!(["water"]);
        detached.key = "7:changed".into();
        detached.payload = None;
        detached.result = Some(json!({"answer":"detached result"}));
        let retry = store
            .begin_linked(
                LaneId::Answer,
                &original.key,
                ("prepared", &original.request),
                store.control().unwrap(),
                "retry_revision",
                Some((&detached, true)),
            )
            .unwrap();
        assert_ne!(retry.id, original.id);
        assert_eq!(retry.key, original.key);
        assert_eq!(retry.request, original.request);
        assert_eq!(retry.payload, original.payload);
        assert_eq!(retry.result, original.result);
        let inspection = store.inspect(retry.id).unwrap();
        assert_eq!(inspection["retry_of"], original.id);
        assert_eq!(inspection["payload_reused"], true);
    }

    #[test]
    fn uncertain_answer_reuses_payload_with_distinct_bounded_durable_attempts() {
        let (_temp, mut config, mut store) = participation_fixture();
        let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 7);
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        config
            .capabilities
            .answer
            .participation
            .uncertain_answer_retry_seconds = 600;
        assert!(!store.answer_retry_allowed(&config, &original).unwrap());
        config
            .capabilities
            .answer
            .participation
            .uncertain_answer_retry_seconds = 0;
        assert!(store.answer_retry_allowed(&config, &original).unwrap());
        let retry = store
            .begin_linked(
                LaneId::Answer,
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
                .model_budget_used(LaneId::Answer, &original.key)
                .unwrap(),
            1
        );
        drop(store);
        let mut store = Store::open(&config).unwrap();
        let mut retry = store.operation(retry.id).unwrap().unwrap();
        config.capabilities.answer.participation.mode = ParticipationMode::Strict;
        assert!(!store.dispatch_intent(&mut retry, &config).unwrap());
        config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = false;
        assert!(!store.dispatch_intent(&mut retry, &config).unwrap());
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
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
                LaneId::Answer,
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
        config
            .capabilities
            .answer
            .participation
            .retry_uncertain_answers = true;
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 2;
        let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 62);
        observe(&store, 62, false).unwrap();
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
            "operation_retry_minimum"
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
            .fail_read(
                &ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge,
                },
                90,
                300,
                0,
                None,
            )
            .unwrap();
        drop(store);
        let readonly = Store::read_only(&config).unwrap().unwrap();
        let status = readonly.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["retry"]["reason"], "read_backoff");
        assert_eq!(
            status["work"]["answer"]["retry"]["next_at"],
            readonly
                .read_backoff(&ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge
                })
                .unwrap()
                .next_at
        );
        assert_eq!(
            readonly.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        assert_eq!(
            readonly
                .attempt_count(LaneId::Answer, &original.key)
                .unwrap(),
            1
        );
        drop(readonly);
        let mut store = Store::open(&config).unwrap();
        let discovery = ReadKey::Discovery {
            lane: LaneId::Answer,
            source: DiscoverySource::Challenge,
        };
        assert!(!store.read_started(&discovery).unwrap());
        store.db.execute(
            "UPDATE read_state SET local_next_at=0 WHERE owner='answer' AND purpose='discovery'",
            [],
        ).unwrap();
        assert!(store.read_started(&discovery).unwrap());
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "freshness_in_flight"
        );
        assert!(status["work"]["answer"]["retry"]["next_at"].is_null());
        store
            .read_finished(
                &ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge,
                },
                Some(200),
                None,
            )
            .unwrap();
        store
            .reset_read(&ReadKey::Discovery {
                lane: LaneId::Answer,
                source: DiscoverySource::Challenge,
            })
            .unwrap();

        observe(&store, 62, true).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(
            status["work"]["answer"]["retry"]["reason"],
            "hosted_answer_observed"
        );
        assert_eq!(
            store.operation(original.id).unwrap().unwrap().state,
            "unknown"
        );
        observe(&store, 62, false).unwrap();
        let mut retry = store
            .begin_linked(
                LaneId::Answer,
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
            "operation_retry_minimum"
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
        observe(&store, 62, true).unwrap();
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
        let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 62);
        observe(&store, 62, false).unwrap();
        for (mode, enabled, capacity, delay, expected) in [
            (ParticipationMode::Strict, true, 8, 0, "account_uncertainty"),
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
                "lane_unresolved_capacity",
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
            config.capabilities.answer.participation.mode = mode;
            config
                .capabilities
                .answer
                .participation
                .retry_uncertain_answers = enabled;
            config
                .capabilities
                .answer
                .participation
                .max_unresolved_operations = CountLimit::from(capacity);
            config
                .capabilities
                .answer
                .participation
                .uncertain_answer_retry_seconds = delay;
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
            config
                .capabilities
                .answer
                .participation
                .retry_uncertain_answers = true;
            let mut original = dispatched_unknown(&mut store, &config, LaneId::Answer, 9);
            let mut retry = store
                .begin_linked(
                    LaneId::Answer,
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
    fn completed_mining_health_requires_current_idle_work() {
        use crate::health::{self, Options};
        let (_temp, mut config, mut store) = participation_fixture();
        config.capabilities.answer.mode = Mode::Off;
        config.capabilities.judge.mode = Mode::Off;
        config.capabilities.mine.schedule.each_epoch = true;
        let observe_mine = |store: &Store, epoch| {
            store.set_authority_epoch(1).unwrap();
            store
                .seed_lane_observation_for_test(
                    LaneId::Mine,
                    LaneObservationStamp {
                        authority_epoch: 1,
                        generation: store.control().unwrap().generation,
                        request_sequence: epoch,
                        started_at: now(),
                        completed_at: now(),
                    },
                    LaneObservation {
                        epoch,
                        answered: false,
                        fingerprint: "fingerprint",
                        challenge: &json!({}),
                    },
                )
                .unwrap();
        };
        observe_mine(&store, 10);
        observe_read_only_lanes(&store).unwrap();
        let mut mine = dispatched_unknown(&mut store, &config, LaneId::Mine, 10);
        mine.state = "completed".into();
        store.save(&mine, "mine_completed").unwrap();
        store.runtime_state(&config, false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let changes = store.db.total_changes();
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["mine"]["phase"], "completed");
        assert_eq!(status["work"]["mine"]["operation_id"], mine.id);
        assert_eq!(status["work"]["mine"]["operation_epoch"], 10);
        let options = Options {
            min_free_mib: 0,
            ..Options::default()
        };
        let health = health::check(&config, options).unwrap();
        assert_eq!(health["components"]["mine"]["state"], "ok", "{health}");
        assert_eq!(store.db.total_changes(), changes);

        config.capabilities.mine.schedule.each_epoch = false;
        store
            .db
            .execute(
                "INSERT INTO schedule(kind,next_at) VALUES ('mine:participation',?1)",
                [now() + 3600],
            )
            .unwrap();
        store.runtime_state(&config, false).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["work"]["mine"]["phase"],
            "completed"
        );
        store
            .db
            .execute(
                "UPDATE schedule SET next_at=0 WHERE kind='mine:participation'",
                [],
            )
            .unwrap();
        // Completion expires, but a viable scheduled path need not be unhealthy.
        assert_ne!(
            store.status(&config).unwrap()["work"]["mine"]["phase"],
            "completed"
        );

        let mut rejected = dispatched_unknown(&mut store, &config, LaneId::Mine, 10);
        rejected.state = "rejected".into();
        store.save(&rejected, "submission_rejected").unwrap();
        assert!(store.participation_next_at(LaneId::Mine).unwrap() > now());
        assert_ne!(
            store.status(&config).unwrap()["work"]["mine"]["phase"],
            "completed"
        );

        config.capabilities.mine.schedule.each_epoch = true;
        store.runtime_state(&config, false).unwrap();
        observe_mine(&store, 11);
        assert_ne!(
            store.status(&config).unwrap()["work"]["mine"]["phase"],
            "completed"
        );
        let current = dispatched_unknown(&mut store, &config, LaneId::Mine, 11);
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["mine"]["operation_id"], current.id);
        assert_eq!(status["work"]["mine"]["phase"], "unknown");
    }

    #[test]
    fn mine_each_epoch_and_safe_same_operation_retry_are_distinct() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.capabilities.mine.schedule.each_epoch = true;
        let mut mine = dispatched_unknown(&mut store, &config, LaneId::Mine, 10);
        mine.state = "retry".into();
        store.save(&mine, "submission_backoff").unwrap();
        assert!(store.dispatch_intent(&mut mine, &config).unwrap());
        mine.state = "completed".into();
        store.save(&mine, "mine_completed").unwrap();
        assert!(store.mine_epoch_attempted(10).unwrap());
        let mut duplicate = prepared_epoch(&mut store, LaneId::Mine, 10, "rotated");
        assert!(!store.dispatch_intent(&mut duplicate, &config).unwrap());
        duplicate.state = "discarded".into();
        store.save(&duplicate, "request_no_longer_current").unwrap();
        let mut next = prepared_epoch(&mut store, LaneId::Mine, 11, "new");
        assert!(store.dispatch_intent(&mut next, &config).unwrap());
    }

    #[test]
    fn status_requires_effective_lane_policy_without_desired_fallback() {
        let (_temp, mut config, mut store) = participation_fixture();
        dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        store.runtime_state(&config, false).unwrap();
        config.capabilities.answer.participation.mode = ParticipationMode::Strict;
        assert_eq!(
            store.status(&config).unwrap()["participation"]["lanes"]["answer"]["allowed"],
            true
        );
        store.db.execute("DELETE FROM runtime_policy", []).unwrap();
        let changes = store.db.total_changes();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["policy_source"], "unavailable");
        assert!(status["participation"]["lanes"]["answer"].is_null());
        assert_eq!(store.db.total_changes(), changes);
    }

    #[test]
    fn proven_nonacceptance_allows_new_fingerprint_within_distinct_attempt_budget() {
        let (_temp, mut config, mut store) = participation_fixture();
        config.capabilities.answer.participation.mode = ParticipationMode::Strict;
        let mut old = dispatched_unknown(&mut store, &config, LaneId::Answer, 7);
        old.state = "retry".into();
        store.save(&old, "submission_backoff").unwrap();
        old.state = "discarded".into();
        store.save(&old, "request_no_longer_current").unwrap();
        assert!(!store.answer_epoch_attempted(7).unwrap());
        let mut current = prepared_epoch(&mut store, LaneId::Answer, 7, "rotated");
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 1;
        assert!(!store.dispatch_intent(&mut current, &config).unwrap());
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 2;
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
        let mut old = dispatched_unknown(&mut store, &config, LaneId::Answer, 7);
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
        let mut current = prepared_epoch(&mut store, LaneId::Answer, 7, "rotated");
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 1;
        assert!(!store.dispatch_intent(&mut current, &config).unwrap());
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 2;
        assert!(store.dispatch_intent(&mut current, &config).unwrap());
    }

    #[test]
    fn oldest_unresolved_is_not_the_current_grace_blocker() {
        let (_temp, mut config, mut store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Bounded(4);
        let old = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        let old_since = now() - 86400;
        store
            .db
            .execute(
                "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
                params![old_since, old.id],
            )
            .unwrap();
        let recent = dispatched_unknown(&mut store, &config, LaneId::Mine, 2);
        let prepared = prepared_epoch(&mut store, LaneId::Answer, 3, "current");
        observe(&store, 3, false).unwrap();
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 300;
        store.runtime_state(&config, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["oldest_unresolved_operation"], old.id);
        assert_eq!(status["oldest_unresolved_since"], old_since);
        assert_eq!(status["admission_blocked"], true);
        assert_eq!(
            status["work"]["answer"]["reason"],
            "account_uncertainty_grace"
        );
        assert!(status["work"]["answer"]["next_at"].as_i64().unwrap() >= now() + 299);
        assert!(!store.admission_allowed(&config, &prepared).unwrap());
        assert!(status.get("blocking_operation").is_none());
        assert!(status.get("blocked_since").is_none());

        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 0;
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
        let revision = config.lane_revision(LaneId::Judge).unwrap();
        let generation = store.control().unwrap().generation;
        store
            .record_assignment_selection(&revision, generation, 2, false, false)
            .unwrap();
        store.defer(LaneId::Judge, 120).unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        let work = store.status(&config).unwrap()["work"]["judge"].clone();
        assert_eq!(work["reason"], "no_eligible_in_observed_inventory");
        assert_eq!(work["assessment"]["observed_opportunities"], 2);
        assert_eq!(work["assessment"]["completeness"], "bounded_partial");
        assert!(work["next_at"].as_i64().unwrap() > now());
        store
            .fail_read(
                &ReadKey::Discovery {
                    lane: LaneId::Judge,
                    source: DiscoverySource::Assignments,
                },
                600,
                900,
                0,
                None,
            )
            .unwrap();
        let floor = store
            .read_backoff(&ReadKey::Discovery {
                lane: LaneId::Judge,
                source: DiscoverySource::Assignments,
            })
            .unwrap()
            .next_at;
        let work = store.status(&config).unwrap()["work"]["judge"].clone();
        assert_eq!(work["reason"], "read_backoff");
        assert!(work["next_at"].as_i64().unwrap() >= floor);
        assert!(
            !store
                .read_started(&ReadKey::Discovery {
                    lane: LaneId::Judge,
                    source: DiscoverySource::Assignments
                })
                .unwrap()
        );
        assert_eq!(
            store.status(&config).unwrap()["work"]["judge"]["assessment"]["observed_opportunities"],
            2
        );
        store
            .cancel_read(&ReadKey::Discovery {
                lane: LaneId::Judge,
                source: DiscoverySource::Assignments,
            })
            .unwrap();
        assert_eq!(
            store
                .read_backoff(&ReadKey::Discovery {
                    lane: LaneId::Judge,
                    source: DiscoverySource::Assignments
                })
                .unwrap()
                .next_at,
            floor
        );
        store
            .record_assignment_selection(&revision, generation, 0, true, false)
            .unwrap();
        config.capabilities.answer.preparation.max_attempts_per_work = config
            .capabilities
            .answer
            .preparation
            .max_attempts_per_work
            .finite()
            .map(|limit| CountLimit::Bounded(limit + 1))
            .unwrap_or(CountLimit::Unbounded);
        store.runtime_state(&config, false).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["work"]["judge"]["assessment"]["observed_opportunities"],
            0
        );
        store.set_paused_unbound(true).unwrap();
        store.set_paused_unbound(false).unwrap();
        let revision = config.lane_revision(LaneId::Judge).unwrap();
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
        let assessment = store.status(&config).unwrap()["work"]["judge"]["assessment"].clone();
        assert_eq!(assessment["observed_opportunities"], 1);
        assert_eq!(assessment["locally_judgeable"], true);
    }

    #[test]
    fn submission_evidence_is_atomic_without_reconstructing_request_minima() {
        let (_temp, mut config, mut store) = participation_fixture();
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 0;
        let mut op = prepared_epoch(&mut store, LaneId::Judge, 1, "limited");
        assert!(store.dispatch_intent(&mut op, &config).unwrap());
        let before: Option<String> = store
            .db
            .query_row(
                "SELECT evidence FROM operation_evidence WHERE operation_id=?1",
                [op.id],
                |row| row.get(0),
            )
            .unwrap();
        let evidence = refusal_evidence(LaneId::Judge, 429, Some("rate_limited"));
        store
            .db
            .execute_batch(
                "CREATE TEMP TRIGGER deny_response_floor BEFORE UPDATE ON operation_evidence
             BEGIN SELECT RAISE(ABORT,'synthetic evidence failure'); END;",
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
            "diagnostic committed despite failed evidence capture"
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
        assert_eq!(floor, 0);
        // Simulate stopping after response capture, before outcome() saves retry.
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        assert_eq!(store.operation(op.id).unwrap().unwrap().state, "unknown");
        assert_eq!(store.operation_poll_timing(op.id).unwrap().1, floor);
        let mut answer = prepared_epoch(&mut store, LaneId::Answer, 2, "fresh");
        assert!(store.admission_allowed(&config, &answer).unwrap());
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
        let mut old = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        old.state = "retry".into();
        store.save(&old, "submission_backoff").unwrap();
        store
            .db
            .execute(
                "UPDATE operation_evidence SET blocked_since=?1 WHERE operation_id=?2",
                params![now() - 3600, old.id],
            )
            .unwrap();
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 300;
        assert!(store.dispatch_intent(&mut old, &config).unwrap());
        old.state = "unknown".into();
        store.save(&old, "dispatch_outcome_unknown").unwrap();
        let mut answer = prepared_epoch(&mut store, LaneId::Answer, 2, "new");
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
        store.runtime_state(&config, false).unwrap();
        dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        let mut answer = begin(&mut store, LaneId::Answer, "2:wait", "generating");
        let started = now() - 120;
        store
            .db
            .execute(
                "UPDATE operation_timing SET generation_started_at=?1 WHERE operation_id=?2",
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
                "UPDATE operation_timing SET model_captured_at=?1 WHERE operation_id=?2",
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
        config.capabilities.answer.participation.mode = ParticipationMode::Strict;
        store.runtime_state(&config, false).unwrap();
        config.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        let status = store.status(&config).unwrap();
        assert_eq!(status["work"]["answer"]["reason"], "account_uncertainty");
        assert!(status["work"]["answer"]["next_at"].is_null());
        assert_eq!(
            status["work"]["answer"]["next_at"],
            status["work"]["answer"]["admission"]["next_at"]
        );
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
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 600;
        store.runtime_state(&config, false).unwrap();
        let grace = store.status(&config).unwrap();
        assert_eq!(
            grace["work"]["answer"]["reason"],
            "account_uncertainty_grace"
        );
        assert_eq!(
            grace["work"]["answer"]["next_at"],
            grace["work"]["answer"]["admission"]["not_before"]
        );
        assert!(grace["work"]["answer"]["next_at"].as_i64().unwrap() > now());
        assert_eq!(
            grace["work"]["answer"]["wait"]["model_captured_at"],
            captured
        );
        assert!(
            grace["work"]["answer"]["wait"]
                .get("blocked_seconds")
                .is_none()
        );
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        let inventory = store
            .operations_list(Some(LaneId::Answer), None, None, 1)
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
    fn durable_wait_evidence_survives_event_pruning_without_mutable_timestamp_fallback() {
        let (_temp, _config, mut store) = participation_fixture();
        let mut op = begin(&mut store, LaneId::Answer, "1:wait", "generating");
        op.state = "generated".into();
        store.save(&op, "model_result_captured").unwrap();
        let before = store.operations_list(None, None, None, 1).unwrap()["operations"][0]["wait"]["model_captured_at"].clone();
        store
            .db
            .execute_batch(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<2000)
             INSERT INTO events(at,code) SELECT 1,'diagnostic' FROM n;",
            )
            .unwrap();
        store.event("diagnostic", None).unwrap();
        store
            .db
            .execute("UPDATE operations SET updated_at=1 WHERE id=?1", [op.id])
            .unwrap();
        let inventory = store.operations_list(None, None, None, 1).unwrap();
        assert_eq!(
            inventory["operations"][0]["wait"]["model_captured_at"],
            before
        );
        store.db.execute("DELETE FROM events", []).unwrap();
        store
            .db
            .execute(
                "UPDATE operation_timing SET model_captured_at=NULL WHERE operation_id=?1",
                [op.id],
            )
            .unwrap();
        let missing = store.operations_list(None, None, None, 1).unwrap();
        assert!(missing["operations"][0]["wait"]["model_captured_at"].is_null());
        assert!(missing["operations"][0]["wait"]["unsent_since_capture_seconds"].is_null());
    }

    #[test]
    fn prepared_mining_has_no_model_capture_timestamp() {
        let (_temp, _config, mut store) = participation_fixture();
        let mine = begin(&mut store, LaneId::Mine, "model-free", "prepared");
        let captured: Option<i64> = store
            .db
            .query_row(
                "SELECT model_captured_at FROM operation_timing WHERE operation_id=?1",
                [mine.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(captured, None);
    }

    #[test]
    fn queued_transition_timing_survives_polling_and_preserves_retry_minima() {
        let (_temp, config, mut store) = participation_fixture();
        let mut op = prepared_epoch(&mut store, LaneId::Mine, 1, "queued");
        assert!(store.dispatch_intent(&mut op, &config).unwrap());
        op.state = "queued".into();
        op.next_at = now() + 300;
        store.save(&op, "submission_queued").unwrap();
        let queued = now() - 120;
        store
            .db
            .execute(
                "UPDATE operation_timing SET queued_since=?1 WHERE operation_id=?2",
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
    fn captured_retry_preserves_original_model_capture_time_or_unknown() {
        for captured in [Some(1234_i64), None] {
            let (_temp, config, mut store) = participation_fixture();
            let original = dispatched_unknown(&mut store, &config, LaneId::Answer, 2);
            store
                .db
                .execute(
                    "UPDATE operation_timing SET model_captured_at=?1 WHERE operation_id=?2",
                    params![captured, original.id],
                )
                .unwrap();
            let retry = store
                .begin_linked(
                    LaneId::Answer,
                    &original.key,
                    ("prepared", &original.request),
                    store.control().unwrap(),
                    "revision",
                    Some((&original, true)),
                )
                .unwrap();
            let retained: Option<i64> = store
                .db
                .query_row(
                    "SELECT model_captured_at FROM operation_timing WHERE operation_id=?1",
                    [retry.id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained, captured);
        }
    }

    #[test]
    fn operation_inventory_is_sanitized_filtered_and_completely_paginated() {
        let (_temp, config, mut store) = participation_fixture();
        let mut old = dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        old.job_id = Some("private-bearer-job-canary".into());
        old.txid = Some("private-bound-tx-canary".into());
        store.save(&old, "bound_identifiers").unwrap();
        let answer = dispatched_unknown(&mut store, &config, LaneId::Answer, 2);
        dispatched_unknown(&mut store, &config, LaneId::Mine, 3);
        let retry = store
            .begin_linked(
                LaneId::Answer,
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
            .operations_list(Some(LaneId::Answer), Some("unknown"), None, 100)
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
        dispatched_unknown(&mut store, &config, LaneId::Judge, 1);
        config.capabilities.answer.participation.mode = ParticipationMode::Manual;
        config
            .capabilities
            .answer
            .participation
            .uncertainty_grace_seconds = 600;
        let older = store.authorize(&config, 2, LaneId::Answer).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        let revoked = store.authorize(&config, 3, LaneId::Answer).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        assert!(store.authorize(&config, 4, LaneId::Mine).is_err());
        config.capabilities.mine.participation.mode = ParticipationMode::Manual;
        let newest = store.authorize(&config, 4, LaneId::Mine).unwrap()["grant_id"]
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
        let mut answer = prepared_epoch(&mut store, LaneId::Answer, 3, "new");
        assert!(!store.dispatch_intent(&mut answer, &config).unwrap());
        let replacement = store.authorize(&config, 3, LaneId::Answer).unwrap()["grant_id"]
            .as_i64()
            .unwrap();
        assert_ne!(replacement, revoked);
        assert!(store.dispatch_intent(&mut answer, &config).unwrap());
        assert!(store.revoke_grant(replacement).is_err());
        store.set_paused_unbound(true).unwrap();
        store.set_paused_unbound(false).unwrap();
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
        store.set_paused_unbound(false).unwrap();
        let op = begin(&mut store, LaneId::Mine, "epoch:8", "prepared");
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
        store.defer(LaneId::Answer, 300).unwrap();
        let work_at = store.next_at(LaneId::Answer).unwrap();
        for (failures, seconds) in [(1, 12), (2, 22), (3, 27), (4, 27)] {
            let before = now();
            let state = store
                .fail_read(
                    &ReadKey::Discovery {
                        lane: LaneId::Answer,
                        source: DiscoverySource::Challenge,
                    },
                    10,
                    25,
                    2,
                    None,
                )
                .unwrap();
            assert_eq!(state.failures, failures);
            assert!(state.next_at > before + seconds);
            assert!(state.next_at <= now() + seconds + 1);
            assert_eq!(store.next_at(LaneId::Answer).unwrap(), work_at);
            drop(store);
            store = Store::open(&config).unwrap();
            assert_eq!(
                store
                    .read_backoff(&ReadKey::Discovery {
                        lane: LaneId::Answer,
                        source: DiscoverySource::Challenge
                    })
                    .unwrap(),
                state
            );
        }
        let before = now();
        let state = store
            .fail_read(
                &ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge,
                },
                10,
                25,
                2,
                None,
            )
            .unwrap();
        assert!(state.next_at >= before + 27);
        store
            .fail_read(&ReadKey::Identity, 10, 25, 2, None)
            .unwrap();
        store.reset_read(&ReadKey::Identity).unwrap();
        assert_eq!(
            store
                .read_backoff(&ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge
                })
                .unwrap(),
            state
        );
        store
            .reset_read(&ReadKey::Discovery {
                lane: LaneId::Answer,
                source: DiscoverySource::Challenge,
            })
            .unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store
                .read_backoff(&ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge
                })
                .unwrap(),
            ReadBackoff::default()
        );
        let restarted = store
            .fail_read(
                &ReadKey::Discovery {
                    lane: LaneId::Answer,
                    source: DiscoverySource::Challenge,
                },
                10,
                25,
                2,
                None,
            )
            .unwrap();
        assert_eq!(restarted.failures, 1);
        assert!(restarted.next_at >= now() + 12);
    }

    #[test]
    fn read_backoff_cap_never_shortens_configured_base_delay() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        for failures in 1..=3 {
            let before = now();
            let state = store
                .fail_read(
                    &ReadKey::Discovery {
                        lane: LaneId::Mine,
                        source: DiscoverySource::Challenge,
                    },
                    900,
                    100,
                    30,
                    None,
                )
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
            let gate = AccountAdmissionGuard::acquire(&config).unwrap();
            AccountLock::control_store(&config, &gate).unwrap();
            assert!(AccountLock::control_store(&alternate, &gate).is_err());
        }
        drop(owner);
        assert!(AccountLock::acquire(&alternate).is_err());
        assert!(AccountAdmissionGuard::acquire(&alternate).is_err());
        let gate = AccountAdmissionGuard::acquire(&config).unwrap();
        assert!(AccountLock::control_store(&alternate, &gate).is_err());
        AccountLock::control_store(&config, &gate).unwrap();
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
        store.set_paused_unbound(false).unwrap();
        drop(store);
        let mut store = Store::open(&config).unwrap();
        assert_eq!(
            store.control().unwrap(),
            Control {
                paused: false,
                generation: 1
            }
        );
        store.set_paused_unbound(true).unwrap();
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
                "BEFORE UPDATE OF failures ON read_state",
                HostedIdentityOutcome::AuthenticationFailed,
                403,
            ),
            (
                "BEFORE UPDATE OF local_next_at ON read_state",
                HostedIdentityOutcome::Verified,
                200,
            ),
        ] {
            let (_temp, config) = fixture();
            let store = Store::open(&config).unwrap();
            store.read_started(&ReadKey::Identity).unwrap();
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
                    None,
                )
                .unwrap();
            store.read_started(&ReadKey::Identity).unwrap();
            let before = store.status(&config).unwrap()["hosted_identity"].clone();
            let reads = store.reads_projection().unwrap()["reads"].take();
            let before_read = reads
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["purpose"] == "identity")
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
                        None,
                    )
                    .is_err()
            );
            drop(store);
            let reader = Store::read_only(&config).unwrap().unwrap();
            assert_eq!(reader.status(&config).unwrap()["hosted_identity"], before);
            let reads = reader.reads_projection().unwrap()["reads"].take();
            let after_read = reads
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["purpose"] == "identity")
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
                .complete_identity_read(Some(http), Some("http_status"), outcome, (10, 60, 0), None)
                .unwrap();
            drop(store);
            let reader = Store::read_only(&config).unwrap().unwrap();
            let status = reader.status(&config).unwrap();
            assert_eq!(status["hosted_identity"]["status"], outcome.as_str());
            assert_eq!(
                status["hosted_identity_verified"],
                outcome == HostedIdentityOutcome::Verified
            );
            let backoff = reader.read_backoff(&ReadKey::Identity).unwrap();
            if outcome == HostedIdentityOutcome::Verified {
                assert_eq!(backoff.failures, 0);
            } else {
                assert!(backoff.next_at >= started + 10);
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
    fn legacy_identity_normalization_is_audited_idempotent_and_preserves_other_evidence() {
        let (_temp, config, mut store) = participation_fixture();
        observe(&store, 42, false).unwrap();
        store
            .db
            .execute("UPDATE health_evidence SET hosted_identity_verified=0", [])
            .unwrap();
        store.read_started(&ReadKey::Identity).unwrap();
        store
            .read_finished(&ReadKey::Identity, None, Some("timeout"))
            .unwrap();
        store
            .fail_read(&ReadKey::Identity, 30, 120, 0, None)
            .unwrap();
        let op = prepared_epoch(&mut store, LaneId::Judge, 42, "captured");
        let control = store.control().unwrap();
        let operation = store.inspect(op.id).unwrap();
        let reads = store.reads_projection().unwrap()["reads"].take();
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
        assert_eq!(store.reads_projection().unwrap()["reads"], reads);
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
                store.read_started(&ReadKey::Identity).unwrap();
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
        config.capabilities.answer.mode = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        assert!(store.status(&config).unwrap()["hosted_identity_verified"].is_null());
        store.set_paused_unbound(false).unwrap();
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
        observe(&store, 54, true).unwrap();
        observe_read_only_lanes(&store).unwrap();
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
    fn pause_generation_closes_admission_even_after_resume() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        assert!(
            store
                .begin(
                    LaneId::Answer,
                    "1:word",
                    "generating",
                    &json!({}),
                    store.control().unwrap(),
                    "rev"
                )
                .is_err()
        );
        store.set_paused_unbound(false).unwrap();
        let stale = store.control().unwrap();
        store.set_paused_unbound(true).unwrap();
        store.set_paused_unbound(false).unwrap();
        assert!(
            store
                .begin(
                    LaneId::Answer,
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
        store.set_paused_unbound(false).unwrap();
        begin(&mut store, LaneId::Answer, "1:word", "generating");
        drop(store);
        let mut store = Store::open(&config).unwrap();
        store.recover().unwrap();
        assert!(store.pending().unwrap().is_none());
        assert!(store.answer_epoch_attempted(1).unwrap());
        assert!(store.attempted(LaneId::Answer, "1:word").unwrap());
        // A model cannot submit on its own; unrelated protocol work remains live.
        let op = begin(&mut store, LaneId::Mine, "2:word", "dispatching");
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
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Answer, "1:word", "prepared");
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
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Answer, "2:word", "generated");
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
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Answer, "3:word", "prepared");
        op.payload = Some(json!({"answer":"verified-history"}));
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        op.state = "included_pending".into();
        op.txid = Some("a".repeat(64));
        store.save(&op, "transaction_included_unconfirmed").unwrap();
        assert_eq!(store.history().unwrap(), vec!["verified-history"]);
        assert!(store.effect().unwrap().is_some());
        let included = store
            .admission_projection(&config, LaneId::Answer, Some(3), None)
            .unwrap();
        assert_eq!(included["own_count"], 1);
        assert_eq!(included["account_unresolved"], 1);
        op.state = "confirmed".into();
        store.save(&op, "receipt_included").unwrap();
        assert!(store.pending().unwrap().is_none());
        assert_eq!(store.history().unwrap(), vec!["verified-history"]);
        let confirmed = store
            .admission_projection(&config, LaneId::Answer, Some(3), None)
            .unwrap();
        assert_eq!(confirmed["own_count"], 0);
        assert_eq!(confirmed["account_unresolved"], 0);
        assert!(
            store
                .reconciliation_batch(LaneId::Answer)
                .unwrap()
                .iter()
                .any(|pending| pending.id == op.id)
        );
        op.state = "final".into();
        store.save(&op, "receipt_final").unwrap();
        assert!(
            store
                .reconciliation_batch(LaneId::Answer)
                .unwrap()
                .is_empty()
        );
        begin(&mut store, LaneId::Judge, "assignment", "generating");
        assert!(store.answer_epoch_attempted(3).unwrap());
    }

    #[test]
    fn proven_prelaunch_failure_is_retryable_but_unknown_is_not() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Answer, "4:word", "generating");
        op.state = "prelaunch_failed".into();
        store.save(&op, "executable_unavailable").unwrap();
        assert!(!store.answer_epoch_attempted(4).unwrap());
        let mut next = begin(&mut store, LaneId::Answer, "4:word", "generating");
        next.state = "model_unknown".into();
        store.save(&next, "model_launch_unknown").unwrap();
        assert!(store.answer_epoch_attempted(4).unwrap());
    }

    #[test]
    fn normalized_assignment_attempt_survives_restart() {
        let (_temp, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Judge, &"A".repeat(64), "prepared");
        op.state = "abstained".into();
        store.save(&op, "assignment_evidence_insufficient").unwrap();
        drop(store);
        let store = Store::open(&config).unwrap();
        assert!(store.attempted(LaneId::Judge, &"a".repeat(64)).unwrap());
        assert!(!store.attempted(LaneId::Judge, &"b".repeat(64)).unwrap());
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
        observe(&store, 54, false).unwrap();
        store
            .db
            .execute("UPDATE lane_observations SET first_observed_at=1", [])
            .unwrap();
        observe(&store, 54, false).unwrap();
        let status = store.status(&config).unwrap();
        assert_eq!(status["epoch_evidence"]["first_observed_at"], 1);
        assert_eq!(status["epoch_evidence"]["answered"], false);
        observe(&store, 54, true).unwrap();
        assert_eq!(
            store.status(&config).unwrap()["epoch_evidence"]["answered"],
            true
        );
        observe(&store, 55, false).unwrap();
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
        config.capabilities.answer.mode = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Unavailable)
            .unwrap();
        observe(&store, 54, false).unwrap();
        store
            .db
            .execute("UPDATE lane_observations SET first_observed_at=1", [])
            .unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        let options = Options {
            min_free_mib: 0,
            ..Options::default()
        };
        for answered in [false, true] {
            observe(&store, 54, answered).unwrap();
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
            observe(&store, 54, answered).unwrap();
            observe_read_only_lanes(&store).unwrap();
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
        observe(&store, 55, false).unwrap();
        observe_read_only_lanes(&store).unwrap();
        prepared_epoch(&mut store, LaneId::Answer, 55, "current_challenge");
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
        let report = health::check(&config, options).unwrap();
        assert_eq!(report["healthy"], true, "{report}");
    }

    #[test]
    fn health_is_read_only_and_current_lifecycle_overrides_old_stop() {
        use crate::health::{self, Options};
        let (_temp, mut config) = fixture();
        config.capabilities.answer.mode = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        store.runtime_state(&config, false).unwrap();
        store
            .record_identity_outcome(HostedIdentityOutcome::Verified)
            .unwrap();
        observe(&store, 54, true).unwrap();
        observe_read_only_lanes(&store).unwrap();
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
        let report = health::check(&config, options).unwrap();
        assert_eq!(report["healthy"], true, "{report}");
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

    pub(super) fn bound_fixture() -> (tempfile::TempDir, Config) {
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
        store.set_paused_unbound(false).unwrap();
        let mut answer = begin(&mut store, LaneId::Answer, "1:words", "prepared");
        let mut judge = begin(&mut store, LaneId::Judge, &"a".repeat(64), "prepared");
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
        assert!(
            AccountAdmissionGuard::for_control(&config)
                .and_then(|gate| AccountLock::control_store(&config, &gate))
                .is_err()
        );
        assert!(Store::open(&config).is_err());
        assert!(Store::read_only(&config).is_err());
        assert!(!config.state_dir.join("state.sqlite3").exists());
        remove_anchors(&config);
    }

    #[test]
    fn independent_dispatch_witness_detects_database_only_rollback() {
        let (dir, config) = bound_fixture();
        let (lock, mut store) = AccountLock::acquire(&config).unwrap();
        store
            .set_paused(false, &AccountAdmissionGuard::acquire(&config).unwrap())
            .unwrap();
        let backup = fs::canonicalize(dir.path()).unwrap().join("before.sqlite3");
        store
            .db
            .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
            .unwrap();
        let mut op = begin(&mut store, LaneId::Mine, "1", "prepared");
        op.state = "dispatching".into();
        store.save(&op, "dispatch_intent").unwrap();
        let binding = read_binding(&config).unwrap().unwrap();
        assert_eq!(binding.dispatch_sequence, 1);
        drop(store);
        drop(lock);
        fs::copy(backup, config.state_dir.join("state.sqlite3")).unwrap();
        assert!(AccountLock::acquire(&config).is_err());
        assert!(
            AccountAdmissionGuard::for_control(&config)
                .and_then(|gate| AccountLock::control_store(&config, &gate))
                .is_err()
        );
        remove_anchors(&config);
    }

    #[test]
    fn journal_ahead_crash_gap_preserves_unknown_and_advances_witness() {
        let (_dir, config) = bound_fixture();
        drop(AccountLock::acquire(&config).unwrap());
        // A Store without attached binding simulates death after SQLite commit,
        // before witness advancement; production dispatch cannot cross that gap.
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Mine, "1", "prepared");
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
    fn adoption_requires_an_existing_initialized_journal() {
        let (_dir, config) = bound_fixture();
        let adopted = AccountLock::adopt(&config).is_ok();
        let initialized = config.state_dir.join("state.sqlite3").exists();
        remove_anchors(&config);
        assert!(!adopted);
        assert!(!initialized);
    }

    #[test]
    fn unanchored_schema3_requires_explicit_adoption() {
        let (_dir, config) = bound_fixture();
        let store = Store::open(&config).unwrap();
        let identity = store.database_identity().unwrap();
        drop(store);
        let acquired = AccountLock::acquire(&config).is_ok();
        let controlled = AccountAdmissionGuard::for_control(&config)
            .and_then(|gate| AccountLock::control_store(&config, &gate))
            .is_ok();
        remove_anchors(&config);
        assert!(!acquired && !controlled);
        let (lock, adopted) = AccountLock::adopt(&config).unwrap();
        assert_eq!(adopted.database_identity().unwrap(), identity);
        drop(adopted);
        drop(lock);
        remove_anchors(&config);
    }

    #[test]
    fn missing_schema3_authority_is_not_recreated() {
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
        config.capabilities.answer.preparation.max_attempts_per_work = CountLimit::Bounded(2);
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        let mut model = begin(&mut store, LaneId::Answer, "1:word", "generating");
        model.state = "model_unknown".into();
        store.save(&model, "model_launch_unknown").unwrap();
        let mut effect = begin(&mut store, LaneId::Judge, &"A".repeat(64), "prepared");
        effect.state = "dispatching".into();
        store.save(&effect, "dispatch_intent").unwrap();
        effect.state = "unknown".into();
        store.save(&effect, "dispatch_outcome_unknown").unwrap();
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(model.id).unwrap().unwrap().state,
            "model_unknown"
        );
        config.capabilities.answer.preparation.retry_uncertain = true;
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(model.id).unwrap().unwrap().state,
            "superseded_model_unknown"
        );
        assert_eq!(store.effect().unwrap().unwrap().id, effect.id);
        assert!(store.attempted(LaneId::Judge, &"a".repeat(64)).unwrap());
        let mut retry = begin(&mut store, LaneId::Answer, "1:word", "generating");
        retry.state = "model_unknown".into();
        store.save(&retry, "model_launch_unknown").unwrap();
        store.retry_models(&config).unwrap();
        assert_eq!(
            store.operation(retry.id).unwrap().unwrap().state,
            "model_unknown"
        );
    }

    #[test]
    fn missing_independent_binding_is_not_silently_readopted() {
        let (_dir, config) = bound_fixture();
        drop(AccountLock::acquire(&config).unwrap());
        fs::remove_file(lock_path(&config, "binding").unwrap()).unwrap();
        assert!(AccountLock::acquire(&config).is_err());
        assert!(
            AccountAdmissionGuard::for_control(&config)
                .and_then(|gate| AccountLock::control_store(&config, &gate))
                .is_err()
        );
        assert!(Store::read_only(&config).is_err());
        remove_anchors(&config);
    }

    #[test]
    fn unchanged_observation_retains_transition_age_and_private_candidates() {
        let (_dir, config) = fixture();
        let mut store = Store::open(&config).unwrap();
        store.set_paused_unbound(false).unwrap();
        let mut op = begin(&mut store, LaneId::Mine, "1", "prepared");
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
