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
mod epoch;
mod inspection;
pub mod migration;
mod projection;
pub(crate) use projection::{JudgeInventory, judge_inventory};
mod reads;
mod schema;
pub(crate) use reads::{
    DiscoverySource, LaneObservation, LaneObservationStamp, ReadKey, ReconciliationPass,
};
use schema::initialize_schema;
#[cfg(test)]
mod atomic_tests;
#[cfg(test)]
mod writer_continuity_tests;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationProvenance {
    binding_revision: i64,
    bound_since: Option<i64>,
    first_observed_at: i64,
    consecutive_404: u8,
    last_result_at: Option<i64>,
    last_status: Option<u16>,
    #[serde(default)]
    observer_authority_epoch: Option<u64>,
    #[serde(default)]
    active_request_sequence: Option<u64>,
}

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

#[derive(Debug)]
struct MissingRefusalOperation;
impl std::fmt::Display for MissingRefusalOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("operation not found")
    }
}
impl std::error::Error for MissingRefusalOperation {}

/// Local-only extension of recover resolve. A preview never opens a writer;
/// application requires its exact snapshot token and excludes a live controller.
pub fn recovery_refusal(config_path: &Path, operation: i64, apply: Option<&str>) -> Result<Value> {
    let _configuration = crate::admin::lock_config_directory(config_path)?;
    let config = Config::load_metadata(config_path)?;
    let store = Store::read_only(&config)?.context("journal not initialized")?;
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

/// Apply only the frozen preview. The stopped-writer guards and each operation's
/// token determine whether that exact candidate can still be repaired.
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
        "restoration":{"manager_action":"none","runtime":"unchanged","verified":null}});
    let Some(store) = Store::read_only(&config)? else {
        if apply.is_some() {
            return Err(RefusalRecoveryError("refusal_recovery_conflict").into());
        }
        return Ok(report);
    };
    store.routing_change_allowed(&config)?;
    let Some(apply) = apply else {
        let snapshot = store.db.unchecked_transaction()?;
        let (mut eligible, ineligible) = Store::refusal_candidates(&snapshot, &revision)?;
        let (identity, _) = Store::identity_normalization_preview(&snapshot, &revision)?;
        if identity["eligible"] == true {
            eligible.push(identity);
        }
        report["eligible"] = Value::Array(eligible);
        report["ineligible"] = Value::Array(ineligible);
        snapshot.commit()?;
        return Ok(report);
    };
    let eligible = apply["eligible"]
        .as_array()
        .context(RefusalRecoveryError("repair_report_invalid"))?;
    // Writer acquisition may bind a new routing profile. That must not reset
    // observations as a side effect of local identity normalization.
    if eligible.iter().any(|row| row["kind"] == "identity")
        && store.routing_status(&config)?["matches_config"] != true
    {
        return Err(RefusalRecoveryError("identity_evidence_changed").into());
    }
    drop(store);
    let (_account, mut store) = AccountLock::acquire(&config)
        .map_err(|error| error.context(RefusalRecoveryError("doctor_account_unavailable")))?;
    let _gate = AccountAdmissionGuard::acquire(&config)?;
    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    let mut failure = None;
    for preview in eligible {
        if failure.is_some() {
            skipped.push(skipped_doctor_repair(preview, "earlier_repair_failed"));
            continue;
        }
        let identity = preview["kind"] == "identity";
        let result = match (
            identity,
            preview["operation_id"].as_i64(),
            preview["preview_token"].as_str(),
        ) {
            (true, _, Some(token)) => store.normalize_legacy_identity(&revision, token),
            (false, Some(id), Some(token)) => store.resolve_refusal(id, &revision, token),
            _ => Err(RefusalRecoveryError("repair_report_invalid").into()),
        };
        match result {
            Ok(result) if result["applied"] == true => applied.push(result),
            Ok(result) => skipped.push(result),
            Err(error) => {
                let code = if let Some(error) = error.downcast_ref::<RefusalRecoveryError>() {
                    error.0
                } else if identity {
                    "identity_normalization_failed"
                } else if error.downcast_ref::<MissingRefusalOperation>().is_some() {
                    "refusal_recovery_ineligible"
                } else {
                    "refusal_recovery_failed"
                };
                if !matches!(
                    code,
                    "identity_evidence_changed"
                        | "refusal_recovery_conflict"
                        | "refusal_recovery_ineligible"
                ) {
                    failure = Some(code);
                }
                skipped.push(skipped_doctor_repair(preview, code));
            }
        }
    }
    report["applied"] = Value::Array(applied);
    report["skipped"] = Value::Array(skipped);
    report["failure"] = json!(failure);
    report["execution"] = json!(if failure.is_some() {
        "partial"
    } else {
        "complete"
    });
    Ok(report)
}

pub(crate) fn skipped_doctor_repair(preview: &Value, reason: &str) -> Value {
    json!({"operation_id":preview["operation_id"],"kind":preview["kind"],
        "classification":preview["classification"],"eligible":false,"applied":false,"reason":reason})
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

pub(super) fn check_sqlite_has_moved(db: &Connection) -> Result<()> {
    let mut moved: std::ffi::c_int = 0;
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            db.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            (&mut moved as *mut std::ffi::c_int).cast(),
        )
    };
    if rc == rusqlite::ffi::SQLITE_OK {
        if moved != 0 {
            bail!("bound journal file moved or unlinked");
        }
        return Ok(());
    }
    if rc == rusqlite::ffi::SQLITE_NOTFOUND {
        return Ok(());
    }
    bail!("cannot verify SQLite journal file continuity (rc={rc})");
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
        crate::protocol::BOUND_JOB_EXPIRY_CONFLICT => crate::protocol::BOUND_JOB_EXPIRY_CONFLICT,
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
// Drive from operation_links so SQLite does not scan every finalized answer.
const HISTORICAL_ANSWERS: &str = "
    SELECT original.id AS operation_id,MIN(accepted.id) AS accepted_answer_id
    FROM operation_links link
    CROSS JOIN operations original ON original.id=link.retry_of
    CROSS JOIN operation_evidence evidence ON evidence.operation_id=original.id
    CROSS JOIN operations accepted ON accepted.id=link.operation_id
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
    restriction_basis: Option<&'static str>,
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

    /// Identity of the database file actually read by this store: the
    /// authoritative content id from the open connection plus the file object
    /// identity observed around the open. Diagnostics must match a process
    /// bracket against this identity, never against a path heartbeat alone.
    /// Missing file identity reports nulls and never grants attribution.
    ///
    /// On unix the identity is verified against the actual open handle at
    /// projection time, not just the open-time stat: the bundled unix VFS
    /// reports whether the path was renamed, moved, deleted, or replaced
    /// since this connection opened it (SQLITE_FCNTL_HAS_MOVED), and the live
    /// path must still resolve to the pinned file object. An unavailable
    /// handle answer or any mismatch fails closed instead of attributing a
    /// different database. The content id is selected on this same handle, so
    /// callers holding the snapshot transaction across the projection keep
    /// the rows and the identity describing one view.
    pub(crate) fn journal_identity(&self) -> Result<Value> {
        let (database_id, _) = self.database_identity()?;
        #[cfg(unix)]
        let (device, inode) = match &self.database_file {
            Some((path, expected)) => {
                use std::os::unix::fs::MetadataExt;
                let mut moved: std::os::raw::c_int = 0;
                self.db
                    .file_control(Some("main"), rusqlite::FileControl::HasMoved(&mut moved))
                    .context("journal handle identity unavailable")?;
                if moved != 0 {
                    bail!("journal moved since open; reread local state");
                }
                let current = fs::symlink_metadata(path)?;
                if !same_journal_file(&current, expected) {
                    bail!("journal replaced since open; reread local state");
                }
                (Some(expected.dev()), Some(expected.ino()))
            }
            None => (None, None),
        };
        #[cfg(not(unix))]
        let (device, inode): (Option<u64>, Option<u64>) = (None, None);
        Ok(json!({"database_id": database_id, "device": device, "inode": inode}))
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
        check_sqlite_has_moved(db).context("bound journal continuity lost")?;
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
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = {
            let mut attempt = 0_u8;
            loop {
                match db.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                }) {
                    Ok(version) => break version,
                    Err(rusqlite::Error::SqliteFailure(err, _))
                        if attempt < 20
                            && (err.extended_code == rusqlite::ffi::SQLITE_READONLY_RECOVERY
                                || matches!(
                                    err.code,
                                    rusqlite::ErrorCode::DatabaseBusy
                                        | rusqlite::ErrorCode::DatabaseLocked
                                )) =>
                    {
                        attempt += 1;
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        };
        if version != CURRENT_JOURNAL_FORMAT {
            bail!("unsupported state schema; stop the runtime and use explicit migration");
        }
        // Pin the file object actually opened: a path swap between the
        // pre-open stat and the first read must fail closed, never attribute
        // the bracket to a different database.
        let reopened = fs::symlink_metadata(&path)?;
        #[cfg(unix)]
        {
            if !same_journal_file(&metadata, &reopened) {
                bail!("journal replaced during open; reread local state");
            }
        }
        check_sqlite_has_moved(&db)?;
        let store = Self {
            db,
            binding: None,
            writer_path: None,
            database_file: Some((path, reopened)),
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
        let existing_metadata = existing
            .as_ref()
            .and_then(|s| s.database_file.as_ref().map(|(_, m)| m.clone()));
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
        let opened_metadata = fs::symlink_metadata(&path)?;
        validate_private_file(&opened_metadata)?;
        if let Some(expected) = &existing_metadata
            && !same_journal_file(expected, &opened_metadata)
        {
            bail!("journal replaced between inspection and writable open");
        }
        check_sqlite_has_moved(&db)?;
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
        if !fresh && !schema::query_indexes_present(&store.db)? {
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

    /// Commit only the recorded update transition. Re-entry after an uncertain
    /// acknowledgment accepts its exact post-state without repeating control.
    pub(crate) fn restore_update_pause(
        &mut self,
        database_id: &str,
        expected_generation: i64,
        expected_paused: bool,
        desired_paused: bool,
        account: &AccountAdmissionGuard,
    ) -> Result<Value> {
        if expected_generation < 0 {
            bail!("update restoration has an invalid generation");
        }
        let post_generation = if expected_paused == desired_paused {
            expected_generation
        } else {
            expected_generation
                .checked_add(1)
                .context("update restoration generation exhausted")?
        };
        self.check_pause_guard(account)?;
        self.continuity()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        account.validated_binding()?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        let id: String = tx.query_row(
            "SELECT database_id FROM authority WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if id != database_id {
            bail!("update restoration database identity conflict");
        }
        let (paused, generation): (bool, i64) = tx.query_row(
            "SELECT paused,generation FROM control WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let before = paused == expected_paused && generation == expected_generation;
        let already_applied = !before && paused == desired_paused && generation == post_generation;
        if !before && !already_applied {
            bail!("update restoration control conflict");
        }
        let applied = before && expected_paused != desired_paused;
        if applied {
            Self::write_pause(&tx, desired_paused)?;
        }
        account.validated_binding()?;
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit().context(
            "update restoration commit uncertain; retry only the same conditional transition",
        )?;
        self.check_pause_guard(account)
            .and_then(|()| self.continuity())
            .context(
                "update restoration commit uncertain; retry only the same conditional transition",
            )?;
        Ok(json!({"paused":desired_paused,"generation":post_generation,
            "applied":applied,"already_applied":already_applied}))
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
        Self::recover_legacy_grade_abstention(&tx)?;
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
        let event = match state {
            "generating" | "prepared" => state,
            "abstained" if kind == LaneId::Judge && retry.is_none() => {
                "assignment_evidence_insufficient"
            }
            _ => bail!("invalid initial operation state"),
        };
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
            params![now(), event, kind.as_str(), id],
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
                        params![op.id,serde_json::to_string(&json!({"lane":op.kind,
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
                captured["dispatch_policy"] = json!({"lane":op.kind,
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
            Self::capture_reconciliation_binding(
                tx,
                op.id,
                binding_revision,
                op.job_id.is_some()
                    && op.txid.is_none()
                    && matches!(target_state, "queued" | "unknown"),
                now(),
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
        Self::capture_and_trim_transition_events(tx)?;
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
        if Self::answer_job_expiry_conflict_in(db, epoch)? {
            return Ok(Some(crate::protocol::BOUND_JOB_EXPIRY_CONFLICT));
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
                if accounting.restriction_basis == Some("retained_legacy_floor") {
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

    fn capture_reconciliation_binding(
        db: &Connection,
        operation_id: i64,
        binding_revision: i64,
        bound_job: bool,
        at: i64,
    ) -> Result<()> {
        let saved: Option<String> = db
            .query_row(
                "SELECT policy FROM operation_evidence WHERE operation_id=?1",
                [operation_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if !bound_job && saved.is_none() {
            return Ok(());
        }
        let mut policy: Value = saved
            .map(|text| serde_json::from_str(&text))
            .transpose()?
            .unwrap_or_else(|| json!({}));
        let object = policy
            .as_object_mut()
            .context("captured operation policy is not an object")?;
        if bound_job {
            object.insert(
                "reconciliation".into(),
                serde_json::to_value(ReconciliationProvenance {
                    binding_revision,
                    bound_since: Some(at),
                    first_observed_at: at,
                    consecutive_404: 0,
                    last_result_at: None,
                    last_status: None,
                    observer_authority_epoch: None,
                    active_request_sequence: None,
                })?,
            );
        } else if object.remove("reconciliation").is_none() {
            return Ok(());
        }
        db.execute(
            "INSERT INTO operation_evidence(operation_id,policy) VALUES (?1,?2)
             ON CONFLICT(operation_id) DO UPDATE SET policy=excluded.policy",
            params![operation_id, serde_json::to_string(&policy)?],
        )?;
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
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
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
        Self::attempted_in(&self.db, kind, key)
    }

    fn attempted_in(db: &Connection, kind: LaneId, key: &str) -> Result<bool> {
        Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE kind=?1 AND work_key=?2 COLLATE NOCASE AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model','retry_model','superseded_model_unknown'))",
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

    fn capture_and_trim_transition_events(db: &Connection) -> Result<()> {
        Self::capture_work_revision(db)?;
        db.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )?;
        Ok(())
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

    #[cfg(test)]
    pub(crate) fn runtime_state(&self, config: &Config, reload_blocked: bool) -> Result<()> {
        self.runtime_state_with_mode(config, reload_blocked, false)
    }

    pub(crate) fn runtime_state_with_mode(
        &self,
        config: &Config,
        reload_blocked: bool,
        once: bool,
    ) -> Result<()> {
        self.runtime_state_for_instance(config, reload_blocked, once, None)
    }

    pub(crate) fn runtime_state_for_instance(
        &self,
        config: &Config,
        reload_blocked: bool,
        once: bool,
        instance: Option<&str>,
    ) -> Result<()> {
        self.continuity()?;
        // Reserve the writer before reading metadata that concurrent lane controls can change.
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let mut policy = json!({"capabilities":config.capabilities,
            "identity":config.identity,"runtime":config.runtime,"build":crate::runtime::build_info()});
        let (authority_epoch, stored_instance, account_generation): (
            Option<u64>,
            Option<String>,
            i64,
        ) = tx.query_row(
            "SELECT (SELECT authority_epoch FROM runtime_authority WHERE singleton=1),
                    (SELECT runtime_instance FROM runtime_state WHERE singleton=1),
                    generation FROM control WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let runtime_instance = instance.map(str::to_owned).or(stored_instance);
        policy["process"] = json!({
            "pid":std::process::id(),
            "start_ticks":crate::installer::current_start_ticks(),
            "run_mode": if once { "once" } else { "continuous" },
            "authority_epoch":authority_epoch,
            "runtime_instance":runtime_instance,
            "account_generation":account_generation,
            "invocation_id":std::env::var("INVOCATION_ID").ok().filter(|id|
                id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        });
        policy["update_background"] = crate::update::advisory::background_policy();
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
            "INSERT INTO runtime_state(singleton,effective_revision,reload_blocked,capabilities,observed_at,runtime_instance,controller_stopped)
             VALUES (1,?1,?2,?3,?4,?5,0) ON CONFLICT(singleton) DO UPDATE SET
            effective_revision=excluded.effective_revision,reload_blocked=excluded.reload_blocked,
            capabilities=excluded.capabilities,observed_at=excluded.observed_at,
            runtime_instance=COALESCE(excluded.runtime_instance,runtime_state.runtime_instance),
            controller_stopped=0",
            params![
                config.revision()?,
                reload_blocked,
                serde_json::to_string(&config.capabilities)?,
                now(),
                instance
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
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
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
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
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
            .context(MissingRefusalOperation)?;
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
        let policy = self.db.query_row("SELECT policy,evidence,dispatch_sequence,blocked_since,resolution FROM operation_evidence WHERE operation_id=?1",
            [id], |r| Ok(json!({"captured_policy":r.get::<_,Option<String>>(0)?,
                "evidence":r.get::<_,Option<String>>(1)?,"dispatch_sequence":r.get::<_,Option<i64>>(2)?,
                "blocked_since":r.get::<_,Option<i64>>(3)?,"resolution":r.get::<_,Option<String>>(4)?}))).optional()?;
        let candidates = self
            .db
            .query_row(
                "SELECT candidates,truncated FROM operation_candidates WHERE operation_id=?1",
                [id],
                |r| {
                    Ok(json!({"untrusted":true,"candidates":r.get::<_,String>(0)?,
                "truncated":r.get::<_,bool>(1)?}))
                },
            )
            .optional()?;
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
        config: &Config,
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
            "SELECT o.id,o.kind,o.state,
                CASE WHEN json_type(o.request,'$.solver.epoch')='integer'
                     AND json_extract(o.request,'$.solver.epoch')>=0
                     THEN json_extract(o.request,'$.solver.epoch') END,
                o.created_at,o.updated_at,o.next_at,o.generation,
                o.job_id IS NOT NULL,o.txid IS NOT NULL,{link_columns},{evidence_columns},{timing_column},{model_column}
            FROM operations o {link_join} {evidence_join} {timing_join}
            WHERE (?1 IS NULL OR o.kind=?1) AND (?2 IS NULL OR o.state=?2)
                AND (?3 IS NULL OR o.id<?3) ORDER BY o.id DESC LIMIT ?4",
        ))?;
        let rows = statement.query_map(
            params![kind.map(|k| k.as_str()),state,before,(limit+1) as i64],
            |r| Ok((json!({
                "operation_id":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,
                "state":r.get::<_,String>(2)?,"epoch":r.get::<_,Option<u64>>(3)?,
                "created_at":r.get::<_,i64>(4)?,
                "updated_at":r.get::<_,i64>(5)?,"next_at":r.get::<_,i64>(6)?,
                "generation":r.get::<_,i64>(7)?,"has_job_id":r.get::<_,bool>(8)?,
                "has_txid":r.get::<_,bool>(9)?,"retry_of":r.get::<_,Option<i64>>(10)?,
                "payload_reused":r.get::<_,bool>(11)?,"blocked_since":r.get::<_,Option<i64>>(12)?,
                "model_deadline":r.get::<_,Option<i64>>(13)?,"http_deadline":r.get::<_,Option<i64>>(14)?,
                "retry_not_before":r.get::<_,Option<i64>>(15)?,
            }),r.get::<_,Option<String>>(16)?)),
        )?;
        let mut operations = Vec::with_capacity(limit);
        let mut more = false;
        for row in rows {
            let (mut operation, model_attempt) = row?;
            if operations.len() == limit {
                more = true;
                break;
            }
            operation["model_attempt"] = model_attempt
                .map(|value| serde_json::from_str::<Value>(&value))
                .transpose()?
                .unwrap_or(Value::Null);
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
        let ids: Vec<_> = operations
            .iter()
            .filter_map(|row| row["operation_id"].as_i64())
            .collect();
        let inspections = self.operation_inspection(config, &ids, current)?;
        if inspections.len() != operations.len() {
            bail!("operation inspection snapshot is incomplete");
        }
        for (row, inspection) in operations.iter_mut().zip(inspections) {
            if row["operation_id"].as_i64() != Some(inspection.operation_id) {
                bail!("operation inspection snapshot mismatch");
            }
            row["mining"] = inspection.mining;
            row["reconciliation"] = inspection.reconciliation;
        }
        let next_before = more
            .then(|| operations.last().and_then(|op| op["operation_id"].as_i64()))
            .flatten();
        snapshot.commit()?;
        Ok(json!({"operations":operations,"next_before":next_before}))
    }

    pub(crate) fn grants(&self, before: Option<i64>, limit: usize) -> Result<Value> {
        validate_page(before, limit)?;
        let snapshot = self.db.unchecked_transaction()?;
        let control = self.control()?;
        let mut statement = self.db.prepare(
            "SELECT g.id,g.epoch,g.kind,g.generation,g.created_at,g.consumed_by,r.revoked_at,
                g.lane_control_revision,COALESCE(g.lane_control_revision=l.control_revision,0)
            FROM manual_grants g LEFT JOIN lane_control l ON l.lane=g.kind
            LEFT JOIN manual_grant_revocations r ON r.grant_id=g.id
            WHERE (?1 IS NULL OR g.id<?1) ORDER BY g.id DESC LIMIT ?2",
        )?;
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
mod tests;
