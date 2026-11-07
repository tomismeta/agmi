use crate::config::{Config, Mode, Participation, ParticipationMode, WorkKind};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// SQLite may see a new inode only after its raw creation descriptor is closed.
static DATABASE_OPEN: Mutex<()> = Mutex::new(());

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
fn account_home() -> Result<PathBuf> {
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

/// Read failures are independent of normal work cadence and shared by callers
/// of the same endpoint class, including answer/mine challenge observations.
#[derive(Clone, Copy)]
pub(crate) enum ReadScope {
    Challenge,
    Identity,
    Assignments,
    AssignmentEvidence,
    Job,
    Receipt,
}

impl ReadScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Identity => "identity",
            Self::Assignments => "assignments",
            Self::AssignmentEvidence => "assignment_evidence",
            Self::Job => "job",
            Self::Receipt => "receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadBackoff {
    pub failures: u32,
    pub next_at: i64,
}

pub(crate) struct Store {
    db: Connection,
    binding: Option<(PathBuf, Binding)>,
    writer_path: Option<(PathBuf, fs::Metadata)>,
    database_file: Option<(PathBuf, fs::Metadata)>,
}

struct RiskDecision {
    blockers: Vec<i64>,
    retry_of: Option<i64>,
    grant: Option<i64>,
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
        private_dir(&config.state_dir)?;
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
             CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, at INTEGER NOT NULL, code TEXT NOT NULL,
                kind TEXT, operation_id INTEGER);
             CREATE TABLE IF NOT EXISTS schedule (kind TEXT PRIMARY KEY, next_at INTEGER NOT NULL, cursor TEXT);
             CREATE TABLE IF NOT EXISTS read_backoff (
                scope TEXT PRIMARY KEY, failures INTEGER NOT NULL, next_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS observation (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                epoch INTEGER NOT NULL, observed_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS runtime_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                effective_revision TEXT NOT NULL, reload_blocked INTEGER NOT NULL,
                capabilities TEXT NOT NULL, observed_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS health_evidence (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                hosted_identity_verified INTEGER CHECK(hosted_identity_verified IN (0,1)),
                epoch INTEGER, first_observed_at INTEGER,
                answered INTEGER CHECK(answered IN (0,1)));"
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
             UPDATE operations SET work_key=lower(work_key) WHERE kind='judge' AND length(work_key)=64;
             UPDATE operations SET txid=lower(txid) WHERE length(txid)=64;
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
                if !decision.blockers.is_empty() || decision.retry_of.is_some() {
                    tx.execute(
                        "INSERT INTO risk_admissions
                        VALUES ((SELECT dispatch_sequence FROM authority WHERE singleton=1),?1,?2,?3,?4,?5,?6,?7)",
                        params![op.id,serde_json::to_string(&config.participation)?,config.revision()?,
                            serde_json::to_string(&decision.blockers)?,decision.retry_of,decision.grant,now()],
                    )?;
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

    fn risk_decision(
        db: &Connection,
        config: &Config,
        op: &Operation,
    ) -> Result<Option<RiskDecision>> {
        let reload_blocked: bool = db.query_row(
            "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)",
            [],
            |r| r.get(0),
        )?;
        if reload_blocked {
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
        let mut statement = db.prepare(
            "SELECT o.id,o.state,COALESCE(e.blocked_since,o.created_at),
                COALESCE(t.retry_not_before,o.next_at)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            LEFT JOIN operation_timing t ON t.operation_id=o.id
            WHERE o.id!=?1 AND o.state IN ('dispatching','queued','unknown','included_pending') ORDER BY o.id",
        )?;
        let effects = statement
            .query_map([op.id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if effects.len() as u64 + 1 > u64::from(policy.max_unresolved_operations)
            || effects.iter().any(|e| e.1 == "dispatching" || e.3 > now())
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
                AND (e.dispatch_sequence IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final'))",
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
            blockers: effects.iter().map(|e| e.0).collect(),
            retry_of,
            grant: None,
        };
        if effects.is_empty() && retry_of.is_none() {
            return Ok(Some(decision));
        }
        if policy.mode == ParticipationMode::Strict || !policy.allows(op.kind) {
            return Ok(None);
        }
        if effects.iter().any(|e| {
            Some(e.0) == retry_of
                && e.2.saturating_add(
                    i64::try_from(policy.uncertain_answer_retry_seconds).unwrap_or(i64::MAX),
                ) > now()
        }) {
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
        } else if effects.iter().any(|e| {
            let grace = if Some(e.0) == retry_of {
                policy
                    .uncertainty_grace_seconds
                    .max(policy.uncertain_answer_retry_seconds)
            } else {
                policy.uncertainty_grace_seconds
            };
            e.2.saturating_add(i64::try_from(grace).unwrap_or(i64::MAX)) > now()
        }) {
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
        if unresolved + 1 > u64::from(config.participation.max_unresolved_operations) {
            bail!("manual authorization exceeds unresolved operation limit");
        }
        let (attempts,accepted,uncertain): (u32,bool,bool) = tx.query_row(
            "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0),
            COALESCE(MAX(o.state IN ('dispatching','queued','unknown','included_pending')),0)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind=?1 AND o.work_key LIKE ?2
            AND (e.dispatch_sequence IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final'))",
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
        if config.participation.mode == ParticipationMode::Strict
            || !config.participation.retry_uncertain_answers
            || !config.participation.allow_answer
        {
            return Ok(false);
        }
        let control = self.control()?;
        if control.paused || config.mode(WorkKind::Answer) != Mode::Active {
            return Ok(false);
        }
        // The regular admission helper reads linkage from durable operations. For
        // preparation, use the existing epoch budget and blocker bounds directly.
        let epoch = original.request["solver"]["epoch"]
            .as_u64()
            .context("answer epoch missing")?;
        let (attempts,accepted): (u32,bool) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(MAX(o.txid IS NOT NULL OR o.state IN ('included_pending','confirmed','final')),0)
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE o.kind='answer' AND o.work_key LIKE ?1
            AND (e.dispatch_sequence IS NOT NULL OR o.state IN ('dispatching','queued','unknown','included_pending','confirmed','final'))",
            [format!("{epoch}:%")], |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        let eligible = !accepted
            && attempts < config.participation.max_answer_attempts_per_epoch
            && self.uncertainty_open(config, WorkKind::Answer, Some(epoch), Some(original.id))?;
        Ok(eligible)
    }

    fn uncertainty_open(
        &self,
        config: &Config,
        kind: WorkKind,
        epoch: Option<u64>,
        retry_of: Option<i64>,
    ) -> Result<bool> {
        let policy = &config.participation;
        let mut statement = self.db.prepare(
            "SELECT o.id,o.state,COALESCE(e.blocked_since,o.created_at),
            COALESCE(t.retry_not_before,o.next_at) FROM operations o
            LEFT JOIN operation_evidence e ON e.operation_id=o.id
            LEFT JOIN operation_timing t ON t.operation_id=o.id
            WHERE o.state IN ('dispatching','queued','unknown','included_pending')",
        )?;
        let effects = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if effects.is_empty() {
            return Ok(true);
        }
        if policy.mode == ParticipationMode::Strict
            || !policy.allows(kind)
            || effects.len() as u64 + 1 > u64::from(policy.max_unresolved_operations)
            || effects.iter().any(|e| e.1 == "dispatching" || e.3 > now())
        {
            return Ok(false);
        }
        if effects.iter().any(|e| {
            Some(e.0) == retry_of
                && e.2.saturating_add(
                    i64::try_from(policy.uncertain_answer_retry_seconds).unwrap_or(i64::MAX),
                ) > now()
        }) {
            return Ok(false);
        }
        if policy.mode == ParticipationMode::Manual {
            let Some(epoch) = epoch else { return Ok(false) };
            return Ok(self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM manual_grants WHERE epoch=?1 AND kind=?2 AND generation=?3 AND consumed_by IS NULL
                AND NOT EXISTS(SELECT 1 FROM manual_grant_revocations WHERE grant_id=manual_grants.id))",
                params![i64::try_from(epoch)?,kind.as_str(),self.control()?.generation], |r| r.get(0),
            )?);
        }
        Ok(effects.iter().all(|e| {
            let grace = if retry_of == Some(e.0) {
                policy
                    .uncertainty_grace_seconds
                    .max(policy.uncertain_answer_retry_seconds)
            } else {
                policy.uncertainty_grace_seconds
            };
            e.2.saturating_add(i64::try_from(grace).unwrap_or(i64::MAX)) <= now()
        }))
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
            ('dispatching','retry','queued','unknown','included_pending','confirmed','final','completed','rejected','stale')
            OR (o.state='discarded' AND e.operation_id IS NULL AND
                (EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code='dispatch_intent')
                OR NOT EXISTS(SELECT 1 FROM events WHERE operation_id=o.id AND code='prepared')))))",
            params![format!("{epoch}:%"),excluding], |r| r.get(0),
        )?)
    }

    /// At most two bound requests per cycle; a durable cursor survives restarts.
    pub(crate) fn reconciliation_batch(&self) -> Result<Vec<Operation>> {
        let cursor: i64 = self.db.query_row(
            "SELECT COALESCE(CAST(cursor AS INTEGER),0) FROM schedule WHERE kind='reconciliation'",
            [], |r| r.get(0),
        ).optional()?.unwrap_or(0);
        let mut statement = self.db.prepare(
            "SELECT id FROM operations WHERE state IN ('queued','unknown','included_pending')
            AND (job_id IS NOT NULL OR txid IS NOT NULL) AND next_at<=?1
            ORDER BY CASE WHEN id>?2 THEN 0 ELSE 1 END,id LIMIT 2",
        )?;
        let ids = statement
            .query_map(params![now(), cursor], |r| r.get::<_, i64>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if let Some(last) = ids.last() {
            self.db.execute(
                "INSERT INTO schedule(kind,next_at,cursor) VALUES ('reconciliation',0,?1)
                ON CONFLICT(kind) DO UPDATE SET cursor=excluded.cursor",
                [last.to_string()],
            )?;
        }
        ids.into_iter()
            .map(|id| {
                self.operation(id)?
                    .context("reconciliation operation missing")
            })
            .collect()
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
        let failures = self.read_backoff(scope)?.failures.saturating_add(1);
        let multiplier = 1_u64.checked_shl(failures - 1).unwrap_or(u64::MAX);
        let seconds = retry_seconds
            .saturating_mul(multiplier)
            .min(cap_seconds.max(retry_seconds))
            .max(server_minimum.unwrap_or(0))
            .saturating_add(jitter_seconds);
        let state = ReadBackoff {
            failures,
            next_at: not_before(seconds),
        };
        self.db.execute(
            "INSERT INTO read_backoff(scope,failures,next_at) VALUES (?1,?2,?3)
             ON CONFLICT(scope) DO UPDATE SET failures=excluded.failures,next_at=excluded.next_at",
            params![scope.as_str(), state.failures, state.next_at],
        )?;
        Ok(state)
    }

    pub(crate) fn reset_read(&self, scope: ReadScope) -> Result<()> {
        self.db
            .execute("DELETE FROM read_backoff WHERE scope=?1", [scope.as_str()])?;
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

    /// Latest hosted identity result, independent of bounded diagnostic events.
    /// This is persisted evidence, not a live verification or freshness guarantee.
    pub(crate) fn record_hosted_identity(&self, verified: bool) -> Result<()> {
        self.db.execute(
            "INSERT INTO health_evidence(singleton,hosted_identity_verified) VALUES (1,?1)
             ON CONFLICT(singleton) DO UPDATE SET
             hosted_identity_verified=excluded.hosted_identity_verified",
            [verified],
        )?;
        Ok(())
    }

    pub(crate) fn safety_observed(&self, id: i64) -> Result<()> {
        self.db.execute(
            "INSERT INTO operation_evidence(operation_id,safety_observed_at) VALUES (?1,?2)
            ON CONFLICT(operation_id) DO UPDATE SET safety_observed_at=excluded.safety_observed_at",
            params![id, now()],
        )?;
        Ok(())
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
        let (hosted_identity_verified, first_observed_at, answered): (
            Option<bool>,
            Option<i64>,
            Option<bool>,
        ) = if has_health_evidence {
            self.db
                .query_row(
                    "SELECT hosted_identity_verified,first_observed_at,answered
                     FROM health_evidence WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .unwrap_or((None, None, None))
        } else {
            (None, None, None)
        };
        let epoch_evidence = json!({"first_observed_at":first_observed_at,"answered":answered});
        let effect = self.effect()?;
        let unresolved_count: u64 = self.db.query_row(
            "SELECT COUNT(*) FROM operations WHERE state IN ('dispatching','queued','unknown','included_pending')",
            [], |r| r.get(0),
        )?;
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
        let risk_admissions: u64 = if self.has_table("risk_admissions")? {
            self.db
                .query_row("SELECT COUNT(*) FROM risk_admissions", [], |r| r.get(0))?
        } else {
            0
        };
        let epoch = observed.as_ref().and_then(|o| o["epoch"].as_u64());
        let mut uncertainty_blocks = json!({});
        let mut affected = Vec::new();
        for kind in [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine] {
            let mut blocked = if self.has_table("operation_timing")?
                && self.has_table("manual_grants")?
                && self.has_table("manual_grant_revocations")?
            {
                !self.uncertainty_open(&policy_config, kind, epoch, None)?
            } else {
                unresolved_count > 0
            };
            if !blocked
                && unresolved_count > 0
                && kind == WorkKind::Answer
                && let Some(epoch) = epoch
                && self.answer_epoch_attempted(epoch)?
            {
                blocked = match self.uncertain_answer(epoch)? {
                    Some(original) => !self.answer_retry_allowed(&policy_config, &original)?,
                    // Accepted or model-only work is eligibility, not an uncertainty fence.
                    None => false,
                };
            }
            uncertainty_blocks[kind.as_str()] = json!(blocked);
            if blocked {
                affected.push(kind.as_str());
            }
        }
        let blocked = !affected.is_empty();
        let participation = json!({"policy":policy_config.participation,"policy_source":policy_source,
            "unresolved_count":unresolved_count,"risk_admissions":risk_admissions,
            "observation_epoch":epoch,"uncertainty_blocks":uncertainty_blocks});
        let blocking_operation = effect.as_ref().map(|op| op.id);
        let blocked_since = if self.schema_version()? == 2 {
            effect.as_ref().map(|op| self.db.query_row(
                "SELECT COALESCE((SELECT blocked_since FROM operation_evidence WHERE operation_id=?1),created_at)
                FROM operations WHERE id=?1", [op.id], |r| r.get::<_,i64>(0))).transpose()?
        } else {
            pending.as_ref().and_then(|p| p["created_at"].as_i64())
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
        let status = json!({"initialized":true,"paused":control.paused,"generation":control.generation,
            "identity_fingerprint":digest(format!("{}\n{}",stored["chain"].as_str().unwrap_or_default(),stored["address"].as_str().unwrap_or_default())),
            "chain":stored["chain"],"capabilities":config.capabilities,"observation":observed,
            "configured_revision":config.optional_revision()?,"effective_runtime":effective,
            "controller_stopped":controller_stopped,"epoch_evidence":epoch_evidence,
            "identity_matches_config":stored_identity==identity(config)?,"last_event":last_event,
            "hosted_identity_verified":hosted_identity_verified,
            "pending":pending,"operations":counts,"evidence":"authenticated_hosted_response",
            "admission_blocked":blocked,"blocking_operation":blocking_operation,"blocked_since":blocked_since,
            "affected_capabilities":affected,"participation":participation,
            "last_progress_at":last_progress,"last_reported_build":effective.as_ref().map(|e| &e["policy"]["build"]),
            "process_identity":"unverified",
            "captured_work":captured_work,"last_safety_observation_at":last_safety_observation,
            "finality":"node_reported_only","paid":"not_verified"});
        snapshot.commit()?;
        Ok(status)
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
        let admissions = if self.has_table("risk_admissions")? {
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

    fn fixture() -> (tempfile::TempDir, Config) {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: temp.path().join("state"),
            ..Config::default()
        };
        (temp, config)
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
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(
            store
                .reconciliation_batch()
                .unwrap()
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            ids[2..]
        );
        assert_eq!(
            store
                .reconciliation_batch()
                .unwrap()
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            ids[..2]
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
    fn hosted_identity_failure_survives_event_pruning_and_reopen_until_verified() {
        use crate::health::{self, Options};
        let (_temp, mut config) = fixture();
        config.capabilities.answer = crate::config::Mode::Active;
        let mut store = Store::open(&config).unwrap();
        assert!(store.status(&config).unwrap()["hosted_identity_verified"].is_null());
        store.set_paused(false).unwrap();
        store.record_hosted_identity(false).unwrap();
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
        assert_eq!(health["issues"], json!(["hosted_identity_unverified"]));
        store.record_hosted_identity(true).unwrap();
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
        assert!(reader.record_hosted_identity(false).is_err());
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
        store.record_hosted_identity(true).unwrap();
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
        store.record_hosted_identity(false).unwrap();
        store.observe(54, false).unwrap();
        store
            .db
            .execute("UPDATE health_evidence SET first_observed_at=1", [])
            .unwrap();
        store.record_hosted_identity(true).unwrap();
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
