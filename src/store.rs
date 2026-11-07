use crate::config::{Config, WorkKind};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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
    private_dir(&root)?;
    let key = digest(format!(
        "{}\n{}",
        config.network.chain, config.network.address
    ));
    Ok(root.join(format!("{key}.{suffix}")))
}

pub(crate) struct AccountLock(File);
impl AccountLock {
    pub(crate) fn acquire(config: &Config) -> Result<(Self, Store)> {
        let _gate = AdmissionGuard::acquire(config)?;
        let mut file = private_file(&lock_path(config, "writer")?)?;
        file.try_lock()
            .map_err(std::io::Error::from)
            .context("another runtime already owns this account")?;
        let store = Self::open_bound_store(&mut file, config)?;
        Ok((Self(file), store))
    }

    fn open_bound_store(file: &mut File, config: &Config) -> Result<Store> {
        if config.network.address.is_empty()
            || config.network.credential_file.as_os_str().is_empty()
        {
            bail!("durable control requires a configured account and credential file");
        }
        let expected = digest(config.state_dir.as_os_str().as_encoded_bytes());
        let initialize = file.metadata()?.len() == 0;
        if !initialize {
            let mut binding = [0_u8; 64];
            if file.metadata()?.len() != 64
                || file.read_exact(&mut binding).is_err()
                || binding != expected.as_bytes()
            {
                bail!(
                    "account is bound to a different durable state directory; use its original configuration"
                );
            }
        }
        // Invalid permissions, paths or identity must not reserve an unused account.
        let store = Store::open(config)?;
        if initialize {
            file.write_all(expected.as_bytes())?;
            file.sync_all()?;
            let path = lock_path(config, "writer")?;
            File::open(path.parent().context("account lock directory missing")?)?.sync_all()?;
            File::open(account_home()?)?.sync_all()?;
        }
        Ok(store)
    }

    /// Caller holds AdmissionGuard. The binding survives the writer's lifetime;
    /// an empty replacement database must never erase unresolved submissions.
    pub(crate) fn control_store(config: &Config) -> Result<Store> {
        let mut file = private_file(&lock_path(config, "writer")?)?;
        Self::open_bound_store(&mut file, config)
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
    pub(crate) fn read_only(config: &Config) -> Result<Option<Self>> {
        let path = config.state_dir.join("state.sqlite3");
        if !path.exists() {
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
        if version != 1 {
            bail!("unsupported state schema");
        }
        Ok(Some(Self { db }))
    }

    pub(crate) fn open(config: &Config) -> Result<Self> {
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
                if version != 1 {
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
        tx.commit()?;
        Ok(Self { db })
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
        let unresolved: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE state IN
            ('generating','generated','prepared','dispatching','queued','unknown','included_pending','retry'))", [], |row| row.get(0))?;
        if unresolved {
            bail!("an operation already holds the account boundary");
        }
        // Mining has no model payload; publish its complete prepared intent atomically.
        let payload = (kind == WorkKind::Mine && state == "prepared").then_some("{}");
        tx.execute("INSERT INTO operations(kind,work_key,state,request,generation,revision,created_at,updated_at,payload)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?7,?8)", params![kind.as_str(),key,state,serde_json::to_string(request)?,control.generation,revision,now(),payload])?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO events(at,code,kind,operation_id) VALUES (?1,?2,?3,?4)",
            params![now(), state, kind.as_str(), id],
        )?;
        tx.commit()?;
        self.operation(id)?.context("durable operation missing")
    }

    pub(crate) fn save(&mut self, op: &Operation, event: &str) -> Result<()> {
        // Only local static codes enter the public event stream.
        if !event.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            bail!("invalid local event code");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE operations SET state=?1,result=?2,payload=?3,job_id=?4,txid=?5,next_at=?6,updated_at=?7 WHERE id=?8",
            params![op.state,op.result.as_ref().map(serde_json::to_string).transpose()?,
                op.payload.as_ref().map(serde_json::to_string).transpose()?,op.job_id,op.txid,op.next_at,now(),op.id])?;
        tx.execute(
            "INSERT INTO events(at,code,kind,operation_id) VALUES (?1,?2,?3,?4)",
            params![now(), event, op.kind.as_str(), op.id],
        )?;
        tx.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)",
            [],
        )?;
        tx.commit()?;
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

    fn operation(&self, id: i64) -> Result<Option<Operation>> {
        let row = self
            .db
            .query_row(
                "SELECT id,kind,work_key,state,request,result,payload,job_id,txid,next_at
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

    pub(crate) fn pending(&self) -> Result<Option<Operation>> {
        let id: Option<i64> = self.db.query_row("SELECT id FROM operations WHERE state IN
            ('generating','generated','prepared','dispatching','queued','unknown','included_pending','retry') ORDER BY id LIMIT 1", [], |r| r.get(0)).optional()?;
        match id {
            Some(id) => self.operation(id),
            None => Ok(None),
        }
    }

    pub(crate) fn awaiting_finality(&self, kind: WorkKind) -> Result<Option<Operation>> {
        let id:Option<i64> = self.db.query_row("SELECT id FROM operations WHERE state='confirmed' AND kind=?1 AND next_at<=?2 ORDER BY next_at,id LIMIT 1",
            params![kind.as_str(),now()],|r|r.get(0)).optional()?;
        match id {
            Some(id) => self.operation(id),
            None => Ok(None),
        }
    }

    pub(crate) fn next_assignment(&self, ids: &[String]) -> Result<Option<String>> {
        let cursor: Option<String> = self
            .db
            .query_row("SELECT cursor FROM schedule WHERE kind='judge'", [], |r| {
                r.get(0)
            })
            .optional()?
            .flatten();
        let mut first: Option<&String> = None;
        let mut after: Option<&String> = None;
        for id in ids {
            if self.attempted(WorkKind::Judge, id)? {
                continue;
            }
            if first.is_none_or(|current| id < current) {
                first = Some(id);
            }
            if cursor.as_ref().is_none_or(|last| id > last)
                && after.is_none_or(|current| id < current)
            {
                after = Some(id);
            }
        }
        let selected = after.or(first);
        if let Some(id) = selected {
            self.db.execute("INSERT INTO schedule(kind,next_at,cursor) VALUES ('judge',0,?1) ON CONFLICT(kind) DO UPDATE SET cursor=excluded.cursor",[id])?;
        }
        Ok(selected.cloned())
    }

    pub(crate) fn attempted(&self, kind: WorkKind, key: &str) -> Result<bool> {
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE kind=?1 AND work_key=?2 AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model'))",
            params![kind.as_str(),key], |r| r.get(0))?)
    }

    pub(crate) fn answer_epoch_attempted(&self, epoch: u64) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE kind='answer' AND work_key LIKE ?1
            AND state NOT IN ('discarded','stale','prelaunch_failed','abandoned_model'))",
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
        let mut stmt = self.db.prepare("SELECT payload FROM operations WHERE kind='answer' AND state IN ('confirmed','final') ORDER BY id DESC LIMIT 8")?;
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
        self.db.execute(
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
        self.db.execute(
            "INSERT INTO events(at,code) SELECT ?1,'controller_running'
             WHERE COALESCE((SELECT code FROM events WHERE code IN
             ('controller_running','runtime_stopped') ORDER BY id DESC LIMIT 1),'') != 'controller_running'",
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

    pub(crate) fn status(&self, config: &Config) -> Result<Value> {
        // Keep heartbeat, epoch and answer evidence in one read snapshot.
        let snapshot = self.db.unchecked_transaction()?;
        let control = self.control()?;
        let mut stmt = self.db.prepare(
            "SELECT kind,state,COUNT(*) FROM operations GROUP BY kind,state ORDER BY kind,state",
        )?;
        let counts = stmt.query_map([], |r| Ok(json!({"kind":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"count":r.get::<_,i64>(2)?})))?
            .collect::<std::result::Result<Vec<_>,_>>()?;
        let pending: Option<Value> = self.db.query_row(
            "SELECT kind,state,next_at,revision,generation,created_at,updated_at FROM operations
             WHERE state IN ('generating','generated','prepared','dispatching','queued','unknown','included_pending','retry')
             ORDER BY id LIMIT 1", [], |r| {
                Ok(json!({"kind":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,
                    "next_at":r.get::<_,i64>(2)?,"captured_revision":r.get::<_,String>(3)?,
                    "captured_generation":r.get::<_,i64>(4)?,"created_at":r.get::<_,i64>(5)?,
                    "updated_at":r.get::<_,i64>(6)?}))
            },
        ).optional()?;
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
        let status = json!({"initialized":true,"paused":control.paused,"generation":control.generation,
            "identity_fingerprint":digest(format!("{}\n{}",stored["chain"].as_str().unwrap_or_default(),stored["address"].as_str().unwrap_or_default())),
            "chain":stored["chain"],"capabilities":config.capabilities,"observation":observed,
            "configured_revision":config.optional_revision()?,"effective_runtime":effective,
            "controller_stopped":controller_stopped,"epoch_evidence":epoch_evidence,
            "identity_matches_config":stored_identity==identity(config)?,"last_event":last_event,
            "hosted_identity_verified":hosted_identity_verified,
            "pending":pending,"operations":counts,"evidence":"authenticated_hosted_response",
            "finality":"node_reported_only","paid":"not_verified"});
        snapshot.commit()?;
        Ok(status)
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
        store
            .begin(
                kind,
                key,
                state,
                &json!({"private":"request-canary"}),
                control,
                "revision",
            )
            .unwrap()
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
        let mut op = begin(&mut store, WorkKind::Answer, "1:word", "dispatching");
        op.payload = Some(json!({"answer":"answer-canary"}));
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
        let mut op = begin(&mut store, WorkKind::Answer, "3:word", "included_pending");
        op.payload = Some(json!({"answer":"verified-history"}));
        assert!(store.history().unwrap().is_empty());
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
    fn assignment_cursor_advances_past_failed_hydration_and_survives_restart() {
        let (_temp, config) = fixture();
        let store = Store::open(&config).unwrap();
        let ids = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(store.next_assignment(&ids).unwrap().as_deref(), Some("a"));
        drop(store);
        let store = Store::open(&config).unwrap();
        assert_eq!(store.next_assignment(&ids).unwrap().as_deref(), Some("b"));
        assert_eq!(store.next_assignment(&ids).unwrap().as_deref(), Some("c"));
        assert_eq!(store.next_assignment(&ids).unwrap().as_deref(), Some("a"));
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
}
