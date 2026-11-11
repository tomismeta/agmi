use super::*;
use anyhow::ensure;
use std::time::{Duration, Instant};

const UNCERTAINTY_IDS: usize = 32;
const MAX_OBSERVATION_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub enum LaneControlError {
    NotInitialized,
    UnsupportedFormat,
    MissingState,
    Continuity,
    Conflict,
    Busy,
    CommitUncertain,
}
impl LaneControlError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotInitialized => "lane_control_not_initialized",
            Self::UnsupportedFormat => "lane_control_unsupported_journal",
            Self::MissingState => "lane_control_state_missing",
            Self::Continuity => "lane_control_continuity",
            Self::Conflict => "lane_control_conflict",
            Self::Busy => "lane_control_busy",
            Self::CommitUncertain => "lane_control_commit_uncertain",
        }
    }
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotInitialized => "initialize the account journal before lane control",
            Self::UnsupportedFormat => {
                "lane control requires the current journal format; use explicit stopped migration"
            }
            Self::MissingState => {
                "required lane control, schedule or gate state is missing or invalid; no automatic repair was performed"
            }
            Self::Continuity => {
                "account, journal, witness or lane gate continuity could not be established"
            }
            Self::Conflict => "lane control token changed; reread the lane before deciding again",
            Self::Busy => {
                "lane control acquisition deadline expired or the admission gate is busy; no control change was made"
            }
            Self::CommitUncertain => {
                "lane control commit could not be acknowledged; reread its token and state before retrying"
            }
        }
    }
}
impl std::fmt::Display for LaneControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for LaneControlError {}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct LaneControlSnapshot {
    pub lane_id: LaneId,
    pub paused: bool,
    pub control_revision: i64,
}

pub(crate) struct AdmissionObservation<'a> {
    pub(crate) runtime_instance: &'a str,
    pub(crate) state: &'a str,
    pub(crate) reasons: &'a [&'a str],
    pub(crate) observed_at: i64,
    pub(crate) valid_until: Option<i64>,
}

pub(super) fn opened_file(path: &Path, writable: bool, create: bool) -> Result<File> {
    let parent = path.parent().context("private file parent missing")?;
    if create {
        private_dir(parent)?;
    } else {
        validate_private_dir(parent)?;
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    validate_private_file(&file.metadata()?)?;
    check_opened_path(path, &file)?;
    Ok(file)
}

pub(super) fn check_opened_path(path: &Path, file: &File) -> Result<()> {
    check_file_identity(path, &file.metadata()?)
}

pub(super) fn check_file_identity(path: &Path, expected: &fs::Metadata) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_private_file(&path_metadata)?;
    ensure!(
        same_journal_file(&path_metadata, expected),
        LaneControlError::Continuity
    );
    Ok(())
}

fn inode(metadata: &fs::Metadata) -> Result<(i64, i64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((
            i64::try_from(metadata.dev())?,
            i64::try_from(metadata.ino())?,
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        bail!("lane admission requires stable operating-system file identities")
    }
}

fn read_bound_binding(config: &Config) -> Result<Binding> {
    let binding = read_binding(config)?.context(LaneControlError::Continuity)?;
    ensure!(
        binding.writer_inode.is_some() && binding.admission_inode.is_some(),
        LaneControlError::Continuity
    );
    Ok(binding)
}

fn gate_path(config: &Config, database_id: &str, lane: LaneId) -> Result<PathBuf> {
    ensure!(
        database_id.len() == 32 && database_id.bytes().all(|b| b.is_ascii_hexdigit()),
        LaneControlError::Continuity
    );
    lock_path(config, &format!("lane-{database_id}-{}", lane.as_str()))
}

pub(crate) struct LaneAdmissionGuard {
    file: File,
    path: PathBuf,
    database_id: String,
    account_identity: String,
    lane: LaneId,
}
impl LaneAdmissionGuard {
    pub(crate) fn lane_id(&self) -> LaneId {
        self.lane
    }

    fn lock(
        config: &Config,
        database_id: &str,
        lane: LaneId,
        create: bool,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        let path = gate_path(config, database_id, lane)?;
        let file = opened_file(&path, true, create).context(LaneControlError::MissingState)?;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(error) => {
                    let error = std::io::Error::from(error);
                    if error.kind() != std::io::ErrorKind::WouldBlock {
                        return Err(error.into());
                    }
                    let Some(deadline) = deadline else {
                        return Err(LaneControlError::Busy.into());
                    };
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or(LaneControlError::Busy)?;
                    std::thread::sleep(remaining.min(Duration::from_millis(5)));
                }
            }
        }
        check_opened_path(&path, &file)?;
        if create {
            file.sync_all()?;
        }
        Ok(Self {
            file,
            path,
            database_id: database_id.into(),
            account_identity: digest(identity(config)?),
            lane,
        })
    }

    pub(crate) fn try_acquire(config: &Config, lane: LaneId) -> Result<Self> {
        let control = ExistingLaneControlStore::open(config, false)?;
        let guard = Self::lock(config, &control.binding.database_id, lane, false, None)?;
        guard.validate(&control.db, config)?;
        control.check_files()?;
        Ok(guard)
    }

    pub(super) fn validate(&self, db: &Connection, config: &Config) -> Result<()> {
        ensure!(
            self.account_identity == digest(identity(config)?),
            LaneControlError::Continuity
        );
        self.validate_bound(db)
    }

    pub(super) fn validate_account(&self, account: &AccountAdmissionGuard) -> Result<()> {
        let binding = account.validated_binding()?;
        ensure!(
            account.1 == self.path.with_extension("admission")
                && binding.database_id == self.database_id
                && binding.identity == self.account_identity,
            LaneControlError::Continuity
        );
        Ok(())
    }

    pub(super) fn validate_bound(&self, db: &Connection) -> Result<()> {
        check_opened_path(&self.path, &self.file)?;
        let (database_id, stored): (String, String) = db.query_row(
            "SELECT a.database_id,c.identity FROM authority a,control c WHERE a.singleton=1 AND c.singleton=1", [],
            |r| Ok((r.get(0)?, r.get(1)?)))?;
        ensure!(
            database_id == self.database_id && digest(&stored) == self.account_identity,
            LaneControlError::Continuity
        );
        let expected: (i64, i64) = db
            .query_row(
                "SELECT gate_device,gate_inode FROM lane_control WHERE lane=?1",
                [self.lane.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context(LaneControlError::MissingState)?;
        ensure!(
            expected == inode(&self.file.metadata()?)?,
            LaneControlError::Continuity
        );
        Ok(())
    }
}
impl Drop for LaneAdmissionGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub(super) struct LaneGateSet {
    gates: Vec<LaneAdmissionGuard>,
}

pub(super) fn provision_unbound_lane_gates(
    config: &Config,
    database_id: &str,
) -> Result<LaneGateSet> {
    let mut gates = Vec::with_capacity(LaneId::COUNT);
    for lane in LaneId::ALL {
        gates.push(LaneAdmissionGuard::lock(
            config,
            database_id,
            lane,
            true,
            None,
        )?);
    }
    File::open(
        lock_path(config, "writer")?
            .parent()
            .context("lock directory missing")?,
    )?
    .sync_all()?;
    Ok(LaneGateSet { gates })
}

pub(super) fn provision_lane_gates(
    config: &Config,
    database_id: &str,
    account: &AccountAdmissionGuard,
    writer: &AccountLock,
) -> Result<LaneGateSet> {
    check_opened_path(&lock_path(config, "admission")?, &account.0)?;
    check_opened_path(&lock_path(config, "writer")?, &writer.0)?;
    provision_unbound_lane_gates(config, database_id)
}

pub(super) fn open_required_lane_gates(
    config: &Config,
    db: &Connection,
    account: &AccountAdmissionGuard,
    writer: &AccountLock,
) -> Result<LaneGateSet> {
    ensure!(
        db.is_autocommit(),
        "acquire lane gates before the SQLite transaction"
    );
    check_opened_path(&lock_path(config, "admission")?, &account.0)?;
    check_opened_path(&lock_path(config, "writer")?, &writer.0)?;
    validate_required_lane_state(db)?;
    let id: String = db.query_row(
        "SELECT database_id FROM authority WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let mut gates = Vec::with_capacity(LaneId::COUNT);
    for lane in LaneId::ALL {
        let gate = LaneAdmissionGuard::lock(config, &id, lane, false, None)?;
        gate.validate(db, config)?;
        gates.push(gate);
    }
    Ok(LaneGateSet { gates })
}

pub(super) fn initialize_lane_state(db: &Connection, gates: &LaneGateSet) -> Result<()> {
    ensure!(
        !db.is_autocommit(),
        "lane provisioning transaction required"
    );
    let count: i64 = db.query_row("SELECT COUNT(*) FROM lane_control", [], |r| r.get(0))?;
    ensure!(
        count == 0 && gates.gates.len() == LaneId::COUNT,
        "destination lane authority must be new"
    );
    let (database_id, identity): (String, String) = db.query_row(
        "SELECT a.database_id,c.identity FROM authority a,control c WHERE a.singleton=1 AND c.singleton=1",
        [], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let account_identity = digest(identity);
    for gate in &gates.gates {
        ensure!(
            gate.database_id == database_id && gate.account_identity == account_identity,
            LaneControlError::Continuity
        );
        check_opened_path(&gate.path, &gate.file)?;
        let (device, inode) = inode(&gate.file.metadata()?)?;
        db.execute("INSERT INTO lane_control(lane,paused,control_revision,gate_device,gate_inode) VALUES(?1,0,0,?2,?3)",
            params![gate.lane.as_str(), device, inode])?;
        db.execute(
            "INSERT INTO schedule(kind,next_at,cursor,served_in_round) VALUES(?1,0,NULL,0)
            ON CONFLICT(kind) DO UPDATE SET served_in_round=0",
            [gate.lane.as_str()],
        )?;
    }
    Ok(())
}

pub(super) fn validate_required_lane_state(db: &Connection) -> Result<()> {
    let count: usize = db
        .query_row("SELECT COUNT(*) FROM lane_control", [], |r| r.get(0))
        .context(LaneControlError::MissingState)?;
    ensure!(count == LaneId::COUNT, LaneControlError::MissingState);
    let id: String = db.query_row(
        "SELECT database_id FROM authority WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        LaneControlError::Continuity
    );
    let raw: String = db.query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
        r.get(0)
    })?;
    let identity: Value = serde_json::from_str(&raw)?;
    let chain = identity["chain"]
        .as_str()
        .context(LaneControlError::Continuity)?;
    let address = identity["address"]
        .as_str()
        .context(LaneControlError::Continuity)?;
    for lane in LaneId::ALL {
        let (paused, revision, device, node, served): (i64, i64, i64, i64, i64) = db
            .query_row(
                "SELECT c.paused,c.control_revision,c.gate_device,c.gate_inode,s.served_in_round
             FROM lane_control c JOIN schedule s ON s.kind=c.lane WHERE c.lane=?1",
                [lane.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .context(LaneControlError::MissingState)?;
        ensure!(
            matches!(paused, 0 | 1) && revision >= 0 && matches!(served, 0 | 1),
            LaneControlError::MissingState
        );
        let path = account_lock_path(chain, address, &format!("lane-{id}-{}", lane.as_str()))?;
        let file = opened_file(&path, false, false).context(LaneControlError::MissingState)?;
        ensure!(
            (device, node) == inode(&file.metadata()?)?,
            LaneControlError::Continuity
        );
    }
    Ok(())
}

struct ExistingLaneControlStore {
    db: Connection,
    binding: Binding,
    database: fs::Metadata,
    database_path: PathBuf,
    writer: File,
    writer_path: PathBuf,
}
impl ExistingLaneControlStore {
    fn open(config: &Config, writable: bool) -> Result<Self> {
        let database_path = config.state_dir.join("state.sqlite3");
        if !database_path.exists() && !lock_path(config, "binding")?.exists() {
            return Err(LaneControlError::NotInitialized.into());
        }
        // Independent witness is read before any authoritative SQLite snapshot.
        let binding = read_bound_binding(config)?;
        validate_private_dir(&config.state_dir)?;
        let database_path = fs::canonicalize(&config.state_dir)?.join("state.sqlite3");
        // SQLite owns all database descriptors: closing an auxiliary descriptor
        // can release this process's SQLite locks on POSIX systems.
        let database =
            fs::symlink_metadata(&database_path).context(LaneControlError::Continuity)?;
        validate_private_file(&database)?;
        let writer_path = lock_path(config, "writer")?;
        let mut writer =
            opened_file(&writer_path, false, false).context(LaneControlError::Continuity)?;
        let mut marker = Vec::new();
        (&mut writer).take(65).read_to_end(&mut marker)?;
        ensure!(marker == WRITER_MARKER, LaneControlError::Continuity);
        binding.check_writer(&writer_path, &writer.metadata()?)?;
        let admission_path = writer_path.with_extension("admission");
        binding.check_admission(&admission_path, &fs::symlink_metadata(&admission_path)?)?;
        let flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut db = Connection::open_with_flags(&database_path, flags)?;
        db.busy_timeout(Duration::ZERO)?;
        let version: i64 =
            db.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        ensure!(
            version == CURRENT_JOURNAL_FORMAT,
            LaneControlError::UnsupportedFormat
        );
        migration::ensure_complete(&db)?;
        validate_required_lane_state(&db)?;
        Self::check_binding_in(&db, &binding, config)?;
        if writable {
            drop(db);
            db = Connection::open_with_flags(
                &database_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            db.busy_timeout(Duration::ZERO)?;
            let synchronous: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
            ensure!(
                synchronous == 2,
                "lane control requires FULL SQLite durability"
            );
        }
        let result = Self {
            db,
            binding,
            database,
            database_path,
            writer,
            writer_path,
        };
        result.check_files()?;
        Ok(result)
    }

    fn check_files(&self) -> Result<()> {
        check_file_identity(&self.database_path, &self.database)?;
        Self::check_witness(&self.db, &self.binding, &self.writer_path, &self.writer).map(|_| ())
    }

    fn check_witness(
        db: &Connection,
        expected: &Binding,
        writer_path: &Path,
        writer: &File,
    ) -> Result<Binding> {
        let current = binding_at(&writer_path.with_extension("binding"))?
            .context(LaneControlError::Continuity)?;
        let sequence: i64 = db.query_row(
            "SELECT dispatch_sequence FROM authority WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            current.database_id == expected.database_id
                && current.identity == expected.identity
                && current.location == expected.location
                && current.writer_inode == expected.writer_inode
                && current.admission_inode == expected.admission_inode
                && current.dispatch_sequence >= expected.dispatch_sequence
                && current.dispatch_sequence <= sequence,
            LaneControlError::Continuity
        );
        current.check_writer(writer_path, &writer.metadata()?)?;
        let admission_path = writer_path.with_extension("admission");
        current.check_admission(&admission_path, &fs::symlink_metadata(&admission_path)?)?;
        ensure!(
            writer_marker(writer)? == WRITER_MARKER,
            LaneControlError::Continuity
        );
        Ok(current)
    }

    fn check_binding_in(db: &Connection, binding: &Binding, config: &Config) -> Result<()> {
        let (id, sequence, stored): (String, i64, String) = db.query_row(
            "SELECT a.database_id,a.dispatch_sequence,c.identity FROM authority a,control c WHERE a.singleton=1 AND c.singleton=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        ensure!(
            binding.database_id == id
                && binding.dispatch_sequence <= sequence
                && binding.identity == digest(&stored)
                && stored == identity(config)?
                && binding.location == fs::canonicalize(&config.state_dir)?.to_string_lossy(),
            LaneControlError::Continuity
        );
        Ok(())
    }
}

fn control_token(db: &Connection, lane: LaneId, revision: i64) -> Result<String> {
    let (id, identity): (String, String) = db.query_row(
        "SELECT a.database_id,c.identity FROM authority a,control c WHERE a.singleton=1 AND c.singleton=1", [],
        |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(format!(
        "lane-control:{}",
        digest(format!(
            "{id}\n{}\n{}\n{revision}",
            digest(identity),
            lane.as_str()
        ))
    ))
}

pub fn lane_control_status(config: &Config, lane: LaneId) -> Result<Value> {
    let control = ExistingLaneControlStore::open(config, false)?;
    let snapshot = control.db.unchecked_transaction()?;
    ExistingLaneControlStore::check_binding_in(&snapshot, &control.binding, config)?;
    let result = Store::lane_control_projection(&snapshot, lane)?;
    control.check_files()?;
    snapshot.commit()?;
    Ok(result)
}

pub fn set_lane_paused(
    config: &Config,
    lane: LaneId,
    paused: bool,
    expected_control_token: &str,
    wait_deadline: Instant,
) -> Result<Value> {
    ensure!(Instant::now() < wait_deadline, LaneControlError::Busy);
    let control = ExistingLaneControlStore::open(config, true)?;
    commit_lane_control(
        control,
        config,
        lane,
        paused,
        expected_control_token,
        wait_deadline,
    )
}

fn commit_lane_control(
    mut control: ExistingLaneControlStore,
    config: &Config,
    lane: LaneId,
    paused: bool,
    expected_control_token: &str,
    wait_deadline: Instant,
) -> Result<Value> {
    let gate = LaneAdmissionGuard::lock(
        config,
        &control.binding.database_id,
        lane,
        false,
        Some(wait_deadline),
    )?;
    control.db.busy_timeout(
        wait_deadline
            .checked_duration_since(Instant::now())
            .ok_or(LaneControlError::Busy)?,
    )?;
    let tx = control
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| {
            if matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            ) {
                anyhow::Error::new(LaneControlError::Busy)
            } else {
                error.into()
            }
        })?;
    let version: i64 = tx.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
        r.get(0)
    })?;
    ensure!(
        version == CURRENT_JOURNAL_FORMAT,
        LaneControlError::UnsupportedFormat
    );
    migration::ensure_complete(&tx)?;
    validate_required_lane_state(&tx)?;
    ExistingLaneControlStore::check_binding_in(&tx, &control.binding, config)?;
    let latest = read_bound_binding(config)?;
    ensure!(
        latest.database_id == control.binding.database_id
            && latest.identity == control.binding.identity
            && latest.location == control.binding.location
            && latest.writer_inode == control.binding.writer_inode
            && latest.admission_inode == control.binding.admission_inode
            && latest.dispatch_sequence >= control.binding.dispatch_sequence,
        LaneControlError::Continuity
    );
    ExistingLaneControlStore::check_binding_in(&tx, &latest, config)?;
    gate.validate(&tx, config)?;
    let current = Store::lane_control_in(&tx, lane)?;
    ensure!(
        control_token(&tx, lane, current.control_revision)? == expected_control_token,
        LaneControlError::Conflict
    );
    let changed = current.paused != paused;
    if changed {
        let revision = current
            .control_revision
            .checked_add(1)
            .context("lane control revision exhausted")?;
        let affected = tx.execute("UPDATE lane_control SET paused=?1,control_revision=?2 WHERE lane=?3 AND control_revision=?4",
            params![paused, revision, lane.as_str(), current.control_revision])?;
        ensure!(affected == 1, LaneControlError::Conflict);
        tx.execute(
            "INSERT INTO events(at,code,kind) VALUES(?1,?2,?3)",
            params![
                now(),
                if paused {
                    "lane_paused"
                } else {
                    "lane_resumed"
                },
                lane.as_str()
            ],
        )?;
    }
    let mut result = Store::lane_control_projection(&tx, lane)?;
    check_file_identity(&control.database_path, &control.database)?;
    let accepted = ExistingLaneControlStore::check_witness(
        &tx,
        &latest,
        &control.writer_path,
        &control.writer,
    )?;
    gate.validate(&tx, config)?;
    tx.commit().context(LaneControlError::CommitUncertain)?;
    // Never acknowledge a rollback below a witness observed before commit.
    control.binding = accepted;
    control
        .check_files()
        .context(LaneControlError::CommitUncertain)?;
    check_opened_path(&gate.path, &gate.file).context(LaneControlError::CommitUncertain)?;
    result["fence_ack"] = json!({"acknowledged":true,"scope":"local_admission","committed_at":now(),"changed":changed});
    Ok(result)
}

impl Store {
    pub(super) fn lane_control_in(db: &Connection, lane: LaneId) -> Result<LaneControlSnapshot> {
        let (paused, revision): (i64, i64) = db
            .query_row(
                "SELECT paused,control_revision FROM lane_control WHERE lane=?1",
                [lane.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context(LaneControlError::MissingState)?;
        ensure!(
            matches!(paused, 0 | 1) && revision >= 0,
            LaneControlError::MissingState
        );
        Ok(LaneControlSnapshot {
            lane_id: lane,
            paused: paused == 1,
            control_revision: revision,
        })
    }

    pub(crate) fn lane_control(&self, lane: LaneId) -> Result<LaneControlSnapshot> {
        Self::lane_control_in(&self.db, lane)
    }

    pub(super) fn lane_control_projection(db: &Connection, lane: LaneId) -> Result<Value> {
        let control = Self::lane_control_in(db, lane)?;
        let (paused, generation): (bool, i64) = db.query_row(
            "SELECT paused,generation FROM control WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let mut reasons = Vec::new();
        if paused {
            reasons.push("global_paused");
        }
        if control.paused {
            reasons.push("lane_paused");
        }
        let (unsettled, unresolved): (u64, u64) = db.query_row(
            "SELECT COALESCE(SUM(state='dispatching'),0),COUNT(*) FROM operations
            WHERE kind=?1 AND state IN ('dispatching','queued','unknown','included_pending')",
            [lane.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let mut statement = db.prepare(
            "SELECT id FROM operations WHERE kind=?1 AND state='dispatching' ORDER BY id LIMIT ?2",
        )?;
        let ids = statement
            .query_map(params![lane.as_str(), UNCERTAINTY_IDS as i64], |r| {
                r.get::<_, i64>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let runtime: Option<(Option<String>, bool, Option<String>)> = db.query_row(
            "SELECT control_observations,controller_stopped,runtime_instance FROM runtime_state WHERE singleton=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        let mut observed = json!({"state":"unknown","reasons":["runtime_observation_unavailable"],"freshness":"unobserved",
            "source":"none","observed_at":null,"valid_until":null,"runtime_instance":null,"observed_control_revision":null,
            "accepted_config_revision":null,"authority_epoch":null});
        if let Some((raw, stopped, instance)) = runtime {
            if let Some(raw) = raw {
                if let Ok(value) = serde_json::from_str::<Value>(&raw) {
                    if let Some(record) = value.get(lane.as_str()).filter(|v| v.is_object()) {
                        observed = record.clone();
                        observed["last_observed_state"] = record["state"].clone();
                        observed["state"] = json!("unknown");
                        observed["source"] = json!("runtime_snapshot");
                        observed["freshness"] = json!(if stopped { "stopped" } else { "stale" });
                        observed["reasons"] = json!([if stopped {
                            "runtime_stopped"
                        } else {
                            "runtime_liveness_unverified"
                        }]);
                        observed["runtime_instance"] = json!(instance);
                    }
                } else {
                    observed["reasons"] = json!(["runtime_observation_unusable"]);
                }
            }
            if stopped {
                observed["freshness"] = json!("stopped");
            }
        }
        Ok(
            json!({"desired":{"lane_id":lane,"paused":control.paused,"control_revision":control.control_revision,
                "control_token":control_token(db,lane,control.control_revision)?},
            "authoritative_closure":{"state":if reasons.is_empty(){"not_closed"}else{"closed"},"reasons":reasons,
                "source":"journal_control_transaction","account_generation":generation,"lane_control_revision":control.control_revision,"observed_at":now()},
            "observed_admission":observed,
            "dispatch_uncertainty":{"dispatch_intent_unsettled_count":unsettled,"dispatch_intent_unsettled_ids":ids,
                "ids_limit":UNCERTAINTY_IDS,"ids_truncated":unsettled>UNCERTAINTY_IDS as u64,"unresolved_sent_count":unresolved,
                "source":"journal_control_transaction"}}),
        )
    }

    pub(crate) fn record_admission_observation(
        &self,
        lane: LaneId,
        stamp: &AdmissionStampSnapshot,
        observation: AdmissionObservation<'_>,
    ) -> Result<()> {
        let AdmissionObservation {
            runtime_instance,
            state,
            reasons,
            observed_at,
            valid_until,
        } = observation;
        ensure!(
            matches!(state, "open" | "closed" | "unknown")
                && reasons.len() <= 16
                && reasons.iter().all(|s| !s.is_empty()
                    && s.len() <= 64
                    && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')),
            "invalid admission observation"
        );
        ensure!(
            !runtime_instance.is_empty() && runtime_instance.len() <= 128 && observed_at >= 0,
            "invalid observation identity"
        );
        let value = json!({"state":state,"reasons":reasons,"freshness":"current_observation","source":"runtime_snapshot",
            "observed_at":observed_at,"valid_until":valid_until,"runtime_instance":runtime_instance,
            "observed_control_revision":stamp.lane_control_revision,"accepted_config_revision":stamp.lane_config_revision,
            "authority_epoch":stamp.authority_epoch,"account_generation":stamp.account_generation});
        self.record_lane_snapshot(
            lane,
            stamp,
            "control_observations",
            &value,
            Some(runtime_instance),
        )
    }

    pub(crate) fn record_lane_participation(
        &self,
        lane: LaneId,
        stamp: &AdmissionStampSnapshot,
        value: &Value,
    ) -> Result<()> {
        ensure!(
            value.is_object() && serde_json::to_vec(value)?.len() <= MAX_OBSERVATION_BYTES,
            "invalid lane participation assessment"
        );
        self.record_lane_snapshot(
            lane,
            stamp,
            "lane_participation",
            &json!({"assessment":value,"stamp":stamp}),
            None,
        )
    }

    pub(super) fn observation_stamp_matches(
        db: &Connection,
        lane: LaneId,
        stamp: &AdmissionStampSnapshot,
    ) -> Result<bool> {
        Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM control c,lane_control l,runtime_authority a,runtime_policy p
            WHERE c.singleton=1 AND a.singleton=1 AND p.singleton=1 AND l.lane=?1
            AND c.generation=?2 AND l.control_revision=?3 AND a.authority_epoch=?4
            AND json_extract(p.policy,'$.lane_revisions.' || l.lane)=?5)",
            params![lane.as_str(),stamp.account_generation,stamp.lane_control_revision,stamp.authority_epoch,stamp.lane_config_revision],
            |r| r.get(0))?)
    }

    fn record_lane_snapshot(
        &self,
        lane: LaneId,
        stamp: &AdmissionStampSnapshot,
        column: &str,
        value: &Value,
        runtime_instance: Option<&str>,
    ) -> Result<()> {
        self.continuity()?;
        ensure!(
            matches!(column, "control_observations" | "lane_participation"),
            "invalid observation component"
        );
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        if !Self::observation_stamp_matches(&tx, lane, stamp)? {
            return Ok(());
        }
        let raw: Option<String> = tx.query_row(
            &format!("SELECT {column} FROM runtime_state WHERE singleton=1"),
            [],
            |r| r.get(0),
        )?;
        let mut values = raw
            .map(|v| serde_json::from_str::<Value>(&v))
            .transpose()?
            .unwrap_or_else(|| json!({}));
        ensure!(values.is_object(), "invalid runtime observations");
        if values.get(lane.as_str()) == Some(value) {
            return Ok(());
        }
        values[lane.as_str()] = value.clone();
        let encoded = serde_json::to_string(&values)?;
        ensure!(
            encoded.len() <= MAX_OBSERVATION_BYTES * LaneId::COUNT,
            "runtime observations too large"
        );
        tx.execute(
            &format!("UPDATE runtime_state SET {column}=?1 WHERE singleton=1"),
            [encoded],
        )?;
        if let Some(instance) = runtime_instance {
            tx.execute(
                "UPDATE runtime_state SET runtime_instance=?1 WHERE singleton=1",
                [instance],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "lane_control_tests.rs"]
mod tests;

#[cfg(test)]
mod writer_authority_tests {
    use super::*;

    #[test]
    fn replacement_after_control_open_refuses_precommit_and_rolls_back() {
        let (_directory, config) = super::super::tests::bound_fixture();
        let (owner, store) = AccountLock::acquire(&config).unwrap();
        let mut control = ExistingLaneControlStore::open(&config, true).unwrap();
        let tx = control
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("UPDATE lane_control SET paused=1,control_revision=control_revision+1 WHERE lane='answer'", []).unwrap();
        let path = lock_path(&config, "writer").unwrap();
        let next = path.with_extension("replacement");
        let mut replacement = private_file(&next).unwrap();
        replacement.write_all(WRITER_MARKER).unwrap();
        replacement.sync_all().unwrap();
        fs::rename(next, &path).unwrap();
        assert!(
            ExistingLaneControlStore::check_witness(
                &tx,
                &control.binding,
                &control.writer_path,
                &control.writer,
            )
            .is_err()
        );
        drop(tx);
        let unchanged: (bool, i64) = store
            .db
            .query_row(
                "SELECT paused,control_revision FROM lane_control WHERE lane='answer'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(unchanged, (false, 0));
        let id = store.database_identity().unwrap().0;
        drop(control);
        drop(store);
        drop(owner);
        for lane in LaneId::ALL {
            fs::remove_file(gate_path(&config, &id, lane).unwrap()).unwrap();
        }
        for suffix in ["writer", "binding", "admission"] {
            fs::remove_file(lock_path(&config, suffix).unwrap()).unwrap();
        }
    }
}
