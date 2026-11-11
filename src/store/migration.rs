//! Explicit, local-only schema cutover. Ordinary opens never call this module's writer.
use super::*;
use crate::{capability::LaneId, journal::CURRENT_JOURNAL_FORMAT};
use anyhow::ensure;
use rusqlite::types::ValueRef;
mod conversion;
mod legacy;
mod seals;
const MAX_BYTES: usize = 65536;
const FORMAT: &str = "agmi.atomic-migration.v1";
const PREDECESSOR_SOURCE: &str = "completed_capability_migration";
const RECORD_DDL: &str = "CREATE TABLE capability_migration (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), phase TEXT NOT NULL,
 token TEXT NOT NULL, sealed TEXT NOT NULL);
 CREATE TABLE capability_migration_evidence (id INTEGER PRIMARY KEY, source TEXT NOT NULL, row_json TEXT NOT NULL);";

#[derive(Debug)]
pub enum MigrationError {
    Pending,
    LimitsRequired,
    ApprovalConflict,
    TokenMismatch,
    RiskApprovalRequired,
    AdoptionApprovalRequired,
    Conflict,
    UnsupportedRecovery,
}
impl MigrationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Pending => "migration_pending",
            Self::LimitsRequired => "migration_limits_required",
            Self::ApprovalConflict => "migration_approval_conflict",
            Self::TokenMismatch => "migration_token_mismatch",
            Self::RiskApprovalRequired => "migration_risk_approval_required",
            Self::AdoptionApprovalRequired => "migration_adoption_approval_required",
            Self::Conflict => "migration_conflict",
            Self::UnsupportedRecovery => "migration_recovery_unsupported",
        }
    }
    pub fn message(&self) -> &'static str {
        match self {
            Self::Pending => {
                "A sealed migration is pending. Inspect migration status and finish that migration before ordinary mutations; participation remains paused."
            }
            Self::LimitsRequired => {
                "Supply explicit positive answer, judge and mine caps, or a complete v2 candidate, in the migration proposal. No conversion was approved."
            }
            Self::ApprovalConflict => {
                "The migration approval does not match the current snapshot. Obtain a fresh preview and use its request and token; do not reuse stale approval."
            }
            Self::TokenMismatch => {
                "The token does not identify this sealed migration. Inspect migration status for its token; do not start another migration or overwrite state."
            }
            Self::RiskApprovalRequired => {
                "The proposed participation exposure is changed or unproven. Review the preview and explicitly supply --accept-risk-change with that same token to authorize it."
            }
            Self::AdoptionApprovalRequired => {
                "Initial legacy authority adoption requires explicit adopt_legacy approval in the migration proposal; existing bound authority is never recreated."
            }
            Self::Conflict => {
                "Sealed migration inputs or authority conflict with current state. Keep participation stopped; inspect migration status and privately export the sealed inputs before explicit recovery."
            }
            Self::UnsupportedRecovery => {
                "This seal is not a supported exact historical target3 or explicit current-target approval. Keep the journal stopped and export its unchanged seal; recovery requires the matching verified migration implementation. Missing target metadata never authorizes retargeting."
            }
        }
    }
}
impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for MigrationError {}

pub(crate) fn ensure_complete(db: &Connection) -> Result<()> {
    if table_exists(db, "capability_migration")? {
        let pending: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM capability_migration WHERE phase<>'complete')",
            [],
            |r| r.get(0),
        )?;
        ensure!(!pending, MigrationError::Pending);
    }
    Ok(())
}
pub(crate) fn ensure_no_pending(config: &Config) -> Result<()> {
    if let Some(db) = open_existing(&config.state_dir, false)? {
        ensure_complete(&db)?;
    } else {
        ensure!(read_binding(config)?.is_none(), "bound journal missing");
        ensure!(marker(config)?.is_empty(), "bound journal missing");
    }
    Ok(())
}
fn table_exists(db: &Connection, table: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )?)
}
fn open_existing(state: &Path, writable: bool) -> Result<Option<Connection>> {
    let path = state.join("state.sqlite3");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(metadata) => {
            validate_private_dir(state)?;
            validate_private_file(&metadata)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "journal symlink rejected"
            );
        }
    }
    // SQLite opens the live inode and handles WAL; never copy its files.
    let path = fs::canonicalize(state)?.join("state.sqlite3");
    let flags = if writable {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = Connection::open_with_flags(path, flags | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    if writable {
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
    }
    Ok(Some(db))
}
/// Read-only installer inspection; metadata compatibility never authorizes data conversion.
pub(crate) fn activation_journal_format(state: &Path) -> Result<Option<(i64, bool)>> {
    let Some(db) = open_existing(state, false)? else {
        return Ok(None);
    };
    let format = db.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
        r.get(0)
    })?;
    Ok(Some((format, ensure_complete(&db).is_ok())))
}
fn bytes(path: &Path) -> Result<Vec<u8>> {
    crate::admin::read_optional(path, true)?
        .context("migration configuration missing; restore exact sealed source or candidate")
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)?.join(
        path.file_name()
            .context("configuration file name missing")?,
    ))
}
fn marker(config: &Config) -> Result<Vec<u8>> {
    Ok(read_private_bytes(&lock_path(config, "writer")?, 64)?.unwrap_or_default())
}
fn file_identity(path: &Path) -> Result<Value> {
    metadata_identity(&fs::symlink_metadata(path)?)
}

fn metadata_identity(m: &fs::Metadata) -> Result<Value> {
    validate_private_file(m)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(json!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"mode":m.mode()}))
    }
    #[cfg(not(unix))]
    {
        bail!("migration requires stable operating-system file identities")
    }
}
struct Locks {
    lanes: Option<LaneGateSet>,
    writer: AccountLock,
    admission: AccountAdmissionGuard,
    writer_identity: Value,
    admission_identity: Value,
}
impl Locks {
    fn acquire(config: &Config) -> Result<Self> {
        let source = open_existing(&config.state_dir, false)?;
        let format = source
            .as_ref()
            .map(|db| {
                db.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
                    r.get::<_, i64>(0)
                })
            })
            .transpose()?;
        let pending = if let Some(db) = &source {
            table_exists(db, "capability_migration")?
                && db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM capability_migration WHERE phase<>'complete')",
                    [],
                    |row| row.get::<_, bool>(0),
                )?
        } else {
            false
        };
        let admission = AccountAdmissionGuard::for_migration(
            config,
            !pending && format.is_none_or(|format| format < 3),
        )?;
        let writer = if source.is_some() {
            AccountLock::stopped_for_migration(config)?
        } else {
            let file = private_file(&lock_path(config, "writer")?)?;
            file.try_lock()
                .map_err(std::io::Error::from)
                .context("stop the runtime before migration")?;
            AccountLock(file)
        };
        lane_control::check_opened_path(&lock_path(config, "writer")?, &writer.0)?;
        let writer_identity = metadata_identity(&writer.0.metadata()?)?;
        lane_control::check_opened_path(&lock_path(config, "admission")?, &admission.0)?;
        let admission_identity = metadata_identity(&admission.0.metadata()?)?;
        Ok(Self {
            admission,
            writer,
            lanes: None,
            writer_identity,
            admission_identity,
        })
    }
    fn check(&self, config: &Config) -> Result<()> {
        lane_control::check_opened_path(&lock_path(config, "writer")?, &self.writer.0)?;
        ensure!(
            metadata_identity(&self.writer.0.metadata()?)? == self.writer_identity,
            "locked writer inode changed"
        );
        let admission_path = lock_path(config, "admission")?;
        lane_control::check_opened_path(&admission_path, &self.admission.0)?;
        let metadata = self.admission.0.metadata()?;
        ensure!(
            metadata_identity(&metadata)? == self.admission_identity,
            "locked admission inode changed"
        );
        if let Some(binding) = read_binding(config)?
            && binding.admission_inode.is_some()
        {
            binding.check_admission(&admission_path, &metadata)?;
        }
        Ok(())
    }

    fn check_approved_admission(&self, snapshot: &Value) -> Result<()> {
        if approved_admission_inode(snapshot)?.is_some() {
            ensure!(
                snapshot["admission_inode"] == self.admission_identity,
                "approved admission inode changed"
            );
        }
        Ok(())
    }

    fn sync_admission(&self, config: &Config) -> Result<()> {
        self.check(config)?;
        self.admission.0.sync_all()?;
        File::open(
            lock_path(config, "admission")?
                .parent()
                .context("admission parent missing")?,
        )?
        .sync_all()?;
        self.check(config)
    }
}

fn validated(path: &Path, source: &str) -> Result<Config> {
    ensure!(source.len() <= MAX_BYTES, "candidate exceeds 64 KiB");
    let mut config = Config::parse_bytes(path, source.as_bytes(), false)?;
    crate::admin::validate_complete(path, &mut config)?;
    Ok(config)
}
fn guidance(config: &Config) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for kind in [LaneId::Answer, LaneId::Judge] {
        let model = config.model(kind).context("model configuration missing")?;
        result.insert(kind.as_str().into(), json!({
            "user_path":model.guidance_file,"core_path":model.core_guidance_file,
            "user_sha256":digest(model.guidance.as_bytes()),"core_sha256":digest(model.core_guidance.as_bytes()),
            "user_bytes":model.guidance.as_ref(),"core_bytes":model.core_guidance.as_ref()}));
    }
    Ok(Value::Object(result))
}
fn validate_request(input: &Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(input)?.len() <= MAX_BYTES,
        "migration input exceeds 64 KiB"
    );
    let object = input
        .as_object()
        .context("migration input must be an object")?;
    for key in object.keys() {
        ensure!(
            [
                "caps",
                "candidate_toml",
                "adopt_legacy",
                "initial_database_id"
            ]
            .contains(&key.as_str()),
            "unknown migration option"
        );
    }
    if let Some(v) = object.get("adopt_legacy") {
        ensure!(v.is_boolean(), "adopt_legacy must be boolean");
    }
    Ok(())
}
struct Prepared {
    source: Vec<u8>,
    candidate: String,
    config: Config,
    legacy: Option<legacy::Legacy>,
}
fn prepare(path: &Path, input: &Value) -> Result<Prepared> {
    validate_request(input)?;
    let source = bytes(path)?;
    let parsed: toml::Value = toml::from_str(std::str::from_utf8(&source)?)?;
    let legacy = if parsed.get("schema_version").is_some() {
        None
    } else {
        Some(legacy::Legacy::parse(&source)?)
    };
    // Current-shape source3 conversion preserves the exact configuration; policy
    // changes have their own approval path and are not part of a format cutover.
    let (old, candidate) = if let Some(legacy) = &legacy {
        let baseline = legacy.candidate(Some(&json!({"answer":1,"judge":1,"mine":1})))?;
        let old = validated(path, &baseline)?;
        let candidate = if let Some(candidate) = input.get("candidate_toml") {
            candidate
                .as_str()
                .context("candidate_toml must be a string")?
                .to_owned()
        } else {
            legacy.candidate(input.get("caps"))?
        };
        (old, candidate)
    } else {
        ensure!(
            input.get("caps").is_none()
                && input.get("initial_database_id").is_none()
                && input.get("adopt_legacy").is_none(),
            "format3 conversion does not adopt authority or change caps"
        );
        let text = std::str::from_utf8(&source)?;
        ensure!(
            input
                .get("candidate_toml")
                .is_none_or(|v| v.as_str() == Some(text)),
            "format3 conversion must preserve exact configuration bytes"
        );
        (validated(path, text)?, text.to_owned())
    };
    let config = validated(path, &candidate)?;
    ensure!(
        identity(&old)? == identity(&config)?
            && old.state_dir == config.state_dir
            && old.network == config.network,
        "migration cannot change account, routing, credentials or state location"
    );
    if let Some(caps) = input.get("caps") {
        ensure!(
            caps.as_object().is_some_and(|o| o.len() == 3),
            "caps requires answer, judge and mine"
        );
        for kind in LaneId::ALL {
            ensure!(
                caps[kind.as_str()].as_u64()
                    == Some(u64::from(
                        config.participation(kind).max_unresolved_operations
                    )),
                "explicit caps and candidate caps differ"
            );
        }
    }
    Ok(Prepared {
        source,
        candidate,
        config,
        legacy,
    })
}
fn rows(db: &Connection, table: &str, mut visit: impl FnMut(Value) -> Result<()>) -> Result<()> {
    // Names come exclusively from sqlite_schema; quoted identifiers cannot become SQL.
    let quoted = table.replace('"', "\"\"");
    let mut statement = db.prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))?;
    let columns = statement.column_count();
    let mut cursor = statement.query([])?;
    while let Some(row) = cursor.next()? {
        let mut values = Vec::with_capacity(columns);
        for column in 0..columns {
            values.push(match row.get_ref(column)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(n) => json!(["integer", n]),
                ValueRef::Real(n) => json!(["real", n.to_bits()]),
                ValueRef::Text(s) => json!(["text", s]),
                ValueRef::Blob(s) => json!(["blob", s]),
            });
        }
        visit(Value::Array(values))?;
    }
    Ok(())
}
fn evidence_digest(db: &Connection) -> Result<String> {
    let mut hash = Sha256::new();
    let mut tables = db.prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'capability_migration' ORDER BY name")?;
    let entries = tables.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for entry in entries {
        let (name, sql) = entry?;
        hash.update(serde_json::to_vec(&json!([name, sql]))?);
        rows(db, &name, |row| {
            hash.update(serde_json::to_vec(&row)?);
            Ok(())
        })?;
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn authority(db: &Connection) -> Result<(String, i64)> {
    let (id, sequence): (String, i64) = db
        .query_row(
            "SELECT database_id,dispatch_sequence FROM authority WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("existing authority missing or malformed; authority cannot be recreated")?;
    ensure!(valid_id(&id) && sequence >= 0, "invalid journal authority");
    Ok((id, sequence))
}
fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
fn snapshot(
    config: &Config,
    db: Option<&Connection>,
    input: &Value,
    locks: &Locks,
) -> Result<Value> {
    locks.check(config)?;
    let marker = writer_marker(&locks.writer.0)?;
    let binding_bytes = read_private_bytes(&lock_path(config, "binding")?, 4096)?;
    let binding: Option<Binding> = binding_bytes
        .as_ref()
        .map(|bytes| serde_json::from_slice(bytes))
        .transpose()?;
    if let Some(binding) = &binding {
        binding.validate()?;
        if binding.writer_inode.is_some() {
            binding.check_writer(&lock_path(config, "writer")?, &locks.writer.0.metadata()?)?;
        }
    }
    let mut result = json!({"identity":identity(config)?,"network":config.network,
        "state_dir":config.state_dir,"writer_inode":locks.writer_identity,
        "admission_inode":locks.admission_identity,
        "marker":marker,"binding_bytes":binding_bytes,"branch":"config_only","unresolved":[0,0,0]});
    let Some(db) = db else {
        ensure!(
            binding.is_none() && marker.is_empty(),
            "bound journal missing; not an uninitialized configuration"
        );
        return Ok(result);
    };
    ensure_complete(db)?;
    if table_exists(db, "capability_migration")? {
        let (phase, token, raw) = seals::raw_record(db, None)?;
        let sealed: Value = serde_json::from_str(&raw)?;
        ensure!(
            phase == "complete" && seals::target(&token, &sealed)? == 3,
            "only a completed historical target3 predecessor may be superseded"
        );
        result["predecessor"] = json!({"phase":phase,"token":token,"sealed_raw":raw});
    } else {
        ensure!(
            !table_exists(db, "capability_migration_evidence")?,
            "migration evidence exists without its active seal; explicit recovery required"
        );
    }
    let (version, stored, paused, generation): (i64, String, bool, i64) = db.query_row(
        "SELECT version,identity,paused,generation FROM control WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    ensure!(
        matches!(version, 1 | 2 | 3),
        "explicit migration requires source journal format 1, 2 or 3"
    );
    if version == 3 {
        ensure!(
            paused,
            "format3 conversion requires an explicit durable global pause before preview"
        );
    }
    conversion::validate_source(db, version)?;
    ensure!(stored == identity(config)?, "journal identity mismatch");
    let location = fs::canonicalize(&config.state_dir)?
        .to_string_lossy()
        .into_owned();
    let legacy_marker = digest(config.state_dir.as_os_str().as_encoded_bytes());
    let legacy = marker == legacy_marker.as_bytes();
    let (id, sequence, branch) = if version == 1 {
        ensure!(
            binding.is_none() && legacy && !table_exists(db, "authority")?,
            "schema1 initial adoption proof missing"
        );
        ensure!(
            input["adopt_legacy"] == true,
            MigrationError::AdoptionApprovalRequired
        );
        let id = input["initial_database_id"]
            .as_str()
            .context("preview request must contain initial_database_id")?;
        ensure!(
            valid_id(id),
            "initial_database_id must be 32 hexadecimal digits"
        );
        (id.to_owned(), 0, "initial_adoption")
    } else {
        let (id, sequence) = authority(db)?;
        match &binding {
            Some(b) => {
                ensure!(
                    marker == WRITER_MARKER
                        && b.database_id == id
                        && b.dispatch_sequence <= sequence
                        && b.identity == digest(identity(config)?)
                        && b.location == location,
                    "journal binding continuity mismatch"
                );
                (id, sequence, "established_authority")
            }
            None => {
                ensure!(
                    version == 2 && legacy && input["adopt_legacy"] == true,
                    "unbound authority requires eligible legacy marker and explicit adoption"
                );
                (id, sequence, "legacy_adoption")
            }
        }
    };
    let profile: Option<String> = if table_exists(db, "routing_profile")? {
        db.query_row(
            "SELECT profile FROM routing_profile WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    let expected_profile = serde_json::to_string(&config.network.api)?;
    ensure!(
        profile.as_deref().map_or(
            digest(&expected_profile) == crate::endpoints::LEGACY_API_FINGERPRINT,
            |p| p == expected_profile
        ),
        "migration cannot rotate API routing"
    );
    let mut unresolved = [0u64; 3];
    for (i, kind) in ["answer", "judge", "mine"].iter().enumerate() {
        unresolved[i] = db.query_row("SELECT count(*) FROM operations WHERE kind=?1 AND state IN ('dispatching','queued','unknown','included_pending')",[kind],|r| r.get(0))?;
    }
    result["branch"] = json!(branch);
    result["source_schema"] = json!(version);
    result["database_inode"] = file_identity(&config.state_dir.join("state.sqlite3"))?;
    result["database_id"] = json!(id);
    result["dispatch_sequence"] = json!(sequence);
    result["location"] = json!(location);
    result["paused"] = json!(paused);
    result["generation"] = json!(generation);
    result["routing_profile"] = json!(profile);
    result["unresolved"] = json!(unresolved);
    result["evidence_digest"] = json!(evidence_digest(db)?);
    result["identifierless_unknowns"] = json!(db.query_row(
        "SELECT count(*) FROM operations WHERE state='unknown' AND job_id IS NULL AND txid IS NULL",
        [],
        |r| r.get::<_, i64>(0)
    )?);
    result["bound_unknowns"] = json!(db.query_row("SELECT count(*) FROM operations WHERE state='unknown' AND (job_id IS NOT NULL OR txid IS NOT NULL)",[],|r| r.get::<_,i64>(0))?);
    result["pending_grants_to_revoke"] = if version == 3 {
        json!(0)
    } else if table_exists(db, "manual_grants")? {
        let query = if table_exists(db, "manual_grant_revocations")? {
            "SELECT count(*) FROM manual_grants WHERE consumed_by IS NULL AND id NOT IN (SELECT grant_id FROM manual_grant_revocations)"
        } else {
            "SELECT count(*) FROM manual_grants WHERE consumed_by IS NULL"
        };
        json!(db.query_row(query, [], |r| r.get::<_, i64>(0))?)
    } else {
        json!(0)
    };
    result["retained_effect_floor"] = if table_exists(db, "operation_timing")? {
        json!(db.query_row(
            "SELECT COALESCE(MAX(retry_not_before),0) FROM operation_timing",
            [],
            |r| r.get::<_, i64>(0)
        )?)
    } else {
        json!(db.query_row("SELECT COALESCE(MAX(next_at),0) FROM operations WHERE state IN ('dispatching','queued','unknown','included_pending')",[],|r|r.get::<_,i64>(0))?)
    };
    Ok(result)
}
fn preview_value(
    path: &Path,
    p: &Prepared,
    input: &Value,
    db: Option<&Connection>,
    locks: &Locks,
) -> Result<Value> {
    let state = snapshot(&p.config, db, input, locks)?;
    locks.check(&p.config)?;
    let unresolved: [u64; 3] = serde_json::from_value(state["unresolved"].clone())?;
    ensure!(
        if p.legacy.is_some() {
            state.get("source_schema").is_none()
                || matches!(state["source_schema"].as_i64(), Some(1 | 2))
        } else {
            state["source_schema"] == 3
        },
        "configuration shape does not match the supported source journal format"
    );
    let risk = p.legacy.as_ref().map_or_else(
        || {
            json!({"preservation_proven":true,"risk_change_required":false,
            "unresolved_by_kind":unresolved,"configuration_preserved":true})
        },
        |legacy| legacy.risk(&p.config, unresolved),
    );
    let seal = json!({"format":FORMAT,"target_journal_format":CURRENT_JOURNAL_FORMAT,
        "config_path":path,"source_sha256":digest(&p.source),
        "candidate_sha256":digest(p.candidate.as_bytes()),"effective_revision":p.config.revision()?,
        "guidance":guidance(&p.config)?,"snapshot":state,"request":input,"risk":risk});
    let token = format!("{FORMAT}:{}", digest(serde_json::to_vec(&seal)?));
    let mut result = json!({"target_journal_format":CURRENT_JOURNAL_FORMAT,"token":token,"request":input,"candidate_toml":p.candidate,"risk_change_required":risk["risk_change_required"],
        "risk":risk,"snapshot":state,"seal":seal,"legacy_effective":p.legacy,"candidate_effective":p.config,
        "field_moves":{
            "solver.answer":"capabilities.answer.model","solver.judge":"capabilities.judge.model",
            "capabilities.<lane>":"capabilities.<lane>.mode",
            "timeouts.http_seconds":"capabilities.<lane>.timeouts.http_seconds",
            "timeouts.read_http_seconds_or_http_seconds":"capabilities.<lane>.timeouts.read_http_seconds and identity.read_http_seconds",
            "timeouts.model_seconds":"capabilities.answer.timeouts.model_seconds and capabilities.judge.timeouts.model_seconds",
            "timeouts.shutdown_seconds":"runtime.shutdown_seconds",
            "schedule.common":"capabilities.<lane>.schedule and identity retry/backoff/jitter",
            "schedule.challenge_overrides":"capabilities.answer.schedule.discovery_* and capabilities.mine.schedule.discovery_*",
            "schedule.assignments_overrides":"capabilities.judge.schedule.discovery_*",
            "schedule.mine_seconds_and_mine_each_epoch":"capabilities.mine.schedule.interval_seconds and each_epoch",
            "preparation":"capabilities.answer.preparation and capabilities.judge.preparation with effective while_blocked",
            "participation":"capabilities.<lane>.participation with explicit caps and allow=false mapped to strict",
            "participation.answer_retry_and_history":"capabilities.answer.participation",
            "excluded_judging_assignments":"capabilities.judge.excluded_assignments"},
        "network_actions":false,"participation_resumed":false});
    if p.legacy.is_none() {
        result["field_moves"] = json!({});
    }
    Ok(result)
}
/// Private preview output contains exact candidate configuration, never credentials.
pub fn preview(path: &Path, input: &Value) -> Result<Value> {
    let path = absolute(path)?;
    let _directory = crate::admin::lock_config_directory(&path)?;
    let p = prepare(&path, input)?;
    let locks = Locks::acquire(&p.config)?;
    let db = open_existing(&p.config.state_dir, false)?;
    let mut request = input.clone();
    request["candidate_toml"] = json!(p.candidate);
    if request["adopt_legacy"] == true
        && request.get("initial_database_id").is_none()
        && let Some(db) = &db
    {
        let version: i64 =
            db.query_row("SELECT version FROM control WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if version == 1 {
            request["initial_database_id"] =
                json!(db.query_row("SELECT lower(hex(randomblob(16)))", [], |r| {
                    r.get::<_, String>(0)
                })?);
        }
    }
    validate_request(&request)?;
    if let Some(db) = &db {
        let tx = db.unchecked_transaction()?;
        let result = preview_value(&path, &p, &request, Some(&tx), &locks)?;
        tx.commit()?;
        Ok(result)
    } else {
        preview_value(&path, &p, &request, None, &locks)
    }
}
/// Approval is never inferred: acknowledgment must be the exact preview token.
pub fn apply(
    path: &Path,
    input: &Value,
    expected_token: &str,
    accept_risk_change: Option<&str>,
) -> Result<Value> {
    let path = absolute(path)?;
    let _directory = crate::admin::lock_config_directory(&path)?;
    let p = prepare(&path, input)?;
    let mut locks = Locks::acquire(&p.config)?;
    let mut db = open_existing(&p.config.state_dir, true)?;
    if let Some(db) = db.as_mut() {
        let initial = preview_value(&path, &p, input, Some(db), &locks)?;
        approved(&initial, expected_token, accept_risk_change)?;
        locks.lanes = Some(provision_lane_gates(
            &p.config,
            initial["snapshot"]["database_id"]
                .as_str()
                .context("approved database ID missing")?,
            &locks.admission,
            &locks.writer,
        )?);
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = preview_value(&path, &p, input, Some(&tx), &locks)?;
        approved(&preview, expected_token, accept_risk_change)?;
        locks.sync_admission(&p.config)?;
        locks.check(&p.config)?;
        ensure!(bytes(&path)? == p.source, "source configuration changed");
        seal_conversion(
            &tx,
            &p,
            &preview,
            expected_token,
            accept_risk_change,
            locks.lanes.as_ref().context("destination gates missing")?,
        )?;
        locks.check(&p.config)?;
        locks.check_approved_admission(&preview["snapshot"])?;
        tx.commit()?;
        finish(&path, &p.config, db, &mut locks, expected_token)
    } else {
        let preview = preview_value(&path, &p, input, None, &locks)?;
        approved(&preview, expected_token, accept_risk_change)?;
        locks.check(&p.config)?;
        ensure!(
            open_existing(&p.config.state_dir, false)?.is_none(),
            "authority appeared; obtain a new preview"
        );
        ensure!(bytes(&path)? == p.source, "source configuration changed");
        crate::admin::persist(&path, p.candidate.as_bytes())?;
        Ok(
            json!({"phase":"complete","branch":"config_only","token":expected_token,"participation_resumed":false}),
        )
    }
}
fn seal_conversion(
    db: &Connection,
    p: &Prepared,
    preview: &Value,
    token: &str,
    acknowledgment: Option<&str>,
    gates: &LaneGateSet,
) -> Result<()> {
    seals::prepare_storage(db)?;
    if preview["snapshot"]["source_schema"] != 3 {
        conversion::convert(db, &p.config, &preview["snapshot"])?;
    }
    conversion::add_current_state(db, gates)?;
    db.execute(
        "UPDATE control SET version=?1 WHERE singleton=1",
        [CURRENT_JOURNAL_FORMAT],
    )?;
    let mut sealed = preview["seal"].clone();
    sealed["source_toml"] = json!(std::str::from_utf8(&p.source)?);
    sealed["candidate_toml"] = json!(p.candidate);
    sealed["risk_acknowledged"] = json!(acknowledgment == Some(token));
    sealed["initial_adoption_pending"] = json!(preview["snapshot"]["branch"] == "initial_adoption");
    sealed["post_evidence_digest"] = json!(evidence_digest(db)?);
    sealed["sealed_generation"] = json!(db.query_row(
        "SELECT generation FROM control WHERE singleton=1",
        [],
        |r| r.get::<_, i64>(0)
    )?);
    db.execute(
        "INSERT INTO capability_migration VALUES(1,'journal_ready',?1,?2)",
        params![token, serde_json::to_string(&sealed)?],
    )?;
    Ok(())
}
fn approved(preview: &Value, expected: &str, acknowledgment: Option<&str>) -> Result<()> {
    ensure!(
        preview["token"].as_str() == Some(expected),
        MigrationError::ApprovalConflict
    );
    ensure!(
        preview["risk_change_required"] != true || acknowledgment == Some(expected),
        MigrationError::RiskApprovalRequired
    );
    ensure!(
        acknowledgment.is_none() || acknowledgment == Some(expected),
        MigrationError::ApprovalConflict
    );
    Ok(())
}
fn record(db: &Connection, token: Option<&str>) -> Result<(String, String, Value)> {
    let (phase, stored, raw) = seals::raw_record(db, None)?;
    ensure!(
        token.is_none_or(|token| token == stored),
        MigrationError::TokenMismatch
    );
    Ok((phase, stored, serde_json::from_str(&raw)?))
}
fn check_sealed(
    db: &Connection,
    config: &Config,
    sealed: &Value,
    locks: &Locks,
    target: i64,
) -> Result<()> {
    locks.check(config)?;
    if target == CURRENT_JOURNAL_FORMAT {
        ensure!(locks.lanes.is_some(), "required lane gates are not fenced");
        validate_required_lane_state(db)?;
    }
    let s = &sealed["snapshot"];
    locks.check_approved_admission(s)?;
    ensure!(
        file_identity(&config.state_dir.join("state.sqlite3"))? == s["database_inode"]
            && locks.writer_identity == s["writer_inode"],
        "sealed authority inode changed"
    );
    let (id, sequence) = authority(db)?;
    ensure!(
        json!(id) == s["database_id"] && json!(sequence) == s["dispatch_sequence"],
        "sealed authority changed"
    );
    let (paused, generation, version, stored): (bool, i64, i64, String) = db.query_row(
        "SELECT paused,generation,version,identity FROM control WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    ensure!(
        paused
            && version == target
            && json!(generation) == sealed["sealed_generation"]
            && stored == identity(config)?,
        "sealed paused control changed"
    );
    ensure!(
        json!(evidence_digest(db)?) == sealed["post_evidence_digest"],
        "post-conversion journal evidence changed"
    );
    ensure!(
        guidance(config)? == sealed["guidance"]
            && json!(config.revision()?) == sealed["effective_revision"],
        "approved guidance changed; restore sealed inputs"
    );
    Ok(())
}
fn authority_prerequisite(target: i64, sealed: &Value) -> Option<&'static str> {
    (target == CURRENT_JOURNAL_FORMAT && sealed["snapshot"].get("admission_inode").is_none())
        .then_some(
            "This pre-gate approval establishes only writer authority. Inspect current admission authority; if unanchored, stop all controllers and native work and explicitly recover adopt before ordinary current-format use.",
        )
}

// Absence alone selects the authentic pre-gate explicit4 destination. A present
// member must have the complete metadata shape emitted from the approved FD.
fn approved_admission_inode(snapshot: &Value) -> Result<Option<WriterInode>> {
    let Some(metadata) = snapshot.get("admission_inode") else {
        return Ok(None);
    };
    ensure!(
        metadata.as_object().is_some_and(|object| object.len() == 4)
            && ["device", "inode", "uid", "mode"]
                .iter()
                .all(|key| metadata[*key].as_u64().is_some())
            && metadata["inode"].as_u64().is_some_and(|inode| inode != 0)
            && metadata["uid"]
                .as_u64()
                .is_some_and(|uid| u32::try_from(uid).is_ok())
            && metadata["mode"].as_u64().is_some_and(|mode| {
                u32::try_from(mode).is_ok() && mode & 0o170000 == 0o100000 && mode & 0o077 == 0
            }),
        "approved admission metadata malformed"
    );
    Ok(Some(WriterInode {
        device: metadata["device"]
            .as_u64()
            .context("approved admission device missing")?,
        inode: metadata["inode"]
            .as_u64()
            .context("approved admission inode missing")?,
    }))
}

/// Target4 installs only bytes deterministically derived from the approved source.
/// The seal and its database evidence digest remain untouched.
fn current_destination(config: &Config, snapshot: &Value) -> Result<Vec<u8>> {
    let anchor = WriterInode {
        device: snapshot["writer_inode"]["device"]
            .as_u64()
            .context("approved writer device missing")?,
        inode: snapshot["writer_inode"]["inode"]
            .as_u64()
            .context("approved writer inode missing")?,
    };
    let admission_anchor = approved_admission_inode(snapshot)?;
    let established = snapshot["branch"] == "established_authority";
    let source: Option<Vec<u8>> = serde_json::from_value(snapshot["binding_bytes"].clone())?;
    let mut binding = if established {
        serde_json::from_slice::<Binding>(
            source
                .as_deref()
                .context("approved source binding missing")?,
        )?
    } else {
        ensure!(
            matches!(
                snapshot["branch"].as_str(),
                Some("initial_adoption" | "legacy_adoption")
            ) && source.is_none(),
            "unsupported binding installation branch"
        );
        Binding {
            location: snapshot["location"]
                .as_str()
                .context("location missing")?
                .into(),
            identity: digest(identity(config)?),
            database_id: snapshot["database_id"]
                .as_str()
                .context("ID missing")?
                .into(),
            dispatch_sequence: snapshot["dispatch_sequence"]
                .as_i64()
                .context("sequence missing")?,
            writer_inode: None,
            admission_inode: None,
        }
    };
    binding.validate()?;
    ensure!(
        json!(binding.location) == snapshot["location"]
            && binding.identity == digest(identity(config)?)
            && json!(binding.database_id) == snapshot["database_id"]
            && binding.dispatch_sequence
                <= snapshot["dispatch_sequence"]
                    .as_i64()
                    .context("sequence missing")?,
        "approved source binding disagrees with authority"
    );
    if let Some(existing) = binding.writer_inode {
        ensure!(existing == anchor, "approved source writer anchor mismatch");
    }
    if let Some(admission_anchor) = admission_anchor {
        if let Some(existing) = binding.admission_inode {
            ensure!(
                existing == admission_anchor,
                "approved source admission anchor mismatch"
            );
        }
        if binding.writer_inode.is_some() && binding.admission_inode.is_some() {
            return source.context("anchored source binding missing");
        }
        binding.admission_inode = Some(admission_anchor);
    } else {
        ensure!(
            binding.admission_inode.is_none(),
            "pre-gate approval contains an unsupported admission anchor"
        );
        if binding.writer_inode.is_some() {
            // The pre-gate destination preserves every byte of an anchored source.
            return source.context("anchored source binding missing");
        }
    }
    binding.writer_inode = Some(anchor);
    binding.validate()?;
    Ok(serde_json::to_vec(&binding)?)
}

fn install_current_binding(config: &Config, snapshot: &Value, locks: &mut Locks) -> Result<()> {
    locks.check(config)?;
    ensure!(
        locks.writer_identity == snapshot["writer_inode"],
        "approved writer inode changed"
    );
    locks.check_approved_admission(snapshot)?;
    let destination = current_destination(config, snapshot)?;
    let path = lock_path(config, "binding")?;
    let current = read_private_bytes(&path, 4096)?;
    let current_marker = writer_marker(&locks.writer.0)?;
    let original_marker: Vec<u8> = serde_json::from_value(snapshot["marker"].clone())?;
    if snapshot["branch"] == "established_authority" {
        let source: Vec<u8> = serde_json::from_value(snapshot["binding_bytes"].clone())?;
        ensure!(
            current
                .as_deref()
                .is_some_and(|bytes| bytes == source || bytes == destination)
                && current_marker == original_marker
                && current_marker == WRITER_MARKER,
            "established binding changed"
        );
    } else {
        let historical = if snapshot.get("admission_inode").is_none() {
            let mut historical: Binding = serde_json::from_slice(&destination)?;
            historical.writer_inode = None;
            historical.admission_inode = None;
            Some(serde_json::to_vec(&historical)?)
        } else {
            None
        };
        // Only pre-gate approvals emitted the four-field installed intermediate.
        ensure!(
            (current.as_deref().is_some_and(|bytes| {
                bytes == destination || historical.as_deref() == Some(bytes)
            }) || (current.is_none() && current_marker == original_marker))
                && (current_marker == original_marker || current_marker == WRITER_MARKER),
            "adoption binding conflict"
        );
    }
    locks.check(config)?;
    locks.check_approved_admission(snapshot)?;
    // Republish even an already installed destination: its prior rename may have
    // preceded directory fsync. Completion requires a durable destination.
    write_binding_bytes(&path, &destination)?;
    locks.check(config)?;
    if snapshot["branch"] != "established_authority" {
        AccountLock::mark_writer(&mut locks.writer.0, &lock_path(config, "writer")?)?;
    }
    locks.check(config)?;
    locks.check_approved_admission(snapshot)?;
    Ok(())
}

fn finish(
    path: &Path,
    config: &Config,
    db: &mut Connection,
    locks: &mut Locks,
    token: &str,
) -> Result<Value> {
    let (phase, _, sealed) = record(db, Some(token))?;
    ensure!(
        matches!(phase.as_str(), "journal_ready" | "complete"),
        MigrationError::UnsupportedRecovery
    );
    let target = seals::target(token, &sealed).context(MigrationError::UnsupportedRecovery)?;
    ensure!(
        sealed["config_path"] == json!(path),
        "sealed configuration path mismatch"
    );
    let old = sealed["source_toml"]
        .as_str()
        .context("sealed source missing")?;
    let new = sealed["candidate_toml"]
        .as_str()
        .context("sealed candidate missing")?;
    ensure!(
        json!(digest(old.as_bytes())) == sealed["source_sha256"]
            && json!(digest(new.as_bytes())) == sealed["candidate_sha256"],
        "sealed bytes corrupt"
    );
    if phase == "complete" {
        ensure!(
            bytes(path)? == new.as_bytes(),
            "completed migration config differs"
        );
        return Ok(
            json!({"phase":"complete","token":token,"target_journal_format":target,
            "recovery_prerequisite":authority_prerequisite(target, &sealed),
            "further_migration_required":target != CURRENT_JOURNAL_FORMAT,"participation_resumed":false}),
        );
    }
    check_sealed(db, config, &sealed, locks, target).context(MigrationError::Conflict)?;
    let s = &sealed["snapshot"];
    let branch = s["branch"].as_str().context("sealed branch missing")?;
    if target == CURRENT_JOURNAL_FORMAT {
        install_current_binding(config, s, locks).context(MigrationError::Conflict)?;
    } else if branch != "established_authority" {
        let expected = Binding {
            location: s["location"].as_str().context("location missing")?.into(),
            identity: digest(identity(config)?),
            database_id: s["database_id"].as_str().context("ID missing")?.into(),
            dispatch_sequence: s["dispatch_sequence"]
                .as_i64()
                .context("sequence missing")?,
            writer_inode: None,
            admission_inode: None,
        };
        let current_marker = marker(config)?;
        let legacy: Vec<u8> = serde_json::from_value(s["marker"].clone())?;
        ensure!(
            current_marker == legacy || current_marker == WRITER_MARKER,
            "adoption writer marker changed"
        );
        match read_binding(config)? {
            Some(binding) => ensure!(
                serde_json::to_value(binding)? == serde_json::to_value(&expected)?,
                "adoption binding conflict"
            ),
            None => {
                ensure!(current_marker == legacy, "stable marker lost binding");
                write_binding(&lock_path(config, "binding")?, &expected)?;
            }
        }
        locks.check(config)?;
        locks.writer.0.rewind()?;
        locks.writer.0.write_all(WRITER_MARKER)?;
        locks.writer.0.set_len(WRITER_MARKER.len() as u64)?;
        locks.writer.0.sync_all()?;
        File::open(
            lock_path(config, "writer")?
                .parent()
                .context("writer parent missing")?,
        )?
        .sync_all()?;
    } else {
        ensure!(
            json!(read_private_bytes(&lock_path(config, "binding")?, 4096)?) == s["binding_bytes"]
                && json!(marker(config)?) == s["marker"],
            "established binding changed"
        );
    }
    let installed = bytes(path).context(MigrationError::Conflict)?;
    ensure!(
        installed == old.as_bytes() || installed == new.as_bytes(),
        MigrationError::Conflict
    );
    // Also redo persistence when already new: a prior rename may precede directory fsync.
    crate::admin::persist(path, new.as_bytes())?;
    let installed_config = validated(path, new).context(MigrationError::Conflict)?;
    ensure!(
        bytes(path)? == new.as_bytes(),
        "configuration installation changed"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_sealed(&tx, &installed_config, &sealed, locks, target)
        .context(MigrationError::Conflict)?;
    let binding = read_binding(config)?.context("binding missing after installation")?;
    ensure!(
        json!(binding.database_id) == s["database_id"]
            && binding.dispatch_sequence
                <= s["dispatch_sequence"]
                    .as_i64()
                    .context("sequence missing")?
            && binding.location == s["location"].as_str().context("location missing")?
            && binding.identity == digest(identity(config)?)
            && marker(config)? == WRITER_MARKER,
        "final binding conflict"
    );
    if target == CURRENT_JOURNAL_FORMAT {
        ensure!(
            read_private_bytes(&lock_path(config, "binding")?, 4096)?.as_deref()
                == Some(current_destination(config, s)?.as_slice()),
            "anchored destination binding changed during installation"
        );
        binding.check_writer(&lock_path(config, "writer")?, &locks.writer.0.metadata()?)?;
        if s.get("admission_inode").is_some() {
            binding.check_admission(
                &lock_path(config, "admission")?,
                &locks.admission.0.metadata()?,
            )?;
        }
    } else if branch == "established_authority" {
        ensure!(
            json!(read_private_bytes(&lock_path(config, "binding")?, 4096)?) == s["binding_bytes"],
            "established binding changed during installation"
        );
    } else {
        ensure!(
            json!(binding.dispatch_sequence) == s["dispatch_sequence"],
            "adoption witness sequence changed"
        );
    }
    tx.execute(
        "UPDATE capability_migration SET phase='complete' WHERE singleton=1 AND token=?1",
        [token],
    )?;
    tx.commit()?;
    Ok(
        json!({"phase":"complete","token":token,"target_journal_format":target,
        "further_migration_required":target != CURRENT_JOURNAL_FORMAT,
        "recovery_prerequisite":authority_prerequisite(target, &sealed),
        "paused":true,"generation":sealed["sealed_generation"],"participation_resumed":false}),
    )
}
/// Explicit state location keeps recovery available when the installed config conflicts.
pub fn resume(path: &Path, state_dir: &Path, expected_token: &str) -> Result<Value> {
    let path = absolute(path)?;
    let _directory = crate::admin::lock_config_directory(&path)?;
    let initial = open_existing(state_dir, false)?.context("migration journal missing")?;
    let (_, _, sealed) = record(&initial, Some(expected_token))?;
    seals::target(expected_token, &sealed).context(MigrationError::UnsupportedRecovery)?;
    let config = validated(
        &path,
        sealed["candidate_toml"]
            .as_str()
            .context("candidate missing")?,
    )?;
    ensure!(
        fs::canonicalize(state_dir)? == fs::canonicalize(&config.state_dir)?,
        "migration state location mismatch"
    );
    drop(initial);
    let mut locks = Locks::acquire(&config)?;
    let mut db = open_existing(state_dir, true)?.context("migration journal disappeared")?;
    let (_, _, sealed) = record(&db, Some(expected_token))?;
    if seals::target(expected_token, &sealed).context(MigrationError::UnsupportedRecovery)?
        == CURRENT_JOURNAL_FORMAT
    {
        locks.lanes = Some(open_required_lane_gates(
            &config,
            &db,
            &locks.admission,
            &locks.writer,
        )?);
    }
    finish(&path, &config, &mut db, &mut locks, expected_token)
}
pub fn status(state_dir: &Path) -> Result<Value> {
    let Some(db) = open_existing(state_dir, false)? else {
        return Ok(json!({"phase":"absent","journal_present":false}));
    };
    if !table_exists(&db, "capability_migration")? {
        return Ok(json!({"phase":"not_started","journal_present":true}));
    }
    let (phase, token, sealed) = record(&db, None)?;
    let target = seals::target(&token, &sealed).ok();
    Ok(
        json!({"phase":phase,"pending":phase != "complete","token":token,"target_journal_format":target,
        "recovery_supported":target.is_some(),
        "recovery_prerequisite":match target {
            None => Some(MigrationError::UnsupportedRecovery.message()),
            Some(target) => authority_prerequisite(target, &sealed),
        },
        "further_migration_required":target.is_some_and(|target| target != CURRENT_JOURNAL_FORMAT),
        "history":seals::history(&db)?,
        "branch":sealed["snapshot"]["branch"],"paused_generation":sealed["sealed_generation"],
        "source_sha256":sealed["source_sha256"],"candidate_sha256":sealed["candidate_sha256"],"risk_acknowledged":sealed["risk_acknowledged"],
        "private_export_available":true,"participation_resumed":false}),
    )
}
/// Contains private configuration/guidance bytes; caller must opt into exporting it.
pub fn export(state_dir: &Path, expected_token: &str) -> Result<Value> {
    let db = open_existing(state_dir, false)?.context("migration journal missing")?;
    let (phase, token, raw) = seals::raw_record(&db, Some(expected_token))?;
    let sealed: Value = serde_json::from_str(&raw)?;
    Ok(
        json!({"private":true,"phase":phase,"token":token,"sealed_raw":raw,"sealed":sealed,
        "source_toml":sealed["source_toml"],"candidate_toml":sealed["candidate_toml"],"guidance":sealed["guidance"],"request":sealed["request"]}),
    )
}

#[cfg(test)]
mod tests;
