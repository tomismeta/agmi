use super::*;

/// Additive DDL only. Migration owns legacy conversion and authority establishment.
pub(super) fn initialize_schema(db: &Connection) -> Result<()> {
    db.execute_batch(SCHEMA)?;
    Ok(())
}

/// Only explicit conversion calls this while holding its stopped-writer transaction.
pub(super) fn add_current_columns(db: &Connection) -> Result<()> {
    anyhow::ensure!(!db.is_autocommit(), "migration transaction required");
    for (table, column, definition) in [
        ("control", "work_revision", "INTEGER NOT NULL DEFAULT 0"),
        (
            "schedule",
            "served_in_round",
            "INTEGER NOT NULL DEFAULT 0 CHECK(served_in_round IN (0,1))",
        ),
        ("manual_grants", "lane_control_revision", "INTEGER"),
        ("operation_evidence", "model_attempt", "TEXT"),
        ("operation_timing", "generation_started_at", "INTEGER"),
        ("operation_timing", "model_captured_at", "INTEGER"),
        ("operation_timing", "queued_since", "INTEGER"),
        ("operation_timing", "dispatch_started_at", "INTEGER"),
        ("runtime_state", "runtime_instance", "TEXT"),
        (
            "runtime_state",
            "controller_stopped",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("runtime_state", "control_observations", "TEXT"),
        ("runtime_state", "lane_participation", "TEXT"),
    ] {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name=?2)",
            params![table, column],
            |row| row.get(0),
        )?;
        if !exists {
            db.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {definition}"
            ))?;
        }
    }
    Store::capture_work_revision(db)?;
    Ok(())
}

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS control (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), paused INTEGER NOT NULL,
 generation INTEGER NOT NULL, identity TEXT NOT NULL, version INTEGER NOT NULL,
 work_revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS lane_control (
 lane TEXT PRIMARY KEY, paused INTEGER NOT NULL CHECK(paused IN (0,1)),
 control_revision INTEGER NOT NULL CHECK(control_revision>=0),
 gate_device INTEGER NOT NULL CHECK(gate_device>=0), gate_inode INTEGER NOT NULL CHECK(gate_inode>=0));
CREATE TABLE IF NOT EXISTS operations (
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL, work_key TEXT NOT NULL,
 state TEXT NOT NULL, request TEXT NOT NULL, result TEXT, payload TEXT,
 job_id TEXT, txid TEXT, generation INTEGER NOT NULL, revision TEXT NOT NULL,
 next_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 binding_revision INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS operations_key ON operations(kind,work_key);
CREATE INDEX IF NOT EXISTS operations_state ON operations(state,kind,updated_at);
CREATE INDEX IF NOT EXISTS operations_recovery ON operations(kind,next_at,id);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, at INTEGER NOT NULL, code TEXT NOT NULL, kind TEXT, operation_id INTEGER);
CREATE TABLE IF NOT EXISTS schedule (
 kind TEXT PRIMARY KEY, next_at INTEGER NOT NULL, cursor TEXT,
 served_in_round INTEGER NOT NULL DEFAULT 0 CHECK(served_in_round IN (0,1)));
CREATE TABLE IF NOT EXISTS read_state (
 owner TEXT NOT NULL, purpose TEXT NOT NULL, resource TEXT NOT NULL,
 operation_id INTEGER REFERENCES operations(id), binding_revision INTEGER, remote_resource TEXT,
 retired INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
 in_flight INTEGER NOT NULL DEFAULT 0, started_at INTEGER, finished_at INTEGER,
 last_http_success_at INTEGER, last_success_at INTEGER, last_failure_at INTEGER,
 failure_category TEXT, status INTEGER, local_next_at INTEGER NOT NULL DEFAULT 0,
 server_not_before INTEGER NOT NULL DEFAULT 0, retained_conservative_floor INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(owner,purpose,resource));
CREATE INDEX IF NOT EXISTS read_state_operation ON read_state(operation_id,binding_revision,retired);
CREATE INDEX IF NOT EXISTS read_state_live ON read_state(retired,owner,purpose,resource);
CREATE TABLE IF NOT EXISTS request_restrictions (
 authority TEXT NOT NULL, origin TEXT NOT NULL, scope TEXT NOT NULL, target TEXT NOT NULL,
 basis TEXT NOT NULL, not_before INTEGER NOT NULL, observed_at INTEGER NOT NULL,
 request_id TEXT NOT NULL, source TEXT NOT NULL, read_class INTEGER NOT NULL,
 effect_class INTEGER NOT NULL, server_minimum_seconds INTEGER, policy TEXT,
 PRIMARY KEY(authority,origin,scope,target,basis));
CREATE INDEX IF NOT EXISTS restrictions_deadline ON request_restrictions(not_before,scope);
CREATE TABLE IF NOT EXISTS lane_observations (
 lane TEXT PRIMARY KEY, authority_epoch INTEGER NOT NULL, generation INTEGER NOT NULL,
 request_sequence INTEGER NOT NULL, started_at INTEGER NOT NULL, observed_at INTEGER NOT NULL,
 epoch INTEGER NOT NULL, first_observed_at INTEGER NOT NULL, answered INTEGER NOT NULL,
 fingerprint TEXT NOT NULL, challenge TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lane_observation_evidence (
 lane TEXT NOT NULL, authority_epoch INTEGER NOT NULL, generation INTEGER NOT NULL,
 request_sequence INTEGER NOT NULL, observed_at INTEGER NOT NULL, epoch INTEGER NOT NULL,
 fingerprint TEXT NOT NULL, applied INTEGER NOT NULL,
 PRIMARY KEY(lane,authority_epoch,generation,request_sequence));
CREATE TABLE IF NOT EXISTS runtime_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), effective_revision TEXT NOT NULL,
 reload_blocked INTEGER NOT NULL, capabilities TEXT NOT NULL, observed_at INTEGER NOT NULL,
 runtime_instance TEXT, controller_stopped INTEGER NOT NULL DEFAULT 0,
 control_observations TEXT, lane_participation TEXT);
CREATE TABLE IF NOT EXISTS runtime_authority (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), authority_epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS health_evidence (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), hosted_identity_verified INTEGER,
 epoch INTEGER, first_observed_at INTEGER, answered INTEGER);
CREATE TABLE IF NOT EXISTS hosted_identity_evidence (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), status TEXT NOT NULL,
 observed_at INTEGER, last_verified_at INTEGER, rejection TEXT, legacy_failure INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS identity_normalizations (
 id INTEGER PRIMARY KEY, preview_token TEXT NOT NULL UNIQUE, audit TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS authority (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), database_id TEXT NOT NULL, dispatch_sequence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS operation_evidence (
 operation_id INTEGER PRIMARY KEY REFERENCES operations(id), policy TEXT, model_deadline INTEGER,
 http_deadline INTEGER, dispatch_sequence INTEGER, blocked_since INTEGER, evidence TEXT,
 observed_at INTEGER, safety_observed_at INTEGER, resolution TEXT, model_attempt TEXT);
CREATE TABLE IF NOT EXISTS operation_candidates (
 operation_id INTEGER PRIMARY KEY REFERENCES operations(id), candidates TEXT NOT NULL,
 truncated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS runtime_policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS routing_profile (singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operation_links (
 operation_id INTEGER PRIMARY KEY REFERENCES operations(id), retry_of INTEGER NOT NULL REFERENCES operations(id),
 payload_reused INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS operation_timing (
 operation_id INTEGER PRIMARY KEY REFERENCES operations(id), retry_not_before INTEGER NOT NULL,
 generation_started_at INTEGER, model_captured_at INTEGER, queued_since INTEGER, dispatch_started_at INTEGER);
CREATE TABLE IF NOT EXISTS manual_grants (
 id INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, kind TEXT NOT NULL, generation INTEGER NOT NULL,
 created_at INTEGER NOT NULL, consumed_by INTEGER REFERENCES operations(id), lane_control_revision INTEGER);
CREATE TABLE IF NOT EXISTS manual_grant_revocations (
 grant_id INTEGER PRIMARY KEY REFERENCES manual_grants(id), revoked_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS risk_admissions (
 dispatch_sequence INTEGER PRIMARY KEY, operation_id INTEGER NOT NULL REFERENCES operations(id),
 policy TEXT NOT NULL, revision TEXT NOT NULL, blocker_ids TEXT NOT NULL,
 retry_of INTEGER REFERENCES operations(id), manual_grant_id INTEGER REFERENCES manual_grants(id), admitted_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS risk_historical_answers (
 dispatch_sequence INTEGER NOT NULL REFERENCES risk_admissions(dispatch_sequence),
 operation_id INTEGER NOT NULL REFERENCES operations(id), accepted_answer_id INTEGER NOT NULL REFERENCES operations(id),
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
";
