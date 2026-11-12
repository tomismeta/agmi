use super::*;

pub(super) fn add_current_state(db: &Connection, gates: &LaneGateSet) -> Result<()> {
    initialize_schema(db)?;
    super::super::schema::add_current_columns(db)?;
    initialize_lane_state(db, gates)?;
    Ok(())
}

pub(super) fn validate_source(db: &Connection, version: i64) -> Result<()> {
    ensure!(
        !table_exists(db, "lane_control")?,
        "legacy journal contains current lane authority; hybrid format requires explicit recovery"
    );
    if version == 3 {
        // These were mandatory format3 tables. Sparse historical schedule rows
        // are not lane authority; only the new format provisions a required set.
        for table in [
            "control",
            "operations",
            "events",
            "schedule",
            "read_state",
            "request_restrictions",
            "lane_observations",
            "lane_observation_evidence",
            "assignment_selection",
            "runtime_state",
            "runtime_authority",
            "health_evidence",
            "hosted_identity_evidence",
            "identity_normalizations",
            "authority",
            "operation_evidence",
            "operation_candidates",
            "runtime_policy",
            "routing_profile",
            "operation_links",
            "operation_timing",
            "manual_grants",
            "manual_grant_revocations",
            "risk_admissions",
            "risk_historical_answers",
            "historical_answer_accounting_events",
            "risk_accounting_snapshots",
        ] {
            ensure!(
                table_exists(db, table)?,
                "source format3 required table missing: {table}"
            );
        }
    }
    Ok(())
}

pub(super) fn convert(db: &Connection, config: &Config, snapshot: &Value) -> Result<()> {
    let at = now();
    for table in [
        "read_backoff",
        "read_observations",
        "schedule",
        "runtime_policy",
        "runtime_state",
        "observation",
        "health_evidence",
    ] {
        if table_exists(db, table)? {
            rows(db, table, |row| {
                db.execute(
                    "INSERT INTO capability_migration_evidence(source,row_json) VALUES(?1,?2)",
                    params![table, serde_json::to_string(&row)?],
                )?;
                Ok(())
            })?;
        }
    }
    // Existing bindings receive one recorded initial revision, not invented history.
    db.execute_batch(
        "ALTER TABLE operations ADD COLUMN binding_revision INTEGER NOT NULL DEFAULT 0;
        UPDATE operations SET binding_revision=1 WHERE job_id IS NOT NULL OR txid IS NOT NULL;",
    )?;
    initialize_schema(db)?;
    if snapshot["branch"] == "initial_adoption" {
        db.execute(
            "INSERT INTO authority VALUES(1,?1,0)",
            [snapshot["database_id"]
                .as_str()
                .context("approved initial ID missing")?],
        )?;
    }
    // No source operation generation, artifact, model policy, link or witness is rewritten.
    db.execute(
        "UPDATE control SET paused=1,generation=generation+1 WHERE singleton=1",
        [],
    )?;
    db.execute(
        "INSERT INTO events(at,code) VALUES(?1,'atomic_migration_paused')",
        [at],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO manual_grant_revocations(grant_id,revoked_at)
        SELECT id,?1 FROM manual_grants WHERE consumed_by IS NULL",
        [at],
    )?;
    db.execute("INSERT OR IGNORE INTO operation_timing(operation_id,retry_not_before)
        SELECT id,next_at FROM operations WHERE state IN ('dispatching','queued','unknown','included_pending')",[])?;
    {
        let mut statement = db.prepare("SELECT operation_id,evidence,observed_at FROM operation_evidence WHERE evidence IS NOT NULL")?;
        let evidence = statement.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        for row in evidence {
            let (id, text, observed) = row?;
            if let Ok(value) = serde_json::from_str::<Value>(&text)
                && value["stage"] == "submit"
            {
                let floor = Store::captured_retry_floor(&value, observed);
                if floor > 0 {
                    db.execute(
                        "INSERT INTO operation_timing(operation_id,retry_not_before) VALUES(?1,?2) ON CONFLICT(operation_id)
                    DO UPDATE SET retry_not_before=MAX(retry_not_before,excluded.retry_not_before)",
                        params![id, floor],
                    )?;
                }
            }
        }
    }
    let effect_floor: i64 = db.query_row(
        "SELECT COALESCE(MAX(retry_not_before),0) FROM operation_timing",
        [],
        |r| r.get(0),
    )?;
    // Legacy rows do not establish when a retained minimum was first observed.
    // Zero records missing observation provenance; migration time is not a new observation.
    if effect_floor > 0 {
        restriction(
            db,
            config,
            RetainedRestriction {
                scope: "legacy_account_effect",
                source: "legacy_operation_timing",
                floor: effect_floor,
                at: 0,
                reads: false,
                effects: true,
            },
        )?;
    }
    migrate_reads(db, config)?;
    for (from, to) in [("generating", "model_unknown"), ("dispatching", "unknown")] {
        db.execute("INSERT INTO events(at,code,kind,operation_id) SELECT ?1,?2,kind,id FROM operations WHERE state=?3",params![at,to,from])?;
        db.execute(
            "UPDATE operations SET state=?1,updated_at=?2 WHERE state=?3",
            params![to, at, from],
        )?;
    }
    db.execute("DELETE FROM schedule WHERE kind='reconciliation'", [])?;
    for kind in ["answer", "judge", "mine"] {
        db.execute(
            "INSERT OR IGNORE INTO schedule(kind,next_at,cursor) VALUES(?1,0,NULL)",
            [kind],
        )?;
        db.execute("UPDATE schedule SET cursor=NULL WHERE kind=?1", [kind])?;
    }
    db.execute(
        "INSERT OR IGNORE INTO schedule(kind,next_at,cursor)
        SELECT 'mine:participation',next_at,NULL FROM schedule WHERE kind='mine'",
        [],
    )?;
    if table_exists(db, "observation")? {
        db.execute_batch("ALTER TABLE observation RENAME TO legacy_observation;")?;
    }
    db.execute_batch(
        "DELETE FROM runtime_state; DELETE FROM runtime_policy;
        UPDATE health_evidence SET epoch=NULL,first_observed_at=NULL,answered=NULL;
        DROP TABLE IF EXISTS read_backoff; DROP TABLE IF EXISTS read_observations;",
    )?;
    Ok(())
}
#[derive(Default)]
struct ReadEvidence {
    failures: i64,
    next_at: i64,
    started: Option<i64>,
    finished: Option<i64>,
    http_success: Option<i64>,
    success: Option<i64>,
    failure: Option<i64>,
    category: Option<String>,
    status: Option<i64>,
    local: i64,
    server: i64,
    retained: i64,
}
fn old_read(db: &Connection, scope: &str) -> Result<ReadEvidence> {
    let mut e = ReadEvidence::default();
    if table_exists(db, "read_backoff")?
        && let Some((failures, next)) = db
            .query_row(
                "SELECT failures,next_at FROM read_backoff WHERE scope=?1",
                [scope],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
    {
        e.failures = failures;
        e.next_at = next;
    }
    if table_exists(db, "read_observations")? {
        let mut statement = db.prepare(
            "SELECT started_at,finished_at,last_http_success_at,last_success_at,last_failure_at,
            failure_category,status,local_next_at,server_not_before,retained_conservative_floor
            FROM read_observations WHERE scope=?1",
        )?;
        let mut cursor = statement.query([scope])?;
        if let Some(r) = cursor.next()? {
            e.started = r.get(0)?;
            e.finished = r.get(1)?;
            e.http_success = r.get(2)?;
            e.success = r.get(3)?;
            e.failure = r.get(4)?;
            e.category = r.get(5)?;
            e.status = r.get(6)?;
            e.local = r.get(7)?;
            e.server = r.get(8)?;
            e.retained = r.get(9)?;
        }
    }
    Ok(e)
}
struct RetainedRestriction<'a> {
    scope: &'a str,
    source: &'a str,
    floor: i64,
    at: i64,
    reads: bool,
    effects: bool,
}

fn restriction(db: &Connection, config: &Config, evidence: RetainedRestriction<'_>) -> Result<()> {
    let RetainedRestriction {
        scope,
        source,
        floor,
        at,
        reads,
        effects,
    } = evidence;
    let authority = format!("{}\n{}", config.network.chain, config.network.address);
    let origin = config.network.origin()?.to_string();
    db.execute("INSERT INTO request_restrictions(authority,origin,scope,target,basis,not_before,observed_at,
        request_id,source,read_class,effect_class,server_minimum_seconds,policy)
        VALUES(?1,?2,?3,'*','retained_legacy_floor',?4,?5,?6,?6,?7,?8,NULL,?9)
        ON CONFLICT(authority,origin,scope,target,basis) DO UPDATE SET
        not_before=MAX(not_before,excluded.not_before)",params![authority,origin,scope,floor,at,source,reads,effects,FORMAT])?;
    Ok(())
}
fn insert_read(
    db: &Connection,
    owner: &str,
    purpose: &str,
    resource: &str,
    operation: Option<(i64, i64, &str)>,
    e: &ReadEvidence,
    attributed: bool,
) -> Result<()> {
    let floor = e.next_at.max(e.local).max(e.retained);
    db.execute("INSERT INTO read_state(owner,purpose,resource,operation_id,binding_revision,remote_resource,
        failures,in_flight,started_at,finished_at,last_http_success_at,last_success_at,last_failure_at,
        failure_category,status,local_next_at,server_not_before,retained_conservative_floor)
        VALUES(?1,?2,?3,?4,?5,?6,?7,0,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",params![
        owner,purpose,resource,operation.map(|o|o.0),operation.map(|o|o.1),operation.map(|o|o.2),
        if attributed {e.failures} else {0},
        if attributed {e.started} else {None},if attributed {e.finished} else {None},
        if attributed {e.http_success} else {None},if attributed {e.success} else {None},
        if attributed {e.failure} else {None},if attributed {e.category.as_deref()} else {None},
        if attributed {e.status} else {None},if attributed {e.local} else {0},e.server,floor])?;
    Ok(())
}
fn migrate_reads(db: &Connection, config: &Config) -> Result<()> {
    for (scope, keys) in [
        ("identity", vec![("account", "identity", "identity")]),
        (
            "challenge",
            vec![
                ("answer", "discovery", "challenge"),
                ("mine", "discovery", "challenge"),
            ],
        ),
        ("assignments", vec![("judge", "discovery", "assignments")]),
    ] {
        let e = old_read(db, scope)?;
        for (owner, purpose, resource) in keys {
            insert_read(db, owner, purpose, resource, None, &e, true)?;
        }
        if e.server > 0 {
            restriction(
                db,
                config,
                RetainedRestriction {
                    scope: "account_authenticated",
                    source: scope,
                    floor: e.server,
                    at: 0,
                    reads: true,
                    effects: true,
                },
            )?;
        }
    }
    for (scope, purpose) in [("job", "job"), ("receipt", "receipt")] {
        let e = old_read(db, scope)?;
        if e.server > 0 {
            restriction(
                db,
                config,
                RetainedRestriction {
                    scope: "account_authenticated",
                    source: scope,
                    floor: e.server,
                    at: 0,
                    reads: true,
                    effects: true,
                },
            )?;
        }
        let sql = if purpose == "job" {
            "SELECT id,kind,binding_revision,job_id FROM operations WHERE job_id IS NOT NULL AND txid IS NULL AND state IN ('dispatching','queued','unknown')"
        } else {
            "SELECT id,kind,binding_revision,txid FROM operations WHERE txid IS NOT NULL AND state IN ('dispatching','queued','unknown','included_pending','confirmed')"
        };
        let mut statement = db.prepare(sql)?;
        let operations = statement.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in operations {
            let (id, owner, revision, remote) = row?;
            insert_read(
                db,
                &owner,
                purpose,
                &format!("{id}:{revision}"),
                Some((id, revision, &remote)),
                &e,
                false,
            )?;
        }
    }
    let e = old_read(db, "assignment_evidence")?;
    if e.server > 0 {
        restriction(
            db,
            config,
            RetainedRestriction {
                scope: "account_authenticated",
                source: "assignment_evidence",
                floor: e.server,
                at: 0,
                reads: true,
                effects: true,
            },
        )?;
    }
    let mut statement =
        db.prepare("SELECT DISTINCT work_key FROM operations WHERE kind='judge'")?;
    for id in statement.query_map([], |r| r.get::<_, String>(0))? {
        insert_read(db, "judge", "assignment", &id?, None, &e, false)?;
    }
    Ok(())
}
