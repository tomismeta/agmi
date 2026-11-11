use super::*;

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}
fn hash(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

// A missing target is recognized only as the one historically emitted seal.
// Neither this verifier nor archival changes any stored approval/evidence bytes.
pub(super) fn target(token: &str, sealed: &Value) -> Result<i64> {
    let historical = sealed.get("target_journal_format").is_none();
    let keys = [
        "format",
        "config_path",
        "source_sha256",
        "candidate_sha256",
        "effective_revision",
        "guidance",
        "snapshot",
        "request",
        "risk",
        "source_toml",
        "candidate_toml",
        "risk_acknowledged",
        "initial_adoption_pending",
        "post_evidence_digest",
        "sealed_generation",
    ];
    ensure!(
        sealed.as_object().is_some_and(|object| object.len()
            == keys.len() + usize::from(!historical)
            && keys.iter().all(|key| object.contains_key(*key)))
            && sealed["format"] == FORMAT,
        "unrecognized sealed migration structure; exact historical recovery implementation required"
    );
    let target = if historical {
        3
    } else {
        sealed["target_journal_format"]
            .as_i64()
            .context("invalid sealed target journal format")?
    };
    ensure!(
        historical || target == CURRENT_JOURNAL_FORMAT,
        "unsupported sealed target journal format; matching migration implementation required"
    );
    let source = sealed["snapshot"]["source_schema"].as_i64();
    ensure!(
        if historical {
            matches!(source, Some(1 | 2))
        } else {
            matches!(source, Some(1 | 2 | 3))
        },
        "unrecognized sealed source journal format; exact historical recovery implementation required"
    );
    if historical {
        ensure!(
            exact_keys(
                &sealed["snapshot"],
                &[
                    "identity",
                    "network",
                    "state_dir",
                    "writer_inode",
                    "marker",
                    "binding_bytes",
                    "branch",
                    "unresolved",
                    "source_schema",
                    "database_inode",
                    "database_id",
                    "dispatch_sequence",
                    "location",
                    "paused",
                    "generation",
                    "routing_profile",
                    "evidence_digest",
                    "identifierless_unknowns",
                    "bound_unknowns",
                    "pending_grants_to_revoke",
                    "retained_effect_floor"
                ]
            ),
            "unrecognized historical source snapshot"
        );
        ensure!(
            exact_keys(
                &sealed["risk"],
                &[
                    "old_shared_max",
                    "old_answer_reserved_slots",
                    "proposed_caps",
                    "aggregate_caps",
                    "unresolved_by_kind",
                    "exposure_including_backlog",
                    "conservative_old_bound",
                    "over_cap",
                    "historical_recharge_possible",
                    "preservation_proven",
                    "risk_change_required",
                    "old_policy",
                    "new_policies",
                    "answer_retry_history",
                    "model_cost_policy"
                ]
            ),
            "unrecognized historical risk approval structure"
        );
        ensure!(
            exact_keys(&sealed["guidance"], &["answer", "judge"]),
            "unrecognized historical guidance approval structure"
        );
        for lane in ["answer", "judge"] {
            ensure!(
                exact_keys(
                    &sealed["guidance"][lane],
                    &[
                        "user_path",
                        "core_path",
                        "user_sha256",
                        "core_sha256",
                        "user_bytes",
                        "core_bytes"
                    ]
                ),
                "unrecognized historical lane guidance structure"
            );
        }
    }
    let s = &sealed["snapshot"];
    let branch = s["branch"]
        .as_str()
        .context("sealed source branch missing")?;
    ensure!(
        matches!(
            (source, branch),
            (Some(1), "initial_adoption")
                | (Some(2), "legacy_adoption" | "established_authority")
                | (Some(3), "established_authority")
        ),
        "sealed source authority branch mismatch"
    );
    if branch != "established_authority" {
        ensure!(
            sealed["request"]["adopt_legacy"] == true,
            "sealed legacy adoption approval missing"
        );
    }
    if branch == "initial_adoption" {
        ensure!(
            sealed["request"]["initial_database_id"] == s["database_id"],
            "sealed initial authority approval mismatch"
        );
    }
    ensure!(
        hash(&sealed["source_sha256"])
            && hash(&sealed["candidate_sha256"])
            && hash(&sealed["post_evidence_digest"])
            && hash(&s["evidence_digest"])
            && sealed["effective_revision"].is_string()
            && sealed["guidance"].is_object()
            && sealed["risk_acknowledged"].is_boolean()
            && sealed["initial_adoption_pending"] == (branch == "initial_adoption")
            && s["database_id"].as_str().is_some_and(valid_id)
            && s["dispatch_sequence"].as_i64().is_some_and(|n| n >= 0),
        "sealed migration evidence missing or malformed"
    );
    let generation = s["generation"]
        .as_i64()
        .context("sealed source generation missing")?;
    let expected_generation = if source == Some(3) {
        Some(generation)
    } else {
        generation.checked_add(1)
    };
    ensure!(
        generation >= 0
            && sealed["sealed_generation"].as_i64() == expected_generation
            && expected_generation.is_some(),
        "sealed generation does not match the approved conversion"
    );
    validate_request(&sealed["request"])?;
    for (text, checksum) in [
        ("source_toml", "source_sha256"),
        ("candidate_toml", "candidate_sha256"),
    ] {
        let text = sealed[text]
            .as_str()
            .context("sealed configuration bytes missing")?;
        ensure!(
            text.len() <= MAX_BYTES && sealed[checksum] == digest(text.as_bytes()),
            "sealed configuration bytes corrupt"
        );
    }
    ensure!(
        sealed["request"]["candidate_toml"] == sealed["candidate_toml"],
        "sealed candidate approval mismatch"
    );
    ensure!(
        sealed["risk"]["risk_change_required"].is_boolean()
            && (sealed["risk"]["risk_change_required"] != true
                || sealed["risk_acknowledged"] == true),
        "sealed risk approval missing"
    );
    let mut approval = sealed.clone();
    let object = approval.as_object_mut().context("sealed object missing")?;
    for field in [
        "source_toml",
        "candidate_toml",
        "risk_acknowledged",
        "initial_adoption_pending",
        "post_evidence_digest",
        "sealed_generation",
    ] {
        object.remove(field);
    }
    ensure!(
        token == format!("{FORMAT}:{}", digest(serde_json::to_vec(&approval)?)),
        "sealed token does not authenticate the exact approved historical structure"
    );
    approved_admission_inode(s)?;
    Ok(target)
}

pub(super) fn raw_record(db: &Connection, token: Option<&str>) -> Result<(String, String, String)> {
    ensure!(
        table_exists(db, "capability_migration")?,
        "no sealed migration record"
    );
    let current: (String, String, String) = db.query_row(
        "SELECT phase,token,sealed FROM capability_migration WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if token.is_none_or(|token| token == current.1) {
        return Ok(current);
    }
    let mut found = None;
    let mut statement = db.prepare(
        "SELECT row_json FROM capability_migration_evidence WHERE source=?1 ORDER BY id",
    )?;
    let records = statement.query_map([PREDECESSOR_SOURCE], |r| r.get::<_, String>(0))?;
    for row in records {
        let value: Value = serde_json::from_str(&row?)?;
        if value["token"].as_str() != token {
            continue;
        }
        ensure!(
            found.is_none(),
            "duplicate archived migration token; recovery required"
        );
        found = Some((
            value["phase"]
                .as_str()
                .context("archived phase missing")?
                .to_owned(),
            value["token"]
                .as_str()
                .context("archived token missing")?
                .to_owned(),
            value["sealed_raw"]
                .as_str()
                .context("archived exact seal missing")?
                .to_owned(),
        ));
    }
    found.context(MigrationError::TokenMismatch)
}

pub(super) fn prepare_storage(db: &Connection) -> Result<()> {
    if !table_exists(db, "capability_migration")? {
        ensure!(
            !table_exists(db, "capability_migration_evidence")?,
            "orphaned migration evidence"
        );
        db.execute_batch(RECORD_DDL)?;
        return Ok(());
    }
    ensure!(
        table_exists(db, "capability_migration_evidence")?,
        "prior migration evidence storage missing"
    );
    let (phase, token, raw) = raw_record(db, None)?;
    ensure!(phase == "complete", MigrationError::Pending);
    let sealed: Value = serde_json::from_str(&raw)?;
    ensure!(
        target(&token, &sealed)? == 3,
        "unsupported predecessor target"
    );
    db.execute(
        "INSERT INTO capability_migration_evidence(source,row_json) VALUES(?1,?2)",
        params![
            PREDECESSOR_SOURCE,
            serde_json::to_string(&json!({"phase":phase,"token":token,"sealed_raw":raw}))?
        ],
    )?;
    db.execute("DELETE FROM capability_migration WHERE singleton=1", [])?;
    Ok(())
}

pub(super) fn history(db: &Connection) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    let mut statement = db.prepare(
        "SELECT row_json FROM capability_migration_evidence WHERE source=?1 ORDER BY id",
    )?;
    for row in statement.query_map([PREDECESSOR_SOURCE], |r| r.get::<_, String>(0))? {
        let value: Value = serde_json::from_str(&row?)?;
        result.push(
            json!({"phase":value["phase"],"token":value["token"],"private_export_available":true}),
        );
    }
    Ok(result)
}
