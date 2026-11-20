use super::*;
use crate::config::{HistoricalAnswerCapacity, ParticipationMode};

struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    config: Config,
    source: Vec<u8>,
}
impl Fixture {
    fn new(schema: Option<i64>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let mut legacy = legacy::Legacy {
            state_dir: temp.path().join("state"),
            ..legacy::Legacy::default()
        };
        legacy.network.address = format!("poa1{}", "1".repeat(32));
        legacy.network.chain = format!(
            "migration-{}",
            &digest(temp.path().as_os_str().as_encoded_bytes())[..32]
        );
        legacy.network.credential_file = temp.path().join("key");
        let source = toml::to_string(&legacy).unwrap().into_bytes();
        crate::admin::persist(&path, &source).unwrap();
        let candidate = legacy
            .candidate(Some(&json!({"answer":2,"judge":1,"mine":1})))
            .unwrap();
        let config = validated(&path, &candidate).unwrap();
        let fixture = Self {
            _temp: temp,
            path,
            config,
            source,
        };
        if let Some(schema) = schema {
            fixture.initialize(schema);
        }
        fixture
    }
    fn initialize(&self, schema: i64) {
        private_dir(&self.config.state_dir).unwrap();
        let path = self.config.state_dir.join("state.sqlite3");
        prepare_database(&path).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE control(singleton INTEGER PRIMARY KEY,paused INTEGER NOT NULL,generation INTEGER NOT NULL,identity TEXT NOT NULL,version INTEGER NOT NULL);
            CREATE TABLE operations(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,work_key TEXT NOT NULL,state TEXT NOT NULL,
                request TEXT NOT NULL,result TEXT,payload TEXT,job_id TEXT,txid TEXT,generation INTEGER NOT NULL,
                revision TEXT NOT NULL,next_at INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
            CREATE TABLE routing_profile(singleton INTEGER PRIMARY KEY,profile TEXT NOT NULL);
            CREATE TABLE read_backoff(scope TEXT PRIMARY KEY,failures INTEGER NOT NULL,next_at INTEGER NOT NULL);
            CREATE TABLE observation(singleton INTEGER PRIMARY KEY,epoch INTEGER NOT NULL,observed_at INTEGER NOT NULL);
            INSERT INTO observation VALUES(1,19,50);
            INSERT INTO read_backoff VALUES('job',7,1234);
            INSERT INTO operations VALUES(1,'judge','assignment','dispatching','{}',NULL,'captured','job-1',NULL,4,'original',1200,10,11);
            INSERT INTO operations VALUES(2,'answer','19','generating','{}',NULL,NULL,NULL,NULL,4,'model-original',0,10,11);
        ").unwrap();
        db.execute(
            "INSERT INTO control VALUES(1,0,4,?1,?2)",
            params![identity(&self.config).unwrap(), schema],
        )
        .unwrap();
        db.execute(
            "INSERT INTO routing_profile VALUES(1,?1)",
            [serde_json::to_string(&self.config.network.api).unwrap()],
        )
        .unwrap();
        let mut writer = private_file(&lock_path(&self.config, "writer").unwrap()).unwrap();
        if schema == 1 {
            writer
                .write_all(digest(self.config.state_dir.as_os_str().as_encoded_bytes()).as_bytes())
                .unwrap();
        } else {
            db.execute_batch("CREATE TABLE authority(singleton INTEGER PRIMARY KEY,database_id TEXT NOT NULL,dispatch_sequence INTEGER NOT NULL);
                INSERT INTO authority VALUES(1,'0123456789abcdef0123456789abcdef',7);").unwrap();
            writer.write_all(WRITER_MARKER).unwrap();
            write_binding(
                &lock_path(&self.config, "binding").unwrap(),
                &Binding {
                    location: fs::canonicalize(&self.config.state_dir)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    identity: digest(identity(&self.config).unwrap()),
                    database_id: "0123456789abcdef0123456789abcdef".into(),
                    dispatch_sequence: 7,
                    writer_inode: None,
                    admission_inode: None,
                },
            )
            .unwrap();
        }
        writer.sync_all().unwrap();
    }
    fn preview(&self) -> Value {
        preview(
            &self.path,
            &json!({"caps":{"answer":2,"judge":1,"mine":1},"adopt_legacy":true}),
        )
        .unwrap()
    }
    fn stage(&self, preview: &Value) {
        let path = absolute(&self.path).unwrap();
        let _directory = crate::admin::lock_config_directory(&path).unwrap();
        let p = prepare(&path, &preview["request"]).unwrap();
        let locks = Locks::acquire(&p.config).unwrap();
        let mut db = open_existing(&p.config.state_dir, true).unwrap().unwrap();
        let gates = provision_lane_gates(
            &p.config,
            preview["snapshot"]["database_id"].as_str().unwrap(),
            &locks.admission,
            &locks.writer,
        )
        .unwrap();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let mut current = preview_value(&path, &p, &preview["request"], Some(&tx), &locks).unwrap();
        if preview["snapshot"].get("admission_inode").is_none() {
            current = pre_gate_proposal(current);
        }
        let token = preview["token"].as_str().unwrap();
        approved(&current, token, Some(token)).unwrap();
        locks.sync_admission(&p.config).unwrap();
        seal_conversion(&tx, &p, &current, token, Some(token), &gates).unwrap();
        tx.commit().unwrap();
    }
}
// Reproduce an authentic pre-gate explicit4 approval before sealing it, without
// editing any persisted approval or changing the current preview implementation.
fn pre_gate_proposal(mut proposal: Value) -> Value {
    proposal["snapshot"]
        .as_object_mut()
        .unwrap()
        .remove("admission_inode");
    proposal["seal"]["snapshot"]
        .as_object_mut()
        .unwrap()
        .remove("admission_inode");
    proposal["token"] = json!(format!(
        "{FORMAT}:{}",
        digest(serde_json::to_vec(&proposal["seal"]).unwrap())
    ));
    proposal
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The fixture's randomized chain owns this entire account namespace.
        let writer = lock_path(&self.config, "writer").unwrap();
        let prefix = format!("{}.", writer.file_stem().unwrap().to_string_lossy());
        for entry in fs::read_dir(writer.parent().unwrap()).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}
#[test]
fn stale_approval_never_changes_legacy_schema_marker_or_config() {
    let fixture = Fixture::new(Some(1));
    let preview = fixture.preview();
    let before_marker = marker(&fixture.config).unwrap();
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    db.execute("UPDATE operations SET next_at=next_at+1 WHERE id=1", [])
        .unwrap();
    drop(db);
    assert!(
        apply(
            &fixture.path,
            &preview["request"],
            preview["token"].as_str().unwrap(),
            None
        )
        .is_err()
    );
    let db = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .unwrap();
    assert_eq!(
        db.query_row("SELECT version FROM control", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(!table_exists(&db, "authority").unwrap());
    assert!(!table_exists(&db, "capability_migration").unwrap());
    assert_eq!(marker(&fixture.config).unwrap(), before_marker);
    assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
}
#[test]
fn historical_recharge_and_over_cap_backlog_require_bound_acknowledgment() {
    let mut legacy = legacy::Legacy::default();
    legacy.participation.mode = ParticipationMode::ParticipationFirst;
    legacy.participation.allow_judge = true;
    legacy.participation.max_historical_unknown_answers = 1;
    let text = legacy
        .candidate(Some(&json!({"answer":2,"judge":1,"mine":1})))
        .unwrap();
    let candidate: Config = toml::from_str(&text).unwrap();
    let risk = legacy.risk(&candidate, [3, 0, 0]);
    assert_eq!(risk["risk_change_required"], true);
    assert_eq!(risk["exposure_including_backlog"], 5);
    let preview = json!({"token":"approved","risk_change_required":true});
    assert!(approved(&preview, "approved", None).is_err());
    assert!(approved(&preview, "approved", Some("another-preview")).is_err());
    assert!(approved(&preview, "approved", Some("approved")).is_ok());
    let mut safe = candidate;
    safe.capabilities
        .answer
        .participation
        .max_historical_unknown_answers = 0;
    safe.capabilities
        .answer
        .participation
        .historical_unknown_answer_capacity = HistoricalAnswerCapacity::Bounded;
    assert_eq!(legacy.risk(&safe, [0, 0, 0])["risk_change_required"], false);
    assert_eq!(legacy.risk(&safe, [0, 6, 0])["risk_change_required"], true);
}

#[test]
fn strict_mode_does_not_hide_unbounded_exposure_or_recurring_inference_risk() {
    let legacy = legacy::Legacy::default();
    let baseline: Config = toml::from_str(&legacy.candidate(None).unwrap()).unwrap();
    assert_eq!(
        legacy.risk(&baseline, [0; 3])["risk_change_required"],
        false
    );
    let mut increased_attempts = baseline.clone();
    increased_attempts
        .capabilities
        .answer
        .participation
        .max_answer_attempts_per_epoch += 1;
    let risk = legacy.risk(&increased_attempts, [0; 3]);
    assert_eq!(risk["answer_retry_policy_increased"], true);
    assert_eq!(risk["risk_change_required"], true);
    let mut candidate = baseline.clone();
    candidate
        .capabilities
        .answer
        .participation
        .max_unresolved_operations = crate::config::CountLimit::Unbounded;
    let risk = legacy.risk(&candidate, [10, 0, 0]);
    assert_eq!(risk["risk_change_required"], true);
    assert_eq!(risk["unbounded_exposure"], true);
    assert!(risk["exposure_including_backlog"].is_null());
    candidate = baseline;
    candidate
        .capabilities
        .judge
        .preparation
        .max_attempts_per_work = crate::config::CountLimit::Unbounded;
    let risk = legacy.risk(&candidate, [0; 3]);
    assert_eq!(risk["risk_change_required"], true);
    assert_eq!(risk["model_cost_increased"], true);
    assert_eq!(risk["recurring_inference_possible"], true);
    let proposal = legacy
        .candidate(Some(&json!({"answer":"unbounded","judge":1,"mine":1})))
        .unwrap();
    let candidate: Config = toml::from_str(&proposal).unwrap();
    assert_eq!(
        candidate
            .capabilities
            .answer
            .participation
            .max_unresolved_operations,
        crate::config::CountLimit::Unbounded
    );
}
#[test]
fn strict_migration_attempt_increase_requires_exact_acknowledgment() {
    let fixture = Fixture::new(None);
    let mut candidate = fixture.config.clone();
    candidate
        .capabilities
        .answer
        .participation
        .max_answer_attempts_per_epoch += 1;
    let proposal = preview(
        &fixture.path,
        &json!({
            "candidate_toml":toml::to_string(&candidate).unwrap()
        }),
    )
    .unwrap();
    let token = proposal["token"].as_str().unwrap();
    assert_eq!(proposal["risk_change_required"], true);
    assert!(apply(&fixture.path, &proposal["request"], token, None).is_err());
    assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    apply(&fixture.path, &proposal["request"], token, Some(token)).unwrap();
    assert_eq!(
        Config::load(&fixture.path)
            .unwrap()
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch,
        candidate
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch
    );
    assert!(!fixture.config.state_dir.exists());
}

#[test]
fn config_only_conversion_never_bootstraps_and_absence_race_rejects() {
    let fixture = Fixture::new(None);
    let preview = fixture.preview();
    assert!(!fixture.config.state_dir.exists());
    apply(
        &fixture.path,
        &preview["request"],
        preview["token"].as_str().unwrap(),
        None,
    )
    .unwrap();
    assert!(!fixture.config.state_dir.exists());
    assert!(marker(&fixture.config).unwrap().is_empty());
    assert!(read_binding(&fixture.config).unwrap().is_none());
    let fixture = Fixture::new(None);
    let preview = fixture.preview();
    fixture.initialize(2);
    assert!(
        apply(
            &fixture.path,
            &preview["request"],
            preview["token"].as_str().unwrap(),
            None
        )
        .is_err()
    );
    assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    fs::remove_file(fixture.config.state_dir.join("state.sqlite3")).unwrap();
    assert!(fixture.preview_result().is_err());
}
impl Fixture {
    fn preview_result(&self) -> Result<Value> {
        preview(
            &self.path,
            &json!({"caps":{"answer":2,"judge":1,"mine":1},"adopt_legacy":true}),
        )
    }
}
#[test]
fn full_commit_keeps_pending_paused_and_resumes_exact_old_or_new_bytes() {
    for schema in [1, 2] {
        for installed_new in [false, true] {
            let fixture = Fixture::new(Some(schema));
            let preview = fixture.preview();
            let token = preview["token"].as_str().unwrap();
            fixture.stage(&preview);
            assert!(ensure_no_pending(&fixture.config).is_err());
            let db = open_existing(&fixture.config.state_dir, false)
                .unwrap()
                .unwrap();
            let expected_id = authority(&db).unwrap();
            assert_eq!(
                db.query_row("SELECT generation FROM control", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                5
            );
            assert_eq!(
                db.query_row("SELECT state FROM operations WHERE id=1", [], |r| r
                    .get::<_, String>(0))
                    .unwrap(),
                "unknown"
            );
            assert_eq!(
                db.query_row("SELECT state FROM operations WHERE id=2", [], |r| r
                    .get::<_, String>(0))
                    .unwrap(),
                "model_unknown"
            );
            assert_eq!(
                db.query_row("SELECT generation FROM operations WHERE id=1", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                4
            );
            assert_eq!(
                db.query_row(
                    "SELECT failures FROM read_state WHERE owner='judge' AND purpose='job'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            assert_eq!(db.query_row("SELECT retained_conservative_floor FROM read_state WHERE owner='judge' AND purpose='job'",[],|r|r.get::<_,i64>(0)).unwrap(),1234);
            assert_eq!(
                db.query_row("SELECT count(*) FROM lane_observations", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert!(table_exists(&db, "legacy_observation").unwrap());
            drop(db);
            let exported = export(&fixture.config.state_dir, token).unwrap();
            assert_eq!(
                exported["source_toml"].as_str().unwrap().as_bytes(),
                fixture.source
            );
            if installed_new {
                crate::admin::persist(
                    &fixture.path,
                    exported["candidate_toml"].as_str().unwrap().as_bytes(),
                )
                .unwrap();
            }
            resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
            resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
            ensure_no_pending(&fixture.config).unwrap();
            let db = open_existing(&fixture.config.state_dir, false)
                .unwrap()
                .unwrap();
            assert_eq!(authority(&db).unwrap(), expected_id);
            assert_eq!(
                db.query_row("SELECT generation FROM control", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                5
            );
            assert!(
                db.query_row("SELECT paused FROM control", [], |r| r.get::<_, bool>(0))
                    .unwrap()
            );
            assert_eq!(marker(&fixture.config).unwrap(), WRITER_MARKER);
        }
    }
}
#[test]
fn interrupted_adoption_binding_keeps_same_id_and_conflicts_never_overwrite() {
    let fixture = Fixture::new(Some(1));
    let preview = pre_gate_proposal(fixture.preview());
    let token = preview["token"].as_str().unwrap();
    fixture.stage(&preview);
    let db = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .unwrap();
    let (id, sequence) = authority(&db).unwrap();
    let original_seal = export(&fixture.config.state_dir, token).unwrap()["sealed_raw"].clone();
    let original_digest = evidence_digest(&db).unwrap();
    drop(db);
    // Simulate binding durability before the locked marker rewrite.
    write_binding(
        &lock_path(&fixture.config, "binding").unwrap(),
        &Binding {
            location: fs::canonicalize(&fixture.config.state_dir)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            identity: digest(identity(&fixture.config).unwrap()),
            database_id: id.clone(),
            dispatch_sequence: sequence,
            writer_inode: None,
            admission_inode: None,
        },
    )
    .unwrap();
    crate::admin::persist(&fixture.path, b"operator edit").unwrap();
    assert!(resume(&fixture.path, &fixture.config.state_dir, token).is_err());
    assert_eq!(bytes(&fixture.path).unwrap(), b"operator edit");
    assert_eq!(marker(&fixture.config).unwrap(), WRITER_MARKER);
    assert!(ensure_no_pending(&fixture.config).is_err());
    fs::remove_file(&fixture.path).unwrap();
    assert!(resume(&fixture.path, &fixture.config.state_dir, token).is_err());
    crate::admin::persist(&fixture.path, &fixture.source).unwrap();
    resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
    assert!(
        read_binding(&fixture.config)
            .unwrap()
            .unwrap()
            .writer_inode
            .is_some()
    );
    assert_eq!(
        export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
        original_seal
    );
    let db = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .unwrap();
    assert_eq!(evidence_digest(&db).unwrap(), original_digest);
    assert_eq!(
        read_binding(&fixture.config).unwrap().unwrap().database_id,
        id
    );
}
#[test]
fn stable_marker_without_binding_and_missing_schema2_authority_fail_closed() {
    for remove_authority in [false, true] {
        let fixture = Fixture::new(Some(2));
        if remove_authority {
            let db = open_existing(&fixture.config.state_dir, true)
                .unwrap()
                .unwrap();
            db.execute("DELETE FROM authority", []).unwrap();
        } else {
            fs::remove_file(lock_path(&fixture.config, "binding").unwrap()).unwrap();
        }
        assert!(fixture.preview_result().is_err());
        assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    }
}
#[test]
fn altered_sealed_control_is_a_conflict_not_a_new_pause() {
    let fixture = Fixture::new(Some(2));
    let preview = fixture.preview();
    fixture.stage(&preview);
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    db.execute("UPDATE control SET generation=generation+1", [])
        .unwrap();
    drop(db);
    assert!(
        resume(
            &fixture.path,
            &fixture.config.state_dir,
            preview["token"].as_str().unwrap()
        )
        .is_err()
    );
    assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    assert!(ensure_no_pending(&fixture.config).is_err());
}

#[test]
fn changed_guidance_is_conflict_and_private_export_restores_exact_input() {
    let fixture = Fixture::new(Some(2));
    let guidance_path = fixture._temp.path().join("answer-guidance.txt");
    crate::admin::persist(&guidance_path, b"approved guidance").unwrap();
    let mut legacy: toml::Value =
        toml::from_str(std::str::from_utf8(&fixture.source).unwrap()).unwrap();
    legacy["solver"]["answer"].as_table_mut().unwrap().insert(
        "guidance_file".into(),
        toml::Value::String(guidance_path.to_string_lossy().into_owned()),
    );
    crate::admin::persist(&fixture.path, toml::to_string(&legacy).unwrap().as_bytes()).unwrap();
    let preview = fixture.preview();
    let token = preview["token"].as_str().unwrap();
    fixture.stage(&preview);
    crate::admin::persist(&guidance_path, b"unapproved edit").unwrap();
    assert!(resume(&fixture.path, &fixture.config.state_dir, token).is_err());
    assert!(ensure_no_pending(&fixture.config).is_err());
    let exported = export(&fixture.config.state_dir, token).unwrap();
    assert_eq!(
        exported["guidance"]["answer"]["user_bytes"],
        "approved guidance"
    );
    crate::admin::persist(
        &guidance_path,
        exported["guidance"]["answer"]["user_bytes"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
}

#[test]
fn missing_binding_after_stable_marker_is_not_interrupted_initial_adoption() {
    let fixture = Fixture::new(Some(1));
    let preview = fixture.preview();
    let token = preview["token"].as_str().unwrap();
    fixture.stage(&preview);
    crate::admin::persist(&fixture.path, b"conflicting edit").unwrap();
    assert!(resume(&fixture.path, &fixture.config.state_dir, token).is_err());
    assert_eq!(marker(&fixture.config).unwrap(), WRITER_MARKER);
    fs::remove_file(lock_path(&fixture.config, "binding").unwrap()).unwrap();
    crate::admin::persist(&fixture.path, &fixture.source).unwrap();
    assert!(resume(&fixture.path, &fixture.config.state_dir, token).is_err());
    assert!(!lock_path(&fixture.config, "binding").unwrap().exists());
}

impl Fixture {
    fn format3() -> Self {
        let mut fixture = Self::new(Some(2));
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        drop(AccountAdmissionGuard::for_migration(&fixture.config, true).unwrap());
        db.execute_batch(
            "ALTER TABLE operations ADD COLUMN binding_revision INTEGER NOT NULL DEFAULT 0;",
        )
        .unwrap();
        db.execute_batch(include_str!("schema3.sql")).unwrap();
        db.execute_batch(
            "UPDATE control SET version=3,paused=1;
            INSERT INTO schedule VALUES('answer',120,'retained-cursor');
            INSERT INTO schedule VALUES('mine:participation',999,NULL);
            INSERT INTO manual_grants VALUES(1,19,'answer',4,20,NULL);
            INSERT INTO manual_grants VALUES(2,19,'judge',4,21,1);
            INSERT INTO manual_grant_revocations VALUES(2,22);
            INSERT INTO operation_timing(operation_id,retry_not_before) VALUES(1,1234);
            INSERT INTO operation_evidence(operation_id,policy,evidence,observed_at)
                VALUES(1,'{\"captured\":true}','{\"remote\":\"uncertain\"}',11);
            INSERT INTO runtime_state VALUES(1,'retained-runtime',0,'{}',23);",
        )
        .unwrap();
        fixture.source = toml::to_string_pretty(&fixture.config)
            .unwrap()
            .into_bytes();
        crate::admin::persist(&fixture.path, &fixture.source).unwrap();
        fixture
    }

    // A data fixture of the exact historical approval envelope, not an old
    // executable or evidence that compatibility has been exercised on Linux.
    fn historical_pending(schema: i64) -> (Self, String, String) {
        let fixture = Self::new(Some(schema));
        let proposal = retired_marker_proposal(&fixture, pre_gate_proposal(fixture.preview()));
        let mut sealed = proposal["seal"].clone();
        sealed
            .as_object_mut()
            .unwrap()
            .remove("target_journal_format");
        // These fields were not part of historical target-3 approval bytes.
        for field in [
            "unbounded_exposure",
            "model_cost_increased",
            "recurring_inference_possible",
            "answer_retry_policy_increased",
        ] {
            sealed["risk"].as_object_mut().unwrap().remove(field);
        }
        let token = format!("{FORMAT}:{}", digest(serde_json::to_vec(&sealed).unwrap()));
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        db.execute_batch("BEGIN IMMEDIATE; ALTER TABLE operations ADD COLUMN binding_revision INTEGER NOT NULL DEFAULT 0;").unwrap();
        db.execute_batch(include_str!("schema3.sql")).unwrap();
        if schema == 1 {
            db.execute(
                "INSERT INTO authority VALUES(1,?1,0)",
                [sealed["snapshot"]["database_id"].as_str().unwrap()],
            )
            .unwrap();
        }
        db.execute_batch(
            "UPDATE control SET version=3,paused=1,generation=generation+1;
            UPDATE operations SET state='unknown' WHERE state='dispatching';
            UPDATE operations SET state='model_unknown' WHERE state='generating';",
        )
        .unwrap();
        db.execute_batch(RECORD_DDL).unwrap();
        db.execute("INSERT INTO capability_migration_evidence(source,row_json) VALUES('historical_fixture','{\"retained\":true}')", []).unwrap();
        sealed["source_toml"] = json!(std::str::from_utf8(&fixture.source).unwrap());
        sealed["candidate_toml"] = proposal["candidate_toml"].clone();
        sealed["risk_acknowledged"] = json!(true);
        sealed["initial_adoption_pending"] = json!(schema == 1);
        sealed["post_evidence_digest"] = json!(evidence_digest(&db).unwrap());
        sealed["sealed_generation"] = json!(5);
        let raw = serde_json::to_string_pretty(&sealed).unwrap();
        db.execute(
            "INSERT INTO capability_migration VALUES(1,'journal_ready',?1,?2)",
            params![token, raw],
        )
        .unwrap();
        db.execute_batch("COMMIT").unwrap();
        (fixture, token, raw)
    }
}

#[test]
fn format3_conversion_requires_pause_and_exact_configuration() {
    let fixture = Fixture::format3();
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    db.execute("UPDATE control SET paused=0", []).unwrap();
    assert!(preview(&fixture.path, &json!({})).is_err());
    db.execute("UPDATE control SET paused=1", []).unwrap();
    assert!(
        preview(
            &fixture.path,
            &json!({"caps":{"answer":2,"judge":1,"mine":1}})
        )
        .is_err()
    );
    assert!(preview(&fixture.path, &json!({"candidate_toml":"schema_version=2"})).is_err());
    let proposal = preview(&fixture.path, &json!({})).unwrap();
    assert_eq!(
        proposal["seal"]["target_journal_format"],
        CURRENT_JOURNAL_FORMAT
    );
    assert_eq!(proposal["risk_change_required"], false);
    assert_eq!(
        proposal["candidate_toml"].as_str().unwrap().as_bytes(),
        fixture.source
    );
    db.execute("UPDATE schedule SET next_at=121 WHERE kind='answer'", [])
        .unwrap();
    assert!(
        apply(
            &fixture.path,
            &proposal["request"],
            proposal["token"].as_str().unwrap(),
            None
        )
        .is_err()
    );
    assert_eq!(
        db.query_row("SELECT version FROM control", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn format3_conversion_preserves_authority_evidence_grants_and_schedule() {
    let fixture = Fixture::format3();
    let db = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .unwrap();
    // A valid older external witness is retained exactly, not advanced to DB sequence 7.
    let binding_path = lock_path(&fixture.config, "binding").unwrap();
    let mut original = read_binding(&fixture.config).unwrap().unwrap();
    original.dispatch_sequence = 6;
    write_binding(&binding_path, &original).unwrap();
    let binding = fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap();
    let authority_before = authority(&db).unwrap();
    let mut operations = Vec::new();
    rows(&db, "operations", |row| {
        operations.push(row);
        Ok(())
    })
    .unwrap();
    drop(db);
    let proposal = preview(&fixture.path, &json!({})).unwrap();
    fixture.stage(&proposal);
    let token = proposal["token"].as_str().unwrap();
    assert!(ensure_no_pending(&fixture.config).is_err());
    resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
    let db = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .unwrap();
    let mut after = Vec::new();
    rows(&db, "operations", |row| {
        after.push(row);
        Ok(())
    })
    .unwrap();
    assert_eq!(operations, after);
    assert_eq!(authority(&db).unwrap(), authority_before);
    let destination = fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap();
    assert_eq!(
        destination,
        current_destination(&fixture.config, &proposal["snapshot"]).unwrap()
    );
    let mut anchored: Binding = serde_json::from_slice(&destination).unwrap();
    assert_eq!(
        anchored.writer_inode,
        Some(
            WriterInode::from_metadata(
                &fs::metadata(lock_path(&fixture.config, "writer").unwrap()).unwrap()
            )
            .unwrap()
        )
    );
    assert_eq!(
        anchored.admission_inode,
        Some(
            WriterInode::from_metadata(
                &fs::metadata(lock_path(&fixture.config, "admission").unwrap()).unwrap()
            )
            .unwrap()
        )
    );
    anchored.writer_inode = None;
    anchored.admission_inode = None;
    assert_eq!(serde_json::to_vec(&anchored).unwrap(), binding);
    assert_eq!(proposal["snapshot"]["binding_bytes"], json!(binding));
    assert_eq!(
        record(&db, Some(token)).unwrap().2["snapshot"]["binding_bytes"],
        json!(binding)
    );
    assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    assert_eq!(
        db.query_row("SELECT generation FROM control", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        db.query_row("SELECT version FROM control", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        CURRENT_JOURNAL_FORMAT
    );
    assert_eq!(
        db.query_row(
            "SELECT next_at,cursor,served_in_round FROM schedule WHERE kind='answer'",
            [],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?
            ))
        )
        .unwrap(),
        (120, "retained-cursor".into(), false)
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM manual_grants WHERE lane_control_revision IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM manual_grant_revocations", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT evidence,model_attempt FROM operation_evidence WHERE operation_id=1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        )
        .unwrap(),
        ("{\"remote\":\"uncertain\"}".into(), None)
    );
    assert_eq!(db.query_row("SELECT retry_not_before,generation_started_at,model_captured_at,queued_since,dispatch_started_at FROM operation_timing WHERE operation_id=1", [],
        |r| Ok((r.get::<_,i64>(0)?,r.get::<_,Option<i64>>(1)?,r.get::<_,Option<i64>>(2)?,
            r.get::<_,Option<i64>>(3)?,r.get::<_,Option<i64>>(4)?))).unwrap(), (1234,None,None,None,None));
    validate_required_lane_state(&db).unwrap();
}

#[test]
fn historical_target3_finishes_unchanged_then_archives_exact_prior_seal() {
    for schema in [1, 2] {
        let (fixture, old_token, raw) = Fixture::historical_pending(schema);
        assert!(preview(&fixture.path, &json!({})).is_err());
        resume(&fixture.path, &fixture.config.state_dir, &old_token).unwrap();
        let db = open_existing(&fixture.config.state_dir, false)
            .unwrap()
            .unwrap();
        assert_eq!(
            db.query_row("SELECT version FROM control", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert!(!table_exists(&db, "lane_control").unwrap());
        let binding_bytes = fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap();
        let binding_value: Value = serde_json::from_slice(&binding_bytes).unwrap();
        assert_eq!(binding_value.as_object().unwrap().len(), 4);
        assert!(binding_value.get("writer_inode").is_none());
        assert!(binding_value.get("admission_inode").is_none());
        let sealed: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            json!(evidence_digest(&db).unwrap()),
            sealed["post_evidence_digest"]
        );
        if schema == 2 {
            assert_eq!(json!(binding_bytes), sealed["snapshot"]["binding_bytes"]);
        } else {
            let binding: Binding = serde_json::from_slice(&binding_bytes).unwrap();
            assert_eq!(serde_json::to_vec(&binding).unwrap(), binding_bytes);
        }
        assert_eq!(
            export(&fixture.config.state_dir, &old_token).unwrap()["sealed_raw"],
            raw
        );
        drop(db);
        let next = preview(&fixture.path, &json!({})).unwrap();
        assert_ne!(next["token"].as_str().unwrap(), old_token);
        apply(
            &fixture.path,
            &next["request"],
            next["token"].as_str().unwrap(),
            None,
        )
        .unwrap();
        assert!(
            read_binding(&fixture.config)
                .unwrap()
                .unwrap()
                .writer_inode
                .is_some()
        );
        let archived = export(&fixture.config.state_dir, &old_token).unwrap();
        assert_eq!(archived["phase"], "complete");
        assert_eq!(archived["sealed_raw"], raw);
        assert!(archived["sealed"].get("target_journal_format").is_none());
        assert_eq!(
            status(&fixture.config.state_dir).unwrap()["history"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let db = open_existing(&fixture.config.state_dir, false)
            .unwrap()
            .unwrap();
        assert_eq!(db.query_row("SELECT row_json FROM capability_migration_evidence WHERE source='historical_fixture'", [],
            |r| r.get::<_,String>(0)).unwrap(), "{\"retained\":true}");
        assert!(resume(&fixture.path, &fixture.config.state_dir, &old_token).is_err());
    }
}

#[test]
fn unknown_or_retargeted_historical_seals_refuse_intact() {
    for mutation in ["format", "target", "source", "hash", "admission", "extra"] {
        let (fixture, token, raw) = Fixture::historical_pending(2);
        let mut sealed: Value = serde_json::from_str(&raw).unwrap();
        match mutation {
            "format" => sealed["format"] = json!("unknown"),
            "target" => sealed["target_journal_format"] = json!(CURRENT_JOURNAL_FORMAT),
            "source" => sealed["snapshot"]["source_schema"] = json!(3),
            "hash" => sealed["source_sha256"] = json!("0".repeat(64)),
            "admission" => {
                sealed["snapshot"]["admission_inode"] =
                    json!({"device":1,"inode":1,"uid":1,"mode":0o100600})
            }
            _ => sealed["ambiguous"] = json!(true),
        }
        let changed = serde_json::to_string(&sealed).unwrap();
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        db.execute("UPDATE capability_migration SET sealed=?1", [&changed])
            .unwrap();
        let before = evidence_digest(&db).unwrap();
        assert!(resume(&fixture.path, &fixture.config.state_dir, &token).is_err());
        assert_eq!(evidence_digest(&db).unwrap(), before);
        assert_eq!(seals::raw_record(&db, None).unwrap().2, changed);
        assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    }
}

#[test]
fn source3_missing_required_tables_or_hybrid_lane_authority_refuse() {
    for sql in [
        "DROP TABLE operation_candidates",
        "CREATE TABLE lane_control(lane TEXT PRIMARY KEY)",
    ] {
        let fixture = Fixture::format3();
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        db.execute_batch(sql).unwrap();
        let before = evidence_digest(&db).unwrap();
        assert!(preview(&fixture.path, &json!({})).is_err());
        assert_eq!(evidence_digest(&db).unwrap(), before);
    }
}

#[test]
fn missing_current_lane_state_during_resume_is_never_repaired() {
    let fixture = Fixture::format3();
    let proposal = preview(&fixture.path, &json!({})).unwrap();
    fixture.stage(&proposal);
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    db.execute("DELETE FROM lane_control WHERE lane='judge'", [])
        .unwrap();
    let before = evidence_digest(&db).unwrap();
    assert!(
        resume(
            &fixture.path,
            &fixture.config.state_dir,
            proposal["token"].as_str().unwrap()
        )
        .is_err()
    );
    assert_eq!(evidence_digest(&db).unwrap(), before);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM lane_control WHERE lane='judge'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        status(&fixture.config.state_dir).unwrap()["phase"],
        "journal_ready"
    );
}

#[test]
fn locked_writer_replacement_before_snapshot_never_seals() {
    let fixture = Fixture::format3();
    let p = prepare(&fixture.path, &json!({})).unwrap();
    let locks = Locks::acquire(&fixture.config).unwrap();
    let path = lock_path(&fixture.config, "writer").unwrap();
    let replacement = path.with_extension("replacement");
    crate::admin::persist(&replacement, WRITER_MARKER).unwrap();
    fs::rename(replacement, &path).unwrap();
    let db = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .unwrap();
    let original_binding = fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap();
    assert!(preview_value(&fixture.path, &p, &json!({}), Some(&db), &locks).is_err());
    assert!(!table_exists(&db, "capability_migration").unwrap());
    assert_eq!(
        fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap(),
        original_binding
    );
}

#[test]
fn target4_binding_installation_accepts_only_exact_source_or_destination() {
    for state in [
        "source",
        "destination",
        "third",
        "missing",
        "anchor",
        "admission_anchor",
        "writer_only",
        "sequence",
    ] {
        let fixture = Fixture::format3();
        let proposal = preview(&fixture.path, &json!({})).unwrap();
        fixture.stage(&proposal);
        let token = proposal["token"].as_str().unwrap();
        let original = export(&fixture.config.state_dir, token).unwrap()["sealed_raw"].clone();
        let destination = current_destination(&fixture.config, &proposal["snapshot"]).unwrap();
        let path = lock_path(&fixture.config, "binding").unwrap();
        match state {
            "destination" => write_binding_bytes(&path, &destination).unwrap(),
            "third" => {
                let mut third = destination.clone();
                third.push(b'\n');
                write_binding_bytes(&path, &third).unwrap();
            }
            "missing" => fs::remove_file(&path).unwrap(),
            "anchor" | "admission_anchor" | "writer_only" | "sequence" => {
                let mut changed: Binding = serde_json::from_slice(&destination).unwrap();
                if state == "anchor" {
                    changed.writer_inode.as_mut().unwrap().inode += 1;
                } else if state == "admission_anchor" {
                    changed.admission_inode.as_mut().unwrap().inode += 1;
                } else if state == "writer_only" {
                    changed.admission_inode = None;
                } else {
                    changed.dispatch_sequence -= 1;
                }
                write_binding(&path, &changed).unwrap();
            }
            _ => {}
        }
        let before = fs::read(&path).ok();
        let result = resume(&fixture.path, &fixture.config.state_dir, token);
        if matches!(state, "source" | "destination") {
            result.unwrap();
            resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
            assert_eq!(fs::read(&path).unwrap(), destination);
        } else {
            assert!(result.is_err(), "{state}");
            assert_eq!(fs::read(&path).ok(), before);
        }
        assert_eq!(
            export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
            original
        );
    }
}

#[test]
fn completed_unanchored4_is_not_retrofitted_by_resume() {
    for removed in ["both", "admission", "writer"] {
        let fixture = Fixture::format3();
        let proposal = preview(&fixture.path, &json!({})).unwrap();
        let token = proposal["token"].as_str().unwrap();
        apply(&fixture.path, &proposal["request"], token, None).unwrap();
        let path = lock_path(&fixture.config, "binding").unwrap();
        let mut binding = read_binding(&fixture.config).unwrap().unwrap();
        if removed != "admission" {
            binding.writer_inode = None;
        }
        if removed != "writer" {
            binding.admission_inode = None;
        }
        write_binding(&path, &binding).unwrap();
        let original = fs::read(&path).unwrap();
        resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(AccountLock::acquire(&fixture.config).is_err());
        assert!(AccountAdmissionGuard::acquire(&fixture.config).is_err());
        assert!(
            AccountAdmissionGuard::for_control(&fixture.config)
                .and_then(|gate| AccountLock::control_store(&fixture.config, &gate))
                .is_err()
        );
        drop(AccountLock::adopt(&fixture.config).unwrap());
        let adopted = read_binding(&fixture.config).unwrap().unwrap();
        assert!(adopted.writer_inode.is_some());
        assert!(adopted.admission_inode.is_some());
    }
}

#[test]
fn pre_gate_anchored_source3_preserves_exact_noncanonical_binding_bytes() {
    let fixture = Fixture::format3();
    let path = lock_path(&fixture.config, "binding").unwrap();
    let mut binding = read_binding(&fixture.config).unwrap().unwrap();
    binding.writer_inode = Some(
        WriterInode::from_metadata(
            &fs::metadata(lock_path(&fixture.config, "writer").unwrap()).unwrap(),
        )
        .unwrap(),
    );
    let original = serde_json::to_vec_pretty(&binding).unwrap();
    write_binding_bytes(&path, &original).unwrap();
    let proposal = pre_gate_proposal(preview(&fixture.path, &json!({})).unwrap());
    fixture.stage(&proposal);
    resume(
        &fixture.path,
        &fixture.config.state_dir,
        proposal["token"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(proposal["snapshot"]["binding_bytes"], json!(original));
}

#[test]
fn pre_gate4_retains_every_prior_adoption_installation_state() {
    for schema in [1, 2] {
        for state in ["absent", "historical", "destination"] {
            for permanent_marker in [false, true] {
                let fixture = Fixture::new(Some(schema));
                let binding_path = lock_path(&fixture.config, "binding").unwrap();
                let legacy_marker = digest(fixture.config.state_dir.as_os_str().as_encoded_bytes());
                if schema == 2 {
                    fs::remove_file(&binding_path).unwrap();
                    let writer_path = lock_path(&fixture.config, "writer").unwrap();
                    let mut writer = lane_control::opened_file(&writer_path, true, false).unwrap();
                    writer.set_len(0).unwrap();
                    writer.write_all(legacy_marker.as_bytes()).unwrap();
                    writer.sync_all().unwrap();
                }
                let proposal = pre_gate_proposal(fixture.preview());
                fixture.stage(&proposal);
                let token = proposal["token"].as_str().unwrap();
                let destination =
                    current_destination(&fixture.config, &proposal["snapshot"]).unwrap();
                match state {
                    "historical" => {
                        let mut binding: Binding = serde_json::from_slice(&destination).unwrap();
                        binding.writer_inode = None;
                        write_binding(&binding_path, &binding).unwrap();
                    }
                    "destination" => write_binding_bytes(&binding_path, &destination).unwrap(),
                    _ => {}
                }
                if permanent_marker {
                    let writer_path = lock_path(&fixture.config, "writer").unwrap();
                    let mut writer = lane_control::opened_file(&writer_path, true, false).unwrap();
                    AccountLock::mark_writer(&mut writer, &writer_path).unwrap();
                }
                let original_binding = fs::read(&binding_path).ok();
                let original_marker = marker(&fixture.config).unwrap();
                let original = export(&fixture.config.state_dir, token).unwrap();
                let db = open_existing(&fixture.config.state_dir, false)
                    .unwrap()
                    .unwrap();
                let before = evidence_digest(&db).unwrap();
                let result = resume(&fixture.path, &fixture.config.state_dir, token);
                if state == "absent" && permanent_marker {
                    assert!(result.is_err());
                    assert_eq!(fs::read(&binding_path).ok(), original_binding);
                    assert_eq!(marker(&fixture.config).unwrap(), original_marker);
                    assert_eq!(
                        status(&fixture.config.state_dir).unwrap()["phase"],
                        "journal_ready"
                    );
                } else {
                    let complete = result.unwrap();
                    assert_eq!(complete["further_migration_required"], false);
                    assert!(complete["recovery_prerequisite"].is_string());
                    assert_eq!(fs::read(&binding_path).unwrap(), destination);
                    let binding = read_binding(&fixture.config).unwrap().unwrap();
                    assert!(binding.writer_inode.is_some());
                    assert!(binding.admission_inode.is_none());
                    assert!(AccountAdmissionGuard::acquire(&fixture.config).is_err());
                    resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
                    assert_eq!(fs::read(&binding_path).unwrap(), destination);
                }
                assert_eq!(evidence_digest(&db).unwrap(), before);
                assert_eq!(
                    export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
                    original["sealed_raw"]
                );
                if state == "destination" && permanent_marker {
                    drop(AccountLock::adopt(&fixture.config).unwrap());
                    let adopted = fs::read(&binding_path).unwrap();
                    let adopted_digest = evidence_digest(&db).unwrap();
                    resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
                    assert_eq!(fs::read(&binding_path).unwrap(), adopted);
                    assert_eq!(evidence_digest(&db).unwrap(), adopted_digest);
                    assert_eq!(
                        export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
                        original["sealed_raw"]
                    );
                }
            }
        }
    }
}

#[test]
fn pre_gate4_established_source_and_writer_destination_remain_exact() {
    for schema in [2, 3] {
        for state in [
            "source",
            "destination",
            "replaced_gate",
            "third",
            "admission",
            "witness",
            "missing",
        ] {
            let fixture = if schema == 3 {
                Fixture::format3()
            } else {
                Fixture::new(Some(2))
            };
            let proposal = pre_gate_proposal(if schema == 3 {
                preview(&fixture.path, &json!({})).unwrap()
            } else {
                fixture.preview()
            });
            fixture.stage(&proposal);
            let token = proposal["token"].as_str().unwrap();
            let path = lock_path(&fixture.config, "binding").unwrap();
            let destination = current_destination(&fixture.config, &proposal["snapshot"]).unwrap();
            match state {
                "destination" => write_binding_bytes(&path, &destination).unwrap(),
                "replaced_gate" => {
                    // An authentic old approval did not record this identity.
                    // It may finish writer-only, never learn an admission anchor.
                    let gate = lock_path(&fixture.config, "admission").unwrap();
                    let replacement = gate.with_extension("replacement");
                    crate::admin::persist(&replacement, &fs::read(&gate).unwrap()).unwrap();
                    fs::rename(replacement, gate).unwrap();
                }
                "third" => {
                    let mut third = destination.clone();
                    third.push(b'\n');
                    write_binding_bytes(&path, &third).unwrap();
                }
                "admission" | "witness" => {
                    let mut changed: Binding = serde_json::from_slice(&destination).unwrap();
                    if state == "admission" {
                        changed.admission_inode = Some(
                            WriterInode::from_metadata(
                                &fs::metadata(lock_path(&fixture.config, "admission").unwrap())
                                    .unwrap(),
                            )
                            .unwrap(),
                        );
                    } else {
                        changed.dispatch_sequence -= 1;
                    }
                    write_binding(&path, &changed).unwrap();
                }
                "missing" => fs::remove_file(&path).unwrap(),
                _ => {}
            }
            let original = export(&fixture.config.state_dir, token).unwrap();
            let installed = fs::read(&path).ok();
            let db = open_existing(&fixture.config.state_dir, false)
                .unwrap()
                .unwrap();
            let before = evidence_digest(&db).unwrap();
            let result = resume(&fixture.path, &fixture.config.state_dir, token);
            if matches!(state, "source" | "destination" | "replaced_gate") {
                result.unwrap();
                assert_eq!(fs::read(&path).unwrap(), destination);
                assert!(
                    read_binding(&fixture.config)
                        .unwrap()
                        .unwrap()
                        .admission_inode
                        .is_none()
                );
            } else {
                assert!(result.is_err(), "{schema}/{state}");
                assert_eq!(fs::read(&path).ok(), installed);
                assert_eq!(
                    status(&fixture.config.state_dir).unwrap()["phase"],
                    "journal_ready"
                );
            }
            assert_eq!(evidence_digest(&db).unwrap(), before);
            assert_eq!(
                export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
                original["sealed_raw"]
            );
        }
    }
}

#[test]
fn new4_adoption_installs_only_the_approved_dual_anchor_destination() {
    for schema in [1, 2] {
        for state in [
            "absent",
            "destination",
            "marked_destination",
            "historical",
            "writer_only",
            "admission_only",
            "third",
            "missing_after_marker",
        ] {
            let fixture = Fixture::new(Some(schema));
            let path = lock_path(&fixture.config, "binding").unwrap();
            if schema == 2 {
                fs::remove_file(&path).unwrap();
                let mut writer =
                    AccountLock::rotation_lock_file(&fixture.config, "writer").unwrap();
                writer.set_len(0).unwrap();
                writer
                    .write_all(
                        digest(fixture.config.state_dir.as_os_str().as_encoded_bytes()).as_bytes(),
                    )
                    .unwrap();
                writer.sync_all().unwrap();
            }
            let proposal = fixture.preview();
            fixture.stage(&proposal);
            let token = proposal["token"].as_str().unwrap();
            let destination = current_destination(&fixture.config, &proposal["snapshot"]).unwrap();
            if !matches!(state, "absent" | "missing_after_marker") {
                let mut binding: Binding = serde_json::from_slice(&destination).unwrap();
                if matches!(state, "historical" | "admission_only") {
                    binding.writer_inode = None;
                }
                if matches!(state, "historical" | "writer_only") {
                    binding.admission_inode = None;
                }
                let mut installed = serde_json::to_vec(&binding).unwrap();
                if state == "third" {
                    installed.push(b'\n');
                }
                write_binding_bytes(&path, &installed).unwrap();
            }
            if matches!(state, "marked_destination" | "missing_after_marker") {
                let writer_path = lock_path(&fixture.config, "writer").unwrap();
                let mut writer = lane_control::opened_file(&writer_path, true, false).unwrap();
                AccountLock::mark_writer(&mut writer, &writer_path).unwrap();
            }
            let original = export(&fixture.config.state_dir, token).unwrap();
            let db = open_existing(&fixture.config.state_dir, false)
                .unwrap()
                .unwrap();
            let before = evidence_digest(&db).unwrap();
            let installed_before = fs::read(&path).ok();
            let marker_before = marker(&fixture.config).unwrap();
            let result = resume(&fixture.path, &fixture.config.state_dir, token);
            if matches!(state, "absent" | "destination" | "marked_destination") {
                result.unwrap();
                assert_eq!(fs::read(&path).unwrap(), destination);
                let binding = read_binding(&fixture.config).unwrap().unwrap();
                assert!(binding.writer_inode.is_some());
                assert!(binding.admission_inode.is_some());
                assert_eq!(marker(&fixture.config).unwrap(), WRITER_MARKER);
                resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
                assert_eq!(fs::read(&path).unwrap(), destination);
            } else {
                assert!(result.is_err(), "{schema}/{state}");
                assert_eq!(fs::read(&path).ok(), installed_before);
                assert_eq!(marker(&fixture.config).unwrap(), marker_before);
                assert_eq!(
                    status(&fixture.config.state_dir).unwrap()["phase"],
                    "journal_ready"
                );
            }
            assert_eq!(evidence_digest(&db).unwrap(), before);
            assert_eq!(
                export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
                original["sealed_raw"]
            );
        }
    }
}

#[test]
fn new4_source3_preserves_approved_bytes_and_existing_anchor_values() {
    for anchors in ["none", "writer", "admission", "both"] {
        let fixture = Fixture::format3();
        let path = lock_path(&fixture.config, "binding").unwrap();
        let mut source = read_binding(&fixture.config).unwrap().unwrap();
        let writer = WriterInode::from_metadata(
            &fs::metadata(lock_path(&fixture.config, "writer").unwrap()).unwrap(),
        )
        .unwrap();
        let admission = WriterInode::from_metadata(
            &fs::metadata(lock_path(&fixture.config, "admission").unwrap()).unwrap(),
        )
        .unwrap();
        if matches!(anchors, "writer" | "both") {
            source.writer_inode = Some(writer);
        }
        if matches!(anchors, "admission" | "both") {
            source.admission_inode = Some(admission);
        }
        source.dispatch_sequence -= 1;
        let original = serde_json::to_vec_pretty(&source).unwrap();
        write_binding_bytes(&path, &original).unwrap();
        let proposal = preview(&fixture.path, &json!({})).unwrap();
        let token = proposal["token"].as_str().unwrap();
        apply(&fixture.path, &proposal["request"], token, None).unwrap();
        let installed = fs::read(&path).unwrap();
        let mut expected = source;
        expected.writer_inode = Some(writer);
        expected.admission_inode = Some(admission);
        assert_eq!(
            installed,
            if anchors == "both" {
                original.clone()
            } else {
                serde_json::to_vec(&expected).unwrap()
            }
        );
        assert_eq!(proposal["snapshot"]["binding_bytes"], json!(original));
        assert_eq!(
            export(&fixture.config.state_dir, token).unwrap()["sealed"]["snapshot"]["binding_bytes"],
            json!(original)
        );
    }
}

#[test]
fn locked_admission_replacement_before_snapshot_never_seals() {
    for rewrite_binding in [false, true] {
        let fixture = Fixture::format3();
        let p = prepare(&fixture.path, &json!({})).unwrap();
        let locks = Locks::acquire(&fixture.config).unwrap();
        let path = lock_path(&fixture.config, "admission").unwrap();
        let replacement = path.with_extension("replacement");
        crate::admin::persist(&replacement, &fs::read(&path).unwrap()).unwrap();
        fs::rename(replacement, &path).unwrap();
        if rewrite_binding {
            let mut binding = read_binding(&fixture.config).unwrap().unwrap();
            binding.admission_inode =
                Some(WriterInode::from_metadata(&fs::metadata(&path).unwrap()).unwrap());
            write_binding(&lock_path(&fixture.config, "binding").unwrap(), &binding).unwrap();
        }
        let db = open_existing(&fixture.config.state_dir, false)
            .unwrap()
            .unwrap();
        let original_binding = fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap();
        assert!(preview_value(&fixture.path, &p, &json!({}), Some(&db), &locks).is_err());
        assert!(!table_exists(&db, "capability_migration").unwrap());
        assert_eq!(
            fs::read(lock_path(&fixture.config, "binding").unwrap()).unwrap(),
            original_binding
        );
    }
}

#[test]
fn new4_missing_replaced_or_reanchored_gate_refuses_without_repair() {
    for pending in [false, true] {
        for changed in ["missing", "replaced", "reanchored"] {
            let fixture = Fixture::format3();
            let proposal = preview(&fixture.path, &json!({})).unwrap();
            let token = proposal["token"].as_str().unwrap();
            if pending {
                fixture.stage(&proposal);
            }
            let path = lock_path(&fixture.config, "admission").unwrap();
            if changed == "missing" {
                fs::remove_file(&path).unwrap();
            } else {
                let replacement = path.with_extension("replacement");
                crate::admin::persist(&replacement, &fs::read(&path).unwrap()).unwrap();
                fs::rename(replacement, &path).unwrap();
                if changed == "reanchored" {
                    let mut binding = read_binding(&fixture.config).unwrap().unwrap();
                    binding.admission_inode =
                        Some(WriterInode::from_metadata(&fs::metadata(&path).unwrap()).unwrap());
                    write_binding(&lock_path(&fixture.config, "binding").unwrap(), &binding)
                        .unwrap();
                }
            }
            let binding_path = lock_path(&fixture.config, "binding").unwrap();
            let binding_before = fs::read(&binding_path).unwrap();
            let gate_before = fs::metadata(&path)
                .ok()
                .map(|metadata| metadata_identity(&metadata).unwrap());
            let db = open_existing(&fixture.config.state_dir, false)
                .unwrap()
                .unwrap();
            let before = evidence_digest(&db).unwrap();
            let seal_before = if pending {
                Some(seals::raw_record(&db, None).unwrap())
            } else {
                None
            };
            let result = if pending {
                resume(&fixture.path, &fixture.config.state_dir, token)
            } else {
                apply(&fixture.path, &proposal["request"], token, None)
            };
            assert!(result.is_err(), "{pending}/{changed}");
            assert_eq!(fs::read(&binding_path).unwrap(), binding_before);
            assert_eq!(
                fs::metadata(&path)
                    .ok()
                    .map(|metadata| metadata_identity(&metadata).unwrap()),
                gate_before
            );
            assert_eq!(evidence_digest(&db).unwrap(), before);
            assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
            if let Some(seal_before) = seal_before {
                assert_eq!(seals::raw_record(&db, None).unwrap(), seal_before);
            } else {
                assert!(!table_exists(&db, "capability_migration").unwrap());
            }
        }
    }
}

#[test]
fn present_malformed_admission_snapshot_never_selects_pre_gate_recovery() {
    for mutation in ["null", "partial", "string", "zero", "uid", "mode", "extra"] {
        let fixture = Fixture::format3();
        let proposal = preview(&fixture.path, &json!({})).unwrap();
        fixture.stage(&proposal);
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        let (_, _, mut sealed) = record(&db, None).unwrap();
        let metadata = &mut sealed["snapshot"]["admission_inode"];
        match mutation {
            "null" => *metadata = Value::Null,
            "partial" => {
                metadata.as_object_mut().unwrap().remove("uid");
            }
            "string" => metadata["inode"] = json!("123"),
            "zero" => metadata["inode"] = json!(0),
            "uid" => metadata["uid"] = json!(u64::MAX),
            "mode" => metadata["mode"] = json!(0o100666),
            _ => metadata["extra"] = json!(true),
        }
        let mut approval = sealed.clone();
        for key in [
            "source_toml",
            "candidate_toml",
            "risk_acknowledged",
            "initial_adoption_pending",
            "post_evidence_digest",
            "sealed_generation",
        ] {
            approval.as_object_mut().unwrap().remove(key);
        }
        let token = format!(
            "{FORMAT}:{}",
            digest(serde_json::to_vec(&approval).unwrap())
        );
        let raw = serde_json::to_string(&sealed).unwrap();
        db.execute(
            "UPDATE capability_migration SET token=?1,sealed=?2",
            params![token, raw],
        )
        .unwrap();
        let binding_path = lock_path(&fixture.config, "binding").unwrap();
        let binding_before = fs::read(&binding_path).unwrap();
        let before = evidence_digest(&db).unwrap();
        assert!(seals::target(&token, &sealed).is_err(), "{mutation}");
        assert_eq!(
            status(&fixture.config.state_dir).unwrap()["recovery_supported"],
            false
        );
        assert!(resume(&fixture.path, &fixture.config.state_dir, &token).is_err());
        assert_eq!(evidence_digest(&db).unwrap(), before);
        assert_eq!(
            seals::raw_record(&db, None).unwrap(),
            ("journal_ready".into(), token, raw)
        );
        assert_eq!(fs::read(&binding_path).unwrap(), binding_before);
        assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
    }
}

#[test]
fn malformed_present_binding_admission_refuses_preview_without_normalization() {
    for metadata in [
        Value::Null,
        json!({"device":1}),
        json!({"device":1,"inode":0}),
    ] {
        let fixture = Fixture::format3();
        let path = lock_path(&fixture.config, "binding").unwrap();
        let mut binding: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        binding["admission_inode"] = metadata;
        let raw = serde_json::to_vec(&binding).unwrap();
        write_binding_bytes(&path, &raw).unwrap();
        let db = open_existing(&fixture.config.state_dir, false)
            .unwrap()
            .unwrap();
        let before = evidence_digest(&db).unwrap();
        assert!(preview(&fixture.path, &json!({})).is_err());
        assert_eq!(evidence_digest(&db).unwrap(), before);
        assert!(!table_exists(&db, "capability_migration").unwrap());
        assert_eq!(fs::read(&path).unwrap(), raw);
    }
}

#[test]
fn new4_gate_member_removal_cannot_reuse_the_authenticated_token() {
    let fixture = Fixture::format3();
    let proposal = preview(&fixture.path, &json!({})).unwrap();
    fixture.stage(&proposal);
    let token = proposal["token"].as_str().unwrap();
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    let (_, _, mut sealed) = record(&db, Some(token)).unwrap();
    sealed["snapshot"]
        .as_object_mut()
        .unwrap()
        .remove("admission_inode");
    let raw = serde_json::to_string(&sealed).unwrap();
    db.execute("UPDATE capability_migration SET sealed=?1", [&raw])
        .unwrap();
    let path = lock_path(&fixture.config, "binding").unwrap();
    let binding_before = fs::read(&path).unwrap();
    let before = evidence_digest(&db).unwrap();
    assert!(seals::target(token, &sealed).is_err());
    assert!(resume(&fixture.path, &fixture.config.state_dir, token).is_err());
    assert_eq!(fs::read(path).unwrap(), binding_before);
    assert_eq!(evidence_digest(&db).unwrap(), before);
    assert_eq!(
        seals::raw_record(&db, None).unwrap(),
        ("journal_ready".into(), token.into(), raw)
    );
    assert_eq!(bytes(&fixture.path).unwrap(), fixture.source);
}

// Construct approval bytes using the deployed marker and old effective digest
// before sealing, rather than mutating an authenticated stored record.
fn retired_marker_proposal(fixture: &Fixture, mut proposal: Value) -> Value {
    let candidate = format!(
        "schema_version = 2\n{}",
        proposal["candidate_toml"].as_str().unwrap()
    );
    proposal["candidate_toml"] = json!(candidate);
    proposal["request"]["candidate_toml"] = json!(candidate);
    proposal["seal"]["request"] = proposal["request"].clone();
    proposal["seal"]["candidate_sha256"] = json!(digest(candidate.as_bytes()));
    #[derive(serde::Serialize)]
    struct RetiredConfig<'a> {
        schema_version: u32,
        #[serde(flatten)]
        config: &'a Config,
    }
    let config = sealed_config(&fixture.path, &candidate).unwrap();
    let mut hash = Sha256::new();
    hash.update(
        serde_json::to_vec(&RetiredConfig {
            schema_version: 2,
            config: &config,
        })
        .unwrap(),
    );
    for model in [
        &config.capabilities.answer.model,
        &config.capabilities.judge.model,
    ] {
        hash.update((model.guidance.len() as u64).to_le_bytes());
        hash.update(model.guidance.as_bytes());
        hash.update((model.core_guidance.len() as u64).to_le_bytes());
        hash.update(model.core_guidance.as_bytes());
    }
    proposal["seal"]["effective_revision"] = json!(format!("{:x}", hash.finalize()));
    proposal["token"] = json!(format!(
        "{FORMAT}:{}",
        digest(serde_json::to_vec(&proposal["seal"]).unwrap())
    ));
    proposal
}

#[test]
fn authentic_pre_gate_marker_candidate_resumes_exact_bytes_and_old_revision() {
    let fixture = Fixture::new(Some(2));
    let proposal = retired_marker_proposal(&fixture, pre_gate_proposal(fixture.preview()));
    let token = proposal["token"].as_str().unwrap();
    let mut p = prepare(&fixture.path, &fixture.preview()["request"]).unwrap();
    p.candidate = proposal["candidate_toml"].as_str().unwrap().to_owned();
    let locks = Locks::acquire(&p.config).unwrap();
    let mut db = open_existing(&p.config.state_dir, true).unwrap().unwrap();
    let gates = provision_lane_gates(
        &p.config,
        proposal["snapshot"]["database_id"].as_str().unwrap(),
        &locks.admission,
        &locks.writer,
    )
    .unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    approved(&proposal, token, Some(token)).unwrap();
    seal_conversion(&tx, &p, &proposal, token, Some(token), &gates).unwrap();
    tx.commit().unwrap();
    let raw = seals::raw_record(&db, None).unwrap().2;
    drop(db);
    drop(gates);
    drop(locks);
    resume(&fixture.path, &fixture.config.state_dir, token).unwrap();
    assert_eq!(bytes(&fixture.path).unwrap(), p.candidate.as_bytes());
    assert!(Config::load(&fixture.path).is_err());
    assert_eq!(
        status(&fixture.config.state_dir).unwrap()["further_migration_required"],
        true
    );
    assert_eq!(
        export(&fixture.config.state_dir, token).unwrap()["sealed_raw"],
        raw
    );
}

#[test]
fn journal4_marker_cutover_preserves_all_existing_journal_rows_and_archives_seal() {
    let fixture = Fixture::format3();
    let initial = preview(&fixture.path, &json!({})).unwrap();
    let old_token = initial["token"].as_str().unwrap();
    apply(&fixture.path, &initial["request"], old_token, None).unwrap();
    let old_raw = export(&fixture.config.state_dir, old_token).unwrap()["sealed_raw"].clone();
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    db.execute("UPDATE control SET paused=0", []).unwrap();
    assert!(preview(&fixture.path, &json!({})).is_err());
    db.execute("UPDATE control SET paused=1", []).unwrap();
    db.execute(
        "UPDATE lane_control SET paused=1,control_revision=7 WHERE lane='judge'",
        [],
    )
    .unwrap();
    // Distinct lane controls and runtime evidence must survive a config-only cutover.
    let mut tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'capability_migration%' ORDER BY name").unwrap();
    let names: Vec<String> = tables
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    drop(tables);
    let mut before = Vec::new();
    for name in &names {
        rows(&db, name, |row| {
            before.push((name.clone(), row));
            Ok(())
        })
        .unwrap();
    }
    let source = format!(
        "schema_version = 2\n{}",
        std::str::from_utf8(&bytes(&fixture.path).unwrap()).unwrap()
    );
    crate::admin::persist(&fixture.path, source.as_bytes()).unwrap();
    assert!(Config::load(&fixture.path).is_err());
    let proposal = preview(&fixture.path, &json!({})).unwrap();
    assert_eq!(proposal["risk_change_required"], false);
    assert!(
        !proposal["candidate_toml"]
            .as_str()
            .unwrap()
            .contains("schema_version")
    );
    apply(
        &fixture.path,
        &proposal["request"],
        proposal["token"].as_str().unwrap(),
        None,
    )
    .unwrap();
    Config::load(&fixture.path).unwrap();
    let mut after = Vec::new();
    for name in &names {
        rows(&db, name, |row| {
            after.push((name.clone(), row));
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(before, after);
    assert_eq!(
        export(&fixture.config.state_dir, old_token).unwrap()["sealed_raw"],
        old_raw
    );
}

#[test]
fn no_journal_per_lane_cutovers_and_ambiguous_shapes_fail_closed() {
    for marked in [false, true] {
        let fixture = Fixture::new(None);
        let text = toml::to_string(&fixture.config).unwrap();
        let source = if marked {
            format!("schema_version=2\n{text}")
        } else {
            text
        };
        crate::admin::persist(&fixture.path, source.as_bytes()).unwrap();
        let proposal = preview(&fixture.path, &json!({})).unwrap();
        apply(
            &fixture.path,
            &proposal["request"],
            proposal["token"].as_str().unwrap(),
            None,
        )
        .unwrap();
        Config::load(&fixture.path).unwrap();
    }
    for text in [
        "",
        "[network]\n",
        "[capabilities]\n",
        "[runtime]\n[participation]\n",
        "[capabilities]\nanswer='off'\n[capabilities.judge]\nmode='off'\n",
    ] {
        assert!(
            global_shape(&toml::from_str(text).unwrap()).is_err(),
            "{text}"
        );
    }
}

type UpgradeInspectionEvidence = (Vec<PathBuf>, Vec<(PathBuf, Vec<u8>)>, Option<String>);

// Capture consumer-visible durable evidence, including the absence of lock files.
// SQLite's shared-memory coordination bytes are not migration journal evidence.
fn upgrade_inspection_evidence(fixture: &Fixture) -> UpgradeInspectionEvidence {
    fn paths(root: &Path, result: &mut Vec<PathBuf>) {
        if root.is_dir() {
            for entry in fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                result.push(path.clone());
                paths(&path, result);
            }
        }
    }
    let journal = open_existing(&fixture.config.state_dir, false)
        .unwrap()
        .map(|db| evidence_digest(&db).unwrap());
    // List paths after observing SQLite: this collector's read-only WAL reader
    // can itself establish coordination sidecars before returning the snapshot.
    let mut files = Vec::new();
    paths(fixture._temp.path(), &mut files);
    files.sort();
    let writer = lock_path(&fixture.config, "writer").unwrap();
    let prefix = format!("{}.", writer.file_stem().unwrap().to_string_lossy());
    let mut authority = Vec::new();
    if let Ok(entries) = fs::read_dir(writer.parent().unwrap()) {
        for entry in entries {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                authority.push((entry.path(), fs::read(entry.path()).unwrap()));
            }
        }
    }
    authority.push((fixture.path.clone(), bytes(&fixture.path).unwrap()));
    authority.sort();
    (files, authority, journal)
}

fn current_upgrade_fixture() -> Fixture {
    let fixture = Fixture::format3();
    let proposal = preview(&fixture.path, &json!({})).unwrap();
    apply(
        &fixture.path,
        &proposal["request"],
        proposal["token"].as_str().unwrap(),
        None,
    )
    .unwrap();
    fixture
}

#[test]
fn upgrade_inspection_and_proposal_preflight_never_initialize_config_only_sources() {
    for kind in [
        UpgradeKind::Conversion,
        UpgradeKind::MarkerOnly,
        UpgradeKind::Compatible,
    ] {
        let fixture = Fixture::new(None);
        if kind != UpgradeKind::Conversion {
            let text = toml::to_string(&fixture.config).unwrap();
            let source = if kind == UpgradeKind::MarkerOnly {
                format!("schema_version=2\n{text}")
            } else {
                text
            };
            crate::admin::persist(&fixture.path, source.as_bytes()).unwrap();
        }
        let before = upgrade_inspection_evidence(&fixture);
        let inspected = inspect_upgrade(&fixture.path).unwrap();
        assert_eq!(inspected.kind, kind);
        assert_eq!(inspected.state_dir, fixture.config.state_dir);
        assert_eq!(
            inspected.source_sha256,
            digest(bytes(&fixture.path).unwrap())
        );
        assert_eq!(inspected.journal_format, None);
        assert_eq!(inspected.paused, None);
        assert_eq!(inspected.generation, None);
        assert_eq!(inspected.database_id, None);
        assert_eq!(inspected.dispatch_sequence, None);
        assert_eq!(
            automatic_upgrade(&fixture.path).unwrap(),
            AutomaticUpgrade::Preserving
        );
        assert!(inspected.pending.is_none());
        validate_upgrade_proposal(&fixture.path, &json!({})).unwrap();
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
        assert!(!fixture.config.state_dir.exists());
        assert!(!lock_path(&fixture.config, "writer").unwrap().exists());
        assert!(!lock_path(&fixture.config, "admission").unwrap().exists());
        assert!(!lock_path(&fixture.config, "binding").unwrap().exists());
    }
}

#[test]
fn upgrade_legacy_inspection_discovers_without_caps_but_never_invents_policy_or_adoption() {
    for schema in [1, 2] {
        let mut fixture = Fixture::new(Some(schema));
        let mut legacy = legacy::Legacy::parse(&fixture.source).unwrap();
        legacy.participation.mode = ParticipationMode::ParticipationFirst;
        legacy.participation.allow_judge = true;
        fixture.source = toml::to_string(&legacy).unwrap().into_bytes();
        crate::admin::persist(&fixture.path, &fixture.source).unwrap();
        let before = upgrade_inspection_evidence(&fixture);
        let inspected = inspect_upgrade(&fixture.path).unwrap();
        assert_eq!(inspected.kind, UpgradeKind::Conversion);
        assert_eq!(inspected.journal_format, Some(schema));
        assert_eq!(inspected.paused, Some(false));
        assert_eq!(inspected.generation, Some(4));
        assert_eq!(inspected.dispatch_sequence, (schema == 2).then_some(7));
        assert_eq!(
            automatic_upgrade(&fixture.path).unwrap(),
            AutomaticUpgrade::DecisionRequired("lane_limits_required")
        );
        let missing = validate_upgrade_proposal(&fixture.path, &json!({})).unwrap_err();
        assert!(matches!(
            missing.downcast_ref::<MigrationError>(),
            Some(MigrationError::LimitsRequired)
        ));
        let caps = json!({"caps":{"answer":2,"judge":1,"mine":1}});
        if schema == 1 {
            assert!(validate_upgrade_proposal(&fixture.path, &caps).is_err());
            let approved = json!({"caps":{"answer":2,"judge":1,"mine":1},"adopt_legacy":true});
            validate_upgrade_proposal(&fixture.path, &approved).unwrap();
            assert!(validate_upgrade_proposal(
                &fixture.path,
                &json!({"caps":{"answer":2,"judge":1,"mine":1},"adopt_legacy":true,"initial_database_id":"invalid"}),
            ).is_err());
        } else {
            validate_upgrade_proposal(&fixture.path, &caps).unwrap();
        }
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
        // Validation is not risk approval and does not seal even an increased exposure.
        let db = open_existing(&fixture.config.state_dir, false)
            .unwrap()
            .unwrap();
        assert!(!table_exists(&db, "capability_migration").unwrap());
    }
    let fixture = Fixture::new(Some(2));
    fs::remove_file(lock_path(&fixture.config, "binding").unwrap()).unwrap();
    fs::write(
        lock_path(&fixture.config, "writer").unwrap(),
        digest(fixture.config.state_dir.as_os_str().as_encoded_bytes()),
    )
    .unwrap();
    assert_eq!(
        inspect_upgrade(&fixture.path).unwrap().kind,
        UpgradeKind::Conversion
    );
    assert!(validate_upgrade_proposal(&fixture.path, &json!({})).is_err());
    validate_upgrade_proposal(&fixture.path, &json!({"adopt_legacy":true})).unwrap();
    assert_eq!(
        automatic_upgrade(&fixture.path).unwrap(),
        AutomaticUpgrade::DecisionRequired("authority_adoption_required")
    );
}

#[test]
fn upgrade_marker4_and_source3_preflight_do_not_require_or_change_the_future_pause() {
    for current in [false, true] {
        let fixture = if current {
            current_upgrade_fixture()
        } else {
            Fixture::format3()
        };
        let source = format!(
            "schema_version=2\n{}",
            String::from_utf8(bytes(&fixture.path).unwrap()).unwrap()
        );
        crate::admin::persist(&fixture.path, source.as_bytes()).unwrap();
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        db.execute("UPDATE control SET paused=0", []).unwrap();
        drop(db);
        let before = upgrade_inspection_evidence(&fixture);
        let inspected = inspect_upgrade(&fixture.path).unwrap();
        assert_eq!(
            inspected.kind,
            if current {
                UpgradeKind::MarkerOnly
            } else {
                UpgradeKind::Conversion
            }
        );
        assert_eq!(inspected.journal_format, Some(if current { 4 } else { 3 }));
        assert_eq!(inspected.paused, Some(false));
        validate_upgrade_proposal(&fixture.path, &json!({})).unwrap();
        assert_eq!(
            automatic_upgrade(&fixture.path).unwrap(),
            AutomaticUpgrade::Preserving
        );
        assert!(
            validate_upgrade_proposal(
                &fixture.path,
                &json!({"caps":{"answer":2,"judge":1,"mine":1}})
            )
            .is_err()
        );
        let mut changed = fixture.config.clone();
        changed.runtime.shutdown_seconds += 1;
        assert!(
            validate_upgrade_proposal(
                &fixture.path,
                &json!({"candidate_toml":toml::to_string(&changed).unwrap()}),
            )
            .is_err()
        );
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
        assert!(preview(&fixture.path, &json!({})).is_err());
        assert!(automatic_preview(&fixture.path).is_err());
    }
}

#[test]
fn upgrade_current_compatibility_uses_metadata_and_not_a_completed_seals_stale_inputs() {
    let fixture = current_upgrade_fixture();
    let mut current = Config::load_metadata(&fixture.path).unwrap();
    current.runtime.shutdown_seconds += 1;
    current.capabilities.answer.model.guidance_file =
        Some(fixture._temp.path().join("missing-guidance"));
    crate::admin::persist(&fixture.path, toml::to_string(&current).unwrap().as_bytes()).unwrap();
    let db = open_existing(&fixture.config.state_dir, true)
        .unwrap()
        .unwrap();
    db.execute("UPDATE control SET paused=0,generation=generation+7", [])
        .unwrap();
    drop(db);
    let before = upgrade_inspection_evidence(&fixture);
    let inspected = inspect_upgrade(&fixture.path).unwrap();
    assert_eq!(inspected.kind, UpgradeKind::Compatible);
    assert_eq!(inspected.journal_format, Some(CURRENT_JOURNAL_FORMAT));
    assert_eq!(inspected.paused, Some(false));
    assert!(inspected.pending.is_none());
    assert_eq!(upgrade_inspection_evidence(&fixture), before);
}

#[test]
fn upgrade_pending_discovery_preserves_canonical_target_token_and_prerequisites_without_caps() {
    for pre_gate in [false, true] {
        let mut fixture = Fixture::new(Some(2));
        let mut legacy = legacy::Legacy::parse(&fixture.source).unwrap();
        legacy.participation.mode = ParticipationMode::ParticipationFirst;
        legacy.participation.allow_judge = true;
        fixture.source = toml::to_string(&legacy).unwrap().into_bytes();
        crate::admin::persist(&fixture.path, &fixture.source).unwrap();
        let proposal = fixture.preview();
        let proposal = if pre_gate {
            pre_gate_proposal(proposal)
        } else {
            proposal
        };
        fixture.stage(&proposal);
        let before = upgrade_inspection_evidence(&fixture);
        let inspected = inspect_upgrade(&fixture.path).unwrap();
        assert_eq!(inspected.kind, UpgradeKind::Pending);
        assert_eq!(inspected.journal_format, Some(4));
        let pending = inspected.pending.unwrap();
        assert_eq!(pending, status(&fixture.config.state_dir).unwrap());
        assert_eq!(pending["token"], proposal["token"]);
        assert_eq!(pending["target_journal_format"], 4);
        assert_eq!(pending["recovery_supported"], true);
        assert_eq!(pending["recovery_prerequisite"].is_string(), pre_gate);
        assert!(pending.get("candidate_toml").is_none());
        assert!(pending.get("seal").is_none());
        assert!(validate_upgrade_proposal(&fixture.path, &json!({})).is_err());
        assert!(automatic_upgrade(&fixture.path).is_err());
        assert!(automatic_preview(&fixture.path).is_err());
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
    }
    let (fixture, token, _) = Fixture::historical_pending(1);
    let before = upgrade_inspection_evidence(&fixture);
    let inspected = inspect_upgrade(&fixture.path).unwrap();
    assert_eq!(inspected.kind, UpgradeKind::Pending);
    let pending = inspected.pending.unwrap();
    assert_eq!(pending["token"], token);
    assert_eq!(pending["target_journal_format"], 3);
    assert_eq!(pending["further_migration_required"], true);
    assert!(automatic_upgrade(&fixture.path).is_err());
    assert!(automatic_preview(&fixture.path).is_err());
    assert_eq!(upgrade_inspection_evidence(&fixture), before);
}

#[test]
fn upgrade_pre_gate4_discovery_accepts_historical_intermediates_but_never_adopts_them() {
    let fixture = Fixture::new(Some(1));
    let proposal = pre_gate_proposal(fixture.preview());
    fixture.stage(&proposal);
    let mut intermediate: Binding = serde_json::from_slice(
        &current_destination(&fixture.config, &proposal["snapshot"]).unwrap(),
    )
    .unwrap();
    intermediate.writer_inode = None;
    intermediate.admission_inode = None;
    write_binding(
        &lock_path(&fixture.config, "binding").unwrap(),
        &intermediate,
    )
    .unwrap();
    for stable in [false, true] {
        if stable {
            fs::write(lock_path(&fixture.config, "writer").unwrap(), WRITER_MARKER).unwrap();
        }
        let before = upgrade_inspection_evidence(&fixture);
        let inspected = inspect_upgrade(&fixture.path).unwrap();
        assert_eq!(inspected.kind, UpgradeKind::Pending);
        assert!(inspected.pending.unwrap()["recovery_prerequisite"].is_string());
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
    }
    resume(
        &fixture.path,
        &fixture.config.state_dir,
        proposal["token"].as_str().unwrap(),
    )
    .unwrap();
    let before = upgrade_inspection_evidence(&fixture);
    assert!(inspect_upgrade(&fixture.path).is_err());
    assert_eq!(upgrade_inspection_evidence(&fixture), before);
    assert!(
        read_binding(&fixture.config)
            .unwrap()
            .unwrap()
            .admission_inode
            .is_none()
    );
}

#[test]
fn upgrade_inspection_rejects_conflicting_unsupported_and_corrupt_states_without_repair() {
    for mutation in ["seal", "phase", "config", "control", "authority"] {
        let fixture = Fixture::new(Some(2));
        let proposal = fixture.preview();
        fixture.stage(&proposal);
        let db = open_existing(&fixture.config.state_dir, true)
            .unwrap()
            .unwrap();
        match mutation {
            "seal" => {
                let mut sealed = export(
                    &fixture.config.state_dir,
                    proposal["token"].as_str().unwrap(),
                )
                .unwrap()["sealed"]
                    .clone();
                sealed["target_journal_format"] = json!(99);
                db.execute(
                    "UPDATE capability_migration SET sealed=?1",
                    [serde_json::to_string(&sealed).unwrap()],
                )
                .unwrap();
            }
            "phase" => {
                db.execute("UPDATE capability_migration SET phase='unknown'", [])
                    .unwrap();
            }
            "config" => {
                let mut legacy = legacy::Legacy::parse(&fixture.source).unwrap();
                legacy.participation.max_unresolved_operations += 1;
                crate::admin::persist(&fixture.path, toml::to_string(&legacy).unwrap().as_bytes())
                    .unwrap();
            }
            "control" => {
                db.execute("UPDATE control SET generation=generation+1", [])
                    .unwrap();
            }
            _ => {
                db.execute("DELETE FROM authority", []).unwrap();
            }
        }
        drop(db);
        let before = upgrade_inspection_evidence(&fixture);
        assert!(inspect_upgrade(&fixture.path).is_err(), "{mutation}");
        assert!(automatic_upgrade(&fixture.path).is_err(), "{mutation}");
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
    }
    for mutation in ["version", "authority", "binding", "journal", "lane"] {
        let fixture = current_upgrade_fixture();
        if mutation == "journal" {
            fs::remove_file(fixture.config.state_dir.join("state.sqlite3")).unwrap();
        } else if mutation == "binding" {
            fs::remove_file(lock_path(&fixture.config, "binding").unwrap()).unwrap();
        } else {
            let db = open_existing(&fixture.config.state_dir, true)
                .unwrap()
                .unwrap();
            db.execute_batch(match mutation {
                "version" => "UPDATE control SET version=99;",
                "authority" => "DELETE FROM authority;",
                _ => "DELETE FROM lane_control WHERE lane='answer';",
            })
            .unwrap();
        }
        let before = upgrade_inspection_evidence(&fixture);
        assert!(inspect_upgrade(&fixture.path).is_err(), "{mutation}");
        assert!(automatic_upgrade(&fixture.path).is_err(), "{mutation}");
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
    }
    let fixture = Fixture::new(None);
    for source in [
        format!(
            "schema_version=99\n{}",
            toml::to_string(&fixture.config).unwrap()
        ),
        format!(
            "schema_version=2\n{}",
            String::from_utf8(fixture.source.clone()).unwrap()
        ),
        format!(
            "[participation]\n{}",
            toml::to_string(&fixture.config).unwrap()
        ),
    ] {
        crate::admin::persist(&fixture.path, source.as_bytes()).unwrap();
        let before = upgrade_inspection_evidence(&fixture);
        assert!(inspect_upgrade(&fixture.path).is_err());
        assert_eq!(upgrade_inspection_evidence(&fixture), before);
    }
}

#[test]
fn automatic_conversion_uses_only_canonical_mapping_and_preserves_control_identity() {
    for source in [2, 3, 4] {
        let fixture = match source {
            2 => Fixture::new(Some(2)),
            3 => Fixture::format3(),
            _ => current_upgrade_fixture(),
        };
        if source == 4 {
            let marked = format!(
                "schema_version=2\n{}",
                String::from_utf8(bytes(&fixture.path).unwrap()).unwrap()
            );
            crate::admin::persist(&fixture.path, marked.as_bytes()).unwrap();
        }
        let before = inspect_upgrade(&fixture.path).unwrap();
        let witness = marker(&fixture.config).unwrap();
        let proposal = automatic_preview(&fixture.path).unwrap();
        assert_eq!(proposal["risk"]["preservation_proven"], true);
        assert_eq!(proposal["risk_change_required"], false);
        assert_eq!(proposal["request"].as_object().unwrap().len(), 1);
        assert_eq!(
            proposal["request"]["candidate_toml"],
            proposal["candidate_toml"]
        );
        if source == 2 {
            // The real strict source cap is four, not the metadata-only baseline one.
            let candidate =
                validated(&fixture.path, proposal["candidate_toml"].as_str().unwrap()).unwrap();
            for lane in LaneId::ALL {
                assert_eq!(
                    candidate
                        .participation(lane)
                        .max_unresolved_operations
                        .finite(),
                    Some(4)
                );
            }
        }
        apply(
            &fixture.path,
            &proposal["request"],
            proposal["token"].as_str().unwrap(),
            None,
        )
        .unwrap();
        let after = inspect_upgrade(&fixture.path).unwrap();
        assert_eq!(after.kind, UpgradeKind::Compatible);
        assert_eq!(after.database_id, before.database_id);
        assert_eq!(after.dispatch_sequence, before.dispatch_sequence);
        assert_eq!(
            after.generation,
            before.generation.map(|g| g + i64::from(source == 2))
        );
        assert_eq!(after.paused, Some(true));
        assert_eq!(marker(&fixture.config).unwrap(), witness);
    }
}

#[test]
fn automatic_decision_never_masks_unsafe_authority_or_infers_missing_proof() {
    let fixture = Fixture::new(Some(1));
    assert_eq!(
        automatic_upgrade(&fixture.path).unwrap(),
        AutomaticUpgrade::DecisionRequired("authority_adoption_required")
    );
    let fixture = Fixture::new(Some(2));
    let mut legacy = legacy::Legacy::parse(&fixture.source).unwrap();
    legacy.participation.mode = ParticipationMode::ParticipationFirst;
    crate::admin::persist(&fixture.path, toml::to_string(&legacy).unwrap().as_bytes()).unwrap();
    fs::remove_file(lock_path(&fixture.config, "binding").unwrap()).unwrap();
    assert!(automatic_upgrade(&fixture.path).is_err());
    for risk in [
        json!({}),
        json!({"risk_change_required":false}),
        json!({"preservation_proven":true}),
        json!({"preservation_proven":true,"risk_change_required":true}),
    ] {
        assert!(!preservation_proven(&risk));
    }
}

#[test]
fn update_pause_restoration_is_conditional_idempotent_and_never_provisions() {
    let absent = Fixture::new(None);
    let before = upgrade_inspection_evidence(&absent);
    assert!(
        crate::runtime::restore_update_pause(
            &absent.config,
            "0123456789abcdef0123456789abcdef",
            0,
            true,
            false
        )
        .is_err()
    );
    assert_eq!(upgrade_inspection_evidence(&absent), before);

    let fixture = current_upgrade_fixture();
    let config = Config::load(&fixture.path).unwrap();
    let inspected = inspect_upgrade(&fixture.path).unwrap();
    let id = inspected.database_id.unwrap();
    let generation = inspected.generation.unwrap();
    let unchanged =
        crate::runtime::restore_update_pause(&config, &id, generation, true, true).unwrap();
    assert_eq!(
        unchanged,
        json!({"paused":true,"generation":generation,"applied":false,"already_applied":false})
    );
    assert!(
        crate::runtime::restore_update_pause(
            &config,
            "fedcba9876543210fedcba9876543210",
            generation,
            true,
            false
        )
        .is_err()
    );
    let result =
        crate::runtime::restore_update_pause(&config, &id, generation, true, false).unwrap();
    assert_eq!(
        result,
        json!({"paused":false,"generation":generation+1,"applied":true,"already_applied":false})
    );
    // Simulate loss of the committed acknowledgment, keeping the original expectation.
    let replay =
        crate::runtime::restore_update_pause(&config, &id, generation, true, false).unwrap();
    assert_eq!(
        replay,
        json!({"paused":false,"generation":generation+1,"applied":false,"already_applied":true})
    );
    // A later same-valued operator control is still newer intent.
    crate::runtime::resume(&config).unwrap();
    assert!(crate::runtime::restore_update_pause(&config, &id, generation, true, false).is_err());
    let after = inspect_upgrade(&fixture.path).unwrap();
    assert_eq!(after.generation, Some(generation + 2));
    assert_eq!(after.paused, Some(false));
    // Even an exact post-state cannot authorize restoration after authority loss.
    fs::remove_file(lock_path(&config, "binding").unwrap()).unwrap();
    assert!(
        crate::runtime::restore_update_pause(&config, &id, generation + 1, true, false).is_err()
    );
}

#[test]
fn runtime_policy_publishes_local_process_identity_without_external_probes() {
    let fixture = current_upgrade_fixture();
    let config = Config::load(&fixture.path).unwrap();
    let (_account, store) = AccountLock::acquire(&config).unwrap();
    store.runtime_state(&config, false).unwrap();
    let policy: String = store
        .db
        .query_row(
            "SELECT policy FROM runtime_policy WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let policy: Value = serde_json::from_str(&policy).unwrap();
    assert_eq!(policy["process"]["pid"], std::process::id());
    assert_eq!(
        policy["process"]["invocation_id"],
        json!(
            std::env::var("INVOCATION_ID")
                .ok()
                .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        )
    );
}
