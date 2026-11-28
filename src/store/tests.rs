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

fn doctor_fixture() -> (tempfile::TempDir, Config, PathBuf) {
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
    (temp, config, path)
}

#[test]
fn doctor_batch_preserves_partial_progress_and_fences_configuration_and_writer() {
    let (_temp, config, path) = doctor_fixture();
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
fn doctor_apply_revalidates_the_frozen_candidates_without_substituting_new_work() {
    let (_temp, config, path) = doctor_fixture();
    let (account, mut store) = AccountLock::acquire(&config).unwrap();
    store
        .set_paused(false, &AccountAdmissionGuard::acquire(&config).unwrap())
        .unwrap();
    for epoch in 1..=4 {
        let op = prepared_epoch(&mut store, LaneId::Judge, epoch, "historical");
        store
            .db
            .execute("UPDATE operations SET state='unknown' WHERE id=?1", [op.id])
            .unwrap();
        if epoch != 4 {
            store
                .record_evidence(op.id, &refusal_evidence(op.kind, 429, Some("rate_limited")))
                .unwrap();
            age_refusal_evidence(&store, op.id);
        }
    }
    let preview = doctor_repairs(&path, None).unwrap();
    assert_eq!(preview["eligible"].as_array().unwrap().len(), 3);
    assert_eq!(preview["ineligible"][0]["operation_id"], 4);
    store
        .db
        .execute_batch(
            "UPDATE operations SET result='{}' WHERE id=1;
         UPDATE operations SET job_id='fixture-job' WHERE id=2;",
        )
        .unwrap();
    store
        .record_evidence(
            4,
            &refusal_evidence(LaneId::Judge, 429, Some("rate_limited")),
        )
        .unwrap();
    age_refusal_evidence(&store, 4);
    drop(store);
    drop(account);

    let result = doctor_repairs(&path, Some(&preview)).unwrap();
    assert_eq!(result["failure"], Value::Null);
    assert_eq!(result["applied"].as_array().unwrap().len(), 1);
    assert_eq!(result["applied"][0]["operation_id"], 3);
    assert_eq!(result["skipped"].as_array().unwrap().len(), 2);
    assert_eq!(result["skipped"][0]["reason"], "refusal_recovery_conflict");
    assert_eq!(
        result["skipped"][1]["reason"],
        "refusal_recovery_ineligible"
    );
    let store = Store::read_only(&config).unwrap().unwrap();
    assert_eq!(store.operation(4).unwrap().unwrap().state, "unknown");
    drop(store);
    let repeat = doctor_repairs(&path, Some(&preview)).unwrap();
    assert_eq!(repeat["applied"], json!([]));
    assert_eq!(repeat["skipped"][2]["reason"], "already_resolved");
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
        Outcome, Response, ResponseSource, classify_source, response_candidates, response_evidence,
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
            assert!(
                store
                    .reconciliation_batch(&config, kind, &mut Default::default())
                    .unwrap()
                    .is_empty()
            );
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
                    .operations_list(&config, None, Some("refused"), None, 10)
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

#[cfg(unix)]
#[test]
fn journal_identity_fails_closed_on_swapped_clone_with_matching_id() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (_temp, config) = fixture();
    let db_path = config.state_dir.join("state.sqlite3");
    // Initialized journal; the read handle stays open across the swap.
    drop(Store::open(&config).unwrap());
    let store = Store::read_only(&config).unwrap().unwrap();
    let (database_id, _) = store.database_identity().unwrap();
    let identity = store.journal_identity().unwrap();
    assert_eq!(identity["database_id"].as_str(), Some(database_id.as_str()));
    let pinned = identity["inode"].as_u64().unwrap();
    assert_eq!(
        pinned,
        fs::symlink_metadata(&db_path).unwrap().ino(),
        "identity must describe the file actually opened"
    );
    // Byte-identical clone with a tweaked non-authority row: the swap
    // keeps the same authority content id on a different file object.
    let clone_path = fs::canonicalize(&config.state_dir)
        .unwrap()
        .join("state.clone.sqlite3");
    fs::copy(&db_path, &clone_path).unwrap();
    {
        let clone = Connection::open_with_flags(
            &clone_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        clone
            .execute("INSERT INTO events(at,code) VALUES(1,'identity_probe')", [])
            .unwrap();
        let clone_id: String = clone
            .query_row(
                "SELECT database_id FROM authority WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(clone_id, database_id);
    }
    fs::set_permissions(&clone_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&clone_path, &db_path).unwrap();
    // The open handle still reads the original snapshot, but the live
    // path resolves elsewhere: attribution must fail closed, never claim
    // the clone under the original identity.
    assert!(store.journal_identity().is_err());
    // A fresh open pins the replacement instead of inheriting the pin.
    drop(store);
    let reopened = Store::read_only(&config).unwrap().unwrap();
    let identity = reopened.journal_identity().unwrap();
    assert_eq!(identity["database_id"].as_str(), Some(database_id.as_str()));
    assert_ne!(identity["inode"].as_u64().unwrap(), pinned);
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

fn dispatched_unknown(store: &mut Store, config: &Config, kind: LaneId, epoch: u64) -> Operation {
    let mut op = prepared_epoch(store, kind, epoch, "fingerprint");
    assert!(store.dispatch_intent(&mut op, config).unwrap());
    op.state = "unknown".into();
    store.save(&op, "dispatch_outcome_unknown").unwrap();
    op
}

fn accepted_linked_answer(store: &mut Store, config: &Config, original: &Operation) -> Operation {
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
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
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
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
                .unwrap();
        assert_eq!(
            (accounting.eligible, accounting.exempt, accounting.active()),
            (0, 0, u64::from(owner == LaneId::Answer)),
            "{change}"
        );
        assert_eq!(accounting.total, 1, "{change}");
        if owner != LaneId::Answer {
            let owning_lane =
                Store::uncertainty_accounting(&store.db, &config, owner, None, None, true).unwrap();
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
        let accounting =
            Store::uncertainty_accounting(&store.db, &config, LaneId::Answer, None, None, false)
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
fn required_routing_profile_table_fails_instead_of_using_default_profile() {
    let (_temp, config, store) = participation_fixture();
    assert!(store.routing_profile().unwrap().is_none());
    assert_eq!(
        store.routing_status(&config).unwrap()["matches_config"],
        true
    );
    store
        .db
        .execute_batch("DROP TABLE routing_profile")
        .unwrap();
    drop(store);
    let store = Store::read_only(&config).unwrap().unwrap();
    assert!(store.routing_profile().is_err());
    assert!(store.routing_status(&config).is_err());
    assert!(store.routing_change_allowed(&config).is_err());
}

#[test]
fn required_operation_links_table_fails_routing_retry_assessment_when_missing() {
    let (_temp, mut config, mut store) = participation_fixture();
    config.capabilities.answer.preparation.max_attempts_per_work = CountLimit::Bounded(1);
    begin(&mut store, LaneId::Answer, "7:retry", "rejected");
    assert!(!store.routing_busy(&config).unwrap());
    store
        .db
        .execute_batch("DROP TABLE operation_links")
        .unwrap();
    drop(store);
    let store = Store::read_only(&config).unwrap().unwrap();
    let mut changed = config.clone();
    changed.network.api.routes.insert(
        crate::endpoints::Endpoint::Challenge,
        "/different-challenge".into(),
    );
    assert!(store.routing_busy(&changed).is_err());
    assert!(store.routing_status(&changed).is_err());
    assert!(store.routing_change_allowed(&changed).is_err());
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
            .reconciliation_batch(&config, LaneId::Answer, &mut Default::default())
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
            config.capabilities.answer.preparation.max_attempts_per_work = CountLimit::Bounded(2);
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
        serde_json::from_str(risk["risk_admissions"][0]["blocker_ids"].as_str().unwrap()).unwrap();
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
    store
        .db
        .execute(
            "UPDATE read_state SET local_next_at=0 WHERE owner='answer' AND purpose='discovery'",
            [],
        )
        .unwrap();
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
    let health = health::check(&config.state_dir.join("config.toml"), &config, options).unwrap();
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
    // Retained applied policy remains usable without interpreting its old label.
    store
        .db
        .execute(
            "UPDATE runtime_policy SET policy=json_set(policy,'$.schema_version',2)",
            [],
        )
        .unwrap();
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
    for (pointer, replacement) in [
        ("/identity", Value::Null),
        ("/runtime", Value::Null),
        ("/capabilities/answer", Value::Null),
        ("/capabilities/judge/mode", Value::Null),
        ("/capabilities/mine/participation", Value::Null),
        ("/capabilities/answer/participation", json!({})),
        ("/capabilities/judge/timeouts", json!({})),
        ("/capabilities/mine/schedule", json!({})),
        ("/identity", json!({})),
        ("/runtime", json!({})),
        ("/lane_revisions", Value::Null),
        ("/lane_revisions/answer", Value::Null),
        ("/lane_revisions/judge", json!("")),
    ] {
        store.runtime_state(&config, false).unwrap();
        let raw: String = store
            .db
            .query_row("SELECT policy FROM runtime_policy", [], |row| row.get(0))
            .unwrap();
        let mut policy: Value = serde_json::from_str(&raw).unwrap();
        *policy.pointer_mut(pointer).unwrap() = replacement;
        store
            .db
            .execute("UPDATE runtime_policy SET policy=?1", [policy.to_string()])
            .unwrap();
        let changes = store.db.total_changes();
        let status = store.status(&config).unwrap();
        assert_eq!(status["participation"]["policy_source"], "unavailable");
        assert!(status["participation"]["lanes"]["answer"].is_null());
        assert_eq!(store.db.total_changes(), changes);
    }
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
    assert_eq!(work["phase"], "observing");
    assert_eq!(work["reason"], "cadence");
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
    assert!(
        WaitEvidence::default().projection("generated", None, 100)["unsent_since_capture_seconds"]
            .is_null()
    );
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
        .operations_list(&config, Some(LaneId::Answer), None, None, 1)
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
    let (_temp, config, mut store) = participation_fixture();
    let mut op = begin(&mut store, LaneId::Answer, "1:wait", "generating");
    op.state = "generated".into();
    store.save(&op, "model_result_captured").unwrap();
    let before = store.operations_list(&config, None, None, None, 1).unwrap()["operations"][0]
        ["wait"]["model_captured_at"]
        .clone();
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
    let inventory = store.operations_list(&config, None, None, None, 1).unwrap();
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
    let missing = store.operations_list(&config, None, None, None, 1).unwrap();
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
    let inventory = store.operations_list(&config, None, None, None, 1).unwrap();
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
    let pruned = store.operations_list(&config, None, None, None, 1).unwrap();
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
    let first = store.operations_list(&config, None, None, None, 2).unwrap();
    assert_eq!(first["operations"].as_array().unwrap().len(), 2);
    assert_eq!(first["operations"][0]["operation_id"], retry.id);
    assert_eq!(first["operations"][0]["retry_of"], answer.id);
    assert_eq!(first["operations"][0]["payload_reused"], true);
    drop(store);
    let store = Store::read_only(&config).unwrap().unwrap();
    let second = store
        .operations_list(&config, None, None, first["next_before"].as_i64(), 2)
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
        .operations_list(&config, Some(LaneId::Answer), Some("unknown"), None, 100)
        .unwrap();
    assert_eq!(filtered["operations"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["operations"][0]["operation_id"], answer.id);
    assert!(
        store
            .operations_list(&config, None, None, None, 1001)
            .is_err()
    );
    assert!(
        store
            .operations_list(&config, None, None, Some(0), 1)
            .is_err()
    );
    assert!(
        store
            .operations_list(&config, None, Some("unknown' OR 1"), None, 1)
            .is_err()
    );
}

#[test]
fn required_grant_tables_fail_inventory_and_authorization_when_missing() {
    for table in ["manual_grants", "manual_grant_revocations"] {
        let (_temp, config, store) = participation_fixture();
        assert_eq!(store.grants(None, 10).unwrap()["grants"], json!([]));
        assert_eq!(store.manual_authorized(LaneId::Answer, None).unwrap(), None);
        assert_eq!(
            store.manual_authorized(LaneId::Answer, Some(7)).unwrap(),
            Some(false)
        );
        store
            .db
            .execute_batch(&format!("DROP TABLE {table}"))
            .unwrap();
        drop(store);
        let store = Store::read_only(&config).unwrap().unwrap();
        assert!(store.grants(None, 10).is_err(), "{table}");
        assert!(
            store.manual_authorized(LaneId::Answer, Some(7)).is_err(),
            "{table}"
        );
        assert_eq!(store.manual_authorized(LaneId::Answer, None).unwrap(), None);
    }
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
    let (preview, captured) = Store::identity_normalization_preview(&store.db, "config").unwrap();
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
    let health = health::check(&config.state_dir.join("config.toml"), &config, options).unwrap();
    assert_eq!(health["healthy"], false);
    assert_eq!(health["hosted_identity"]["rejection"], "identity_mismatch");
    store
        .record_identity_outcome(HostedIdentityOutcome::Verified)
        .unwrap();
    assert_eq!(
        health::check(&config.state_dir.join("config.toml"), &config, options).unwrap()["healthy"],
        true
    );
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
            .reconciliation_batch(&config, LaneId::Answer, &mut Default::default())
            .unwrap()
            .iter()
            .any(|pending| pending.id == op.id)
    );
    op.state = "final".into();
    store.save(&op, "receipt_final").unwrap();
    assert!(
        store
            .reconciliation_batch(&config, LaneId::Answer, &mut Default::default())
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
        let health =
            health::check(&config.state_dir.join("config.toml"), &config, options).unwrap();
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
    let report = health::check(&config.state_dir.join("config.toml"), &config, options).unwrap();
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
    let report = health::check(&config.state_dir.join("config.toml"), &config, options).unwrap();
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
