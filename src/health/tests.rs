use super::*;
use crate::config::Mode;

#[test]
fn managed_health_never_uses_one_lane_wait_to_cover_another_fault() {
    let mut report = json!({
        "checked_at":100,"hosted_identity_verified":true,
        "issues":["shared_server_restriction"],
        "intervention":{"unattended":true,"controller":{"ready":true}},
        "components":{"controller":{"state":"ok"},"answer":{"state":"disabled"},
            "mine":{"state":"disabled"},"judge":{"state":"blocked","mode":"active",
                "reasons":["shared_server_restriction"]}},
        "work":{"judge":{"intervention":{"status":"automatic_recovery",
            "reason":"shared_server_restriction","next_action":"await_retry_eligibility",
            "observation_fresh":true,"next_at":101}}}
    });
    assert!(managed_health_wait(&report));
    report["components"]["answer"] = json!({"state":"unknown","mode":"active",
        "reasons":["shared_server_restriction"]});
    assert!(!managed_health_wait(&report));
    report["components"]["answer"] = json!({"state":"disabled"});
    report["issues"] = json!(["shared_server_restriction", "state_disk_space_low"]);
    assert!(!managed_health_wait(&report));
    report["issues"] = json!(["shared_server_restriction"]);
    report["work"]["judge"]["intervention"]["next_at"] = json!(100);
    assert!(!managed_health_wait(&report));

    report["work"]["judge"]["intervention"]["next_at"] = json!(103);
    report["admission_blocked"] = json!(true);
    report["issues"] = json!([
        "admission_blocked",
        "shared_server_restriction",
        "operation_backoff"
    ]);
    report["components"]["judge"]["reasons"] = json!(["operation_backoff"]);
    report["work"]["judge"]["intervention"]["reason"] = json!("operation_backoff");
    report["participation"]["lanes"]["judge"] =
        json!({"allowed":false,"reason":"shared_server_restriction","not_before":102});
    assert!(managed_health_wait(&report));
    report["participation"]["lanes"]["judge"]["not_before"] = json!(104);
    assert!(!managed_health_wait(&report));
    report["participation"]["lanes"]["judge"]["not_before"] = json!(102);
    report["participation"]["lanes"]["answer"] = report["participation"]["lanes"]["judge"].take();
    report["components"]["answer"] = json!({"state":"ok","mode":"active"});
    assert!(!managed_health_wait(&report));
}

pub(super) fn fixture() -> (Config, Options, Value) {
    let mut config = Config::default();
    config.capabilities.answer.mode = Mode::Active;
    config.capabilities.judge.mode = Mode::Active;
    config.capabilities.mine.mode = Mode::Active;
    config.capabilities.mine.schedule.each_epoch = true;
    let mut status = json!({
        "initialized":true,"paused":false,"controller_stopped":false,
        "identity_matches_config":true,"admission_blocked":false,
        "hosted_identity":{"status":"verified","observed_at":10000,"last_verified_at":10000,
            "rejection":null,"legacy_failure":false},
        "effective_runtime":{"observed_at":10000,"reload_blocked":false,"policy":config},
        "observations":{
            "answer":{"observed_at":10000,"first_observed_at":10000,"epoch":7,"answered":true},
            "mine":{"observed_at":10000,"first_observed_at":10000,"epoch":7,"answered":false}},
        "participation":{"unresolved_count":0,"risk_admissions":0},
        "pending":null,"pending_work":[],"captured_work":[],"reads":[],"work":{}
    });
    for name in LANES {
        status["work"][name] = json!({"phase":"observing","reason":"cadence",
            "next_action":if name == "judge" {"observe_assignments"} else {"observe_challenge"},
            "next_at":10020,"admission":{"allowed":true,"reason":null,"pre_intent_blocker":null,"scope":null,
                "own_count":0,"own_limit":4,"own_remaining":4,"account_unresolved":0,
                "required_release":0,"blocker_ids":[],"not_before":null}});
        status["participation"]["lanes"][name] = status["work"][name]["admission"].clone();
        status["reads"].as_array_mut().unwrap().push(json!({
            "owner":name,"purpose":"discovery",
            "resource":if name == "judge" {"assignments"} else {"challenge"},
            "state":"idle","last_success_at":10000,"status":200}));
    }
    status["work"]["answer"]["phase"] = json!("answered");
    status["work"]["judge"]["assessment"] = json!({"observed_at":10000,"valid_until":10060,
        "observed_opportunities":0,"completeness":"complete","locally_judgeable":false});
    status["work"]["mine"]["phase"] = json!("completed");
    status["work"]["mine"]["operation_epoch"] = json!(7);
    (config, Options::default(), status)
}

#[test]
fn observation_expiry_is_strict_and_a_policy_change_cannot_extend_recorded_evidence() {
    for lane in ["answer", "mine"] {
        let (config, options, mut status) = fixture();
        status["observations"][lane]["observed_at"] = json!(9881);
        status["lane_participation"][lane]["assessment"] =
            json!({"observed_at":9881,"valid_until":10001});
        let current = evaluate(&config, options, &status, 10000);
        assert_eq!(current["components"][lane]["state"], "ok");
        assert_eq!(
            current["work"][lane]["intervention"]["observation_fresh"],
            true
        );
        status["observations"][lane]["observed_at"] = json!(9880);
        status["lane_participation"][lane]["assessment"] =
            json!({"observed_at":9880,"valid_until":10000});
        let expired = evaluate(&config, options, &status, 10000);
        assert_eq!(expired["healthy"], false);
        assert_eq!(expired["components"][lane]["state"], "unknown");
        let intervention = &expired["work"][lane]["intervention"];
        assert_eq!(intervention["observation_fresh"], false);
        assert_eq!(intervention["status"], "automatic_recovery");
        assert_eq!(intervention["next_action"], "observe_challenge");
        assert_eq!(expired["intervention"]["unattended"], true);
        status["effective_runtime"]["policy"]["capabilities"][lane]["schedule"]["observation_max_age_seconds"] =
            json!(3600);
        let after_policy_change = evaluate(&config, options, &status, 10000);
        assert_eq!(after_policy_change["components"][lane]["state"], "unknown");
        assert_eq!(
            after_policy_change["work"][lane]["intervention"]["observation_fresh"],
            false
        );
    }
}

#[test]
fn stale_projected_stamp_cannot_complete_recent_work() {
    for lane in LANES {
        for mode in ["active", "read_only"] {
            let (config, options, mut status) = fixture();
            status["effective_runtime"]["policy"]["capabilities"][lane]["mode"] = json!(mode);
            status["lane_participation"][lane] = json!({
                "freshness":"stale",
                "assessment":{"observed_at":10000,"valid_until":10060}
            });
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["healthy"], false, "{lane}/{mode}: {health}");
            assert_eq!(
                health["components"][lane]["state"], "unknown",
                "{lane}/{mode}: {health}"
            );
            assert!(!work_complete(&status, lane, 10000, options.stale_seconds));
        }
    }
}

#[test]
fn confirmed_judging_is_accepted_but_never_supplies_fresh_inventory() {
    let (config, options, mut status) = fixture();
    status["work"]["judge"]["phase"] = json!("included");
    status["pending_work"] = json!([{
        "kind":"judge","state":"confirmed","created_at":1,"updated_at":1
    }]);
    let accepted = evaluate(&config, options, &status, 10000);
    assert_eq!(accepted["healthy"], true, "{accepted}");
    assert_eq!(accepted["components"]["judge"]["state"], "ok");
    assert_eq!(accepted["work"]["judge"]["progress"], "idle");
    assert!(!has(&accepted, "current_work_outcome_unresolved"));
    for state in ["unknown", "queued", "included_pending"] {
        status["pending_work"][0]["state"] = json!(state);
        status["work"]["judge"]["phase"] = json!(state);
        let unresolved = evaluate(&config, options, &status, 10000);
        assert_eq!(unresolved["healthy"], false, "{state}: {unresolved}");
        assert_eq!(unresolved["components"]["judge"]["state"], "blocked");
        assert!(has(&unresolved, "current_work_outcome_unresolved"));
    }
    status["pending_work"][0]["state"] = json!("confirmed");
    status["work"]["judge"]["phase"] = json!("included");
    status["work"]["judge"]["assessment"]["valid_until"] = json!(9999);
    let stale = evaluate(&config, options, &status, 10000);
    assert_eq!(stale["healthy"], false, "{stale}");
    assert_eq!(stale["components"]["judge"]["state"], "unknown");
    assert_ne!(stale["work"]["judge"]["progress"], "idle");
}

#[test]
fn old_bound_missing_jobs_do_not_mask_fresh_work_or_current_faults() {
    let (config, options, mut status) = fixture();
    let mut pending = Vec::new();
    for id in 1..=1000 {
        pending.push(
            json!({"operation_id":id,"binding_revision":1,"kind":"judge",
            "state":"queued","work_class":"pending_remote","nonblocking_for_fresh_work":true,
            "created_at":1,"updated_at":1}),
        );
        status["reads"].as_array_mut().unwrap().push(json!({
            "owner":"judge","purpose":"job","resource":format!("{id}:1"),
            "operation_id":id,"binding_revision":1,"state":"idle","status":404,
            "last_failure_at":9999,"failures":10,"failure_category":"job_not_found","next_at":12000
        }));
    }
    status["pending_work"] = json!(pending);
    status["participation"]["unresolved_count"] = json!(1000);
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["healthy"], true);
    assert_eq!(health["intervention"]["unattended"], true);
    assert_eq!(health["risk"]["background_remote_work"], 1000);
    assert_eq!(
        health["components"]["api"]["resources"][0]["health"]["state"],
        "degraded"
    );
    assert_eq!(
        health["components"]["api"]["resources"][0]["dependency"],
        "background_remote_work"
    );
    status["pending_work"].as_array_mut().unwrap().push(json!({
        "kind":"judge","state":"dispatching","created_at":1,"updated_at":1,"http_deadline":1
    }));
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "dispatch_outcome_uncertain"
    ));
    status["pending_work"].as_array_mut().unwrap().pop();
    status["work"]["judge"]["assessment"]["locally_judgeable"] = json!(true);
    status["reads"][1]["last_failure_at"] = json!(10000);
    status["reads"][1]["failures"] = json!(1);
    status["reads"][1]["failure_category"] = json!("transport");
    assert_ne!(
        evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
        "ok"
    );
}

#[test]
fn retained_unbounded_uncertainty_remains_risk_not_fresh_work_blocker() {
    let (config, options, mut status) = fixture();
    status["participation"]["unresolved_count"] = json!(3000);
    status["participation"]["risk_admissions"] = json!(1);
    status["pending_work"] =
        json!([{"kind":"answer","state":"unknown","created_at":1,"updated_at":1}]);
    status["participation"]["lanes"]["answer"]["retained_uncertainty_nonblocking"] = json!(true);
    status["participation"]["lanes"]["answer"]["own_limit"] = json!("unbounded");
    status["participation"]["lanes"]["answer"]["own_count"] = json!(3000);
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["healthy"], true);
    assert_eq!(health["risk"]["unresolved_effects"], 3000);
    assert_eq!(
        health["risk"]["retained_uncertainty_nonblocking_lanes"],
        json!(["answer"])
    );
    assert_eq!(health["intervention"]["unattended"], true);
    assert_eq!(health["risk"]["attention_required"], true);
}

fn has(value: &Value, code: &str) -> bool {
    value["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item == code)
}

#[test]
fn mining_completion_expires_at_interval_boundary() {
    let (config, options, mut status) = fixture();
    status["effective_runtime"]["policy"]["capabilities"]["mine"]["schedule"]["each_epoch"] =
        json!(false);
    status["work"]["mine"]["completion_valid_until"] = json!(10010);
    assert_eq!(
        evaluate(&config, options, &status, 10009)["components"]["mine"]["state"],
        "ok"
    );
    assert_eq!(
        evaluate(&config, options, &status, 10010)["components"]["mine"]["state"],
        "unknown"
    );
    status["work"]["mine"]["completion_valid_until"] = Value::Null;
    assert_eq!(
        evaluate(&config, options, &status, 10009)["components"]["mine"]["state"],
        "unknown"
    );
}

#[test]
fn canonical_lane_controls_and_model_evidence_are_preserved_without_permits() {
    let (mut config, options, mut status) = fixture();
    config.capabilities.answer.mode = Mode::Off;
    let control = json!({
        "desired":{"lane_id":"answer","paused":true,"control_revision":7,"control_token":"bound-token"},
        "authoritative_closure":{"state":"closed","reasons":["lane_paused"],
            "source":"journal_control_transaction","account_generation":2,"lane_control_revision":7,"observed_at":10000},
        "observed_admission":{"state":"unknown","reasons":["control_revision_changed"],"freshness":"stale",
            "source":"runtime_snapshot","observed_at":9999,"valid_until":10001,
            "runtime_instance":"earlier-runtime","observed_control_revision":6,
            "accepted_config_revision":"accepted-config","authority_epoch":3},
        "dispatch_uncertainty":{"dispatch_intent_unsettled_count":2,"dispatch_intent_unsettled_ids":[41,42],
            "ids_truncated":false,"unresolved_sent_count":3,"source":"journal_control_transaction"}
    });
    status["lane_controls"]["answer"] = control.clone();
    status["pending_work"] = json!([{"id":41,"kind":"answer","state":"unknown","created_at":9999,
        "model_attempt":{"producer":{"requested":{"model":"requested-model"}},
            "completion":{"reported":{"model":{"value":"reported-model","source":"native_envelope"}}}}}]);
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["lane_controls"]["answer"], control);
    assert_eq!(health["components"]["answer"]["control"], control);
    assert_eq!(health["components"]["answer"]["state"], "blocked");
    assert_eq!(health["desired_capabilities"]["answer"], "off");
    assert_eq!(health["effective_capabilities"]["answer"]["mode"], "active");
    assert_eq!(health["pending_work"], status["pending_work"]);
    assert!(health["lane_controls"]["answer"]["fence_ack"].is_null());
    status["lane_controls"]["answer"]["desired"]["paused"] = json!(false);
    status["lane_controls"]["answer"]["authoritative_closure"]["state"] = json!("not_closed");
    status["lane_controls"]["answer"]["authoritative_closure"]["reasons"] = json!([]);
    let resumed = evaluate(&config, options, &status, 10000);
    assert_eq!(
        resumed["lane_controls"]["answer"]["observed_admission"]["state"],
        "unknown"
    );
    assert_eq!(
        resumed["lane_controls"]["answer"]["dispatch_uncertainty"],
        control["dispatch_uncertainty"]
    );
}

#[test]
fn effective_policy_is_never_replaced_by_desired_config() {
    let (mut config, options, mut status) = fixture();
    status["effective_runtime"]["policy"] = Value::Null;
    let before = evaluate(&config, options, &status, 10000);
    config.capabilities.answer.timeouts.model_seconds = 7200;
    config.capabilities.answer.schedule.poll_seconds = 7200;
    config.capabilities.answer.mode = Mode::Off;
    let after = evaluate(&config, options, &status, 10000);
    assert_eq!(before["thresholds"], after["thresholds"]);
    assert!(has(&after, "effective_policy_unavailable"));
    assert_eq!(after["components"]["answer"]["mode"], Value::Null);
    assert_eq!(after["current_epoch"]["evidence_fresh"], Value::Null);
}

#[test]
fn pending_model_admission_uses_only_its_captured_execution_bound() {
    let (config, options, mut status) = fixture();
    status["work"]["answer"]["phase"] = json!("preparing");
    status["work"]["answer"]["reason"] = json!("model_running");
    status["captured_work"] = json!([{"kind":"answer","state":"generating",
        "created_at":1,"updated_at":1,"model_deadline":null,
        "pending_execution_deadline":10001,
        "diagnostic":{"stage":"model_preflight","execution":"not_started",
            "state":"awaiting_admission","remaining_budget_millis":1}}]);
    let before = evaluate(&config, options, &status, 10000);
    assert_eq!(before["healthy"], true);
    assert_eq!(
        before["work"]["answer"]["intervention"]["reason"],
        "model_launch_awaiting_admission"
    );
    assert_eq!(before["work"]["answer"]["intervention"]["next_at"], 10001);

    // Diagnostic budgets cannot renew the captured bound.
    status["captured_work"][0]["diagnostic"]["remaining_budget_millis"] = json!(999999);
    let expired = evaluate(&config, options, &status, 10001);
    assert!(has(&expired, "pending_model_execution_expired"));
    assert!(!has(&expired, "model_work_overdue"));
    assert_eq!(expired["healthy"], false);
    assert_eq!(expired["risk"]["attention_required"], false);
    assert_eq!(expired["components"]["answer"]["state"], "degraded");
    assert_eq!(
        expired["work"]["answer"]["intervention"]["reason"],
        "pending_model_execution_expired"
    );
    assert_eq!(
        expired["work"]["answer"]["intervention"]["status"],
        "undetermined"
    );
    assert_eq!(
        expired["work"]["answer"]["intervention"]["next_action"],
        "inspect_local_evidence"
    );
    assert!(expired["captured_work"][0]["model_deadline"].is_null());

    status["captured_work"][0]["pending_execution_deadline"] = Value::Null;
    let missing = evaluate(&config, options, &status, 10001);
    assert!(!has(&missing, "pending_model_execution_expired"));
    assert!(!has(&missing, "model_work_overdue"));
    assert!(
        missing["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "model_deadline_unavailable")
    );
    assert_eq!(missing["components"]["answer"]["state"], "unknown");
    assert_eq!(
        missing["work"]["answer"]["intervention"]["reason"],
        "model_deadline_unavailable"
    );

    status["captured_work"][0]["model_deadline"] = json!(1);
    let running = evaluate(&config, options, &status, 10001);
    assert!(has(&running, "model_work_overdue"));
    assert!(!has(&running, "pending_model_execution_expired"));
    assert_eq!(
        running["work"]["answer"]["intervention"]["reason"],
        "in_flight_outcome_overdue"
    );
}

#[test]
fn future_judge_assessment_fails_aggregate_health_without_claiming_readiness() {
    for (mode, pending) in [("active", false), ("read_only", false), ("active", true)] {
        let (config, options, mut status) = fixture();
        status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!(mode);
        if pending {
            status["pending_work"] = json!([{
                "kind":"judge","state":"generating","created_at":9999,
                "updated_at":9999,"model_deadline":10100
            }]);
        }
        let before = evaluate(&config, options, &status, 10000);
        assert_eq!(before["healthy"], true);
        assert_eq!(before["components"]["judge"]["state"], "ok");
        status["work"]["judge"]["assessment"]["observed_at"] = json!(10001);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["issues"], json!(["clock_regressed"]));
        assert_eq!(health["healthy"], false);
        assert_eq!(health["attention_required"], true);
        assert_eq!(health["components"]["judge"]["state"], "unknown");
        assert_eq!(
            health["work"]["judge"]["intervention"]["reason"],
            "clock_regressed"
        );
    }
}

#[test]
fn lane_model_budgets_and_captured_deadlines_are_independent() {
    let (config, options, mut status) = fixture();
    status["effective_runtime"]["policy"]["capabilities"]["answer"]["timeouts"]["model_seconds"] =
        json!(1);
    status["effective_runtime"]["policy"]["capabilities"]["judge"]["timeouts"]["model_seconds"] =
        json!(2000);
    status["pending_work"] = json!([
        {"kind":"answer","state":"generating","created_at":9000,"model_deadline":20000},
        {"kind":"judge","state":"generating","created_at":9000}
    ]);
    let health = evaluate(&config, options, &status, 10000);
    assert!(!has(&health, "model_work_overdue"));
    assert_ne!(
        health["thresholds"]["lanes"]["answer"]["model_seconds"],
        health["thresholds"]["lanes"]["judge"]["model_seconds"]
    );
    assert!(health["thresholds"]["lanes"]["mine"]["model_seconds"].is_null());
    status["pending_work"][0]
        .as_object_mut()
        .unwrap()
        .remove("model_deadline");
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "model_work_overdue"
    ));
    status["effective_runtime"]["policy"]["capabilities"]["answer"]["timeouts"]["model_seconds"] =
        Value::Null;
    let unknown = evaluate(&config, options, &status, 10000);
    assert!(!has(&unknown, "model_work_overdue"));
    assert!(
        unknown["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "model_deadline_unavailable")
    );
}

#[test]
fn mine_observation_never_refreshes_answer_evidence() {
    let (config, options, mut status) = fixture();
    status["observations"]["answer"]["observed_at"] = json!(1);
    status["observations"]["mine"]["epoch"] = json!(8);
    let health = evaluate(&config, options, &status, 10000);
    assert!(has(&health, "challenge_observation_stale"));
    assert_eq!(health["current_epoch"]["epoch"], 7);
    assert_eq!(health["current_epoch"]["evidence_fresh"], false);
    status["observations"]["answer"] = Value::Null;
    status["legacy_observation"] = json!({"epoch":8,"answered":true,"provenance":"unattributed"});
    let health = evaluate(&config, options, &status, 10000);
    assert!(has(&health, "challenge_unobserved"));
    assert_eq!(health["current_epoch"]["answered"], Value::Null);
    assert_eq!(health["legacy_observation"]["provenance"], "unattributed");
}

#[test]
fn answer_grace_requires_fresh_own_observation_and_epoch_start() {
    let (config, options, mut status) = fixture();
    status["observations"]["answer"]["answered"] = json!(false);
    status["observations"]["answer"]["first_observed_at"] = json!(9000);
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "current_epoch_unanswered"
    ));
    status["observations"]["answer"]["first_observed_at"] = json!(9100);
    assert!(!has(
        &evaluate(&config, options, &status, 10000),
        "current_epoch_unanswered"
    ));
    status["observations"]["answer"]["observed_at"] = json!(1);
    assert!(!has(
        &evaluate(&config, options, &status, 10000),
        "current_epoch_unanswered"
    ));
}

#[test]
fn discovery_failure_is_lane_local_and_quota_is_canonical() {
    let (config, options, mut status) = fixture();
    status["reads"][2]["last_failure_at"] = json!(10000);
    status["reads"][2]["failure_category"] = json!("http");
    status["reads"][2]["status"] = json!(503);
    status["work"]["mine"]["phase"] = json!("observing");
    status["work"]["judge"]["admission"] = json!({"allowed":false,
        "reason":"lane_unresolved_capacity","scope":"lane","own_count":1,"own_limit":1,"own_remaining":0});
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["components"]["answer"]["state"], "ok");
    assert_eq!(
        health["components"]["answer"]["admission"]["own_remaining"],
        4
    );
    assert_eq!(
        health["components"]["judge"]["reasons"][0],
        "lane_unresolved_capacity"
    );
    assert_eq!(health["components"]["mine"]["state"], "degraded");
    assert_eq!(health["healthy"], false);
    assert_eq!(
        health["issues"],
        json!(["lane_unresolved_capacity", "api_dependency_unavailable"])
    );
    assert_eq!(health["operational"]["issues"], health["issues"]);
    assert_eq!(health["operational"]["status"], "degraded");
    status["work"]["answer"]["admission"] = json!({"allowed":false,"reason":"account_uncertainty",
        "scope":"account","own_count":0,"own_limit":4,"own_remaining":4});
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(
        health["components"]["answer"]["reasons"][0],
        "account_uncertainty"
    );
    assert_eq!(
        health["components"]["answer"]["admission"]["own_remaining"],
        4
    );
}

#[test]
fn retained_risk_and_old_unknown_do_not_hide_overdue_work() {
    let (config, options, mut status) = fixture();
    status["pending"] = json!({"kind":"answer","state":"unknown","created_at":1});
    status["participation"] = json!({"unresolved_count":4,"risk_admissions":1,
            "lanes":{"answer":{"historical_eligible_count":3,"capacity_exempt_count":3}}});
    status["operations"] = json!([{"state":"model_unknown","count":1}]);
    let clear = evaluate(&config, options, &status, 10000);
    assert_eq!(clear["healthy"], true);
    assert_eq!(clear["risk"]["attention_required"], true);
    assert_eq!(clear["risk"]["unresolved_effects"], 4);
    for (state, issue) in [
        ("prepared", "pending_work_overdue"),
        ("retry", "pending_work_overdue"),
        ("dispatching", "dispatch_outcome_uncertain"),
        ("generating", "model_work_overdue"),
    ] {
        status["pending_work"] = json!([{"kind":"judge","state":state,"created_at":1,
            "updated_at":1,"model_deadline":1,"http_deadline":1}]);
        let health = evaluate(&config, options, &status, 10000);
        assert!(has(&health, issue));
        assert_eq!(health["components"]["judge"]["state"], "degraded");
    }
}

#[test]
fn identity_unknown_and_rejection_remain_distinct() {
    let (config, options, mut status) = fixture();
    for state in [
        "unavailable",
        "invalid_response",
        "legacy_unknown",
        "unobserved",
    ] {
        status["hosted_identity"]["status"] = json!(state);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["hosted_identity"]["status"], state);
        assert!(health["hosted_identity_verified"].is_null());
        assert_eq!(health["components"]["answer"]["state"], "unknown");
    }
    status["hosted_identity"]["rejection"] = json!("authentication_failed");
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["hosted_identity_verified"], false);
    assert_eq!(health["components"]["answer"]["state"], "blocked");
    status.as_object_mut().unwrap().remove("hosted_identity");
    for legacy in [false, true] {
        status["hosted_identity_verified"] = json!(legacy);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["hosted_identity"]["status"], "unobserved");
        assert_eq!(health["hosted_identity"]["legacy_failure"], false);
        assert!(health["hosted_identity_verified"].is_null());
    }
}

#[test]
fn identity_status_rejects_unknown_values_and_uninitialized_claims() {
    let (config, options, mut status) = fixture();
    for state in [
        json!("unexpected"),
        json!("Verified"),
        json!(""),
        Value::Null,
        json!(true),
        json!(42),
        json!([]),
        json!({}),
    ] {
        status["hosted_identity"]["status"] = state;
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["hosted_identity"]["status"], "unobserved");
        assert!(health["hosted_identity_verified"].is_null());
    }
    status["initialized"] = json!(false);
    status["hosted_identity"] = json!({
        "status":"verified","rejection":"authentication_failed","legacy_failure":true
    });
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["hosted_identity"]["status"], "unobserved");
    assert!(health["hosted_identity_verified"].is_null());
    assert!(health["hosted_identity"]["rejection"].is_null());
    assert_eq!(health["hosted_identity"]["legacy_failure"], false);
}

#[test]
fn off_read_only_pause_and_migration_do_not_promise_participation() {
    let (config, options, mut status) = fixture();
    status["paused"] = json!(true);
    status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("read_only");
    status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["components"]["answer"]["state"], "blocked");
    assert_eq!(health["components"]["judge"]["state"], "ok");
    assert_eq!(health["components"]["mine"]["state"], "disabled");
    assert_eq!(health["intervention"]["unattended"], false);
    status["migration"] = json!({"pending":true,"phase":"adopting"});
    let health = evaluate(&config, options, &status, 10000);
    assert!(has(&health, "migration_pending"));
    assert_eq!(health["intervention"]["reason"], "migration_pending");
}

#[test]
fn heartbeat_deadline_boundary_and_controller_fences() {
    let (config, options, status) = fixture();
    let floor = controller_floor(&status)
        .unwrap()
        .max(options.stale_seconds) as i64;
    assert!(!has(
        &evaluate(&config, options, &status, 10000 + floor),
        "controller_stale"
    ));
    assert!(has(
        &evaluate(&config, options, &status, 10001 + floor),
        "controller_stale"
    ));
    for (field, value, code) in [
        ("controller_stopped", json!(true), "controller_stopped"),
        ("identity_matches_config", json!(false), "identity_mismatch"),
    ] {
        let mut changed = status.clone();
        changed[field] = value;
        assert!(has(&evaluate(&config, options, &changed, 10000), code));
    }
    let mut changed = status.clone();
    changed["effective_runtime"]["reload_blocked"] = json!(true);
    assert!(has(
        &evaluate(&config, options, &changed, 10000),
        "reload_blocked"
    ));
    changed["effective_runtime"]["observed_at"] = json!(10001);
    assert!(has(
        &evaluate(&config, options, &changed, 10000),
        "clock_regressed"
    ));
}

#[test]
fn inventory_completeness_and_missing_admission_are_honest() {
    let (config, options, mut status) = fixture();
    status["work"]["judge"]["assessment"]["completeness"] = json!("bounded_partial");
    assert_eq!(
        evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
        "unknown"
    );
    let partial = evaluate(&config, options, &status, 10000);
    assert_eq!(partial["healthy"], false);
    assert_eq!(partial["operational"]["status"], "unknown");
    assert_eq!(partial["issues"], json!(["work_evidence_unavailable"]));
    assert_eq!(partial["operational"]["issues"], partial["issues"]);
    status["work"]["judge"]["assessment"]["completeness"] = json!("complete");
    status["work"]["judge"]["assessment"]["valid_until"] = json!(10000);
    assert_eq!(
        evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
        "unknown"
    );
    status.as_object_mut().unwrap().remove("admission_blocked");
    let health = evaluate(&config, options, &status, 10000);
    assert_eq!(health["operational"]["status"], "unknown");
    assert!(has(&health, "admission_unobserved"));
}

#[test]
fn disk_findings_preserve_lane_evidence_risk_and_controller_provenance() {
    let (config, options, mut status) = fixture();
    status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
    for (code, state, readiness, intervention) in [
        (
            "state_disk_space_low",
            "degraded",
            json!(false),
            "operator_required",
        ),
        (
            "state_disk_space_unavailable",
            "unknown",
            Value::Null,
            "undetermined",
        ),
    ] {
        let mut health = evaluate(&config, options, &status, 10000);
        let before = health.clone();
        apply_disk_issue(&mut health, code);
        assert_eq!(health["risk"], before["risk"]);
        assert_eq!(health["healthy"], false);
        assert_eq!(health["components"]["controller"]["state"], state);
        assert_eq!(health["components"]["controller"]["reasons"], json!([code]));
        assert_eq!(health["operational"]["status"], state);
        assert_eq!(health["issues"], json!([code]));
        assert_eq!(health["operational"]["issues"], health["issues"]);
        assert_eq!(health["intervention"]["status"], intervention);
        assert_eq!(health["intervention"]["controller"]["ready"], readiness);
        assert_eq!(health["intervention"]["controller"]["reason"], code);
        assert_eq!(health["intervention"]["controller"]["observed_at"], 10000);
        assert_eq!(
            health["intervention"]["next_action"],
            "inspect_state_filesystem"
        );
        assert_eq!(health["intervention"]["next_at"], Value::Null);
        assert_ne!(health["intervention"]["unattended"], true);
        for lane in LANES {
            assert_eq!(health["components"][lane], before["components"][lane]);
            assert_eq!(health["work"][lane], before["work"][lane]);
            assert_eq!(
                health["intervention"]["lanes"][lane],
                health["work"][lane]["intervention"]["status"]
            );
        }
    }
}

#[test]
fn participation_opt_out_waives_pause_not_intrinsic_core_or_accounting_faults() {
    let (config, mut options, mut status) = fixture();
    options.expect_participation = false;
    status["paused"] = json!(true);
    status["admission_blocked"] = json!(true);
    for lane in LANES {
        status["work"][lane]["admission"]["allowed"] = json!(false);
        status["work"][lane]["admission"]["reason"] = json!("admission_paused");
        status["participation"]["lanes"][lane] = status["work"][lane]["admission"].clone();
    }
    status["hosted_identity"]["status"] = json!("unobserved");
    status["observations"]["answer"] = Value::Null;
    status["lane_controls"]["answer"]["authoritative_closure"]["state"] = json!("closed");
    status["lane_controls"]["answer"]["authoritative_closure"]["reasons"] =
        json!(["global_paused"]);
    let paused = evaluate(&config, options, &status, 10000);
    assert_eq!(paused["healthy"], true);
    assert_eq!(paused["components"]["controller"]["state"], "blocked");
    assert_eq!(paused["components"]["answer"]["state"], "blocked");
    assert_eq!(paused["intervention"]["unattended"], false);
    for (pointer, value, issue) in [
        (
            "/effective_runtime/observed_at",
            json!(1),
            "controller_stale",
        ),
        (
            "/effective_runtime/policy",
            Value::Null,
            "effective_policy_unavailable",
        ),
        (
            "/identity_matches_config",
            Value::Null,
            "controller_evidence_unavailable",
        ),
        ("/controller_stopped", json!(true), "controller_stopped"),
        (
            "/hosted_identity/rejection",
            json!("authentication_failed"),
            "hosted_identity_authentication_failed",
        ),
    ] {
        let mut changed = status.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let report = evaluate(&config, options, &changed, 10000);
        assert_eq!(report["healthy"], false, "{issue}");
        assert!(has(&report, issue));
        assert_eq!(report["issues"], report["operational"]["issues"]);
    }
    status["effective_runtime"]["reload_blocked"] = json!(true);
    assert_eq!(evaluate(&config, options, &status, 10000)["healthy"], true);
    status["participation"]["lanes"]["judge"]["pre_intent_blocker"] =
        json!({"reason":"lane_unresolved_capacity","not_before":null});
    let blocked = evaluate(&config, options, &status, 10000);
    assert_eq!(blocked["issues"], json!(["lane_unresolved_capacity"]));
    assert_eq!(blocked["operational"]["status"], "blocked");
    status["participation"]["lanes"]["judge"]
        .as_object_mut()
        .unwrap()
        .remove("pre_intent_blocker");
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "admission_evidence_unavailable"
    ));
}

#[test]
fn read_only_requires_observations_without_borrowing_write_identity_or_off_history() {
    let (config, mut options, mut status) = fixture();
    options.expect_participation = false;
    for lane in ["answer", "judge"] {
        status["effective_runtime"]["policy"]["capabilities"][lane]["mode"] = json!("read_only");
        status["work"][lane]["model"] =
            json!({"current_route":true,"failure_category":"native_auth_unavailable"});
    }
    status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
    status["hosted_identity"]["status"] = json!("unobserved");
    status["observations"]["answer"] = Value::Null;
    status["observations"]["mine"]["observed_at"] = json!(20000);
    status["reads"].as_array_mut().unwrap().pop();
    let observed = evaluate(&config, options, &status, 10000);
    assert_eq!(observed["healthy"], true);
    assert_eq!(observed["components"]["answer"]["state"], "ok");
    assert_eq!(observed["components"]["judge"]["state"], "ok");
    assert_eq!(observed["components"]["mine"]["state"], "disabled");
    assert_eq!(observed["intervention"]["unattended"], false);
    options.expect_participation = true;
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "no_active_capabilities"
    ));
    options.expect_participation = false;
    status["reads"][1]["last_success_at"] = json!(1);
    let stale = evaluate(&config, options, &status, 10000);
    assert_eq!(stale["healthy"], false);
    assert_eq!(stale["operational"]["status"], "unknown");
    assert_eq!(stale["components"]["answer"]["state"], "ok");
    assert_eq!(stale["components"]["judge"]["state"], "unknown");
    status["reads"][1]["last_success_at"] = json!(10001);
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "clock_regressed"
    ));
}

#[test]
fn required_unknowns_deduplicate_and_do_not_conceal_known_faults_or_fences() {
    let (config, options, mut status) = fixture();
    status["work"]["judge"]["assessment"]["completeness"] = json!("bounded_partial");
    status["work"]["mine"]["phase"] = json!("observing");
    let unknown = evaluate(&config, options, &status, 10000);
    assert_eq!(unknown["issues"], json!(["work_evidence_unavailable"]));
    assert_eq!(unknown["operational"]["status"], "unknown");
    status["work"]["answer"]["admission"] =
        json!({"allowed":false,"reason":"lane_unresolved_capacity"});
    let blocked = evaluate(&config, options, &status, 10000);
    assert_eq!(
        blocked["issues"],
        json!(["lane_unresolved_capacity", "work_evidence_unavailable"])
    );
    assert_eq!(blocked["operational"]["status"], "blocked");
    status["pending_work"] = json!([{"kind":"mine","state":"dispatching",
        "created_at":1,"updated_at":1,"http_deadline":1}]);
    let fault = evaluate(&config, options, &status, 10000);
    assert_eq!(fault["operational"]["status"], "degraded");
    assert!(has(&fault, "dispatch_outcome_uncertain"));
    assert_eq!(fault["issues"], fault["operational"]["issues"]);
}

#[test]
fn current_completion_supersedes_old_reads_without_folding_unrelated_resources() {
    let (config, options, mut status) = fixture();
    for row in status["reads"].as_array_mut().unwrap() {
        row["last_success_at"] = Value::Null;
        row["last_failure_at"] = json!(9999);
        row["failure_category"] = json!("http");
        row["status"] = json!(503);
    }
    status["reads"]
        .as_array_mut()
        .unwrap()
        .push(json!({"owner":"judge","purpose":"job",
        "resource":"old:1","operation_id":1,"binding_revision":1,"retired":true,
        "last_failure_at":10000,"failure_category":"http","status":403}));
    status["reads_truncated"] = json!(true);
    let completed = evaluate(&config, options, &status, 10000);
    assert_eq!(completed["healthy"], true);
    assert_eq!(
        completed["components"]["api"]["lanes"]["judge"]["state"],
        "degraded"
    );
    assert_eq!(completed["components"]["api"]["resources_truncated"], true);
    status["observations"]["answer"]["answered"] = json!(false);
    status["pending_work"] = json!([{"kind":"answer","state":"generating",
        "created_at":10000,"updated_at":10000,"model_deadline":10100}]);
    let working = evaluate(&config, options, &status, 10000);
    assert_eq!(working["healthy"], true);
    assert_eq!(
        working["components"]["answer"]["reasons"],
        json!(["work_in_progress"])
    );
    status["pending_work"][0]["state"] = json!("queued");
    status["work"]["answer"]["next_action"] = json!("read_job");
    status["work"]["answer"]["binding_revision"] = json!(2);
    status["work"]["answer"]["read_key"] =
        json!({"owner":"answer","purpose":"job","resource":"8:2"});
    status["reads"].as_array_mut().unwrap().push(json!({"owner":"answer","purpose":"job",
        "resource":"8:2","binding_revision":2,"last_failure_at":10000,"failure_category":"http","status":503}));
    let dependent = evaluate(&config, options, &status, 10000);
    assert!(has(&dependent, "api_dependency_unavailable"));
    assert_eq!(dependent["components"]["answer"]["state"], "degraded");
    assert_eq!(dependent["components"]["judge"]["state"], "ok");
    // Isolate exact-binding behavior from the independently failed discovery
    // dependency, which became required again after local generation ended.
    status["reads"][0]["last_success_at"] = json!(10000);
    status["reads"][0]["last_failure_at"] = Value::Null;
    status["reads"][0]["failure_category"] = Value::Null;
    status["reads"][0]["status"] = json!(200);
    status["reads"][4]["binding_revision"] = json!(1);
    let missing_binding = evaluate(&config, options, &status, 10000);
    assert!(!has(&missing_binding, "api_dependency_unavailable"));
    assert_eq!(missing_binding["healthy"], false);
}

#[test]
fn opt_out_and_off_do_not_cancel_captured_deadlines_or_bound_dependencies() {
    let (config, mut options, mut status) = fixture();
    options.expect_participation = false;
    status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("off");
    status["captured_work"] = json!([{"kind":"judge","state":"generating","created_at":9999,
        "diagnostic":{"stage":"model_preflight","execution":"not_started","state":"awaiting_admission"}}]);
    let missing = evaluate(&config, options, &status, 10000);
    assert!(has(&missing, "model_deadline_unavailable"));
    assert_eq!(missing["healthy"], false);
    assert_eq!(missing["components"]["judge"]["state"], "unknown");
    status["captured_work"][0]["pending_execution_deadline"] = json!(9999);
    assert!(has(
        &evaluate(&config, options, &status, 10000),
        "pending_model_execution_expired"
    ));
    status["captured_work"] = json!([{"kind":"judge","state":"queued","created_at":9999}]);
    status["work"]["judge"]["next_action"] = json!("enable_capability");
    status["work"]["judge"]["binding_revision"] = json!(2);
    status["work"]["judge"]["read_key"] = json!({"owner":"judge","purpose":"job","resource":"7:2"});
    status["reads"].as_array_mut().unwrap().push(json!({"owner":"judge","purpose":"job",
        "resource":"7:2","binding_revision":2,"last_failure_at":10000,"failure_category":"http","status":503}));
    let bound = evaluate(&config, options, &status, 10000);
    assert!(has(&bound, "api_dependency_unavailable"));
    assert_eq!(bound["healthy"], false);
    status["reads"][3]["binding_revision"] = json!(1);
    assert!(!has(
        &evaluate(&config, options, &status, 10000),
        "api_dependency_unavailable"
    ));
}

#[test]
fn disk_unknown_never_downgrades_known_core_or_lane_operator_findings() {
    let (config, options, mut status) = fixture();
    for core in [false, true] {
        if core {
            status["identity_matches_config"] = json!(false);
        } else {
            status["paused"] = json!(true);
        }
        let mut health = evaluate(&config, options, &status, 10000);
        let before = health["intervention"]["reason"].clone();
        apply_disk_issue(&mut health, "state_disk_space_unavailable");
        assert_eq!(health["intervention"]["status"], "operator_required");
        assert_eq!(health["intervention"]["reason"], before);
        assert_eq!(health["intervention"]["unattended"], false);
        assert_eq!(
            health["intervention"]["next_action"],
            "inspect_state_filesystem"
        );
        assert_eq!(health["intervention"]["next_at"], Value::Null);
        assert_eq!(
            health["intervention"]["controller"]["ready"],
            if core { json!(false) } else { Value::Null }
        );
    }
}

#[test]
fn restoration_qualifies_stop_only_evidence_under_disk_and_real_effective_modes() {
    let (config, options, mut status) = fixture();
    status["controller_stopped"] = json!(true);
    status["paused"] = json!(true);
    status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("read_only");
    status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
    for disk in [
        None,
        Some("state_disk_space_low"),
        Some("state_disk_space_unavailable"),
    ] {
        let mut health = evaluate(&config, options, &status, 10000);
        if let Some(code) = disk {
            apply_disk_issue(&mut health, code);
        }
        let risk = health["risk"].clone();
        qualify_doctor(
            &mut health,
            &json!({"restoration":{"verified":true,"runtime":"restored"}}),
        );
        assert_eq!(health["healthy"], false);
        assert_eq!(health["risk"], risk);
        assert!(!has(&health, "controller_stopped"));
        assert!(has(&health, "runtime_restored_observation_pending"));
        assert_eq!(
            health["work"]["answer"]["intervention"]["next_action"],
            "resume"
        );
        assert_eq!(
            health["work"]["judge"]["intervention"]["reason"],
            "runtime_restored_observation_pending"
        );
        assert_eq!(
            health["work"]["mine"]["intervention"]["reason"],
            "capability_off"
        );
        assert_eq!(health["intervention"]["unattended"], false);
        assert_eq!(health["components"]["judge"]["state"], "unknown");
        if disk.is_some() {
            assert_eq!(
                health["intervention"]["next_action"],
                "inspect_state_filesystem"
            );
        } else {
            assert_eq!(health["intervention"]["controller"]["ready"], Value::Null);
            assert_eq!(health["intervention"]["reason"], "admission_paused");
        }
        for lane in LANES {
            assert_eq!(
                health["intervention"]["lanes"][lane],
                health["work"][lane]["intervention"]["status"]
            );
            assert_ne!(
                health["work"][lane]["intervention"]["next_action"],
                "start_controller"
            );
        }
    }
}

#[test]
fn restored_unpaused_core_state_tracks_remaining_disk_evidence() {
    let (config, options, mut status) = fixture();
    status["controller_stopped"] = json!(true);
    for (disk, state) in [
        ("state_disk_space_low", "degraded"),
        ("state_disk_space_unavailable", "unknown"),
    ] {
        let mut health = evaluate(&config, options, &status, 10000);
        apply_disk_issue(&mut health, disk);
        qualify_doctor(
            &mut health,
            &json!({"restoration":{"verified":true,"runtime":"restored"}}),
        );
        assert_eq!(health["components"]["controller"]["state"], state);
        assert_eq!(health["operational"]["status"], state);
        assert_eq!(health["healthy"], false);
        assert_eq!(
            health["intervention"]["next_action"],
            "inspect_state_filesystem"
        );
        let reasons = health["components"]["controller"]["reasons"]
            .as_array()
            .unwrap();
        assert!(reasons.iter().any(|reason| reason == disk));
        assert!(
            reasons
                .iter()
                .any(|reason| reason == "runtime_restored_observation_pending")
        );
        assert!(!reasons.iter().any(|reason| reason == "controller_stopped"));
    }
}

#[test]
fn restoration_reclassifies_remaining_identity_uncertainty() {
    let (config, options, mut status) = fixture();
    status["controller_stopped"] = json!(true);
    for state in [
        "unobserved",
        "unavailable",
        "invalid_response",
        "legacy_unknown",
    ] {
        status["hosted_identity"]["status"] = json!(state);
        let mut health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["components"]["controller"]["state"], "blocked");
        qualify_doctor(
            &mut health,
            &json!({"restoration":{"verified":true,"runtime":"restored"}}),
        );
        assert_eq!(health["components"]["controller"]["state"], "unknown");
        assert_eq!(health["operational"]["status"], "unknown");
        assert!(has(&health, &format!("hosted_identity_{state}")));
        assert!(has(&health, "runtime_restored_observation_pending"));
        assert!(!has(&health, "controller_stopped"));
    }
}

#[test]
fn restoration_keeps_independent_lane_faults_and_first_lane_wins_ties() {
    let (config, options, mut status) = fixture();
    status["controller_stopped"] = json!(true);
    status["work"]["judge"]["assessment"]["locally_judgeable"] = json!(true);
    status["work"]["judge"]["model"] =
        json!({"current_route":true,"failure_category":"native_auth_unavailable"});
    status["work"]["mine"]["model"] =
        json!({"current_route":true,"failure_category":"executable_unavailable"});
    for lane in LANES {
        status["work"][lane]["phase"] = json!("stopped");
        status["work"][lane]["reason"] = json!("controller_stopped");
        status["work"][lane]["next_action"] = json!("start_controller");
    }
    let mut health = evaluate(&config, options, &status, 10000);
    qualify_doctor(
        &mut health,
        &json!({"restoration":{"verified":true,"runtime":"restored"}}),
    );
    assert_eq!(
        health["intervention"]["reason"],
        "model_authentication_failed"
    );
    assert_eq!(health["intervention"]["unattended"], false);
    assert_eq!(health["intervention"]["controller"]["ready"], Value::Null);
    assert_eq!(
        health["work"]["mine"]["intervention"]["reason"],
        "model_configuration_failed"
    );
    assert_eq!(health["components"]["controller"]["state"], "unknown");
    assert_eq!(health["healthy"], false);
    for lane in LANES {
        assert_ne!(health["work"][lane]["next_action"], "start_controller");
        assert_ne!(
            health["work"][lane]["intervention"]["next_action"],
            "start_controller"
        );
    }
    let controller = health["intervention"]["controller"].clone();
    let work = health["work"].clone();
    qualify_doctor(
        &mut health,
        &json!({"failure":"repair_restore_failed",
        "restoration":{"verified":false,"runtime":"unrestored"}}),
    );
    assert_eq!(
        health["intervention"]["reason"],
        "doctor_repair_unavailable"
    );
    assert_eq!(health["intervention"]["controller"], controller);
    assert_eq!(health["work"], work);
    for lane in LANES {
        assert_eq!(
            health["intervention"]["lanes"][lane],
            work[lane]["intervention"]["status"]
        );
    }
    for restoration in [
        json!({"verified":false,"runtime":"restored"}),
        json!({"verified":true,"runtime":"unrestored"}),
    ] {
        let mut stopped = evaluate(&config, options, &status, 10000);
        let before = stopped.clone();
        qualify_doctor(&mut stopped, &json!({"restoration":restoration}));
        assert_eq!(stopped, before);
    }
}

#[test]
fn repair_failure_preserves_observed_readiness_without_claiming_doctor_success() {
    let (config, options, status) = fixture();
    let mut health = evaluate(&config, options, &status, 10000);
    let before = health.clone();
    qualify_doctor(
        &mut health,
        &json!({"failure":"doctor_recovery_unavailable"}),
    );
    assert_eq!(health["healthy"], true);
    assert_eq!(health["attention_required"], true);
    assert_eq!(
        health["intervention"]["controller"],
        before["intervention"]["controller"]
    );
    assert_eq!(
        health["intervention"]["lanes"],
        before["intervention"]["lanes"]
    );
    assert_eq!(health["work"], before["work"]);
    assert_eq!(
        health["intervention"]["next_action"],
        "inspect_repair_failure"
    );
    assert_eq!(health["intervention"]["unattended"], false);
    for code in ["state_disk_space_low", "state_disk_space_unavailable"] {
        let mut gated = before.clone();
        apply_disk_issue(&mut gated, code);
        let controller = gated["intervention"]["controller"].clone();
        qualify_doctor(
            &mut gated,
            &json!({"failure":"doctor_recovery_unavailable"}),
        );
        assert_eq!(gated["intervention"]["status"], "operator_required");
        assert_eq!(gated["intervention"]["reason"], "doctor_repair_unavailable");
        assert_eq!(
            gated["intervention"]["next_action"],
            "inspect_state_filesystem"
        );
        assert_eq!(gated["intervention"]["next_at"], Value::Null);
        assert_eq!(gated["intervention"]["unattended"], false);
        assert_eq!(gated["intervention"]["controller"], controller);
        assert_eq!(
            gated["intervention"]["lanes"],
            before["intervention"]["lanes"]
        );
        assert_eq!(gated["work"], before["work"]);
        assert_eq!(gated["risk"], before["risk"]);
    }
}

#[test]
fn restoration_reports_lane_pause_not_global_pause_for_desired_judge_pause() {
    let (config, options, mut status) = fixture();
    status["controller_stopped"] = json!(true);
    // Global admission is unpaused; only the judge lane requests a pause.
    status["paused"] = json!(false);
    status["lane_controls"]["judge"] = json!({"desired": {
        "paused": true,
        "control_token": "judge-token",
        "control_revision": 7
    }});
    // An unrelated lane keeps an independent fault through restoration.
    status["work"]["mine"]["model"] =
        json!({"current_route": true, "failure_category": "executable_unavailable"});
    for lane in LANES {
        status["work"][lane]["phase"] = json!("stopped");
        status["work"][lane]["reason"] = json!("controller_stopped");
        status["work"][lane]["next_action"] = json!("start_controller");
    }
    let mut health = evaluate(&config, options, &status, 10000);
    assert_eq!(
        health["work"]["judge"]["intervention"]["reason"],
        "lane_paused"
    );
    let risk = health["risk"].clone();
    qualify_doctor(
        &mut health,
        &json!({"restoration": {"verified": true, "runtime": "restored"}}),
    );
    assert_eq!(health["healthy"], false);
    assert_eq!(health["risk"], risk);
    assert!(!has(&health, "controller_stopped"));
    assert!(has(&health, "runtime_restored_observation_pending"));
    assert_eq!(health["paused"], false);
    assert_eq!(health["lane_controls"]["judge"]["desired"]["paused"], true);
    assert_eq!(
        health["work"]["judge"]["intervention"]["reason"],
        "lane_paused"
    );
    assert_eq!(
        health["work"]["judge"]["intervention"]["next_action"],
        "resume"
    );
    assert_eq!(health["intervention"]["status"], "operator_required");
    assert_eq!(health["intervention"]["reason"], "lane_paused");
    assert_eq!(health["intervention"]["next_action"], "resume");
    assert_eq!(health["intervention"]["unattended"], false);
    assert_eq!(
        health["intervention"]["lanes"]["judge"],
        health["work"]["judge"]["intervention"]["status"]
    );
    assert_eq!(
        health["work"]["mine"]["intervention"]["reason"],
        "model_configuration_failed"
    );
    for lane in LANES {
        assert_ne!(health["work"][lane]["next_action"], "start_controller");
        assert_ne!(
            health["work"][lane]["intervention"]["next_action"],
            "start_controller"
        );
    }
}
