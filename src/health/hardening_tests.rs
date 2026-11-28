use super::*;

#[test]
fn completed_same_lane_refresh_keeps_only_original_evidence_window() {
    for (index, lane) in LANES.into_iter().enumerate() {
        let (config, options, mut status) = super::tests::fixture();
        status["reads"][index]["last_failure_at"] = json!(10001);
        status["reads"][index]["failures"] = json!(1);
        status["reads"][index]["failure_category"] = json!("transport");
        status["reads"][index]["status"] = json!(503);
        status["lane_participation"][lane]["assessment"] =
            json!({"observed_at":10000,"valid_until":10002});
        if lane == "judge" {
            status["work"][lane]["assessment"]["valid_until"] = json!(10002);
        }
        let transient = evaluate(&config, options, &status, 10001);
        assert_eq!(transient["healthy"], true, "{lane}: {transient}");
        assert_eq!(transient["work"][lane]["refresh"]["state"], "transient");
        assert_eq!(transient["work"][lane]["refresh"]["observed_at"], 10000);
        assert_eq!(transient["work"][lane]["refresh"]["valid_until"], 10002);
        // The raw failure is never relabelled as a successful API read.
        assert_eq!(
            transient["components"]["api"]["lanes"][lane]["state"],
            "degraded"
        );
        status["reads"][index]["in_flight"] = json!(true);
        let refreshing = evaluate(&config, options, &status, 10001);
        assert_eq!(refreshing["work"][lane]["refresh"]["state"], "refreshing");
        assert_eq!(refreshing["work"][lane]["refresh"]["valid_until"], 10002);
        let expired = evaluate(&config, options, &status, 10002);
        assert_eq!(expired["healthy"], false, "{lane}: {expired}");
        assert_eq!(expired["work"][lane]["refresh"]["state"], "blocked");
    }
}

#[test]
fn refreshing_never_borrows_completion_or_hides_auth_stamp_and_deadline_failures() {
    for edge in ["missing", "auth", "stamp", "deadline", "admission"] {
        let (config, options, mut status) = super::tests::fixture();
        status["reads"][0]["last_failure_at"] = json!(10001);
        status["reads"][0]["failures"] = json!(1);
        status["reads"][0]["failure_category"] = json!("transport");
        status["reads"][0]["status"] = json!(503);
        match edge {
            "missing" => status["observations"]["answer"]["answered"] = json!(false),
            "auth" => status["reads"][0]["status"] = json!(401),
            "stamp" => status["lane_participation"]["answer"]["freshness"] = json!("stale"),
            "deadline" => {
                status["pending_work"] = json!([{
                    "kind":"answer","state":"dispatching","created_at":1,"updated_at":1,
                    "http_deadline":1
                }])
            }
            "admission" => {
                status["work"]["answer"]["admission"] = json!({
                    "allowed":false,"reason":"account_uncertainty","scope":"account"
                });
                status["participation"]["lanes"]["answer"] =
                    status["work"]["answer"]["admission"].clone();
            }
            _ => unreachable!(),
        }
        let report = evaluate(&config, options, &status, 10001);
        assert_eq!(report["healthy"], false, "{edge}: {report}");
        assert_eq!(
            report["work"]["answer"]["refresh"]["state"], "blocked",
            "{edge}"
        );
        assert_ne!(report["components"]["answer"]["state"], "ok", "{edge}");
    }
}

#[test]
fn observation_negatives_are_conclusive_but_release_notice_is_passive() {
    for state in [
        "not_assessed",
        "unavailable",
        "observed_match",
        "mismatch",
        "stopped",
    ] {
        let (config, options, mut status) = super::tests::fixture();
        status["process_identity"] = json!(state);
        let baseline = evaluate(&config, options, &status, 10000);
        status["release_advisory"] = json!({"availability":"available","latest_version":"9.9.9"});
        let advisory = evaluate(&config, options, &status, 10000);
        for key in [
            "healthy",
            "issues",
            "warnings",
            "intervention",
            "severity",
            "operator_action_required",
        ] {
            assert_eq!(baseline[key], advisory[key], "{state}/{key}");
        }
        assert_eq!(
            advisory["healthy"],
            !matches!(state, "mismatch" | "stopped")
        );
        assert_eq!(advisory["process_identity"], state);
        if state == "mismatch" {
            assert_eq!(
                advisory["intervention"]["next_action"],
                "inspect_managed_service"
            );
        }
    }
}

#[test]
fn compact_evidence_is_bounded_private_and_never_recalculates_risk() {
    let (config, options, mut status) = super::tests::fixture();
    status["participation"]["unresolved_count"] = json!(2500);
    status["participation"]["lanes"]["answer"]["historical_eligible_count"] = json!(2000);
    status["pending_work"] = json!(
        (0..256)
            .map(|id| json!({
                "kind":"answer","state":"unknown","nonblocking_for_fresh_work":true,
                "operation_id":id,"binding_revision":1,"private":"private-work-canary"
            }))
            .collect::<Vec<_>>()
    );
    status["reads"]
        .as_array_mut()
        .unwrap()
        .extend((0..256).map(|id| {
            json!({
                "owner":"answer","purpose":"job","resource":format!("private-job-canary-{id}"),
                "operation_id":id,"binding_revision":1,"last_failure_at":10000,"status":503,
                "failure_category":"transport"
            })
        }));
    let full = evaluate(&config, options, &status, 10000);
    let mut compact = full.clone();
    compact_diagnostics(&mut compact);
    let envelope = json!({"schema":"agmi.cli.v1","ok":false,"type":"health","data":compact});
    let bytes = serde_json::to_vec(&envelope).unwrap();
    assert!(bytes.len() <= 16 * 1024, "{}", bytes.len());
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("private-work-canary"));
    assert!(!text.contains("private-job-canary"));
    assert_eq!(envelope["data"]["risk"]["unresolved_effects"], 2500);
    assert_eq!(
        envelope["data"]["historical_uncertainty"]["historical_eligible_answers"],
        2000
    );
    assert_eq!(envelope["data"]["pending_work_count"], 256);
    assert_eq!(envelope["data"]["healthy"], full["healthy"]);
    assert_eq!(
        envelope["data"]["components"]["api"]["background_resources"]["count"],
        256
    );
    assert_eq!(full["pending_work"].as_array().unwrap().len(), 256);
}

#[test]
fn managed_health_wait_bounds_transient_upstream_outages_and_rejects_sustained_outages() {
    let at = 10_000_i64;
    let make_report = |observed_at: Option<i64>, age_seconds: Option<u64>, next_at: i64| {
        json!({
            "checked_at": at,
            "healthy": false,
            "hosted_identity_verified": true,
            "issues": ["api_dependency_unavailable", "challenge_observation_stale"],
            "thresholds": { "stale_seconds": 180 },
            "intervention": {
                "unattended": true,
                "controller": { "ready": true },
            },
            "participation": {
                "lanes": {
                    "answer": { "allowed": true },
                    "judge": { "allowed": true },
                    "mine": { "allowed": true },
                },
            },
            "components": {
                "controller": { "state": "ok", "reasons": [] },
                "storage": { "state": "ok", "reasons": [] },
                "disk": { "state": "ok", "reasons": [] },
                "api": { "state": "degraded", "reasons": ["api_dependency_unavailable"] },
                "answer": {
                    "mode": "active",
                    "state": "degraded",
                    "reasons": ["api_dependency_unavailable", "challenge_observation_stale"],
                    "observed_at": observed_at,
                    "age_seconds": age_seconds,
                },
                "judge": { "mode": "off", "state": "disabled", "reasons": [] },
                "mine": { "mode": "off", "state": "disabled", "reasons": [] },
            },
            "work": {
                "answer": {
                    "intervention": {
                        "status": "automatic_recovery",
                        "reason": "read_backoff",
                        "next_action": "observe_challenge",
                        "next_at": next_at,
                        "observation_fresh": false,
                    },
                },
                "judge": { "intervention": {} },
                "mine": { "intervention": {} },
            },
        })
    };
    // Transient blip (age 240s <= 2 * 180s, next retry in 60s <= 180s): accepted as managed wait (exit 3).
    let transient = make_report(Some(at - 240), Some(240), at + 60);
    assert!(managed_health_wait(&transient));
    // Sustained outage (age 900s > 2 * 180s): must NOT be masked as exit 3.
    let sustained = make_report(Some(at - 900), Some(900), at + 60);
    assert!(!managed_health_wait(&sustained));
    // Never-observed outage (observed_at = null): must NOT be masked as exit 3.
    let never_observed = make_report(None, None, at + 60);
    assert!(!managed_health_wait(&never_observed));
}
