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
    let make_report = |last_success_at: Option<i64>, next_at: i64| {
        let mut status = super::tests::fixture().2;
        status["observations"]["answer"]["observed_at"] = json!(last_success_at);
        status["reads"][0]["last_success_at"] = json!(last_success_at);
        status["reads"][0]["last_failure_at"] = json!(at - 5);
        status["reads"][0]["failures"] = json!(2);
        status["reads"][0]["failure_category"] = json!("transport");
        status["reads"][0]["status"] = json!(503);
        status["reads"][0]["next_at"] = json!(next_at);
        let (config, options, _) = super::tests::fixture();
        evaluate(&config, options, &status, at)
    };
    // Transient blip (last success 240s ago <= 2 * 180s, next retry in 60s <= 180s): accepted as managed wait (exit 3).
    let transient = make_report(Some(at - 240), at + 60);
    assert!(managed_health_wait(&transient), "{transient}");
    // Sustained outage (last success 900s ago > 2 * 180s, despite recent failure 5s ago): must NOT be masked as exit 3.
    let sustained = make_report(Some(at - 900), at + 60);
    assert!(!managed_health_wait(&sustained), "{sustained}");
    // Never-observed outage (last_success_at = null, despite recent failure 5s ago): must NOT be masked as exit 3.
    let never_observed = make_report(None, at + 60);
    assert!(!managed_health_wait(&never_observed), "{never_observed}");

    // Verify judge/mine also reject sustained and never-observed outages even when
    // api::project sets component.observed_at to the recent last_failure_at.
    for (index, lane) in [(1usize, "judge"), (2usize, "mine")] {
        for last_success_at in [Some(at - 900), None] {
            let (config, options, mut status) = super::tests::fixture();
            if lane == "judge" {
                status["work"]["judge"]["assessment"]["observed_at"] = json!(last_success_at);
            } else {
                status["observations"][lane]["observed_at"] = json!(last_success_at);
            }
            status["reads"][index]["last_success_at"] = json!(last_success_at);
            status["reads"][index]["last_failure_at"] = json!(at - 5);
            status["reads"][index]["failures"] = json!(3);
            status["reads"][index]["failure_category"] = json!("transport");
            status["reads"][index]["status"] = json!(503);
            status["reads"][index]["next_at"] = json!(at + 60);
            let report = evaluate(&config, options, &status, at);
            assert!(
                !managed_health_wait(&report),
                "{lane} {last_success_at:?} must not exit 3: {report}"
            );
        }
    }
}

#[test]
fn health_intervention_vocabulary_matches_shared_updater_allowlist() {
    let (config, options, mut status) = super::tests::fixture();
    let cases: Vec<(&str, Value)> = vec![
        ("healthy", evaluate(&config, options, &status, 10_000)),
        ("mismatch", {
            status["process_identity"] = json!("mismatch");
            evaluate(&config, options, &status, 10_000)
        }),
        ("degraded_api", {
            let mut s = super::tests::fixture().2;
            s["reads"][0]["last_failure_at"] = json!(10_005);
            s["reads"][0]["failures"] = json!(2);
            s["reads"][0]["failure_category"] = json!("transport");
            s["reads"][0]["status"] = json!(503);
            s["reads"][0]["next_at"] = json!(10_060);
            evaluate(&config, options, &s, 10_010)
        }),
    ];
    for (label, report) in cases {
        if let Some(reason) = report["intervention"]["reason"].as_str() {
            assert!(
                vocabulary::DIAGNOSTIC_REASONS.contains(&reason),
                "{label}: intervention.reason {reason:?} missing from vocabulary::DIAGNOSTIC_REASONS"
            );
        }
        if let Some(action) = report["intervention"]["next_action"].as_str() {
            assert!(
                vocabulary::NEXT_ACTIONS.contains(&action),
                "{label}: intervention.next_action {action:?} missing from vocabulary::NEXT_ACTIONS"
            );
        }
    }
}
