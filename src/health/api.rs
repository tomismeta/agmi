use serde_json::{Map, Value, json};

const SCOPES: [&str; 6] = [
    "challenge",
    "identity",
    "assignments",
    "assignment_evidence",
    "job",
    "receipt",
];

fn timestamp(row: &Value, field: &str) -> Option<i64> {
    row.get(field)?.as_i64().filter(|value| *value >= 0)
}

fn empty(reason: &str) -> Value {
    json!({
        "state": "unknown",
        "reasons": [reason],
        "observed_at": null,
        "age_seconds": null,
        "next_actions": [{"kind":"instruction","authorization_required":false,
            "message":"Inspect locally recorded read evidence; health does not probe endpoints."}],
        "last_http_status": null,
        "last_http_status_observed_at": null,
        "last_success_at": null,
        "last_failure_at": null,
        "failure_category": null,
        "retry_at": null,
        "evidence": "last_recorded_read_not_live_probe"
    })
}

pub(super) fn unknown() -> Value {
    Value::Object(
        SCOPES
            .into_iter()
            .map(|scope| (scope.into(), empty("evidence_unavailable")))
            .collect(),
    )
}

/// Project recorded usable reads, never HTTP completion alone or live reachability.
/// Retry deadlines are retained scheduling evidence, not recovery predictions.
pub(super) fn evaluate(reads: &Value, at: i64, stale: u64) -> Value {
    let Some(rows) = reads.as_array() else {
        return unknown();
    };
    let mut result = Map::new();
    for scope in SCOPES {
        let mut matches = rows
            .iter()
            .filter(|row| row.get("scope").and_then(Value::as_str) == Some(scope));
        let Some(row) = matches.next() else {
            result.insert(scope.into(), empty("never_read"));
            continue;
        };
        if matches.next().is_some() {
            result.insert(scope.into(), empty("evidence_unavailable"));
            continue;
        }
        let success = timestamp(row, "last_success_at");
        let failure = timestamp(row, "last_failure_at");
        // reset_read retains the prior failure timestamp. A same-second reset
        // clears both the category and backoff, distinguishing it from failure.
        let failed = failure.is_some_and(|failed_at| {
            success.is_none_or(|success_at| {
                failed_at > success_at
                    || (failed_at == success_at
                        && (row
                            .get("failure_category")
                            .is_some_and(|value| !value.is_null())
                            || row.get("failures").and_then(Value::as_u64).unwrap_or(0) > 0))
            })
        });
        let observed = if failed { failure } else { success };
        let age = observed
            .filter(|time| *time <= at)
            .map(|time| at.abs_diff(time));
        let (state, reason) = match (observed, age) {
            (Some(_), Some(age)) if age <= stale => {
                if failed {
                    ("degraded", "read_failed")
                } else {
                    ("ok", "read_succeeded")
                }
            }
            (Some(_), Some(_)) => ("unknown", "stale_read_evidence"),
            (Some(_), None) => ("unknown", "future_read_evidence"),
            (None, _) => ("unknown", "never_read"),
        };
        let retry = [
            "next_at",
            "local_next_at",
            "server_not_before",
            "retained_conservative_floor",
        ]
        .into_iter()
        .filter_map(|field| timestamp(row, field))
        .filter(|deadline| *deadline > 0 && *deadline > at)
        .max();
        let status = row
            .get("status")
            .and_then(Value::as_u64)
            .filter(|status| (100..=599).contains(status));
        let mut component = empty(reason);
        component["state"] = json!(state);
        component["observed_at"] = json!(observed);
        component["age_seconds"] = json!(age);
        component["last_success_at"] = json!(success);
        component["last_failure_at"] = json!(failure);
        component["last_http_status"] = json!(status);
        // Cancellation/recovery can replace finished_at while retaining status.
        // Only successful HTTP responses have an independent persisted timestamp.
        component["last_http_status_observed_at"] = json!(
            status
                .filter(|status| (200..300).contains(status))
                .and_then(|_| timestamp(row, "last_http_success_at"))
        );
        component["retry_at"] = json!(retry);
        // Never copy arbitrary source error strings into the health contract.
        if failed {
            component["failure_category"] = json!(crate::store::safe_read_category(
                row["failure_category"]
                    .as_str()
                    .unwrap_or("unusable_response"),
            ));
            component["next_actions"] = if status == Some(401) || status == Some(403) {
                json!([{"kind":"instruction","authorization_required":false,
                    "message":"Review configured credentials and endpoint permissions locally; do not replay writes."}])
            } else {
                json!([{"kind":"instruction","authorization_required":false,
                    "message":"Inspect locally recorded read failures and retained retry deadlines; do not replay writes."}])
            };
        } else if state == "ok" {
            component["next_actions"] = json!([]);
        }
        result.insert(scope.into(), component);
    }
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(row: Value) -> Value {
        let mut row = row;
        row["scope"] = json!("challenge");
        evaluate(&json!([row]), 100, 10)["challenge"].clone()
    }

    #[test]
    fn fresh_and_old_usable_success() {
        assert_eq!(project(json!({"last_success_at":90}))["state"], "ok");
        let old = project(json!({"last_success_at":89}));
        assert_eq!(old["state"], "unknown");
        assert_eq!(old["age_seconds"], 11);
        assert_eq!(
            project(json!({"last_http_success_at":99,"status":200}))["state"],
            "unknown"
        );
    }

    #[test]
    fn never_read_and_unavailable_have_uniform_scopes() {
        let never = evaluate(&json!([]), 100, 10);
        let unavailable = unknown();
        assert_eq!(never.as_object().unwrap().len(), 6);
        for scope in SCOPES {
            assert_eq!(never[scope]["state"], "unknown");
            assert!(never[scope]["observed_at"].is_null());
            assert_eq!(
                never[scope].as_object().unwrap().keys().collect::<Vec<_>>(),
                unavailable[scope]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn cancellation_cannot_redate_a_retained_http_status() {
        let success = project(json!({"status":200,"started_at":95,"finished_at":99,
            "last_http_success_at":80,"last_success_at":80}));
        assert_eq!(success["last_http_status_observed_at"], 80);
        assert_eq!(success["state"], "unknown");
        let failure = project(json!({"status":503,"started_at":95,"finished_at":99,
            "last_failure_at":80,"last_http_success_at":70}));
        assert!(failure["last_http_status_observed_at"].is_null());
        assert_eq!(failure["state"], "unknown");
    }

    #[test]
    fn future_observations_are_unknown() {
        for row in [
            json!({"last_success_at":101}),
            json!({"last_success_at":95,"last_failure_at":101}),
        ] {
            let health = project(row);
            assert_eq!(health["state"], "unknown");
            assert!(health["age_seconds"].is_null());
        }
    }

    #[test]
    fn recent_failure_overrides_success_but_old_failure_is_not_an_outage() {
        let fresh = project(
            json!({"last_success_at":95,"last_failure_at":99,"status":403,"finished_at":99,"failure_category":"secret raw text"}),
        );
        assert_eq!(fresh["state"], "degraded");
        assert_eq!(fresh["last_http_status"], 403);
        assert!(fresh["last_http_status_observed_at"].is_null());
        assert_eq!(fresh["failure_category"], "unusable_response");
        assert!(!fresh.to_string().contains("secret raw text"));
        let old = project(json!({"last_failure_at":80,"status":503,"finished_at":80}));
        assert_eq!(old["state"], "unknown");
        assert_eq!(old["last_http_status"], 503);
        assert_eq!(old["last_failure_at"], 80);
    }

    #[test]
    fn successful_reset_supersedes_retained_failure_including_same_second() {
        for failed_at in [94, 95] {
            assert_eq!(
                project(
                    json!({"last_success_at":95,"last_failure_at":failed_at,"failure_category":null,"failures":0})
                )["state"],
                "ok"
            );
        }
        assert_eq!(
            project(
                json!({"last_success_at":95,"last_failure_at":95,"failure_category":"timeout","failures":1})
            )["state"],
            "degraded"
        );
    }

    #[test]
    fn in_flight_does_not_refresh_evidence() {
        let health = project(json!({"state":"in_flight","started_at":100,"last_success_at":70}));
        assert_eq!(health["state"], "unknown");
        assert_eq!(health["observed_at"], 70);
        assert_eq!(
            project(json!({"state":"in_flight","started_at":100}))["state"],
            "unknown"
        );
    }

    #[test]
    fn retry_uses_maximum_retained_future_floor() {
        let health = project(
            json!({"next_at":101,"local_next_at":110,"server_not_before":120,"retained_conservative_floor":130}),
        );
        assert_eq!(health["retry_at"], 130);
        assert!(
            project(json!({"next_at":100,"local_next_at":-1,"server_not_before":0}))["retry_at"]
                .is_null()
        );
    }

    #[test]
    fn malformed_shapes_do_not_create_success_or_leak_data() {
        for source in [
            Value::Null,
            json!({"challenge":{"last_success_at":99}}),
            json!("private"),
        ] {
            assert_eq!(evaluate(&source, 100, 10), unknown());
        }
        let health = project(
            json!({"last_success_at":"99","last_failure_at":-1,"status":"private","next_at":"private"}),
        );
        assert_eq!(health["state"], "unknown");
        assert!(health["last_http_status"].is_null());
        assert!(health["retry_at"].is_null());
        let duplicate = evaluate(
            &json!([{"scope":"job","last_success_at":99},{"scope":"job"}]),
            100,
            10,
        );
        assert_eq!(duplicate["job"]["state"], "unknown");
    }
}
