//! Local diagnosis and guarded refusal recovery / legacy identity normalization.
use crate::{config::Config, health, lifecycle, store};
use serde_json::{Value, json};
use std::path::Path;

fn failed_repairs(code: &'static str) -> Value {
    json!({"eligible":[],"ineligible":[],"applied":[],"skipped":[],"failure":code,
        "restoration":{"manager_action":"none","runtime":"unchanged"}})
}

fn recovery_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<store::RefusalRecoveryError>()
        .map_or("doctor_recovery_unavailable", |error| error.0)
}

fn unknown_report(reason: &str) -> Value {
    json!({"contract_version":2,"components":health::unknown_components(),
        "healthy":false,"attention_required":true,"issues":[reason],
        "warnings":[],"initialized":null,"paused":null,"evidence":"local_only",
        "assessment_scope":{"evidence":"local_only","state_filesystem":"not_assessed"},
        "operational":{"status":"unknown","issues":[reason]},
        "risk":health::unknown_risk(),
        "work":health::unknown_work(reason),"intervention":health::unknown_intervention(reason)})
}

/// No network/model calls. Repair may restore a previously running managed service;
/// that service resumes its existing participation policy, not a doctor replay.
pub fn check(path: &Path, repair: bool) -> Value {
    let mut repairs = match store::doctor_repairs(path, None) {
        Ok(preview) => preview,
        Err(error) => failed_repairs(recovery_code(&error)),
    };
    let eligible = repairs["eligible"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty());
    if repair && eligible && repairs["failure"].is_null() {
        match lifecycle::with_repair_runtime(path, || {
            Ok(json!({"repairs":store::doctor_repairs(path, Some(&repairs))?}))
        }) {
            Ok(mut report) => repairs = report["repairs"].take(),
            Err(error) => {
                if let Some(failure) = error.downcast_ref::<lifecycle::RepairRuntimeError>() {
                    if let Some(report) = &failure.report {
                        repairs = report["repairs"].clone();
                    }
                    repairs["failure"] = json!(if failure.code == "repair_action_failed" {
                        recovery_code(&error)
                    } else {
                        failure.code
                    });
                    repairs["restoration"] = failure.restoration.clone();
                } else {
                    repairs["failure"] = json!(recovery_code(&error));
                }
            }
        }
    }
    // Refresh after repair/restoration. A changed or invalid configuration is not
    // silently diagnosed using the old account's state.
    let mut report = match Config::load_metadata(path) {
        Ok(current) => health::check(&current, health::Options::default())
            .unwrap_or_else(|_| unknown_report("local_evidence_unavailable")),
        Err(_) => unknown_report("config_changed_during_doctor"),
    };
    report["repair_requested"] = json!(repair);
    report["repair_outcome"] = json!(if !repair {
        "not_requested"
    } else if !repairs["failure"].is_null() {
        "failed"
    } else if repairs["applied"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        "applied"
    } else if repairs["skipped"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        "skipped"
    } else {
        "no_eligible_repairs"
    });
    report["effects"] = json!({"direct_network_requests":false,"direct_model_calls":false,
        "unknown_submissions_replayed":false,"model_attempts_abandoned":false,
        "configuration_changed":false,"pause_state_changed":false,
        "identity_verified":false,"read_deadlines_reset":false,
        "restored_runtime_may_participate":repairs["restoration"]["manager_action"]
            .as_str().is_some_and(|action| action != "none")});
    health::qualify_doctor(&mut report, &repairs);
    repairs["counts"] = json!({
        "eligible":repairs["eligible"].as_array().map_or(0, Vec::len),
        "ineligible":repairs["ineligible"].as_array().map_or(0, Vec::len),
        "applied":repairs["applied"].as_array().map_or(0, Vec::len),
        "skipped":repairs["skipped"].as_array().map_or(0, Vec::len),
    });
    report["repairs"] = repairs;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_scan_without_requested_repair_retains_failure_and_diagnostic_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-config.toml");
        for requested in [false, true] {
            let report = check(&path, requested);
            assert_eq!(
                report["repair_outcome"],
                if requested { "failed" } else { "not_requested" }
            );
            assert!(report["repairs"]["failure"].is_string());
            assert_eq!(report["intervention"]["status"], "operator_required");
            assert_eq!(report["intervention"]["unattended"], false);
            assert_eq!(
                report["intervention"]["next_action"],
                "inspect_repair_failure"
            );
            assert_eq!(report["intervention"]["controller"]["ready"], Value::Null);
            for lane in crate::capability::LaneId::NAMES {
                assert_eq!(report["intervention"]["lanes"][lane], "undetermined");
                assert_eq!(
                    report["work"][lane]["intervention"]["status"],
                    "undetermined"
                );
            }
            assert_eq!(report["issues"], report["operational"]["issues"]);
            assert_eq!(report["risk"]["unresolved_effects"], Value::Null);
        }
        assert!(!path.exists());
    }
}
