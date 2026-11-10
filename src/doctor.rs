//! Local diagnosis and orchestration of existing, token-fenced refusal recovery.
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
    json!({"contract_version":1,"components":health::unknown_components(),
        "healthy":false,"attention_required":true,"issues":[reason],
        "warnings":[],"initialized":null,"paused":null,"evidence":"local_only",
        "work":health::unknown_work(reason),"intervention":health::unknown_intervention(reason)})
}

fn qualify_restoration(report: &mut Value, repairs: &Value) {
    if repairs["restoration"]["verified"] != true
        || repairs["restoration"]["runtime"] != "restored"
        || report["intervention"]["controller"]["reason"] != "controller_stopped"
    {
        return;
    }
    // A verified new process supersedes the old stopped marker, but is not yet
    // fresh participation evidence. Never suggest starting a second controller.
    let reason = "runtime_restored_observation_pending";
    report["intervention"] = health::unknown_intervention(reason);
    let paused = report["paused"] == true;
    let inactive = ["answer", "judge", "mine"].iter().all(|name| {
        matches!(
            report["effective_capabilities"][name].as_str(),
            Some("off" | "read_only")
        )
    });
    for name in ["answer", "judge", "mine"] {
        if report["work"][name]["intervention"]["reason"] == "controller_stopped" {
            report["work"][name]["progress"] = json!("waiting");
            report["work"][name]["intervention"] = json!({"status":"undetermined","reason":reason,
                "next_action":"inspect_local_evidence","next_at":null,"evidence_fresh":null,
                "observation_fresh":null,"evidence":"restored_process_not_yet_observed_by_controller"});
            if paused && report["effective_capabilities"][name] == "active" {
                report["work"][name]["progress"] = json!("blocked");
                report["work"][name]["intervention"]["status"] = json!("operator_required");
                report["work"][name]["intervention"]["reason"] = json!("admission_paused");
                report["work"][name]["intervention"]["next_action"] = json!("resume");
            }
        }
        report["intervention"]["lanes"][name] =
            report["work"][name]["intervention"]["status"].clone();
        if report["work"][name]["intervention"]["status"] == "operator_required" {
            for field in ["status", "reason", "next_action", "next_at"] {
                report["intervention"][field] = report["work"][name]["intervention"][field].clone();
            }
        }
    }
    if paused || inactive || report["intervention"]["status"] == "operator_required" {
        report["intervention"]["unattended"] = json!(false);
    }
}

/// No network/model calls. Repair may restore a previously running managed service;
/// that service resumes its existing participation policy, not a doctor replay.
pub fn check(path: &Path, repair: bool) -> Value {
    let mut repairs = match store::doctor_refusals(path, None) {
        Ok(preview) => preview,
        Err(error) => failed_repairs(recovery_code(&error)),
    };
    let eligible = repairs["eligible"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty());
    if repair && eligible && repairs["failure"].is_null() {
        let revision = repairs["config_revision"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        match lifecycle::with_repair_runtime(path, || {
            Ok(json!({"repairs":store::doctor_refusals(path, Some(&revision))?}))
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
    report["repair_outcome"] = json!(if !repairs["failure"].is_null() {
        "failed"
    } else if !repair {
        "not_requested"
    } else if repairs["applied"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        "applied"
    } else {
        "no_eligible_repairs"
    });
    report["effects"] = json!({"direct_network_requests":false,"direct_model_calls":false,
        "unknown_submissions_replayed":false,"model_attempts_abandoned":false,
        "configuration_changed":false,"pause_state_changed":false,
        "restored_runtime_may_participate":repairs["restoration"]["manager_action"]
            .as_str().is_some_and(|action| action != "none")});
    qualify_restoration(&mut report, &repairs);
    if !repairs["failure"].is_null() {
        report["intervention"] = json!({"status":"operator_required","unattended":false,
            "reason":"doctor_repair_unavailable","next_action":"inspect_repair_failure","next_at":null,
            "evidence":"local_only"});
        report["attention_required"] = json!(true);
    }
    report["repairs"] = repairs;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_process_does_not_invent_readiness_or_suggest_another_start() {
        let repairs = json!({"restoration":{"verified":true,"runtime":"restored"}});
        let mut report = json!({"healthy":false,"intervention":{"status":"operator_required",
            "controller":{"reason":"controller_stopped"}},"work":{"answer":{"phase":"stopped",
            "intervention":{"status":"operator_required","reason":"controller_stopped","next_action":"start_controller"}},
            "judge":{"intervention":{"status":"none_required","reason":"capability_off"}},
            "mine":{"intervention":{"status":"operator_required","reason":"controller_stopped"}}}});
        qualify_restoration(&mut report, &repairs);
        assert_eq!(report["intervention"]["status"], "undetermined");
        assert_eq!(report["intervention"]["unattended"], Value::Null);
        assert_eq!(
            report["work"]["answer"]["intervention"]["next_action"],
            "inspect_local_evidence"
        );
        assert_eq!(
            report["work"]["judge"]["intervention"]["status"],
            "none_required"
        );
        assert_eq!(report["healthy"], false);
        report["intervention"] = json!({"status":"operator_required",
            "controller":{"reason":"identity_mismatch"}});
        qualify_restoration(&mut report, &repairs);
        assert_eq!(report["intervention"]["status"], "operator_required");
        report["paused"] = json!(true);
        report["effective_capabilities"] = json!({"answer":"active","judge":"off","mine":"off"});
        report["intervention"]["controller"]["reason"] = json!("controller_stopped");
        report["work"]["answer"]["intervention"]["reason"] = json!("controller_stopped");
        qualify_restoration(&mut report, &repairs);
        assert_eq!(report["intervention"]["status"], "operator_required");
        assert_eq!(report["intervention"]["unattended"], false);
        assert_eq!(report["intervention"]["controller"]["ready"], Value::Null);
        assert_eq!(
            report["work"]["answer"]["intervention"]["next_action"],
            "resume"
        );
    }
}
