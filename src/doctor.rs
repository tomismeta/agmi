//! Local diagnosis and guarded refusal recovery / legacy identity normalization.
use crate::{config::Config, health, lifecycle, store};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) const DIAGNOSTIC_CHILD_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const REPAIR_ARRAYS: [&str; 4] = ["eligible", "ineligible", "applied", "skipped"];
// The 15 KiB compact target, repair metadata, and CLI envelope fit in this reserve.
const COMPACT_BODY_RESERVE: usize = 128 * 1024;
// repair_row emits six fixed keys, a signed 64-bit ID, two booleans, and fixed
// ASCII enums (no escaped text). 256 bytes covers the largest row and its comma.
const REPAIR_ROW_BYTES: usize = 256;
const REPAIR_ROW_BUDGET: usize = (DIAGNOSTIC_CHILD_LIMIT - COMPACT_BODY_RESERVE) / REPAIR_ROW_BYTES;

pub(crate) struct LegacyRepairArrays {
    arrays: [Value; REPAIR_ARRAYS.len()],
    details_truncated: Value,
}

impl LegacyRepairArrays {
    pub(crate) fn restore(self, report: &mut Value) {
        let repairs = &mut report["repairs"];
        for (key, array) in REPAIR_ARRAYS.into_iter().zip(self.arrays) {
            repairs[key] = array;
        }
        repairs["details_truncated"] = self.details_truncated;
    }
}

/// Move the bounded compatibility receipt outside ordinary compact projection.
/// Only the repair constructor and the preflight failure constructor supply it.
pub(crate) fn take_legacy_repair_arrays(report: &mut Value) -> Option<LegacyRepairArrays> {
    if report["repair_requested"] != true {
        return None;
    }
    let repairs = &mut report["repairs"];
    Some(LegacyRepairArrays {
        arrays: REPAIR_ARRAYS.map(|key| repairs[key].take()),
        details_truncated: repairs["details_truncated"].take(),
    })
}

/// Compact ordinary diagnostics without shortening the legacy repair receipt.
pub fn compact_report(report: &mut Value) {
    let legacy = take_legacy_repair_arrays(report);
    health::compact_diagnostics(report);
    if let Some(legacy) = legacy {
        legacy.restore(report);
    }
}

pub fn failed_repairs(code: &'static str, repair: bool) -> Value {
    json!({"eligible":[],"ineligible":[],"applied":[],"skipped":[],"failure":code,
        "counts":{"eligible":null,"ineligible":null,"applied":null,"skipped":null},
        "preview":"unavailable","execution":if repair {"not_started"} else {"not_requested"},
        "details_truncated":false,
        "restoration":{"manager_action":"none","runtime":"unchanged","verified":null}})
}

pub(crate) fn known_repair_reason(reason: &str) -> Option<&str> {
    matches!(
        reason,
        "eligible"
            | "not_unknown"
            | "retry_after_pending"
            | "acceptance_or_linkage_evidence"
            | "existing_resolution"
            | "retained_refusal_not_proven"
            | "historical_refusal_retired"
            | "legacy_identity_evidence_normalized"
            | "not_legacy_identity_failure"
            | "already_resolved"
            | "earlier_repair_failed"
            | "repair_report_invalid"
            | "repair_action_failed"
            | "repair_runtime_unavailable"
            | "repair_runtime_stop_failed"
            | "repair_runtime_restore_failed"
            | "repair_interrupted"
            | "doctor_recovery_unavailable"
            | "doctor_account_unavailable"
            | "refusal_recovery_schema"
            | "refusal_recovery_conflict"
            | "refusal_recovery_failed"
            | "identity_evidence_changed"
            | "identity_normalization_failed"
            | "refusal_recovery_ineligible"
            | "repair_receipt_too_large"
    )
    .then_some(reason)
}

fn repair_row(row: &Value) -> Value {
    let mut projected = json!({
        "kind":row["kind"].as_str().filter(|kind|
            matches!(*kind, "answer" | "judge" | "mine" | "identity")).unwrap_or("unknown"),
        "classification":row["classification"].as_str().filter(|class| matches!(*class,
            "legacy_429_policy_refusal" | "submit_429_pre_enqueue" | "submit_503_halt_middleware"
            | "legacy_identity_evidence_normalization")),
        "eligible":row["eligible"].as_bool(),
        "applied":row["applied"].as_bool(),
        "reason":row["reason"].as_str().and_then(known_repair_reason).unwrap_or("unavailable"),
    });
    if let Some(id) = row["operation_id"].as_i64() {
        projected["operation_id"] = json!(id);
    }
    projected
}

fn rows<'a>(repairs: &'a Value, key: &str) -> &'a [Value] {
    repairs[key].as_array().map_or(&[], Vec::as_slice)
}

fn finish_repairs(
    mut preview: Value,
    repair: bool,
    execute: impl FnOnce(&Value) -> anyhow::Result<Value>,
) -> Value {
    let eligible = rows(&preview, "eligible").len();
    let ineligible = rows(&preview, "ineligible").len();
    // The frozen preview has one result slot per eligible row, even when
    // runtime preflight fails. Reserve all those slots before invoking it.
    let oversized =
        repair && eligible.saturating_mul(2).saturating_add(ineligible) > REPAIR_ROW_BUDGET;
    preview["preview"] = json!("complete");
    preview["execution"] = json!(if !repair {
        "not_requested"
    } else if eligible == 0 && !oversized {
        "not_needed"
    } else {
        "not_started"
    });
    preview["details_truncated"] = json!(oversized);
    if oversized {
        preview["failure"] = json!("repair_receipt_too_large");
        for key in REPAIR_ARRAYS {
            preview[key] = Value::Null;
        }
    } else if repair && eligible != 0 {
        let actual = match execute(&preview) {
            Ok(mut report) => Some(report["repairs"].take()),
            Err(error) => {
                let recovery = recovery_code(&error);
                if let Ok(failure) = error.downcast::<lifecycle::RepairRuntimeError>() {
                    preview["failure"] = json!(if failure.code == "repair_action_failed" {
                        recovery
                    } else {
                        failure.code
                    });
                    preview["restoration"] = failure.restoration;
                    failure.report.and_then(|mut report| {
                        report["repairs"]
                            .is_object()
                            .then(|| report["repairs"].take())
                    })
                } else {
                    preview["failure"] = json!(recovery);
                    None
                }
            }
        };
        if let Some(mut actual) = actual {
            for key in ["applied", "skipped", "execution", "restoration"] {
                preview[key] = actual[key].take();
            }
            if preview["failure"].is_null() {
                preview["failure"] = actual["failure"].take();
            }
        } else {
            let reason = preview["failure"]
                .as_str()
                .unwrap_or("doctor_recovery_unavailable");
            preview["skipped"] = Value::Array(
                rows(&preview, "eligible")
                    .iter()
                    .map(|row| store::skipped_doctor_repair(row, reason))
                    .collect(),
            );
        }
    }
    preview["counts"] = json!({"eligible":eligible,"ineligible":ineligible,
        "applied":rows(&preview,"applied").len(),"skipped":rows(&preview,"skipped").len()});
    preview
        .as_object_mut()
        .expect("store repair preview object")
        .remove("config_revision");
    for key in REPAIR_ARRAYS {
        for row in preview[key].as_array_mut().into_iter().flatten() {
            *row = repair_row(row);
        }
    }
    preview
}

fn recovery_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<store::RefusalRecoveryError>()
        .map_or("doctor_recovery_unavailable", |error| error.0)
}

fn unknown_report(reason: &str) -> Value {
    json!({"components":health::unknown_components(),
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
    let repairs = match store::doctor_repairs(path, None) {
        Ok(preview) => finish_repairs(preview, repair, |preview| {
            lifecycle::with_repair_runtime(path, || {
                let mut report = json!({});
                report["repairs"] = store::doctor_repairs(path, Some(preview))?;
                Ok(report)
            })
        }),
        Err(error) => failed_repairs(recovery_code(&error), repair),
    };
    // Refresh after repair/restoration. A changed or invalid configuration is not
    // silently diagnosed using the old account's state.
    let mut report = match Config::load_metadata(path) {
        Ok(current) => health::check(path, &current, health::Options::default())
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
            for key in REPAIR_ARRAYS {
                assert_eq!(report["repairs"]["counts"][key], Value::Null);
            }
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

    #[test]
    fn repair_arrays_outlive_the_ordinary_compact_budget() {
        let candidates: Vec<_> = (1..=180)
            .map(|id| {
                json!({"operation_id":id,"kind":"judge","eligible":true,"applied":false,
                "classification":"legacy_429_policy_refusal","reason":"eligible",
                "preview_token":"private-token"})
            })
            .collect();
        let mut preview = failed_repairs("unused", true);
        preview["failure"] = Value::Null;
        preview["eligible"] = Value::Array(candidates);
        preview["ineligible"] = json!([{"operation_id":181,"kind":"mine","eligible":false,
            "reason":"retained_refusal_not_proven"}]);
        let mut report = unknown_report("local_evidence_unavailable");
        report["repair_requested"] = json!(true);
        report["repairs"] = finish_repairs(preview, true, |preview| {
            let (skipped, applied) = rows(preview, "eligible").split_at(7);
            let applied: Vec<_> = applied.iter().map(|row| {
                json!({"operation_id":row["operation_id"],"kind":"judge","eligible":false,"applied":true,
                    "classification":"legacy_429_policy_refusal","reason":"historical_refusal_retired"})
            }).collect();
            let skipped: Vec<_> = skipped
                .iter()
                .map(|row| store::skipped_doctor_repair(row, "refusal_recovery_conflict"))
                .collect();
            Ok(
                json!({"repairs":{"applied":applied,"skipped":skipped,"failure":null,
                "execution":"complete","restoration":{"manager_action":"runtime_stop","runtime":"restored","verified":true}}}),
            )
        });
        compact_report(&mut report);
        for (key, count) in REPAIR_ARRAYS.into_iter().zip([180, 1, 173, 7]) {
            assert_eq!(rows(&report["repairs"], key).len(), count);
            assert_eq!(
                report["repairs"]["counts"][key].as_u64(),
                Some(count as u64)
            );
        }
        assert_eq!(report["repairs"]["details_truncated"], false);
        let serialized = report.to_string();
        assert!((15 * 1024..DIAGNOSTIC_CHILD_LIMIT).contains(&serialized.len()));
        assert!(!serialized.contains("private-token"));
    }

    #[test]
    fn oversized_receipt_refuses_before_runtime_or_store_execution() {
        let count = REPAIR_ROW_BUDGET / 2 + 1;
        let mut preview = failed_repairs("unused", true);
        preview["eligible"] = Value::Array(vec![Value::Null; count]);
        let repairs = finish_repairs(preview, true, |_| {
            panic!("runtime entered for oversized receipt")
        });
        assert_eq!(repairs["failure"], "repair_receipt_too_large");
        assert_eq!(repairs["execution"], "not_started");
        assert_eq!(repairs["restoration"]["manager_action"], "none");
        assert_eq!(repairs["counts"]["eligible"], count as u64);
        assert_eq!(repairs["counts"]["applied"], 0);
        assert_eq!(repairs["details_truncated"], true);
        assert!(REPAIR_ARRAYS.iter().all(|key| repairs[*key].is_null()));
    }
}
