//! Typed operator view of already-qualified local evidence. Never a dispatch permit.
use super::{LANES, lane_mode};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Ready,
    WaitingAutomatically,
    NeedsOperator,
    IntentionallyInactive,
    Unknown,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Target {
    Discovery,
    Preparation,
    Reconciliation,
    Submission,
    None,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Condition {
    FreshWorkRequired,
    RetryEligibility,
    PollOutcomeUnknown,
    AdmissionFenced,
    None,
    Unknown,
}

#[derive(Clone, Copy, Serialize)]
struct Step<'a> {
    state: State,
    target: Option<Target>,
    reason: &'a str,
    not_before: Option<i64>,
    operation_id: Option<i64>,
    condition: Condition,
}

impl<'a> Step<'a> {
    fn unknown(reason: &'a str) -> Self {
        Self {
            state: State::Unknown,
            target: None,
            reason,
            not_before: None,
            operation_id: None,
            condition: Condition::Unknown,
        }
    }
}
pub(super) fn unknown_step(reason: &str) -> Value {
    json!(Step::unknown(reason))
}

#[derive(Serialize)]
struct Intent<'a> {
    requested_mode: Option<&'a str>,
    effective_mode: Option<&'a str>,
    paused: Option<bool>,
    configuration: &'static str,
}

fn intent<'a>(status: &'a Value, lane: &str) -> Intent<'a> {
    let configured = status["configured_revision"].as_str();
    let effective = status["effective_runtime"]["revision"].as_str();
    let paused = status["paused"].as_bool();
    let lane_pause = status["lane_controls"][lane]["desired"]["paused"].as_bool();
    let requested_mode = status["capabilities"][lane]["mode"].as_str();
    let effective_mode = lane_mode(status, lane);
    Intent {
        requested_mode,
        effective_mode,
        paused: match (paused, lane_pause) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        },
        configuration: if status["effective_runtime"]["reload_blocked"] == true {
            "rejected"
        } else if let Some((desired, loaded)) = configured.zip(effective) {
            if desired == loaded {
                "loaded"
            } else {
                "pending"
            }
        } else if requested_mode
            .zip(effective_mode)
            .is_some_and(|(requested, effective)| requested != effective)
        {
            "pending"
        } else {
            "unknown"
        },
    }
}

fn open_admission(work: &Value, intent: &Intent<'_>) -> &'static str {
    if matches!(intent.effective_mode, Some("off" | "read_only")) {
        "not_applicable"
    } else if intent.paused == Some(true) {
        "fenced"
    } else {
        match work["admission"]["allowed"].as_bool() {
            Some(true) => "not_fenced",
            Some(false) => "fenced",
            None => "unknown",
        }
    }
}

fn independent_step<'a>(work: &'a Value, base: Step<'a>) -> Option<Step<'a>> {
    let finding = &work["intervention"];
    if let Some(operation_id) = finding["independent_preparation"].as_i64() {
        return Some(Step {
            state: State::Ready,
            target: Some(Target::Preparation),
            reason: "model_retry_eligible",
            not_before: None,
            operation_id: Some(operation_id),
            condition: Condition::None,
        });
    }
    if let Some(wait) = finding.get("candidate_wait") {
        let target = match wait["target"].as_str()? {
            "preparation" => Target::Preparation,
            "discovery" => Target::Discovery,
            _ => return None,
        };
        return Some(Step {
            state: State::WaitingAutomatically,
            target: Some(target),
            reason: wait["reason"].as_str()?,
            not_before: wait["not_before"].as_i64(),
            operation_id: wait["operation_id"].as_i64(),
            condition: Condition::RetryEligibility,
        });
    }
    if base
        .target
        .is_some_and(|target| matches!(target, Target::Reconciliation))
        && matches!(base.condition, Condition::PollOutcomeUnknown)
    {
        let observation = &finding["next_observation"];
        return Some(Step {
            state: State::WaitingAutomatically,
            not_before: observation["not_before"].as_i64(),
            operation_id: observation["operation_id"].as_i64(),
            condition: if observation["http_status"] == 404 {
                Condition::PollOutcomeUnknown
            } else {
                Condition::RetryEligibility
            },
            ..base
        });
    }
    None
}

fn from_intervention<'a>(work: &'a Value, admission: &str) -> Step<'a> {
    let finding = &work["intervention"];
    let reason = finding["reason"]
        .as_str()
        .unwrap_or("work_evidence_unavailable");
    let action = finding["next_action"].as_str().unwrap_or("");
    let (target, condition) = match action {
        _ if work["progress"] == "complete" || work["progress"] == "idle" => {
            (Target::Discovery, Condition::FreshWorkRequired)
        }
        "retry_model" if reason == "model_retry_eligible" => (Target::Preparation, Condition::None),
        "retry_model" | "await_model" | "await_model_admission" | "revalidate_launch_gate" => {
            (Target::Preparation, Condition::RetryEligibility)
        }
        _ if finding["next_observation"]["operation_id"].is_i64()
            || matches!(action, "read_job" | "read_receipt" | "await_reconciliation") =>
        {
            (
                Target::Reconciliation,
                if finding["resolution"] == "polling_not_guaranteed" {
                    Condition::PollOutcomeUnknown
                } else {
                    Condition::RetryEligibility
                },
            )
        }
        "await_retry_eligibility" | "await_answer_retry" | "await_effect" => {
            (Target::Submission, Condition::RetryEligibility)
        }
        "revalidate_request" | "revalidate_challenge" | "revalidate_assignment" => {
            (Target::Discovery, Condition::RetryEligibility)
        }
        _ if finding["candidate_wait"]["target"] == "discovery" => {
            (Target::Discovery, Condition::RetryEligibility)
        }
        _ if work["phase"] == "dispatching" => (Target::Submission, Condition::None),
        _ if matches!(work["phase"].as_str(), Some("preparing" | "generating")) => {
            (Target::Preparation, Condition::None)
        }
        _ => (Target::Discovery, Condition::None),
    };
    let status = finding["status"].as_str();
    if status == Some("operator_required") {
        return Step {
            state: State::NeedsOperator,
            target: Some(if admission == "fenced" {
                Target::Submission
            } else {
                Target::None
            }),
            condition: if admission == "fenced" {
                Condition::AdmissionFenced
            } else {
                Condition::None
            },
            ..Step::unknown(reason)
        };
    }
    if matches!(target, Target::Reconciliation)
        && matches!(condition, Condition::PollOutcomeUnknown)
    {
        let missing = finding
            .get("missing_observation")
            .unwrap_or(&finding["next_observation"]);
        return Step {
            target: Some(target),
            reason,
            not_before: missing["not_before"].as_i64(),
            operation_id: missing["operation_id"].as_i64(),
            condition,
            ..Step::unknown(reason)
        };
    }
    let scheduled = status == Some("automatic_recovery")
        && ((matches!(target, Target::Submission)
            && finding["next_at"].as_i64().is_some()
            && action == "await_retry_eligibility")
            || (matches!(target, Target::Reconciliation)
                && finding["next_observation"]["operation_id"]
                    .as_i64()
                    .is_some()));
    if matches!(admission, "fenced" | "unknown") && !scheduled {
        // Observing or preparing through a write fence is not an unattended submit path.
        return Step {
            target: Some(Target::Submission),
            condition: if admission == "fenced" {
                Condition::AdmissionFenced
            } else {
                Condition::Unknown
            },
            ..Step::unknown(
                work["admission"]["reason"]
                    .as_str()
                    .unwrap_or("admission_evidence_unavailable"),
            )
        };
    }
    match status {
        Some("automatic_recovery" | "none_required") => Step {
            state: if status == Some("automatic_recovery")
                || matches!(condition, Condition::FreshWorkRequired)
            {
                State::WaitingAutomatically
            } else {
                State::Ready
            },
            target: Some(target),
            reason,
            not_before: if matches!(
                action,
                "await_model_admission" | "await_model" | "await_effect"
            ) {
                None
            } else {
                finding["next_observation"]["not_before"]
                    .as_i64()
                    .or(finding["next_at"].as_i64())
            },
            operation_id: finding["candidate_wait"]["operation_id"]
                .as_i64()
                .or(finding["next_observation"]["operation_id"].as_i64())
                .or(work["operation_id"].as_i64()),
            condition,
        },
        _ => Step::unknown(reason),
    }
}

/// Attach to all three public views after local checks, before presentation.
/// The v1 operation and exit facts remain in their original fields.
pub(super) fn attach(report: &mut Value, status: &Value) {
    let process = &status["process_observation"];
    let observed = &report["intervention"]["controller"];
    let run_mode = process["run_mode"].as_str().unwrap_or("unknown");
    let owner = process["owner"].as_str().unwrap_or("unknown");
    let process_state = match (process["state"].as_str(), observed["reason"].as_str()) {
        (Some("stopped"), _) => "stopped",
        (_, Some("controller_stopped")) => "stopped",
        (_, Some("controller_stale")) => "stale",
        (Some("observed_match"), _) => "running",
        _ => "unknown",
    };
    let continuous =
        process_state == "running" && run_mode == "continuous" && observed["ready"] == true;
    report["intervention"]["controller"]["owner"] = json!(owner);
    report["intervention"]["controller"]["run_mode"] = json!(run_mode);
    report["intervention"]["controller"]["state"] = json!(process_state);

    let at = report["checked_at"].as_i64().unwrap_or(i64::MAX);
    for lane in LANES {
        let intent = intent(status, lane);
        let work = &report["work"][lane];
        let admission = open_admission(work, &intent);
        let component = &report["components"][lane];
        let mut base = from_intervention(work, admission);
        if work["intervention"]["reason"] == "model_retry_eligible" && admission == "not_fenced" {
            base.state = State::Ready;
            base.operation_id = work["model"]["operation_id"].as_i64();
        } else if matches!(base.target, Some(Target::Discovery))
            && matches!(base.condition, Condition::None)
            && component["state"] == "ok"
            && component["reasons"][0] == "fresh_work_available"
            && admission == "not_fenced"
        {
            base.state = State::Ready;
            base.reason = "fresh_work_available";
            base.target = Some(if lane == "mine" {
                Target::Submission
            } else {
                Target::Preparation
            });
            base.not_before = None;
        }
        let inactive = intent.paused == Some(true)
            || matches!(intent.effective_mode, Some("off" | "read_only"));
        let actionable = (continuous && !inactive)
            .then(|| independent_step(work, base))
            .flatten();
        if let Some(missing) = work.get("required_missing_observation")
            && matches!(base.state, State::Ready | State::WaitingAutomatically)
        {
            base = Step {
                target: Some(Target::Reconciliation),
                operation_id: missing["operation_id"].as_i64(),
                not_before: missing["not_before"].as_i64(),
                condition: Condition::PollOutcomeUnknown,
                ..Step::unknown("bound_reconciliation_pending")
            };
        }
        let continuation = if inactive {
            let reason = if intent.paused == Some(true) {
                "participation_paused"
            } else {
                "capability_not_active"
            };
            Step {
                state: State::IntentionallyInactive,
                target: Some(Target::None),
                condition: Condition::None,
                ..Step::unknown(reason)
            }
        } else if !continuous && matches!(base.state, State::Ready | State::WaitingAutomatically) {
            Step::unknown("continuing_owner_unverified")
        } else {
            base
        };
        let mut findings = Vec::new();
        if component["state"] != "ok"
            && component["state"] != "disabled"
            && let Some(reasons) = component["reasons"].as_array()
        {
            for reason in reasons.iter().filter_map(Value::as_str) {
                findings.push(
                    json!({"target":"lane","state":component["state"],"reason":reason,
                    "observed_at":component["observed_at"]}),
                );
            }
        }
        let read = &report["components"]["api"]["lanes"][lane];
        if read["state"] == "degraded" {
            findings.push(
                json!({"target":"discovery","dependency":"lane_discovery","state":"degraded",
                "reason":"read_failed","observed_at":read["observed_at"],
                "http_status":read["last_http_status"],"not_before":read["retry_at"]}),
            );
        }
        let finding = &work["intervention"];
        if let Some(observation) = finding
            .get("next_observation")
            .filter(|observation| observation.is_object())
        {
            findings.push(
                json!({"target":"reconciliation","state":observation["status"],
                "reason":finding["reason"],"dependency":observation["purpose"],
                "operation_id":observation["operation_id"],"http_status":observation["http_status"],
                "not_before":observation["not_before"]}),
            );
        }
        if let Some(missing) = work.get("required_missing_observation") {
            findings.push(json!({"target":"reconciliation","state":"unknown",
                "reason":"bound_reconciliation_pending","dependency":missing["purpose"],
                "operation_id":missing["operation_id"],"binding_revision":missing["binding_revision"],
                "http_status":404,"not_before":missing["not_before"]}));
        }
        if let Some(count) = work["assessment"]["exclusions"]["model_budget_exhausted"]
            .as_u64()
            .filter(|n| *n > 0)
            && work["intervention"]["observation_fresh"] == true
            && work["assessment"]["capped_work_proven"] == true
        {
            findings.push(json!({"target":"current_inventory","state":"exhausted","reason":"model_attempt_budget_exhausted",
                "count":count,"observed_at":work["assessment"]["observed_at"],"valid_until":work["assessment"]["valid_until"]}));
        }
        if let Some(wait) = work["assessment"].get("candidate_wait").filter(|wait| {
            work["intervention"]["observation_fresh"] == true
                && wait["not_before"].as_i64().is_some_and(|floor| floor > at)
        }) {
            findings.push(json!({"target":wait["target"],"state":"waiting","reason":wait["reason"],
                "not_before":wait["not_before"],"operation_id":wait["operation_id"],"dependency":wait["dependency"]}));
        }
        if admission == "fenced"
            && let Some(reason) = work["admission"]["reason"].as_str()
        {
            findings.push(
                json!({"target":"submission","state":"fenced","reason":reason,
                "not_before":work["admission"]["not_before"]}),
            );
        }
        let serialized = (
            json!(intent),
            json!(continuation),
            json!(actionable),
            json!({"items":findings,"truncated":false}),
        );
        let work = &mut report["work"][lane];
        let observation_fresh = work["intervention"]["observation_fresh"] == true;
        if lane != "judge" {
            work["assessment"] = status["lane_participation"][lane]["assessment"].clone();
        }
        {
            let assessment = &mut work["assessment"];
            if !assessment.is_object() {
                *assessment = json!({});
            }
            let completeness = if assessment["observed_at"].as_i64().is_none()
                || assessment["valid_until"].as_i64().is_none()
            {
                "unavailable"
            } else if assessment["valid_until"]
                .as_i64()
                .is_some_and(|until| until <= at)
            {
                "expired"
            } else if !observation_fresh {
                "stale"
            } else {
                assessment["completeness"].as_str().unwrap_or("unavailable")
            };
            let current = matches!(
                completeness,
                "complete" | "bounded_partial" | "single_challenge"
            );
            assessment["completeness"] = json!(completeness);
            if !current {
                for key in [
                    "observed_opportunities",
                    "eligible_candidates",
                    "exclusions",
                    "locally_judgeable",
                    "locally_eligible",
                    "exclusion_reason",
                    "capped_work_proven",
                    "candidate_wait",
                ] {
                    assessment[key] = Value::Null;
                }
            }
        }
        work["intent"] = serialized.0;
        work["admission"]["state"] = json!(admission);
        work["continuation"] = serialized.1;
        work["automatic_step"] = serialized.2;
        work["findings"] = serialized.3;
    }
    qualify_unattended(report);
}

pub(super) fn qualify_unattended(report: &mut Value) {
    let controller = &report["intervention"]["controller"];
    if report["intervention"]["unattended"] == true
        && (controller["state"] != "running"
            || controller["run_mode"] != "continuous"
            || controller["ready"] != true
            || LANES.iter().any(|lane| {
                let work = &report["work"][*lane];
                work["continuation"]["state"] == "unknown"
                    || work["required_missing_observation"].is_object()
            }))
    {
        report["intervention"]["unattended"] = Value::Null;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recent_journal_is_not_a_continuing_controller() {
        let (_, options, status) = super::super::tests::fixture();
        for (owner, mode, expected) in [
            (
                "managed",
                "continuous",
                ("waiting_automatically", Some(true)),
            ),
            ("foreground", "once", ("unknown", None)),
            ("unknown", "unknown", ("unknown", None)),
        ] {
            let mut status = status.clone();
            status["process_observation"] = if owner == "unknown" {
                json!({"state":"unavailable","reason":"snapshot_rollover"})
            } else {
                json!({"state":"observed_match","owner":owner,"run_mode":mode})
            };
            super::super::enrich_status(&mut status, options, 10000);
            assert_eq!(status["work"]["judge"]["continuation"]["state"], expected.0);
            assert_eq!(status["intervention"]["unattended"].as_bool(), expected.1);
            assert_eq!(
                status["work"]["judge"]["intervention"]["status"],
                "none_required"
            );
            let cleared = status["intervention"]["unattended"].clone();
            super::super::qualify_doctor(
                &mut status,
                &json!({"restoration":{"verified":true,"runtime":"restored"}}),
            );
            assert_eq!(
                status["intervention"]["unattended"], cleared,
                "a restoration receipt is not live controller attribution"
            );
        }
    }
}
