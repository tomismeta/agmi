//! Pure interpretation of canonical local work evidence; never admission authority.
use super::{Options, WorkTiming, fresh};
use serde_json::{Value, json};

const LANES: [&str; 3] = ["answer", "judge", "mine"];

struct Finding<'a> {
    progress: &'static str,
    status: &'static str,
    reason: &'a str,
    action: &'a str,
    next_at: Option<i64>,
}

impl<'a> Finding<'a> {
    fn unknown(reason: &'a str) -> Self {
        Self {
            progress: "waiting",
            status: "undetermined",
            reason,
            action: "inspect_local_evidence",
            next_at: None,
        }
    }

    fn blocked(reason: &'a str, action: &'a str) -> Self {
        Self {
            progress: "blocked",
            status: "operator_required",
            reason,
            action,
            next_at: None,
        }
    }

    fn automatic(reason: &'a str, action: &'a str, next_at: Option<i64>) -> Self {
        Self {
            progress: "waiting",
            status: "automatic_recovery",
            reason,
            action,
            next_at,
        }
    }

    fn value(&self, observed: Option<i64>, evidence_fresh: Option<bool>) -> Value {
        json!({"status":self.status,"reason":self.reason,"next_action":self.action,
            "next_at":self.next_at,"observed_at":observed,"evidence_fresh":evidence_fresh,
            "evidence":"local_only_not_a_success_guarantee"})
    }
}

pub(super) fn unknown_work(reason: &str) -> Value {
    let finding = Finding::unknown(reason);
    let mut work = json!({});
    for name in LANES {
        work[name] = json!({"progress":finding.progress,"intervention":finding.value(None, None)});
    }
    work
}

pub(super) fn unknown(reason: &str) -> Value {
    let finding = Finding::unknown(reason);
    let mut result = finding.value(None, None);
    result["unattended"] = Value::Null;
    result["controller"] = json!({"ready":null,"reason":reason,"observed_at":null,
        "evidence_fresh":null,"process_identity":"unverified"});
    result["lanes"] = json!({"answer":"undetermined","judge":"undetermined","mine":"undetermined"});
    result
}

fn timestamp(value: &Value) -> Option<i64> {
    value.as_i64().filter(|time| *time >= 0)
}

fn read<'a>(status: &'a Value, name: &str, work: &Value, purpose: &str) -> Option<&'a Value> {
    match purpose {
        "identity" => super::api::identity(status),
        "job" | "receipt" => {
            super::api::bound(status, work).filter(|row| row["purpose"] == purpose)
        }
        "assignment" => super::api::keyed(status, &work["read_key"])
            .filter(|row| row["purpose"] == "assignment"),
        _ => super::api::discovery(status, name),
    }
}

pub(super) fn read_failed(row: &Value) -> bool {
    timestamp(&row["last_failure_at"]).is_some_and(|failure| {
        timestamp(&row["last_success_at"]).is_none_or(|success| {
            failure > success
                || (failure == success
                    && (!row["failure_category"].is_null()
                        || row["failures"].as_u64().unwrap_or(0) > 0))
        })
    })
}

fn read_auth_failed(row: &Value, at: i64, stale: u64) -> bool {
    read_failed(row)
        && fresh(timestamp(&row["last_failure_at"]), at, stale)
        && matches!(row["status"].as_u64(), Some(401 | 403))
}

fn mode<'a>(status: &'a Value, name: &str) -> Option<&'a str> {
    super::lane_mode(status, name)
}

fn controller(status: &Value, at: i64, stale: Option<u64>) -> (Option<bool>, Finding<'static>) {
    if status["initialized"] == false {
        return (Some(false), core_reason("not_initialized"));
    }
    if status["initialized"] != true {
        return (None, core_reason("local_evidence_unavailable"));
    }
    if status["migration"]["pending"] == true {
        return (Some(false), core_reason("migration_pending"));
    }
    for (blocked, reason) in [
        (
            status["identity_matches_config"] == false,
            "identity_mismatch",
        ),
        (
            status["network_routing"]["matches_config"] == false,
            "api_routing_mismatch",
        ),
        (
            status["effective_runtime"]["reload_blocked"] == true,
            "config_reload_rejected",
        ),
        (status["controller_stopped"] == true, "controller_stopped"),
    ] {
        if blocked {
            return (Some(false), core_reason(reason));
        }
    }
    let observed = timestamp(&status["effective_runtime"]["observed_at"]);
    if observed.is_some_and(|time| time > at) {
        return (None, core_reason("clock_regressed"));
    }
    let Some(stale) = stale else {
        return (None, core_reason("effective_policy_unavailable"));
    };
    if observed.is_none() {
        return (None, core_reason("controller_unobserved"));
    }
    if !fresh(observed, at, stale) {
        return (None, core_reason("controller_stale"));
    }
    if status["identity_matches_config"].as_bool().is_none()
        || status["paused"].as_bool().is_none()
        || status["controller_stopped"].as_bool().is_none()
    {
        return (None, core_reason("controller_evidence_unavailable"));
    }
    (Some(true), core_reason("controller_recent"))
}

/// Store decides how much must clear and which rows count. Health only assesses
/// whether those exact blockers have a bound recovery path, never its success.
fn release_path<'a>(
    status: &'a Value,
    name: &str,
    detail: &'a Value,
    at: i64,
    stale: u64,
    timing: &WorkTiming,
) -> Finding<'a> {
    let Some(needed) = detail["required_release"]
        .as_u64()
        .filter(|needed| *needed > 0)
    else {
        return Finding::unknown("release_evidence_unavailable");
    };
    let Some(ids) = detail["blocker_ids"].as_array() else {
        return Finding::unknown("release_evidence_unavailable");
    };
    let Some(rows) = status["pending_work"].as_array() else {
        return Finding::unknown("reconciliation_evidence_unavailable");
    };
    if !matches!(detail["scope"].as_str(), Some("lane" | "account")) {
        return Finding::unknown("release_evidence_unavailable");
    }
    let mut automatic = 0_u64;
    let mut uncertain = 0_u64;
    let mut authentication_blocked = false;
    let mut next: Option<i64> = None;
    for id in ids {
        let Some(row) = rows.iter().find(|row| row["operation_id"] == *id) else {
            uncertain += 1;
            continue;
        };
        if detail["scope"] == "lane" && row["kind"] != name {
            return Finding::unknown("release_evidence_unavailable");
        }
        if ["created_at", "updated_at"]
            .iter()
            .any(|field| timestamp(&row[*field]).is_some_and(|time| time > at))
        {
            uncertain += 1;
            continue;
        }
        let bound = matches!(row["read_key"]["purpose"].as_str(), Some("job" | "receipt"))
            && row["binding_revision"].as_i64().is_some()
            && row["read_key"]["owner"] == row["kind"]
            && row["read_key"]["resource"].as_str().is_some();
        let dependency = super::api::bound(status, row);
        if bound && dependency.is_none() && status["reads_truncated"] == true {
            uncertain += 1;
            continue;
        }
        if let Some(dependency) = dependency
            && read_failed(dependency)
            && matches!(dependency["status"].as_u64(), Some(401 | 403))
        {
            if read_auth_failed(dependency, at, stale) {
                authentication_blocked = true;
            } else {
                uncertain += 1;
            }
            continue;
        }
        // Captured HTTP deadline, not the candidate lane's timeout, determines
        // whether another lane still has a live dispatch.
        let dispatching = row["state"] == "dispatching"
            && row["http_deadline"]
                .as_i64()
                .is_some_and(|deadline| at <= deadline.saturating_add(timing.shutdown as i64));
        if bound || dispatching {
            automatic += 1;
            let deadline = [
                timestamp(&row["next_at"]),
                timestamp(&row["retry_not_before"]),
                dependency.and_then(|read| timestamp(&read["next_at"])),
            ]
            .into_iter()
            .flatten()
            .max();
            next = match (next, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        } else if row.get("read_key").is_none() || row["state"] == "dispatching" {
            uncertain += 1;
        }
    }
    if automatic >= needed {
        Finding::automatic("bound_reconciliation_pending", "await_reconciliation", next)
    } else if automatic + uncertain >= needed || detail["blocker_ids_truncated"] == true {
        Finding::unknown("reconciliation_evidence_unavailable")
    } else if authentication_blocked {
        Finding::blocked("reconciliation_authentication_failed", "review_credentials")
    } else {
        Finding::blocked(
            if detail["scope"] == "account" {
                "unbound_uncertainty"
            } else {
                "no_automatic_capacity_release"
            },
            "inspect_operations",
        )
    }
}

fn blocker<'a>(
    status: &'a Value,
    name: &str,
    _work: &'a Value,
    detail: &'a Value,
    at: i64,
    stale: u64,
    timing: &WorkTiming,
) -> Option<Finding<'a>> {
    let reason = detail["reason"].as_str()?;
    Some(match reason {
        "lane_unresolved_capacity" | "account_uncertainty" => {
            release_path(status, name, detail, at, stale, timing)
        }
        "manual_authorization_required" => {
            let recovery = release_path(status, name, detail, at, stale, timing);
            if recovery.status == "automatic_recovery" {
                recovery
            } else {
                Finding::blocked(reason, "authorize")
            }
        }
        "account_uncertainty_grace"
        | "shared_server_restriction"
        | "retained_legacy_floor"
        | "operation_retry_minimum"
        | "operation_backoff"
        | "uncertain_answer_retry_delay" => {
            if let Some(next) = timestamp(&detail["not_before"]).or(timestamp(&detail["next_at"])) {
                Finding::automatic(reason, "await_retry_eligibility", Some(next))
            } else {
                Finding::unknown("retry_deadline_unavailable")
            }
        }
        "uncertain_retry_disabled" | "answer_attempt_budget_exhausted" => {
            Finding::blocked(reason, "review_participation_policy")
        }
        "generation_changed" => Finding::automatic(reason, "discard_unsent", None),
        "effect_in_flight" => {
            Finding::automatic(reason, "await_effect", timestamp(&detail["not_before"]))
        }
        _ => return None,
    })
}

fn lane<'a>(
    status: &'a Value,
    name: &str,
    at: i64,
    stale: u64,
    timing: &WorkTiming,
) -> Finding<'a> {
    let work = &status["work"][name];
    let phase = work["phase"].as_str();
    let reason = work["reason"]
        .as_str()
        .unwrap_or("work_evidence_unavailable");
    let action = work["next_action"]
        .as_str()
        .unwrap_or("inspect_local_evidence");
    let next = timestamp(&work["next_at"]);
    let read_only = mode(status, name) == Some("read_only");
    if !read_only && status["paused"] == true {
        return Finding::blocked("admission_paused", "resume");
    }
    let identity = super::hosted_identity(status);
    if !read_only && identity.rejected() {
        return Finding::blocked(
            identity.reason(),
            if identity.rejection == Some("identity_mismatch") {
                "repair_config"
            } else {
                "review_credentials"
            },
        );
    }
    let scope = if name == "judge" {
        "assignments"
    } else {
        "challenge"
    };
    let bound_scope = match action {
        "read_job" => Some("job"),
        "read_receipt" => Some("receipt"),
        "await_identity" => Some("identity"),
        _ if reason == "identity_backoff" => Some("identity"),
        _ if work["read_key"]["purpose"] == "assignment" => Some("assignment"),
        _ => None,
    };
    for dependency in std::iter::once(scope).chain(bound_scope) {
        if read(status, name, work, dependency).is_some_and(|row| {
            ["started_at", "last_success_at", "last_failure_at"]
                .iter()
                .any(|field| timestamp(&row[*field]).is_some_and(|time| time > at))
        }) {
            return Finding::unknown("clock_regressed");
        }
        if let Some(row) = read(status, name, work, dependency)
            && dependency != "identity"
            && read_failed(row)
            && matches!(row["status"].as_u64(), Some(401 | 403))
        {
            return if read_auth_failed(row, at, stale) {
                Finding::blocked("read_authentication_failed", "review_credentials")
            } else {
                Finding::unknown("read_authentication_evidence_stale")
            };
        }
    }
    for pending in std::iter::once(&status["pending"])
        .chain(status["pending_work"].as_array().into_iter().flatten())
        .chain(status["captured_work"].as_array().into_iter().flatten())
        .filter(|row| row["kind"] == name)
    {
        if timestamp(&pending["created_at"]).is_some_and(|time| time > at)
            || timestamp(&pending["updated_at"]).is_some_and(|time| time > at)
        {
            return Finding::unknown("clock_regressed");
        }
        if matches!(
            timing.issue(pending, at),
            Some("model_work_overdue" | "dispatch_outcome_uncertain")
        ) {
            return Finding::unknown("in_flight_outcome_overdue");
        }
        if !read_only && super::model_awaiting_admission(pending) {
            return match super::model_overdue(pending, at, timing.poll, timing.model) {
                Some(false) => Finding::automatic(
                    "model_launch_awaiting_admission",
                    "await_model_admission",
                    timestamp(&pending["pending_execution_deadline"]),
                ),
                Some(true) => Finding::unknown("pending_model_execution_expired"),
                None => Finding::unknown("model_deadline_unavailable"),
            };
        }
    }
    if !read_only && matches!(phase, Some("preparing" | "generating" | "dispatching")) {
        return Finding {
            progress: "working",
            status: "none_required",
            reason,
            action,
            next_at: next,
        };
    }
    let observed = if name == "judge" {
        timestamp(&work["assessment"]["observed_at"])
    } else {
        timestamp(&super::observation(status, name)["observed_at"])
    };
    if observed.is_some_and(|time| time > at) {
        return Finding::unknown("clock_regressed");
    }
    let complete = fresh(observed, at, stale)
        && match name {
            "answer" => super::observation(status, name)["answered"] == true,
            "judge" => {
                super::assessment_fresh(&work["assessment"], at, stale)
                    && work["assessment"]["completeness"] == "complete"
                    && work["assessment"]["locally_judgeable"] == false
            }
            _ => {
                phase == Some("completed")
                    && super::observation(status, name)["epoch"].as_u64().is_some()
                    && work["operation_epoch"] == super::observation(status, name)["epoch"]
            }
        };
    if complete
        && !read_only
        && phase != Some("blocked")
        && status["work"][name]["admission"]["allowed"] == true
    {
        return Finding {
            progress: if name == "judge" { "idle" } else { "complete" },
            status: "none_required",
            reason: if name == "judge" {
                "no_eligible_assignments_observed"
            } else {
                "current_epoch_completed"
            },
            action,
            next_at: next,
        };
    }
    // A bound original can be reconciled even when policy forbids a distinct
    // risk-admitted retry. Never equate disabling retries with disabling reads.
    if !read_only && matches!(action, "read_job" | "read_receipt") {
        let purpose = if action == "read_job" {
            "job"
        } else {
            "receipt"
        };
        if work["read_key"]["owner"] != name
            || work["read_key"]["purpose"] != purpose
            || work["binding_revision"].as_i64().is_none()
            || work["read_key"]["resource"].as_str().is_none()
        {
            return Finding::unknown("reconciliation_evidence_unavailable");
        }
        let dependency = super::api::bound(status, work);
        if dependency.is_none() && status["reads_truncated"] == true {
            return Finding::unknown("reconciliation_evidence_truncated");
        }
        let due = [next, dependency.and_then(|row| timestamp(&row["next_at"]))]
            .into_iter()
            .flatten()
            .max();
        return Finding::automatic("bound_reconciliation_pending", action, due);
    }
    let model = &work["model"];
    if !read_only && model.is_object() {
        if model["current_route"] == true
            && matches!(
                model["failure_category"].as_str(),
                Some("native_auth_unavailable")
            )
        {
            return Finding::blocked("model_authentication_failed", "review_model_configuration");
        }
        if model["current_route"] == true
            && matches!(
                model["failure_category"].as_str(),
                Some(
                    "native_api_unsupported"
                        | "native_route_mismatch"
                        | "executable_unavailable"
                        | "core_guidance_missing"
                        | "invalid_solver_setup"
                        | "unsupported_harness_version"
                        | "invalid_model_deadline"
                )
            )
        {
            return Finding::blocked("model_configuration_failed", "review_model_configuration");
        }
        // Assignment-specific failures do not fence other eligible judgments.
        // Only current-route setup/auth evidence applies across assignments.
        if name != "judge" || model["scope"] == "current_work" {
            if model["budget_used"]
                .as_u64()
                .zip(model["budget_limit"].as_u64())
                .is_some_and(|(used, limit)| used >= limit)
            {
                return Finding::blocked(
                    "model_attempt_budget_exhausted",
                    "inspect_model_attempts",
                );
            }
            match model["retry_eligible"].as_bool() {
                Some(true) => {
                    if super::lane_policy(status, name)["preparation"]["while_blocked"] != true {
                        if let Some(finding) =
                            blocker(status, name, work, &work["admission"], at, stale, timing)
                        {
                            return finding;
                        }
                        if work["admission"]["allowed"] != true {
                            return Finding::unknown("admission_recovery_unproven");
                        }
                    }
                    return Finding::automatic(
                        "model_retry_eligible",
                        "retry_model",
                        timestamp(&model["next_at"]),
                    );
                }
                Some(false) if model["state"] == "model_unknown" => {
                    return Finding::blocked("model_uncertain", "recover_model");
                }
                Some(false) => {
                    return Finding::blocked("model_retry_unavailable", "inspect_model_attempts");
                }
                None => return Finding::unknown("model_retry_evidence_unavailable"),
            }
        }
    }
    if !read_only && reason == "model_uncertain" {
        return if action == "recover_model" {
            Finding::blocked(reason, action)
        } else {
            Finding::unknown("model_retry_evidence_unavailable")
        };
    }
    if !read_only && work["admission"]["allowed"] == false {
        return blocker(status, name, work, &work["admission"], at, stale, timing)
            .unwrap_or_else(|| Finding::unknown("admission_recovery_unproven"));
    }
    let retry = &work["retry"];
    if !read_only && retry.is_object() {
        let retry_reason = retry["reason"]
            .as_str()
            .unwrap_or("retry_evidence_unavailable");
        let retry_action = retry["next_action"]
            .as_str()
            .unwrap_or("await_retry_eligibility");
        if let Some(finding) = blocker(status, name, work, retry, at, stale, timing) {
            return finding;
        }
        return if retry["policy_eligible"] == true {
            Finding::automatic(retry_reason, retry_action, timestamp(&retry["next_at"]))
        } else {
            Finding::unknown(retry_reason)
        };
    }
    if !read_only {
        let admission = if work["admission"].is_object() {
            &work["admission"]
        } else {
            work
        };
        if let Some(finding) = blocker(status, name, work, admission, at, stale, timing) {
            return finding;
        }
        if action == "authoritative_recovery" {
            return Finding::blocked("unbound_outcome_requires_evidence", "inspect_operations");
        }
        if status["work"][name]["admission"]["allowed"] == false || phase == Some("blocked") {
            return Finding::unknown("admission_recovery_unproven");
        }
        if work["admission"]["allowed"].as_bool().is_none() {
            return Finding::unknown("admission_evidence_unavailable");
        }
    }
    for dependency in std::iter::once(scope).chain(bound_scope) {
        if let Some(row) = read(status, name, work, dependency) {
            if timestamp(&row["started_at"]).is_some_and(|time| time > at)
                || timestamp(&row["last_failure_at"]).is_some_and(|time| time > at)
                || timestamp(&row["last_success_at"]).is_some_and(|time| time > at)
            {
                return Finding::unknown("clock_regressed");
            }
            if row["state"] == "in_flight" {
                if timestamp(&row["started_at"])
                    .zip(super::cycle_floor(status, name))
                    .is_some_and(|(started, limit)| at.saturating_sub(started) as u64 > limit)
                {
                    return Finding::unknown("read_outcome_overdue");
                }
                return Finding {
                    progress: "working",
                    status: "none_required",
                    reason: "read_in_flight",
                    action: if name == "judge" {
                        "await_assignments"
                    } else {
                        "await_challenge"
                    },
                    next_at: None,
                };
            }
            if timestamp(&row["next_at"]).is_some_and(|time| time > at) && read_failed(row) {
                return Finding::automatic(
                    "read_backoff",
                    if name == "judge" {
                        "observe_assignments"
                    } else {
                        "observe_challenge"
                    },
                    timestamp(&row["next_at"]),
                );
            }
        }
    }
    if matches!(phase, Some("answered" | "completed" | "included")) && !fresh(observed, at, stale) {
        return Finding::automatic("completion_evidence_stale", "observe_challenge", next);
    }
    if read_only {
        return Finding {
            progress: "idle",
            status: "none_required",
            reason: "capability_read_only",
            action,
            next_at: next,
        };
    }
    if matches!(phase, Some("observing" | "prepared" | "included")) {
        return Finding::automatic(reason, action, next);
    }
    Finding::unknown("work_evidence_unavailable")
}

fn identity_work_retry_at(status: &Value, at: i64, stale: u64) -> Option<i64> {
    LANES
        .into_iter()
        .filter_map(|name| {
            if mode(status, name) != Some("active") {
                return None;
            }
            let work = &status["work"][name];
            let stale = super::cycle_floor(status, name)?.max(stale);
            let next = timestamp(&work["next_at"])?;
            let eligible = match work["phase"].as_str() {
                Some("prepared") => true,
                Some("observing") if name == "judge" => {
                    work["assessment"]["locally_judgeable"] == true
                        && super::assessment_fresh(&work["assessment"], at, stale)
                }
                Some("observing") => {
                    super::observation(status, name)["epoch"].as_u64().is_some()
                        && fresh(
                            timestamp(&super::observation(status, name)["observed_at"]),
                            at,
                            stale,
                        )
                        && (name == "mine" || super::observation(status, name)["answered"] == false)
                }
                _ => false,
            };
            eligible.then_some(next)
        })
        .min()
}

fn identity_recovery(status: &Value, at: i64, stale: u64) -> Option<Finding<'static>> {
    let identity = super::hosted_identity(status);
    if identity.verified() == Some(true) || identity.rejected() {
        return None;
    }
    let finding = if let Some(row) = super::api::identity(status) {
        if ["started_at", "last_failure_at", "last_success_at"]
            .iter()
            .any(|field| timestamp(&row[*field]).is_some_and(|time| time > at))
        {
            Finding::unknown("clock_regressed")
        } else if row["state"] == "in_flight" {
            match timestamp(&row["started_at"]) {
                Some(started)
                    if status["effective_runtime"]["policy"]["identity"]["read_http_seconds"]
                        .as_u64()
                        .is_some_and(|limit| at.saturating_sub(started) as u64 <= limit) =>
                {
                    Finding::automatic(identity.reason(), "await_identity", None)
                }
                Some(_) => Finding::unknown("read_outcome_overdue"),
                None => Finding::unknown(identity.reason()),
            }
        } else if read_failed(row)
            && let Some(floor) = timestamp(&row["next_at"]).filter(|time| *time > at)
            && let Some(next) = identity_work_retry_at(status, at, stale)
        {
            Finding::automatic(identity.reason(), "await_identity", Some(floor.max(next)))
        } else {
            Finding::unknown(identity.reason())
        }
    } else {
        Finding::unknown(identity.reason())
    };
    Some(finding)
}

pub(super) fn project(status: &Value, options: Options, at: i64) -> (Value, Value) {
    let floor = super::controller_floor(status);
    let stale = floor.map(|floor| options.stale_seconds.max(floor));
    let (ready, controller) = controller(status, at, stale);
    let observed = timestamp(&status["effective_runtime"]["observed_at"]);
    let current = stale.map(|stale| fresh(observed, at, stale));
    let mut work = status["work"]
        .as_object()
        .map_or_else(|| json!({}), |work| Value::Object(work.clone()));
    let identity = (ready == Some(true) && status["paused"] == false)
        .then(|| identity_recovery(status, at, options.stale_seconds))
        .flatten();
    for name in LANES {
        let lane_stale =
            super::cycle_floor(status, name).map(|floor| options.stale_seconds.max(floor));
        let mut finding = if mode(status, name) == Some("off") {
            Finding {
                progress: "idle",
                status: "none_required",
                reason: "capability_off",
                action: "none",
                next_at: None,
            }
        } else if ready != Some(true) && controller.reason != "controller_stopped" {
            Finding {
                progress: controller.progress,
                status: controller.status,
                reason: controller.reason,
                action: controller.action,
                next_at: None,
            }
        } else if !matches!(mode(status, name), Some("active" | "read_only")) {
            Finding::unknown("effective_mode_unavailable")
        } else if let Some(timing) = super::work_timing(status, name, options) {
            lane(status, name, at, lane_stale.unwrap_or(0), &timing)
        } else {
            Finding::unknown("effective_policy_unavailable")
        };
        // Preserve independently known lane blockers through a verified restart.
        // Stop-only recommendations can then be qualified without losing them.
        if controller.reason == "controller_stopped"
            && rank(finding.status) < rank(controller.status)
            && mode(status, name) != Some("off")
        {
            finding = Finding::blocked("controller_stopped", "start_controller");
        }
        if mode(status, name) == Some("active")
            && let Some(identity) = &identity
            && (rank(identity.status) > rank(finding.status)
                || (identity.status == "automatic_recovery"
                    && finding.status == "automatic_recovery"))
        {
            finding = Finding {
                progress: if matches!(finding.progress, "complete" | "idle" | "working") {
                    finding.progress
                } else {
                    identity.progress
                },
                status: identity.status,
                reason: identity.reason,
                action: identity.action,
                next_at: identity.next_at,
            };
        }
        if !work[name].is_object() {
            work[name] = json!({});
        }
        work[name]["progress"] = json!(finding.progress);
        work[name]["intervention"] = finding.value(observed, current);
        work[name]["intervention"]["requires_fresh_eligibility"] = json!(
            status["work"][name]["retry"]["requires_fresh_eligibility"] == true
                || matches!(
                    finding.action,
                    "revalidate_challenge" | "revalidate_assignment" | "await_retry_eligibility"
                )
        );
        let evidence_at = if name == "judge" {
            timestamp(&work[name]["assessment"]["observed_at"])
        } else {
            timestamp(&super::observation(status, name)["observed_at"])
        };
        work[name]["intervention"]["observation_fresh"] = json!(lane_stale.map(|stale| {
            if name == "judge" {
                super::assessment_fresh(&work[name]["assessment"], at, stale)
            } else {
                fresh(evidence_at, at, stale)
            }
        }));
    }
    let core = controller.value(observed, current);
    let mut root = core.clone();
    root["controller"] = json!({"ready":ready,"reason":controller.reason,"observed_at":observed,
        "evidence_fresh":current,"process_identity":"unverified"});
    reduce(
        &mut root,
        &work,
        &core,
        &status["effective_runtime"]["policy"]["capabilities"],
        &status["paused"],
    );
    (work, root)
}

fn rank(status: &str) -> u8 {
    match status {
        "operator_required" => 3,
        "undetermined" => 2,
        "automatic_recovery" => 1,
        _ => 0,
    }
}

fn select(root: &mut Value, finding: &Value) {
    for field in ["status", "reason", "next_action", "next_at"] {
        root[field] = finding[field].clone();
    }
}

/// Core first, then stable lane order. Qualifications always precede CLI actions.
fn reduce(root: &mut Value, work: &Value, core: &Value, modes: &Value, paused: &Value) {
    select(root, core);
    for name in LANES {
        let lane = &work[name]["intervention"];
        if rank(lane["status"].as_str().unwrap_or("undetermined"))
            > rank(root["status"].as_str().unwrap_or("undetermined"))
        {
            select(root, lane);
        }
        root["lanes"][name] = lane["status"].clone();
    }
    let active = LANES.iter().any(|name| modes[name]["mode"] == "active");
    let known = LANES.iter().all(|name| {
        matches!(
            modes[name]["mode"].as_str(),
            Some("active" | "read_only" | "off")
        )
    });
    root["unattended"] = if root["status"] == "operator_required"
        || root["controller"]["ready"] == false
        || *paused == true
        || (known && !active)
    {
        json!(false)
    } else if root["status"] == "undetermined" || !known || root["controller"]["ready"].is_null() {
        Value::Null
    } else {
        json!(root["controller"]["ready"] == true && active && *paused == false)
    };
    if !active && known && root["status"] == "none_required" {
        root["reason"] = json!("no_active_capabilities");
    }
}

fn core_reason(reason: &str) -> Finding<'_> {
    match reason {
        "controller_recent" => Finding {
            progress: "idle",
            status: "none_required",
            reason,
            action: "none",
            next_at: None,
        },
        "not_initialized" => Finding::blocked(reason, "initialize_controller"),
        "migration_pending" => Finding::blocked(reason, "complete_migration"),
        "identity_mismatch" | "api_routing_mismatch" | "config_reload_rejected" => {
            Finding::blocked(reason, "repair_config")
        }
        "controller_stopped" => Finding::blocked(reason, "start_controller"),
        "state_disk_space_low" => Finding::blocked(reason, "inspect_state_filesystem"),
        "state_disk_space_unavailable" => {
            let mut finding = Finding::unknown(reason);
            finding.action = "inspect_state_filesystem";
            finding
        }
        _ => Finding::unknown(reason),
    }
}

fn core_finding(controller: &Value) -> Value {
    core_reason(
        controller["reason"]
            .as_str()
            .unwrap_or("local_evidence_unavailable"),
    )
    .value(
        timestamp(&controller["observed_at"]),
        controller["evidence_fresh"].as_bool(),
    )
}

pub(super) fn qualify_disk(report: &mut Value, code: &str) {
    let low = code == "state_disk_space_low";
    let root = &mut report["intervention"];
    let core = &mut root["controller"];
    // A measurement is not a new controller observation. Known core blockers
    // retain their evidence; low disk precedes an otherwise equivalent start.
    if core["ready"] != false || (low && core["reason"] == "controller_stopped") {
        core["ready"] = if low { json!(false) } else { Value::Null };
        core["reason"] = json!(code);
    }
    let core = core_finding(&root["controller"]);
    let mut root = report["intervention"].take();
    reduce(
        &mut root,
        &report["work"],
        &core,
        &report["effective_capabilities"],
        &report["paused"],
    );
    root["next_action"] = json!("inspect_state_filesystem");
    root["next_at"] = Value::Null;
    report["intervention"] = root;
}

pub(super) fn qualify_restoration(report: &mut Value) {
    let reason = "runtime_restored_observation_pending";
    if report["intervention"]["controller"]["reason"] == "controller_stopped" {
        report["intervention"]["controller"]["ready"] = Value::Null;
        report["intervention"]["controller"]["reason"] = json!(reason);
    }
    for name in LANES {
        if report["work"][name]["intervention"]["reason"] == "controller_stopped" {
            let mode = report["effective_capabilities"][name]["mode"].as_str();
            let finding = if mode == Some("off") {
                Finding {
                    progress: "idle",
                    status: "none_required",
                    reason: "capability_off",
                    action: "none",
                    next_at: None,
                }
            } else if mode == Some("active") && report["paused"] == true {
                Finding::blocked("admission_paused", "resume")
            } else if mode == Some("active")
                && report["lane_controls"][name]["desired"]["paused"] == true
            {
                Finding::blocked("lane_paused", "resume")
            } else {
                Finding::unknown(reason)
            };
            report["work"][name]["progress"] = json!(finding.progress);
            report["work"][name]["intervention"] = finding.value(None, None);
            report["work"][name]["intervention"]["observation_fresh"] = Value::Null;
        }
        if report["work"][name]["next_action"] == "start_controller" {
            for field in ["next_action", "reason", "next_at"] {
                report["work"][name][field] = report["work"][name]["intervention"][field].clone();
            }
        }
    }
    let disk = report["issues"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find_map(|code| match code {
            "state_disk_space_low" => Some("state_disk_space_low"),
            "state_disk_space_unavailable" => Some("state_disk_space_unavailable"),
            _ => None,
        });
    if let Some(code) = disk {
        qualify_disk(report, code);
    } else {
        let mut root = report["intervention"].take();
        let core = core_finding(&root["controller"]);
        reduce(
            &mut root,
            &report["work"],
            &core,
            &report["effective_capabilities"],
            &report["paused"],
        );
        report["intervention"] = root;
    }
}

pub(super) fn qualify_repair_failure(report: &mut Value) {
    let action = if report["intervention"]["next_action"] == "inspect_state_filesystem" {
        "inspect_state_filesystem"
    } else {
        "inspect_repair_failure"
    };
    select(
        &mut report["intervention"],
        &Finding::blocked("doctor_repair_unavailable", action).value(None, None),
    );
    report["intervention"]["unattended"] = json!(false);
    report["attention_required"] = json!(true);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        let (_, _, mut status) = crate::health::tests::fixture();
        status["observations"]["answer"]["answered"] = json!(false);
        status["work"]["answer"]["phase"] = json!("observing");
        status["work"]["judge"]["assessment"]["locally_judgeable"] = json!(true);
        status["work"]["mine"]["phase"] = json!("observing");
        status
    }

    fn projection(status: &Value) -> (Value, Value) {
        project(status, Options::default(), 10000)
    }

    fn queued(id: i64, lane: &str) -> Value {
        json!({"operation_id":id,"kind":lane,"state":"queued","binding_revision":1,"next_at":10020,
            "read_key":{"owner":lane,"purpose":"job","resource":format!("{id}:1")}})
    }

    fn block(
        status: &mut Value,
        lane: &str,
        reason: &str,
        scope: &str,
        ids: &[i64],
        required: u64,
    ) {
        status["work"][lane]["admission"] = json!({"allowed":false,"reason":reason,
            "scope":scope,"blocker_ids":ids,"required_release":required,"not_before":null});
    }

    #[test]
    fn truncated_blocker_evidence_never_proves_recovery_impossible() {
        let mut status = fixture();
        block(
            &mut status,
            "answer",
            "account_uncertainty",
            "account",
            &[1],
            2,
        );
        status["work"]["answer"]["admission"]["blocker_ids_truncated"] = json!(true);
        status["pending_work"] =
            json!([{"operation_id":1,"kind":"judge","state":"unknown","read_key":null}]);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
    }

    #[test]
    fn truncated_read_history_does_not_hide_a_possible_authentication_block() {
        let mut status = fixture();
        block(
            &mut status,
            "answer",
            "account_uncertainty",
            "account",
            &[1],
            1,
        );
        status["pending_work"] = json!([queued(1, "judge")]);
        status["reads_truncated"] = json!(true);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
        status["work"]["answer"]["next_action"] = json!("read_job");
        status["work"]["answer"]["read_key"] = queued(2, "answer")["read_key"].clone();
        status["work"]["answer"]["binding_revision"] = json!(1);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "reconciliation_evidence_truncated"
        );
    }

    #[test]
    fn release_requirement_and_blocker_membership_come_only_from_store() {
        let mut status = fixture();
        status["pending_work"] = json!([queued(1,"answer"),queued(2,"judge"),
            {"operation_id":3,"kind":"answer","state":"unknown","read_key":null}]);
        block(
            &mut status,
            "answer",
            "lane_unresolved_capacity",
            "lane",
            &[1, 3],
            2,
        );
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "no_automatic_capacity_release"
        );
        status["work"]["answer"]["admission"]["required_release"] = json!(1);
        let recovery = projection(&status).0["answer"]["intervention"].clone();
        assert_eq!(recovery["status"], "automatic_recovery");
        assert_eq!(recovery["evidence"], "local_only_not_a_success_guarantee");
        block(
            &mut status,
            "answer",
            "lane_unresolved_capacity",
            "lane",
            &[2],
            1,
        );
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
    }

    #[test]
    fn strict_account_uncertainty_spans_lanes_without_consuming_their_allowance() {
        let mut status = fixture();
        status["pending_work"] = json!([queued(1, "judge")]);
        block(
            &mut status,
            "answer",
            "account_uncertainty",
            "account",
            &[1],
            1,
        );
        status["work"]["answer"]["admission"]["own_remaining"] = json!(4);
        let (work, _) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        assert_eq!(work["answer"]["admission"]["own_remaining"], 4);
        status["pending_work"][0]["read_key"] = Value::Null;
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "unbound_uncertainty"
        );
    }

    #[test]
    fn authentication_and_backoff_are_exact_operation_binding_dependencies() {
        let mut status = fixture();
        status["pending_work"] = json!([queued(1, "answer"), queued(2, "answer")]);
        status["reads"] = json!([
            {"owner":"answer","purpose":"job","resource":"1:1","binding_revision":1,
                "last_failure_at":9999,"status":401,"next_at":12000},
            {"owner":"answer","purpose":"job","resource":"2:1","binding_revision":1,
                "last_success_at":9999,"status":200,"next_at":10030}
        ]);
        block(
            &mut status,
            "answer",
            "lane_unresolved_capacity",
            "lane",
            &[2],
            1,
        );
        let (work, _) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        assert_eq!(work["answer"]["intervention"]["next_at"], 10030);
        block(
            &mut status,
            "answer",
            "lane_unresolved_capacity",
            "lane",
            &[1],
            1,
        );
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "reconciliation_authentication_failed"
        );
        status["reads"][0]["last_failure_at"] = json!(1);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
        status["pending_work"][0]["binding_revision"] = json!(2);
        status["pending_work"][0]["read_key"]["resource"] = json!("1:2");
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
    }

    #[test]
    fn direct_recovery_needs_binding_and_combines_only_its_own_due_time() {
        let mut status = fixture();
        status["work"]["answer"]["phase"] = json!("queued");
        status["work"]["answer"]["next_action"] = json!("read_job");
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
        status["work"]["answer"]["read_key"] = queued(1, "answer")["read_key"].clone();
        status["work"]["answer"]["binding_revision"] = json!(1);
        status["reads"] = json!([
            {"owner":"answer","purpose":"job","resource":"2:1","binding_revision":1,
                "last_failure_at":9999,"status":403,"next_at":12000},
            {"owner":"answer","purpose":"job","resource":"1:1","binding_revision":1,
                "last_success_at":9999,"next_at":10100}
        ]);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["next_at"],
            10100
        );
    }

    #[test]
    fn canonical_manual_and_restriction_decisions_are_not_reinterpreted() {
        let mut status = fixture();
        block(
            &mut status,
            "judge",
            "manual_authorization_required",
            "account",
            &[],
            0,
        );
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["next_action"],
            "authorize"
        );
        status["work"]["judge"]["retry"] = json!({"policy_eligible":true,
            "reason":"fresh_evidence_required","next_action":"revalidate_assignment","next_at":10020});
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["next_action"],
            "authorize"
        );
        status["work"]["judge"]["admission"] = json!({"allowed":true,"reason":null});
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "automatic_recovery"
        );
        status["work"]["judge"]["retry"] = Value::Null;
        for reason in [
            "account_uncertainty_grace",
            "shared_server_restriction",
            "retained_legacy_floor",
        ] {
            block(&mut status, "judge", reason, "account", &[], 0);
            assert_eq!(
                projection(&status).0["judge"]["intervention"]["status"],
                "undetermined"
            );
            status["work"]["judge"]["admission"]["not_before"] = json!(10100);
            let (work, _) = projection(&status);
            assert_eq!(work["judge"]["intervention"]["reason"], reason);
            assert_eq!(work["judge"]["intervention"]["next_at"], 10100);
            assert_ne!(work["answer"]["intervention"]["reason"], reason);
        }
    }

    #[test]
    fn model_uncertainty_budget_and_current_route_errors_remain_separate() {
        let mut status = fixture();
        status["work"]["answer"]["model"] = json!({"state":"model_unknown","budget_used":1,
            "budget_limit":2,"retry_eligible":true,"scope":"current_work","current_route":true});
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "model_retry_eligible"
        );
        status["work"]["answer"]["model"]["budget_used"] = json!(2);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "model_attempt_budget_exhausted"
        );
        status["work"]["answer"]["model"]["budget_used"] = json!(1);
        status["work"]["answer"]["model"]["retry_eligible"] = json!(false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["next_action"],
            "recover_model"
        );
        status["work"]["answer"]["model"]["retry_eligible"] = Value::Null;
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
        status["work"]["answer"]["model"]["failure_category"] = json!("native_auth_unavailable");
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "model_authentication_failed"
        );
        status["work"]["judge"]["model"] = json!({"scope":"historical_assignment","current_route":false,
            "state":"model_unknown","budget_used":2,"budget_limit":2,"retry_eligible":false});
        assert_ne!(
            projection(&status).0["judge"]["intervention"]["status"],
            "operator_required"
        );
    }

    #[test]
    fn model_preparation_permission_does_not_claim_effect_admission() {
        let mut status = fixture();
        block(
            &mut status,
            "answer",
            "account_uncertainty",
            "account",
            &[1],
            1,
        );
        status["pending_work"] =
            json!([{"operation_id":1,"kind":"judge","state":"unknown","read_key":null}]);
        status["work"]["answer"]["model"] = json!({"state":"model_unknown","budget_used":1,
            "budget_limit":2,"retry_eligible":true,"scope":"current_work"});
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["next_action"],
            "retry_model"
        );
        assert_eq!(
            projection(&status).0["answer"]["admission"]["allowed"],
            false
        );
        status["effective_runtime"]["policy"]["capabilities"]["answer"]["preparation"]["while_blocked"] =
            json!(false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "unbound_uncertainty"
        );
    }

    #[test]
    fn uncertain_identity_needs_real_read_or_scheduled_work_not_a_success_promise() {
        let mut status = fixture();
        status["hosted_identity"]["status"] = json!("unavailable");
        assert_eq!(projection(&status).1["unattended"], Value::Null);
        status["reads"] = json!([{"owner":"account","purpose":"identity","resource":"identity",
            "last_failure_at":9999,"failure_category":"timeout","next_at":10030}]);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["next_at"],
            10030
        );
        status["hosted_identity"]["rejection"] = json!("authentication_failed");
        assert_eq!(projection(&status).1["unattended"], false);
        status["hosted_identity"]["rejection"] = Value::Null;
        status["reads"][0]["state"] = json!("in_flight");
        status["reads"][0]["started_at"] = json!(1);
        assert_eq!(projection(&status).1["status"], "undetermined");
    }

    #[test]
    fn off_pause_and_stale_controller_preserve_recovery_diagnostics_without_permission() {
        let mut status = fixture();
        status["paused"] = json!(true);
        status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("read_only");
        status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
        let (work, root) = projection(&status);
        assert_eq!(work["answer"]["intervention"]["next_action"], "resume");
        assert_eq!(work["judge"]["intervention"]["status"], "none_required");
        assert_eq!(work["mine"]["intervention"]["status"], "none_required");
        assert_eq!(root["unattended"], false);
        status["paused"] = json!(false);
        for observed in [json!(1), json!(10001), Value::Null] {
            status["effective_runtime"]["observed_at"] = observed;
            assert_eq!(projection(&status).1["unattended"], Value::Null);
        }
    }
}
