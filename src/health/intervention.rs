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

fn read<'a>(status: &'a Value, scope: &str) -> Option<&'a Value> {
    let mut rows = status["reads"]
        .as_array()?
        .iter()
        .filter(|row| row["scope"] == scope);
    let row = rows.next()?;
    rows.next().is_none().then_some(row)
}

fn read_failed(row: &Value) -> bool {
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
    status["effective_runtime"]["capabilities"][name].as_str()
}

fn controller(status: &Value, at: i64, stale: Option<u64>) -> (Option<bool>, Finding<'static>) {
    if status["initialized"] == false {
        return (
            Some(false),
            Finding::blocked("not_initialized", "initialize_controller"),
        );
    }
    if status["initialized"] != true {
        return (None, Finding::unknown("local_evidence_unavailable"));
    }
    for (blocked, reason, action) in [
        (
            status["identity_matches_config"] == false,
            "identity_mismatch",
            "repair_config",
        ),
        (
            status["network_routing"]["matches_config"] == false,
            "api_routing_mismatch",
            "repair_config",
        ),
        (
            status["effective_runtime"]["reload_blocked"] == true,
            "config_reload_rejected",
            "repair_config",
        ),
        (
            status["controller_stopped"] == true,
            "controller_stopped",
            "start_controller",
        ),
    ] {
        if blocked {
            return (Some(false), Finding::blocked(reason, action));
        }
    }
    let observed = timestamp(&status["effective_runtime"]["observed_at"]);
    if observed.is_some_and(|time| time > at)
        || timestamp(&status["observation"]["observed_at"]).is_some_and(|time| time > at)
    {
        return (None, Finding::unknown("clock_regressed"));
    }
    let Some(stale) = stale else {
        return (None, Finding::unknown("effective_policy_unavailable"));
    };
    if observed.is_none() {
        return (None, Finding::unknown("controller_unobserved"));
    }
    if !fresh(observed, at, stale) {
        return (None, Finding::unknown("controller_stale"));
    }
    if status["identity_matches_config"].as_bool().is_none()
        || status["paused"].as_bool().is_none()
        || status["controller_stopped"].as_bool().is_none()
    {
        return (None, Finding::unknown("controller_evidence_unavailable"));
    }
    (
        Some(true),
        Finding {
            progress: "idle",
            status: "none_required",
            reason: "controller_recent",
            action: "none",
            next_at: None,
        },
    )
}

/// A configured reconciliation path can release capacity, but its success is not
/// promised. Count only operations the canonical accountant says consume it.
fn release_path<'a>(
    status: &'a Value,
    name: &str,
    all: bool,
    at: i64,
    stale: u64,
    timing: &WorkTiming,
) -> Finding<'a> {
    let Some(rows) = status["pending_work"].as_array() else {
        return Finding::unknown("reconciliation_evidence_unavailable");
    };
    let participation = &status["participation"];
    let needed = if all {
        participation["unresolved_count"].as_u64()
    } else {
        participation["active_unresolved_count"]
            .as_u64()
            .zip(
                participation["policy"]["max_unresolved_operations"]
                    .as_u64()
                    .map(|limit| {
                        if name == "answer" {
                            limit
                        } else {
                            limit.saturating_sub(
                                participation["policy"]["answer_reserved_slots"]
                                    .as_u64()
                                    .unwrap_or(0),
                            )
                        }
                    }),
            )
            .map(|(active, limit)| active.saturating_add(1).saturating_sub(limit))
    };
    let Some(needed) = needed.filter(|needed| *needed > 0) else {
        return Finding::unknown("capacity_evidence_unavailable");
    };
    let mut automatic = 0;
    let mut uncertain = 0;
    let mut authentication_blocked = false;
    let mut next: Option<i64> = None;
    for row in rows.iter().filter(|row| {
        matches!(
            row["state"].as_str(),
            Some("dispatching" | "queued" | "unknown" | "included_pending")
        )
    }) {
        if !all {
            match row["capacity_counted"].as_bool() {
                Some(false) => continue,
                None => {
                    uncertain += 1;
                    continue;
                }
                Some(true) => {}
            }
        }
        if ["created_at", "updated_at"]
            .iter()
            .any(|field| timestamp(&row[*field]).is_some_and(|time| time > at))
        {
            uncertain += 1;
            continue;
        }
        let bound = matches!(
            row["reconciliation_scope"].as_str(),
            Some("receipt" | "job")
        );
        let dispatching = row["state"] == "dispatching" && timing.issue(row, at).is_none();
        if bound
            && let Some(dependency) = row["reconciliation_scope"]
                .as_str()
                .and_then(|scope| read(status, scope))
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
        if bound || dispatching {
            automatic += 1;
            let deadline = [
                timestamp(&row["next_at"]),
                timestamp(&row["retry_not_before"]),
                row["reconciliation_scope"]
                    .as_str()
                    .and_then(|scope| read(status, scope))
                    .and_then(|read| timestamp(&read["next_at"])),
            ]
            .into_iter()
            .flatten()
            .max();
            next = match (next, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        } else if row.get("reconciliation_scope").is_none() || row["state"] == "dispatching" {
            uncertain += 1;
        }
    }
    if automatic >= needed {
        Finding::automatic("bound_reconciliation_pending", "await_reconciliation", next)
    } else if automatic + uncertain >= needed {
        Finding::unknown("reconciliation_evidence_unavailable")
    } else if authentication_blocked {
        Finding::blocked("reconciliation_authentication_failed", "review_credentials")
    } else {
        Finding::blocked(
            if all {
                "unbound_uncertainty"
            } else {
                "no_automatic_capacity_release"
            },
            "inspect_operations",
        )
    }
}

fn policy_wait<'a>(
    status: &'a Value,
    name: &str,
    work: &'a Value,
    detail: &'a Value,
    at: i64,
    stale: u64,
    timing: &WorkTiming,
) -> Finding<'a> {
    let reason = detail["reason"]
        .as_str()
        .unwrap_or("retry_evidence_unavailable");
    let policy = &status["participation"]["policy"];
    if status["participation"]["policy_source"] != "effective" {
        return Finding::unknown("participation_policy_unavailable");
    }
    if policy["mode"] == "strict" {
        return release_path(status, name, true, at, stale, timing);
    }
    if policy["mode"] == "manual" {
        let granted = detail["manual_authorized"]
            .as_bool()
            .or(work["manual_authorized"].as_bool());
        if granted != Some(true) {
            let recovery = release_path(status, name, true, at, stale, timing);
            return if recovery.status == "automatic_recovery" {
                recovery
            } else if granted == Some(false) {
                Finding::blocked("manual_authorization_required", "authorize")
            } else {
                Finding::unknown("manual_authorization_unobserved")
            };
        }
    } else if policy["mode"] != "participation_first" {
        return Finding::unknown("participation_policy_unavailable");
    }
    let allowed = match name {
        "answer" => "allow_answer",
        "judge" => "allow_judge",
        _ => "allow_mine",
    };
    if policy[allowed] == false {
        return Finding::blocked("participation_disabled", "review_participation_policy");
    }
    if policy[allowed] != true {
        return Finding::unknown("participation_policy_unavailable");
    }
    if matches!(
        reason,
        "uncertainty_grace" | "retained_retry_minimum" | "uncertain_answer_retry_delay"
    ) && timestamp(&detail["next_at"]).is_none()
    {
        return Finding::unknown("retry_deadline_unavailable");
    }
    Finding::automatic(
        reason,
        "await_retry_eligibility",
        timestamp(&detail["next_at"]),
    )
}

fn blocker<'a>(
    status: &'a Value,
    name: &str,
    work: &'a Value,
    detail: &'a Value,
    at: i64,
    stale: u64,
    timing: &WorkTiming,
) -> Option<Finding<'a>> {
    let reason = detail["reason"].as_str()?;
    Some(match reason {
        "uncertainty_grace" | "retained_retry_minimum" | "uncertain_answer_retry_delay" => {
            policy_wait(status, name, work, detail, at, stale, timing)
        }
        "unresolved_capacity" | "answer_capacity_reserved" => {
            if status["participation"]["policy"]["mode"] == "manual" {
                let policy = policy_wait(status, name, work, detail, at, stale, timing);
                if policy.status != "automatic_recovery" {
                    return Some(policy);
                }
            }
            release_path(
                status,
                name,
                status["participation"]["policy"]["mode"] == "strict",
                at,
                stale,
                timing,
            )
        }
        "strict_uncertainty" => release_path(status, name, true, at, stale, timing),
        "manual_authorization_required" => {
            let recovery = release_path(status, name, true, at, stale, timing);
            if recovery.status == "automatic_recovery" {
                recovery
            } else {
                Finding::blocked(reason, "authorize")
            }
        }
        "participation_disabled"
        | "uncertain_retry_disabled"
        | "answer_attempt_budget_exhausted" => {
            Finding::blocked(reason, "review_participation_policy")
        }
        "generation_changed" => {
            Finding::automatic(reason, "discard_unsent", timestamp(&detail["next_at"]))
        }
        "effect_in_flight" => {
            Finding::automatic(reason, "await_effect", timestamp(&detail["next_at"]))
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
        _ if name == "judge"
            && phase == Some("observing")
            && (work["selection"].is_null()
                || work["selection"]["observed_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)) =>
        {
            Some("assignment_evidence")
        }
        _ => None,
    };
    for dependency in std::iter::once(scope).chain(bound_scope) {
        if read(status, dependency).is_some_and(|row| {
            ["started_at", "last_success_at", "last_failure_at"]
                .iter()
                .any(|field| timestamp(&row[*field]).is_some_and(|time| time > at))
        }) {
            return Finding::unknown("clock_regressed");
        }
        if let Some(row) = read(status, dependency)
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
        timestamp(&work["selection"]["observed_at"])
    } else {
        timestamp(&status["observation"]["observed_at"])
    };
    if observed.is_some_and(|time| time > at) {
        return Finding::unknown("clock_regressed");
    }
    let complete = fresh(observed, at, stale)
        && match name {
            "answer" => status["epoch_evidence"]["answered"] == true,
            "judge" => {
                work["selection"]["inventory_complete"] == true
                    && work["selection"]["eligible"] == false
            }
            _ => {
                phase == Some("completed")
                    && status["observation"]["epoch"].as_u64().is_some()
                    && work["operation_epoch"] == status["observation"]["epoch"]
            }
        };
    if complete
        && !read_only
        && phase != Some("blocked")
        && status["participation"]["uncertainty_blocks"][name] == false
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
        return Finding::automatic("bound_reconciliation_pending", action, next);
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
                    if let Some(finding) =
                        blocker(status, name, work, &work["admission"], at, stale, timing)
                    {
                        return finding;
                    }
                    if status["participation"]["uncertainty_blocks"][name] == true {
                        return Finding::unknown("admission_recovery_unproven");
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
        if status["participation"]["uncertainty_blocks"][name] == true || phase == Some("blocked") {
            return Finding::unknown("admission_recovery_unproven");
        }
        if status["participation"]["uncertainty_blocks"][name]
            .as_bool()
            .is_none()
        {
            return Finding::unknown("admission_evidence_unavailable");
        }
    }
    for dependency in std::iter::once(scope).chain(bound_scope) {
        if let Some(row) = read(status, dependency) {
            if timestamp(&row["started_at"]).is_some_and(|time| time > at)
                || timestamp(&row["last_failure_at"]).is_some_and(|time| time > at)
                || timestamp(&row["last_success_at"]).is_some_and(|time| time > at)
            {
                return Finding::unknown("clock_regressed");
            }
            if row["state"] == "in_flight" {
                if timestamp(&row["started_at"])
                    .zip(super::cycle_floor(&status["effective_runtime"]["policy"]))
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
            let next = timestamp(&work["next_at"])?;
            let eligible = match work["phase"].as_str() {
                Some("prepared") => true,
                Some("observing") if name == "judge" => {
                    work["selection"]["eligible"] == true
                        && fresh(timestamp(&work["selection"]["observed_at"]), at, stale)
                }
                Some("observing") => {
                    status["observation"]["epoch"].as_u64().is_some()
                        && fresh(timestamp(&status["observation"]["observed_at"]), at, stale)
                        && (name == "mine" || status["epoch_evidence"]["answered"] == false)
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
    let finding = if let Some(row) = read(status, "identity") {
        if ["started_at", "last_failure_at", "last_success_at"]
            .iter()
            .any(|field| timestamp(&row[*field]).is_some_and(|time| time > at))
        {
            Finding::unknown("clock_regressed")
        } else if row["state"] == "in_flight" {
            match timestamp(&row["started_at"]) {
                Some(started)
                    if super::cycle_floor(&status["effective_runtime"]["policy"])
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
    let policy = &status["effective_runtime"]["policy"];
    let floor = super::cycle_floor(policy);
    let stale = floor.map(|floor| options.stale_seconds.max(floor));
    let timing = WorkTiming {
        http: policy["timeouts"]["http_seconds"].as_u64().unwrap_or(0),
        shutdown: policy["timeouts"]["shutdown_seconds"].as_u64().unwrap_or(0),
        poll: policy["schedule"]["poll_seconds"].as_u64().unwrap_or(0),
        model: policy["timeouts"]["model_seconds"]
            .as_u64()
            .and_then(|model| {
                Some(
                    model
                        .saturating_add(policy["timeouts"]["shutdown_seconds"].as_u64()?)
                        .saturating_add(policy["schedule"]["poll_seconds"].as_u64()?)
                        .saturating_add(policy["schedule"]["jitter_seconds"].as_u64()?)
                        .saturating_add(1),
                )
            }),
        pending: options.work_seconds.max(floor.unwrap_or(0)),
    };
    let (ready, controller) = controller(status, at, stale);
    let observed = timestamp(&status["effective_runtime"]["observed_at"]);
    let current = stale.map(|stale| fresh(observed, at, stale));
    let mut work = status["work"]
        .as_object()
        .map_or_else(|| json!({}), |work| Value::Object(work.clone()));
    let rank = |status: &str| match status {
        "operator_required" => 3,
        "undetermined" => 2,
        "automatic_recovery" => 1,
        _ => 0,
    };
    let identity = (ready == Some(true) && status["paused"] == false)
        .then(|| identity_recovery(status, at, stale.unwrap_or(0)))
        .flatten();
    for name in LANES {
        let mut finding = if mode(status, name) == Some("off") {
            Finding {
                progress: "idle",
                status: "none_required",
                reason: "capability_off",
                action: "none",
                next_at: None,
            }
        } else if ready != Some(true) {
            Finding {
                progress: controller.progress,
                status: controller.status,
                reason: controller.reason,
                action: controller.action,
                next_at: None,
            }
        } else if !matches!(mode(status, name), Some("active" | "read_only")) {
            Finding::unknown("effective_mode_unavailable")
        } else {
            lane(status, name, at, stale.unwrap_or(0), &timing)
        };
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
            timestamp(&work[name]["selection"]["observed_at"])
        } else {
            timestamp(&status["observation"]["observed_at"])
        };
        work[name]["intervention"]["observation_fresh"] =
            json!(stale.map(|stale| fresh(evidence_at, at, stale)));
    }
    // A reservation is a dependency, not itself evidence that the answer can run.
    for name in ["judge", "mine"] {
        if ready == Some(true)
            && mode(status, name) == Some("active")
            && status["paused"] == false
            && status["work"][name]["reason"] == "answer_retry_reserved"
        {
            let answer = &work["answer"]["intervention"];
            let finding = match answer["status"].as_str() {
                Some("automatic_recovery" | "none_required")
                    if work["answer"]["progress"] != "complete" =>
                {
                    Finding::automatic(
                        "answer_retry_reserved",
                        "await_answer_retry",
                        timestamp(&answer["next_at"]),
                    )
                }
                Some("operator_required") => {
                    Finding::blocked("answer_retry_blocked", "inspect_answer_retry")
                }
                _ => Finding::unknown("answer_retry_progress_unproven"),
            };
            work[name]["progress"] = json!(finding.progress);
            work[name]["intervention"] = finding.value(observed, current);
            work[name]["intervention"]["observation_fresh"] = json!(stale.map(|stale| {
                let evidence = if name == "judge" {
                    timestamp(&work[name]["selection"]["observed_at"])
                } else {
                    timestamp(&status["observation"]["observed_at"])
                };
                fresh(evidence, at, stale)
            }));
        }
    }
    let mut root = controller.value(observed, current);
    for name in LANES {
        let lane = &work[name]["intervention"];
        if rank(lane["status"].as_str().unwrap_or("undetermined"))
            > rank(root["status"].as_str().unwrap_or("undetermined"))
        {
            root = lane.clone();
        }
    }
    let active = LANES
        .iter()
        .any(|name| mode(status, name) == Some("active"));
    let modes_known = LANES.iter().all(|name| mode(status, name).is_some());
    root["unattended"] = match root["status"].as_str() {
        Some("operator_required") => json!(false),
        Some("undetermined") => Value::Null,
        _ if !modes_known => Value::Null,
        _ => json!(ready == Some(true) && active && status["paused"] == false),
    };
    if !active && modes_known && root["status"] == "none_required" {
        root["reason"] = json!("no_active_capabilities");
    }
    root["controller"] = json!({"ready":ready,"reason":controller.reason,"observed_at":observed,
        "evidence_fresh":current,"process_identity":"unverified"});
    root["lanes"] = json!({"answer":work["answer"]["intervention"]["status"],
        "judge":work["judge"]["intervention"]["status"],"mine":work["mine"]["intervention"]["status"]});
    (work, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        let mut config = crate::config::Config::default();
        config.participation.mode = crate::config::ParticipationMode::ParticipationFirst;
        config.participation.allow_judge = true;
        config.participation.retry_uncertain_answers = true;
        let mut status = json!({
            "initialized":true,"paused":false,"controller_stopped":false,
            "identity_matches_config":true,"hosted_identity_verified":true,
            "hosted_identity":{"status":"verified","observed_at":10000,
                "last_verified_at":10000,"rejection":null,"legacy_failure":false},
            "effective_runtime":{"observed_at":10000,"reload_blocked":false,
                "capabilities":{"answer":"active","judge":"active","mine":"active"},
                "policy":{"timeouts":config.timeouts,"schedule":config.schedule,
                    "preparation":config.preparation}},
            "observation":{"observed_at":10000,"epoch":7},"epoch_evidence":{"answered":false},
            "participation":{"policy_source":"effective","policy":config.participation,
                "unresolved_count":0,"active_unresolved_count":0,
                "uncertainty_blocks":{"answer":false,"judge":false,"mine":false}},
            "pending_work":[],"reads":[],"work":{}
        });
        for name in LANES {
            status["work"][name] = json!({"phase":"observing","reason":"cadence",
                "next_action":if name == "judge" { "observe_assignments" } else { "observe_challenge" },
                "next_at":10020});
        }
        status
    }

    fn projection(status: &Value) -> (Value, Value) {
        project(status, Options::default(), 10000)
    }

    #[test]
    fn identity_recovery_requires_a_real_retained_retry_or_live_read() {
        for state in [
            "unavailable",
            "invalid_response",
            "legacy_unknown",
            "unobserved",
        ] {
            let mut status = fixture();
            status["hosted_identity"]["status"] = json!(state);
            // A stale compatibility flag is not canonical rejection evidence.
            status["hosted_identity_verified"] = json!(false);
            let (work, root) = projection(&status);
            assert_eq!(root["status"], "undetermined");
            assert_eq!(root["unattended"], Value::Null);
            assert_eq!(work["answer"]["intervention"]["next_at"], Value::Null);
            status["reads"] = json!([{"scope":"identity","state":"idle",
                "last_failure_at":10000,"failure_category":"timeout","next_at":10030}]);
            let (work, root) = projection(&status);
            assert_eq!(root["status"], "automatic_recovery");
            for name in LANES {
                assert_eq!(work[name]["intervention"]["next_action"], "await_identity");
                assert_eq!(work[name]["intervention"]["next_at"], 10030);
            }
            status["reads"][0]["state"] = json!("in_flight");
            status["reads"][0]["started_at"] = json!(9999);
            let (work, _) = projection(&status);
            assert_eq!(
                work["answer"]["intervention"]["status"],
                "automatic_recovery"
            );
            assert_eq!(work["answer"]["intervention"]["next_at"], Value::Null);
            status["reads"][0]["started_at"] = json!(1);
            assert_eq!(projection(&status).1["status"], "undetermined");
            status["reads"][0]["state"] = json!("idle");
            status["reads"][0]["next_at"] = json!(9999);
            assert_eq!(projection(&status).1["status"], "undetermined");
        }
    }

    #[test]
    fn identity_uncertainty_remains_visible_after_current_work_completes() {
        let mut status = fixture();
        status["hosted_identity"]["status"] = json!("unavailable");
        status["epoch_evidence"]["answered"] = json!(true);
        status["work"]["answer"]["phase"] = json!("answered");
        status["work"]["mine"]["phase"] = json!("completed");
        status["work"]["mine"]["operation_epoch"] = json!(7);
        status["work"]["judge"]["selection"] = json!({
            "observed_at":10000,"inventory_complete":true,"eligible":false
        });
        for scheduled in [false, true] {
            if scheduled {
                status["reads"] = json!([{"scope":"identity","state":"idle",
                    "last_failure_at":10000,"failure_category":"timeout","next_at":10030}]);
            }
            let (work, root) = projection(&status);
            // The retained deadline is a floor, not a scheduled identity job.
            assert_eq!(root["status"], "undetermined");
            assert_eq!(root["unattended"], Value::Null);
            for (name, progress) in [
                ("answer", "complete"),
                ("judge", "idle"),
                ("mine", "complete"),
            ] {
                assert_eq!(work[name]["progress"], progress);
                assert_eq!(work[name]["intervention"]["status"], "undetermined");
            }
        }
        // Pending work supplies a real revalidation path; its own schedule can
        // be later than the identity floor.
        status["work"]["judge"] = json!({"phase":"prepared",
            "reason":"identity_backoff","next_action":"revalidate_assignment","next_at":10040});
        let (work, root) = projection(&status);
        assert_eq!(root["status"], "automatic_recovery");
        assert_eq!(root["unattended"], true);
        assert_eq!(root["next_at"], 10040);
        assert_eq!(work["answer"]["progress"], "complete");
        assert_eq!(work["mine"]["progress"], "complete");
    }

    #[test]
    fn identity_backoff_does_not_hide_independent_operator_fences() {
        let mut status = fixture();
        status["hosted_identity"]["status"] = json!("unavailable");
        status["reads"] = json!([{"scope":"identity","state":"idle",
            "last_failure_at":10000,"failure_category":"timeout","next_at":10030}]);
        status["work"]["answer"]["model"] = json!({
            "current_route":true,"failure_category":"native_auth_unavailable"
        });
        let (work, root) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["reason"],
            "model_authentication_failed"
        );
        assert_eq!(root["status"], "operator_required");
        status["work"]["answer"]["model"] = Value::Null;
        status["work"]["answer"]["admission"] = json!({"reason":"manual_authorization_required"});
        let (work, root) = projection(&status);
        assert_eq!(work["answer"]["intervention"]["next_action"], "authorize");
        assert_eq!(root["status"], "operator_required");
    }

    #[test]
    fn retained_identity_rejection_survives_timeout_until_matching_verification() {
        for (rejection, action) in [
            ("authentication_failed", "review_credentials"),
            ("identity_mismatch", "repair_config"),
        ] {
            let mut status = fixture();
            status["hosted_identity"]["status"] = json!("unavailable");
            status["hosted_identity"]["rejection"] = json!(rejection);
            status["reads"] = json!([{"scope":"identity","state":"idle",
                "last_failure_at":10000,"failure_category":"timeout","next_at":10030}]);
            let (work, root) = projection(&status);
            assert_eq!(root["status"], "operator_required");
            for name in LANES {
                assert_eq!(work[name]["intervention"]["next_action"], action);
                assert_eq!(work[name]["intervention"]["next_at"], Value::Null);
            }
            status["hosted_identity"]["status"] = json!("verified");
            status["hosted_identity"]["rejection"] = Value::Null;
            status["reads"] = json!([]);
            assert_ne!(projection(&status).1["status"], "operator_required");
        }
    }

    #[test]
    fn missing_identity_object_is_uncertain_and_read_only_lanes_are_not_escalated() {
        let mut status = fixture();
        status.as_object_mut().unwrap().remove("hosted_identity");
        for legacy in [json!(true), json!(false), Value::Null] {
            status["hosted_identity_verified"] = legacy;
            let (work, _) = projection(&status);
            assert_eq!(work["answer"]["intervention"]["status"], "undetermined");
        }
        status["hosted_identity"] =
            json!({"status":"unavailable","rejection":"authentication_failed"});
        status["effective_runtime"]["capabilities"]["judge"] = json!("read_only");
        status["effective_runtime"]["capabilities"]["mine"] = json!("off");
        let (work, _) = projection(&status);
        assert_eq!(work["judge"]["intervention"]["status"], "none_required");
        assert_eq!(work["mine"]["intervention"]["status"], "none_required");
        status["paused"] = json!(true);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "admission_paused"
        );
        status["initialized"] = json!(false);
        assert_eq!(projection(&status).1["reason"], "not_initialized");
    }

    #[test]
    fn grace_is_automatic_not_manual_even_while_admission_is_closed() {
        let mut status = fixture();
        for name in LANES {
            status["work"][name] = json!({"phase":"blocked","reason":"uncertainty_grace",
                "next_action":"await_reconciliation","next_at":10100});
            status["participation"]["uncertainty_blocks"][name] = json!(true);
        }
        let (work, root) = projection(&status);
        for name in LANES {
            assert_eq!(work[name]["progress"], "waiting");
            assert_eq!(work[name]["intervention"]["status"], "automatic_recovery");
            assert_eq!(work[name]["intervention"]["next_at"], 10100);
            assert_eq!(work[name]["phase"], "blocked");
        }
        assert_eq!(root["unattended"], true);
        status["participation"]["policy"]["mode"] = json!("manual");
        for name in LANES {
            status["work"][name]["manual_authorized"] = json!(false);
        }
        assert_eq!(projection(&status).1["unattended"], false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "manual_authorization_required"
        );
    }

    #[test]
    fn future_uncertain_retry_requires_policy_and_grant_evidence() {
        let mut status = fixture();
        status["work"]["answer"] = json!({"phase":"unknown","next_action":"authoritative_recovery",
            "retry":{"policy_eligible":false,"reason":"uncertain_answer_retry_delay",
                "next_action":"await_retry_eligibility","next_at":10200,"requires_fresh_eligibility":true}});
        let (work, _) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        assert_eq!(work["answer"]["intervention"]["next_at"], 10200);
        assert_eq!(
            work["answer"]["intervention"]["requires_fresh_eligibility"],
            true
        );
        status["participation"]["policy"]["mode"] = json!("manual");
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
        status["work"]["answer"]["retry"]["manual_authorized"] = json!(false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "operator_required"
        );
        status["work"]["answer"]["retry"]["manual_authorized"] = json!(true);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
    }

    #[test]
    fn unbound_capacity_cannot_be_mistaken_for_an_automatic_wait() {
        let mut status = fixture();
        status["participation"]["policy"]["max_unresolved_operations"] = json!(1);
        status["participation"]["active_unresolved_count"] = json!(1);
        status["participation"]["unresolved_count"] = json!(1);
        status["work"]["answer"] = json!({"phase":"blocked","reason":"unresolved_capacity",
            "next_action":"await_reconciliation","next_at":null});
        status["pending_work"] = json!([{"kind":"mine","state":"unknown","capacity_counted":true,
            "reconciliation_scope":null,"next_at":10020}]);
        let (work, root) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["status"],
            "operator_required"
        );
        assert_eq!(root["unattended"], false);
        status["pending_work"][0]["reconciliation_scope"] = json!("job");
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        status["pending_work"][0]["capacity_counted"] = Value::Null;
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
    }

    #[test]
    fn capacity_release_requires_usable_reconciliation_authentication() {
        let mut status = fixture();
        status["participation"]["policy"]["max_unresolved_operations"] = json!(1);
        status["participation"]["active_unresolved_count"] = json!(1);
        status["participation"]["unresolved_count"] = json!(1);
        status["work"]["mine"] = json!({"phase":"blocked","reason":"unresolved_capacity"});
        status["pending_work"] = json!([{"kind":"answer","state":"queued","capacity_counted":true,
            "reconciliation_scope":"job","next_at":10020}]);
        status["reads"] = json!([{"scope":"job","status":401,"last_failure_at":9990,
            "last_success_at":null,"failures":1,"next_at":10100}]);
        assert_eq!(
            projection(&status).0["mine"]["intervention"]["status"],
            "operator_required"
        );
        assert_eq!(projection(&status).1["unattended"], false);
        status["reads"][0]["last_failure_at"] = json!(1);
        assert_eq!(
            projection(&status).0["mine"]["intervention"]["status"],
            "undetermined"
        );
        status["reads"][0]["status"] = json!(503);
        status["reads"][0]["last_failure_at"] = json!(9990);
        assert_eq!(
            projection(&status).0["mine"]["intervention"]["status"],
            "automatic_recovery"
        );
    }

    #[test]
    fn stale_authentication_preserves_uncertainty_for_direct_and_alternative_reads() {
        let mut status = fixture();
        status["work"]["answer"] = json!({"phase":"queued","next_action":"read_job"});
        status["reads"] = json!([{"scope":"job","status":401,"last_failure_at":1,
            "last_success_at":null,"failures":1}]);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
        status["reads"][0]["last_success_at"] = json!(10000);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        status["reads"][0]["last_success_at"] = Value::Null;
        status["reads"]
            .as_array_mut()
            .unwrap()
            .push(json!({"scope":"receipt","status":403,
            "last_failure_at":9999,"last_success_at":null,"failures":1}));
        status["work"]["mine"] = json!({"phase":"blocked","reason":"unresolved_capacity"});
        status["participation"]["policy"]["max_unresolved_operations"] = json!(2);
        status["participation"]["policy"]["answer_reserved_slots"] = json!(0);
        status["participation"]["active_unresolved_count"] = json!(2);
        status["pending_work"] = json!([
            {"state":"queued","capacity_counted":true,"reconciliation_scope":"job"},
            {"state":"queued","capacity_counted":true,"reconciliation_scope":"receipt"}]);
        assert_eq!(
            projection(&status).0["mine"]["intervention"]["status"],
            "undetermined"
        );
        status["participation"]["policy"]["max_unresolved_operations"] = json!(1);
        assert_eq!(
            projection(&status).0["mine"]["intervention"]["status"],
            "operator_required"
        );
    }

    #[test]
    fn unrelated_assignment_model_failure_does_not_block_new_judgments() {
        let mut status = fixture();
        status["work"]["judge"]["selection"] = json!({"observed_at":10000,
            "inventory_complete":true,"eligible":true,"observed_count":2});
        status["work"]["judge"]["model"] = json!({"scope":"historical_assignment",
            "current_route":true,"state":"model_unknown","retry_eligible":false,
            "budget_used":2,"budget_limit":2,"failure_category":null});
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "automatic_recovery"
        );
        status["work"]["judge"]["model"]["failure_category"] = json!("native_auth_unavailable");
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "operator_required"
        );
        status["work"]["judge"]["model"]["current_route"] = json!(false);
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "automatic_recovery"
        );
    }

    #[test]
    fn model_retry_does_not_hide_capacity_block_or_bound_original_recovery() {
        let mut status = fixture();
        status["participation"]["policy"]["max_unresolved_operations"] = json!(1);
        status["participation"]["active_unresolved_count"] = json!(1);
        status["participation"]["unresolved_count"] = json!(1);
        status["participation"]["uncertainty_blocks"]["answer"] = json!(true);
        status["pending_work"] = json!([{"kind":"judge","state":"unknown",
            "capacity_counted":true,"reconciliation_scope":null}]);
        status["work"]["answer"]["admission"] = json!({"reason":"unresolved_capacity"});
        status["work"]["answer"]["model"] = json!({"scope":"current_work",
            "state":"model_unknown","retry_eligible":true,"budget_used":1,"budget_limit":2});
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "operator_required"
        );
        status["work"]["answer"]["phase"] = json!("queued");
        status["work"]["answer"]["next_action"] = json!("read_job");
        status["work"]["answer"]["model"]["budget_used"] = json!(2);
        status["work"]["answer"]["model"]["retry_eligible"] = json!(false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
    }

    #[test]
    fn capacity_release_must_be_large_enough_to_admit_work() {
        let mut status = fixture();
        status["participation"]["policy"]["max_unresolved_operations"] = json!(1);
        status["participation"]["active_unresolved_count"] = json!(2);
        status["work"]["answer"] = json!({"phase":"blocked","reason":"unresolved_capacity"});
        status["pending_work"] = json!([
            {"kind":"mine","state":"queued","capacity_counted":true,"reconciliation_scope":"job"},
            {"kind":"judge","state":"unknown","capacity_counted":true,"reconciliation_scope":null}
        ]);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "operator_required"
        );
    }

    #[test]
    fn strict_prepared_retry_can_wait_for_bound_original_reconciliation() {
        let mut status = fixture();
        status["participation"]["policy"]["mode"] = json!("strict");
        status["participation"]["unresolved_count"] = json!(1);
        status["pending_work"] = json!([{"kind":"answer","state":"queued",
            "reconciliation_scope":"job","next_at":10020}]);
        status["work"]["answer"] = json!({"phase":"prepared","next_action":"revalidate_challenge",
            "retry":{"reason":"strict_uncertainty","policy_eligible":false}});
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        status["pending_work"][0]["reconciliation_scope"] = Value::Null;
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "operator_required"
        );
    }

    #[test]
    fn stopped_stale_missing_and_future_controllers_never_promise_unattended_work() {
        let mut status = fixture();
        status["controller_stopped"] = json!(true);
        assert_eq!(projection(&status).1["unattended"], false);
        assert_eq!(projection(&status).1["controller"]["ready"], false);
        status["controller_stopped"] = json!(false);
        for observed in [json!(1), Value::Null, json!(10001)] {
            status["effective_runtime"]["observed_at"] = observed;
            let (work, root) = projection(&status);
            assert_eq!(root["unattended"], Value::Null);
            for name in LANES {
                assert_eq!(work[name]["intervention"]["status"], "undetermined");
            }
        }
    }

    #[test]
    fn completed_answer_requires_fresh_observation_not_just_a_heartbeat() {
        let mut status = fixture();
        status["epoch_evidence"]["answered"] = json!(true);
        status["work"]["answer"]["phase"] = json!("answered");
        assert_eq!(projection(&status).0["answer"]["progress"], "complete");
        status["observation"]["observed_at"] = json!(1);
        let (work, _) = projection(&status);
        assert_eq!(work["answer"]["progress"], "waiting");
        assert_eq!(work["answer"]["intervention"]["observation_fresh"], false);
        assert_eq!(work["answer"]["phase"], "answered");
        status["observation"]["observed_at"] = json!(10001);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "undetermined"
        );
    }

    #[test]
    fn historical_uncertainty_is_not_an_operator_blocker() {
        let mut status = fixture();
        status["epoch_evidence"]["answered"] = json!(true);
        status["work"]["answer"]["phase"] = json!("answered");
        status["participation"]["unresolved_count"] = json!(5);
        status["participation"]["historical_unknown_answer_count"] = json!(5);
        status["pending_work"] = json!([{"kind":"answer","state":"unknown","created_at":1,
            "capacity_counted":false,"reconciliation_scope":null}]);
        status["operations"] =
            json!([{"kind":"judge","state":"superseded_model_unknown","count":1}]);
        let before = status.clone();
        let (work, root) = projection(&status);
        assert_eq!(work["answer"]["progress"], "complete");
        assert_eq!(work["answer"]["intervention"]["status"], "none_required");
        assert_eq!(root["unattended"], true);
        assert_eq!(status, before);
    }

    #[test]
    fn model_recovery_needs_remaining_budget_and_known_retry_policy() {
        let mut status = fixture();
        status["work"]["answer"]["model"] = json!({"state":"model_unknown",
            "budget_used":1,"budget_limit":2,"retry_eligible":true,"failure_category":null,
            "scope":"current_work","current_route":true});
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
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
    }

    #[test]
    fn read_backoff_and_bound_reconciliation_have_real_automatic_paths() {
        let mut status = fixture();
        status["reads"] = json!([{"scope":"assignments","state":"idle","last_failure_at":10000,
            "status":429,"next_at":10100}]);
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["next_at"],
            10100
        );
        status["reads"][0]["state"] = json!("in_flight");
        assert_eq!(projection(&status).0["judge"]["progress"], "working");
        status["work"]["answer"] = json!({"phase":"queued","next_action":"read_job","next_at":10100,
            "retry":{"policy_eligible":false,"reason":"strict_uncertainty"}});
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        status["work"]["answer"]["next_action"] = json!("authoritative_recovery");
        status["participation"]["unresolved_count"] = json!(1);
        status["pending_work"] = json!([{"kind":"answer","state":"unknown",
            "reconciliation_scope":null}]);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
            "operator_required"
        );
    }

    #[test]
    fn off_read_only_and_pause_do_not_authorize_participation() {
        let mut status = fixture();
        status["paused"] = json!(true);
        status["effective_runtime"]["capabilities"]["judge"] = json!("read_only");
        status["effective_runtime"]["capabilities"]["mine"] = json!("off");
        let (work, root) = projection(&status);
        assert_eq!(work["answer"]["intervention"]["next_action"], "resume");
        assert_eq!(work["judge"]["progress"], "idle");
        assert_eq!(work["judge"]["intervention"]["status"], "none_required");
        assert_eq!(work["mine"]["intervention"]["status"], "none_required");
        assert_eq!(root["unattended"], false);
    }

    #[test]
    fn observing_lane_uses_canonical_admission_not_a_generic_manual_guess() {
        let mut status = fixture();
        status["participation"]["uncertainty_blocks"]["judge"] = json!(true);
        status["work"]["judge"]["admission"] =
            json!({"reason":"uncertainty_grace","next_at":10120});
        let (work, _) = projection(&status);
        assert_eq!(work["judge"]["phase"], "observing");
        assert_eq!(
            work["judge"]["intervention"]["status"],
            "automatic_recovery"
        );
        assert_eq!(work["judge"]["intervention"]["next_at"], 10120);
        status["work"]["judge"]["admission"]["next_at"] = Value::Null;
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "undetermined"
        );
    }

    #[test]
    fn reservation_does_not_invent_an_answer_recovery_path() {
        let mut status = fixture();
        status["work"]["answer"] = json!({"phase":"unknown","next_action":"authoritative_recovery",
            "retry":{"policy_eligible":false,"reason":"uncertain_retry_disabled"}});
        status["work"]["judge"] = json!({"phase":"blocked","reason":"answer_retry_reserved",
            "admission_reservation":{"active":true}});
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "operator_required"
        );
        status["work"]["answer"]["retry"]["policy_eligible"] = json!(true);
        status["work"]["answer"]["retry"]["reason"] = json!("fresh_evidence_required");
        assert_eq!(
            projection(&status).0["judge"]["intervention"]["status"],
            "automatic_recovery"
        );
    }
}
