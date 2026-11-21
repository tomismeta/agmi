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
    detail: Value,
}

impl<'a> Finding<'a> {
    fn unknown(reason: &'a str) -> Self {
        Self {
            progress: "waiting",
            status: "undetermined",
            reason,
            action: "inspect_local_evidence",
            next_at: None,
            detail: json!({}),
        }
    }

    fn blocked(reason: &'a str, action: &'a str) -> Self {
        Self {
            progress: "blocked",
            status: "operator_required",
            reason,
            action,
            next_at: None,
            detail: json!({}),
        }
    }

    fn automatic(reason: &'a str, action: &'a str, next_at: Option<i64>) -> Self {
        Self {
            progress: "waiting",
            status: "automatic_recovery",
            reason,
            action,
            next_at,
            detail: json!({}),
        }
    }

    /// Attach bounded typed witnesses without changing the classification.
    /// Callers pass only canonical store evidence (blocker id lists, safe
    /// read outcomes, retry-floor labels); nothing here re-decides admission.
    fn with(mut self, key: &str, value: Value) -> Self {
        if let Value::Object(fields) = &mut self.detail {
            fields.insert(key.to_owned(), value);
        }
        self
    }

    /// Merge a prebuilt evidence object (flat scalar/array fields only).
    fn with_all(mut self, evidence: Value) -> Self {
        if let (Value::Object(fields), Value::Object(detail)) = (&mut self.detail, evidence) {
            fields.extend(detail);
        }
        self
    }

    fn value(&self, observed: Option<i64>, evidence_fresh: Option<bool>) -> Value {
        let mut result = json!({"status":self.status,"reason":self.reason,"next_action":self.action,
            "next_at":self.next_at,"observed_at":observed,"evidence_fresh":evidence_fresh,
            "evidence":"local_only_not_a_success_guarantee"});
        if let Value::Object(target) = &mut result
            && let Value::Object(detail) = &self.detail
        {
            for (key, value) in detail {
                target.insert(key.clone(), value.clone());
            }
        }
        result
    }
}

pub(super) fn unknown_work(reason: &str) -> Value {
    let finding = Finding::unknown(reason);
    let mut work = json!({});
    for name in LANES {
        work[name] = json!({"progress":finding.progress,"intervention":finding.value(None, None),
            "operational":{"state":"unknown","reasons":[reason]},
            "refresh":{"state":"unknown","reason":reason,"observed_at":null,"valid_until":null,
                "evidence":"same_lane_original_completion_not_retry_authority"},
            "background_recovery":{"count":null,"bound_count":null,"unbound_count":null,
                "required_for_participation":null,"next_action":"inspect_local_evidence",
                "next_at":null,"evidence":"unavailable"}});
    }
    work
}

pub(super) fn unknown(reason: &str) -> Value {
    let finding = Finding::unknown(reason);
    let mut result = finding.value(None, None);
    result["unattended"] = Value::Null;
    result["controller"] = json!({"ready":null,"reason":reason,"observed_at":null,
        "evidence_fresh":null,"process_identity":"not_assessed"});
    result["lanes"] = json!({"answer":"undetermined","judge":"undetermined","mine":"undetermined"});
    result
}

fn timestamp(value: &Value) -> Option<i64> {
    value.as_i64().filter(|time| *time >= 0)
}

/// A retained deadline schedules future work only while it stays ahead of
/// now. Expired timestamps are stale evidence, never a revived promise.
fn future(value: &Value, at: i64) -> Option<i64> {
    timestamp(value).filter(|time| *time > at)
}

/// Which journal operations the store says must clear, carried verbatim from
/// the canonical admission projection. Health never recomputes membership.
fn blocker_evidence(detail: &Value) -> Value {
    json!({
        "blocker_ids": detail.get("blocker_ids").cloned().unwrap_or(Value::Null),
        "required_release": detail.get("required_release").cloned().unwrap_or(Value::Null),
        "release_scope": detail.get("scope").cloned().unwrap_or(Value::Null),
        "release_truncated": detail.get("blocker_ids_truncated").cloned().unwrap_or(Value::Null),
    })
}

fn request_floor_kind(basis: &Value) -> &'static str {
    match basis.as_str() {
        Some("server_retry_after") => "server_restriction",
        Some("local_unscoped_429_cooldown") => "local_backoff",
        Some("retained_legacy_floor") => "retained_floor",
        _ => "shared_restriction",
    }
}

/// Label the wait selected from the persisted admission deadlines.
pub(super) fn floor_kind(reason: &str, basis: &Value) -> Option<&'static str> {
    match reason {
        "operation_retry_minimum" => Some("operation_minimum"),
        "operation_backoff" => Some("local_backoff"),
        "shared_server_restriction" => Some(request_floor_kind(basis)),
        "retained_legacy_floor" => Some("retained_floor"),
        "account_uncertainty_grace" | "uncertain_answer_retry_delay" => Some("participation_grace"),
        _ => None,
    }
}

/// Keep sourced read restrictions distinct from local and legacy waits.
/// The store's `next_at` remains the effective deadline.
fn read_retry_evidence(row: &Value, at: i64) -> Value {
    let ahead = |field: &str| future(&row[field], at);
    let server = ahead("server_not_before").max(ahead("shared_server_not_before"));
    let local = ahead("local_next_at").max(ahead("shared_local_not_before"));
    let retained = ahead("retained_conservative_floor").max(ahead("shared_retained_not_before"));
    let shared = ahead("shared_not_before").filter(|&floor| {
        Some(floor)
            > ahead("shared_server_not_before")
                .max(ahead("shared_local_not_before"))
                .max(ahead("shared_retained_not_before"))
    });
    json!({"server_floor_at":server,"local_retry_at":local,"retained_floor_at":retained,
        "unattributed_shared_floor_at":shared})
}

fn bound_evidence(dependency: Option<&Value>, at: i64) -> Value {
    let row = dependency.unwrap_or(&Value::Null);
    let mut detail = read_retry_evidence(row, at);
    detail["bound_missing"] = json!(dependency.is_none());
    detail["bound_read_status"] = row["status"].clone();
    detail["bound_read_category"] = json!(
        row["failure_category"]
            .as_str()
            .map(crate::store::safe_read_category)
    );
    detail
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

fn missing_remote_evidence(row: &Value) -> bool {
    row["status"].as_u64() == Some(404) && read_failed(row)
}

fn no_observation(status: &str) -> Value {
    json!({"status":status,"owner":null,"purpose":null,"operation_id":null,
        "binding_revision":null,"not_before":null,"floor_kind":null})
}

fn bound_observation(work: &Value) -> Option<&Value> {
    let observed = &work["bound_observation"];
    (matches!(
        observed["owner"].as_str(),
        Some("answer" | "judge" | "mine")
    ) && matches!(observed["purpose"].as_str(), Some("job" | "receipt"))
        && observed["operation_id"].as_i64().is_some()
        && observed["operation_id"] == work["operation_id"]
        && observed["binding_revision"].as_i64().is_some()
        && observed["binding_revision"] == work["binding_revision"]
        && observed["owner"] == work["read_key"]["owner"]
        && observed["purpose"] == work["read_key"]["purpose"])
        .then_some(observed)
}

fn earlier_observation<'a>(
    current: Option<&'a Value>,
    new: &'a Value,
    at: i64,
) -> Option<&'a Value> {
    let rank = |row: &Value| match row["status"].as_str() {
        Some("in_flight") => i64::MIN,
        _ => future(&row["not_before"], at).unwrap_or(at),
    };
    if current.is_none_or(|old| rank(new) < rank(old)) {
        Some(new)
    } else {
        current
    }
}

fn identity_observation(row: &Value, at: i64) -> Value {
    let floors = read_retry_evidence(row, at);
    let mut observed = no_observation(if row["state"] == "in_flight" {
        "in_flight"
    } else {
        "eligible"
    });
    observed["owner"] = json!("account");
    observed["purpose"] = json!("identity");
    if row["state"] != "in_flight"
        && let Some(next) = future(&row["next_at"], at)
    {
        observed["status"] = json!("waiting");
        observed["not_before"] = json!(next);
        observed["floor_kind"] = json!(
            [
                ("server_floor_at", "server_restriction"),
                ("retained_floor_at", "retained_floor"),
                ("local_retry_at", "local_backoff"),
                ("unattributed_shared_floor_at", "shared_restriction"),
            ]
            .into_iter()
            .find(|(field, _)| floors[*field].as_i64() == Some(next))
            .map(|(_, kind)| kind)
        );
    }
    observed
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
        (
            status["controller_stopped"] == true || status["process_identity"] == "stopped",
            "controller_stopped",
        ),
        (
            status["process_identity"] == "mismatch",
            "process_identity_mismatch",
        ),
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
    let mut truncated_reads = false;
    let mut polls_missing_evidence = false;
    let mut selected = None;
    let mut dispatch_in_flight = false;
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
        let bound = matches!(
            row["state"].as_str(),
            Some("queued" | "unknown" | "included_pending" | "confirmed")
        ) && matches!(row["read_key"]["purpose"].as_str(), Some("job" | "receipt"))
            && row["binding_revision"].as_i64().is_some()
            && row["read_key"]["owner"] == row["kind"]
            && row["read_key"]["resource"].as_str().is_some();
        let dependency = bound.then(|| super::api::bound(status, row)).flatten();
        if bound && dependency.is_none() && status["reads_truncated"] == true {
            uncertain += 1;
            truncated_reads = true;
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
            polls_missing_evidence |= bound && dependency.is_some_and(missing_remote_evidence);
            if let Some(observation) = bound_observation(row) {
                polls_missing_evidence |= observation["http_status"] == 404;
                selected = earlier_observation(selected, observation, at);
            } else if dispatching {
                dispatch_in_flight = true;
            }
        } else if row.get("read_key").is_none() || row["state"] == "dispatching" {
            uncertain += 1;
        }
    }
    // Every outcome carries the store's own blocker list so the operator can
    // see which journal operations actually hold the lane.
    let truncated = truncated_reads || detail["blocker_ids_truncated"] == true;
    if automatic >= needed {
        let next = selected.and_then(|row| future(&row["not_before"], at));
        let observation = selected.cloned().unwrap_or_else(|| {
            no_observation(if dispatch_in_flight {
                "dispatch_in_flight"
            } else {
                "not_assessed"
            })
        });
        let finding =
            Finding::automatic("bound_reconciliation_pending", "await_reconciliation", next)
                .with_all(blocker_evidence(detail))
                .with("next_observation", observation);
        if polls_missing_evidence {
            finding.with("resolution", json!("polling_not_guaranteed"))
        } else {
            finding
        }
    } else if automatic + uncertain >= needed || detail["blocker_ids_truncated"] == true {
        Finding::unknown(if truncated_reads {
            "reconciliation_evidence_truncated"
        } else {
            "reconciliation_evidence_unavailable"
        })
        .with_all(blocker_evidence(detail))
        .with(
            "next_observation",
            no_observation(if truncated {
                "truncated"
            } else {
                "not_assessed"
            }),
        )
    } else if authentication_blocked {
        Finding::blocked("reconciliation_authentication_failed", "review_credentials")
            .with_all(blocker_evidence(detail))
            .with("next_observation", no_observation("authentication_failed"))
    } else {
        Finding::blocked(
            if detail["scope"] == "account" {
                "unbound_uncertainty"
            } else {
                "no_automatic_capacity_release"
            },
            "inspect_operations",
        )
        .with_all(blocker_evidence(detail))
        .with("next_observation", no_observation("no_safe_binding"))
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
                Finding::blocked(reason, "authorize").with_all(blocker_evidence(detail))
            }
        }
        reason if let Some(kind) = floor_kind(reason, &detail["restriction_basis"]) => {
            // The primary reason can be an earlier operation-level check.
            // A later request restriction still prevents reaching eligibility.
            let primary = future(&detail["not_before"], at).or(future(&detail["next_at"], at));
            let request = future(&detail["request_restriction_at"], at);
            match primary.max(request) {
                Some(next) => {
                    let kind = if request.is_some() && request >= primary {
                        request_floor_kind(&detail["restriction_basis"])
                    } else {
                        kind
                    };
                    Finding::automatic(reason, "await_retry_eligibility", Some(next))
                        .with("retry_floor", json!(kind))
                }
                None => Finding::unknown("retry_deadline_unavailable"),
            }
        }
        "uncertain_retry_disabled" | "answer_attempt_budget_exhausted" => {
            Finding::blocked(reason, "review_participation_policy")
        }
        "generation_changed" => Finding::automatic(reason, "discard_unsent", None),
        "effect_in_flight" => {
            Finding::automatic(reason, "await_effect", future(&detail["not_before"], at))
        }
        _ => return None,
    })
}

fn lane_observation_fresh(status: &Value, lane: &str, at: i64, stale: u64) -> Option<bool> {
    if lane == "judge" {
        Some(super::judge_inventory_fresh(status, at, stale))
    } else {
        super::observation_fresh(
            status,
            lane,
            timestamp(&super::observation(status, lane)["observed_at"]),
            at,
            stale,
        )
    }
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
        .filter(|row| row["kind"] == name && row["nonblocking_for_fresh_work"] != true)
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
            detail: json!({}),
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
    let complete = super::work_complete(status, name, at, stale);
    if complete
        && name != "judge"
        && !read_only
        && phase != Some("blocked")
        && status["work"][name]["admission"]["allowed"] == true
    {
        return Finding {
            progress: "complete",
            status: "none_required",
            reason: "current_epoch_completed",
            action,
            next_at: next,
            detail: json!({}),
        };
    }
    // Current admission blockers outrank background job/receipt maintenance.
    if !read_only
        && work["admission"]["allowed"] == false
        && matches!(action, "read_job" | "read_receipt")
    {
        return blocker(status, name, work, &work["admission"], at, stale, timing)
            .unwrap_or_else(|| Finding::unknown("admission_recovery_unproven"));
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
            return Finding::unknown("reconciliation_evidence_unavailable")
                .with("next_observation", no_observation("no_safe_binding"));
        }
        let dependency = super::api::bound(status, work);
        if dependency.is_none() && status["reads_truncated"] == true {
            return Finding::unknown("reconciliation_evidence_truncated")
                .with_all(bound_evidence(None, at))
                .with("next_observation", no_observation("truncated"));
        }
        let observation = bound_observation(work);
        let due = observation.and_then(|row| future(&row["not_before"], at));
        // A bound job the server reports as unknown or expired (404) keeps
        // polling on the reconciliation schedule, but that polling is not a
        // probable resolution: the remote side may never have the job again.
        let missing = dependency.is_some_and(missing_remote_evidence)
            || observation.is_some_and(|read| read["http_status"] == 404);
        let finding = Finding::automatic("bound_reconciliation_pending", action, due)
            .with_all(bound_evidence(dependency, at))
            .with(
                "next_observation",
                observation
                    .cloned()
                    .unwrap_or_else(|| no_observation("not_assessed")),
            );
        return if missing {
            finding.with("resolution", json!("polling_not_guaranteed"))
        } else {
            finding
        };
    }
    let model = &work["model"];
    if !read_only && model.is_object() {
        if model["current_route"] == true
            && model["current_runtime"] == true
            && model["scope"] == "current_work"
            && model["state"] == "prelaunch_failed"
            && status["controller_stopped"] == false
            && fresh(
                status["effective_runtime"]["observed_at"].as_i64(),
                at,
                stale,
            )
            && let Some(
                code @ ("native_workspace_unavailable"
                | "native_workspace_capacity"
                | "native_workspace_permission"
                | "native_workspace_failure"),
            ) = model["failure_category"].as_str()
        {
            return Finding::blocked(code, "inspect_model_workspace");
        }
        if let Some(reason) = super::model_route_fault(model) {
            return Finding::blocked(reason, "review_model_configuration");
        }
        // Assignment-specific failures do not fence other eligible judgments.
        // Only current-route setup/auth evidence applies across assignments.
        if (name != "judge" || model["scope"] == "current_work")
            && matches!(
                model["state"].as_str(),
                Some(
                    "model_unknown"
                        | "superseded_model_unknown"
                        | "abandoned_model"
                        | "rejected"
                        | "retry_model"
                        | "prelaunch_failed"
                )
            )
        {
            if model["blocker"] == "model_budget_exhausted" {
                return Finding::blocked(
                    "model_attempt_budget_exhausted",
                    "inspect_model_attempts",
                );
            }
            if matches!(
                model["blocker"].as_str(),
                Some("model_uncertain_retry_disabled" | "model_uncertain_replacement_exhausted")
            ) {
                return Finding::blocked(
                    model["blocker"].as_str().unwrap(),
                    "inspect_model_attempts",
                );
            }
            if model["blocker"] == "model_preparation_reserved" {
                return Finding::automatic("model_preparation_reserved", "await_model", None);
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
                Some(false) if timestamp(&model["next_at"]).is_some() => {
                    return Finding::automatic(
                        model["blocker"].as_str().unwrap_or("model_retry_backoff"),
                        "await_retry_eligibility",
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
    if name == "judge"
        && !read_only
        && phase != Some("blocked")
        && work["admission"]["allowed"] == true
        && complete
    {
        return Finding {
            progress: "idle",
            status: "none_required",
            reason: "no_eligible_assignments_observed",
            action,
            next_at: next,
            detail: json!({}),
        };
    }
    if !read_only && reason == "model_uncertain" {
        return if action == "recover_model" {
            Finding::blocked(reason, action)
        } else {
            Finding::unknown("model_retry_evidence_unavailable")
        };
    }
    let retry = &work["retry"];
    if !read_only && work["admission"]["allowed"] == false {
        return blocker(status, name, work, &work["admission"], at, stale, timing)
            .unwrap_or_else(|| Finding::unknown("admission_recovery_unproven"));
    }
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
            return Finding::blocked("unbound_outcome_requires_evidence", "inspect_operations")
                .with("next_observation", no_observation("no_safe_binding"));
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
                    detail: json!({}),
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
                )
                .with_all(read_retry_evidence(row, at));
            }
        }
    }
    if matches!(phase, Some("answered" | "completed" | "included")) {
        match lane_observation_fresh(status, name, at, stale) {
            Some(false) => {
                return Finding::automatic(
                    "completion_evidence_stale",
                    if name == "judge" {
                        "observe_assignments"
                    } else {
                        "observe_challenge"
                    },
                    next.filter(|&deadline| deadline > at),
                );
            }
            None => return Finding::unknown("effective_policy_unavailable"),
            Some(true) => {}
        }
    }
    if read_only {
        return Finding {
            progress: "idle",
            status: "none_required",
            reason: "capability_read_only",
            action,
            next_at: next,
            detail: json!({}),
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
                    super::judge_inventory_fresh(status, at, stale)
                        && super::judge_inventory(&work["assessment"])
                            == super::JudgeInventory::Available
                }
                Some("observing") => {
                    super::observation(status, name)["epoch"].as_u64().is_some()
                        && lane_observation_fresh(status, name, at, stale) == Some(true)
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
                        .with("next_observation", identity_observation(row, at))
                }
                Some(_) => Finding::unknown("read_outcome_overdue"),
                None => Finding::unknown(identity.reason()),
            }
        } else if read_failed(row)
            && let Some(floor) = timestamp(&row["next_at"]).filter(|time| *time > at)
            && let Some(next) = identity_work_retry_at(status, at, stale)
        {
            Finding::automatic(identity.reason(), "await_identity", Some(floor.max(next)))
                .with_all(read_retry_evidence(row, at))
                .with("next_observation", identity_observation(row, at))
        } else {
            Finding::unknown(identity.reason())
        }
    } else {
        let finding = Finding::unknown(identity.reason());
        if status["reads_truncated"] == true {
            finding.with("next_observation", no_observation("truncated"))
        } else {
            finding
        }
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
                detail: json!({}),
            }
        } else if ready != Some(true) && controller.reason != "controller_stopped" {
            Finding {
                progress: controller.progress,
                status: controller.status,
                reason: controller.reason,
                action: controller.action,
                next_at: None,
                detail: json!({}),
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
            && finding.detail.get("next_observation").is_none()
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
                detail: finding.detail,
            }
            .with_all(identity.detail.clone());
        }
        if !work[name].is_object() {
            work[name] = json!({});
        }
        if name == "judge"
            && work[name]["reason"] == "no_eligible_in_observed_inventory"
            && lane_stale.is_none_or(|stale| !super::judge_inventory_fresh(status, at, stale))
        {
            work[name]["reason"] = json!("work_evidence_unavailable");
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
        work[name]["intervention"]["observation_fresh"] =
            json!(lane_stale.and_then(|stale| lane_observation_fresh(status, name, at, stale)));
    }
    let core = controller.value(observed, current);
    let mut root = core.clone();
    root["controller"] = json!({"ready":ready,"reason":controller.reason,"observed_at":observed,
        "evidence_fresh":current,"process_identity":status["process_identity"].as_str().unwrap_or("not_assessed")});
    reduce(
        &mut root,
        &work,
        &core,
        &status["effective_runtime"]["policy"]["capabilities"],
        &status["paused"],
    );
    (work, root)
}

/// Reconcile action guidance with the shared readiness result. Background
/// recovery stays visible separately and never wins the primary recommendation.
pub(super) fn qualify_operational(report: &mut Value, status: &Value) {
    let observed = report["checked_at"].as_i64();
    for name in LANES {
        let component = &report["components"][name];
        let state = component["state"].as_str().unwrap_or("unknown");
        let reason = component["reasons"][0]
            .as_str()
            .unwrap_or("work_evidence_unavailable");
        let existing = &report["work"][name]["intervention"];
        let replacement = match reason {
            "model_work_overdue" | "dispatch_outcome_uncertain" => Some(Finding {
                progress: "blocked",
                status: "undetermined",
                reason: "in_flight_outcome_overdue",
                action: "inspect_operations",
                next_at: None,
                detail: json!({}),
            }),
            "pending_model_execution_expired" => Some(Finding::unknown(reason)),
            "pending_work_overdue" => Some(Finding {
                progress: "blocked",
                status: "undetermined",
                reason,
                action: "inspect_operations",
                next_at: None,
                detail: json!({}),
            }),
            "model_attempt_budget_exhausted"
            | "model_uncertain_retry_disabled"
            | "model_uncertain_replacement_exhausted" => {
                Some(Finding::blocked(reason, "inspect_model_attempts"))
            }
            "current_work_outcome_unresolved"
                if existing["status"] != "operator_required"
                    && existing["status"] != "automatic_recovery" =>
            {
                Some(Finding::blocked(reason, "inspect_operations"))
            }
            "work_evidence_unavailable" if existing["reason"] == "completion_evidence_stale" => {
                None
            }
            _ if state == "unknown"
                && matches!(
                    reason,
                    "work_evidence_unavailable"
                        | "admission_evidence_unavailable"
                        | "model_deadline_unavailable"
                        | "clock_regressed"
                )
                && existing["status"] != "operator_required" =>
            {
                Some(Finding::unknown(reason))
            }
            _ => None,
        };
        let override_observation = matches!(
            reason,
            "model_work_overdue"
                | "dispatch_outcome_uncertain"
                | "pending_model_execution_expired"
                | "pending_work_overdue"
                | "clock_regressed"
        );
        let replacement =
            replacement.map(|finding| (finding.progress, finding.value(observed, None)));
        if let Some((progress, Value::Object(fields))) = replacement {
            report["work"][name]["progress"] = json!(progress);
            let intervention = report["work"][name]["intervention"]
                .as_object_mut()
                .expect("projected intervention");
            if override_observation {
                intervention.remove("next_observation");
            }
            intervention.extend(fields);
        }
        let mut count = 0_u64;
        let mut bound = 0_u64;
        let mut selected = None;
        let mut missing = None;
        for row in status["pending_work"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["kind"] == name && row["nonblocking_for_fresh_work"] == true)
        {
            count += 1;
            if matches!(row["read_key"]["purpose"].as_str(), Some("job" | "receipt")) {
                bound += 1;
                if let (Some(at), Some(observation)) = (observed, bound_observation(row)) {
                    selected = earlier_observation(selected, observation, at);
                    if observation["http_status"] == 404 {
                        missing = earlier_observation(missing, observation, at);
                    }
                }
            }
        }
        report["work"][name]["background_recovery"] = json!({
            "count":count,"bound_count":bound,"unbound_count":count-bound,
            "required_for_participation":false,
            "next_action":if bound > 0 {"await_reconciliation"} else if count > 0 {"inspect_operations"} else {"none"},
            "next_at":selected.and_then(|row| observed.and_then(|at| future(&row["not_before"], at))),
            "evidence":"retained_outcomes_not_retry_authority",
        });
        if let Some(observation) = selected {
            report["work"][name]["background_recovery"]["next_observation"] = observation.clone();
        } else if bound > 0 && status["reads_truncated"] == true {
            report["work"][name]["background_recovery"]["next_observation"] =
                no_observation("truncated");
        }
        if let Some(observation) = missing.filter(|row| Some(*row) != selected) {
            report["work"][name]["background_recovery"]["missing_observation"] =
                observation.clone();
        }
    }
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

fn rank(status: &str) -> u8 {
    match status {
        "operator_required" => 3,
        "undetermined" => 2,
        "automatic_recovery" => 1,
        _ => 0,
    }
}

fn select(root: &mut Value, finding: &Value) {
    for field in ["status", "reason", "next_action", "next_at", "retry_floor"] {
        root[field] = finding[field].clone();
    }
    if let Some(observation) = finding.get("next_observation") {
        root["next_observation"] = observation.clone();
    } else if let Some(root) = root.as_object_mut() {
        root.remove("next_observation");
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
            detail: json!({}),
        },
        "not_initialized" => Finding::blocked(reason, "initialize_controller"),
        "migration_pending" => Finding::blocked(reason, "complete_migration"),
        "identity_mismatch" | "api_routing_mismatch" | "config_reload_rejected" => {
            Finding::blocked(reason, "repair_config")
        }
        "controller_stopped" => Finding::blocked(reason, "start_controller"),
        "process_identity_mismatch" => Finding::blocked(reason, "inspect_managed_service"),
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
    root.as_object_mut()
        .expect("root finding")
        .remove("next_observation");
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
                    detail: json!({}),
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
            "read_key":{"owner":lane,"purpose":"job","resource":format!("{id}:1")},
            "bound_observation":{"owner":lane,"purpose":"job","operation_id":id,"binding_revision":1,
                "status":"waiting","not_before":10020,"floor_kind":"operation_poll"}})
    }

    fn direct_poll(status: &mut Value, id: i64, at: i64) {
        let work = &mut status["work"]["answer"];
        let projected = queued(id, "answer");
        for key in [
            "read_key",
            "binding_revision",
            "operation_id",
            "bound_observation",
        ] {
            work[key] = projected[key].clone();
        }
        work["bound_observation"]["not_before"] = json!(at);
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
        status["pending_work"][0]["retry_not_before"] = json!(15000);
        status["pending_work"][0]["bound_observation"]["not_before"] = json!(10090);
        status["pending_work"][0]["bound_observation"]["floor_kind"] =
            json!("reconciliation_service");
        status["pending_work"][0]["nonblocking_for_fresh_work"] = json!(true);
        block(
            &mut status,
            "answer",
            "account_uncertainty",
            "account",
            &[1],
            1,
        );
        status["work"]["answer"]["admission"]["own_remaining"] = json!(4);
        let (work, root) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        assert_eq!(work["answer"]["admission"]["own_remaining"], 4);
        let next = &work["answer"]["intervention"]["next_observation"];
        assert_eq!(next["owner"], "judge");
        assert_eq!(next["purpose"], "job");
        assert_eq!(next["not_before"], 10090);
        assert_eq!(next["floor_kind"], "reconciliation_service");
        assert_eq!(&root["next_observation"], next);
        status["pending_work"][0]["read_key"] = Value::Null;
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "unbound_uncertainty"
        );
        let (work, _) = projection(&status);
        let next = &work["answer"]["intervention"]["next_observation"];
        assert_eq!(next["status"], "no_safe_binding");
        assert!(next["purpose"].is_null());
    }

    #[test]
    fn authentication_and_backoff_are_exact_operation_binding_dependencies() {
        let mut status = fixture();
        status["pending_work"] = json!([queued(1, "answer"), queued(2, "answer")]);
        status["pending_work"][1]["bound_observation"]["not_before"] = json!(10030);
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
        direct_poll(&mut status, 1, 10100);
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
    fn diagnostics_wait_for_the_latest_admission_floor_and_report_its_source() {
        let mut status = fixture();
        block(
            &mut status,
            "answer",
            "operation_backoff",
            "operation",
            &[],
            0,
        );
        status["work"]["answer"]["admission"]["not_before"] = json!(10010);
        for (basis, kind) in [
            ("server_retry_after", "server_restriction"),
            ("local_unscoped_429_cooldown", "local_backoff"),
            ("retained_legacy_floor", "retained_floor"),
            ("", "shared_restriction"),
        ] {
            let admission = &mut status["work"]["answer"]["admission"];
            admission["request_restriction_at"] = json!(10020);
            admission["restriction_basis"] = json!(basis);
            let (work, _) = projection(&status);
            let finding = &work["answer"]["intervention"];
            assert_eq!(finding["reason"], "operation_backoff");
            assert_eq!(finding["retry_floor"], kind);
            assert_eq!(finding["next_at"], 10020);
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
        status["work"]["answer"]["model"]["blocker"] = json!("model_budget_exhausted");
        status["work"]["answer"]["model"]["retry_eligible"] = json!(false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["reason"],
            "model_attempt_budget_exhausted"
        );
        status["work"]["answer"]["model"]["budget_used"] = json!(1);
        status["work"]["answer"]["model"]["blocker"] = json!("model_uncertain_retry_disabled");
        status["work"]["answer"]["model"]["retry_eligible"] = json!(false);
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["next_action"],
            "inspect_model_attempts"
        );
        status["work"]["answer"]["model"]["blocker"] = Value::Null;
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
    fn local_workspace_failures_require_host_inspection_not_model_recovery() {
        for code in [
            "native_workspace_unavailable",
            "native_workspace_capacity",
            "native_workspace_permission",
            "native_workspace_failure",
        ] {
            let mut status = fixture();
            status["work"]["answer"]["model"] = json!({
                "state":"prelaunch_failed","retry_eligible":true,
                "scope":"current_work","current_route":true,"current_runtime":true,
                "failure_category":code
            });
            let (work, _) = projection(&status);
            assert_eq!(work["answer"]["intervention"]["reason"], code);
            assert_eq!(
                work["answer"]["intervention"]["status"],
                "operator_required"
            );
            assert_eq!(
                work["answer"]["intervention"]["next_action"],
                "inspect_model_workspace"
            );
            assert!(work["answer"]["intervention"]["next_at"].is_null());
            status["work"]["answer"]["model"]["current_route"] = json!(false);
            assert_eq!(
                projection(&status).0["answer"]["intervention"]["reason"],
                "model_retry_eligible"
            );
            status["work"]["answer"]["model"]["current_route"] = json!(true);
            for (field, value) in [
                ("current_runtime", json!(false)),
                ("scope", json!("historical_assignment")),
                ("state", json!("confirmed")),
            ] {
                let mut changed = status.clone();
                changed["work"]["answer"]["model"][field] = value;
                assert_ne!(
                    projection(&changed).0["answer"]["intervention"]["next_action"],
                    "inspect_model_workspace"
                );
            }
        }
    }

    #[test]
    fn model_unbounded_retry_uses_canonical_cooldown_and_uncertainty_limits() {
        let mut status = fixture();
        status["work"]["answer"]["model"] = json!({
            "state":"retry_model","budget_used":9000,"budget_limit":"unbounded",
            "retry_eligible":false,"scope":"current_work",
            "blocker":"model_retry_cooldown","next_at":12000
        });
        let work = projection(&status).0;
        assert_eq!(
            work["answer"]["intervention"]["status"],
            "automatic_recovery"
        );
        assert_eq!(work["answer"]["intervention"]["next_at"], 12000);
        status["work"]["answer"]["model"]["next_at"] = Value::Null;
        status["work"]["answer"]["model"]["blocker"] =
            json!("model_uncertain_replacement_exhausted");
        assert_eq!(
            projection(&status).0["answer"]["intervention"]["status"],
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
        let (work, _) = projection(&status);
        assert_eq!(
            work["answer"]["intervention"]["next_observation"]["owner"],
            "account"
        );
        assert_eq!(
            work["answer"]["intervention"]["next_observation"]["purpose"],
            "identity"
        );
        assert!(work["answer"]["intervention"]["next_observation"]["operation_id"].is_null());
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

    #[test]
    fn valid_binding_without_a_read_keeps_its_first_poll() {
        let mut status = fixture();
        status["work"]["answer"]["phase"] = json!("queued");
        status["work"]["answer"]["next_action"] = json!("read_job");
        direct_poll(&mut status, 9, 10020);
        status["reads"] = json!([]);
        let intervention = projection(&status).0["answer"]["intervention"].clone();
        assert_eq!(intervention["status"], "automatic_recovery");
        assert_eq!(intervention["reason"], "bound_reconciliation_pending");
        assert_eq!(intervention["bound_missing"], true);
        assert_eq!(intervention["next_observation"]["not_before"], 10020);
    }

    #[test]
    fn bound_job_404_polls_without_promising_resolution() {
        let mut status = fixture();
        status["work"]["answer"]["phase"] = json!("queued");
        status["work"]["answer"]["next_action"] = json!("read_job");
        direct_poll(&mut status, 1, 10070);
        status["reads"] = json!([
            {"owner":"answer","purpose":"job","resource":"1:1","binding_revision":1,
                "last_failure_at":9999,"status":404,"failure_category":"not_found",
                "next_at":10070,"local_next_at":10020,"server_not_before":10040,
                "retained_conservative_floor":10050,"shared_local_not_before":10060,
                "shared_server_not_before":10070,"shared_not_before":10070}
        ]);
        let intervention = projection(&status).0["answer"]["intervention"].clone();
        assert_eq!(intervention["status"], "automatic_recovery");
        assert_eq!(intervention["reason"], "bound_reconciliation_pending");
        assert_eq!(intervention["resolution"], "polling_not_guaranteed");
        assert_eq!(intervention["bound_missing"], false);
        assert_eq!(intervention["bound_read_status"], 404);
        assert_eq!(intervention["bound_read_category"], "not_found");
        assert_eq!(intervention["server_floor_at"], 10070);
        assert_eq!(intervention["local_retry_at"], 10060);
        assert_eq!(intervention["retained_floor_at"], 10050);
        assert_eq!(intervention["next_at"], 10070);
    }

    #[test]
    fn expired_retry_floor_is_stale_evidence_not_a_wait() {
        let mut status = fixture();
        block(
            &mut status,
            "answer",
            "shared_server_restriction",
            "account",
            &[],
            0,
        );
        status["work"]["answer"]["admission"]["not_before"] = json!(9000);
        let intervention = projection(&status).0["answer"]["intervention"].clone();
        assert_eq!(intervention["status"], "undetermined");
        assert_eq!(intervention["reason"], "retry_deadline_unavailable");
        assert!(intervention["retry_floor"].is_null());
        assert!(intervention["next_at"].is_null());
    }

    #[test]
    fn release_path_names_the_store_blockers_it_counts() {
        let mut status = fixture();
        status["pending_work"] = json!([queued(1, "answer")]);
        status["reads"] = json!([
            {"owner":"answer","purpose":"job","resource":"1:1","binding_revision":1,
                "last_failure_at":9999,"status":404,"next_at":10030}
        ]);
        block(
            &mut status,
            "answer",
            "lane_unresolved_capacity",
            "lane",
            &[1],
            1,
        );
        let intervention = projection(&status).0["answer"]["intervention"].clone();
        assert_eq!(intervention["status"], "automatic_recovery");
        assert_eq!(intervention["resolution"], "polling_not_guaranteed");
        assert_eq!(intervention["blocker_ids"], json!([1]));
        assert_eq!(intervention["required_release"], 1);
        assert_eq!(intervention["release_scope"], "lane");
        assert_eq!(intervention["release_truncated"], Value::Null);
    }
}
