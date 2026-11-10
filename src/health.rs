//! Read-only, local health evidence with a versioned, bounded component contract.
//! Component readiness is separate from retained effect risk and never authorizes
//! replay. Effective modes and fresh local evidence are not live remote probes.
use crate::{
    config::{Config, Mode, WorkKind},
    runtime,
    store::now,
};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

mod api;
mod intervention;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub stale_seconds: u64,
    pub work_seconds: u64,
    pub answer_grace_seconds: u64,
    pub expect_participation: bool,
    pub min_free_mib: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            stale_seconds: 180,
            work_seconds: 1800,
            answer_grace_seconds: 900,
            expect_participation: true,
            min_free_mib: 128,
        }
    }
}

/// Add local progress and intervention evidence without changing admission or risk.
/// Status uses default thresholds; health and doctor use their selected options.
pub fn enrich_status(status: &mut Value, options: Options, at: i64) {
    let (work, intervention) = intervention::project(status, options, at);
    status["work"] = work;
    status["intervention"] = intervention;
}

/// Stable diagnostic shapes when configuration or journal evidence is unavailable.
pub fn unknown_intervention(reason: &str) -> Value {
    intervention::unknown(reason)
}

pub fn unknown_work(reason: &str) -> Value {
    intervention::unknown_work(reason)
}

/// This command opens existing state read-only, never recovers it, and performs
/// neither network nor model calls. Errors are deliberately replaced at this boundary.
pub fn check(config: &Config, options: Options) -> Result<Value> {
    let status = match runtime::status(config) {
        Ok(status) => status,
        Err(_) => {
            return Ok(json!({
                "contract_version":1,"components":unknown_components(),
                "work":unknown_work("local_evidence_unavailable"),
                "intervention":unknown_intervention("local_evidence_unavailable"),
                "healthy":false,"attention_required":true,
                "issues":["local_evidence_unavailable"],"warnings":[],
                "operational":{"status":"unknown","issues":["local_evidence_unavailable"]},
                "risk":{"status":"unknown","attention_required":null,"unresolved_effects":null,"unresolved_model_attempts":null},
                "evidence":"local_only","mutations":false
            }));
        }
    };
    let mut result = evaluate(config, options, &status, now());
    if options.min_free_mib != 0 {
        let available = available_mib(&config.state_dir).ok();
        let issue = match available {
            Some(mib) if mib < options.min_free_mib => Some("state_disk_space_low"),
            None => Some("state_disk_space_unavailable"),
            _ => None,
        };
        result["state_free_mib"] = json!(available);
        if available.is_some_and(|mib| mib < options.min_free_mib.saturating_mul(4).max(512)) {
            result["warnings"]
                .as_array_mut()
                .expect("health warnings array")
                .push(json!("state_disk_headroom_low"));
        }
        if let Some(code) = issue {
            apply_disk_issue(&mut result, code);
        }
    }
    result["thresholds"]["min_free_mib"] = json!(options.min_free_mib);
    result["thresholds"]["warn_free_mib"] = json!(if options.min_free_mib == 0 {
        0
    } else {
        options.min_free_mib.saturating_mul(4).max(512)
    });
    result["attention_required"] = json!(
        result["healthy"].as_bool() != Some(true)
            || result["warnings"]
                .as_array()
                .is_some_and(|warnings| !warnings.is_empty())
    );
    Ok(result)
}

#[cfg(unix)]
fn available_mib(path: &std::path::Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    // Before initialization, inspect the closest existing ancestor without
    // creating it. statvfs follows the filesystem actually containing state.
    let mut existing = path;
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| anyhow!("state filesystem unavailable"))?;
    }
    let path = std::ffi::CString::new(existing.as_os_str().as_bytes())
        .map_err(|_| anyhow!("state filesystem unavailable"))?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated; statvfs initializes info on success.
    if unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err(anyhow!("state filesystem unavailable"));
    }
    let info = unsafe { info.assume_init() };
    let bytes = (info.f_bavail as u128).saturating_mul(info.f_frsize as u128);
    Ok((bytes / (1024 * 1024)).min(u64::MAX as u128) as u64)
}

#[cfg(not(unix))]
fn available_mib(_path: &std::path::Path) -> Result<u64> {
    Err(anyhow!("state filesystem unavailable"))
}
fn age(value: &Value, at: i64) -> Option<u64> {
    value
        .as_i64()
        .map(|time| at.saturating_sub(time).max(0) as u64)
}

fn model_overdue(work: &Value, at: i64, poll: u64, fallback: Option<u64>) -> Option<bool> {
    if let Some(deadline) = work["model_deadline"].as_i64() {
        return Some(at > deadline.saturating_add(poll as i64));
    }
    Some(age(&work["created_at"], at)? > fallback?)
}

struct WorkTiming {
    http: u64,
    shutdown: u64,
    poll: u64,
    model: Option<u64>,
    pending: u64,
}

impl WorkTiming {
    fn issue(&self, work: &Value, at: i64) -> Option<&'static str> {
        match work["state"].as_str() {
            Some("unknown") => None,
            Some("generating") => (model_overdue(work, at, self.poll, self.model) == Some(true))
                .then_some("model_work_overdue"),
            Some("dispatching")
                if work["http_deadline"].as_i64().map_or(
                    age(&work["updated_at"], at).is_some_and(|seconds| {
                        seconds > self.http.saturating_add(self.shutdown).saturating_add(1)
                    }),
                    |deadline| at > deadline.saturating_add(self.shutdown as i64),
                ) =>
            {
                Some("dispatch_outcome_uncertain")
            }
            Some(_)
                if age(&work["created_at"], at).is_some_and(|seconds| seconds > self.pending) =>
            {
                Some("pending_work_overdue")
            }
            _ => None,
        }
    }
}

fn cycle_floor(policy: &Value) -> Option<u64> {
    let http = policy["timeouts"]["http_seconds"].as_u64()?;
    Some(
        http.max(
            policy["timeouts"]["read_http_seconds"]
                .as_u64()
                .unwrap_or(http),
        )
        .saturating_add(policy["schedule"]["poll_seconds"].as_u64()?)
        .saturating_add(policy["schedule"]["jitter_seconds"].as_u64()?)
        .saturating_add(policy["timeouts"]["shutdown_seconds"].as_u64()?)
        .saturating_add(1),
    )
}

fn evaluate(config: &Config, options: Options, status: &Value, at: i64) -> Value {
    // Use the running controller's policy, not a newly edited desired config.
    // Native inference is independent and no longer expands heartbeat grace.
    let policy = &status["effective_runtime"]["policy"];
    let floor = cycle_floor(policy);
    let timing_known = floor.is_some();
    let http = policy["timeouts"]["http_seconds"].as_u64().unwrap_or(0);
    let read_http = policy["timeouts"]["read_http_seconds"]
        .as_u64()
        .unwrap_or(http);
    let poll = policy["schedule"]["poll_seconds"].as_u64().unwrap_or(0);
    let shutdown = policy["timeouts"]["shutdown_seconds"].as_u64().unwrap_or(0);
    let cycle_floor = floor.unwrap_or(0);
    let stale = options.stale_seconds.max(cycle_floor);
    let work_limit = options.work_seconds.max(cycle_floor);
    let grace = options.answer_grace_seconds.max(cycle_floor);
    let model_limit = match (
        policy["timeouts"]["model_seconds"].as_u64(),
        policy["timeouts"]["shutdown_seconds"].as_u64(),
        policy["schedule"]["poll_seconds"].as_u64(),
        policy["schedule"]["jitter_seconds"].as_u64(),
    ) {
        (Some(model), Some(shutdown), Some(poll), Some(jitter)) => Some(
            model
                .saturating_add(shutdown)
                .saturating_add(poll)
                .saturating_add(jitter)
                .saturating_add(1),
        ),
        _ => None,
    };
    let initialized = status["initialized"].as_bool() == Some(true);
    let paused = status["paused"].as_bool() != Some(false);
    let effective = &status["effective_runtime"];
    let effective_mode = |kind: WorkKind| {
        effective["capabilities"][kind.as_str()]
            .as_str()
            .map(|mode| mode == "active")
            .unwrap_or(config.mode(kind) == Mode::Active)
    };
    let active = [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine]
        .iter()
        .any(|kind| effective_mode(*kind));
    let heartbeat_age = age(&effective["observed_at"], at);
    let observation_age = age(&status["observation"]["observed_at"], at);
    let epoch_age = age(&status["epoch_evidence"]["first_observed_at"], at);
    let pending = &status["pending"];
    let pending_age = age(&pending["created_at"], at);
    let mut issues = Vec::<&str>::new();
    let mut warnings = Vec::<&str>::new();
    if !initialized {
        issues.push("not_initialized");
    }
    if initialized && !timing_known {
        issues.push("effective_policy_unavailable");
    }
    if status["identity_matches_config"].as_bool() == Some(false) {
        issues.push("identity_mismatch");
    }
    if status["network_routing"]["matches_config"].as_bool() == Some(false) {
        issues.push("api_routing_mismatch");
    }
    if status["hosted_identity_verified"].as_bool() == Some(false) {
        issues.push("hosted_identity_unverified");
    } else if status["hosted_identity_verified"].as_bool().is_none() && !paused && active {
        issues.push("hosted_identity_unobserved");
    }
    if status["controller_stopped"].as_bool() == Some(true) {
        issues.push("controller_stopped");
    }
    match heartbeat_age {
        None => issues.push("controller_unobserved"),
        Some(seconds) if timing_known && seconds > stale => issues.push("controller_stale"),
        _ => {}
    }
    if effective["observed_at"]
        .as_i64()
        .is_some_and(|time| time > at)
        || status["observation"]["observed_at"]
            .as_i64()
            .is_some_and(|time| time > at)
    {
        issues.push("clock_regressed");
    }
    if options.expect_participation {
        if paused {
            issues.push("participation_paused");
        }
        if effective["reload_blocked"].as_bool() == Some(true) {
            issues.push("reload_blocked");
        }
        if !active {
            issues.push("no_active_capabilities");
        }
    }
    let timing = WorkTiming {
        http,
        shutdown,
        poll,
        model: model_limit,
        pending: work_limit,
    };
    // The representative oldest pending row must not hide later overdue work.
    for work in
        std::iter::once(pending).chain(status["pending_work"].as_array().into_iter().flatten())
    {
        if work["state"] == "unknown" && !warnings.contains(&"pending_outcome_uncertain") {
            warnings.push("pending_outcome_uncertain");
        } else if work["state"] == "generating"
            && model_overdue(work, at, poll, model_limit).is_none()
            && !warnings.contains(&"model_deadline_unavailable")
        {
            warnings.push("model_deadline_unavailable");
        }
        if timing_known
            && let Some(issue) = timing.issue(work, at)
            && !issues.contains(&issue)
        {
            issues.push(issue);
        }
    }
    let answer_expected = options.expect_participation && effective_mode(WorkKind::Answer);
    if answer_expected {
        match observation_age {
            None => issues.push("challenge_unobserved"),
            Some(seconds) if timing_known && seconds > stale => {
                issues.push("challenge_observation_stale")
            }
            _ => {}
        }
        if timing_known
            && status["epoch_evidence"]["answered"].as_bool() == Some(false)
            && epoch_age.is_some_and(|seconds| seconds > grace)
            && observation_age.is_some_and(|seconds| seconds <= stale)
        {
            issues.push("current_epoch_unanswered");
        }
        if status["epoch_evidence"]["answered"].as_bool().is_none() {
            issues.push("answer_evidence_unavailable");
        }
    }
    let unresolved_models = status["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| {
            matches!(
                row["state"].as_str(),
                Some("model_unknown" | "superseded_model_unknown")
            )
        })
        .fold(0_u64, |total, row| {
            total.saturating_add(row["count"].as_u64().unwrap_or(0))
        });
    if unresolved_models > 0 {
        warnings.push("model_execution_unresolved");
    }
    if status["participation"]["unresolved_count"]
        .as_u64()
        .unwrap_or(0)
        > 0
        && status["participation"]["risk_admissions"]
            .as_u64()
            .unwrap_or(0)
            > 0
    {
        warnings.push("participation_risk_admitted");
    }
    let preparing = status["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|row| row["state"] == "generating" && row["count"].as_u64().unwrap_or(0) > 0);
    for work in status["captured_work"].as_array().into_iter().flatten() {
        if !timing_known || work["state"] != "generating" {
            continue;
        }
        match model_overdue(work, at, poll, model_limit) {
            Some(true) if !issues.contains(&"model_work_overdue") => {
                issues.push("model_work_overdue")
            }
            None if !warnings.contains(&"model_deadline_unavailable") => {
                warnings.push("model_deadline_unavailable")
            }
            _ => {}
        }
    }
    // Health measures operational readiness; uncertainty remains explicit risk.
    // "clear" is not a guarantee of remote availability or successful submission.
    let admission = status["admission_blocked"].as_bool();
    let operational_status = if issues == ["effective_policy_unavailable"] {
        "unknown"
    } else if !issues.is_empty() {
        "degraded"
    } else if admission == Some(true) {
        "blocked"
    } else if admission == Some(false) {
        "clear"
    } else {
        "unknown"
    };
    if admission == Some(true) {
        issues.push("admission_blocked");
    } else if admission.is_none() {
        issues.push("admission_unobserved");
    }
    let risk_attention = issues.contains(&"dispatch_outcome_uncertain")
        || warnings.iter().any(|code| {
            matches!(
                *code,
                "pending_outcome_uncertain"
                    | "model_execution_unresolved"
                    | "participation_risk_admitted"
            )
        });
    let attention_required = !issues.is_empty() || !warnings.is_empty();
    let (work, intervention) = intervention::project(status, options, at);
    let mut result = json!({"healthy":issues.is_empty(),"checked_at":at,"issues":issues,
        "warnings":warnings,"attention_required":attention_required,
        "unresolved_model_attempts":unresolved_models,
        "initialized":initialized,"paused":paused,"expect_participation":options.expect_participation,
        "controller_stopped":status["controller_stopped"].as_bool().unwrap_or(false),
        "hosted_identity_verified":status["hosted_identity_verified"].as_bool(),
        "heartbeat_age_seconds":heartbeat_age,"observation_age_seconds":observation_age,
        "heartbeat_recent":heartbeat_age.is_some_and(|age|age<=stale),
        "observing":observation_age.is_some_and(|age|age<=stale),"preparing":preparing,
        "last_safety_observation_at":status["last_safety_observation_at"],
        "work":work,"intervention":intervention,
        "captured_work":status["captured_work"],
        "pending_work":status["pending_work"],
        "epoch_observed_age_seconds":epoch_age,"pending_age_seconds":pending_age,
        "admission_blocked":admission,
        "oldest_unresolved_operation":status["oldest_unresolved_operation"],
        "oldest_unresolved_since":status["oldest_unresolved_since"],
        "oldest_unresolved_age_seconds":age(&status["oldest_unresolved_since"],at),
        "affected_capabilities":status["affected_capabilities"],
        "progress_age_seconds":age(&status["last_progress_at"],at),
        "desired_capabilities":config.capabilities,"effective_capabilities":effective["capabilities"],
        "participation":status["participation"],"desired_participation":config.participation,
        "last_reported_build":status["last_reported_build"],"process_identity":"unverified",
        "evidence":"local_only","notifications":"local_exit_status_and_journal"});
    result["current_epoch"] = json!({"epoch":status["observation"]["epoch"].as_u64(),
        "answered":status["epoch_evidence"]["answered"].as_bool(),
        "evidence_fresh":timing_known.then(|| observation_age.is_some_and(|age|age<=stale)
            && status["observation"]["observed_at"].as_i64().is_some_and(|time| time<=at)),
        "evidence":"last_local_observation_not_a_live_remote_check"});
    result["thresholds"] = json!({"stale_seconds":stale,"work_seconds":work_limit,
        "answer_grace_seconds":grace,"model_seconds":model_limit,
        "cycle_floor_seconds":timing_known.then_some(cycle_floor),
        "read_http_seconds":timing_known.then_some(read_http),
        "write_http_seconds":timing_known.then_some(http),
        "timing_source":if timing_known {"effective"} else {"unavailable"}});
    result["operational"] = json!({"status":operational_status,"issues":issues,
        "evidence":"local_only_not_a_submission_guarantee"});
    result["risk"] = json!({"attention_required":risk_attention,
        "unresolved_effects":status["participation"]["unresolved_count"].as_u64(),
        "active_unresolved_effects":status["participation"]["active_unresolved_count"].as_u64(),
        "historical_unknown_answers":status["participation"]["historical_unknown_answer_count"].as_u64(),
        "historical_eligible_answers":status["participation"]["historical_eligible_count"].as_u64(),
        "capacity_exempt_answers":status["participation"]["capacity_exempt_count"].as_u64(),
        "unresolved_model_attempts":unresolved_models});
    result["contract_version"] = json!(1);
    result["components"] = components(status, &result, at, stale, &timing);
    result
}

fn apply_disk_issue(result: &mut Value, code: &str) {
    result["issues"]
        .as_array_mut()
        .expect("health issues array")
        .push(json!(code));
    result["healthy"] = json!(false);
    result["operational"]["status"] = json!("degraded");
    result["operational"]["issues"]
        .as_array_mut()
        .expect("operational health issues array")
        .push(json!(code));
    let intervention = &mut result["intervention"];
    intervention["status"] = json!(if code == "state_disk_space_low" {
        "operator_required"
    } else {
        "undetermined"
    });
    intervention["reason"] = json!(code);
    intervention["next_action"] = json!("inspect_state_filesystem");
    intervention["next_at"] = Value::Null;
    intervention["unattended"] = if code == "state_disk_space_low" {
        json!(false)
    } else {
        Value::Null
    };
    for name in ["controller", "answer", "judge", "mine"] {
        let row = &mut result["components"][name];
        if row["state"] == "ok" {
            row["state"] = json!("degraded");
            row["next_actions"] = inspection_actions();
        }
        if row["state"] != "disabled" {
            row["reasons"]
                .as_array_mut()
                .expect("component reasons")
                .push(json!(code));
        }
    }
}

fn component(state: &str, reason: &str, observed: Option<i64>, at: i64) -> Value {
    json!({
        "state":state,"reasons":[reason],"observed_at":observed,
        "age_seconds":observed.filter(|time| *time <= at).map(|time| at.saturating_sub(time) as u64),
        "next_actions":if state == "ok" || state == "disabled" {
            json!([])
        } else {
            inspection_actions()
        }
    })
}

fn inspection_actions() -> Value {
    json!([{"kind":"instruction","authorization_required":false,
        "message":"Inspect agmi status and agmi health using the same selected configuration; these commands read local evidence only."}])
}

/// A stable shape for unavailable local evidence; this grants no replay authority.
pub fn unknown_components() -> Value {
    let mut value = json!({"api":api::unknown()});
    for name in ["controller", "answer", "judge", "mine"] {
        value[name] = component("unknown", "local_evidence_unavailable", None, 0);
        if name != "controller" {
            value[name]["mode"] = Value::Null;
        }
    }
    value
}

fn fresh(timestamp: Option<i64>, at: i64, stale: u64) -> bool {
    timestamp.is_some_and(|time| time <= at && at.saturating_sub(time) as u64 <= stale)
}

fn components(status: &Value, health: &Value, at: i64, stale: u64, timing: &WorkTiming) -> Value {
    let effective = &status["effective_runtime"];
    let observed = effective["observed_at"].as_i64();
    let active = ["answer", "judge", "mine"]
        .iter()
        .any(|name| effective["capabilities"][name] == "active");
    let controller_issue = if status["initialized"] != true {
        Some(("unknown", "not_initialized"))
    } else if status["identity_matches_config"] == false {
        Some(("blocked", "identity_mismatch"))
    } else if status["network_routing"]["matches_config"] == false {
        Some(("blocked", "api_routing_mismatch"))
    } else if status["hosted_identity_verified"] == false {
        Some(("blocked", "hosted_identity_unverified"))
    } else if status["controller_stopped"] == true {
        Some(("blocked", "controller_stopped"))
    } else if status["paused"] == true && active {
        Some(("blocked", "participation_paused"))
    } else if effective["reload_blocked"] == true {
        Some(("blocked", "reload_blocked"))
    } else if health["thresholds"]["timing_source"] != "effective" {
        Some(("unknown", "effective_policy_unavailable"))
    } else if observed.is_some_and(|time| time > at) {
        Some(("unknown", "clock_regressed"))
    } else if observed.is_none() {
        Some(("unknown", "controller_unobserved"))
    } else if !fresh(observed, at, stale) {
        Some(("unknown", "controller_stale"))
    } else if status["hosted_identity_verified"].is_null() && active {
        Some(("unknown", "hosted_identity_unobserved"))
    } else if status["paused"].as_bool().is_none()
        || status["identity_matches_config"].as_bool().is_none()
    {
        Some(("unknown", "controller_evidence_unavailable"))
    } else {
        None
    };
    let (state, reason) = controller_issue.unwrap_or(("ok", "controller_recent"));
    let controller = component(state, reason, observed, at);
    let apis = api::evaluate(&status["reads"], at, stale);
    let mut value = json!({"controller":controller,"api":apis});
    for name in ["answer", "judge", "mine"] {
        let mode = effective["capabilities"][name].as_str();
        let work = &status["work"][name];
        let scope = if name == "judge" {
            "assignments"
        } else {
            "challenge"
        };
        let primary = &value["api"][scope];
        let observation = if name == "judge" {
            work["selection"]["observed_at"].as_i64()
        } else {
            status["observation"]["observed_at"].as_i64()
        };
        let evidence_at = observation.or(primary["observed_at"].as_i64());
        // Decide with borrowed codes; allocate each JSON component only once.
        let mut finding = ("unknown", "work_evidence_unavailable", evidence_at);
        if mode == Some("off") {
            finding = ("disabled", "capability_off", observed);
        } else if !matches!(mode, Some("active" | "read_only")) {
            finding = ("unknown", "effective_mode_unavailable", observed);
        } else if let Some((state, reason)) = controller_issue.filter(|(_, reason)| {
            mode != Some("read_only")
                || !matches!(
                    *reason,
                    "participation_paused" | "hosted_identity_unobserved"
                )
        }) {
            finding = (state, reason, observed);
        } else {
            let read_only = mode == Some("read_only");
            let admission = status["participation"]["uncertainty_blocks"][name].as_bool();
            let reserved = name != "answer" && work["admission_reservation"]["active"] == true;
            // Only explicit per-capability admission evidence can fence this row.
            // Unknown effects remain risk, not a global outage or replay permission.
            if !read_only && (admission == Some(true) || reserved || work["phase"] == "blocked") {
                finding = (
                    "blocked",
                    if admission == Some(true) {
                        "admission_blocked"
                    } else if reserved {
                        "answer_retry_reserved"
                    } else {
                        "work_blocked"
                    },
                    evidence_at,
                );
            } else {
                let complete = fresh(observation, at, stale)
                    && match name {
                        "answer" => status["epoch_evidence"]["answered"] == true,
                        "judge" => {
                            work["selection"]["inventory_complete"] == true
                                && work["selection"]["eligible"] == false
                        }
                        _ => {
                            work["phase"] == "completed"
                                && status["observation"]["epoch"].as_u64().is_some()
                                && work["operation_epoch"] == status["observation"]["epoch"]
                        }
                    };
                if read_only {
                    if primary["state"] == "ok" {
                        finding = (
                            "ok",
                            "read_only_observation_recent",
                            primary["observed_at"].as_i64(),
                        );
                    }
                } else if complete {
                    finding = (
                        "ok",
                        match name {
                            "answer" => "current_epoch_answered",
                            "judge" => "no_eligible_assignments_observed",
                            _ => "current_epoch_completed",
                        },
                        observation,
                    );
                }
                // Completed current work or idle inventory cannot hide another
                // overdue operation. Share the overall health deadline authority.
                for pending in std::iter::once(&status["pending"])
                    .chain(status["pending_work"].as_array().into_iter().flatten())
                    .chain(status["captured_work"].as_array().into_iter().flatten())
                    .filter(|pending| pending["kind"] == name)
                {
                    let timestamp = pending["updated_at"]
                        .as_i64()
                        .or(pending["created_at"].as_i64());
                    if timing.issue(pending, at).is_some() {
                        finding = ("degraded", "work_overdue", timestamp);
                        break;
                    }
                    let timely = match pending["state"].as_str() {
                        Some("generating") => {
                            model_overdue(pending, at, timing.poll, timing.model) == Some(false)
                        }
                        Some("dispatching") => {
                            pending["http_deadline"].as_i64().is_some()
                                || pending["updated_at"].as_i64().is_some()
                        }
                        Some(
                            "generated" | "prepared" | "retry" | "queued" | "included_pending",
                        ) => pending["created_at"].as_i64().is_some(),
                        _ => false,
                    };
                    if !complete
                        && !read_only
                        && timely
                        && timestamp.is_some_and(|time| time <= at)
                        && admission == Some(false)
                    {
                        finding = ("ok", "work_in_progress", timestamp);
                    }
                }
                // Challenge/assignments are capability-scoped dependencies. Other
                // APIs matter only when this work is actually waiting for them.
                let bound_scope = match work["next_action"].as_str() {
                    Some("read_receipt") => Some("receipt"),
                    Some("read_job") => Some("job"),
                    _ if matches!(
                        work["reason"].as_str(),
                        Some("identity_backoff" | "identity_in_flight")
                    ) =>
                    {
                        Some("identity")
                    }
                    _ if name == "judge"
                        && !read_only
                        && work["phase"] == "observing"
                        && (work["selection"].is_null()
                            || (work["selection"]["eligible"] == false
                                && work["selection"]["observed_count"]
                                    .as_u64()
                                    .is_some_and(|count| count > 0))) =>
                    {
                        // A failed hydration can make a nonempty inventory
                        // ineligible. Do not mistake that for healthy idle work.
                        Some("assignment_evidence")
                    }
                    _ => None,
                };
                for dependency in std::iter::once(scope).chain(bound_scope) {
                    let api = &value["api"][dependency];
                    if matches!(api["state"].as_str(), Some("degraded" | "blocked")) {
                        finding = (
                            "degraded",
                            if dependency == "assignment_evidence" {
                                "recent_assignment_evidence_failure"
                            } else {
                                "api_dependency_unavailable"
                            },
                            api["observed_at"].as_i64(),
                        );
                        break;
                    }
                }
                if name == "answer"
                    && health["issues"].as_array().is_some_and(|issues| {
                        issues
                            .iter()
                            .any(|issue| issue == "current_epoch_unanswered")
                    })
                {
                    finding = ("degraded", "current_epoch_unanswered", observation);
                }
            }
        }
        let mut row = component(finding.0, finding.1, finding.2, at);
        row["mode"] = json!(mode);
        value[name] = row;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Config, Options, Value) {
        let mut config = Config::default();
        config.capabilities.answer = Mode::Active;
        let status = json!({"initialized":true,"paused":false,"identity_matches_config":true,
            "hosted_identity_verified":true,"admission_blocked":false,
            "effective_runtime":{"observed_at":10000,"reload_blocked":false,
                "policy":{"timeouts":{"http_seconds":config.timeouts.http_seconds,
                    "shutdown_seconds":config.timeouts.shutdown_seconds},
                    "schedule":config.schedule}},
            "observation":{"observed_at":10000},
            "epoch_evidence":{"first_observed_at":10000,"answered":true},"pending":null});
        (config, Options::default(), status)
    }

    fn has(value: &Value, code: &str) -> bool {
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == code)
    }

    #[test]
    fn missing_effective_timing_cannot_be_replaced_by_desired_intervals() {
        let (mut config, options, mut status) = fixture();
        config.timeouts.http_seconds = 7200;
        config.timeouts.shutdown_seconds = 7200;
        config.schedule.poll_seconds = 7200;
        status["effective_runtime"]["capabilities"] =
            json!({"answer":"active","judge":"active","mine":"active"});
        status["effective_runtime"]["policy"] = Value::Null;
        let health = evaluate(&config, options, &status, 11000);
        assert_eq!(health["healthy"], false);
        assert!(has(&health, "effective_policy_unavailable"));
        assert_eq!(health["components"]["controller"]["state"], "unknown");
        assert_eq!(health["current_epoch"]["evidence_fresh"], Value::Null);
        assert_eq!(health["thresholds"]["timing_source"], "unavailable");
        config.timeouts.http_seconds = 1;
        config.timeouts.shutdown_seconds = 1;
        config.schedule.poll_seconds = 1;
        let changed = evaluate(&config, options, &status, 11000);
        assert_eq!(health["thresholds"], changed["thresholds"]);
    }

    #[test]
    fn hosted_identity_failure_overrides_local_match_and_fresh_challenge() {
        let (config, options, mut status) = fixture();
        status["hosted_identity_verified"] = json!(true);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], true);
        assert_eq!(health["hosted_identity_verified"], true);
        status["hosted_identity_verified"] = json!(false);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], false);
        assert_eq!(health["issues"], json!(["hosted_identity_unverified"]));
        assert_eq!(health["hosted_identity_verified"], false);
        assert!(!has(&health, "identity_mismatch"));
        assert!(has(
            &evaluate(
                &config,
                Options {
                    expect_participation: false,
                    ..options
                },
                &status,
                10000
            ),
            "hosted_identity_unverified"
        ));
        status["hosted_identity_verified"] = json!(true);
        assert_eq!(evaluate(&config, options, &status, 10000)["healthy"], true);
    }

    #[test]
    fn mine_only_requires_identity_evidence_without_inventing_failure_or_risk() {
        let (mut config, _, mut status) = fixture();
        config.capabilities.answer = Mode::Off;
        config.capabilities.judge = Mode::Off;
        config.capabilities.mine = Mode::Active;
        status["observation"] = Value::Null;
        status["hosted_identity_verified"] = Value::Null;
        status["admission_blocked"] = json!(false);
        for expect_participation in [false, true] {
            let options = Options {
                expect_participation,
                ..Options::default()
            };
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["healthy"], false);
            assert_eq!(health["issues"], json!(["hosted_identity_unobserved"]));
            assert_eq!(health["operational"]["status"], "degraded");
            assert_eq!(health["operational"]["issues"], health["issues"]);
            assert!(health["hosted_identity_verified"].is_null());
            assert_eq!(health["risk"]["attention_required"], false);
            assert_eq!(health["evidence"], "local_only");
            status["hosted_identity_verified"] = json!(true);
            let verified = evaluate(&config, options, &status, 10000);
            assert_eq!(verified["healthy"], true);
            assert_eq!(verified["operational"]["status"], "clear");
            status["hosted_identity_verified"] = Value::Null;
        }
    }

    #[test]
    fn paused_or_nonactive_modes_do_not_require_new_upstream_identity_evidence() {
        let (config, _, mut status) = fixture();
        let options = Options {
            expect_participation: false,
            ..Options::default()
        };
        status["hosted_identity_verified"] = Value::Null;
        status["paused"] = json!(true);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], true);
        assert!(health["hosted_identity_verified"].is_null());
        status["paused"] = json!(false);
        for mode in ["read_only", "off"] {
            // Effective modes, not a newly edited desired configuration, govern readiness.
            status["effective_runtime"]["capabilities"] =
                json!({"answer":mode,"judge":mode,"mine":mode});
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["healthy"], true);
            assert!(health["hosted_identity_verified"].is_null());
        }
    }

    #[test]
    fn heartbeat_floor_and_exact_boundary() {
        let (config, options, status) = fixture();
        let floor = evaluate(&config, options, &status, 10000)["thresholds"]["stale_seconds"]
            .as_u64()
            .unwrap();
        assert!(!has(
            &evaluate(&config, options, &status, 10000 + floor as i64),
            "controller_stale"
        ));
        assert!(has(
            &evaluate(&config, options, &status, 10001 + floor as i64),
            "controller_stale"
        ));
        let options = Options {
            stale_seconds: floor + 100,
            ..options
        };
        assert!(!has(
            &evaluate(&config, options, &status, 10001 + floor as i64),
            "controller_stale"
        ));
    }

    #[test]
    fn configured_stagger_does_not_trigger_a_false_stall() {
        let (mut config, options, mut status) = fixture();
        config.schedule.jitter_seconds = 0;
        status["effective_runtime"]["policy"]["schedule"]["jitter_seconds"] = json!(0);
        let floor = evaluate(&config, options, &status, 10000)["thresholds"]["stale_seconds"]
            .as_i64()
            .unwrap();
        let at = 10000 + floor + 15;
        assert!(has(
            &evaluate(&config, options, &status, at),
            "controller_stale"
        ));
        config.schedule.jitter_seconds = 30;
        assert!(has(
            &evaluate(&config, options, &status, at),
            "controller_stale"
        ));
        status["effective_runtime"]["policy"]["schedule"]["jitter_seconds"] = json!(30);
        assert!(!has(
            &evaluate(&config, options, &status, at),
            "controller_stale"
        ));
    }

    #[test]
    fn stopped_paused_and_reload_blocked_are_not_healthy() {
        let (config, options, mut status) = fixture();
        status["controller_stopped"] = json!(true);
        status["paused"] = json!(true);
        status["effective_runtime"]["reload_blocked"] = json!(true);
        let health = evaluate(&config, options, &status, 10000);
        for code in [
            "controller_stopped",
            "participation_paused",
            "reload_blocked",
        ] {
            assert!(has(&health, code));
        }
        assert!(!has(
            &evaluate(
                &config,
                Options {
                    expect_participation: false,
                    ..options
                },
                &status,
                10000
            ),
            "participation_paused"
        ));
    }

    #[test]
    fn unresolved_model_work_is_a_warning_not_a_current_mutation_blocker() {
        let (config, options, mut status) = fixture();
        status["operations"] =
            json!([{"state":"model_unknown","count":1},{"state":"confirmed","count":3}]);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], true);
        assert_eq!(health["attention_required"], true);
        assert_eq!(health["warnings"], json!(["model_execution_unresolved"]));
        assert_eq!(health["unresolved_model_attempts"], 1);
        assert_eq!(health["issues"], json!([]));
        status["pending"] = json!({"state":"unknown","created_at":10000});
        assert_eq!(
            evaluate(&config, options, &status, 10000)["warnings"],
            json!(["pending_outcome_uncertain", "model_execution_unresolved"])
        );
    }

    #[test]
    fn model_and_queue_age_cannot_be_hidden_by_recent_polls() {
        let (config, options, mut status) = fixture();
        status["pending"] =
            json!({"state":"queued","created_at":8000,"updated_at":10000,"next_at":20000});
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "pending_work_overdue"
        ));
        status["effective_runtime"]["policy"] =
            json!({"timeouts":config.timeouts,"schedule":config.schedule});
        status["pending"] = json!({"state":"generating","created_at":10000});
        let limit = evaluate(&config, options, &status, 10000)["thresholds"]["model_seconds"]
            .as_i64()
            .unwrap();
        assert!(!has(
            &evaluate(&config, options, &status, 10000 + limit),
            "model_work_overdue"
        ));
        assert!(has(
            &evaluate(&config, options, &status, 10001 + limit),
            "model_work_overdue"
        ));
    }

    #[test]
    fn answer_grace_uses_epoch_start_and_authenticated_answer_state() {
        let (config, options, mut status) = fixture();
        status["epoch_evidence"] = json!({"first_observed_at":9000,"answered":false});
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "current_epoch_unanswered"
        ));
        assert!(!has(
            &evaluate(&config, options, &status, 20000),
            "current_epoch_unanswered"
        ));
        status["epoch_evidence"]["first_observed_at"] = json!(9100);
        assert!(!has(
            &evaluate(&config, options, &status, 10000),
            "current_epoch_unanswered"
        ));
        status["epoch_evidence"]["answered"] = json!(true);
        assert!(!has(
            &evaluate(&config, options, &status, 20000),
            "current_epoch_unanswered"
        ));
        status["epoch_evidence"] = Value::Null;
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "answer_evidence_unavailable"
        ));
    }

    #[test]
    fn output_never_copies_untrusted_status_fields() {
        let (config, options, mut status) = fixture();
        status["pending"] =
            json!({"state":"secret-canary","kind":"secret-canary","job_id":"secret-canary"});
        status["chain"] = json!("secret-canary");
        assert!(
            !evaluate(&config, options, &status, 10000)
                .to_string()
                .contains("secret-canary")
        );
    }

    #[test]
    fn missing_state_is_unhealthy_without_creating_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: dir.path().join("missing"),
            ..Config::default()
        };
        let health = check(&config, Options::default()).unwrap();
        assert!(has(&health, "not_initialized"));
        assert!(!config.state_dir.exists());
    }

    #[test]
    fn effective_modes_and_captured_deadline_override_desired_policy() {
        let (mut config, options, mut status) = fixture();
        config.capabilities.answer = Mode::Off;
        config.timeouts.model_seconds = 1;
        status["effective_runtime"]["capabilities"] =
            json!({"answer":"active","judge":"off","mine":"off"});
        status["pending"] =
            json!({"kind":"answer","state":"generating","created_at":1,"model_deadline":20000});
        let health = evaluate(&config, options, &status, 10000);
        assert!(!has(&health, "no_active_capabilities"));
        assert!(!has(&health, "model_work_overdue"));
        status["admission_blocked"] = json!(true);
        status["oldest_unresolved_operation"] = json!(17);
        status["oldest_unresolved_since"] = json!(9000);
        status["pending"] = json!({"kind":"judge","state":"unknown","created_at":9000});
        status["operations"] = json!([{"kind":"answer","state":"generating","count":1}]);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], false);
        assert_eq!(health["preparing"], true);
        assert_eq!(health["admission_blocked"], true);
        assert_eq!(health["oldest_unresolved_age_seconds"], 1000);
        for obsolete in ["blocking_operation", "blocked_since", "blocked_age_seconds"] {
            assert!(health.get(obsolete).is_none());
        }
        status["admission_blocked"] = json!(false);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["admission_blocked"], false);
        assert_eq!(health["oldest_unresolved_operation"], 17);
        assert_eq!(health["oldest_unresolved_age_seconds"], 1000);
    }

    #[test]
    fn uncaptured_model_deadline_never_uses_desired_policy_as_execution_evidence() {
        let (mut config, options, mut status) = fixture();
        config.timeouts.model_seconds = 1;
        config.timeouts.shutdown_seconds = 1;
        config.schedule.poll_seconds = 1;
        config.schedule.jitter_seconds = 0;
        status["pending"] = json!({"state":"generating","created_at":9000});
        let unavailable = evaluate(&config, options, &status, 10000);
        assert!(!has(&unavailable, "model_work_overdue"));
        assert_eq!(unavailable["thresholds"]["model_seconds"], Value::Null);
        assert!(
            unavailable["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "model_deadline_unavailable")
        );
        status["effective_runtime"]["policy"] = json!({
            "timeouts":{"model_seconds":2000,"http_seconds":30,"shutdown_seconds":30},
            "schedule":{"poll_seconds":120,"jitter_seconds":30}
        });
        assert!(!has(
            &evaluate(&config, options, &status, 10000),
            "model_work_overdue"
        ));
        status["pending"]["created_at"] = json!(7000);
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "model_work_overdue"
        ));
    }

    #[test]
    fn effective_read_timeout_prevents_false_staleness_without_using_desired_policy() {
        let (mut config, options, mut status) = fixture();
        config.timeouts.read_http_seconds = Some(6000);
        status["effective_runtime"]["policy"] = json!({
            "timeouts":{"http_seconds":5,"read_http_seconds":600,"shutdown_seconds":1},
            "schedule":{"poll_seconds":1,"jitter_seconds":0}
        });
        let within_read = evaluate(&config, options, &status, 10500);
        assert!(!has(&within_read, "controller_stale"));
        assert!(!has(&within_read, "challenge_observation_stale"));
        assert!(has(
            &evaluate(&config, options, &status, 10604),
            "controller_stale"
        ));
    }

    #[test]
    fn risk_admission_does_not_hide_unresolved_effects() {
        let (config, options, mut status) = fixture();
        status["pending"] = json!({"state":"unknown","created_at":9000});
        status["participation"] = json!({"unresolved_count":1,"risk_admissions":1});
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["warnings"][0], "pending_outcome_uncertain");
        assert!(
            health["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|warning| warning == "participation_risk_admitted")
        );
        status["participation"]["unresolved_count"] = json!(0);
        status["pending"] = Value::Null;
        let resolved = evaluate(&config, options, &status, 10000);
        assert!(
            resolved["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|warning| warning != "participation_risk_admitted")
        );
    }

    #[test]
    fn retained_risk_does_not_hide_operational_blockage_or_staleness() {
        let (config, options, mut status) = fixture();
        status["pending"] = json!({"state":"unknown","created_at":9000});
        status["participation"] = json!({"unresolved_count":1,"risk_admissions":1});
        status["admission_blocked"] = json!(false);
        let clear = evaluate(&config, options, &status, 10000);
        assert_eq!(clear["healthy"], true);
        assert_eq!(clear["attention_required"], true);
        assert_eq!(clear["operational"]["status"], "clear");
        assert_eq!(clear["operational"]["issues"], json!([]));
        assert_eq!(clear["risk"]["attention_required"], true);
        assert_eq!(clear["risk"]["unresolved_effects"], 1);

        status["admission_blocked"] = json!(true);
        let blocked = evaluate(&config, options, &status, 10000);
        assert_eq!(blocked["operational"]["status"], "blocked");
        assert_eq!(
            blocked["operational"]["issues"],
            json!(["admission_blocked"])
        );
        assert_eq!(blocked["healthy"], false);
        assert!(has(&blocked, "admission_blocked"));
        assert_eq!(blocked["warnings"][0], "pending_outcome_uncertain");

        status["admission_blocked"] = json!(false);
        status["observation"]["observed_at"] = json!(1);
        let stale = evaluate(&config, options, &status, 10000);
        assert_eq!(stale["operational"]["status"], "degraded");
        assert_eq!(stale["healthy"], false);
        assert_eq!(
            stale["operational"]["issues"],
            json!(["challenge_observation_stale"])
        );
        assert_eq!(stale["risk"]["attention_required"], true);
    }

    #[test]
    fn old_unknown_does_not_hide_later_overdue_work() {
        let (config, options, mut status) = fixture();
        status["pending"] = json!({"state":"unknown","created_at":1});
        for (state, issue) in [
            ("queued", "pending_work_overdue"),
            ("included_pending", "pending_work_overdue"),
            ("dispatching", "dispatch_outcome_uncertain"),
            ("generating", "model_work_overdue"),
        ] {
            status["pending_work"] = json!([{"state":state,"created_at":1,
                "updated_at":1,"http_deadline":1,"model_deadline":1}]);
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["healthy"], false, "{state}");
            assert!(has(&health, issue), "{state}");
            assert_eq!(health["warnings"][0], "pending_outcome_uncertain");
        }
    }

    #[test]
    fn absent_admission_evidence_is_not_operational_clear() {
        let (config, options, mut status) = fixture();
        status.as_object_mut().unwrap().remove("admission_blocked");
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["operational"]["status"], "unknown");
        assert_eq!(health["healthy"], false);
        assert_eq!(health["admission_blocked"], Value::Null);
        assert!(has(&health, "admission_unobserved"));
        assert_eq!(health["risk"]["unresolved_effects"], Value::Null);
    }

    #[test]
    fn live_heartbeat_does_not_make_old_answer_evidence_current() {
        let (config, options, mut status) = fixture();
        status["observation"]["epoch"] = json!(56);
        let fresh = evaluate(&config, options, &status, 10000);
        assert_eq!(fresh["current_epoch"]["evidence_fresh"], true);
        let stale_at = 10001 + fresh["thresholds"]["stale_seconds"].as_i64().unwrap();
        status["effective_runtime"]["observed_at"] = json!(stale_at);
        let stale = evaluate(&config, options, &status, stale_at);
        assert_eq!(stale["heartbeat_recent"], true);
        assert_eq!(stale["current_epoch"]["answered"], true);
        assert_eq!(stale["current_epoch"]["evidence_fresh"], false);
        assert!(has(&stale, "challenge_observation_stale"));
        status["observation"]["observed_at"] = json!(stale_at + 1);
        let future = evaluate(&config, options, &status, stale_at);
        assert_eq!(future["current_epoch"]["evidence_fresh"], false);
        assert!(has(&future, "clock_regressed"));
    }
    #[test]
    fn historical_allowance_preserves_risk_without_inventing_an_operational_block() {
        let (config, options, mut status) = fixture();
        status["pending"] = json!({"state":"unknown","created_at":9000});
        status["participation"] = json!({"unresolved_count":4,"active_unresolved_count":1,
            "historical_unknown_answer_count":3,"risk_admissions":1});
        status["admission_blocked"] = json!(false);
        status["work"] = json!({"answer":{"phase":"answered","reason":"hosted_answer_observed",
            "next_at":null,"next_action":"observe_challenge"}});
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], true);
        assert_eq!(health["operational"]["status"], "clear");
        assert_eq!(health["risk"]["unresolved_effects"], 4);
        assert_eq!(health["risk"]["active_unresolved_effects"], 1);
        assert_eq!(health["risk"]["historical_unknown_answers"], 3);
        assert_eq!(health["warnings"][0], "pending_outcome_uncertain");
        assert_eq!(health["work"]["answer"]["next_at"], Value::Null);
        assert_eq!(health["work"]["answer"]["phase"], "answered");
    }

    fn component_fixture() -> (Config, Options, Value) {
        let (config, options, mut status) = fixture();
        status["effective_runtime"]["capabilities"] =
            json!({"answer":"active","judge":"active","mine":"active"});
        status["observation"]["epoch"] = json!(56);
        status["participation"] = json!({"unresolved_count":3,"risk_admissions":1,
            "uncertainty_blocks":{"answer":false,"judge":false,"mine":false}});
        status["pending"] = json!({"kind":"answer","state":"unknown","created_at":1});
        status["work"] = json!({
            "answer":{"phase":"answered","next_action":"observe_challenge"},
            "judge":{"phase":"observing","next_action":"observe_assignments",
                "selection":{"observed_at":10000,"observed_count":0,
                    "inventory_complete":true,"eligible":false}},
            "mine":{"phase":"completed","operation_epoch":56}
        });
        status["reads"] = json!([
            {"scope":"challenge","state":"idle","finished_at":10000,"last_success_at":10000,"status":200},
            {"scope":"assignments","state":"idle","finished_at":10000,"last_success_at":10000,"status":200},
            {"scope":"identity","state":"idle","finished_at":1,"last_success_at":1,"status":200},
            {"scope":"job","state":"idle","finished_at":1,"last_failure_at":1,"status":503},
            {"scope":"receipt","state":"idle","finished_at":1,"last_failure_at":1,"status":500}
        ]);
        (config, options, status)
    }

    #[test]
    fn refusal_priority_is_not_reported_as_uncertain_execution() {
        let (config, options, mut status) = component_fixture();
        status["participation"]["unresolved_count"] = json!(0);
        status["pending"] = Value::Null;
        for kind in ["answer", "judge", "mine"] {
            status["work"][kind]["admission_reservation"] =
                json!({"active":true,"same_operation":true,"basis":"proven_refusal_retry"});
        }
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "ok");
        for kind in ["judge", "mine"] {
            assert_eq!(result["components"][kind]["state"], "blocked");
            assert_eq!(
                result["components"][kind]["reasons"][0],
                "answer_retry_reserved"
            );
        }
        status["effective_runtime"]["capabilities"]["judge"] = json!("read_only");
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "ok"
        );
    }

    #[test]
    fn no_eligible_judgments_requires_complete_current_inventory() {
        let (config, options, mut status) = component_fixture();
        status["work"]["judge"]["selection"]["observed_count"] = json!(12);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "ok"
        );
        status["work"]["judge"]["selection"]["inventory_complete"] = json!(false);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "unknown"
        );
        status["work"]["judge"]["selection"]["inventory_complete"] = json!(true);
        status["work"]["judge"]["selection"]["eligible"] = json!(true);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "unknown"
        );
    }

    #[test]
    fn completed_or_idle_work_does_not_hide_later_overdue_work() {
        let (config, options, mut status) = component_fixture();
        for kind in ["answer", "judge", "mine"] {
            for pending in [
                json!({"kind":kind,"state":"queued","created_at":1,"updated_at":9999}),
                json!({"kind":kind,"state":"dispatching","created_at":9999,"updated_at":1}),
                json!({"kind":kind,"state":"generating","created_at":1,"model_deadline":1}),
            ] {
                status["pending_work"] = json!([pending]);
                let result = evaluate(&config, options, &status, 10000);
                assert_eq!(result["healthy"], false);
                assert_eq!(result["components"][kind]["state"], "degraded");
            }
            status["pending_work"] = json!([{"kind":kind,"state":"unknown","created_at":1}]);
            assert_eq!(
                evaluate(&config, options, &status, 10000)["components"][kind]["state"],
                "ok"
            );
        }
    }

    #[test]
    fn intentional_observers_do_not_require_write_identity_verification() {
        let (config, options, mut status) = component_fixture();
        status["effective_runtime"]["capabilities"] =
            json!({"answer":"read_only","judge":"read_only","mine":"off"});
        status["hosted_identity_verified"] = Value::Null;
        status["paused"] = json!(true);
        let result = evaluate(&config, options, &status, 10000);
        for name in ["controller", "answer", "judge"] {
            assert_eq!(result["components"][name]["state"], "ok");
        }
        status["effective_runtime"]["capabilities"]["answer"] = json!("active");
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["answer"]["state"],
            "blocked"
        );
        status["paused"] = json!(false);
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "unknown");
        assert_eq!(result["components"]["judge"]["state"], "ok");
        status["hosted_identity_verified"] = json!(false);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "blocked"
        );
    }

    #[test]
    fn hydration_failure_affects_only_judging_without_current_usable_selection() {
        let (config, options, mut status) = component_fixture();
        status["reads"].as_array_mut().unwrap().push(json!({
            "scope":"assignment_evidence","last_failure_at":10000,"status":503}));
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "ok"
        );
        status["work"]["judge"]["selection"]["observed_count"] = json!(1);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "degraded"
        );
        status["work"]["judge"]["selection"] = Value::Null;
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["judge"]["state"], "degraded");
        assert_eq!(result["components"]["answer"]["state"], "ok");
        status["work"]["judge"]["phase"] = json!("generating");
        status["captured_work"] = json!([{"kind":"judge","state":"generating",
            "created_at":9999,"model_deadline":10100}]);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "ok"
        );
    }

    #[test]
    fn canyon_components_separate_current_operations_from_retained_risk() {
        let (config, options, status) = component_fixture();
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["contract_version"], 1);
        assert_eq!(result["healthy"], true);
        assert_eq!(result["operational"]["status"], "clear");
        assert_eq!(result["risk"]["attention_required"], true);
        for name in ["controller", "answer", "judge", "mine"] {
            assert_eq!(result["components"][name]["state"], "ok", "{name}");
            assert_eq!(result["components"][name]["observed_at"], 10000);
            assert_eq!(result["components"][name]["age_seconds"], 0);
        }
        for name in ["identity", "job", "receipt", "assignment_evidence"] {
            assert_eq!(
                result["components"]["api"][name]["state"], "unknown",
                "{name}"
            );
        }
        assert_eq!(result["components"]["api"]["challenge"]["state"], "ok");
        assert_eq!(result["components"]["api"]["assignments"]["state"], "ok");
    }

    #[test]
    fn components_use_applied_modes_and_keep_read_only_distinct() {
        let (mut config, options, mut status) = component_fixture();
        config.capabilities.answer = Mode::Off;
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["answer"]["state"],
            "ok"
        );
        status["effective_runtime"]["capabilities"] =
            json!({"answer":"off","judge":"read_only","mine":"off"});
        status["participation"]["uncertainty_blocks"]["judge"] = json!(true);
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "disabled");
        assert_eq!(result["components"]["judge"]["state"], "ok");
        assert_eq!(result["components"]["judge"]["mode"], "read_only");
        assert_eq!(result["components"]["mine"]["state"], "disabled");
        status["effective_runtime"]["capabilities"] = Value::Null;
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "unknown");
        assert_eq!(result["components"]["answer"]["mode"], Value::Null);
    }

    #[test]
    fn controller_failures_override_fresh_capability_evidence() {
        let (config, options, status) = component_fixture();
        for (field, value, expected) in [
            ("paused", json!(true), "blocked"),
            ("controller_stopped", json!(true), "blocked"),
            ("identity_matches_config", json!(false), "blocked"),
            ("hosted_identity_verified", json!(false), "blocked"),
        ] {
            let mut changed = status.clone();
            changed[field] = value;
            let result = evaluate(&config, options, &changed, 10000);
            for name in ["controller", "answer", "judge", "mine"] {
                assert_eq!(
                    result["components"][name]["state"], expected,
                    "{field}/{name}"
                );
            }
        }
        for timestamp in [1, 10001] {
            let mut changed = status.clone();
            changed["effective_runtime"]["observed_at"] = json!(timestamp);
            let result = evaluate(&config, options, &changed, 10000);
            for name in ["controller", "answer", "judge", "mine"] {
                assert_eq!(result["components"][name]["state"], "unknown", "{name}");
            }
        }
    }

    #[test]
    fn read_failures_and_admission_are_capability_scoped() {
        let (config, options, mut status) = component_fixture();
        status["reads"][1] = json!({"scope":"assignments","state":"idle",
            "finished_at":10000,"last_success_at":9990,"last_failure_at":10000,
            "failure_category":"http","status":429,"next_at":10100});
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["judge"]["state"], "degraded");
        assert_eq!(result["components"]["answer"]["state"], "ok");
        assert_eq!(result["components"]["mine"]["state"], "ok");
        status["reads"][1] = json!({"scope":"assignments","state":"idle",
            "finished_at":10000,"last_success_at":10000,"status":200});
        status["reads"][0] = json!({"scope":"challenge","state":"idle",
            "finished_at":10000,"last_failure_at":10000,"status":503,"next_at":10100});
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["judge"]["state"], "ok");
        assert_eq!(result["components"]["answer"]["state"], "degraded");
        assert_eq!(result["components"]["mine"]["state"], "degraded");
        status["participation"]["uncertainty_blocks"]["judge"] = json!(true);
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["judge"]["state"], "blocked");
        assert_eq!(result["components"]["answer"]["state"], "degraded");
    }

    #[test]
    fn unused_api_failure_only_affects_work_waiting_for_it() {
        let (config, options, mut status) = component_fixture();
        status["reads"][3] = json!({"scope":"job","state":"idle",
            "finished_at":10000,"last_failure_at":10000,"status":503,"next_at":10100});
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "ok");
        assert_eq!(result["components"]["judge"]["state"], "ok");
        status["epoch_evidence"]["answered"] = json!(false);
        status["work"]["answer"] = json!({"phase":"queued","next_action":"read_job"});
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "degraded");
        assert_eq!(result["components"]["judge"]["state"], "ok");
    }

    #[test]
    fn missing_work_is_unknown_and_normal_model_work_is_not_failure() {
        let (config, options, mut status) = component_fixture();
        status["work"] = Value::Null;
        status["epoch_evidence"]["answered"] = Value::Null;
        status["pending"] = Value::Null;
        let result = evaluate(&config, options, &status, 10000);
        for name in ["answer", "judge", "mine"] {
            assert_eq!(result["components"][name]["state"], "unknown", "{name}");
        }
        status["captured_work"] = json!([{"kind":"answer","state":"generating",
            "created_at":9990,"model_deadline":10100}]);
        let result = evaluate(&config, options, &status, 10000);
        assert_eq!(result["components"]["answer"]["state"], "ok");
        assert_eq!(result["components"]["judge"]["state"], "unknown");
        status["participation"]["uncertainty_blocks"] = Value::Null;
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["answer"]["state"],
            "unknown"
        );
        let unavailable = unknown_components();
        for name in ["controller", "answer", "judge", "mine"] {
            assert_eq!(unavailable[name]["state"], "unknown");
            assert!(unavailable[name]["observed_at"].is_null());
            assert!(unavailable[name]["age_seconds"].is_null());
            assert!(unavailable[name]["reasons"].is_array());
            assert!(unavailable[name]["next_actions"].is_array());
        }
        assert_eq!(unavailable["api"].as_object().unwrap().len(), 6);
    }

    #[test]
    fn final_disk_findings_update_components_without_changing_risk() {
        let (config, options, mut status) = component_fixture();
        status["effective_runtime"]["capabilities"]["mine"] = json!("off");
        for code in ["state_disk_space_low", "state_disk_space_unavailable"] {
            let mut result = evaluate(&config, options, &status, 10000);
            let risk = result["risk"].clone();
            apply_disk_issue(&mut result, code);
            assert_eq!(result["healthy"], false);
            assert_eq!(result["operational"]["status"], "degraded");
            assert_eq!(result["risk"], risk);
            for name in ["controller", "answer", "judge"] {
                assert_eq!(result["components"][name]["state"], "degraded");
                assert!(
                    result["components"][name]["reasons"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|reason| reason == code)
                );
                assert!(
                    !result["components"][name]["next_actions"]
                        .as_array()
                        .unwrap()
                        .is_empty()
                );
            }
            assert_eq!(result["components"]["mine"]["state"], "disabled");
        }
    }
}
