//! Read-only, local health evidence with a bounded component contract.
//! Component readiness is separate from retained effect risk and never authorizes
//! replay. Effective modes and fresh local evidence are not live remote probes.
use crate::store::{JudgeInventory, judge_inventory};
use crate::{capability::LaneId, config::Config, runtime, store::now};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::path::Path;

mod api;
mod assessment;
mod intervention;
pub(crate) mod vocabulary;

/// A bounded view of canonical evidence, not an upstream-response classifier.
/// Only structured evidence establishes identity state.
pub(crate) struct HostedIdentity<'a> {
    evidence: &'a Value,
    status: &'a str,
    rejection: Option<&'a str>,
    legacy_failure: bool,
}

pub(crate) fn hosted_identity(status: &Value) -> HostedIdentity<'_> {
    let evidence = &status["hosted_identity"];
    let state = if status["initialized"] == false {
        "unobserved"
    } else {
        evidence["status"]
            .as_str()
            .filter(|state| {
                matches!(
                    *state,
                    "verified"
                        | "unavailable"
                        | "authentication_failed"
                        | "identity_mismatch"
                        | "invalid_response"
                        | "legacy_unknown"
                        | "unobserved"
                )
            })
            .unwrap_or("unobserved")
    };
    let rejection = if status["initialized"] == false {
        None
    } else {
        evidence["rejection"]
            .as_str()
            .filter(|value| matches!(*value, "authentication_failed" | "identity_mismatch"))
            .or_else(|| {
                matches!(state, "authentication_failed" | "identity_mismatch").then_some(state)
            })
    };
    HostedIdentity {
        evidence,
        status: state,
        rejection,
        legacy_failure: status["initialized"] != false && evidence["legacy_failure"] == true,
    }
}

impl HostedIdentity<'_> {
    fn rejected(&self) -> bool {
        self.rejection.is_some()
    }

    pub(crate) fn verified(&self) -> Option<bool> {
        if self.rejected() {
            Some(false)
        } else {
            (self.status == "verified").then_some(true)
        }
    }

    fn reason(&self) -> &'static str {
        match self.rejection.unwrap_or(self.status) {
            "authentication_failed" => "hosted_identity_authentication_failed",
            "identity_mismatch" => "hosted_identity_mismatch",
            "unavailable" => "hosted_identity_unavailable",
            "invalid_response" => "hosted_identity_invalid_response",
            "legacy_unknown" => "hosted_identity_legacy_unknown",
            _ => "hosted_identity_unobserved",
        }
    }

    pub(crate) fn value(&self) -> Value {
        let timestamp = |key: &str| self.evidence[key].as_i64().filter(|time| *time >= 0);
        json!({"status":self.status,"rejection":self.rejection,
            "observed_at":timestamp("observed_at"),"last_verified_at":timestamp("last_verified_at"),
            "legacy_failure":self.legacy_failure})
    }
}
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

/// Project the same local readiness/risk evaluation as health and doctor.
/// Status does not probe filesystem capacity; health qualifies that separately.
pub fn enrich_status(status: &mut Value, options: Options, at: i64) {
    let mut report = evaluate_evidence(options, status, at);
    assessment::attach(&mut report, status);
    for field in [
        "work",
        "intervention",
        "components",
        "healthy",
        "operational",
        "risk",
        "issues",
        "warnings",
        "attention_required",
        "checked_at",
        "thresholds",
        "expect_participation",
        "assessment_scope",
        "operational_now",
        "historical_uncertainty",
        "operator_action_required",
        "severity",
    ] {
        status[field] = report[field].take();
    }
}

/// Stable diagnostic shapes when configuration or journal evidence is unavailable.
pub fn unknown_intervention(reason: &str) -> Value {
    intervention::unknown(reason)
}

pub fn unknown_work(reason: &str) -> Value {
    intervention::unknown_work(reason)
}

pub fn unknown_risk() -> Value {
    json!({"status":"unknown","attention_required":null,"unresolved_effects":null,
        "historical_eligible_answers":null,"capacity_exempt_answers":null,
        "unresolved_model_attempts":null,"background_remote_work":null,
        "retained_uncertainty_nonblocking_lanes":null})
}

/// Doctor supplies lifecycle facts; health owns their effect on existing evidence.
pub(crate) fn qualify_doctor(report: &mut Value, repairs: &Value) {
    if repairs["restoration"]["verified"] == true && repairs["restoration"]["runtime"] == "restored"
    {
        let reason = "runtime_restored_observation_pending";
        let mut superseded = false;
        for name in ["controller", "answer", "judge", "mine"] {
            let row = &mut report["components"][name];
            if let Some(reasons) = row["reasons"].as_array_mut()
                && reasons.iter().any(|reason| reason == "controller_stopped")
            {
                superseded = true;
                reasons.retain(|reason| reason != "controller_stopped");
                if !reasons.iter().any(|item| item == reason) {
                    reasons.push(json!(reason));
                }
                if reasons.iter().all(|reason| {
                    reason
                        .as_str()
                        .is_some_and(|code| unknown_issue(code) || code == "state_disk_space_low")
                }) {
                    row["state"] = json!(if reasons
                        .iter()
                        .any(|reason| reason == "state_disk_space_low")
                    {
                        "degraded"
                    } else {
                        "unknown"
                    });
                }
                row["next_actions"] = inspection_actions();
            }
        }
        if superseded {
            report["issues"]
                .as_array_mut()
                .expect("health issues array")
                .retain(|issue| issue != "controller_stopped");
            push_issue(report, reason);
            finalize_readiness(report);
            sync_work_components(report);
        }
        if superseded
            || report["intervention"]["controller"]["reason"] == "controller_stopped"
            || LANES.iter().any(|lane| {
                let work = &report["work"][*lane];
                work["intervention"]["reason"] == "controller_stopped"
                    || work["next_action"] == "start_controller"
            })
        {
            intervention::qualify_restoration(report);
        }
        let controller = &mut report["intervention"]["controller"];
        if controller["reason"] == reason {
            controller["state"] = json!("unknown");
            controller["run_mode"] = json!("unknown");
        }
        for lane in LANES {
            let work = &mut report["work"][lane];
            if work["continuation"]["reason"] == "controller_stopped" {
                work["continuation"] = assessment::unknown_step(reason);
                work["automatic_step"] = Value::Null;
            }
            if let Some(findings) = work["findings"]["items"].as_array_mut() {
                for finding in findings {
                    if finding["reason"] == "controller_stopped" {
                        finding["reason"] = json!(reason);
                        finding["state"] = json!("unknown");
                    }
                }
            }
        }
        if report["intervention"]["controller"].get("state").is_some() {
            assessment::qualify_unattended(report);
        }
    }
    if !repairs["failure"].is_null() {
        intervention::qualify_repair_failure(report);
    }
    operational_summary(report);
}

/// This command opens existing state read-only, never recovers it, and performs
/// neither network nor model calls. Errors are deliberately replaced at this boundary.
pub fn check(config_path: &Path, config: &Config, options: Options) -> Result<Value> {
    let at = now();
    let status = match local_status(config_path, config, at) {
        Ok(status) => status,
        Err(_) => {
            let mut report = json!({
                "components":unknown_components(),
                "work":unknown_work("local_evidence_unavailable"),
                "intervention":unknown_intervention("local_evidence_unavailable"),
                "healthy":false,"attention_required":true,
                "issues":["local_evidence_unavailable"],"warnings":[],
                "operational":{"status":"unknown","issues":["local_evidence_unavailable"]},
                "risk":unknown_risk(),
                "assessment_scope":{"evidence":"local_only","state_filesystem":"not_assessed"},
                "evidence":"local_only","mutations":false,"process_identity":"not_assessed",
                "process_observation":{"state":"not_assessed","reason":"local_evidence_unavailable",
                    "evidence_scope":"managed_invocation_and_stable_file_object_not_checksum_attestation"}
            });
            operational_summary(&mut report);
            return Ok(report);
        }
    };
    let mut result = evaluate(config, options, &status, at);
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
        result["assessment_scope"]["state_filesystem"] = json!("assessed");
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
    operational_summary(&mut result);
    qualify_refresh(&mut result, &status, options, at);
    assessment::attach(&mut result, &status);
    Ok(result)
}

/// Journal facts plus bounded local observations and a read-only release cache.
/// This path must not initialize installer state, read credentials or probe HTTP.
pub fn local_status(config_path: &Path, config: &Config, at: i64) -> Result<Value> {
    let (mut status, process) =
        crate::installer::observe_status_process(config_path, config, || {
            runtime::status_evidence(config)
        })?;
    if let Some(object) = status.as_object_mut() {
        object.remove("journal_identity");
    }
    let process = serde_json::to_value(process)?;
    let selected = serde_json::to_value(crate::installer::observe_selected(config_path))?;
    status["process_identity"] = process["state"].clone();
    status["release_advisory"] =
        crate::update::advisory::diagnostic_view(config_path, &selected, &process, at);
    let effective = &status["effective_runtime"];
    let recorded = &effective["policy"]["process"];
    let background = &effective["policy"]["update_background"];
    let current = status["controller_stopped"] == false
        && !matches!(process["state"].as_str(), Some("stopped" | "mismatch"))
        && effective["runtime_instance"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        && effective["authority_epoch"].as_u64().is_some()
        && recorded["runtime_instance"] == effective["runtime_instance"]
        && recorded["authority_epoch"] == effective["authority_epoch"]
        && recorded["account_generation"] == status["generation"]
        && controller_floor(&status).is_some_and(|floor| {
            fresh(
                effective["observed_at"].as_i64(),
                at,
                floor.max(Options::default().stale_seconds),
            )
        });
    status["release_advisory"]["background"] = if current && background["enabled"].is_boolean() {
        json!({"enabled":background["enabled"],"reason":background["reason"]})
    } else {
        json!({"enabled":null,"reason":"current_runtime_policy_unavailable"})
    };
    status["process_observation"] = process;
    status["selected_image"] = selected;
    Ok(status)
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

fn model_awaiting_admission(work: &Value) -> bool {
    work["state"] == "generating"
        && work["model_deadline"].is_null()
        && (work["pending_execution_deadline"].as_i64().is_some()
            || (work["diagnostic"]["stage"] == "model_preflight"
                && work["diagnostic"]["execution"] == "not_started"
                && work["diagnostic"]["state"] == "awaiting_admission"))
}

fn model_overdue(work: &Value, at: i64, poll: u64, fallback: Option<u64>) -> Option<bool> {
    if let Some(deadline) = work["model_deadline"].as_i64() {
        return Some(at > deadline.saturating_add(poll as i64));
    }
    if model_awaiting_admission(work) {
        return work["pending_execution_deadline"]
            .as_i64()
            .map(|deadline| at >= deadline);
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
                .then_some(if model_awaiting_admission(work) {
                    "pending_model_execution_expired"
                } else {
                    "model_work_overdue"
                }),
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
            Some("generated" | "prepared" | "retry")
                if age(&work["created_at"], at).is_some_and(|seconds| seconds > self.pending) =>
            {
                Some("pending_work_overdue")
            }
            _ => None,
        }
    }
}

const LANES: [&str; LaneId::COUNT] = LaneId::NAMES;

fn lane_policy<'a>(status: &'a Value, lane: &str) -> &'a Value {
    &status["effective_runtime"]["policy"]["capabilities"][lane]
}

fn lane_mode<'a>(status: &'a Value, lane: &str) -> Option<&'a str> {
    lane_policy(status, lane)["mode"].as_str()
}

fn observation<'a>(status: &'a Value, lane: &str) -> &'a Value {
    &status["observations"][lane]
}

fn cycle_floor(status: &Value, lane: &str) -> Option<u64> {
    let policy = lane_policy(status, lane);
    Some(
        policy["timeouts"]["http_seconds"]
            .as_u64()?
            .max(policy["timeouts"]["read_http_seconds"].as_u64()?)
            .saturating_add(policy["schedule"]["poll_seconds"].as_u64()?)
            .saturating_add(policy["schedule"]["jitter_seconds"].as_u64()?)
            .saturating_add(
                status["effective_runtime"]["policy"]["runtime"]["shutdown_seconds"].as_u64()?,
            )
            .saturating_add(1),
    )
}

fn controller_floor(status: &Value) -> Option<u64> {
    LANES.into_iter().try_fold(0_u64, |floor, lane| {
        Some(floor.max(cycle_floor(status, lane)?))
    })
}

fn work_timing(status: &Value, lane: &str, options: Options) -> Option<WorkTiming> {
    let policy = lane_policy(status, lane);
    let floor = cycle_floor(status, lane)?;
    let shutdown = status["effective_runtime"]["policy"]["runtime"]["shutdown_seconds"].as_u64()?;
    let poll = policy["schedule"]["poll_seconds"].as_u64()?;
    Some(WorkTiming {
        http: policy["timeouts"]["http_seconds"].as_u64()?,
        shutdown,
        poll,
        model: policy["timeouts"]["model_seconds"].as_u64().map(|model| {
            model
                .saturating_add(shutdown)
                .saturating_add(poll)
                .saturating_add(policy["schedule"]["jitter_seconds"].as_u64().unwrap_or(0))
                .saturating_add(1)
        }),
        pending: options.work_seconds.max(floor),
    })
}

fn evaluate(config: &Config, options: Options, status: &Value, at: i64) -> Value {
    let mut result = evaluate_evidence(options, status, at);
    result["captured_work"] = status["captured_work"].clone();
    result["pending_work"] = status["pending_work"].clone();
    result["desired_capabilities"] = json!(
        LaneId::ALL
            .into_iter()
            .map(|lane| (lane.as_str(), config.mode(lane)))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    result
}

fn evaluate_evidence(options: Options, status: &Value, at: i64) -> Value {
    // Desired configuration never substitutes for missing applied evidence.
    let effective = &status["effective_runtime"];
    let floor = controller_floor(status);
    let stale = options.stale_seconds.max(floor.unwrap_or(0));
    let answer_floor = cycle_floor(status, "answer");
    let answer_stale = options.stale_seconds.max(answer_floor.unwrap_or(0));
    let grace = options.answer_grace_seconds.max(answer_floor.unwrap_or(0));
    let initialized = status["initialized"] == true;
    let paused = status["paused"] != false;
    let active = LANES
        .into_iter()
        .any(|lane| lane_mode(status, lane) == Some("active"));
    let modes_known = LANES.into_iter().all(|lane| {
        matches!(
            lane_mode(status, lane),
            Some("active" | "read_only" | "off")
        )
    });
    let heartbeat_age = age(&effective["observed_at"], at);
    let answer = observation(status, "answer");
    let observation_age = age(&answer["observed_at"], at);
    let epoch_age = age(&answer["first_observed_at"], at);
    let answer_fresh = answer_floor.and_then(|_| {
        observation_fresh(
            status,
            "answer",
            answer["observed_at"].as_i64(),
            at,
            answer_stale,
        )
    });
    let mut issues = Vec::<&str>::new();
    let mut warnings = Vec::<&str>::new();
    if !initialized {
        issues.push("not_initialized");
    }
    if initialized && (floor.is_none() || !modes_known) {
        issues.push("effective_policy_unavailable");
    }
    if status["migration"]["pending"] == true {
        issues.push("migration_pending");
    }
    if status["identity_matches_config"] == false {
        issues.push("identity_mismatch");
    }
    if status["network_routing"]["matches_config"] == false {
        issues.push("api_routing_mismatch");
    }
    let identity = hosted_identity(status);
    if active && (identity.rejected() || (!paused && identity.verified() != Some(true))) {
        issues.push(identity.reason());
    }
    if status["controller_stopped"] == true {
        issues.push("controller_stopped");
    }
    if status["process_identity"] == "stopped" && !issues.contains(&"controller_stopped") {
        issues.push("controller_stopped");
    }
    if status["process_identity"] == "mismatch" {
        issues.push("process_identity_mismatch");
    }
    match heartbeat_age {
        None => issues.push("controller_unobserved"),
        Some(seconds) if floor.is_some() && seconds > stale => issues.push("controller_stale"),
        _ => {}
    }
    if effective["observed_at"]
        .as_i64()
        .is_some_and(|time| time > at)
        || LANES.into_iter().any(|lane| {
            let required = current_work(status, lane)
                || lane_mode(status, lane) == Some("read_only")
                || (options.expect_participation && lane_mode(status, lane) == Some("active"));
            let observed = if lane == "judge" {
                &status["work"][lane]["assessment"]["observed_at"]
            } else {
                &observation(status, lane)["observed_at"]
            };
            required && observed.as_i64().is_some_and(|time| time > at)
        })
    {
        issues.push("clock_regressed");
    }
    if options.expect_participation {
        if paused {
            issues.push("participation_paused");
        }
        if effective["reload_blocked"] == true {
            issues.push("reload_blocked");
        }
        if modes_known && !active {
            issues.push("no_active_capabilities");
        }
    }
    for work in std::iter::once(&status["pending"])
        .chain(status["pending_work"].as_array().into_iter().flatten())
        .chain(status["captured_work"].as_array().into_iter().flatten())
    {
        if work["state"] == "unknown" && !warnings.contains(&"pending_outcome_uncertain") {
            warnings.push("pending_outcome_uncertain");
        }
        // Remote follow-up retains risk without becoming a dependency of
        // canonical distinct or already completed participation.
        if work["nonblocking_for_fresh_work"] == true {
            if !warnings.contains(&"background_remote_work_retained") {
                warnings.push("background_remote_work_retained");
            }
            continue;
        }
        if work["state"] != "unknown"
            && ["created_at", "updated_at"]
                .into_iter()
                .any(|field| work[field].as_i64().is_some_and(|time| time > at))
            && !issues.contains(&"clock_regressed")
        {
            issues.push("clock_regressed");
        }
        let timing = work["kind"]
            .as_str()
            .and_then(|lane| work_timing(status, lane, options));
        if work["state"] == "generating"
            && let Some(timing) = timing.as_ref()
            && model_overdue(work, at, timing.poll, timing.model).is_none()
        {
            if !warnings.contains(&"model_deadline_unavailable") {
                warnings.push("model_deadline_unavailable");
            }
            if !issues.contains(&"model_deadline_unavailable") {
                issues.push("model_deadline_unavailable");
            }
        }
        if let Some(issue) = timing.as_ref().and_then(|timing| timing.issue(work, at))
            && !issues.contains(&issue)
        {
            issues.push(issue);
        }
    }
    if options.expect_participation && lane_mode(status, "answer") == Some("active") {
        match (observation_age, answer_fresh) {
            (None, _) => issues.push("challenge_unobserved"),
            (_, Some(false)) => issues.push("challenge_observation_stale"),
            (_, None) if !issues.contains(&"effective_policy_unavailable") => {
                issues.push("effective_policy_unavailable");
            }
            _ => {}
        }
        if answer_floor.is_some()
            && answer["answered"] == false
            && epoch_age.is_some_and(|seconds| seconds > grace)
            && answer_fresh == Some(true)
        {
            issues.push("current_epoch_unanswered");
        }
        if answer["answered"].as_bool().is_none() {
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
    let admission = status["admission_blocked"].as_bool();
    // Final readiness is reduced only after required component findings are known.
    if admission == Some(true) && options.expect_participation {
        issues.push("admission_blocked");
    } else if admission.is_none() {
        issues.push("admission_unobserved");
    }
    let risk_attention = status["participation"]["unresolved_count"]
        .as_u64()
        .unwrap_or(0)
        > 0
        || issues.contains(&"dispatch_outcome_uncertain")
        || warnings.iter().any(|code| {
            matches!(
                *code,
                "pending_outcome_uncertain"
                    | "model_execution_unresolved"
                    | "participation_risk_admitted"
                    | "background_remote_work_retained"
            )
        });
    let (work, intervention) = intervention::project(status, options, at);
    let mut thresholds = json!({});
    for lane in LANES {
        let policy = lane_policy(status, lane);
        let timing = work_timing(status, lane, options);
        thresholds[lane] = json!({
            "stale_seconds":cycle_floor(status,lane).map(|floor| options.stale_seconds.max(floor)),
            "work_seconds":timing.as_ref().map(|timing| timing.pending),
            "model_seconds":timing.as_ref().and_then(|timing| timing.model),
            "read_http_seconds":policy["timeouts"]["read_http_seconds"].as_u64(),
            "write_http_seconds":policy["timeouts"]["http_seconds"].as_u64(),
            "model_attempt_limit":policy["preparation"]["max_attempts_per_work"],
            "max_uncertain_replacements_per_work":policy["preparation"]["max_uncertain_replacements_per_work"].as_u64().unwrap_or(1),
            "timing_source":if timing.is_some() {"effective"} else {"unavailable"}
        });
    }
    let mut result = json!({
        "healthy":issues.is_empty(),"checked_at":at,
        "issues":issues,"warnings":warnings,"attention_required":!issues.is_empty() || !warnings.is_empty(),
        "unresolved_model_attempts":unresolved_models,"initialized":initialized,"paused":paused,
        "expect_participation":options.expect_participation,
        "controller_stopped":status["controller_stopped"].as_bool().unwrap_or(false),
        "hosted_identity_verified":identity.verified(),"hosted_identity":identity.value(),
        "heartbeat_age_seconds":heartbeat_age,"observation_age_seconds":observation_age,
        "heartbeat_recent":fresh(effective["observed_at"].as_i64(),at,stale),
        "observing":fresh(answer["observed_at"].as_i64(),at,answer_stale),"preparing":preparing,
        "last_safety_observation_at":status["last_safety_observation_at"],
        "work":work,"intervention":intervention,"epoch_observed_age_seconds":epoch_age,
        "pending_age_seconds":age(&status["pending"]["created_at"],at),"admission_blocked":admission,
    });
    result["oldest_unresolved_operation"] = status["oldest_unresolved_operation"].clone();
    result["oldest_unresolved_since"] = status["oldest_unresolved_since"].clone();
    result["oldest_unresolved_age_seconds"] = json!(age(&status["oldest_unresolved_since"], at));
    result["affected_capabilities"] = status["affected_capabilities"].clone();
    result["progress_age_seconds"] = json!(age(&status["last_progress_at"], at));
    result["effective_capabilities"] = effective["policy"]["capabilities"].clone();
    // Store owns control freshness, closure and uncertainty; never infer them
    // from desired files or a successful resume.
    result["lane_controls"] = status["lane_controls"].clone();
    result["lane_participation"] = status["lane_participation"].clone();
    result["participation"] = status["participation"].clone();
    result["request_restrictions"] = status["request_restrictions"].clone();
    result["migration"] = status["migration"].clone();
    result["legacy_observation"] = status["legacy_observation"].clone();
    result["observations"] = status["observations"].clone();
    result["last_reported_build"] = status["last_reported_build"].clone();
    result["process_identity"] = json!(
        status["process_identity"]
            .as_str()
            .unwrap_or("not_assessed")
    );
    result["process_observation"] = status["process_observation"].clone();
    result["selected_image"] = status["selected_image"].clone();
    result["release_advisory"] = status["release_advisory"].clone();
    result["evidence"] = json!("local_only");
    result["notifications"] = json!("local_exit_status_and_journal");
    result["assessment_scope"] = json!({"evidence":"local_only","state_filesystem":"not_assessed"});
    result["current_epoch"] = json!({
        "epoch":answer["epoch"].as_u64(),"answered":answer["answered"].as_bool(),
        "source":"answer","evidence_fresh":answer_fresh,
        "evidence":"last_local_observation_not_a_live_remote_check"
    });
    result["thresholds"] = json!({
        "stale_seconds":stale,"answer_grace_seconds":grace,
        "cycle_floor_seconds":floor,"timing_source":if floor.is_some() {"effective"} else {"unavailable"}
    });
    result["thresholds"]["lanes"] = thresholds;
    result["operational"] = json!({
        "status":"unknown","issues":issues,"evidence":"local_only_not_a_submission_guarantee"
    });
    result["risk"] = json!({
        "attention_required":risk_attention,
        "unresolved_effects":status["participation"]["unresolved_count"].as_u64(),
        "historical_eligible_answers":status["participation"]["lanes"]["answer"]["historical_eligible_count"].as_u64(),
        "capacity_exempt_answers":status["participation"]["lanes"]["answer"]["capacity_exempt_count"].as_u64(),
        "unresolved_model_attempts":unresolved_models,
        "retained_uncertainty_nonblocking_lanes":LANES.into_iter().filter(|lane|status["participation"]["lanes"][*lane]["retained_uncertainty_nonblocking"]==true).collect::<Vec<_>>(),
    });
    result["risk"]["background_remote_work"] = json!(
        status["pending_work"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|work| work["nonblocking_for_fresh_work"] == true)
            .count()
    );
    result["components"] = components(status, &result, at, stale, options);
    qualify_components(&mut result, status, options);
    finalize_readiness(&mut result);
    intervention::qualify_operational(&mut result, status);
    sync_work_components(&mut result);
    operational_summary(&mut result);
    qualify_refresh(&mut result, status, options, at);
    result
}

/// Classify a failed health check as a managed wait only when every issue
/// is covered by that lane's own fresh, bounded automatic admission path.
pub fn managed_health_wait(report: &Value) -> bool {
    let Some(at) = report["checked_at"].as_i64() else {
        return false;
    };
    let Some(issues) = report["issues"]
        .as_array()
        .filter(|issues| !issues.is_empty())
    else {
        return false;
    };
    if report["intervention"]["unattended"] != true
        || report["intervention"]["controller"]["ready"] != true
        || report["components"]["controller"]["state"] != "ok"
        || report["hosted_identity_verified"] != true
    {
        return false;
    }
    let timed_reason = |reason: &Value| {
        reason
            .as_str()
            .and_then(|reason| intervention::floor_kind(reason, &Value::Null))
            .is_some()
    };
    let stale_limit = report["thresholds"]["stale_seconds"]
        .as_i64()
        .filter(|&s| s > 0)
        .unwrap_or(Options::default().stale_seconds as i64);
    let mut explained: Vec<&str> = Vec::new();
    let mut aggregate_covered = false;
    for lane in LANES {
        let component = &report["components"][lane];
        let intervention = &report["work"][lane]["intervention"];
        let admission = &report["participation"]["lanes"][lane];
        let lane_blocked = component["mode"] == "active" && admission["allowed"] == false;
        if intervention["resolution"] == "polling_not_guaranteed"
            || report["work"][lane]["required_missing_observation"].is_object()
        {
            return false;
        }
        if matches!(component["state"].as_str(), Some("ok" | "disabled")) && !lane_blocked {
            continue;
        }
        let Some(reasons) = component["reasons"].as_array() else {
            return false;
        };
        if reasons.is_empty() {
            return false;
        }
        let next = intervention["next_at"].as_i64().filter(|&next| next > at);
        if component["mode"] != "active"
            || intervention["status"] != "automatic_recovery"
            || next.is_none()
        {
            return false;
        }
        let next_at = next.expect("checked future next_at");
        let is_strict_blocked_wait = reasons.len() == 1
            && component["state"] == "blocked"
            && intervention["reason"] == reasons[0]
            && intervention["next_action"] == "await_retry_eligibility"
            && intervention["observation_fresh"] == true
            && timed_reason(&reasons[0]);
        let bounded_outage_age = intervention["observation_fresh"] == true
            || (component["observed_at"].as_i64().is_some()
                && component["age_seconds"]
                    .as_u64()
                    .is_some_and(|age| age <= (stale_limit.max(60) as u64).saturating_mul(2)));
        let is_transient_upstream_wait = !is_strict_blocked_wait
            && bounded_outage_age
            && next_at.saturating_sub(at) <= stale_limit.max(60)
            && matches!(
                intervention["reason"].as_str(),
                Some("read_backoff" | "shared_server_restriction")
            )
            && matches!(
                intervention["next_action"].as_str(),
                Some("observe_challenge" | "observe_assignments" | "await_retry_eligibility")
            )
            && matches!(component["state"].as_str(), Some("degraded" | "blocked"))
            && reasons.iter().all(|reason| {
                matches!(
                    reason.as_str(),
                    Some(
                        "api_dependency_unavailable"
                            | "challenge_observation_stale"
                            | "shared_server_restriction"
                            | "work_evidence_unavailable"
                            | "admission_blocked"
                    )
                )
            });
        if !is_strict_blocked_wait && !is_transient_upstream_wait {
            return false;
        }
        for reason in reasons {
            if let Some(code) = reason.as_str() {
                explained.push(code);
            }
        }
        if lane_blocked {
            let reason = &admission["reason"];
            let deadline = admission["not_before"]
                .as_i64()
                .max(admission["request_restriction_at"].as_i64());
            if !timed_reason(reason)
                || deadline.is_none_or(|until| until <= at || Some(until) > next)
            {
                return false;
            }
            aggregate_covered = true;
            if let Some(code) = reason.as_str() {
                explained.push(code);
            }
        }
    }
    issues.iter().all(|issue| {
        issue.as_str().is_some_and(|code| {
            (code == "admission_blocked"
                && aggregate_covered
                && report["admission_blocked"] == true)
                || explained.contains(&code)
        })
    })
}

fn operational_summary(report: &mut Value) {
    report["operational_now"] = report["operational"]["status"].clone();
    let historical = report["risk"]["historical_eligible_answers"].as_u64();
    let unresolved = report["risk"]["unresolved_effects"].as_u64();
    report["historical_uncertainty"] = json!({
        "status":if historical.is_some_and(|count| count > 0) {"retained"}
            else if unresolved == Some(0) && report["risk"]["unresolved_model_attempts"] == 0 {
                "none"
            } else {"not_assessed"},
        "historical_eligible_answers":historical,
        "other_unresolved_scope":"not_assessed"
    });
    report["operator_action_required"] = json!(matches!(
        report["intervention"]["status"].as_str(),
        Some("operator_required" | "undetermined")
    ));
    report["severity"] = json!(match report["operational"]["status"].as_str() {
        Some("clear")
            if report["attention_required"] == true
                || report["operator_action_required"] == true =>
            "warning",
        Some("clear") => "clear",
        Some("blocked") => "blocked",
        Some("degraded") => "degraded",
        _ => "unknown",
    });
}

/// Presentation only: the original completion and readiness predicates decide
/// safety, and every deadline comes from the same lane's original evidence.
fn qualify_refresh(report: &mut Value, status: &Value, options: Options, at: i64) {
    for lane in LANES {
        let stale = cycle_floor(status, lane).map(|floor| options.stale_seconds.max(floor));
        let observed = if lane == "judge" {
            status["work"][lane]["assessment"]["observed_at"].as_i64()
        } else {
            observation(status, lane)["observed_at"].as_i64()
        };
        let mut original_deadline = None::<i64>;
        let mut retain_deadline = |value: i64| {
            original_deadline =
                Some(original_deadline.map_or(value, |previous| previous.min(value)));
        };
        if let Some((observed, stale)) = observed.zip(stale) {
            retain_deadline(
                observed
                    .saturating_add(i64::try_from(stale).unwrap_or(i64::MAX))
                    .saturating_add(1),
            );
            if lane != "judge"
                && let Some(maximum) =
                    lane_policy(status, lane)["schedule"]["observation_max_age_seconds"].as_u64()
            {
                retain_deadline(
                    observed.saturating_add(i64::try_from(maximum).unwrap_or(i64::MAX)),
                );
            }
        }
        for assessment in [
            &status["work"][lane]["assessment"],
            &status["lane_participation"][lane]["assessment"],
        ] {
            if assessment["observed_at"].as_i64() == observed
                && let Some(deadline) = assessment["valid_until"].as_i64()
            {
                retain_deadline(deadline);
            }
        }
        if lane == "mine"
            && lane_policy(status, lane)["schedule"]["each_epoch"] != true
            && let Some(deadline) = status["work"][lane]["completion_valid_until"].as_i64()
        {
            retain_deadline(deadline);
        }
        let row = api::discovery(status, lane);
        let failed = row.is_some_and(intervention::read_failed);
        let in_flight =
            row.is_some_and(|row| row["in_flight"] == true || row["state"] == "in_flight");
        let safe = lane_mode(status, lane) == Some("active")
            && report["components"]["controller"]["state"] == "ok"
            && report["components"][lane]["state"] == "ok"
            && report["work"][lane]["intervention"]["status"] == "none_required"
            && stale.is_some_and(|stale| work_complete(status, lane, at, stale));
        let (state, reason) = if (failed || in_flight) && safe {
            if in_flight {
                ("refreshing", "completed_work_discovery_in_flight")
            } else {
                ("transient", "completed_work_discovery_failed")
            }
        } else if failed || in_flight {
            ("blocked", "required_evidence_or_action_outstanding")
        } else if row.is_none() {
            ("unknown", "discovery_evidence_unavailable")
        } else {
            ("idle", "no_refresh_outstanding")
        };
        report["work"][lane]["refresh"] = json!({
            "state":state,"reason":reason,"observed_at":observed,
            "valid_until":original_deadline,
            "evidence":"same_lane_original_completion_not_retry_authority"
        });
    }
}

/// Explicit public presentation allowlist. Classification always precedes this
/// projection; omitted witnesses must never be used to infer safe admission.
pub fn compact_diagnostics(data: &mut Value) {
    operational_summary(data);
    fn within_budget(value: &Value) -> bool {
        struct ByteCount(usize);
        impl std::io::Write for ByteCount {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(bytes.len());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut count = ByteCount(0);
        serde_json::to_writer(&mut count, value).is_ok() && count.0 <= 15 * 1024
    }
    fn fields(value: &Value, names: &[&str], truncated: &mut bool) -> Value {
        let mut out = serde_json::Map::new();
        for &name in names {
            let Some(value) = value.get(name) else {
                continue;
            };
            let projected = match value {
                Value::String(text) if text.len() > 160 => {
                    *truncated = true;
                    let mut end = 160;
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    json!(format!("{}…", &text[..end]))
                }
                Value::Array(rows) => {
                    if rows.len() > 8 {
                        *truncated = true;
                    }
                    Value::Array(
                        rows.iter()
                            .take(8)
                            .filter_map(|row| {
                                if row.is_object() || row.is_array() {
                                    *truncated = true;
                                    None
                                } else if row.as_str().is_some_and(|text| text.len() > 160) {
                                    *truncated = true;
                                    Some(json!("presentation_value_truncated"))
                                } else {
                                    Some(row.clone())
                                }
                            })
                            .collect(),
                    )
                }
                Value::Object(_) => continue,
                _ => value.clone(),
            };
            out.insert(name.to_owned(), projected);
        }
        if let Some(flag) = names
            .iter()
            .copied()
            .find(|name| matches!(*name, "release_truncated" | "blocker_ids_truncated"))
            && matches!(
                (value["blocker_ids"].as_array(), out.get("blocker_ids").and_then(Value::as_array)),
                (Some(original), Some(compact)) if original.len() > compact.len()
            )
        {
            out.insert(flag.to_owned(), Value::Bool(true));
        }
        Value::Object(out)
    }
    fn observation(out: &mut Value, source: &Value, truncated: &mut bool) {
        for key in [
            "next_observation",
            "missing_observation",
            "required_missing_observation",
        ] {
            let Some(value) = source.get(key).filter(|value| value.is_object()) else {
                continue;
            };
            out[key] = fields(
                value,
                &[
                    "status",
                    "owner",
                    "purpose",
                    "operation_id",
                    "binding_revision",
                    "not_before",
                    "floor_kind",
                    "http_status",
                    "scope",
                    "historical_cadence_qualified",
                    "cadence_seconds",
                    "binding_age_seconds",
                    "consecutive_404",
                ],
                truncated,
            );
        }
    }
    fn scoped_work(out: &mut Value, source: &Value, truncated: &mut bool) {
        observation(out, source, truncated);
        for key in ["intent", "continuation", "automatic_step"] {
            if let Some(value) = source.get(key) {
                out[key] = value.clone();
            }
        }
        if let Some(items) = source["findings"]["items"].as_array() {
            let cut = items.len() > 4;
            *truncated |= cut;
            out["findings"] =
                json!({"items":items.iter().take(4).collect::<Vec<_>>(),"truncated":cut});
        }
        let mut assessment = fields(
            &source["assessment"],
            &[
                "observed_at",
                "valid_until",
                "completeness",
                "observed_opportunities",
                "eligible_candidates",
                "locally_judgeable",
                "locally_eligible",
                "exclusion_reason",
                "assessment_reason",
                "capped_work_proven",
            ],
            truncated,
        );
        if source["assessment"]["exclusions"].is_object() {
            assessment["exclusions"] = fields(
                &source["assessment"]["exclusions"],
                &[
                    "already_attempted",
                    "already_settled",
                    "configured_exclusion",
                    "model_budget_exhausted",
                    "model_retry_cooldown",
                    "assignment_read_backoff",
                    "assignment_resource_restricted",
                    "model_uncertain_retry_disabled",
                    "model_uncertain_replacement_exhausted",
                    "model_preparation_reserved",
                    "observation_stale",
                ],
                truncated,
            );
        }
        out["assessment"] = assessment;
        if out.get("admission").is_none() {
            out["admission"] = fields(
                &source["admission"],
                &["state", "allowed", "reason", "scope", "not_before"],
                truncated,
            );
        }
    }
    fn admission(value: &Value, truncated: &mut bool) -> Value {
        let mut out = fields(value, ADMISSION, truncated);
        if let Some(blocker) = value.get("pre_intent_blocker") {
            out["pre_intent_blocker"] = if blocker.is_null() {
                Value::Null
            } else {
                fields(blocker, &["reason", "not_before"], truncated)
            };
        }
        out
    }
    fn verbose_command() -> Value {
        json!({"kind":"instruction","authorization_required":false,
            "message":"Use --verbose to see the full command for this configuration."})
    }

    fn actions(value: &Value, truncated: &mut bool) -> Value {
        let Some(rows) = value.as_array() else {
            return json!([]);
        };
        if rows.len() > 4 {
            *truncated = true;
        }
        json!(
            rows.iter()
                .take(4)
                .map(|row| {
                    let mut action = fields(
                        row,
                        &[
                            "kind",
                            "disposition",
                            "authorization_required",
                            "message",
                            "until",
                            "clock",
                            "evidence",
                        ],
                        truncated,
                    );
                    if row["kind"] == "command" {
                        let argv = &row["argv"];
                        if argv.as_array().is_some_and(|args| {
                            (1..=8).contains(&args.len())
                                && args
                                    .iter()
                                    .all(|arg| arg.as_str().is_some_and(|s| s.len() <= 160))
                        }) {
                            action["argv"] = argv.clone();
                        } else {
                            *truncated = true;
                            return verbose_command();
                        }
                    }
                    action
                })
                .collect::<Vec<_>>()
        )
    }
    let source = &*data;
    let mut truncated = false;
    let mut out = fields(
        source,
        &[
            "healthy",
            "checked_at",
            "issues",
            "warnings",
            "attention_required",
            "initialized",
            "paused",
            "controller_stopped",
            "hosted_identity_verified",
            "heartbeat_age_seconds",
            "observation_age_seconds",
            "heartbeat_recent",
            "observing",
            "preparing",
            "pending_age_seconds",
            "epoch_observed_age_seconds",
            "admission_blocked",
            "unresolved_model_attempts",
            "oldest_unresolved_operation",
            "oldest_unresolved_since",
            "oldest_unresolved_age_seconds",
            "affected_capabilities",
            "progress_age_seconds",
            "last_safety_observation_at",
            "process_identity",
            "evidence",
            "notifications",
            "mutations",
            "expect_participation",
            "state_free_mib",
            "operational_now",
            "operator_action_required",
            "severity",
            "repair_requested",
            "repair_outcome",
            "next_before",
            "reads_truncated",
        ],
        &mut truncated,
    );
    if let Some(root_actions) = source.get("next_actions") {
        out["next_actions"] = actions(root_actions, &mut truncated);
    }
    const FINDING: &[&str] = &[
        "status",
        "state",
        "reason",
        "reasons",
        "observed_at",
        "age_seconds",
        "progress",
        "next_action",
        "next_at",
        "unattended",
        "evidence_fresh",
        "observation_fresh",
        "requires_fresh_eligibility",
        "ready",
        "owner",
        "run_mode",
        "mode",
        "process_identity",
        "last_http_status",
        "last_http_status_observed_at",
        "last_success_at",
        "last_failure_at",
        "failure_category",
        "retry_at",
        "server_floor_at",
        "local_retry_at",
        "retained_floor_at",
        "unattributed_shared_floor_at",
        "blocker_ids",
        "required_release",
        "release_scope",
        "release_truncated",
        "bound_missing",
        "bound_read_status",
        "bound_read_category",
        "resolution",
        "retry_floor",
        "evidence",
        "valid_until",
        "count",
        "bound_count",
        "unbound_count",
        "required_for_participation",
        "completeness",
        "locally_judgeable",
        "observed_opportunities",
        "eligible_candidates",
        "assessment_reason",
    ];
    const ADMISSION: &[&str] = &[
        "state",
        "allowed",
        "reason",
        "scope",
        "own_count",
        "own_limit",
        "own_remaining",
        "account_unresolved",
        "required_release",
        "blocker_ids",
        "blocker_ids_truncated",
        "not_before",
        "restriction_basis",
        "request_restriction_at",
        "retained_uncertainty_nonblocking",
        "historical_eligible_count",
        "capacity_exempt_count",
        "unresolved_count",
    ];
    for name in [
        "operational",
        "risk",
        "historical_uncertainty",
        "assessment_scope",
        "current_epoch",
        "last_reported_build",
        "hosted_identity",
        "writer_authority",
        "desired_capabilities",
        "migration",
        "legacy_observation",
        "effects",
    ] {
        if source.get(name).is_some() {
            out[name] = fields(
                &source[name],
                &[
                    "status",
                    "issues",
                    "evidence",
                    "evidence_fresh",
                    "attention_required",
                    "unresolved_effects",
                    "historical_eligible_answers",
                    "capacity_exempt_answers",
                    "unresolved_model_attempts",
                    "background_remote_work",
                    "retained_uncertainty_nonblocking_lanes",
                    "other_unresolved_scope",
                    "state_filesystem",
                    "epoch",
                    "answered",
                    "source",
                    "version",
                    "commit",
                    "target",
                    "dirty",
                    "build_profile",
                    "build_timestamp",
                    "observed_at",
                    "last_verified_at",
                    "rejection",
                    "legacy_failure",
                    "answer",
                    "judge",
                    "mine",
                    "pending",
                    "required",
                    "format",
                    "reason",
                    "direct_network_requests",
                    "direct_model_calls",
                    "unknown_submissions_replayed",
                    "model_attempts_abandoned",
                    "configuration_changed",
                    "pause_state_changed",
                    "identity_verified",
                    "read_deadlines_reset",
                    "restored_runtime_may_participate",
                ],
                &mut truncated,
            );
        }
    }
    for name in [
        "pending_work",
        "captured_work",
        "reads",
        "request_restrictions",
    ] {
        if let Some(value) = source.get(name) {
            out[format!("{name}_count")] = json!(value.as_array().map(Vec::len));
        }
    }
    out["process_observation"] = fields(
        &source["process_observation"],
        &[
            "state",
            "reason",
            "inspected_at",
            "pid",
            "start_ticks",
            "image_relation",
            "evidence_scope",
        ],
        &mut truncated,
    );
    out["selected_image"] = fields(
        &source["selected_image"],
        &[
            "ownership",
            "state",
            "reason",
            "inspected_at",
            "release",
            "digest",
        ],
        &mut truncated,
    );
    out["release_advisory"] = fields(
        &source["release_advisory"],
        &[
            "availability",
            "freshness",
            "checked_at",
            "latest_version",
            "reason",
            "storage",
            "adoption_required",
            "retry_not_before",
            "next_due_at",
            "owner",
            "selected_running_relation",
            "installability",
            "next_action",
        ],
        &mut truncated,
    );
    for name in ["background", "last_good", "next_action"] {
        if source["release_advisory"][name].is_object() {
            out["release_advisory"][name] = fields(
                &source["release_advisory"][name],
                &[
                    "enabled",
                    "reason",
                    "availability",
                    "checked_at",
                    "latest_version",
                    "kind",
                    "instruction",
                    "argv",
                    "authorization_required",
                ],
                &mut truncated,
            );
        }
    }
    out["thresholds"] = fields(
        &source["thresholds"],
        &[
            "stale_seconds",
            "answer_grace_seconds",
            "cycle_floor_seconds",
            "timing_source",
            "min_free_mib",
            "warn_free_mib",
        ],
        &mut truncated,
    );
    out["intervention"] = fields(&source["intervention"], FINDING, &mut truncated);
    observation(
        &mut out["intervention"],
        &source["intervention"],
        &mut truncated,
    );
    for name in ["controller", "lanes"] {
        out["intervention"][name] = fields(
            &source["intervention"][name],
            &[
                "ready",
                "reason",
                "status",
                "state",
                "owner",
                "run_mode",
                "next_action",
                "next_at",
                "observed_at",
                "evidence_fresh",
                "process_identity",
                "answer",
                "judge",
                "mine",
            ],
            &mut truncated,
        );
    }
    out["participation"] = fields(
        &source["participation"],
        &[
            "unresolved_count",
            "risk_admissions",
            "allowed",
            "reason",
            "scope",
        ],
        &mut truncated,
    );
    out["observations"] = if source["observations"].is_null() {
        Value::Null
    } else {
        json!({})
    };
    for lane in LANES {
        if let Some(observed) = source["observations"].get(lane) {
            out["observations"][lane] = if observed.is_null() {
                Value::Null
            } else {
                fields(
                    observed,
                    &["observed_at", "first_observed_at", "epoch", "answered"],
                    &mut truncated,
                )
            };
        }
        out["work"][lane] = fields(
            &source["work"][lane],
            &[
                "phase",
                "reason",
                "next_action",
                "next_at",
                "progress",
                "operation_epoch",
                "completion_valid_until",
                "binding_revision",
            ],
            &mut truncated,
        );
        for name in [
            "intervention",
            "operational",
            "refresh",
            "background_recovery",
        ] {
            out["work"][lane][name] = fields(&source["work"][lane][name], FINDING, &mut truncated);
            observation(
                &mut out["work"][lane][name],
                &source["work"][lane][name],
                &mut truncated,
            );
        }
        out["work"][lane]["model"] = fields(
            &source["work"][lane]["model"],
            &[
                "operation_id",
                "failure_category",
                "grade_failure",
                "current_route",
                "current_runtime",
                "budget_used",
                "budget_limit",
                "scope",
                "unresolved_attempts",
                "attempts",
                "max_attempts",
                "execution",
                "state",
                "pending_execution_deadline",
            ],
            &mut truncated,
        );
        out["work"][lane]["retry"] = fields(
            &source["work"][lane]["retry"],
            &[
                "policy_eligible",
                "requires_fresh_eligibility",
                "reason",
                "next_at",
                "eligible",
            ],
            &mut truncated,
        );
        out["work"][lane]["next_actions"] =
            actions(&source["work"][lane]["next_actions"], &mut truncated);
        out["work"][lane]["background_recovery"]["next_actions"] = actions(
            &source["work"][lane]["background_recovery"]["next_actions"],
            &mut truncated,
        );
        out["work"][lane]["admission"] =
            admission(&source["work"][lane]["admission"], &mut truncated);
        scoped_work(
            &mut out["work"][lane],
            &source["work"][lane],
            &mut truncated,
        );
        out["participation"]["lanes"][lane] =
            admission(&source["participation"]["lanes"][lane], &mut truncated);
        out["thresholds"]["lanes"][lane] = fields(
            &source["thresholds"]["lanes"][lane],
            &[
                "stale_seconds",
                "work_seconds",
                "model_seconds",
                "read_http_seconds",
                "write_http_seconds",
                "model_attempt_limit",
                "max_uncertain_replacements_per_work",
                "timing_source",
            ],
            &mut truncated,
        );
        out["lane_participation"][lane] = fields(
            &source["lane_participation"][lane],
            &["freshness", "state", "reason", "epoch"],
            &mut truncated,
        );
        out["lane_controls"][lane] = fields(
            &source["lane_controls"][lane],
            &["paused", "reason"],
            &mut truncated,
        );
        out["lane_controls"][lane]["authoritative_closure"] = fields(
            &source["lane_controls"][lane]["authoritative_closure"],
            FINDING,
            &mut truncated,
        );
        out["components"][lane] = fields(&source["components"][lane], FINDING, &mut truncated);
        out["components"][lane]["admission"] = out["work"][lane]["admission"].clone();
        let policy = source
            .get("effective_capabilities")
            .unwrap_or(&source["effective_runtime"]["policy"]["capabilities"]);
        out["effective_capabilities"][lane] = fields(&policy[lane], &["mode"], &mut truncated);
        for section in ["timeouts", "schedule", "preparation", "participation"] {
            out["effective_capabilities"][lane][section] = fields(
                &policy[lane][section],
                &[
                    "read_http_seconds",
                    "http_seconds",
                    "model_seconds",
                    "poll_seconds",
                    "retry_seconds",
                    "backoff_max_seconds",
                    "jitter_seconds",
                    "observation_max_age_seconds",
                    "each_epoch",
                    "max_attempts_per_work",
                    "max_uncertain_replacements_per_work",
                    "while_blocked",
                    "retry_uncertain",
                    "mode",
                    "max_unresolved_operations",
                    "uncertainty_grace_seconds",
                    "retry_uncertain_answers",
                    "uncertain_answer_retry_seconds",
                    "max_answer_attempts_per_epoch",
                    "max_historical_unknown_answers",
                    "historical_unknown_answer_capacity",
                    "interval_seconds",
                    "discovery_retry_seconds",
                    "discovery_backoff_max_seconds",
                ],
                &mut truncated,
            );
        }
    }
    if source.get("effective_runtime").is_some() {
        out["effective_runtime"] = fields(
            &source["effective_runtime"],
            &[
                "revision",
                "reload_blocked",
                "observed_at",
                "authority_epoch",
            ],
            &mut truncated,
        );
    }
    out["components"]["controller"] =
        fields(&source["components"]["controller"], FINDING, &mut truncated);
    out["components"]["api"]["identity"] = fields(
        &source["components"]["api"]["identity"],
        FINDING,
        &mut truncated,
    );
    for lane in LANES {
        out["components"]["api"]["lanes"][lane] = fields(
            &source["components"]["api"]["lanes"][lane],
            FINDING,
            &mut truncated,
        );
    }
    let resources = source["components"]["api"]["resources"]
        .as_array()
        .filter(|rows| {
            !rows.is_empty() || source["components"]["api"]["resources_truncated"].is_boolean()
        });
    out["components"]["api"]["resources"] = json!([]);
    out["components"]["api"]["resources_count"] = json!(resources.map(Vec::len));
    out["components"]["api"]["resources_truncated"] =
        source["components"]["api"]["resources_truncated"].clone();
    let total = resources.map(|_| 0);
    let mut background = json!({"count":total,"degraded":total,"unknown":total});
    for row in resources.into_iter().flatten() {
        if row["dependency"] == "background_remote_work" {
            background["count"] = json!(background["count"].as_u64().unwrap_or(0) + 1);
            if let Some(state @ ("degraded" | "unknown")) = row["health"]["state"].as_str() {
                background[state] = json!(background[state].as_u64().unwrap_or(0) + 1);
            }
        }
    }
    out["components"]["api"]["background_resources"] = background;
    if source["repairs"].is_object() {
        out["repairs"] = fields(
            &source["repairs"],
            &["failure", "preview", "execution", "details_truncated"],
            &mut truncated,
        );
        out["repairs"]["counts"] = fields(
            &source["repairs"]["counts"],
            &["eligible", "ineligible", "applied", "skipped"],
            &mut truncated,
        );
        for name in ["eligible", "ineligible", "applied", "skipped"] {
            if let Some(rows) = source["repairs"][name].as_array() {
                if rows.len() > 4 {
                    truncated = true;
                    out["repairs"]["details_truncated"] = json!(true);
                }
                out["repairs"][name] = Value::Array(
                    rows.iter()
                        .take(4)
                        .map(|row| {
                            fields(
                                row,
                                &[
                                    "operation_id",
                                    "kind",
                                    "classification",
                                    "eligible",
                                    "reason",
                                    "applied",
                                ],
                                &mut truncated,
                            )
                        })
                        .collect(),
                );
            }
        }
        out["repairs"]["restoration"] = fields(
            &source["repairs"]["restoration"],
            &["manager_action", "runtime", "verified"],
            &mut truncated,
        );
    }
    if let Some(rows) = source["diagnostics"].as_array() {
        if rows.len() > 4 {
            truncated = true;
        }
        out["diagnostics"] = json!(
            rows.iter()
                .take(4)
                .map(|row| {
                    let mut diagnostic = fields(
                        row,
                        &["code", "severity", "message", "scope"],
                        &mut truncated,
                    );
                    diagnostic["next_actions"] = actions(&row["next_actions"], &mut truncated);
                    diagnostic
                })
                .collect::<Vec<_>>()
        );
    }
    // Reserve room for the cli.v1 envelope. First compact repetitive per-lane
    // instructions and verbose command arrays before omitting primary diagnostic
    // sections so routine healthy/warning reports retain core evidence.
    let mut omitted = Vec::new();
    let mut fits = within_budget(&out);
    if !fits {
        let mut trimmed_actions = false;
        if let Some(rows) = out["diagnostics"].as_array_mut() {
            for row in rows {
                if let Some(list) = row["next_actions"].as_array_mut() {
                    let before = list.len();
                    list.retain(|item| item["kind"] != "instruction");
                    if list.len() != before {
                        trimmed_actions = true;
                    }
                }
            }
        }
        for lane in LANES {
            if let Some(list) =
                out["work"][lane]["background_recovery"]["next_actions"].as_array_mut()
                && !list.is_empty()
            {
                list.clear();
                trimmed_actions = true;
            }
        }
        if trimmed_actions {
            truncated = true;
            omitted.push("verbose_actions");
            fits = within_budget(&out);
        }
    }
    for name in [
        "lane_participation",
        "effective_capabilities",
        "effective_runtime",
        "selected_image",
        "last_reported_build",
        "hosted_identity",
        "writer_authority",
    ] {
        if fits {
            break;
        }
        if out[name].is_object() {
            if name == "effective_capabilities" {
                for lane in LANES {
                    out[name][lane] = fields(&out[name][lane], &["mode"], &mut truncated);
                }
            } else {
                out[name] = json!({});
            }
            omitted.push(name);
            truncated = true;
            fits = within_budget(&out);
        }
    }
    if !fits {
        for lane in LANES {
            let background = &source["work"][lane]["background_recovery"];
            out["work"][lane]["retry"] = json!({});
            out["work"][lane]["background_recovery"] = fields(
                background,
                &[
                    "count",
                    "bound_count",
                    "unbound_count",
                    "required_for_participation",
                    "next_at",
                ],
                &mut truncated,
            );
            observation(
                &mut out["work"][lane]["background_recovery"],
                &source["work"][lane]["background_recovery"],
                &mut truncated,
            );
            out["work"][lane]["background_recovery"]["next_actions"] = json!([]);
            scoped_work(
                &mut out["work"][lane],
                &source["work"][lane],
                &mut truncated,
            );
            out["components"][lane] = fields(
                &out["components"][lane],
                &["state", "reasons", "mode", "observed_at", "age_seconds"],
                &mut truncated,
            );
        }
        let background = out["components"]["api"]["background_resources"].take();
        out["components"]["api"] = json!({
            "resources":[],"resources_count":resources.map(Vec::len),
            "resources_truncated":source["components"]["api"]["resources_truncated"],
            "background_resources":background,
            "details_omitted":true,
        });
        omitted.push("work_detail_and_api");
        truncated = true;
        fits = within_budget(&out);
    }
    if !fits {
        // Worst-case strings/lists still cannot turn routine output into an
        // unbounded log. Keep the canonical top-level decisions and their types.
        let background = out["components"]["api"]["background_resources"].take();
        for (name, value) in out.as_object_mut().expect("compact object") {
            if value.is_object()
                && !matches!(
                    name.as_str(),
                    "operational"
                        | "risk"
                        | "historical_uncertainty"
                        | "intervention"
                        | "work"
                        | "repairs"
                )
            {
                *value = json!({});
            }
        }
        out["components"]["api"]["background_resources"] = background;
        for lane in LANES {
            let work = &source["work"][lane];
            let mut intervention = fields(
                &work["intervention"],
                &[
                    "status",
                    "reason",
                    "next_action",
                    "next_at",
                    "release_scope",
                    "required_release",
                    "release_truncated",
                ],
                &mut truncated,
            );
            observation(&mut intervention, &work["intervention"], &mut truncated);
            let mut background = fields(
                &work["background_recovery"],
                &[
                    "count",
                    "bound_count",
                    "unbound_count",
                    "required_for_participation",
                ],
                &mut truncated,
            );
            observation(
                &mut background,
                &work["background_recovery"],
                &mut truncated,
            );
            background["next_actions"] = json!([]);
            out["work"][lane] = json!({"intervention":intervention,"background_recovery":background,
                "phase":work["phase"],"progress":work["progress"],"reason":work["reason"],
                "next_actions":actions(&work["next_actions"], &mut truncated)});
            scoped_work(&mut out["work"][lane], work, &mut truncated);
        }
        omitted.push("extended_details");
        truncated = true;
        fits = within_budget(&out);
    }
    if !fits {
        fn bound(value: &mut Value) {
            match value {
                Value::String(text) if text.len() > 64 => {
                    let mut end = 64;
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    text.truncate(end);
                }
                Value::Object(object) if object.get("kind").is_some_and(|v| v == "command") => {
                    *value = verbose_command();
                }
                Value::Array(rows) => {
                    rows.truncate(2);
                    for row in rows {
                        bound(row);
                    }
                }
                Value::Object(object) => {
                    for child in object.values_mut() {
                        bound(child);
                    }
                }
                _ => {}
            }
        }
        for lane in LANES {
            scoped_work(
                &mut out["work"][lane],
                &source["work"][lane],
                &mut truncated,
            );
        }
        bound(&mut out);
        omitted.push("long_strings_and_lists");
        truncated = true;
    }
    out["presentation"] = json!({"truncated":truncated,"omitted_sections":omitted,
        "scope":"allowlisted_summary_not_admission_evidence",
        "resource_details_omitted":resources.is_some_and(|rows| !rows.is_empty())});
    *data = out;
}

fn sync_work_components(report: &mut Value) {
    for lane in LANES {
        report["work"][lane]["operational"] = json!({
            "state":report["components"][lane]["state"],
            "reasons":report["components"][lane]["reasons"],
        });
    }
}

fn settled_inventory(assessment: &Value) -> bool {
    let settled = assessment["exclusions"]["already_settled"].as_u64();
    settled.is_some_and(|count| count > 0)
        && settled == assessment["observed_opportunities"].as_u64()
}

fn work_complete(status: &Value, lane: &str, at: i64, stale: u64) -> bool {
    if status["lane_participation"][lane]["freshness"] == "stale" {
        return false;
    }
    let work = &status["work"][lane];
    if lane == "judge" {
        judge_inventory_fresh(status, at, stale)
            && matches!(
                judge_inventory(&work["assessment"]),
                JudgeInventory::Idle | JudgeInventory::Exhausted
            )
            && model_route_fault(&work["model"]).is_none()
            && !judge_model_relevance_unknown(&work["model"])
            && !current_remote_work(status, lane)
            && !status["pending_work"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|row| {
                    row["kind"] == lane
                        && row.get("nonblocking_for_fresh_work") == Some(&Value::Null)
                })
    } else {
        let observed = observation(status, lane);
        observation_fresh(status, lane, observed["observed_at"].as_i64(), at, stale) == Some(true)
            && if lane == "answer" {
                observed["answered"] == true
            } else {
                work["phase"] == "completed"
                    && observed["epoch"].as_u64().is_some()
                    && work["operation_epoch"] == observed["epoch"]
                    && (lane_policy(status, lane)["schedule"]["each_epoch"] == true
                        || work["completion_valid_until"]
                            .as_i64()
                            .is_some_and(|deadline| at < deadline))
            }
    }
}

fn push_issue(result: &mut Value, code: &str) {
    let issues = result["issues"]
        .as_array_mut()
        .expect("health issues array");
    if !issues.iter().any(|issue| issue == code) {
        issues.push(json!(code));
    }
}

pub(crate) fn judge_model_relevance_unknown(model: &Value) -> bool {
    model["scope"] == "unassessed_assignment"
        && matches!(
            model["state"].as_str(),
            Some(
                "model_unknown"
                    | "superseded_model_unknown"
                    | "abandoned_model"
                    | "retry_model"
                    | "prelaunch_failed"
                    | "rejected"
            )
        )
}

fn judge_inventory_fresh(status: &Value, at: i64, stale: u64) -> bool {
    status["lane_participation"]["judge"]["freshness"] != "stale"
        && assessment_fresh(&status["work"]["judge"]["assessment"], at, stale)
}

pub(crate) fn model_route_fault(model: &Value) -> Option<&'static str> {
    if model["current_route"] != true {
        return None;
    }
    match model["failure_category"].as_str()? {
        "native_auth_unavailable" => Some("model_authentication_failed"),
        "native_api_unsupported"
        | "native_route_mismatch"
        | "executable_unavailable"
        | "core_guidance_missing"
        | "invalid_solver_setup"
        | "unsupported_harness_version"
        | "native_qualification_failed"
        | "native_qualification_unavailable"
        | "invalid_model_deadline" => Some("model_configuration_failed"),
        _ => None,
    }
}

fn current_remote_work(status: &Value, lane: &str) -> bool {
    std::iter::once(&status["pending"])
        .chain(status["pending_work"].as_array().into_iter().flatten())
        .any(|work| {
            work["kind"] == lane
                && work
                    .get("nonblocking_for_fresh_work")
                    .is_none_or(|flag| flag == false)
                && matches!(
                    work["state"].as_str(),
                    Some("unknown" | "queued" | "included_pending")
                )
        })
}

fn current_work(status: &Value, lane: &str) -> bool {
    std::iter::once(&status["pending"])
        .chain(status["pending_work"].as_array().into_iter().flatten())
        .chain(status["captured_work"].as_array().into_iter().flatten())
        .any(|work| {
            work["kind"] == lane
                && work
                    .get("nonblocking_for_fresh_work")
                    .is_none_or(|flag| flag == false)
                && matches!(
                    work["state"].as_str(),
                    Some(
                        "unknown"
                            | "generating"
                            | "generated"
                            | "prepared"
                            | "dispatching"
                            | "retry"
                            | "queued"
                            | "included_pending"
                    )
                )
        })
        || (matches!(
            status["work"][lane]["read_key"]["purpose"].as_str(),
            Some("job" | "receipt")
        ) && status["work"][lane]["operation_id"].as_i64().is_some())
}

fn expectation_only(code: &str) -> bool {
    matches!(
        code,
        "participation_paused"
            | "admission_paused"
            | "lane_paused"
            | "reload_blocked"
            | "config_reload_rejected"
            | "capability_not_active"
            | "no_active_capabilities"
    )
}

fn qualify_components(result: &mut Value, status: &Value, options: Options) {
    for name in ["controller", "answer", "judge", "mine"] {
        let mode = lane_mode(status, name);
        let current = name != "controller" && current_work(status, name);
        let required = name == "controller"
            || mode == Some("read_only")
            || current
            || (options.expect_participation && mode == Some("active"));
        if mode == Some("active") {
            let admission = &status["participation"]["lanes"][name];
            if !options.expect_participation {
                match admission.get("pre_intent_blocker") {
                    Some(Value::Null) => {}
                    Some(blocker) => push_issue(
                        result,
                        blocker["reason"]
                            .as_str()
                            .unwrap_or("admission_evidence_unavailable"),
                    ),
                    None => push_issue(result, "admission_evidence_unavailable"),
                }
            } else if admission["allowed"] == false {
                push_issue(
                    result,
                    admission["reason"].as_str().unwrap_or("admission_blocked"),
                );
            }
        }
        if result["work"][name]["required_missing_observation"].is_object() {
            push_issue(result, "api_dependency_unavailable");
            let component = &mut result["components"][name];
            if let Some(reasons) = component["reasons"].as_array_mut()
                && !reasons
                    .iter()
                    .any(|reason| reason == "api_dependency_unavailable")
            {
                reasons.push(json!("api_dependency_unavailable"));
            }
            if component["state"] == "ok" {
                component["state"] = json!("degraded");
            }
        }
        if current
            && let Some(dependency) = api::bound(status, &status["work"][name])
            && matches!(dependency["purpose"].as_str(), Some("job" | "receipt"))
            // Bound 404s already use the causal, page-independent decision
            // above. Selection for display does not make a receipt required.
            && dependency["status"] != 404
        {
            let stale = cycle_floor(status, name)
                .unwrap_or(0)
                .max(options.stale_seconds);
            let at = result["checked_at"]
                .as_i64()
                .expect("health observation time");
            if api::has_future_observation(dependency, at) {
                push_issue(result, "clock_regressed");
            } else if intervention::read_failed(dependency)
                && fresh(dependency["last_failure_at"].as_i64(), at, stale)
            {
                push_issue(result, "api_dependency_unavailable");
            }
        }
        if !required
            || matches!(
                result["components"][name]["state"].as_str(),
                Some("ok" | "disabled")
            )
        {
            continue;
        }
        let reasons = result["components"][name]["reasons"].take();
        for reason in reasons
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if options.expect_participation || !expectation_only(reason) {
                push_issue(result, reason);
            }
        }
        result["components"][name]["reasons"] = reasons;
    }
}

fn unknown_issue(code: &str) -> bool {
    matches!(
        code,
        "effective_policy_unavailable"
            | "effective_mode_unavailable"
            | "clock_regressed"
            | "controller_unobserved"
            | "controller_stale"
            | "controller_evidence_unavailable"
            | "challenge_unobserved"
            | "challenge_observation_stale"
            | "answer_evidence_unavailable"
            | "admission_unobserved"
            | "model_deadline_unavailable"
            | "state_disk_space_unavailable"
            | "runtime_restored_observation_pending"
            | "local_evidence_unavailable"
            | "work_evidence_unavailable"
            | "admission_evidence_unavailable"
            | "reconciliation_evidence_unavailable"
            | "reconciliation_evidence_truncated"
            | "hosted_identity_unobserved"
            | "hosted_identity_unavailable"
            | "hosted_identity_invalid_response"
            | "hosted_identity_legacy_unknown"
    )
}

fn issue_state(result: &Value, code: &str) -> &'static str {
    if unknown_issue(code) {
        return "unknown";
    }
    match code {
        "admission_blocked" | "admission_paused" | "lane_paused" => return "blocked",
        "not_initialized"
        | "migration_pending"
        | "identity_mismatch"
        | "api_routing_mismatch"
        | "controller_stopped"
        | "process_identity_mismatch"
        | "participation_paused"
        | "reload_blocked"
        | "state_disk_space_low"
        | "api_dependency_unavailable"
        | "model_work_overdue"
        | "dispatch_outcome_uncertain"
        | "pending_work_overdue"
        | "pending_model_execution_expired"
        | "hosted_identity_authentication_failed"
        | "hosted_identity_mismatch" => return "degraded",
        _ => {}
    }
    for name in ["controller", "answer", "judge", "mine"] {
        let admission = &result["participation"]["lanes"][name];
        if admission["pre_intent_blocker"]["reason"] == code
            || (admission["allowed"] == false && admission["reason"] == code)
        {
            return "blocked";
        }
        let row = &result["components"][name];
        if row["reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|reason| reason == code))
        {
            return match row["state"].as_str() {
                Some("degraded") => "degraded",
                Some("blocked") => "blocked",
                _ => "unknown",
            };
        }
        if row["admission"]["allowed"] == false && row["admission"]["reason"] == code {
            return "blocked";
        }
    }
    "degraded"
}

fn finalize_readiness(result: &mut Value) {
    let issues = result["issues"].as_array().expect("health issues array");
    let mut state = "clear";
    let rank = |state| match state {
        "degraded" => 3,
        "blocked" => 2,
        "unknown" => 1,
        _ => 0,
    };
    for code in issues.iter().filter_map(Value::as_str) {
        let finding = issue_state(result, code);
        if rank(finding) > rank(state) {
            state = finding;
        }
    }
    result["healthy"] = json!(issues.is_empty());
    result["operational"]["status"] = json!(state);
    result["operational"]["issues"] = result["issues"].clone();
    result["attention_required"] = json!(
        result["healthy"] != true
            || result["warnings"]
                .as_array()
                .is_some_and(|warnings| !warnings.is_empty())
    );
}

fn apply_disk_issue(result: &mut Value, code: &str) {
    push_issue(result, code);
    let row = &mut result["components"]["controller"];
    if row["state"] == "ok" || (code == "state_disk_space_low" && row["state"] == "unknown") {
        row["state"] = json!(if code == "state_disk_space_low" {
            "degraded"
        } else {
            "unknown"
        });
        row["next_actions"] = inspection_actions();
    }
    let reasons = row["reasons"].as_array_mut().expect("component reasons");
    reasons.retain(|reason| reason != "controller_recent");
    if !reasons.iter().any(|reason| reason == code) {
        reasons.push(json!(code));
    }
    intervention::qualify_disk(result, code);
    finalize_readiness(result);
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

fn observation_fresh(
    status: &Value,
    lane: &str,
    timestamp: Option<i64>,
    at: i64,
    stale: u64,
) -> Option<bool> {
    let maximum_age = lane_policy(status, lane)["schedule"]["observation_max_age_seconds"]
        .as_u64()
        .filter(|seconds| *seconds > 0)?;
    let assessment = &status["lane_participation"][lane]["assessment"];
    // A later policy must not extend an already recorded observation deadline.
    let recorded_bound = assessment.is_null()
        || assessment["observed_at"].as_i64() != timestamp
        || assessment_fresh(assessment, at, stale);
    Some(
        fresh(timestamp, at, stale)
            && timestamp.is_some_and(|time| (at.saturating_sub(time) as u64) < maximum_age)
            && status["lane_participation"][lane]["freshness"] != "stale"
            && recorded_bound,
    )
}

fn assessment_fresh(assessment: &Value, at: i64, stale: u64) -> bool {
    // Aggregate inventory validity expires at its earliest page, not its last.
    fresh(assessment["observed_at"].as_i64(), at, stale)
        && assessment["valid_until"]
            .as_i64()
            .is_some_and(|until| until > at)
}

fn components(status: &Value, health: &Value, at: i64, stale: u64, options: Options) -> Value {
    let effective = &status["effective_runtime"];
    let observed = effective["observed_at"].as_i64();
    let active = LANES
        .iter()
        .any(|name| lane_mode(status, name) == Some("active"));
    let identity = hosted_identity(status);
    // Participation gates must not conceal independent intrinsic core evidence.
    let controller_findings = [
        (status["initialized"] != true, "unknown", "not_initialized"),
        (
            status["migration"]["pending"] == true,
            "blocked",
            "migration_pending",
        ),
        (
            status["identity_matches_config"] == false,
            "blocked",
            "identity_mismatch",
        ),
        (
            status["network_routing"]["matches_config"] == false,
            "blocked",
            "api_routing_mismatch",
        ),
        (
            status["process_identity"] == "mismatch",
            "blocked",
            "process_identity_mismatch",
        ),
        (
            status["controller_stopped"] == true || status["process_identity"] == "stopped",
            "blocked",
            "controller_stopped",
        ),
        (
            status["paused"] == true && active,
            "blocked",
            "participation_paused",
        ),
        (
            effective["reload_blocked"] == true,
            "blocked",
            "reload_blocked",
        ),
        (
            health["thresholds"]["timing_source"] != "effective"
                || LANES.iter().any(|name| {
                    !matches!(
                        lane_mode(status, name),
                        Some("active" | "read_only" | "off")
                    )
                }),
            "unknown",
            "effective_policy_unavailable",
        ),
        (
            observed.is_some_and(|time| time > at),
            "unknown",
            "clock_regressed",
        ),
        (observed.is_none(), "unknown", "controller_unobserved"),
        (
            observed.is_some_and(|time| time <= at) && !fresh(observed, at, stale),
            "unknown",
            "controller_stale",
        ),
        (
            active
                && (identity.rejected()
                    || (status["paused"] == false && identity.verified() != Some(true))),
            if identity.rejected() {
                "blocked"
            } else {
                "unknown"
            },
            identity.reason(),
        ),
        (
            status["paused"].as_bool().is_none()
                || status["identity_matches_config"].as_bool().is_none()
                || status["controller_stopped"].as_bool().is_none(),
            "unknown",
            "controller_evidence_unavailable",
        ),
    ];
    let intrinsic = controller_findings.iter().find(|(applies, _, _)| *applies);
    let (state, reason) = intrinsic
        .map(|(_, state, reason)| (*state, *reason))
        .unwrap_or(("ok", "controller_recent"));
    let mut controller = component(state, reason, observed, at);
    if intrinsic.is_some() {
        controller["reasons"] = controller_findings
            .iter()
            .filter(|(applies, _, _)| *applies)
            .map(|(_, _, reason)| json!(reason))
            .collect();
    }
    let apis = api::evaluate(status, at, options.stale_seconds);
    let mut value = json!({"controller":controller,"api":apis});
    for name in LANES {
        let mode = lane_mode(status, name);
        let stale = cycle_floor(status, name)
            .unwrap_or(0)
            .max(options.stale_seconds);
        let timing = work_timing(status, name, options);
        let work = &status["work"][name];
        let primary = &value["api"]["lanes"][name];
        let observation = if name == "judge" {
            work["assessment"]["observed_at"].as_i64()
        } else {
            observation(status, name)["observed_at"].as_i64()
        };
        let evidence_at = observation.or(primary["observed_at"].as_i64());
        // Decide with borrowed codes; allocate each JSON component only once.
        let mut finding = ("unknown", "work_evidence_unavailable", evidence_at);
        let mut concurrent_read_issue = None;
        if mode == Some("off") {
            finding = ("disabled", "capability_off", observed);
        } else if observation.is_some_and(|time| time > at) {
            finding = ("unknown", "clock_regressed", observation);
        } else if mode == Some("active")
            && status["lane_controls"][name]["authoritative_closure"]["state"] == "closed"
        {
            let closure = &status["lane_controls"][name]["authoritative_closure"];
            let has_reason = |code| {
                closure["reasons"]
                    .as_array()
                    .is_some_and(|reasons| reasons.iter().any(|reason| reason == code))
            };
            finding = (
                "blocked",
                if has_reason("global_paused") {
                    "admission_paused"
                } else if has_reason("lane_paused") {
                    "lane_paused"
                } else {
                    "admission_blocked"
                },
                status["lane_controls"][name]["authoritative_closure"]["observed_at"].as_i64(),
            );
        } else if !matches!(mode, Some("active" | "read_only")) {
            finding = ("unknown", "effective_mode_unavailable", observed);
        } else {
            let read_only = mode == Some("read_only");
            let admission = work["admission"]["allowed"]
                .as_bool()
                .map(|allowed| !allowed);
            if !read_only && (admission == Some(true) || work["phase"] == "blocked") {
                finding = (
                    "blocked",
                    work["admission"]["reason"]
                        .as_str()
                        .unwrap_or("admission_blocked"),
                    evidence_at,
                );
                // An admission timer does not explain a separate failed discovery.
                if intervention::floor_kind(finding.1, &work["admission"]["restriction_basis"])
                    .is_some()
                    && let Some(dependency) = api::discovery(status, name)
                {
                    concurrent_read_issue = if api::has_future_observation(dependency, at) {
                        Some("clock_regressed")
                    } else if primary["state"] == "degraded" {
                        Some("api_dependency_unavailable")
                    } else {
                        None
                    };
                }
            } else if !read_only && admission.is_none() {
                finding = ("unknown", "admission_evidence_unavailable", evidence_at);
            } else {
                let complete = work_complete(status, name, at, stale);
                let usable_observation = if name == "judge" {
                    judge_inventory_fresh(status, at, stale)
                } else {
                    observation_fresh(status, name, observation, at, stale) == Some(true)
                };
                if read_only {
                    if primary["state"] == "ok"
                        && observation_fresh(
                            status,
                            name,
                            primary["observed_at"].as_i64(),
                            at,
                            stale,
                        ) == Some(true)
                    {
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
                            "judge" if work["assessment"]["capped_work_proven"] == true => {
                                "model_attempts_exhausted_for_observed_work"
                            }
                            "judge" if settled_inventory(&work["assessment"]) => {
                                "observed_judgments_already_settled"
                            }
                            "judge" => "no_eligible_assignments_observed",
                            _ => "current_epoch_completed",
                        },
                        observation,
                    );
                } else if !read_only
                    && admission == Some(false)
                    && primary["state"] == "ok"
                    && usable_observation
                    && work["phase"] == "observing"
                    && match name {
                        "judge" => {
                            judge_inventory(&work["assessment"]) == JudgeInventory::Available
                        }
                        "answer" => status["observations"][name]["answered"] == false,
                        _ => status["observations"][name]["epoch"].as_u64().is_some(),
                    }
                {
                    finding = ("ok", "fresh_work_available", observation);
                }
                if !read_only
                    && !complete
                    && usable_observation
                    && current_remote_work(status, name)
                    && matches!(
                        work["phase"].as_str(),
                        Some("unknown" | "queued" | "included_pending")
                    )
                {
                    finding = ("blocked", "current_work_outcome_unresolved", observation);
                }
                if !read_only
                    && name == "judge"
                    && usable_observation
                    && let JudgeInventory::Blocked(reason) = judge_inventory(&work["assessment"])
                {
                    finding = (
                        if reason == "api_dependency_unavailable" {
                            "degraded"
                        } else {
                            "blocked"
                        },
                        reason,
                        observation,
                    );
                }
                // Completed current work or idle inventory cannot hide another
                // overdue operation. Share the overall health deadline authority.
                for pending in std::iter::once(&status["pending"])
                    .chain(status["pending_work"].as_array().into_iter().flatten())
                    .chain(status["captured_work"].as_array().into_iter().flatten())
                    .filter(|pending| {
                        pending["kind"] == name && pending["nonblocking_for_fresh_work"] != true
                    })
                {
                    let timestamp = pending["updated_at"]
                        .as_i64()
                        .or(pending["created_at"].as_i64());
                    if model_awaiting_admission(pending)
                        && pending["pending_execution_deadline"].as_i64().is_none()
                    {
                        finding = ("unknown", "model_deadline_unavailable", timestamp);
                        break;
                    }
                    if let Some(issue) =
                        timing.as_ref().and_then(|timing| timing.issue(pending, at))
                    {
                        finding = ("degraded", issue, timestamp);
                        break;
                    }
                    let timely = match pending["state"].as_str() {
                        Some("generating") => {
                            timing.as_ref().and_then(|timing| {
                                model_overdue(pending, at, timing.poll, timing.model)
                            }) == Some(false)
                        }
                        Some("dispatching") => {
                            pending["http_deadline"].as_i64().is_some()
                                || pending["updated_at"].as_i64().is_some()
                        }
                        Some("generated" | "prepared" | "retry") => {
                            pending["created_at"].as_i64().is_some()
                        }
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
                // A dependency is selected by owner and exact binding, never by
                // the first job/receipt/hydration error in the account.
                let bound = match work["next_action"].as_str() {
                    Some("read_job" | "read_receipt") => api::bound(status, work),
                    _ if !read_only
                        && matches!(
                            work["reason"].as_str(),
                            Some("identity_backoff" | "identity_in_flight")
                        ) =>
                    {
                        api::identity(status)
                    }
                    _ if work["read_key"]["purpose"] == "assignment" => {
                        api::keyed(status, &work["read_key"])
                    }
                    _ => None,
                };
                for (dependency, bound_read) in
                    [(api::discovery(status, name), false), (bound, true)]
                {
                    let Some(dependency) = dependency else {
                        continue;
                    };
                    if api::has_future_observation(dependency, at) {
                        finding = ("unknown", "clock_regressed", evidence_at);
                        break;
                    }
                    // Current completion or timely work supersedes older discovery
                    // failures; unrelated recorded history is not a dependency.
                    if !read_only
                        && ((!bound_read
                            && complete
                            && !matches!(dependency["status"].as_u64(), Some(401 | 403)))
                            || ((complete || (!bound_read && finding.1 == "work_in_progress"))
                                && dependency["last_failure_at"]
                                    .as_i64()
                                    .zip(finding.2)
                                    .is_none_or(|(failure, observed)| failure <= observed)))
                    {
                        continue;
                    }
                    let dependency = api::project(Some(dependency), at, stale);
                    if dependency["state"] == "degraded" {
                        finding = (
                            "degraded",
                            "api_dependency_unavailable",
                            dependency["observed_at"].as_i64(),
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
        // Intent does not cancel native execution or an unsettled dispatch.
        // Keep its deadline visible even when admission/mode overlays win above.
        for pending in std::iter::once(&status["pending"])
            .chain(status["pending_work"].as_array().into_iter().flatten())
            .chain(status["captured_work"].as_array().into_iter().flatten())
            .filter(|pending| {
                pending["kind"] == name && pending["nonblocking_for_fresh_work"] != true
            })
        {
            if pending["state"] == "generating"
                && let Some(timing) = timing.as_ref()
                && model_overdue(pending, at, timing.poll, timing.model).is_none()
            {
                finding = (
                    "unknown",
                    "model_deadline_unavailable",
                    pending["updated_at"].as_i64(),
                );
                continue;
            }
            if let Some(issue) = timing.as_ref().and_then(|timing| timing.issue(pending, at)) {
                finding = ("degraded", issue, pending["updated_at"].as_i64());
                break;
            }
        }
        let intervention_reason = health["work"][name]["intervention"]["reason"].as_str();
        if mode == Some("active")
            && matches!(
                intervention_reason,
                Some(
                    "model_authentication_failed"
                        | "model_configuration_failed"
                        | "native_workspace_unavailable"
                        | "native_workspace_capacity"
                        | "native_workspace_permission"
                        | "native_workspace_failure"
                        | "model_attempt_budget_exhausted"
                        | "model_uncertain"
                        | "model_uncertain_retry_disabled"
                        | "model_uncertain_replacement_exhausted"
                        | "model_retry_unavailable"
                )
            )
            && finding.0 != "degraded"
        {
            finding = ("degraded", intervention_reason.unwrap(), evidence_at);
        }
        let inherited = controller_findings
            .iter()
            .filter(|(applies, _, _)| *applies)
            .map(|(_, state, reason)| (*state, *reason))
            .find(|(_, reason)| {
                mode != Some("read_only")
                    || (!reason.starts_with("hosted_identity_")
                        && *reason != "participation_paused")
            })
            .filter(|_| mode != Some("off"));
        let local = finding;
        if let Some((state, reason)) = inherited
            && matches!(finding.0, "ok" | "unknown")
            && (finding.0 == "ok" || state == "blocked")
        {
            finding = (state, reason, observed);
        }
        let mut row = component(finding.0, finding.1, finding.2, at);
        if local.1 != finding.1 && !matches!(local.0, "ok" | "disabled") {
            row["reasons"].as_array_mut().unwrap().push(json!(local.1));
        }
        if let Some(issue) = concurrent_read_issue
            && issue != finding.1
            && issue != local.1
        {
            row["reasons"].as_array_mut().unwrap().push(json!(issue));
        }
        row["mode"] = json!(mode);
        row["admission"] = work["admission"].clone();
        row["control"] = status["lane_controls"][name].clone();
        value[name] = row;
    }
    value
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod hardening_tests;
