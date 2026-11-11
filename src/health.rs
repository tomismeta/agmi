//! Read-only, local health evidence with a versioned, bounded component contract.
//! Component readiness is separate from retained effect risk and never authorizes
//! replay. Effective modes and fresh local evidence are not live remote probes.
use crate::{capability::LaneId, config::Config, runtime, store::now};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

mod api;
mod intervention;

/// A bounded view of canonical evidence, not an upstream-response classifier.
/// Legacy booleans cannot establish either a current permit or a rejection.
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
        match evidence["status"].as_str() {
            Some(
                state @ ("verified"
                | "unavailable"
                | "authentication_failed"
                | "identity_mismatch"
                | "invalid_response"
                | "legacy_unknown"
                | "unobserved"),
            ) => state,
            _ if !evidence.is_object() && status["hosted_identity_verified"].is_boolean() => {
                "legacy_unknown"
            }
            _ => "unobserved",
        }
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
        legacy_failure: status["initialized"] != false
            && (evidence["legacy_failure"] == true
                || (!evidence.is_object() && status["hosted_identity_verified"] == false)),
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
        }
        intervention::qualify_restoration(report);
    }
    if !repairs["failure"].is_null() {
        intervention::qualify_repair_failure(report);
    }
}

/// This command opens existing state read-only, never recovers it, and performs
/// neither network nor model calls. Errors are deliberately replaced at this boundary.
pub fn check(config: &Config, options: Options) -> Result<Value> {
    let status = match runtime::status_evidence(config) {
        Ok(status) => status,
        Err(_) => {
            return Ok(json!({
                "contract_version":2,"components":unknown_components(),
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
            Some(_)
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
            && timing
                .as_ref()
                .and_then(|timing| model_overdue(work, at, timing.poll, timing.model))
                .is_none()
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
        match observation_age {
            None => issues.push("challenge_unobserved"),
            Some(seconds) if answer_floor.is_some() && seconds > answer_stale => {
                issues.push("challenge_observation_stale");
            }
            _ => {}
        }
        if answer_floor.is_some()
            && answer["answered"] == false
            && epoch_age.is_some_and(|seconds| seconds > grace)
            && observation_age.is_some_and(|seconds| seconds <= answer_stale)
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
    let risk_attention = issues.contains(&"dispatch_outcome_uncertain")
        || warnings.iter().any(|code| {
            matches!(
                *code,
                "pending_outcome_uncertain"
                    | "model_execution_unresolved"
                    | "participation_risk_admitted"
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
            "model_attempt_limit":policy["preparation"]["max_attempts_per_work"].as_u64(),
            "timing_source":if timing.is_some() {"effective"} else {"unavailable"}
        });
    }
    let mut result = json!({
        "contract_version":2,"healthy":issues.is_empty(),"checked_at":at,
        "issues":issues,"warnings":warnings,"attention_required":!issues.is_empty() || !warnings.is_empty(),
        "unresolved_model_attempts":unresolved_models,"initialized":initialized,"paused":paused,
        "expect_participation":options.expect_participation,
        "controller_stopped":status["controller_stopped"].as_bool().unwrap_or(false),
        "hosted_identity_verified":identity.verified(),"hosted_identity":identity.value(),
        "heartbeat_age_seconds":heartbeat_age,"observation_age_seconds":observation_age,
        "heartbeat_recent":fresh(effective["observed_at"].as_i64(),at,stale),
        "observing":fresh(answer["observed_at"].as_i64(),at,answer_stale),"preparing":preparing,
        "last_safety_observation_at":status["last_safety_observation_at"],
        "work":work,"intervention":intervention,"captured_work":status["captured_work"],
        "pending_work":status["pending_work"],"epoch_observed_age_seconds":epoch_age,
        "pending_age_seconds":age(&status["pending"]["created_at"],at),"admission_blocked":admission,
    });
    result["oldest_unresolved_operation"] = status["oldest_unresolved_operation"].clone();
    result["oldest_unresolved_since"] = status["oldest_unresolved_since"].clone();
    result["oldest_unresolved_age_seconds"] = json!(age(&status["oldest_unresolved_since"], at));
    result["affected_capabilities"] = status["affected_capabilities"].clone();
    result["progress_age_seconds"] = json!(age(&status["last_progress_at"], at));
    result["desired_capabilities"] = json!(
        LaneId::ALL
            .into_iter()
            .map(|lane| (lane.as_str(), config.mode(lane)))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
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
    result["process_identity"] = json!("unverified");
    result["evidence"] = json!("local_only");
    result["notifications"] = json!("local_exit_status_and_journal");
    result["current_epoch"] = json!({
        "epoch":answer["epoch"].as_u64(),"answered":answer["answered"].as_bool(),
        "source":"answer","evidence_fresh":answer_floor.map(|_| fresh(answer["observed_at"].as_i64(),at,answer_stale)),
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
        "unresolved_model_attempts":unresolved_models
    });
    result["components"] = components(status, &result, at, stale, options);
    qualify_components(&mut result, status, options);
    finalize_readiness(&mut result);
    result
}

fn push_issue(result: &mut Value, code: &str) {
    let issues = result["issues"]
        .as_array_mut()
        .expect("health issues array");
    if !issues.iter().any(|issue| issue == code) {
        issues.push(json!(code));
    }
}

fn current_work(status: &Value, lane: &str) -> bool {
    std::iter::once(&status["pending"])
        .chain(status["pending_work"].as_array().into_iter().flatten())
        .chain(status["captured_work"].as_array().into_iter().flatten())
        .any(|work| {
            work["kind"] == lane
                && matches!(
                    work["state"].as_str(),
                    Some(
                        "generating"
                            | "generated"
                            | "prepared"
                            | "dispatching"
                            | "retry"
                            | "queued"
                            | "included_pending"
                    )
                )
        })
        || matches!(
            status["work"][lane]["read_key"]["purpose"].as_str(),
            Some("job" | "receipt")
        )
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
        if current
            && let Some(dependency) = api::bound(status, &status["work"][name])
            && matches!(dependency["purpose"].as_str(), Some("job" | "receipt"))
        {
            let stale = cycle_floor(status, name)
                .unwrap_or(0)
                .max(options.stale_seconds);
            let at = result["checked_at"]
                .as_i64()
                .expect("health observation time");
            if ["started_at", "last_success_at", "last_failure_at"]
                .into_iter()
                .any(|field| dependency[field].as_i64().is_some_and(|time| time > at))
            {
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

fn assessment_fresh(assessment: &Value, at: i64, stale: u64) -> bool {
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
            status["controller_stopped"] == true,
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
        if mode == Some("off") {
            finding = ("disabled", "capability_off", observed);
        } else if name == "judge" && observation.is_some_and(|time| time > at) {
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
            } else if !read_only && admission.is_none() {
                finding = ("unknown", "admission_evidence_unavailable", evidence_at);
            } else {
                let complete = fresh(observation, at, stale)
                    && match name {
                        "answer" => status["observations"][name]["answered"] == true,
                        "judge" => {
                            assessment_fresh(&work["assessment"], at, stale)
                                && work["assessment"]["completeness"] == "complete"
                                && work["assessment"]["locally_judgeable"] == false
                        }
                        _ => {
                            work["phase"] == "completed"
                                && status["observations"][name]["epoch"].as_u64().is_some()
                                && work["operation_epoch"] == status["observations"][name]["epoch"]
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
                    if ["started_at", "last_success_at", "last_failure_at"]
                        .into_iter()
                        .any(|field| dependency[field].as_i64().is_some_and(|time| time > at))
                    {
                        finding = ("unknown", "clock_regressed", evidence_at);
                        break;
                    }
                    // Current completion or timely work supersedes older discovery
                    // failures; unrelated recorded history is not a dependency.
                    if !read_only
                        && (complete || (!bound_read && finding.1 == "work_in_progress"))
                        && dependency["last_failure_at"]
                            .as_i64()
                            .zip(finding.2)
                            .is_none_or(|(failure, observed)| failure <= observed)
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
        let intervention_reason = health["work"][name]["intervention"]["reason"].as_str();
        if mode == Some("active")
            && matches!(
                intervention_reason,
                Some(
                    "model_authentication_failed"
                        | "model_configuration_failed"
                        | "model_attempt_budget_exhausted"
                        | "model_uncertain"
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
        row["mode"] = json!(mode);
        row["admission"] = work["admission"].clone();
        row["control"] = status["lane_controls"][name].clone();
        value[name] = row;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    pub(super) fn fixture() -> (Config, Options, Value) {
        let mut config = Config::default();
        config.capabilities.answer.mode = Mode::Active;
        config.capabilities.judge.mode = Mode::Active;
        config.capabilities.mine.mode = Mode::Active;
        let mut status = json!({
            "initialized":true,"paused":false,"controller_stopped":false,
            "identity_matches_config":true,"admission_blocked":false,
            "hosted_identity":{"status":"verified","observed_at":10000,"last_verified_at":10000,
                "rejection":null,"legacy_failure":false},
            "effective_runtime":{"observed_at":10000,"reload_blocked":false,"policy":config},
            "observations":{
                "answer":{"observed_at":10000,"first_observed_at":10000,"epoch":7,"answered":true},
                "mine":{"observed_at":10000,"first_observed_at":10000,"epoch":7,"answered":false}},
            "participation":{"unresolved_count":0,"risk_admissions":0},
            "pending":null,"pending_work":[],"captured_work":[],"reads":[],"work":{}
        });
        for name in LANES {
            status["work"][name] = json!({"phase":"observing","reason":"cadence",
                "next_action":if name == "judge" {"observe_assignments"} else {"observe_challenge"},
                "next_at":10020,"admission":{"allowed":true,"reason":null,"pre_intent_blocker":null,"scope":null,
                    "own_count":0,"own_limit":4,"own_remaining":4,"account_unresolved":0,
                    "required_release":0,"blocker_ids":[],"not_before":null}});
            status["participation"]["lanes"][name] = status["work"][name]["admission"].clone();
            status["reads"].as_array_mut().unwrap().push(json!({
                "owner":name,"purpose":"discovery",
                "resource":if name == "judge" {"assignments"} else {"challenge"},
                "state":"idle","last_success_at":10000,"status":200}));
        }
        status["work"]["answer"]["phase"] = json!("answered");
        status["work"]["judge"]["assessment"] = json!({"observed_at":10000,"valid_until":10060,
            "observed_opportunities":0,"completeness":"complete","locally_judgeable":false});
        status["work"]["mine"]["phase"] = json!("completed");
        status["work"]["mine"]["operation_epoch"] = json!(7);
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
    fn canonical_lane_controls_and_model_evidence_are_preserved_without_permits() {
        let (mut config, options, mut status) = fixture();
        config.capabilities.answer.mode = Mode::Off;
        let control = json!({
            "desired":{"lane_id":"answer","paused":true,"control_revision":7,"control_token":"bound-token"},
            "authoritative_closure":{"state":"closed","reasons":["lane_paused"],
                "source":"journal_control_transaction","account_generation":2,"lane_control_revision":7,"observed_at":10000},
            "observed_admission":{"state":"unknown","reasons":["control_revision_changed"],"freshness":"stale",
                "source":"runtime_snapshot","observed_at":9999,"valid_until":10001,
                "runtime_instance":"earlier-runtime","observed_control_revision":6,
                "accepted_config_revision":"accepted-config","authority_epoch":3},
            "dispatch_uncertainty":{"dispatch_intent_unsettled_count":2,"dispatch_intent_unsettled_ids":[41,42],
                "ids_truncated":false,"unresolved_sent_count":3,"source":"journal_control_transaction"}
        });
        status["lane_controls"]["answer"] = control.clone();
        status["pending_work"] = json!([{"id":41,"kind":"answer","state":"unknown","created_at":9999,
            "model_attempt":{"producer":{"requested":{"model":"requested-model"}},
                "completion":{"reported":{"model":{"value":"reported-model","source":"native_envelope"}}}}}]);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["lane_controls"]["answer"], control);
        assert_eq!(health["components"]["answer"]["control"], control);
        assert_eq!(health["components"]["answer"]["state"], "blocked");
        assert_eq!(health["desired_capabilities"]["answer"], "off");
        assert_eq!(health["effective_capabilities"]["answer"]["mode"], "active");
        assert_eq!(health["pending_work"], status["pending_work"]);
        assert!(health["lane_controls"]["answer"]["fence_ack"].is_null());
        status["lane_controls"]["answer"]["desired"]["paused"] = json!(false);
        status["lane_controls"]["answer"]["authoritative_closure"]["state"] = json!("not_closed");
        status["lane_controls"]["answer"]["authoritative_closure"]["reasons"] = json!([]);
        let resumed = evaluate(&config, options, &status, 10000);
        assert_eq!(
            resumed["lane_controls"]["answer"]["observed_admission"]["state"],
            "unknown"
        );
        assert_eq!(
            resumed["lane_controls"]["answer"]["dispatch_uncertainty"],
            control["dispatch_uncertainty"]
        );
    }

    #[test]
    fn effective_policy_is_never_replaced_by_desired_config() {
        let (mut config, options, mut status) = fixture();
        status["effective_runtime"]["policy"] = Value::Null;
        let before = evaluate(&config, options, &status, 10000);
        config.capabilities.answer.timeouts.model_seconds = 7200;
        config.capabilities.answer.schedule.poll_seconds = 7200;
        config.capabilities.answer.mode = Mode::Off;
        let after = evaluate(&config, options, &status, 10000);
        assert_eq!(before["thresholds"], after["thresholds"]);
        assert!(has(&after, "effective_policy_unavailable"));
        assert_eq!(after["components"]["answer"]["mode"], Value::Null);
        assert_eq!(after["current_epoch"]["evidence_fresh"], Value::Null);
    }

    #[test]
    fn pending_model_admission_uses_only_its_captured_execution_bound() {
        let (config, options, mut status) = fixture();
        status["work"]["answer"]["phase"] = json!("preparing");
        status["work"]["answer"]["reason"] = json!("model_running");
        status["captured_work"] = json!([{"kind":"answer","state":"generating",
            "created_at":1,"updated_at":1,"model_deadline":null,
            "pending_execution_deadline":10001,
            "diagnostic":{"stage":"model_preflight","execution":"not_started",
                "state":"awaiting_admission","remaining_budget_millis":1}}]);
        let before = evaluate(&config, options, &status, 10000);
        assert_eq!(before["healthy"], true);
        assert_eq!(
            before["work"]["answer"]["intervention"]["reason"],
            "model_launch_awaiting_admission"
        );
        assert_eq!(before["work"]["answer"]["intervention"]["next_at"], 10001);

        // Diagnostic budgets cannot renew the captured bound.
        status["captured_work"][0]["diagnostic"]["remaining_budget_millis"] = json!(999999);
        let expired = evaluate(&config, options, &status, 10001);
        assert!(has(&expired, "pending_model_execution_expired"));
        assert!(!has(&expired, "model_work_overdue"));
        assert_eq!(expired["healthy"], false);
        assert_eq!(expired["risk"]["attention_required"], false);
        assert_eq!(expired["components"]["answer"]["state"], "degraded");
        assert_eq!(
            expired["work"]["answer"]["intervention"]["reason"],
            "pending_model_execution_expired"
        );
        assert_eq!(
            expired["work"]["answer"]["intervention"]["status"],
            "undetermined"
        );
        assert_eq!(
            expired["work"]["answer"]["intervention"]["next_action"],
            "inspect_local_evidence"
        );
        assert!(expired["captured_work"][0]["model_deadline"].is_null());

        status["captured_work"][0]["pending_execution_deadline"] = Value::Null;
        let missing = evaluate(&config, options, &status, 10001);
        assert!(!has(&missing, "pending_model_execution_expired"));
        assert!(!has(&missing, "model_work_overdue"));
        assert!(
            missing["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|warning| warning == "model_deadline_unavailable")
        );
        assert_eq!(missing["components"]["answer"]["state"], "unknown");
        assert_eq!(
            missing["work"]["answer"]["intervention"]["reason"],
            "model_deadline_unavailable"
        );

        status["captured_work"][0]["model_deadline"] = json!(1);
        let running = evaluate(&config, options, &status, 10001);
        assert!(has(&running, "model_work_overdue"));
        assert!(!has(&running, "pending_model_execution_expired"));
        assert_eq!(
            running["work"]["answer"]["intervention"]["reason"],
            "in_flight_outcome_overdue"
        );
    }

    #[test]
    fn future_judge_assessment_fails_aggregate_health_without_claiming_readiness() {
        for (mode, pending) in [("active", false), ("read_only", false), ("active", true)] {
            let (config, options, mut status) = fixture();
            status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!(mode);
            if pending {
                status["pending_work"] = json!([{
                    "kind":"judge","state":"generating","created_at":9999,
                    "updated_at":9999,"model_deadline":10100
                }]);
            }
            let before = evaluate(&config, options, &status, 10000);
            assert_eq!(before["healthy"], true);
            assert_eq!(before["components"]["judge"]["state"], "ok");
            status["work"]["judge"]["assessment"]["observed_at"] = json!(10001);
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["issues"], json!(["clock_regressed"]));
            assert_eq!(health["healthy"], false);
            assert_eq!(health["attention_required"], true);
            assert_eq!(health["components"]["judge"]["state"], "unknown");
            assert_eq!(
                health["work"]["judge"]["intervention"]["reason"],
                "clock_regressed"
            );
        }
    }

    #[test]
    fn lane_model_budgets_and_captured_deadlines_are_independent() {
        let (config, options, mut status) = fixture();
        status["effective_runtime"]["policy"]["capabilities"]["answer"]["timeouts"]["model_seconds"] =
            json!(1);
        status["effective_runtime"]["policy"]["capabilities"]["judge"]["timeouts"]["model_seconds"] =
            json!(2000);
        status["pending_work"] = json!([
            {"kind":"answer","state":"generating","created_at":9000,"model_deadline":20000},
            {"kind":"judge","state":"generating","created_at":9000}
        ]);
        let health = evaluate(&config, options, &status, 10000);
        assert!(!has(&health, "model_work_overdue"));
        assert_ne!(
            health["thresholds"]["lanes"]["answer"]["model_seconds"],
            health["thresholds"]["lanes"]["judge"]["model_seconds"]
        );
        assert!(health["thresholds"]["lanes"]["mine"]["model_seconds"].is_null());
        status["pending_work"][0]
            .as_object_mut()
            .unwrap()
            .remove("model_deadline");
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "model_work_overdue"
        ));
        status["effective_runtime"]["policy"]["capabilities"]["answer"]["timeouts"]["model_seconds"] =
            Value::Null;
        let unknown = evaluate(&config, options, &status, 10000);
        assert!(!has(&unknown, "model_work_overdue"));
        assert!(
            unknown["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "model_deadline_unavailable")
        );
    }

    #[test]
    fn mine_observation_never_refreshes_answer_evidence() {
        let (config, options, mut status) = fixture();
        status["observations"]["answer"]["observed_at"] = json!(1);
        status["observations"]["mine"]["epoch"] = json!(8);
        let health = evaluate(&config, options, &status, 10000);
        assert!(has(&health, "challenge_observation_stale"));
        assert_eq!(health["current_epoch"]["epoch"], 7);
        assert_eq!(health["current_epoch"]["evidence_fresh"], false);
        status["observations"]["answer"] = Value::Null;
        status["legacy_observation"] =
            json!({"epoch":8,"answered":true,"provenance":"unattributed"});
        let health = evaluate(&config, options, &status, 10000);
        assert!(has(&health, "challenge_unobserved"));
        assert_eq!(health["current_epoch"]["answered"], Value::Null);
        assert_eq!(health["legacy_observation"]["provenance"], "unattributed");
    }

    #[test]
    fn answer_grace_requires_fresh_own_observation_and_epoch_start() {
        let (config, options, mut status) = fixture();
        status["observations"]["answer"]["answered"] = json!(false);
        status["observations"]["answer"]["first_observed_at"] = json!(9000);
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "current_epoch_unanswered"
        ));
        status["observations"]["answer"]["first_observed_at"] = json!(9100);
        assert!(!has(
            &evaluate(&config, options, &status, 10000),
            "current_epoch_unanswered"
        ));
        status["observations"]["answer"]["observed_at"] = json!(1);
        assert!(!has(
            &evaluate(&config, options, &status, 10000),
            "current_epoch_unanswered"
        ));
    }

    #[test]
    fn discovery_failure_is_lane_local_and_quota_is_canonical() {
        let (config, options, mut status) = fixture();
        status["reads"][2]["last_failure_at"] = json!(10000);
        status["reads"][2]["failure_category"] = json!("http");
        status["reads"][2]["status"] = json!(503);
        status["work"]["mine"]["phase"] = json!("observing");
        status["work"]["judge"]["admission"] = json!({"allowed":false,
            "reason":"lane_unresolved_capacity","scope":"lane","own_count":1,"own_limit":1,"own_remaining":0});
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["components"]["answer"]["state"], "ok");
        assert_eq!(
            health["components"]["answer"]["admission"]["own_remaining"],
            4
        );
        assert_eq!(
            health["components"]["judge"]["reasons"][0],
            "lane_unresolved_capacity"
        );
        assert_eq!(health["components"]["mine"]["state"], "degraded");
        assert_eq!(health["healthy"], false);
        assert_eq!(
            health["issues"],
            json!(["lane_unresolved_capacity", "api_dependency_unavailable"])
        );
        assert_eq!(health["operational"]["issues"], health["issues"]);
        assert_eq!(health["operational"]["status"], "degraded");
        status["work"]["answer"]["admission"] = json!({"allowed":false,"reason":"account_uncertainty",
            "scope":"account","own_count":0,"own_limit":4,"own_remaining":4});
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(
            health["components"]["answer"]["reasons"][0],
            "account_uncertainty"
        );
        assert_eq!(
            health["components"]["answer"]["admission"]["own_remaining"],
            4
        );
    }

    #[test]
    fn retained_risk_and_old_unknown_do_not_hide_overdue_work() {
        let (config, options, mut status) = fixture();
        status["pending"] = json!({"kind":"answer","state":"unknown","created_at":1});
        status["participation"] = json!({"unresolved_count":4,"risk_admissions":1,
                "lanes":{"answer":{"historical_eligible_count":3,"capacity_exempt_count":3}}});
        status["operations"] = json!([{"state":"model_unknown","count":1}]);
        let clear = evaluate(&config, options, &status, 10000);
        assert_eq!(clear["healthy"], true);
        assert_eq!(clear["risk"]["attention_required"], true);
        assert_eq!(clear["risk"]["unresolved_effects"], 4);
        for (state, issue) in [
            ("queued", "pending_work_overdue"),
            ("included_pending", "pending_work_overdue"),
            ("dispatching", "dispatch_outcome_uncertain"),
            ("generating", "model_work_overdue"),
        ] {
            status["pending_work"] = json!([{"kind":"judge","state":state,"created_at":1,
                "updated_at":1,"model_deadline":1,"http_deadline":1}]);
            let health = evaluate(&config, options, &status, 10000);
            assert!(has(&health, issue));
            assert_eq!(health["components"]["judge"]["state"], "degraded");
        }
    }

    #[test]
    fn identity_unknown_and_rejection_remain_distinct() {
        let (config, options, mut status) = fixture();
        for state in [
            "unavailable",
            "invalid_response",
            "legacy_unknown",
            "unobserved",
        ] {
            status["hosted_identity"]["status"] = json!(state);
            let health = evaluate(&config, options, &status, 10000);
            assert!(health["hosted_identity_verified"].is_null());
            assert_eq!(health["components"]["answer"]["state"], "unknown");
        }
        status["hosted_identity"]["rejection"] = json!("authentication_failed");
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["hosted_identity_verified"], false);
        assert_eq!(health["components"]["answer"]["state"], "blocked");
        status.as_object_mut().unwrap().remove("hosted_identity");
        for legacy in [false, true] {
            status["hosted_identity_verified"] = json!(legacy);
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["hosted_identity"]["status"], "legacy_unknown");
            assert_eq!(health["hosted_identity"]["legacy_failure"], !legacy);
            assert!(health["hosted_identity_verified"].is_null());
        }
    }

    #[test]
    fn off_read_only_pause_and_migration_do_not_promise_participation() {
        let (config, options, mut status) = fixture();
        status["paused"] = json!(true);
        status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("read_only");
        status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["components"]["answer"]["state"], "blocked");
        assert_eq!(health["components"]["judge"]["state"], "ok");
        assert_eq!(health["components"]["mine"]["state"], "disabled");
        assert_eq!(health["intervention"]["unattended"], false);
        status["migration"] = json!({"pending":true,"phase":"adopting"});
        let health = evaluate(&config, options, &status, 10000);
        assert!(has(&health, "migration_pending"));
        assert_eq!(health["intervention"]["reason"], "migration_pending");
    }

    #[test]
    fn heartbeat_deadline_boundary_and_controller_fences() {
        let (config, options, status) = fixture();
        let floor = controller_floor(&status)
            .unwrap()
            .max(options.stale_seconds) as i64;
        assert!(!has(
            &evaluate(&config, options, &status, 10000 + floor),
            "controller_stale"
        ));
        assert!(has(
            &evaluate(&config, options, &status, 10001 + floor),
            "controller_stale"
        ));
        for (field, value, code) in [
            ("controller_stopped", json!(true), "controller_stopped"),
            ("identity_matches_config", json!(false), "identity_mismatch"),
        ] {
            let mut changed = status.clone();
            changed[field] = value;
            assert!(has(&evaluate(&config, options, &changed, 10000), code));
        }
        let mut changed = status.clone();
        changed["effective_runtime"]["reload_blocked"] = json!(true);
        assert!(has(
            &evaluate(&config, options, &changed, 10000),
            "reload_blocked"
        ));
        changed["effective_runtime"]["observed_at"] = json!(10001);
        assert!(has(
            &evaluate(&config, options, &changed, 10000),
            "clock_regressed"
        ));
    }

    #[test]
    fn inventory_completeness_and_missing_admission_are_honest() {
        let (config, options, mut status) = fixture();
        status["work"]["judge"]["assessment"]["completeness"] = json!("bounded_partial");
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "unknown"
        );
        let partial = evaluate(&config, options, &status, 10000);
        assert_eq!(partial["healthy"], false);
        assert_eq!(partial["operational"]["status"], "unknown");
        assert_eq!(partial["issues"], json!(["work_evidence_unavailable"]));
        assert_eq!(partial["operational"]["issues"], partial["issues"]);
        status["work"]["judge"]["assessment"]["completeness"] = json!("complete");
        status["work"]["judge"]["assessment"]["valid_until"] = json!(10000);
        assert_eq!(
            evaluate(&config, options, &status, 10000)["components"]["judge"]["state"],
            "unknown"
        );
        status.as_object_mut().unwrap().remove("admission_blocked");
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["operational"]["status"], "unknown");
        assert!(has(&health, "admission_unobserved"));
    }

    #[test]
    fn disk_findings_preserve_lane_evidence_risk_and_controller_provenance() {
        let (config, options, mut status) = fixture();
        status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
        for (code, state, readiness, intervention) in [
            (
                "state_disk_space_low",
                "degraded",
                json!(false),
                "operator_required",
            ),
            (
                "state_disk_space_unavailable",
                "unknown",
                Value::Null,
                "undetermined",
            ),
        ] {
            let mut health = evaluate(&config, options, &status, 10000);
            let before = health.clone();
            apply_disk_issue(&mut health, code);
            assert_eq!(health["risk"], before["risk"]);
            assert_eq!(health["healthy"], false);
            assert_eq!(health["components"]["controller"]["state"], state);
            assert_eq!(health["components"]["controller"]["reasons"], json!([code]));
            assert_eq!(health["operational"]["status"], state);
            assert_eq!(health["issues"], json!([code]));
            assert_eq!(health["operational"]["issues"], health["issues"]);
            assert_eq!(health["intervention"]["status"], intervention);
            assert_eq!(health["intervention"]["controller"]["ready"], readiness);
            assert_eq!(health["intervention"]["controller"]["reason"], code);
            assert_eq!(health["intervention"]["controller"]["observed_at"], 10000);
            assert_eq!(
                health["intervention"]["next_action"],
                "inspect_state_filesystem"
            );
            assert_eq!(health["intervention"]["next_at"], Value::Null);
            assert_ne!(health["intervention"]["unattended"], true);
            for lane in LANES {
                assert_eq!(health["components"][lane], before["components"][lane]);
                assert_eq!(health["work"][lane], before["work"][lane]);
                assert_eq!(
                    health["intervention"]["lanes"][lane],
                    health["work"][lane]["intervention"]["status"]
                );
            }
        }
    }

    #[test]
    fn participation_opt_out_waives_pause_not_intrinsic_core_or_accounting_faults() {
        let (config, mut options, mut status) = fixture();
        options.expect_participation = false;
        status["paused"] = json!(true);
        status["admission_blocked"] = json!(true);
        for lane in LANES {
            status["work"][lane]["admission"]["allowed"] = json!(false);
            status["work"][lane]["admission"]["reason"] = json!("admission_paused");
            status["participation"]["lanes"][lane] = status["work"][lane]["admission"].clone();
        }
        status["hosted_identity"]["status"] = json!("unobserved");
        status["observations"]["answer"] = Value::Null;
        status["lane_controls"]["answer"]["authoritative_closure"]["state"] = json!("closed");
        status["lane_controls"]["answer"]["authoritative_closure"]["reasons"] =
            json!(["global_paused"]);
        let paused = evaluate(&config, options, &status, 10000);
        assert_eq!(paused["healthy"], true);
        assert_eq!(paused["components"]["controller"]["state"], "blocked");
        assert_eq!(paused["components"]["answer"]["state"], "blocked");
        assert_eq!(paused["intervention"]["unattended"], false);
        for (pointer, value, issue) in [
            (
                "/effective_runtime/observed_at",
                json!(1),
                "controller_stale",
            ),
            (
                "/effective_runtime/policy",
                Value::Null,
                "effective_policy_unavailable",
            ),
            (
                "/identity_matches_config",
                Value::Null,
                "controller_evidence_unavailable",
            ),
            ("/controller_stopped", json!(true), "controller_stopped"),
            (
                "/hosted_identity/rejection",
                json!("authentication_failed"),
                "hosted_identity_authentication_failed",
            ),
        ] {
            let mut changed = status.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let report = evaluate(&config, options, &changed, 10000);
            assert_eq!(report["healthy"], false, "{issue}");
            assert!(has(&report, issue));
            assert_eq!(report["issues"], report["operational"]["issues"]);
        }
        status["effective_runtime"]["reload_blocked"] = json!(true);
        assert_eq!(evaluate(&config, options, &status, 10000)["healthy"], true);
        status["participation"]["lanes"]["judge"]["pre_intent_blocker"] =
            json!({"reason":"lane_unresolved_capacity","not_before":null});
        let blocked = evaluate(&config, options, &status, 10000);
        assert_eq!(blocked["issues"], json!(["lane_unresolved_capacity"]));
        assert_eq!(blocked["operational"]["status"], "blocked");
        status["participation"]["lanes"]["judge"]
            .as_object_mut()
            .unwrap()
            .remove("pre_intent_blocker");
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "admission_evidence_unavailable"
        ));
    }

    #[test]
    fn read_only_requires_observations_without_borrowing_write_identity_or_off_history() {
        let (config, mut options, mut status) = fixture();
        options.expect_participation = false;
        for lane in ["answer", "judge"] {
            status["effective_runtime"]["policy"]["capabilities"][lane]["mode"] =
                json!("read_only");
            status["work"][lane]["model"] =
                json!({"current_route":true,"failure_category":"native_auth_unavailable"});
        }
        status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
        status["hosted_identity"]["status"] = json!("unobserved");
        status["observations"]["answer"] = Value::Null;
        status["observations"]["mine"]["observed_at"] = json!(20000);
        status["reads"].as_array_mut().unwrap().pop();
        let observed = evaluate(&config, options, &status, 10000);
        assert_eq!(observed["healthy"], true);
        assert_eq!(observed["components"]["answer"]["state"], "ok");
        assert_eq!(observed["components"]["judge"]["state"], "ok");
        assert_eq!(observed["components"]["mine"]["state"], "disabled");
        assert_eq!(observed["intervention"]["unattended"], false);
        options.expect_participation = true;
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "no_active_capabilities"
        ));
        options.expect_participation = false;
        status["reads"][1]["last_success_at"] = json!(1);
        let stale = evaluate(&config, options, &status, 10000);
        assert_eq!(stale["healthy"], false);
        assert_eq!(stale["operational"]["status"], "unknown");
        assert_eq!(stale["components"]["answer"]["state"], "ok");
        assert_eq!(stale["components"]["judge"]["state"], "unknown");
        status["reads"][1]["last_success_at"] = json!(10001);
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "clock_regressed"
        ));
    }

    #[test]
    fn required_unknowns_deduplicate_and_do_not_conceal_known_faults_or_fences() {
        let (config, options, mut status) = fixture();
        status["work"]["judge"]["assessment"]["completeness"] = json!("bounded_partial");
        status["work"]["mine"]["phase"] = json!("observing");
        let unknown = evaluate(&config, options, &status, 10000);
        assert_eq!(unknown["issues"], json!(["work_evidence_unavailable"]));
        assert_eq!(unknown["operational"]["status"], "unknown");
        status["work"]["answer"]["admission"] =
            json!({"allowed":false,"reason":"lane_unresolved_capacity"});
        let blocked = evaluate(&config, options, &status, 10000);
        assert_eq!(
            blocked["issues"],
            json!(["lane_unresolved_capacity", "work_evidence_unavailable"])
        );
        assert_eq!(blocked["operational"]["status"], "blocked");
        status["pending_work"] = json!([{"kind":"mine","state":"dispatching",
            "created_at":1,"updated_at":1,"http_deadline":1}]);
        let fault = evaluate(&config, options, &status, 10000);
        assert_eq!(fault["operational"]["status"], "degraded");
        assert!(has(&fault, "dispatch_outcome_uncertain"));
        assert_eq!(fault["issues"], fault["operational"]["issues"]);
    }

    #[test]
    fn current_completion_supersedes_old_reads_without_folding_unrelated_resources() {
        let (config, options, mut status) = fixture();
        for row in status["reads"].as_array_mut().unwrap() {
            row["last_success_at"] = Value::Null;
            row["last_failure_at"] = json!(9999);
            row["failure_category"] = json!("http");
            row["status"] = json!(503);
        }
        status["reads"]
            .as_array_mut()
            .unwrap()
            .push(json!({"owner":"judge","purpose":"job",
            "resource":"old:1","operation_id":1,"binding_revision":1,"retired":true,
            "last_failure_at":10000,"failure_category":"http","status":403}));
        status["reads_truncated"] = json!(true);
        let completed = evaluate(&config, options, &status, 10000);
        assert_eq!(completed["healthy"], true);
        assert_eq!(
            completed["components"]["api"]["lanes"]["judge"]["state"],
            "degraded"
        );
        assert_eq!(completed["components"]["api"]["resources_truncated"], true);
        status["observations"]["answer"]["answered"] = json!(false);
        status["pending_work"] = json!([{"kind":"answer","state":"generating",
            "created_at":10000,"updated_at":10000,"model_deadline":10100}]);
        let working = evaluate(&config, options, &status, 10000);
        assert_eq!(working["healthy"], true);
        assert_eq!(
            working["components"]["answer"]["reasons"],
            json!(["work_in_progress"])
        );
        status["pending_work"][0]["state"] = json!("queued");
        status["work"]["answer"]["next_action"] = json!("read_job");
        status["work"]["answer"]["binding_revision"] = json!(2);
        status["work"]["answer"]["read_key"] =
            json!({"owner":"answer","purpose":"job","resource":"8:2"});
        status["reads"].as_array_mut().unwrap().push(json!({"owner":"answer","purpose":"job",
            "resource":"8:2","binding_revision":2,"last_failure_at":10000,"failure_category":"http","status":503}));
        let dependent = evaluate(&config, options, &status, 10000);
        assert!(has(&dependent, "api_dependency_unavailable"));
        assert_eq!(dependent["components"]["answer"]["state"], "degraded");
        assert_eq!(dependent["components"]["judge"]["state"], "ok");
        status["reads"][4]["binding_revision"] = json!(1);
        assert_eq!(evaluate(&config, options, &status, 10000)["healthy"], true);
    }

    #[test]
    fn opt_out_and_off_do_not_cancel_captured_deadlines_or_bound_dependencies() {
        let (config, mut options, mut status) = fixture();
        options.expect_participation = false;
        status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("off");
        status["captured_work"] = json!([{"kind":"judge","state":"generating","created_at":9999,
            "diagnostic":{"stage":"model_preflight","execution":"not_started","state":"awaiting_admission"}}]);
        let missing = evaluate(&config, options, &status, 10000);
        assert!(has(&missing, "model_deadline_unavailable"));
        assert_eq!(missing["healthy"], false);
        assert_eq!(missing["components"]["judge"]["state"], "disabled");
        status["captured_work"][0]["pending_execution_deadline"] = json!(9999);
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "pending_model_execution_expired"
        ));
        status["captured_work"] = json!([{"kind":"judge","state":"queued","created_at":9999}]);
        status["work"]["judge"]["next_action"] = json!("enable_capability");
        status["work"]["judge"]["binding_revision"] = json!(2);
        status["work"]["judge"]["read_key"] =
            json!({"owner":"judge","purpose":"job","resource":"7:2"});
        status["reads"].as_array_mut().unwrap().push(json!({"owner":"judge","purpose":"job",
            "resource":"7:2","binding_revision":2,"last_failure_at":10000,"failure_category":"http","status":503}));
        let bound = evaluate(&config, options, &status, 10000);
        assert!(has(&bound, "api_dependency_unavailable"));
        assert_eq!(bound["healthy"], false);
        status["reads"][3]["binding_revision"] = json!(1);
        assert!(!has(
            &evaluate(&config, options, &status, 10000),
            "api_dependency_unavailable"
        ));
    }

    #[test]
    fn disk_unknown_never_downgrades_known_core_or_lane_operator_findings() {
        let (config, options, mut status) = fixture();
        for core in [false, true] {
            if core {
                status["identity_matches_config"] = json!(false);
            } else {
                status["paused"] = json!(true);
            }
            let mut health = evaluate(&config, options, &status, 10000);
            let before = health["intervention"]["reason"].clone();
            apply_disk_issue(&mut health, "state_disk_space_unavailable");
            assert_eq!(health["intervention"]["status"], "operator_required");
            assert_eq!(health["intervention"]["reason"], before);
            assert_eq!(health["intervention"]["unattended"], false);
            assert_eq!(
                health["intervention"]["next_action"],
                "inspect_state_filesystem"
            );
            assert_eq!(health["intervention"]["next_at"], Value::Null);
            assert_eq!(
                health["intervention"]["controller"]["ready"],
                if core { json!(false) } else { Value::Null }
            );
        }
    }

    #[test]
    fn restoration_qualifies_stop_only_evidence_under_disk_and_real_effective_modes() {
        let (config, options, mut status) = fixture();
        status["controller_stopped"] = json!(true);
        status["paused"] = json!(true);
        status["effective_runtime"]["policy"]["capabilities"]["judge"]["mode"] = json!("read_only");
        status["effective_runtime"]["policy"]["capabilities"]["mine"]["mode"] = json!("off");
        for disk in [
            None,
            Some("state_disk_space_low"),
            Some("state_disk_space_unavailable"),
        ] {
            let mut health = evaluate(&config, options, &status, 10000);
            if let Some(code) = disk {
                apply_disk_issue(&mut health, code);
            }
            let risk = health["risk"].clone();
            qualify_doctor(
                &mut health,
                &json!({"restoration":{"verified":true,"runtime":"restored"}}),
            );
            assert_eq!(health["healthy"], false);
            assert_eq!(health["risk"], risk);
            assert!(!has(&health, "controller_stopped"));
            assert!(has(&health, "runtime_restored_observation_pending"));
            assert_eq!(
                health["work"]["answer"]["intervention"]["next_action"],
                "resume"
            );
            assert_eq!(
                health["work"]["judge"]["intervention"]["reason"],
                "runtime_restored_observation_pending"
            );
            assert_eq!(
                health["work"]["mine"]["intervention"]["reason"],
                "capability_off"
            );
            assert_eq!(health["intervention"]["unattended"], false);
            assert_eq!(health["components"]["judge"]["state"], "unknown");
            if disk.is_some() {
                assert_eq!(
                    health["intervention"]["next_action"],
                    "inspect_state_filesystem"
                );
            } else {
                assert_eq!(health["intervention"]["controller"]["ready"], Value::Null);
                assert_eq!(health["intervention"]["reason"], "admission_paused");
            }
            for lane in LANES {
                assert_eq!(
                    health["intervention"]["lanes"][lane],
                    health["work"][lane]["intervention"]["status"]
                );
                assert_ne!(
                    health["work"][lane]["intervention"]["next_action"],
                    "start_controller"
                );
            }
        }
    }

    #[test]
    fn restored_unpaused_core_state_tracks_remaining_disk_evidence() {
        let (config, options, mut status) = fixture();
        status["controller_stopped"] = json!(true);
        for (disk, state) in [
            ("state_disk_space_low", "degraded"),
            ("state_disk_space_unavailable", "unknown"),
        ] {
            let mut health = evaluate(&config, options, &status, 10000);
            apply_disk_issue(&mut health, disk);
            qualify_doctor(
                &mut health,
                &json!({"restoration":{"verified":true,"runtime":"restored"}}),
            );
            assert_eq!(health["components"]["controller"]["state"], state);
            assert_eq!(health["operational"]["status"], state);
            assert_eq!(health["healthy"], false);
            assert_eq!(
                health["intervention"]["next_action"],
                "inspect_state_filesystem"
            );
            let reasons = health["components"]["controller"]["reasons"]
                .as_array()
                .unwrap();
            assert!(reasons.iter().any(|reason| reason == disk));
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason == "runtime_restored_observation_pending")
            );
            assert!(!reasons.iter().any(|reason| reason == "controller_stopped"));
        }
    }

    #[test]
    fn restoration_reclassifies_remaining_identity_uncertainty() {
        let (config, options, mut status) = fixture();
        status["controller_stopped"] = json!(true);
        for state in [
            "unobserved",
            "unavailable",
            "invalid_response",
            "legacy_unknown",
        ] {
            status["hosted_identity"]["status"] = json!(state);
            let mut health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["components"]["controller"]["state"], "blocked");
            qualify_doctor(
                &mut health,
                &json!({"restoration":{"verified":true,"runtime":"restored"}}),
            );
            assert_eq!(health["components"]["controller"]["state"], "unknown");
            assert_eq!(health["operational"]["status"], "unknown");
            assert!(has(&health, &format!("hosted_identity_{state}")));
            assert!(has(&health, "runtime_restored_observation_pending"));
            assert!(!has(&health, "controller_stopped"));
        }
    }

    #[test]
    fn restoration_keeps_independent_lane_faults_and_first_lane_wins_ties() {
        let (config, options, mut status) = fixture();
        status["controller_stopped"] = json!(true);
        status["work"]["judge"]["assessment"]["locally_judgeable"] = json!(true);
        status["work"]["judge"]["model"] =
            json!({"current_route":true,"failure_category":"native_auth_unavailable"});
        status["work"]["mine"]["model"] =
            json!({"current_route":true,"failure_category":"executable_unavailable"});
        for lane in LANES {
            status["work"][lane]["phase"] = json!("stopped");
            status["work"][lane]["reason"] = json!("controller_stopped");
            status["work"][lane]["next_action"] = json!("start_controller");
        }
        let mut health = evaluate(&config, options, &status, 10000);
        qualify_doctor(
            &mut health,
            &json!({"restoration":{"verified":true,"runtime":"restored"}}),
        );
        assert_eq!(
            health["intervention"]["reason"],
            "model_authentication_failed"
        );
        assert_eq!(health["intervention"]["unattended"], false);
        assert_eq!(health["intervention"]["controller"]["ready"], Value::Null);
        assert_eq!(
            health["work"]["mine"]["intervention"]["reason"],
            "model_configuration_failed"
        );
        assert_eq!(health["components"]["controller"]["state"], "unknown");
        assert_eq!(health["healthy"], false);
        for lane in LANES {
            assert_ne!(health["work"][lane]["next_action"], "start_controller");
            assert_ne!(
                health["work"][lane]["intervention"]["next_action"],
                "start_controller"
            );
        }
        let controller = health["intervention"]["controller"].clone();
        let work = health["work"].clone();
        qualify_doctor(
            &mut health,
            &json!({"failure":"repair_restore_failed",
            "restoration":{"verified":false,"runtime":"unrestored"}}),
        );
        assert_eq!(
            health["intervention"]["reason"],
            "doctor_repair_unavailable"
        );
        assert_eq!(health["intervention"]["controller"], controller);
        assert_eq!(health["work"], work);
        for lane in LANES {
            assert_eq!(
                health["intervention"]["lanes"][lane],
                work[lane]["intervention"]["status"]
            );
        }
        for restoration in [
            json!({"verified":false,"runtime":"restored"}),
            json!({"verified":true,"runtime":"unrestored"}),
        ] {
            let mut stopped = evaluate(&config, options, &status, 10000);
            let before = stopped.clone();
            qualify_doctor(&mut stopped, &json!({"restoration":restoration}));
            assert_eq!(stopped, before);
        }
    }

    #[test]
    fn repair_failure_preserves_observed_readiness_without_claiming_doctor_success() {
        let (config, options, status) = fixture();
        let mut health = evaluate(&config, options, &status, 10000);
        let before = health.clone();
        qualify_doctor(
            &mut health,
            &json!({"failure":"doctor_recovery_unavailable"}),
        );
        assert_eq!(health["healthy"], true);
        assert_eq!(health["attention_required"], true);
        assert_eq!(
            health["intervention"]["controller"],
            before["intervention"]["controller"]
        );
        assert_eq!(
            health["intervention"]["lanes"],
            before["intervention"]["lanes"]
        );
        assert_eq!(health["work"], before["work"]);
        assert_eq!(
            health["intervention"]["next_action"],
            "inspect_repair_failure"
        );
        assert_eq!(health["intervention"]["unattended"], false);
        for code in ["state_disk_space_low", "state_disk_space_unavailable"] {
            let mut gated = before.clone();
            apply_disk_issue(&mut gated, code);
            let controller = gated["intervention"]["controller"].clone();
            qualify_doctor(
                &mut gated,
                &json!({"failure":"doctor_recovery_unavailable"}),
            );
            assert_eq!(gated["intervention"]["status"], "operator_required");
            assert_eq!(gated["intervention"]["reason"], "doctor_repair_unavailable");
            assert_eq!(
                gated["intervention"]["next_action"],
                "inspect_state_filesystem"
            );
            assert_eq!(gated["intervention"]["next_at"], Value::Null);
            assert_eq!(gated["intervention"]["unattended"], false);
            assert_eq!(gated["intervention"]["controller"], controller);
            assert_eq!(
                gated["intervention"]["lanes"],
                before["intervention"]["lanes"]
            );
            assert_eq!(gated["work"], before["work"]);
            assert_eq!(gated["risk"], before["risk"]);
        }
    }

    #[test]
    fn restoration_reports_lane_pause_not_global_pause_for_desired_judge_pause() {
        let (config, options, mut status) = fixture();
        status["controller_stopped"] = json!(true);
        // Global admission is unpaused; only the judge lane requests a pause.
        status["paused"] = json!(false);
        status["lane_controls"]["judge"] = json!({"desired": {
            "paused": true,
            "control_token": "judge-token",
            "control_revision": 7
        }});
        // An unrelated lane keeps an independent fault through restoration.
        status["work"]["mine"]["model"] =
            json!({"current_route": true, "failure_category": "executable_unavailable"});
        for lane in LANES {
            status["work"][lane]["phase"] = json!("stopped");
            status["work"][lane]["reason"] = json!("controller_stopped");
            status["work"][lane]["next_action"] = json!("start_controller");
        }
        let mut health = evaluate(&config, options, &status, 10000);
        assert_eq!(
            health["work"]["judge"]["intervention"]["reason"],
            "controller_stopped"
        );
        let risk = health["risk"].clone();
        qualify_doctor(
            &mut health,
            &json!({"restoration": {"verified": true, "runtime": "restored"}}),
        );
        assert_eq!(health["healthy"], false);
        assert_eq!(health["risk"], risk);
        assert!(!has(&health, "controller_stopped"));
        assert!(has(&health, "runtime_restored_observation_pending"));
        assert_eq!(health["paused"], false);
        assert_eq!(health["lane_controls"]["judge"]["desired"]["paused"], true);
        assert_eq!(
            health["work"]["judge"]["intervention"]["reason"],
            "lane_paused"
        );
        assert_eq!(
            health["work"]["judge"]["intervention"]["next_action"],
            "resume"
        );
        assert_eq!(health["intervention"]["status"], "operator_required");
        assert_eq!(health["intervention"]["reason"], "lane_paused");
        assert_eq!(health["intervention"]["next_action"], "resume");
        assert_eq!(health["intervention"]["unattended"], false);
        assert_eq!(
            health["intervention"]["lanes"]["judge"],
            health["work"]["judge"]["intervention"]["status"]
        );
        assert_eq!(
            health["work"]["mine"]["intervention"]["reason"],
            "model_configuration_failed"
        );
        for lane in LANES {
            assert_ne!(health["work"][lane]["next_action"], "start_controller");
            assert_ne!(
                health["work"][lane]["intervention"]["next_action"],
                "start_controller"
            );
        }
    }
}
