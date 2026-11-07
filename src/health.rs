//! Read-only, local health evidence. Output contains only bounded diagnostic codes,
//! booleans and ages; never copy raw status, event text or operation identifiers.
use crate::{
    config::{Config, Mode, WorkKind},
    runtime,
    store::now,
};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

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

/// This command opens existing state read-only, never recovers it, and performs
/// neither network nor model calls. Errors are deliberately replaced at this boundary.
pub fn check(config: &Config, options: Options) -> Result<Value> {
    let status =
        runtime::status(config).map_err(|_| anyhow!("local health evidence unavailable"))?;
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
            result["issues"]
                .as_array_mut()
                .expect("health issues array")
                .push(json!(code));
            result["healthy"] = json!(false);
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

fn evaluate(config: &Config, options: Options, status: &Value, at: i64) -> Value {
    // Use the running controller's policy, not a newly edited desired config.
    // Native inference is independent and no longer expands heartbeat grace.
    let policy = &status["effective_runtime"]["policy"];
    let http = policy["timeouts"]["http_seconds"]
        .as_u64()
        .unwrap_or(config.timeouts.http_seconds);
    let poll = policy["schedule"]["poll_seconds"]
        .as_u64()
        .unwrap_or(config.schedule.poll_seconds);
    let jitter = policy["schedule"]["jitter_seconds"]
        .as_u64()
        .unwrap_or(config.schedule.jitter_seconds);
    let shutdown = policy["timeouts"]["shutdown_seconds"]
        .as_u64()
        .unwrap_or(config.timeouts.shutdown_seconds);
    let cycle_floor = http
        .saturating_add(poll)
        .saturating_add(jitter)
        .saturating_add(shutdown)
        .saturating_add(1);
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
    if status["identity_matches_config"].as_bool() == Some(false) {
        issues.push("identity_mismatch");
    }
    if status["hosted_identity_verified"].as_bool() == Some(false) {
        issues.push("hosted_identity_unverified");
    }
    if status["controller_stopped"].as_bool() == Some(true) {
        issues.push("controller_stopped");
    }
    match heartbeat_age {
        None => issues.push("controller_unobserved"),
        Some(seconds) if seconds > stale => issues.push("controller_stale"),
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
        if ![WorkKind::Answer, WorkKind::Judge, WorkKind::Mine]
            .iter()
            .any(|kind| effective_mode(*kind))
        {
            issues.push("no_active_capabilities");
        }
    }
    match pending["state"].as_str() {
        Some("unknown") => issues.push("pending_outcome_uncertain"),
        Some("generating") => match model_overdue(pending, at, poll, model_limit) {
            Some(true) => issues.push("model_work_overdue"),
            None => warnings.push("model_deadline_unavailable"),
            _ => {}
        },
        Some("dispatching")
            if pending["http_deadline"].as_i64().map_or(
                age(&pending["updated_at"], at).is_some_and(|seconds| {
                    seconds > http.saturating_add(shutdown).saturating_add(1)
                }),
                |deadline| at > deadline.saturating_add(shutdown as i64),
            ) =>
        {
            issues.push("dispatch_outcome_uncertain");
        }
        Some(_) if pending_age.is_some_and(|seconds| seconds > work_limit) => {
            // created_at deliberately survives repeated queue polls and Retry-After.
            issues.push("pending_work_overdue");
        }
        _ => {}
    }
    let answer_expected = options.expect_participation && effective_mode(WorkKind::Answer);
    if answer_expected {
        match observation_age {
            None => issues.push("challenge_unobserved"),
            Some(seconds) if seconds > stale => issues.push("challenge_observation_stale"),
            _ => {}
        }
        if status["epoch_evidence"]["answered"].as_bool() == Some(false)
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
    let preparing = status["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|row| row["state"] == "generating" && row["count"].as_u64().unwrap_or(0) > 0);
    for work in status["captured_work"].as_array().into_iter().flatten() {
        if work["state"] != "generating" {
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
    let attention_required = !issues.is_empty() || !warnings.is_empty();
    json!({"healthy":issues.is_empty(),"checked_at":at,"issues":issues,
        "warnings":warnings,"attention_required":attention_required,
        "unresolved_model_attempts":unresolved_models,
        "initialized":initialized,"paused":paused,"expect_participation":options.expect_participation,
        "controller_stopped":status["controller_stopped"].as_bool().unwrap_or(false),
        "hosted_identity_verified":status["hosted_identity_verified"].as_bool(),
        "heartbeat_age_seconds":heartbeat_age,"observation_age_seconds":observation_age,
        "heartbeat_recent":heartbeat_age.is_some_and(|age|age<=stale),
        "observing":observation_age.is_some_and(|age|age<=stale),"preparing":preparing,
        "last_safety_observation_at":status["last_safety_observation_at"],
        "captured_work":status["captured_work"],
        "epoch_observed_age_seconds":epoch_age,"pending_age_seconds":pending_age,
        "admission_blocked":status["admission_blocked"].as_bool().unwrap_or(false),
        "blocking_operation":status["blocking_operation"],"blocked_since":status["blocked_since"],
        "blocked_age_seconds":age(&status["blocked_since"],at),
        "affected_capabilities":status["affected_capabilities"],
        "progress_age_seconds":age(&status["last_progress_at"],at),
        "desired_capabilities":config.capabilities,"effective_capabilities":effective["capabilities"],
        "last_reported_build":status["last_reported_build"],"process_identity":"unverified",
        "thresholds":{"stale_seconds":stale,"work_seconds":work_limit,
            "answer_grace_seconds":grace,"model_seconds":model_limit,"cycle_floor_seconds":cycle_floor},
        "evidence":"local_only","notifications":"local_exit_status_and_journal"})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Config, Options, Value) {
        let mut config = Config::default();
        config.capabilities.answer = Mode::Active;
        let status = json!({"initialized":true,"paused":false,"identity_matches_config":true,
            "effective_runtime":{"observed_at":10000,"reload_blocked":false},
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
    fn hosted_identity_failure_overrides_local_match_and_fresh_challenge() {
        let (config, options, mut status) = fixture();
        for evidence in [Value::Null, json!(true)] {
            status["hosted_identity_verified"] = evidence.clone();
            let health = evaluate(&config, options, &status, 10000);
            assert_eq!(health["healthy"], true);
            assert_eq!(health["hosted_identity_verified"], evidence);
        }
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
        let (mut config, options, status) = fixture();
        config.schedule.jitter_seconds = 0;
        let floor = evaluate(&config, options, &status, 10000)["thresholds"]["stale_seconds"]
            .as_i64()
            .unwrap();
        let at = 10000 + floor + 15;
        assert!(has(
            &evaluate(&config, options, &status, at),
            "controller_stale"
        ));
        config.schedule.jitter_seconds = 30;
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
        assert!(has(
            &evaluate(&config, options, &status, 10000),
            "pending_outcome_uncertain"
        ));
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
        status["blocking_operation"] = json!(17);
        status["blocked_since"] = json!(9000);
        status["pending"] = json!({"kind":"judge","state":"unknown","created_at":9000});
        status["operations"] = json!([{"kind":"answer","state":"generating","count":1}]);
        let health = evaluate(&config, options, &status, 10000);
        assert_eq!(health["healthy"], false);
        assert_eq!(health["preparing"], true);
        assert_eq!(health["admission_blocked"], true);
        assert_eq!(health["blocked_age_seconds"], 1000);
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
}
