//! Sanitized CLI presentation. Never render untyped error chains or parser values.
use anyhow::Error;
use clap::{
    CommandFactory,
    error::{ContextKind, ContextValue, ErrorKind},
};
use serde_json::{Value, json};
use std::{borrow::Cow, path::Path};

#[derive(Debug)]
pub(crate) struct BoundaryError(pub &'static str, pub &'static str);
impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}
impl std::error::Error for BoundaryError {}

pub(crate) fn action(config: Option<&Path>, command: &[&str], authorization: bool) -> Value {
    let mut argv = vec!["agmi".to_owned()];
    if let Some(path) = config {
        let resolved = std::path::absolute(path);
        let Some(path) = resolved.as_ref().ok().and_then(|path| path.to_str()) else {
            return json!({"kind":"instruction","authorization_required":false,
                "message":"Select the same configuration with an absolute UTF-8 --config path before continuing."});
        };
        argv.extend(["--config".into(), path.to_owned()]);
    }
    argv.extend(command.iter().map(|part| (*part).to_owned()));
    json!({"kind":"command","argv":argv,"authorization_required":authorization})
}
/// Render one argv element with POSIX single-quote escaping when needed.
fn shell_quote(argument: &str) -> Cow<'_, str> {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'))
    {
        return Cow::Borrowed(argument);
    }
    Cow::Owned(format!("'{}'", argument.replace('\'', "'\\''")))
}

/// Render an argv array as a readable POSIX command line.
fn render_argv(argv: &Value) -> String {
    let Some(parts) = argv.as_array() else {
        return "Inspect local evidence".to_owned();
    };
    let mut rendered = String::new();
    for part in parts.iter().filter_map(Value::as_str) {
        if !rendered.is_empty() {
            rendered.push(' ');
        }
        rendered.push_str(&shell_quote(part));
    }
    rendered
}

/// A generated action carries a compare-and-swap token when it resumes a lane
/// with `--expected-control <token>`. Human diagnostics must never print the
/// token; they point at `lane show` instead. JSON keeps the exact action.
fn token_lane(argv: &Value) -> Option<&str> {
    let parts = argv.as_array()?;
    if !parts.iter().any(|part| part == "--expected-control") {
        return None;
    }
    let position = parts.iter().position(|part| part == "lane")?;
    if !matches!(parts.get(position + 1)?.as_str(), Some("pause" | "resume")) {
        return None;
    }
    let lane = parts.get(position + 2)?.as_str()?;
    agmi::capability::LaneId::NAMES
        .contains(&lane)
        .then_some(lane)
}

pub(crate) fn parser(error: &clap::Error, config: Option<&Path>) -> Value {
    fn fields(command: &clap::Command, names: &mut Vec<String>) {
        for arg in command.get_arguments() {
            if let Some(long) = arg.get_long() {
                names.push(format!("--{long}"));
            } else {
                names.push(format!("<{}>", arg.get_id().as_str().to_uppercase()));
            }
        }
        for child in command.get_subcommands() {
            fields(child, names);
        }
    }
    let mut known = Vec::new();
    fields(&super::Cli::command(), &mut known);
    known.sort();
    known.dedup();
    let supplied = match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(value)) => vec![value.as_str()],
        Some(ContextValue::Strings(values)) => values.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    let fields: Vec<_> = known
        .into_iter()
        .filter(|field| {
            supplied.iter().any(|value| {
                value
                    .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '|'))
                    .any(|part| part == field.trim_matches(['<', '>']))
            })
        })
        .collect();
    let reason = match error.kind() {
        ErrorKind::MissingRequiredArgument => "missing_required_fields",
        ErrorKind::MissingSubcommand => "missing_subcommand",
        ErrorKind::ArgumentConflict => "conflicting_fields",
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => "invalid_field_value",
        _ => "invalid_arguments",
    };
    json!({"code":"invalid_arguments","message":"Invalid command arguments.",
        "details":{"reason":reason,"fields":fields,
            "missing_fields":if error.kind() == ErrorKind::MissingRequiredArgument { fields.clone() } else { Vec::new() }},
        "next_actions":[action(config, &["--help"], false)]})
}

pub(crate) fn execution(error: &Error, config: Option<&Path>) -> Value {
    if let Some(error) = error.downcast_ref::<agmi::store::LaneControlError>() {
        return json!({
            "code":error.code(),"message":error.message(),"details":{},
            "next_actions":[
                action(config, &["lane", "--help"], false),
                {"kind":"instruction","authorization_required":false,
                 "message":"Reread lane show for the selected lane before retrying with its current desired.control_token. Preserve dispatch uncertainty; neither resume nor a fence acknowledgement authorizes replay."}
            ]
        });
    }
    if let Some(error) = error.downcast_ref::<agmi::store::migration::MigrationError>() {
        return json!({
            "code":error.code(),"message":error.message(),"details":{},
            "next_actions":[action(config, &["config", "migrate", "--help"], false)]
        });
    }
    if let Some(diagnostic) = error.downcast_ref::<agmi::config::ConfigDiagnostic>() {
        if error
            .downcast_ref::<agmi::lifecycle::LifecycleError>()
            .is_some_and(|error| error.code == "initialization_invalid")
        {
            return json!({
                "code":"initialization_invalid",
                "message":diagnostic.to_string(),
                "details":diagnostic,
                "next_actions":[
                    action(config, &["init", "--help"], false),
                    action(config, &["config", "schema"], false),
                    {"kind":"instruction","authorization_required":true,
                     "message":"Correct the reported initialization field in the init arguments or network profile, then repeat init. No identity verification was requested and no onboarding files were written; preserve any existing credentials and journal state."}
                ]
            });
        }
        let mut actions = vec![action(
            config,
            if diagnostic.is_missing() {
                &["init", "--help"]
            } else {
                &["config", "schema"]
            },
            false,
        )];
        if let Some((kind, layer)) = diagnostic.guidance_selector() {
            actions = vec![
                action(config, &["config", "show"], false),
                json!({"kind":"instruction","authorization_required":true,
                    "message":"Repair the selected route's guidance file or configured path. Use a readable UTF-8 regular file of at most 64 KiB; core guidance must be nonempty. Do not disable the route or replace core instructions merely to bypass validation."}),
                action(
                    config,
                    &[
                        "guidance",
                        "set",
                        "--kind",
                        kind.as_str(),
                        "--layer",
                        layer,
                        "--help",
                    ],
                    false,
                ),
            ];
        } else {
            actions.push(json!({"kind":"instruction","authorization_required":true,
                "message":"Inspect the selected configuration locally and repair the reported field, file format or file access. Use the schema for supported names, types and values; preserve account identity, credentials and journal state. Run config check after repair."}));
        }
        return json!({
            "code":if diagnostic.is_missing() { "config_missing" } else { "config_invalid" },
            "message":diagnostic.to_string(),
            "details":diagnostic,
            "next_actions":actions
        });
    }
    if error.is::<agmi::store::RoutingProfileError>() {
        return json!({
            "code":"api_routing_pending",
            "message":"API routing cannot change while unresolved or reusable work remains. Restore network.api from status.network_routing.bound_api; preserve the journal.",
            "details":{},
            "next_actions":[action(config, &["status"], false), action(config, &["operations", "list"], false)]
        });
    }
    if let Some(error) = error.downcast_ref::<agmi::store::RefusalRecoveryError>() {
        let message = match error.0 {
            "refusal_recovery_conflict" => {
                "Refusal preview changed. Preview this operation again before applying its new token."
            }
            "refusal_recovery_ineligible" => {
                "Retained evidence does not permit refusal retirement. Preserve the unknown operation; inspect its refusal preview."
            }
            _ => {
                "Refusal recovery requires an intact adopted journal. Preserve state and inspect recovery prerequisites."
            }
        };
        return json!({
            "code":error.0,"message":message,"details":{},
            "next_actions":[action(config, &["recover", "resolve", "--help"], false)]
        });
    }
    if let Some((code, message, details)) = agmi::registration::error_details(error) {
        return json!({
            "code":code,
            "message":message,
            "details":details,
            "next_actions":[
                action(config, &["identity", "status"], false),
                action(config, &["identity", "create", "--help"], false)
            ]
        });
    }
    let boundary = error.downcast_ref::<BoundaryError>();
    let lifecycle = error.downcast_ref::<agmi::lifecycle::LifecycleError>();
    let code = boundary
        .map(|e| e.0)
        .or_else(|| lifecycle.map(|e| e.code))
        .or_else(|| agmi::admin::error_code(error))
        .unwrap_or("operation_failed");
    // Only typed codes and static messages cross this boundary, never outer contexts.
    let message = boundary.map(|e| e.1).or_else(|| lifecycle.map(|e| e.message)).unwrap_or(match code {
        "admin_validation" => "Invalid configuration, patch or guidance; check schema, types and file references.",
        "admin_unsafe_file" => "Administration requires private owned regular files without symlinks or hardlinks.",
        "admin_io" => "Cannot read or persist administration files; a save may have completed. Reread revisions before retrying.",
        "admin_revision_conflict" => "Revision conflict; read the current revision before retrying.",
        "admin_busy" => "Configuration acquisition deadline reached or directory busy; lane control was not changed. Retry after inspecting the current lane token.",
        "admin_routing_runtime_active" => "Stop the controller before changing API routes; preserve its journal and pause state.",
        _ => "Operation failed; inspect local prerequisites before retrying.",
    });
    let command: &[&str] = match code {
        "config_missing" => &["init", "--help"],
        "config_invalid" => &["config", "schema"],
        "registration_configuration_invalid" => &["identity", "create", "--help"],
        "admin_routing_runtime_active" => &["status"],
        "admin_busy" => &["lane", "--help"],
        "admin_revision_conflict" | "admin_io" | "admin_unsafe_file" => &["config", "show"],
        "admin_validation" => &["config", "schema"],
        "configuration_exists"
        | "initialization_failed"
        | "credential_rotation_failed"
        | "service_config_unsupported" => &["config", "show"],
        "credential_input_unavailable"
        | "credential_input_interrupted"
        | "identity_verification_prerequisite"
        | "credential_identity_unverified"
        | "identity_verification_unavailable" => &["init", "--help"],
        "invalid_release_digest" => &["install", "--help"],
        "invalid_release_identity" => &["update", "--help"],
        _ => &["health"],
    };
    let mut value = json!({"code":code,"message":message,"details":{},"next_actions":[action(config, command, false)]});
    if code == "admin_routing_runtime_active" {
        value["next_actions"] = json!([
            action(config, &["status"], false),
            {"kind":"instruction","authorization_required":true,
             "message":"Stop the controller that owns this selected configuration before changing API routes. Do not stop a different account's service."},
            action(config, &["config", "show"], false)
        ]);
    }
    if code == "credential_rotation_requires_stop" {
        value["next_actions"] = json!([
            action(config, &["status"], false),
            {"kind":"instruction","authorization_required":true,
             "message":"Stop the controller that owns this selected configuration before retrying credential rotation. Do not stop a different account's service."}
        ]);
    }
    if code == "credential_rotation_requires_pause" {
        value["next_actions"] = json!([
            action(config, &["pause"], true),
            action(config, &["credentials", "rotate", "--help"], false)
        ]);
    }
    if matches!(
        code,
        "invalid_release_digest" | "invalid_release_identity" | "service_config_unsupported"
    ) {
        value["details"] = json!({"stage":"preflight","staging":"not_started","activation":"not_started","service":"unknown"});
    }
    if code.starts_with("update_") {
        value["next_actions"] = json!([
            action(None, &["update", "--help"], false),
            action(None, &["service", "status"], false),
            {"kind":"instruction","authorization_required":false,
             "message":"Preserve the pinned update record, retained releases and user state. Inspect the reported operation before retrying; failure never authorizes an older-journal restore, stale-intent restart, work replay or uncertainty reset."}
        ]);
    }
    if code.starts_with("logs_") {
        value["next_actions"] = json!([
            action(config, &["logs"], false),
            action(config, &["doctor"], false),
            {"kind":"instruction","authorization_required":false,
             "message":"Following stopped; retained history may be incomplete. Inspect the journal and start a new follow explicitly; do not reset state to restart the cursor."}
        ]);
    }
    if let Some(error) = error.downcast_ref::<agmi::lifecycle::InstallerError>() {
        value["code"] = json!("installer_failed");
        value["message"] =
            json!("Installer did not complete; inspect installation before retrying.");
        value["details"] = error.evidence.clone();
        let reason = error.evidence["failure_code"].as_str().unwrap_or("unknown");
        let repair = match reason {
            "unsupported_platform" => "Use Linux with an available user-systemd manager.",
            "invalid_arguments" => {
                "Inspect install or update help and correct the requested arguments."
            }
            "missing_prerequisite" => {
                "Install the required Linux command dependencies before retrying."
            }
            "candidate_unavailable" => "Select an accessible regular executable release candidate.",
            "candidate_execution_unavailable" => {
                "Inspect candidate execute permissions and access, and use an executable TMPDIR and staging filesystem."
            }
            "digest_mismatch" => {
                "Recheck the candidate against an independently trusted SHA256 digest; do not execute an unverified candidate."
            }
            "installer_busy" => {
                "Inspect the current installer and lock ownership; do not remove a lock held by another installer."
            }
            "preparation_failed" => {
                "Inspect installation directory permissions and filesystem capacity."
            }
            "release_invalid" => "Select a verified release compatible with this host.",
            "configuration_invalid" => {
                "Repair the selected configuration before retrying installation."
            }
            "manager_context_mismatch" => {
                "Use the installation owner's normal HOME and user-systemd session; verify that the manager loads that home's .config/systemd/user directory."
            }
            "service_state_unavailable" => {
                "Inspect user-manager connectivity and wait for runtime/timer transitions to settle before retrying."
            }
            "insufficient_space" => {
                "Free unrelated filesystem capacity; never delete the journal, WAL, retained evidence or credentials."
            }
            "unit_invalid" => {
                "Inspect the user-service unit and overrides before changing installation state."
            }
            "stop_failed"
            | "bootstrap_recovery_failed"
            | "switch_failed"
            | "reload_failed"
            | "start_failed"
            | "service_failed" => {
                "Inspect the installed release, user-service state and unit overrides manually before any retry or rollback."
            }
            _ => {
                "Inspect installation and user-service state manually; the failure reason is unavailable. Do not infer that activation was rolled back."
            }
        };
        value["next_actions"] = json!([
            action(None, &["service", "status"], false),
            {"kind":"instruction","authorization_required":false,"message":repair},
            action(config, if reason == "configuration_invalid" { &["config", "check"] } else { &["install", "--help"] }, false)
        ]);
        if reason == "manager_context_mismatch" {
            value["next_actions"].as_array_mut().unwrap().remove(0);
        }
    }
    value
}

pub(crate) fn diagnostics(data: &mut Value, config: Option<&Path>) {
    let mut codes: Vec<&str> = Vec::new();
    for code in [
        data.get("issues"),
        data.get("warnings"),
        data["operational"].get("issues"),
    ]
    .into_iter()
    .flatten()
    .flat_map(|value| value.as_array().into_iter().flatten())
    .filter_map(Value::as_str)
    {
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    for name in ["controller", "answer", "judge", "mine"] {
        let component = &data["components"][name];
        let relevant = !matches!(component["state"].as_str(), Some("ok") | Some("disabled"));
        if !relevant {
            continue;
        }
        for reason in component["reasons"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !codes.contains(&reason) {
                codes.push(reason);
            }
        }
    }
    let mut diagnostics: Vec<_> = codes.iter().map(|code| {
        let (command, authorization): (&[&str], bool) = match *code {
            "config_missing" | "config_location_unavailable" => (&["init", "--help"], false),
            "config_invalid" | "no_active_capabilities" | "reload_blocked" => (&["config", "check"], false),
            "participation_paused" => (&["resume"], true),
            "controller_stopped" | "controller_unobserved" | "controller_stale" => (&["status"], false),
            "pending_outcome_uncertain" | "dispatch_outcome_uncertain" | "pending_work_overdue" |
            "model_work_overdue" | "model_execution_unresolved" | "participation_risk_admitted" |
            "admission_blocked" => (&["operations", "list"], false),
            "challenge_unobserved" | "challenge_observation_stale" | "current_epoch_unanswered" |
            "answer_evidence_unavailable" | "hosted_identity_unverified" | "hosted_identity_unobserved" |
            "hosted_identity_unavailable" | "hosted_identity_invalid_response" |
            "hosted_identity_legacy_unknown" | "hosted_identity_authentication_failed" => (&["reads"], false),
            "hosted_identity_mismatch" => (&["config", "show"], false),
            "not_initialized" => (&["run", "--once"], true),
            _ => (&["status"], false),
        };
        let mut actions = vec![action(config, command, authorization)];
        let instruction = match *code {
            "config_location_unavailable" => Some("Select the existing configuration with --config, or choose a private configuration path before initialization."),
            "local_evidence_unavailable" => Some("Inspect local state access and integrity without deleting, replacing or opening a second writer on the journal."),
            "state_disk_space_low" | "state_disk_headroom_low" | "state_disk_space_unavailable" =>
                Some("Inspect state filesystem capacity and access. Preserve the journal, WAL, retained evidence and credentials; do not delete state to free space."),
            "clock_regressed" => Some("Inspect host clock synchronization before trusting age or deadline evidence."),
            "identity_mismatch" => Some("Restore the configuration for this journal's existing identity. Do not replace its account or erase state."),
            "hosted_identity_authentication_failed" => Some("Hosted identity verification recorded an authentication rejection. Review the selected credential without exposing it; any replacement requires the existing paused/stopped same-identity checks. A later timeout does not clear the rejection."),
            "hosted_identity_mismatch" => Some("Hosted identity verification recorded a different identity. Review the bound account and network configuration; preserve the journal and do not replace identity or erase evidence to bypass the mismatch."),
            "hosted_identity_unavailable" | "hosted_identity_invalid_response" =>
                Some("Identity availability or response evidence is inconclusive, not a credential rejection. Follow a reported retry only when the controller has a retained automatic path; do not change credentials to bypass a timeout."),
            "hosted_identity_legacy_unknown" | "hosted_identity_unverified" =>
                Some("Legacy identity evidence does not establish the original failure or current verification. Doctor --repair can normalize an eligible legacy false flag while retaining uncertainty; it cannot verify identity or repair credentials."),
            "api_routing_mismatch" => Some("Restore the bound network.api profile shown by status. Routing changes require a stopped controller and no unresolved or reusable work; never erase evidence to bypass this boundary."),
            "model_execution_unresolved" => Some("Retained model uncertainty is risk evidence, not necessarily a current blocker. Inspect the affected lane before considering stopped-writer recover-model; never reset an unresolved network request."),
            "background_remote_work_retained" => Some("Retained remote outcomes remain risk and reconciliation evidence, not a current participation dependency. Background follow-up does not authorize replay, clear uncertainty or require increasing budgets."),
            "no_active_capabilities" => Some("Review model authentication, routes, guidance and desired capability modes before explicitly changing configuration."),
            _ => None,
        };
        if let Some(message) = instruction {
            actions.push(json!({"kind":"instruction","message":message,
                "authorization_required":*code == "identity_mismatch"}));
        }
        json!({"code":code,"next_actions":actions})
    }).collect();
    let checked_at = data["checked_at"].as_i64().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    });
    if let Some(work) = data["work"].as_object_mut() {
        for detail in work.values_mut() {
            detail["next_actions"] =
                intervention_actions(&detail["intervention"], &diagnostics, config, checked_at);
            if detail["background_recovery"]["count"].as_u64().unwrap_or(0) > 0 {
                detail["background_recovery"]["next_actions"] = json!([
                    action(config, &["operations", "list"], false),
                    action(config, &["reads"], false),
                ]);
            }
        }
    }
    for lane in agmi::capability::LaneId::NAMES {
        let control = &data["lane_controls"][lane];
        if control["desired"]["paused"] == true {
            let mut actions = vec![action(config, &["lane", "show", lane], false)];
            if let Some(token) = control["desired"]["control_token"].as_str() {
                actions.push(action(
                    config,
                    &["lane", "resume", lane, "--expected-control", token],
                    true,
                ));
                actions.push(json!({"kind":"instruction","authorization_required":false,
                    "message":"This removes only the selected lane override. Reread its token after any conflict. Global pause, effective configuration and admission prerequisites remain independent; no retry authority is created."}));
            }
            if let Some(existing) = data["work"][lane]["next_actions"].as_array_mut() {
                existing.retain(|step| {
                    !step["argv"]
                        .as_array()
                        .and_then(|parts| parts.last())
                        .is_some_and(|word| word == "resume")
                });
                for step in actions {
                    if !existing.contains(&step) {
                        existing.push(step);
                    }
                }
            }
        }
    }
    // Shared inspection prerequisites take precedence over mutation and waiting.
    let gated = inspection_gate(data).is_some();
    if gated {
        for lane in agmi::capability::LaneId::NAMES {
            if let Some(actions) = data["work"][lane]["next_actions"].as_array_mut() {
                actions.retain(|step| !contradicts_inspection_gate(step));
            }
        }
        for diagnostic in &mut diagnostics {
            if let Some(actions) = diagnostic["next_actions"].as_array_mut() {
                actions.retain(|step| !contradicts_inspection_gate(step));
            }
        }
    }
    let mut actions = intervention_actions(&data["intervention"], &diagnostics, config, checked_at)
        .as_array()
        .cloned()
        .unwrap_or_default();
    if data["intervention"]["next_action"] == "resume" && data["paused"] != true {
        actions = if let Some(lane) = agmi::capability::LaneId::NAMES.into_iter().find(|lane| {
            data["lane_controls"][*lane]["desired"]["paused"] == true
                && data["work"][*lane]["intervention"]["next_action"] == "resume"
        }) {
            data["work"][lane]["next_actions"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![action(config, &["lane", "show", lane], false)])
        } else {
            vec![action(config, &["lane", "--help"], false)]
        };
    }
    if data["repair_requested"] == false
        && !gated
        && data["repairs"]["eligible"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    {
        actions.push(action(config, &["doctor", "--repair"], true));
    }
    if ["eligible", "ineligible", "applied", "skipped"]
        .iter()
        .any(|key| {
            data["repairs"][*key]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["kind"] == "identity"))
        })
    {
        actions.push(json!({"kind":"instruction","authorization_required":false,
            "message":"Identity repair is local legacy-evidence normalization only. It retains legacy uncertainty and recorded rejection; it does not verify identity, replace credentials, change read retries or authorize work."}));
    }
    if let Some(existing) = data["next_actions"].as_array().cloned() {
        for step in &existing {
            if gated && contradicts_inspection_gate(step) {
                continue;
            }
            if !actions.contains(step) {
                actions.push(step.clone());
            }
        }
    }
    if gated {
        actions.retain(|step| !contradicts_inspection_gate(step));
    }
    data["next_actions"] = json!(actions);
    data["diagnostics"] = Value::Array(diagnostics);
}
fn inspection_gate(data: &Value) -> Option<&'static str> {
    if data["intervention"]["next_action"] == "inspect_state_filesystem"
        || data["components"]["controller"]["reasons"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|reason| {
                matches!(
                    reason.as_str(),
                    Some("state_disk_space_low" | "state_disk_space_unavailable")
                )
            })
    {
        Some("inspect filesystem first")
    } else if data["intervention"]["next_action"] == "inspect_repair_failure" {
        Some("inspect repair failure first")
    } else {
        None
    }
}

fn contradicts_inspection_gate(step: &Value) -> bool {
    if step["authorization_required"] == true || step["kind"].as_str() == Some("wait") {
        return true;
    }
    if step["kind"].as_str() == Some("instruction") {
        return step["message"].as_str().is_some_and(|message| {
            message.contains("automatic path; wait for fresh local evidence")
        });
    }
    if step["kind"].as_str() != Some("command") {
        return false;
    }
    let Some(parts) = step["argv"].as_array() else {
        return false;
    };
    parts.iter().any(|part| {
        matches!(
            part.as_str(),
            Some("--expected-control" | "resume" | "recover-model" | "run" | "--repair")
        )
    })
}

fn intervention_actions(
    detail: &Value,
    diagnostics: &[Value],
    config: Option<&Path>,
    checked_at: i64,
) -> Value {
    let mut actions = Vec::new();
    match detail["status"].as_str() {
        Some("none_required") => return json!([]),
        Some("automatic_recovery") => {
            if let Some(deadline) = detail["next_at"].as_i64().filter(|at| *at > checked_at) {
                actions.push(json!({"kind":"wait","until":deadline,"clock":"unix_seconds",
                    "authorization_required":false,"evidence":"reported_local_deadline_not_a_success_guarantee"}));
            }
            actions.push(json!({"kind":"instruction","authorization_required":false,
                "message":"The configured controller has an automatic path; wait for fresh local evidence. Retry eligibility and upstream success are not guaranteed. Do not replay writes or change policy merely to bypass the wait."}));
            actions.push(action(config, &["health"], false));
        }
        _ => {
            if detail["next_action"] == "inspect_local_evidence"
                && let Some(actions) = diagnostics
                    .iter()
                    .find(|diagnostic| diagnostic["code"] == detail["reason"])
                    .and_then(|diagnostic| diagnostic["next_actions"].as_array())
            {
                return Value::Array(actions.clone());
            }
            if detail["next_action"].as_str() == Some("inspect_state_filesystem") {
                actions.push(json!({"kind":"instruction","authorization_required":false,
                    "message":"Inspect state filesystem capacity and access. Preserve the journal, WAL, retained evidence and credentials; do not delete state to free space."}));
                actions.push(action(config, &["status"], false));
                return json!(actions);
            }
            let command: &[&str] = match detail["next_action"].as_str() {
                Some("resume") => &["resume"],
                Some("initialize_controller") => &["run", "--once"],
                Some("start_controller") => &["run"],
                Some(
                    "repair_config" | "review_participation_policy" | "review_model_configuration",
                ) => &["config", "show"],
                Some("review_credentials") => &["reads"],
                Some("recover_model") => &["recover-model"],
                Some("authorize") => &["recover", "authorize", "--help"],
                Some("inspect_operations" | "inspect_model_attempts" | "inspect_answer_retry") => {
                    &["operations", "list"]
                }
                _ => &["status"],
            };
            if command == ["run"] {
                actions.push(json!({"kind":"instruction","authorization_required":false,
                    "message":"Inspect the selected managed service or foreground controller before starting it; do not run two controllers."}));
            }
            if command == ["recover-model"] {
                actions.push(json!({"kind":"instruction","authorization_required":false,
                    "message":"Inspect retained model evidence and stop its controller before explicitly authorizing model-only abandonment. Abandonment does not refund execution exposure or grant another attempt; eligible regeneration may incur another model charge. Sent network requests are never reset."}));
            }
            actions.push(action(
                config,
                command,
                matches!(
                    command,
                    ["resume"] | ["run"] | ["run", "--once"] | ["recover-model"]
                ),
            ));
        }
    }
    json!(actions)
}

pub(crate) fn onboarding(data: &mut Value, config: Option<&Path>) {
    if data["dry_run"] == true {
        data["next_actions"] = json!([{"kind":"instruction","authorization_required":true,
            "message":"Repeat the verified init command without --dry-run to create configuration. No onboarding files were written."}]);
        return;
    }
    data["next_actions"] = json!([
        action(config, &["config", "show"], false),
        action(config, &["agents"], false),
        {"kind":"instruction","authorization_required":true,
            "message":"Review native model authentication, routes and guidance; explicitly configure desired active capability modes with config apply. Initialization leaves all capabilities read-only."},
        action(config, &["config", "check"], false),
        action(config, &["run", "--once"], true),
        {"kind":"instruction","authorization_required":true,
            "message":"Choose a controller: install and start the user service if desired, or run agmi in the foreground. Installation and running state have not been inspected. Do not run two controllers."},
        action(config, &["resume"], true),
        {"kind":"instruction","authorization_required":true,
            "message":"Keep the chosen controller running after resume; a completed run --once is not a supervised controller."},
        action(config, &["health"], false)
    ]);
}

pub(crate) fn human(kind: &str, data: &Value) {
    match kind {
        "health" | "doctor" => {
            print_diagnostic_verdict(kind, data);
            print_core_row(data);
            for lane in agmi::capability::LaneId::NAMES {
                print_lane_row(data, lane);
            }
            print_unrepresented_issues(data);
            print_risk_caveat(data);
            if kind == "doctor" {
                print_doctor_repairs(data);
            }
            print_next(data);
        }
        "init" => println!(
            "Identity verified; configuration {}. Participation is not ready; capabilities remain read-only and the journal is not initialized.",
            if data["dry_run"] == true {
                "not written (dry run)"
            } else {
                "created"
            }
        ),
        "status" => {
            println!(
                "Local status: initialized={} paused={} (local evidence only)",
                fmt_json(&data["initialized"]),
                fmt_json(&data["paused"])
            );
            println!(
                "Operational: {} (default diagnostic thresholds; state filesystem not assessed).",
                data["operational"]["status"].as_str().unwrap_or("unknown")
            );
            print_core_row(data);
            for lane in agmi::capability::LaneId::NAMES {
                print_lane_row(data, lane);
            }
            print_unrepresented_issues(data);
            print_risk_caveat(data);
            print_next(data);
        }
        "update" => {
            println!(
                "Update: {} ({})",
                data["update"]["status"].as_str().unwrap_or("unknown"),
                data["update"]["reason"]
                    .as_str()
                    .unwrap_or("no_reason_reported")
            );
            for (key, label) in [("current", "Installed"), ("published", "Published stable")] {
                let identity = &data["update"][key];
                if identity.is_object() {
                    println!(
                        "{label}: {} / {} / {} ({})",
                        identity["version"].as_str().unwrap_or("unknown"),
                        identity["commit"].as_str().unwrap_or("unknown"),
                        identity["source_dirty"].as_str().unwrap_or("unknown"),
                        identity["target"].as_str().unwrap_or("unknown")
                    );
                }
            }
            if let Some(note) = data["repair"]["evidence_limit"].as_str() {
                println!("Repair evidence: {note}");
            }
            println!(
                "Repair: {}",
                data["repair"]["status"].as_str().unwrap_or("not_requested")
            );
            if let Some(reason) = data["repair"]["reason"].as_str() {
                println!("Repair reason: {reason}");
            }
            if let Some(status) = data["update"]["doctor_status"].as_str() {
                println!(
                    "Doctor: {status}; observed release: {}",
                    data["update"]["doctor_release"]
                        .as_str()
                        .unwrap_or("unknown")
                );
            }
            if let Some(evidence) = data.get("installation") {
                println!(
                    "Activation: {}; service: {}; failure: {}",
                    evidence["activation"], evidence["service"], evidence["failure_code"]
                );
            }
            if data["update"]["check"] == true || data["update"]["dry_run"] == true {
                println!("No activation or repair performed.");
            }
            if data["readiness"].is_object() {
                print_intervention(&data["readiness"]);
                print_actions(&data["readiness"]["next_actions"]);
            } else {
                println!("Readiness: not assessed.");
            }
            println!(
                "Update success is separate from readiness; retained uncertainty and upstream waits are not erased."
            );
        }
        "install" | "service" => {
            let evidence = data.get("installation").unwrap_or(data);
            println!(
                "{kind}: stage={}, activation={}, service={}",
                evidence["stage"], evidence["activation"], evidence["service"]
            );
            if data["dry_run"] == true {
                println!("Dry run: no installer changes.");
            }
            if kind == "service"
                && data["plan"]["arguments"][1] == "status"
                && let Some(output) = data["output"].as_str()
            {
                print!("{output}");
            }
        }
        "lane_show" | "lane_pause" | "lane_resume" => print_lane_control(data),
        "pause" => println!(
            "Participation paused; dispatched requests and server auto-mining are not retracted."
        ),
        "resume" => println!(
            "Configured capabilities authorized; resume does not start a controller or change capability modes."
        ),
        _ => println!(
            "{}",
            serde_json::to_string_pretty(data).expect("JSON serializes")
        ),
    }
    if !matches!(kind, "health" | "doctor" | "status") {
        print_actions(&data["next_actions"]);
    }
}
fn fmt_json(value: &Value) -> Cow<'_, str> {
    match value {
        Value::Bool(true) => Cow::Borrowed("true"),
        Value::Bool(false) => Cow::Borrowed("false"),
        Value::Number(number) => Cow::Owned(number.to_string()),
        Value::String(text) => Cow::Borrowed(text),
        _ => Cow::Borrowed("unknown"),
    }
}

fn unattended_label(value: &Value) -> &'static str {
    match value {
        Value::Bool(true) => "yes",
        Value::Bool(false) => "no",
        _ => "unknown",
    }
}

fn lane_mode_human<'a>(data: &'a Value, lane: &str) -> &'a str {
    data["effective_capabilities"][lane]["mode"]
        .as_str()
        .or_else(|| data["effective_runtime"]["policy"]["capabilities"][lane]["mode"].as_str())
        .or_else(|| data["components"][lane]["mode"].as_str())
        .unwrap_or("unknown")
}

fn join_reasons(component: &Value) -> String {
    let reasons: Vec<&str> = component["reasons"]
        .as_array()
        .map(|rows| rows.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if reasons.is_empty() {
        "unspecified".to_owned()
    } else {
        reasons.join(",")
    }
}

fn print_diagnostic_verdict(kind: &str, data: &Value) {
    if kind == "doctor" {
        let outcome = data["repair_outcome"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if data["repair_requested"] == false {
                    "not_requested".to_owned()
                } else {
                    "unknown".to_owned()
                }
            });
        println!(
            "Doctor: local assessment (local evidence only); unattended={}; repair_outcome={outcome}",
            unattended_label(&data["intervention"]["unattended"])
        );
        return;
    }
    let verdict = match &data["healthy"] {
        Value::Bool(true) => "healthy",
        Value::Bool(false) => "attention required",
        _ => "unknown evidence",
    };
    if data["expect_participation"] == false {
        println!(
            "Health: {verdict} (local evidence only; expect_participation=false opt-out, not unattended participation)"
        );
    } else {
        println!("Health: {verdict} (local evidence only)");
    }
    println!(
        "Operational: {}",
        data["operational"]["status"].as_str().unwrap_or("unknown")
    );
}

fn print_core_row(data: &Value) {
    let component = &data["components"]["controller"];
    let root = &data["intervention"];
    if let Some(state) = component["state"].as_str() {
        print!("Core: {state}");
        if state != "ok" {
            print!(" ({})", join_reasons(component));
        }
    } else {
        print!("Core: ready={}", fmt_json(&root["controller"]["ready"]));
    }
    println!(
        "; {} ({})",
        intervention_label(&root["status"]),
        root["reason"].as_str().unwrap_or("evidence_unavailable")
    );
    if let Some(gate) = inspection_gate(data) {
        println!("Shared prerequisite: {gate}; lane recovery paths remain conditional.");
    }
}

fn print_lane_row(data: &Value, lane: &str) {
    let work = &data["work"][lane];
    let intervention = &work["intervention"];
    let component = &data["components"][lane];
    let state = component["state"].as_str();
    print!(
        "- {lane}: {}; {}; {}",
        lane_mode_human(data, lane),
        work["progress"].as_str().unwrap_or("unknown"),
        intervention_label(&intervention["status"])
    );
    if intervention["status"] != "none_required" {
        print!(
            " ({})",
            intervention["reason"]
                .as_str()
                .unwrap_or("evidence_unavailable")
        );
    }
    if let Some(state) = state {
        print!("; {state}");
        if !matches!(state, "ok" | "disabled") {
            print!(" ({})", join_reasons(component));
            if let Some(age) = component["age_seconds"].as_u64() {
                print!("; age={age}s");
            }
        }
    }
    let control = &data["lane_controls"][lane];
    if control["authoritative_closure"]["state"] == "closed" {
        print!("; fenced");
    } else {
        let observed = &control["observed_admission"];
        if observed["state"] != "open" || observed["freshness"] != "current_observation" {
            print!(
                "; admission={}",
                observed["state"].as_str().unwrap_or("unknown")
            );
            if let Some(freshness) = observed["freshness"].as_str()
                && freshness != "current_observation"
            {
                print!("/{freshness}");
            }
        }
    }
    if intervention["status"] == "automatic_recovery"
        && let Some(at) = intervention["next_at"].as_i64()
    {
        print!("; next_at={at}");
    }
    println!();
}

fn print_unrepresented_issues(data: &Value) {
    let mut printed = false;
    for code in data["issues"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let represented = data["intervention"]["reason"] == code
            || ["controller", "answer", "judge", "mine"]
                .into_iter()
                .any(|name| {
                    let component = &data["components"][name];
                    let shown = component["state"].as_str().is_some_and(|state| {
                        state != "ok" && (name == "controller" || state != "disabled")
                    });
                    (shown
                        && component["reasons"]
                            .as_array()
                            .is_some_and(|reasons| reasons.iter().any(|reason| reason == code)))
                        || (name != "controller"
                            && data["work"][name]["intervention"]["status"] != "none_required"
                            && data["work"][name]["intervention"]["reason"] == code)
                });
        if !represented {
            if !printed {
                print!("Issues:");
                printed = true;
            }
            print!(" {code}");
        }
    }
    if printed {
        println!();
    }
}

fn print_risk_caveat(data: &Value) {
    let effects = data
        .pointer("/risk/unresolved_effects")
        .or_else(|| data.pointer("/participation/unresolved_count"))
        .and_then(Value::as_u64);
    let models = data
        .pointer("/risk/unresolved_model_attempts")
        .and_then(Value::as_u64)
        .or_else(|| {
            data["operations"]
                .as_array()?
                .iter()
                .try_fold(0_u64, |total, row| {
                    if matches!(
                        row["state"].as_str(),
                        Some("model_unknown" | "superseded_model_unknown")
                    ) {
                        Some(total.saturating_add(row["count"].as_u64()?))
                    } else {
                        Some(total)
                    }
                })
        });
    for (label, count) in [
        ("unresolved effects", effects),
        ("unresolved model attempts", models),
    ] {
        match count {
            Some(0) => {}
            Some(count) => println!("Risk: {label}={count} (retained uncertainty)."),
            None => println!("Risk: {label}=unknown."),
        }
    }
    if let Some(count) = data["participation"]["risk_admissions"].as_u64()
        && count > 0
    {
        println!("Risk admissions: {count} (retained history).");
    }
    if let Some(count) = data["risk"]["background_remote_work"].as_u64()
        && count > 0
    {
        println!(
            "Background follow-up: {count} remote operations; retained risk, not current participation blockers."
        );
    }
    if data["healthy"] == true && data["attention_required"] == true {
        println!(
            "Operationally healthy; retained risk or warnings still require attention, not replay."
        );
    }
    let mut first = true;
    for lane in agmi::capability::LaneId::ALL {
        let nonblocking = data["participation"]["lanes"][lane.as_str()]["retained_uncertainty_nonblocking"]
            == true
            || data["risk"]["retained_uncertainty_nonblocking_lanes"]
                .as_array()
                .is_some_and(|lanes| {
                    lanes
                        .iter()
                        .any(|value| value.as_str() == Some(lane.as_str()))
                });
        if nonblocking {
            if first {
                print!("Risk policy: retained uncertainty does not block distinct fresh work in");
                first = false;
            }
            print!(" {}", lane.as_str());
        }
    }
    if !first {
        println!("; same-work replay remains fenced.");
    }
    if let Some(warnings) = data["warnings"].as_array()
        && !warnings.is_empty()
    {
        print!("Warnings:");
        for warning in warnings.iter().filter_map(Value::as_str) {
            print!(" {warning}");
        }
        println!();
    }
    if data["components"]["api"]["resources_truncated"] == true || data["reads_truncated"] == true {
        println!("Coverage: recorded reads truncated; this view is not exhaustive.");
    }
    println!("Local evidence and recorded reads are not live probes, permits or settlement.");
}

fn print_doctor_repairs(data: &Value) {
    let repairs = &data["repairs"];
    let count = |key: &str| {
        repairs[key]
            .as_array()
            .map_or("unknown".to_owned(), |rows| rows.len().to_string())
    };
    println!(
        "Repairs: requested={}; eligible={}, ineligible={}, applied={}, skipped={}",
        fmt_json(&data["repair_requested"]),
        count("eligible"),
        count("ineligible"),
        count("applied"),
        count("skipped")
    );
    if !repairs["failure"].is_null() {
        println!("Repair failure: {}", fmt_json(&repairs["failure"]));
    }
    let restoration = &repairs["restoration"];
    if restoration.is_object() {
        let runtime = restoration["runtime"].as_str().unwrap_or("unknown");
        let manager = restoration["manager_action"].as_str().unwrap_or("unknown");
        let verified = match &restoration["verified"] {
            Value::Bool(true) => "verified",
            Value::Bool(false) => "unverified",
            _ => "verification unknown",
        };
        println!("Restoration: runtime={runtime} manager={manager}; {verified}");
        if runtime == "restored"
            && restoration["verified"] == true
            && data["intervention"]["controller"]["ready"] != true
        {
            println!(
                "Fresh controller observation is still pending; applied repairs never imply participation."
            );
        }
    }
    let mut seen = Vec::<&str>::new();
    for key in ["eligible", "ineligible", "applied", "skipped"] {
        for row in repairs[key].as_array().into_iter().flatten() {
            for field in ["reason", "evidence_limit"] {
                if let Some(value) = row[field].as_str()
                    && value != "eligible"
                    && !seen.contains(&value)
                {
                    println!("  {key}: {value}");
                    seen.push(value);
                }
            }
        }
    }
    if repairs["skipped"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
        || repairs["ineligible"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    {
        println!("Skipped and ineligible outcomes remain unresolved evidence.");
    }
    println!(
        "Repair counts are local outcomes, not proof of current participation or remote success. Identity normalization retains uncertainty; it does not verify identity or repair credentials."
    );
}

fn print_next(data: &Value) {
    let mut combined: Vec<Value> = Vec::new();
    let mut push_unique = |step: &Value| {
        let step = sanitized_step(step);
        if !combined.contains(&step) {
            combined.push(step);
        }
    };
    for step in data["next_actions"].as_array().into_iter().flatten() {
        push_unique(step);
    }
    for lane in agmi::capability::LaneId::NAMES {
        for step in data["work"][lane]["next_actions"]
            .as_array()
            .into_iter()
            .flatten()
        {
            push_unique(step);
        }
    }
    if combined.is_empty() {
        return;
    }
    println!("Next:");
    print_actions(&json!(combined));
}

/// Sanitized human rendering for parser and execution errors: reason, field
/// detail and numbered shell-quoted commands. JSON envelopes keep full detail.
pub(crate) fn human_error(error: &Value) {
    eprintln!(
        "agmi: {} [{}]",
        error["message"].as_str().unwrap_or("Operation failed"),
        error["code"].as_str().unwrap_or("operation_failed")
    );
    for (key, label) in [
        ("reason", "Reason"),
        ("failure_code", "Failure"),
        ("stage", "Stage"),
        ("activation", "Activation"),
        ("service", "Service"),
    ] {
        if let Some(value) = error["details"][key].as_str() {
            eprintln!("{label}: {value}");
        }
    }
    if let Some(recovery) = error["details"]["bootstrap_recovery"].as_object() {
        eprintln!(
            "Unit recovery: definitions={}, manager_reload={}",
            fmt_json(recovery.get("definitions_restored").unwrap_or(&Value::Null)),
            fmt_json(
                recovery
                    .get("manager_reload_succeeded")
                    .unwrap_or(&Value::Null)
            )
        );
    }
    let fields: Vec<&str> = error["details"]["fields"]
        .as_array()
        .map(|rows| rows.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !fields.is_empty() {
        eprintln!("Fields: {}", fields.join(", "));
    }
    let missing: Vec<&str> = error["details"]["missing_fields"]
        .as_array()
        .map(|rows| rows.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !missing.is_empty() && missing != fields {
        eprintln!("Missing: {}", missing.join(", "));
    }
    eprintln!("Next:");
    let mut seen: Vec<String> = Vec::new();
    let mut index = 0;
    for step in error["next_actions"].as_array().into_iter().flatten() {
        let step = sanitized_step(step);
        let description = match step["kind"].as_str() {
            Some("command") => render_argv(&step["argv"]),
            _ => step["message"]
                .as_str()
                .unwrap_or("Inspect local evidence")
                .to_owned(),
        };
        if seen.contains(&description) {
            continue;
        }
        seen.push(description.clone());
        index += 1;
        eprintln!(
            "{index}. {description}{}",
            if step["authorization_required"] == true {
                " [explicit authorization required]"
            } else {
                ""
            }
        );
    }
}

fn print_lane_control(control: &Value) {
    let desired = &control["desired"];
    println!(
        "Lane {}: desired paused={}, control revision={}, token={}",
        desired["lane_id"].as_str().unwrap_or("unknown"),
        desired["paused"],
        desired["control_revision"],
        desired["control_token"].as_str().unwrap_or("unavailable")
    );
    println!(
        "  Journal closure: {} {}; runtime observed admission: {} ({}, source={})",
        control["authoritative_closure"]["state"]
            .as_str()
            .unwrap_or("unknown"),
        control["authoritative_closure"]["reasons"],
        control["observed_admission"]["state"]
            .as_str()
            .unwrap_or("unknown"),
        control["observed_admission"]["freshness"]
            .as_str()
            .unwrap_or("unobserved"),
        control["observed_admission"]["source"]
            .as_str()
            .unwrap_or("none")
    );
    println!(
        "  Observation: at={}, valid_until={}, control_revision={}, accepted_config_revision={}",
        control["observed_admission"]["observed_at"],
        control["observed_admission"]["valid_until"],
        control["observed_admission"]["observed_control_revision"],
        control["observed_admission"]["accepted_config_revision"]
    );
    if control["fence_ack"].is_object() {
        println!(
            "  Local admission fence: acknowledged={}, changed={}, committed_at={}",
            control["fence_ack"]["acknowledged"],
            control["fence_ack"]["changed"],
            control["fence_ack"]["committed_at"]
        );
    }
    println!(
        "  Dispatch uncertainty: unsettled intent={}, ids={}, ids_truncated={}, unresolved sent={}",
        control["dispatch_uncertainty"]["dispatch_intent_unsettled_count"],
        control["dispatch_uncertainty"]["dispatch_intent_unsettled_ids"],
        control["dispatch_uncertainty"]["ids_truncated"],
        control["dispatch_uncertainty"]["unresolved_sent_count"]
    );
    println!(
        "  not_closed is not open; observations are not permits. A fence does not cancel or settle earlier work."
    );
}

fn print_intervention(data: &Value) {
    let root = &data["intervention"];
    println!(
        "Intervention: {}; unattended={}; controller_ready={}",
        intervention_label(&root["status"]),
        root["unattended"],
        root["controller"]["ready"]
    );
    for name in ["answer", "judge", "mine"] {
        let work = &data["work"][name];
        let intervention = &work["intervention"];
        println!(
            "- {name}: {}; {} ({})",
            work["progress"].as_str().unwrap_or("unknown"),
            intervention_label(&intervention["status"]),
            intervention["reason"]
                .as_str()
                .unwrap_or("evidence_unavailable")
        );
        println!(
            "  Evidence: controller_fresh={}, observation_fresh={}, next_at={}",
            intervention["evidence_fresh"],
            intervention["observation_fresh"],
            intervention["next_at"]
        );
        print_actions(&work["next_actions"]);
    }
    println!(
        "Local deadlines describe configured paths, not guaranteed success; controller identity is not independently verified."
    );
}

fn intervention_label(status: &Value) -> &'static str {
    match status.as_str() {
        Some("none_required") => "none required",
        Some("automatic_recovery") => "waiting automatically",
        Some("operator_required") => "operator required",
        _ => "undetermined",
    }
}

fn sanitized_step(step: &Value) -> Value {
    if step["kind"].as_str() == Some("command")
        && let Some(lane) = token_lane(&step["argv"])
    {
        // Preserve the selected invocation prefix (including --config) while
        // pointing at the explicit CAS workflow instead of printing the token.
        let mut prefix: Vec<String> = step["argv"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_else(|| vec!["agmi".to_owned()]);
        if let Some(position) = prefix.iter().position(|part| part == "lane") {
            prefix.truncate(position);
        } else {
            prefix = vec!["agmi".to_owned()];
        }
        prefix.extend(["lane".to_owned(), "show".to_owned(), lane.to_owned()]);
        return json!({"kind":"command","argv":prefix,"authorization_required":false});
    }
    step.clone()
}

fn print_actions(actions: &Value) {
    let mut seen: Vec<String> = Vec::new();
    let mut index = 0;
    for step in actions.as_array().into_iter().flatten() {
        let description = match step["kind"].as_str() {
            Some("command") => render_argv(&step["argv"]),
            Some("wait") => format!(
                "Wait until Unix timestamp {} (reported deadline)",
                step["until"]
            ),
            _ => step["message"]
                .as_str()
                .unwrap_or("Inspect local evidence")
                .to_owned(),
        };
        if seen.contains(&description) {
            continue;
        }
        seen.push(description.clone());
        index += 1;
        println!(
            "{index}. {description}{}",
            if step["authorization_required"] == true {
                " [explicit authorization required]"
            } else {
                ""
            }
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn prerequisite_actions_progress_without_repeating_the_failed_status_check() {
        for (code, command) in [
            ("config_missing", ["init", "--help"]),
            ("config_location_unavailable", ["init", "--help"]),
            ("config_invalid", ["config", "check"]),
        ] {
            let mut report = crate::health_prerequisite(code);
            diagnostics(&mut report, Some(Path::new("/selected/config.toml")));
            let actions = report["next_actions"].as_array().unwrap();
            assert!(actions.iter().any(|step| step["argv"]
                == json!([
                    "agmi",
                    "--config",
                    "/selected/config.toml",
                    command[0],
                    command[1]
                ])
                && step["authorization_required"] == false));
            assert!(!actions.iter().any(|step| {
                step["argv"]
                    .as_array()
                    .and_then(|argv| argv.last())
                    .is_some_and(|word| word == "status")
            }));
        }
    }

    #[test]
    fn lane_only_root_resume_requires_its_token_not_a_global_resume() {
        for token in [json!("lane-token"), Value::Null] {
            let mut report = json!({
                "paused":false,"issues":[],
                "intervention":{"status":"operator_required","reason":"lane_paused","next_action":"resume"},
                "work":{"judge":{"intervention":{"status":"operator_required","reason":"lane_paused","next_action":"resume"}}},
                "lane_controls":{"judge":{"desired":{"paused":true,"control_token":token}}}
            });
            diagnostics(&mut report, Some(Path::new("/selected/config.toml")));
            let root = report["next_actions"].as_array().unwrap();
            assert!(!root.iter().any(|step| {
                step["argv"]
                    .as_array()
                    .and_then(|argv| argv.last())
                    .is_some_and(|word| word == "resume")
            }));
            assert!(root.iter().any(|step| step["argv"]
                == json!([
                    "agmi",
                    "--config",
                    "/selected/config.toml",
                    "lane",
                    "show",
                    "judge"
                ])));
            let mutation = root
                .iter()
                .find(|step| step["authorization_required"] == true);
            if token.is_null() {
                assert!(mutation.is_none());
            } else {
                assert_eq!(
                    mutation.unwrap()["argv"],
                    json!([
                        "agmi",
                        "--config",
                        "/selected/config.toml",
                        "lane",
                        "resume",
                        "judge",
                        "--expected-control",
                        "lane-token"
                    ])
                );
            }
        }
    }

    #[test]
    fn paused_lane_actions_use_its_control_token_not_global_resume() {
        let mut value = json!({"work":{"judge":{"intervention":{"status":"operator_required",
            "next_action":"resume","next_at":null}}},
            "lane_controls":{"judge":{"desired":{"paused":true,"control_token":"journal-lane-token"}}}});
        diagnostics(&mut value, Some(Path::new("/selected/config.toml")));
        let actions = value["work"]["judge"]["next_actions"].as_array().unwrap();
        assert_eq!(
            actions[0]["argv"],
            json!([
                "agmi",
                "--config",
                "/selected/config.toml",
                "lane",
                "show",
                "judge"
            ])
        );
        assert_eq!(
            actions[1]["argv"],
            json!([
                "agmi",
                "--config",
                "/selected/config.toml",
                "lane",
                "resume",
                "judge",
                "--expected-control",
                "journal-lane-token"
            ])
        );
        assert_eq!(actions[1]["authorization_required"], true);
        assert!(
            !actions.iter().any(|step| step["argv"]
                == json!(["agmi", "--config", "/selected/config.toml", "resume"]))
        );
    }

    use super::*;

    #[test]
    fn installer_failures_sanitize_context_and_scope_repair_actions() {
        for reason in [
            "configuration_invalid",
            "unknown",
            "manager_context_mismatch",
        ] {
            let error = Error::new(agmi::lifecycle::InstallerError {
                evidence: json!({"failure_code":reason,"stage":"preflight","activation":"not_started","service":"unknown"}),
            }).context("private-installer-path-and-output");
            let value = execution(&error, Some(Path::new("/selected/config.toml")));
            assert_eq!(value["code"], "installer_failed");
            assert_eq!(value["details"]["failure_code"], reason);
            if reason == "manager_context_mismatch" {
                assert_eq!(value["next_actions"][0]["kind"], "instruction");
                assert!(
                    !value["next_actions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|action| { action["argv"] == json!(["agmi", "service", "status"]) })
                );
            } else {
                assert_eq!(
                    value["next_actions"][0]["argv"],
                    json!(["agmi", "service", "status"])
                );
            }
            if reason == "configuration_invalid" {
                assert_eq!(
                    value["next_actions"][2]["argv"],
                    json!([
                        "agmi",
                        "--config",
                        "/selected/config.toml",
                        "config",
                        "check"
                    ])
                );
            }
            assert!(!value.to_string().contains("private-installer"));
        }
    }

    #[test]
    fn diagnostic_actions_use_only_supplied_future_deadlines_and_keep_risk() {
        let mut value = json!({"checked_at":100,"issues":["pending_outcome_uncertain"],
            "risk":{"unresolved_effects":4},"operational":{"status":"clear"},
            "work":{"answer":{"intervention":{"status":"automatic_recovery","next_action":"await_reconciliation","next_at":120}},
                "judge":{"intervention":{"status":"automatic_recovery","next_action":"await_assignments","next_at":null}},
                "mine":{"intervention":{"status":"automatic_recovery","next_action":"observe_challenge","next_at":99}}}});
        diagnostics(&mut value, Some(Path::new("private path/config.toml")));
        assert_eq!(value["risk"]["unresolved_effects"], 4);
        assert_eq!(value["operational"]["status"], "clear");
        let wait = &value["work"]["answer"]["next_actions"][0];
        assert_eq!(wait["kind"], "wait");
        assert_eq!(wait["until"], 120);
        for kind in ["judge", "mine"] {
            assert!(
                value["work"][kind]["next_actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|action| action["kind"] != "wait")
            );
        }
        assert_eq!(
            value["diagnostics"][0]["next_actions"][0]["authorization_required"],
            false
        );
    }

    #[test]
    fn untyped_errors_never_render_private_context_or_sources() {
        let error =
            anyhow::anyhow!("private-provider-output").context("private-path-and-credential");
        let value = execution(&error, None);
        assert_eq!(value["code"], "operation_failed");
        assert!(!value.to_string().contains("private-"));
        assert!(value["details"].is_object());
        assert_eq!(value["next_actions"][0]["authorization_required"], false);
    }

    #[test]
    fn recovery_and_resume_suggestions_require_explicit_authorization() {
        let mut value = json!({"issues":["participation_paused","model_execution_unresolved"],
            "work":{"answer":{"intervention":{"status":"operator_required","next_action":"resume","next_at":null}},
                "judge":{"intervention":{"status":"operator_required","next_action":"start_controller","next_at":null}}}});
        diagnostics(&mut value, None);
        assert_eq!(
            value["diagnostics"][0]["next_actions"][0]["authorization_required"],
            true
        );
        assert_eq!(
            value["diagnostics"][1]["next_actions"][0]["argv"],
            json!(["agmi", "operations", "list"])
        );
        for kind in ["answer", "judge"] {
            assert!(
                value["work"][kind]["next_actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|action| action["kind"] == "command"
                        && action["authorization_required"] == true)
            );
        }
    }

    #[test]
    fn doctor_repair_is_an_explicit_opt_in_and_preserves_precise_actions() {
        let mut value = json!({"intervention":{"status":"none_required"},
            "repair_requested":false,"repairs":{"eligible":[{"operation_id":7}]},
            "next_actions":[action(None, &["recover", "resolve", "--help"], false)]});
        diagnostics(&mut value, Some(Path::new("/selected/config.toml")));
        let actions = value["next_actions"].as_array().unwrap();
        assert!(actions.iter().any(|step| step["argv"]
            == json!([
                "agmi",
                "--config",
                "/selected/config.toml",
                "doctor",
                "--repair"
            ])
            && step["authorization_required"] == true));
        assert!(
            actions
                .iter()
                .any(|step| step["argv"] == json!(["agmi", "recover", "resolve", "--help"]))
        );
    }

    #[test]
    fn identity_repair_guidance_explains_limits_without_fabricating_a_wait() {
        let mut value = json!({"checked_at":100,"issues":["hosted_identity_legacy_unknown"],
            "intervention":{"status":"undetermined","reason":"hosted_identity_legacy_unknown",
                "next_action":"inspect_local_evidence"},
            "repair_requested":false,"repairs":{"eligible":[{"kind":"identity",
                "classification":"legacy_identity_evidence_normalization"}]}});
        diagnostics(&mut value, None);
        let actions = value["next_actions"].as_array().unwrap();
        assert!(
            actions
                .iter()
                .any(|step| step["argv"] == json!(["agmi", "doctor", "--repair"])
                    && step["authorization_required"] == true)
        );
        assert!(actions.iter().any(|step| {
            step["message"]
                .as_str()
                .is_some_and(|message| message.contains("does not verify identity"))
        }));
        assert!(actions.iter().all(|step| step["kind"] != "wait"));
    }

    #[test]
    fn stale_or_manual_work_never_gets_a_misleading_wait_action() {
        for status in ["undetermined", "operator_required"] {
            let actions = intervention_actions(
                &json!({"status":status,
                "next_action":"inspect_local_evidence","next_at":200}),
                &[],
                None,
                100,
            );
            assert!(
                actions
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|step| step["kind"] != "wait")
            );
        }
    }
    #[test]
    fn argv_rendering_quotes_boundaries_without_new_quoting_rules() {
        assert_eq!(shell_quote("health"), "health");
        assert_eq!(shell_quote("--config"), "--config");
        assert_eq!(
            render_argv(&json!([
                "agmi",
                "--config",
                "/path with space/config.toml",
                "health"
            ])),
            "agmi --config '/path with space/config.toml' health"
        );
        assert_eq!(
            render_argv(&json!(["agmi", "lane", "show", "it's"])),
            "agmi lane show 'it'\\''s'"
        );
    }

    #[test]
    fn disk_gate_suppresses_start_resume_retry_and_unconditional_wait() {
        let mut value = json!({"checked_at":100,
            "issues":["state_disk_space_low"],
            "intervention":{"status":"operator_required","reason":"state_disk_space_low",
                "next_action":"inspect_state_filesystem","next_at":null},
            "work":{
                "answer":{"intervention":{"status":"operator_required","next_action":"resume","next_at":null}},
                "judge":{"intervention":{"status":"automatic_recovery","next_action":"await_reconciliation","next_at":120}},
                "mine":{"intervention":{"status":"operator_required","next_action":"start_controller","next_at":null}}},
            "next_actions":[
                {"kind":"command","argv":["agmi","run"],"authorization_required":true},
                {"kind":"wait","until":120,"authorization_required":false},
                {"kind":"command","argv":["agmi","status"],"authorization_required":false}]});
        diagnostics(&mut value, None);
        for lane in ["answer", "judge", "mine"] {
            let actions = value["work"][lane]["next_actions"].as_array().unwrap();
            assert!(
                actions.iter().all(|step| step["kind"] != "wait"),
                "{lane} keeps no unconditional wait under a disk gate"
            );
            assert!(
                !actions.iter().any(|step| step["argv"]
                    .as_array()
                    .is_some_and(|argv| argv.contains(&json!("run"))
                        || argv.contains(&json!("resume"))
                        || argv.contains(&json!("recover-model")))),
                "{lane} keeps no start/resume/retry under a disk gate"
            );
        }
        let root = value["next_actions"].as_array().unwrap();
        assert!(root.iter().any(|step| {
            step["message"]
                .as_str()
                .is_some_and(|message| message.contains("Preserve the journal"))
        }));
        assert!(root.iter().all(|step| step["kind"] != "wait"));
        assert!(!root.iter().any(|step| {
            step["argv"]
                .as_array()
                .is_some_and(|argv| argv.contains(&json!("run")) || argv.contains(&json!("resume")))
        }));
    }

    #[test]
    fn component_only_reasons_gain_diagnostics_without_changing_health() {
        let mut value = json!({"issues":[],"warnings":[],"operational":{"status":"clear","issues":[]},
            "components":{"controller":{"state":"ok","reasons":["controller_recent"]},
                "answer":{"state":"degraded","reasons":["api_dependency_unavailable"]},
                "judge":{"state":"ok","reasons":["no_eligible_assignments_observed"]},
                "mine":{"state":"disabled","reasons":["capability_off"]}},
            "intervention":{"status":"none_required"},
            "work":{"answer":{"intervention":{"status":"none_required"}},
                "judge":{"intervention":{"status":"none_required"}},
                "mine":{"intervention":{"status":"none_required"}}}});
        let healthy = value["operational"]["status"].clone();
        diagnostics(&mut value, None);
        assert_eq!(value["operational"]["status"], healthy);
        assert!(
            value["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["code"] == "api_dependency_unavailable")
        );
        assert!(
            !value["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["code"] == "controller_recent" || row["code"] == "capability_off")
        );
    }

    #[test]
    fn human_sanitization_replaces_token_commands_with_lane_show() {
        let step = json!({"kind":"command",
            "argv":["agmi","--config","/selected/config.toml","lane","resume","judge",
                "--expected-control","lane-control:secret"],
            "authorization_required":true});
        let sanitized = sanitized_step(&step);
        assert_eq!(
            sanitized["argv"],
            json!([
                "agmi",
                "--config",
                "/selected/config.toml",
                "lane",
                "show",
                "judge"
            ])
        );
        assert_eq!(sanitized["authorization_required"], false);
        assert!(!render_argv(&sanitized["argv"]).contains("lane-control:secret"));
        let plain = json!({"kind":"command",
            "argv":["agmi","--config","/selected/config.toml","lane","show","judge"],
            "authorization_required":false});
        assert_eq!(sanitized_step(&plain), plain);
    }
}
