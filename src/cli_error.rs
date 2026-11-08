//! Sanitized CLI presentation. Never render untyped error chains or parser values.
use anyhow::Error;
use clap::{
    CommandFactory,
    error::{ContextKind, ContextValue, ErrorKind},
};
use serde_json::{Value, json};
use std::path::Path;

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
    if error.is::<agmi::store::RoutingProfileError>() {
        return json!({
            "code":"api_routing_pending",
            "message":"API routing cannot change while unresolved or reusable work remains. Restore network.api from status.network_routing.bound_api; preserve the journal.",
            "details":{},
            "next_actions":[action(config, &["status"], false), action(config, &["operations", "list"], false)]
        });
    }
    if let Some((code, details)) = agmi::registration::error_details(error) {
        return json!({
            "code":code,
            "message":"Registration did not complete. Inspect local evidence before any further action; an uncertain remote outcome must not be retried.",
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
        "admin_routing_runtime_active" => "Stop the controller before changing API routes; preserve its journal and pause state.",
        _ => "Operation failed; inspect local prerequisites before retrying.",
    });
    let command: &[&str] = match code {
        "config_missing" => &["init", "--help"],
        "config_invalid" => &["config", "check"],
        "registration_configuration_invalid" => &["identity", "create", "--help"],
        "admin_routing_runtime_active" => &["status"],
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
    if let Some(error) = error.downcast_ref::<agmi::lifecycle::InstallerError>() {
        value["code"] = json!("installer_failed");
        value["message"] =
            json!("Installer did not complete; inspect installation before retrying.");
        value["details"] = error.evidence.clone();
        value["next_actions"] = json!([action(None, &["service", "status"], false)]);
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
    let diagnostics: Vec<_> = codes.iter().map(|code| {
        let (command, authorization): (&[&str], bool) = match *code {
            "config_missing" | "config_location_unavailable" => (&["init", "--help"], false),
            "config_invalid" | "no_active_capabilities" | "reload_blocked" => (&["config", "check"], false),
            "participation_paused" => (&["resume"], true),
            "controller_stopped" | "controller_unobserved" | "controller_stale" => (&["status"], false),
            "pending_outcome_uncertain" | "dispatch_outcome_uncertain" | "pending_work_overdue" |
            "model_work_overdue" | "model_execution_unresolved" | "participation_risk_admitted" |
            "admission_blocked" => (&["operations", "list"], false),
            "challenge_unobserved" | "challenge_observation_stale" | "current_epoch_unanswered" |
            "answer_evidence_unavailable" | "hosted_identity_unverified" | "hosted_identity_unobserved" => (&["reads"], false),
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
            "api_routing_mismatch" => Some("Restore the bound network.api profile shown by status. Routing changes require a stopped controller and no unresolved or reusable work; never erase evidence to bypass this boundary."),
            "model_execution_unresolved" => Some("Inspect retained model evidence while stopped before explicitly authorizing recover-model; unresolved network requests must not be reset."),
            "no_active_capabilities" => Some("Review model authentication, routes, guidance and desired capability modes before explicitly changing configuration."),
            _ => None,
        };
        if let Some(message) = instruction {
            actions.push(json!({"kind":"instruction","message":message,
                "authorization_required":*code == "identity_mismatch"}));
        }
        json!({"code":code,"next_actions":actions})
    }).collect();
    data["diagnostics"] = json!(diagnostics);
    let checked_at = data["checked_at"].as_i64().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    });
    if let Some(work) = data["work"].as_object_mut() {
        for detail in work.values_mut() {
            let command: &[&str] = match detail["next_action"].as_str() {
                Some("resume") => &["resume"],
                Some("repair_config" | "enable_capability") => &["config", "show"],
                Some("await_reconciliation") => &["operations", "list"],
                Some("start_controller") => &["run"],
                _ => &["reads"],
            };
            let authorization = matches!(command, ["resume"] | ["run"]);
            let mut actions = Vec::new();
            if let Some(deadline) = detail["next_at"].as_i64().filter(|at| *at > checked_at) {
                actions.push(json!({"kind":"wait","until":deadline,"clock":"unix_seconds",
                    "authorization_required":false,"evidence":"reported_local_deadline_not_a_success_guarantee"}));
            }
            actions.push(action(config, command, authorization));
            detail["next_actions"] = json!(actions);
        }
    }
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
        "health" => {
            println!(
                "Health: {} (local evidence only)",
                if data["healthy"] == true {
                    "healthy"
                } else {
                    "attention required"
                }
            );
            println!(
                "Operational: {}; unresolved effects: {} (risk and admission reported separately)",
                data["operational"]["status"].as_str().unwrap_or("unknown"),
                data["risk"]["unresolved_effects"]
            );
            for diagnostic in data["diagnostics"].as_array().into_iter().flatten() {
                println!("- {}", diagnostic["code"].as_str().unwrap_or("unknown"));
                print_actions(&diagnostic["next_actions"]);
            }
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
                "Local status: initialized={}, paused={} (not a health verdict)",
                data["initialized"], data["paused"]
            );
            for (kind, work) in data["work"].as_object().into_iter().flatten() {
                println!(
                    "- {kind}: {} ({})",
                    work["phase"].as_str().unwrap_or("unknown"),
                    work["reason"].as_str().unwrap_or("unknown")
                );
                print_actions(&work["next_actions"]);
            }
            println!(
                "Unresolved effects: {}; risk admissions: {}",
                data["participation"]["unresolved_count"], data["participation"]["risk_admissions"]
            );
        }
        "install" | "update" | "service" => {
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
    print_actions(&data["next_actions"]);
}

fn print_actions(actions: &Value) {
    for (index, step) in actions.as_array().into_iter().flatten().enumerate() {
        let description = match step["kind"].as_str() {
            Some("command") => step["argv"].to_string(),
            Some("wait") => format!(
                "Wait until Unix timestamp {} (reported deadline)",
                step["until"]
            ),
            _ => step["message"]
                .as_str()
                .unwrap_or("Inspect local evidence")
                .to_owned(),
        };
        println!(
            "{}. {}{}",
            index + 1,
            description,
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
    use super::*;

    #[test]
    fn diagnostic_actions_use_only_supplied_future_deadlines_and_keep_risk() {
        let mut value = json!({"checked_at":100,"issues":["pending_outcome_uncertain"],
            "risk":{"unresolved_effects":4},"operational":{"status":"clear"},
            "work":{"answer":{"next_action":"await_reconciliation","next_at":120},
                "judge":{"next_action":"await_assignments","next_at":null},
                "mine":{"next_action":"observe_challenge","next_at":99}}});
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
            "work":{"answer":{"next_action":"resume","next_at":null},
                "judge":{"next_action":"start_controller","next_at":null}}});
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
            assert_eq!(
                value["work"][kind]["next_actions"][0]["authorization_required"],
                true
            );
        }
    }
}
