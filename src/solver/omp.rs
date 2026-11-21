//! Single-use public omp RPC shell. No agent turn, inherited transcript, or provider client.
use super::contract::*;
use super::*;
use crate::config::OmpConfig;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::io::Write;
mod rpc;

const BRIDGE: &str = include_str!("../../adapters/omp.ts");
const COMMAND: &str = "agmi-omp-once-v1";
const READY: &str = "agmi_omp_ready_v1";
const DISPATCH: &str = "agmi_omp_dispatch_v1";
const TERMINAL: &str = "agmi_omp_result_v1";
const BODY_LIMIT: usize = 2 * MAX_INPUT + 16 * 1024;
const STDERR_LIMIT: usize = 256 * 1024;

pub(super) struct Prepared {
    pub args: Vec<String>,
    pub input: Vec<u8>,
}

pub(super) fn check_version(bytes: &[u8]) -> Result<()> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| SolverNotStarted("unsupported_harness_version"))?;
    ensure!(
        matches!(text.trim(), "19.0.1" | "omp/19.0.1" | "omp 19.0.1"),
        SolverNotStarted("unsupported_harness_version")
    );
    Ok(())
}

fn selection(model: &ModelConfig) -> Result<(String, String, String)> {
    let selection = ModelSelection::new(model)?;
    let provider = selection.provider().to_owned();
    let name = selection.model().to_owned();
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&selection)?));
    Ok((provider, name, digest))
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| SolverNotStarted("invalid_solver_setup"))?;
    file.write_all(bytes)
        .map_err(|_| SolverNotStarted("invalid_solver_setup"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))
            .map_err(|_| SolverNotStarted("invalid_solver_setup"))?;
    }
    Ok(())
}

fn remaining_ms(deadline: ExecutionDeadline) -> Result<u64> {
    let remaining = deadline
        .at
        .saturating_duration_since(tokio::time::Instant::now());
    ensure!(
        !remaining.is_zero(),
        NativeFailure("model_deadline_exceeded")
    );
    Ok(u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .max(1))
}

pub(super) fn prepare(
    model: &ModelConfig,
    request: &NativeRequest,
    invocation_id: &str,
    scratch: &Path,
    deadline: ExecutionDeadline,
) -> Result<Prepared> {
    ensure!(
        scratch.is_absolute() && safe_identifier(invocation_id),
        SolverNotStarted("invalid_solver_setup")
    );
    let default_route = OmpConfig::default();
    let route = model.omp.as_ref().unwrap_or(&default_route);
    let (provider, name, selection_digest) = selection(model)?;
    let request_bytes = encode_request(request.request())?;
    let request_digest = format!("{:x}", Sha256::digest(&request_bytes));
    let request_json =
        String::from_utf8(request_bytes).map_err(|_| SolverNotStarted("invalid_solver_setup"))?;
    let home = if route.provider_discovery_cwd.is_none() {
        dirs::home_dir()
    } else {
        None
    };
    let discovery = route
        .provider_discovery_cwd
        .as_deref()
        .or(home.as_deref())
        .context(SolverNotStarted("invalid_solver_setup"))?;
    ensure!(
        discovery.is_absolute(),
        SolverNotStarted("invalid_solver_setup")
    );
    let timeout_ms = remaining_ms(deadline)?;
    let bootstrap = json!({
        "protocol":1, "invocation_id":invocation_id, "request_digest":request_digest,
        "selection_digest":selection_digest, "provider":provider, "model":name,
        "reasoning_effort":model.reasoning, "provider_discovery_cwd":discovery,
        "deadline_unix_ms":deadline.unix_millis()
    });
    let mut body = json!({
        "protocol":1, "invocation_id":invocation_id, "request_digest":request_digest,
        "selection_digest":selection_digest, "provider":provider, "model":name,
        "reasoning_effort":model.reasoning,
        "policy":SECURITY_AND_OUTPUT, "timeout_ms":timeout_ms
    });
    body["request_json"] = Value::String(request_json);
    let input = serde_json::to_vec(&body)?;
    ensure!(
        input.len() <= BODY_LIMIT,
        SolverNotStarted("invalid_solver_setup")
    );
    let bridge = scratch.join("omp.ts");
    let overlay = scratch.join("omp-overlay.json");
    private_file(&bridge, BRIDGE.as_bytes())?;
    private_file(
        &scratch.join("omp-bootstrap.json"),
        &serde_json::to_vec(&bootstrap)?,
    )?;
    private_file(&overlay, br#"{"autoResume":false,"retry":{"enabled":false,"modelFallback":false},"providers":{"cacheWarming":"off"}}"#)?;
    let tmp = scratch.join("tmp");
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory
        .create(&tmp)
        .map_err(|_| SolverNotStarted("invalid_solver_setup"))?;
    let mut args = [
        "--mode",
        "rpc",
        "--no-ui",
        "--no-session",
        "--no-tools",
        "--no-lsp",
        "--no-pty",
        "--no-skills",
        "--no-rules",
        "--no-context-files",
        "--no-prewalk",
        "--no-title",
    ]
    .map(str::to_owned)
    .to_vec();
    args.extend([
        "--model".into(),
        model.model.clone(),
        "--thinking".into(),
        model.reasoning.clone(),
        "--trusted-extension".into(),
        bridge
            .to_str()
            .context(SolverNotStarted("invalid_solver_setup"))?
            .into(),
        "--config".into(),
        overlay
            .to_str()
            .context(SolverNotStarted("invalid_solver_setup"))?
            .into(),
    ]);
    if let Some(profile) = &route.profile {
        args.extend(["--profile".into(), profile.clone()]);
    }
    Ok(Prepared { args, input })
}

pub(super) fn spawn(
    executable: &Path,
    args: &[String],
    cwd: &Path,
    route: &OmpConfig,
) -> Result<OwnedChild> {
    route
        .validate()
        .map_err(|_| SolverNotStarted("invalid_solver_setup"))?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env(
            "HOME",
            dirs::home_dir().context(SolverNotStarted("invalid_solver_setup"))?,
        )
        .env(
            "PATH",
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into()),
        )
        .env("LANG", "C.UTF-8");
    for name in &route.env {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("OMP_PROFILE", route.profile.as_deref().unwrap_or("default"));
    if let Some(directory) = &route.agent_dir {
        command.env("PI_CODING_AGENT_DIR", directory);
    }
    command.env("TMPDIR", cwd.join("tmp"));
    spawn_owned(command)
}

const BINDING_KEYS: [&str; 7] = [
    "protocol",
    "invocation_id",
    "request_digest",
    "selection_digest",
    "provider",
    "model",
    "reasoning_effort",
];

fn binding(value: &Value, expected: &Value) -> Result<()> {
    ensure!(value.is_object(), NativeFailure("native_envelope_invalid"));
    for key in BINDING_KEYS {
        ensure!(
            value.get(key).is_some() && value.get(key) == expected.get(key),
            NativeFailure("native_run_binding_mismatch")
        );
    }
    Ok(())
}

fn entries(data: &Value) -> Result<&[Value]> {
    let entries = data["entries"]
        .as_array()
        .context(NativeFailure("native_envelope_invalid"))?;
    ensure!(entries.len() <= 32, NativeFailure("native_output_limit"));
    let mut ids = std::collections::HashSet::new();
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .filter(|s| safe_identifier(s))
            .context(NativeFailure("native_envelope_invalid"))?;
        ensure!(ids.insert(id), NativeFailure("native_run_binding_mismatch"));
    }
    Ok(entries)
}

fn ready_entry(data: &Value, expected: &Value) -> Result<String> {
    let mut ready = None;
    let mut refusal = None;
    for entry in entries(data)? {
        if entry["type"] == "custom" && entry["customType"] == READY {
            ensure!(
                ready.is_none() && refusal.is_none(),
                NativeFailure("native_run_binding_mismatch")
            );
            binding(&entry["data"], expected)?;
            ready = entry["id"].as_str();
        } else if entry["type"] == "custom" && entry["customType"] == TERMINAL {
            let terminal = &entry["data"];
            binding(terminal, expected)?;
            ensure!(
                ready.is_none() && refusal.is_none(),
                NativeFailure("native_run_binding_mismatch")
            );
            // Only this exact phase can prove no inference request was sent.
            // Inspect the whole snapshot: a ready, dispatch, message, or
            // second result anywhere in it invalidates the refusal proof.
            let reason = terminal_failure(terminal).0;
            ensure!(
                terminal["ok"] == false
                    && terminal["stage"] == "startup"
                    && terminal
                        .as_object()
                        .is_some_and(|data| data.len() == BINDING_KEYS.len() + 3)
                    && matches!(
                        reason,
                        "native_api_unsupported" | "native_failure" | "model_deadline_exceeded"
                    ),
                NativeFailure("native_envelope_invalid")
            );
            refusal = Some(reason);
        } else {
            ensure!(
                entry["type"].is_string()
                    && entry["type"] != "message"
                    && !entry["customType"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("agmi_omp_")),
                NativeFailure("native_envelope_invalid")
            );
        }
    }
    if let Some(reason) = refusal {
        return Err(SolverNotStarted(reason).into());
    }
    ready
        .map(str::to_owned)
        .context(NativeFailure("native_envelope_invalid"))
}

fn terminal_failure(terminal: &Value) -> NativeFailure {
    NativeFailure(match terminal["reason_code"].as_str() {
        Some("native_output_limit") => "native_output_limit",
        Some("native_provenance_mismatch") => "native_provenance_mismatch",
        Some("native_run_binding_mismatch") => "native_run_binding_mismatch",
        Some("model_deadline_exceeded") => "model_deadline_exceeded",
        Some("native_api_unsupported") => "native_api_unsupported",
        Some("native_auth_unavailable") => "native_auth_unavailable",
        Some("native_route_mismatch") => "native_route_mismatch",
        Some("native_process_failed") => "native_process_failed",
        // A failed provider stream is not a failed local process: it leaves
        // inference completion unknown rather than completed-invalid.
        Some("native_stream_failed") => "native_stream_failed",
        Some("native_failure") => "native_failure",
        _ => "native_envelope_invalid",
    })
}

fn terminal_entry<'a>(
    data: &'a Value,
    expected: &Value,
    evidence: &mut NativeReportedEvidence,
) -> Result<&'a Value> {
    let entries = entries(data)?;
    ensure!(
        (1..=2).contains(&entries.len()),
        NativeFailure("native_envelope_invalid")
    );
    if entries.len() == 2 {
        ensure!(
            entries[0]["type"] == "custom" && entries[0]["customType"] == DISPATCH,
            NativeFailure("native_envelope_invalid")
        );
        binding(&entries[0]["data"], expected)?;
    }
    let last = &entries[entries.len() - 1];
    ensure!(
        last["type"] == "custom" && last["customType"] == TERMINAL,
        NativeFailure("native_envelope_invalid")
    );
    binding(&last["data"], expected)?;
    ensure!(
        last["data"].get("stage").is_none(),
        NativeFailure("native_envelope_invalid")
    );
    let terminal = &last["data"];
    let report = |key: &str, source| -> Result<Option<Reported<String>>> {
        match terminal.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if safe_identifier(value) => Ok(Some(Reported {
                value: value.clone(),
                source,
            })),
            _ => Err(NativeFailure("native_envelope_invalid").into()),
        }
    };
    // SDK provider/model name the catalog route. Do not turn a requested
    // model echo into evidence of which model the provider actually served.
    evidence.provider = report("native_provider", EvidenceSource::AdapterContract)?;
    evidence.model = report("wire_model", EvidenceSource::NativeEnvelope)?;
    evidence.winner_model = report("upstream_model", EvidenceSource::NativeEnvelope)?;
    evidence.winner_provider = report("upstream_provider", EvidenceSource::NativeEnvelope)?;
    evidence.run_id = terminal["invocation_id"].as_str().map(|value| Reported {
        value: value.to_owned(),
        source: EvidenceSource::AdapterContract,
    });
    if entries.len() == 2 {
        evidence.reasoning_effort = terminal["reasoning_effort"].as_str().map(|value| Reported {
            value: value.to_owned(),
            source: EvidenceSource::AdapterContract,
        });
    }
    if terminal["ok"] == false {
        return Err(terminal_failure(terminal).into());
    }
    ensure!(
        entries.len() == 2 && terminal["ok"] == true && terminal.get("reason_code").is_none(),
        NativeFailure("native_envelope_invalid")
    );
    ensure!(
        terminal["native_provider"] == expected["provider"]
            && terminal["native_model"] == expected["model"],
        NativeFailure("native_provenance_mismatch")
    );
    ensure!(
        matches!(terminal.get("output_phase"), Some(Value::Null))
            || terminal["output_phase"] == "final_answer",
        NativeFailure("native_envelope_invalid")
    );
    ensure!(
        ["wire_model", "upstream_model", "upstream_provider"]
            .iter()
            .all(|&key| terminal.get(key).is_some()),
        NativeFailure("native_envelope_invalid")
    );
    let output = terminal["output"]
        .as_str()
        .context(NativeFailure("native_envelope_invalid"))?;
    ensure!(
        output.len() <= MAX_OUTPUT,
        NativeFailure("native_output_limit")
    );
    Ok(terminal)
}

async fn drain_stderr(mut reader: impl AsyncRead + Unpin) -> Result<()> {
    let mut buffer = [0u8; 8192];
    let mut total = 0;
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| NativeFailure("native_pipe_failed"))?;
        if count == 0 {
            return Ok(());
        }
        total += count;
        ensure!(total <= STDERR_LIMIT, NativeFailure("native_output_limit"));
    }
}

pub(super) struct ReceivedTerminal {
    entries: Value,
    binding: Value,
    startup: bool,
}

impl ReceivedTerminal {
    fn new(entries: Value, mut binding: Value, startup: bool) -> Self {
        if let Some(body) = binding.as_object_mut() {
            body.retain(|key, _| BINDING_KEYS.contains(&key.as_str()));
        }
        Self {
            entries,
            binding,
            startup,
        }
    }

    pub(super) fn verify(
        mut self,
        model: String,
        reported: &mut NativeReportedEvidence,
    ) -> Result<(String, String, String, String)> {
        if self.startup {
            ready_entry(&self.entries, &self.binding)?;
            return Err(NativeFailure("native_envelope_invalid").into());
        }
        terminal_entry(&self.entries, &self.binding, reported)?;
        // Move the checked native value without re-encoding.
        let terminal = self
            .entries
            .get_mut("entries")
            .and_then(Value::as_array_mut)
            .and_then(|entries| entries.last_mut())
            .and_then(|entry| entry.get_mut("data"))
            .context(NativeFailure("native_envelope_invalid"))?;
        let take = |value: &mut Value, key| match value[key].take() {
            Value::String(text) => Ok(text),
            _ => Err(NativeFailure("native_envelope_invalid")),
        };
        Ok((
            take(terminal, "provider")?,
            model,
            take(terminal, "invocation_id")?,
            take(terminal, "output")?,
        ))
    }
}

pub(super) async fn collect(
    owner: &mut OwnedChild,
    input: Vec<u8>,
    deadline: ExecutionDeadline,
    facts: &mut NativeAttemptCompletion,
) -> Result<ReceivedTerminal> {
    use base64::Engine as _;
    let operation = async {
        ensure!(
            input.len() <= BODY_LIMIT,
            NativeFailure("native_envelope_invalid")
        );
        let mut body: Value =
            serde_json::from_slice(&input).map_err(|_| NativeFailure("native_envelope_invalid"))?;
        drop(input);
        let mut writer = owner
            .child
            .stdin
            .take()
            .context(NativeFailure("native_pipe_failed"))?;
        let stdout = owner
            .child
            .stdout
            .take()
            .context(NativeFailure("native_pipe_failed"))?;
        let stderr = owner
            .child
            .stderr
            .take()
            .context(NativeFailure("native_pipe_failed"))?;
        let conversation = async {
            let mut reader = rpc::Reader::new(stdout);
            let ready = reader.next().await?;
            reader.negotiate(&ready)?;
            let negotiation = rpc::exchange(
                &mut writer,
                &mut reader,
                &json!({"id":"negotiate","type":"negotiate_protocol","protocolVersion":2}),
            )
            .await?;
            ensure!(
                negotiation["protocolVersion"] == 2,
                NativeFailure("native_envelope_invalid")
            );
            reader.enable_v2();
            let commands = rpc::exchange(
                &mut writer,
                &mut reader,
                &json!({"id":"commands","type":"get_available_commands"}),
            )
            .await?;
            let commands = commands["commands"]
                .as_array()
                .context(NativeFailure("native_envelope_invalid"))?;
            ensure!(
                commands.len() <= 256
                    && commands.iter().filter(|c| c["name"] == COMMAND).count() == 1,
                NativeFailure("native_envelope_invalid")
            );
            let initial = rpc::exchange(
                &mut writer,
                &mut reader,
                &json!({"id":"ready-entries","type":"get_entries"}),
            )
            .await?;
            if initial["entries"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|entry| entry["customType"] == TERMINAL))
            {
                // Do not dispatch after a potential startup refusal. Only the
                // controller validates the bound terminal and classifies it.
                return Ok(ReceivedTerminal::new(initial, body, true));
            }
            let cursor = ready_entry(&initial, &body)?;
            body["timeout_ms"] = json!(remaining_ms(deadline)?);
            let bytes =
                serde_json::to_vec(&body).map_err(|_| NativeFailure("native_envelope_invalid"))?;
            ensure!(
                bytes.len() <= BODY_LIMIT,
                NativeFailure("native_output_limit")
            );
            let mut message =
                String::with_capacity(COMMAND.len() + 2 + bytes.len().div_ceil(3) * 4);
            message.push('/');
            message.push_str(COMMAND);
            message.push(' ');
            URL_SAFE_NO_PAD.encode_string(&bytes, &mut message);
            let receipt = rpc::exchange(
                &mut writer,
                &mut reader,
                &json!({"id":"once","type":"prompt","message":message}),
            )
            .await?;
            ensure!(receipt.is_null(), NativeFailure("native_envelope_invalid"));
            rpc::local_completion(&mut reader, "once").await?;
            let final_entries = rpc::exchange(
                &mut writer,
                &mut reader,
                &json!({"id":"terminal-entries","type":"get_entries","since":cursor}),
            )
            .await?;
            Ok(ReceivedTerminal::new(final_entries, body, false))
        };
        tokio::pin!(conversation);
        let drain = drain_stderr(stderr);
        tokio::pin!(drain);
        tokio::select! {
            result = &mut conversation => result,
            drained = &mut drain => { drained?; conversation.await }
        }
    };
    let outcome = match tokio::time::timeout_at(deadline.at, operation).await {
        Ok(outcome) if tokio::time::Instant::now() < deadline.at => outcome,
        _ => Err(NativeFailure("model_deadline_exceeded").into()),
    };
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX);
    // Stop the owned group without delaying terminal delivery for process reaping.
    let stopped = owner.stop_and_observe();
    facts.cancellation = CancellationEvidence {
        requested_at: Some(requested_at),
        local_process_stop: if stopped {
            LocalProcessStop::Observed
        } else {
            LocalProcessStop::Unknown
        },
        remote_run_stop: RemoteRunStop::Unknown,
    };
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Value {
        json!({"protocol":1,"invocation_id":"invocation","request_digest":"request","selection_digest":"selection","provider":"provider","model":"model/name","reasoning_effort":"high"})
    }
    fn entry(id: &str, kind: &str, data: Value) -> Value {
        json!({"id":id,"type":"custom","customType":kind,"data":data})
    }
    #[test]
    fn requires_unique_bound_readiness() {
        let e = expected();
        let ready = entry("ready", READY, e.clone());
        assert_eq!(
            ready_entry(&json!({"entries":[ready.clone()]}), &e).unwrap(),
            "ready"
        );
        assert!(
            ready_entry(
                &json!({"entries":[ready.clone(),entry("duplicate",READY,e.clone())]}),
                &e
            )
            .is_err()
        );
        let mut wrong = e.clone();
        wrong["request_digest"] = json!("wrong");
        let error = ready_entry(&json!({"entries":[entry("ready",READY,wrong)]}), &e).unwrap_err();
        assert_eq!(failure_code(&error), "native_run_binding_mismatch");
    }
    #[test]
    fn only_a_unique_startup_refusal_without_contradictions_proves_no_dispatch() {
        let e = expected();
        let mut terminal = e.clone();
        terminal["ok"] = json!(false);
        terminal["reason_code"] = json!("native_api_unsupported");
        terminal["stage"] = json!("startup");
        let refusal = entry("refused", TERMINAL, terminal.clone());
        let error = ready_entry(&json!({"entries":[refusal.clone()]}), &e).unwrap_err();
        assert_eq!(failure_code(&error), "native_api_unsupported");
        assert!(!execution_may_have_started(&error));

        let mut wrong = terminal.clone();
        wrong["request_digest"] = json!("wrong");
        let mut not_startup = terminal.clone();
        not_startup.as_object_mut().unwrap().remove("stage");
        let mut claimed_output = terminal;
        claimed_output["output"] = json!("not a refusal");
        for entries in [
            json!([refusal.clone(), entry("dispatch", DISPATCH, e.clone())]),
            json!([entry("ready", READY, e.clone()), refusal.clone()]),
            json!([refusal.clone(), entry("ready", READY, e.clone())]),
            json!([refusal,{"id":"message","type":"message"}]),
            json!([entry("wrong", TERMINAL, wrong)]),
            json!([entry("without-stage", TERMINAL, not_startup)]),
            json!([entry("with-output", TERMINAL, claimed_output)]),
        ] {
            let error = ready_entry(&json!({"entries":entries}), &e).unwrap_err();
            assert!(execution_may_have_started(&error));
        }
    }

    #[test]
    fn requires_phase_and_explicit_unknown_served_identity() {
        let expected = expected();
        let mut terminal = expected.clone();
        terminal["ok"] = json!(true);
        terminal["native_provider"] = json!("provider");
        terminal["native_model"] = json!("model/name");
        terminal["output"] = json!("artifact");
        terminal["output_phase"] = Value::Null;
        terminal["wire_model"] = Value::Null;
        terminal["upstream_model"] = Value::Null;
        terminal["upstream_provider"] = Value::Null;
        let response = |terminal| {
            json!({"entries":[
                entry("dispatch",DISPATCH,expected.clone()),
                entry("terminal",TERMINAL,terminal)
            ]})
        };
        let mut evidence = NativeReportedEvidence::default();
        terminal_entry(&response(terminal.clone()), &expected, &mut evidence).unwrap();
        assert_eq!(
            evidence.provider.unwrap().source,
            EvidenceSource::AdapterContract
        );
        assert!(evidence.model.is_none() && evidence.winner_model.is_none());

        let mut no_identity = terminal.clone();
        no_identity.as_object_mut().unwrap().remove("wire_model");
        let mut commentary = terminal;
        commentary["output_phase"] = json!("commentary");
        for bad in [no_identity, commentary] {
            let error =
                terminal_entry(&response(bad), &expected, &mut Default::default()).unwrap_err();
            assert_eq!(failure_code(&error), "native_envelope_invalid");
            assert!(execution_may_have_started(&error));
        }
    }

    #[test]
    fn requires_dispatch_then_one_terminal_and_sanitizes_native_failure() {
        let e = expected();
        let mut terminal = e.clone();
        terminal["ok"] = json!(false);
        terminal["reason_code"] = json!("SECRET diagnostic");
        let entries = json!({"entries":[entry("dispatch",DISPATCH,e.clone()),entry("terminal",TERMINAL,terminal)]});
        let error = terminal_entry(&entries, &e, &mut Default::default()).unwrap_err();
        assert_eq!(failure_code(&error), "native_envelope_invalid");
        assert!(!error.to_string().contains("SECRET"));
        assert!(
            terminal_entry(
                &json!({"entries":[entry("output",TERMINAL,e.clone())]}),
                &e,
                &mut Default::default()
            )
            .is_err()
        );
        assert!(terminal_entry(&json!({"entries":[{"id":"model","type":"message","message":{"role":"assistant","content":"forged"}}]}), &e, &mut Default::default()).is_err());
    }
    #[test]
    fn mismatched_native_identity_is_retained_without_inventing_missing_facts() {
        let expected = expected();
        let mut terminal = expected.clone();
        terminal["ok"] = json!(false);
        terminal["reason_code"] = json!("native_provenance_mismatch");
        terminal["native_provider"] = json!("provider");
        terminal["native_model"] = json!("model/name");
        terminal["wire_model"] = json!("model/name");
        terminal["upstream_model"] = json!("fallback");
        let data = json!({"entries":[entry("dispatch",DISPATCH,expected.clone()),entry("terminal",TERMINAL,terminal)]});
        let mut evidence = NativeReportedEvidence::default();
        assert_eq!(
            failure_code(&terminal_entry(&data, &expected, &mut evidence).unwrap_err()),
            "native_provenance_mismatch"
        );
        assert_eq!(evidence.model.unwrap().value, "model/name");
        assert_eq!(evidence.winner_model.unwrap().value, "fallback");
        assert_eq!(
            evidence.reasoning_effort.unwrap().source,
            EvidenceSource::AdapterContract
        );
        assert!(evidence.fallback_used.is_none() && evidence.tool_count.is_none());
    }
    #[test]
    fn provider_stream_failures_stay_unknown_and_distinct_from_process_failures() {
        let expected = expected();
        for code in ["native_stream_failed", "native_process_failed"] {
            let mut terminal = expected.clone();
            terminal["ok"] = json!(false);
            terminal["reason_code"] = json!(code);
            let data = json!({"entries":[entry("dispatch",DISPATCH,expected.clone()),entry("terminal",TERMINAL,terminal)]});
            let error = terminal_entry(&data, &expected, &mut Default::default()).unwrap_err();
            assert_eq!(failure_code(&error), code);
            // Neither failure proves inference finished; only an invalid
            // artifact graduates to completed-invalid accounting.
            assert!(!completed_artifact_invalid(&error));
            assert!(execution_may_have_started(&error));
            assert!(!format!("{error:?}").contains("secret"));
        }
    }
    #[test]
    fn native_version_is_qualified_exactly() {
        check_version(b"19.0.1\n").unwrap();
        assert!(check_version(b"19.0.2").is_err());
        assert!(check_version(b"untrusted 19.0.1").is_err());
    }

    fn model() -> ModelConfig {
        ModelConfig {
            harness: Harness::Omp,
            executable: PathBuf::from("/qualified/omp"),
            model: "provider/model/name".into(),
            reasoning: "high".into(),
            hermes_api_url: crate::config::default_hermes_api_url(),
            omp: Some(OmpConfig {
                provider_discovery_cwd: Some(PathBuf::from("/authorized")),
                ..Default::default()
            }),
            guidance_file: None,
            core_guidance_file: None,
            core_guidance: "".into(),
            guidance: "".into(),
        }
    }
    #[test]
    fn prepares_bound_private_assets_without_task_argv_and_rejects_replacement() {
        let scratch = Scratch::new().unwrap();
        let request = SolverRequest {
            id: "request".into(),
            kind: LaneId::Answer,
            epoch: 1,
            words: vec!["/command @file".into()],
            min_chars: 1,
            max_chars: 100,
            assignment: None,
            candidate: None,
            history: vec![],
            guidance: "subordinate".into(),
            core_guidance: "operator".into(),
            candidate_author: None,
            author_history: None,
        };
        let native = NativeRequest::Answer(AnswerTask::new(request.clone()).unwrap());
        let deadline = ExecutionDeadline {
            at: tokio::time::Instant::now() + Duration::from_secs(30),
            unix_seconds: now_for_test() + 30,
        };
        let model = model();
        let prepared = prepare(&model, &native, "invocation", &scratch.0, deadline).unwrap();
        assert!(
            !prepared
                .args
                .iter()
                .any(|arg| arg.contains("subordinate") || arg.contains("/command @file"))
        );
        let body: Value = serde_json::from_slice(&prepared.input).unwrap();
        let bootstrap: Value =
            serde_json::from_slice(&std::fs::read(scratch.0.join("omp-bootstrap.json")).unwrap())
                .unwrap();
        binding(&bootstrap, &body).unwrap();
        assert!(bootstrap.get("request_json").is_none());
        assert_eq!(
            body["request_json"],
            String::from_utf8(encode_request(&request).unwrap()).unwrap()
        );
        assert_eq!(
            body["request_digest"],
            format!("{:x}", Sha256::digest(encode_request(&request).unwrap()))
        );
        assert_eq!(body["model"], "model/name");
        assert_eq!(bootstrap["provider_discovery_cwd"], "/authorized");
        assert!(prepare(&model, &native, "other", &scratch.0, deadline).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(scratch.0.join("omp-bootstrap.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
            assert_eq!(
                std::fs::metadata(scratch.0.join("tmp"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
    fn now_for_test() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
    #[test]
    fn selection_and_result_require_exact_route_effort_and_host_invocation() {
        let model = model();
        let (provider, name, digest) = selection(&model).unwrap();
        let binding = json!({"protocol":1,"invocation_id":"invocation","selection_digest":digest,
            "request_digest":"sample","provider":provider,"model":name,"reasoning_effort":"high"});
        let mut value = binding.clone();
        value.as_object_mut().unwrap().extend(
            json!({"ok":true,"native_provider":"provider","native_model":"model/name","output":"artifact",
                "wire_model":null,"upstream_model":null,"upstream_provider":null,"output_phase":null})
                .as_object().unwrap().clone(),
        );
        let check = |terminal| {
            ReceivedTerminal::new(
                json!({"entries":[
                    {"id":"dispatch","type":"custom","customType":DISPATCH,"data":binding},
                    {"id":"terminal","type":"custom","customType":TERMINAL,"data":terminal},
                ]}),
                binding.clone(),
                false,
            )
            .verify(model.model.clone(), &mut Default::default())
        };
        assert_eq!(
            check(value.clone()).unwrap(),
            (
                "provider".into(),
                "provider/model/name".into(),
                "invocation".into(),
                "artifact".into()
            )
        );
        let mut wrong = value.clone();
        wrong["native_model"] = json!("fallback");
        assert_eq!(
            failure_code(&check(wrong).unwrap_err()),
            "native_provenance_mismatch"
        );
        value["invocation_id"] = json!("other");
        assert_eq!(
            failure_code(&check(value).unwrap_err()),
            "native_run_binding_mismatch"
        );
        let mut changed = model.clone();
        changed.omp.as_mut().unwrap().profile = Some("another".into());
        assert_ne!(selection(&changed).unwrap().2, selection(&model).unwrap().2);
    }
}
