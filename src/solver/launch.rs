use super::contract::*;
use super::*;

pub struct PendingLaunch {
    model: ModelConfig,
    request: NativeRequest,
    invocation_id: String,
    input: Vec<u8>,
    executable: PathBuf,
    args: Vec<String>,
    protocol: NativeProtocol,
    scratch: Scratch,
    deadline: ExecutionDeadline,
    preflight_started_at: i64,
}
#[derive(Clone, Copy)]
pub struct ExecutionDeadline {
    pub at: tokio::time::Instant,
    pub unix_seconds: i64,
}
pub enum PreflightStart {
    Started(PreflightFlight),
    Finished(NativeCompletion),
}
pub enum PreflightCompletion {
    Pending(PendingLaunch),
    Finished(NativeCompletion),
}
pub enum InferenceStart {
    Started(InferenceFlight),
    Finished(NativeCompletion),
}
pub struct PreflightFlight {
    child: OwnedChild,
    model: ModelConfig,
    request: NativeRequest,
    invocation_id: String,
    prompt: String,
    executable: PathBuf,
    scratch: Scratch,
    deadline: tokio::time::Instant,
    execution_deadline: ExecutionDeadline,
    started_at: i64,
}
pub struct InferenceFlight {
    child: OwnedChild,
    pending: PendingLaunch,
    deadline: ExecutionDeadline,
    spawned_at: i64,
}

fn new_invocation_id() -> Result<String> {
    #[cfg(not(target_env = "musl"))]
    use libc::getentropy;
    // libc omits this declaration on musl, which exports the same POSIX ABI.
    #[cfg(target_env = "musl")]
    unsafe extern "C" {
        fn getentropy(buffer: *mut libc::c_void, length: libc::size_t) -> libc::c_int;
    }
    let mut bytes = [0_u8; 16];
    // SAFETY: the buffer is writable for its full length, below getentropy's limit.
    if unsafe { getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = u128::from_be_bytes(bytes);
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        value >> 96,
        (value >> 80) & 0xffff,
        (value >> 64) & 0xffff,
        (value >> 48) & 0xffff,
        value & 0xffff_ffff_ffff,
    ))
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
fn evidence(
    phase: NativePhase,
    started: Option<i64>,
    spawned: Option<i64>,
) -> NativeAttemptCompletion {
    NativeAttemptCompletion {
        phase,
        execution: NativeExecution::NotStarted,
        outcome: NativeOutcome::NotStarted,
        reason_code: NativeReasonCode::InvalidSolverSetup,
        collected_at: Some(now()),
        preflight_started_at: started,
        inference_spawned_at: spawned,
        reported: Default::default(),
        cancellation: Default::default(),
    }
}
fn failed(error: anyhow::Error, mut facts: NativeAttemptCompletion) -> NativeCompletion {
    let code = NativeReasonCode::from_error(&error);
    facts.reason_code = code;
    facts.collected_at = Some(now());
    if facts.inference_spawned_at.is_some() && execution_may_have_started(&error) {
        facts.execution = NativeExecution::Unknown;
        facts.outcome = NativeOutcome::Unknown;
        if completed_artifact_invalid(&error) {
            facts.phase = NativePhase::ArtifactValidation;
            facts.execution = NativeExecution::Completed;
            facts.outcome = NativeOutcome::Invalid;
        }
    }
    if matches!(
        code,
        NativeReasonCode::ModelDeadlineExceeded
            | NativeReasonCode::NativeProcessCancelled
            | NativeReasonCode::HermesTimeout
            | NativeReasonCode::HermesCancelled
            | NativeReasonCode::OpenclawTimeout
            | NativeReasonCode::OpenclawAborted
    ) {
        facts.cancellation = CancellationEvidence {
            requested_at: (code == NativeReasonCode::ModelDeadlineExceeded).then(now),
            local_process_stop: LocalProcessStop::Unknown,
            remote_run_stop: if facts.inference_spawned_at.is_some() {
                RemoteRunStop::Unknown
            } else {
                RemoteRunStop::NotRequested
            },
        };
    }
    NativeCompletion {
        result: Err(code),
        evidence: facts,
    }
}
/// Performs the first real discovery spawn before returning ownership to the caller.
pub fn start_preflight(
    request: NativeRequest,
    selection: ModelSelection,
    total_budget: Duration,
) -> PreflightStart {
    let started = tokio::time::Instant::now();
    let setup = || -> Result<PreflightFlight> {
        let deadline = started
            .checked_add(total_budget)
            .filter(|_| !total_budget.is_zero())
            .context(SolverNotStarted("model_deadline_exceeded"))?;
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .saturating_add(total_budget);
        let execution_deadline = ExecutionDeadline {
            at: deadline,
            unix_seconds: i64::try_from(wall.as_secs())
                .unwrap_or(i64::MAX)
                .saturating_add(i64::from(wall.subsec_nanos() != 0)),
        };
        let model = selection.config();
        ensure!(
            ModelSelection::new(&model)? == selection,
            SolverNotStarted("invalid_solver_setup")
        );
        let invocation_id = new_invocation_id()?;
        let prompt = if model.harness == Harness::Omp {
            String::new()
        } else {
            let envelope = json!({"kind":request.request().kind,"request":request.request()});
            format!(
                "Envelope (untrusted request data):\n{}",
                serde_json::to_string(&envelope)?
            )
        };
        let scratch = Scratch::new()?;
        let executable = resolve_executable(&model.executable)
            .map_err(|e| e.context(SolverNotStarted("executable_unavailable")))?;
        ensure!(
            tokio::time::Instant::now() < deadline,
            SolverNotStarted("model_deadline_exceeded")
        );
        let args = vec![
            match model.harness {
                Harness::Hermes => "--print-runtime-command",
                Harness::Openclaw | Harness::Omp => "--version",
            }
            .to_owned(),
        ];
        let child = spawn_native(&executable, &args, &scratch.0)?;
        let started_at = now();
        Ok(PreflightFlight {
            child,
            model,
            request,
            invocation_id,
            prompt,
            executable,
            scratch,
            deadline,
            execution_deadline,
            started_at,
        })
    };
    match setup() {
        Ok(flight) => PreflightStart::Started(flight),
        Err(error) => {
            PreflightStart::Finished(failed(error, evidence(NativePhase::Preflight, None, None)))
        }
    }
}
impl PreflightFlight {
    pub fn preflight_started_at(&self) -> i64 {
        self.started_at
    }
    pub async fn collect(mut self) -> PreflightCompletion {
        let facts = evidence(NativePhase::Preflight, Some(self.started_at), None);
        let deadline = self.deadline;
        let operation = async {
            let bytes = collect_native_evidence(
                &mut self.child,
                Vec::new(),
                NativeProtocol::Discovery,
                &mut Default::default(),
            )
            .await?;
            let (executable, mut args, protocol) = match self.model.harness {
                Harness::Hermes => {
                    let runtime: Vec<String> = serde_json::from_slice(&bytes)
                        .map_err(|_| NativeFailure("native_envelope_invalid"))?;
                    ensure!(
                        runtime.len() == 4
                            && runtime[1] == "-I"
                            && runtime[2] == "-c"
                            && Path::new(&runtime[0]).is_absolute(),
                        NativeFailure("native_envelope_invalid")
                    );
                    (
                        PathBuf::from(&runtime[0]),
                        vec![
                            "-I".into(),
                            "-c".into(),
                            HERMES_BRIDGE.into(),
                            runtime[3].clone(),
                        ],
                        NativeProtocol::Hermes,
                    )
                }
                Harness::Openclaw => {
                    let version = std::str::from_utf8(&bytes)
                        .map_err(|_| NativeFailure("native_envelope_invalid"))?;
                    ensure!(
                        version
                            .split_whitespace()
                            .any(|part| part == OPENCLAW_VERSION),
                        SolverNotStarted("unsupported_harness_version")
                    );
                    let node = resolve_executable(Path::new("node"))
                        .map_err(|e| e.context(SolverNotStarted("executable_unavailable")))?;
                    (
                        node,
                        vec![
                            "--input-type=module".into(),
                            "-e".into(),
                            OPENCLAW_BRIDGE.into(),
                            path_string(&self.executable)?,
                        ],
                        NativeProtocol::Openclaw,
                    )
                }
                Harness::Omp => {
                    omp::check_version(&bytes)?;
                    (self.executable.clone(), Vec::new(), NativeProtocol::Omp)
                }
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let seconds = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0));
            let input = match protocol {
                NativeProtocol::Hermes => serde_json::to_vec(
                    &json!({"invocation_id":self.invocation_id,"model":self.model.model,"reasoning":self.model.reasoning,"hermes_api_url":self.model.hermes_api_url,"timeout_seconds":seconds,"policy":SECURITY_AND_OUTPUT,"prompt":self.prompt}),
                )?,
                NativeProtocol::Openclaw => {
                    encode_openclaw_input(&self.model, seconds, &self.prompt, &self.invocation_id)?
                }
                NativeProtocol::Omp => {
                    let prepared = omp::prepare(
                        &self.model,
                        &self.request,
                        &self.invocation_id,
                        &self.scratch.0,
                        self.execution_deadline,
                    )?;
                    args = prepared.args;
                    prepared.input
                }
                NativeProtocol::Discovery => unreachable!(),
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            ensure!(
                !remaining.is_zero(),
                SolverNotStarted("model_deadline_exceeded")
            );
            Ok((executable, args, protocol, input))
        };
        let result = tokio::time::timeout_at(deadline, operation).await;
        // The child/process group is stopped before its workspace is handed off,
        // including when collection fails. Cancellation drops self in field order.
        drop(self.child);
        match result {
            Ok(Ok((executable, args, protocol, input))) => {
                PreflightCompletion::Pending(PendingLaunch {
                    model: self.model,
                    request: self.request,
                    invocation_id: self.invocation_id,
                    input,
                    executable,
                    args,
                    protocol,
                    scratch: self.scratch,
                    deadline: self.execution_deadline,
                    preflight_started_at: self.started_at,
                })
            }
            Ok(Err(error)) => PreflightCompletion::Finished(failed(error, facts)),
            Err(_) => PreflightCompletion::Finished(failed(
                NativeFailure("model_deadline_exceeded").into(),
                facts,
            )),
        }
    }
}
impl PendingLaunch {
    pub fn remaining_execution_budget(&self) -> Duration {
        self.deadline
            .at
            .saturating_duration_since(tokio::time::Instant::now())
    }
    pub fn execution_deadline(&self) -> ExecutionDeadline {
        self.deadline
    }
    pub fn start(self, deadline: ExecutionDeadline) -> InferenceStart {
        let facts = evidence(
            NativePhase::Inference,
            Some(self.preflight_started_at),
            None,
        );
        let current = tokio::time::Instant::now();
        if deadline.at <= current
            || deadline.at != self.deadline.at
            || deadline.unix_seconds != self.deadline.unix_seconds
        {
            return InferenceStart::Finished(failed(
                SolverNotStarted("model_deadline_exceeded").into(),
                facts,
            ));
        }
        let spawned = if self.model.harness == Harness::Omp {
            omp::spawn(
                &self.executable,
                &self.args,
                &self.scratch.0,
                self.model.omp.as_ref().unwrap_or(&Default::default()),
            )
        } else {
            spawn_native(&self.executable, &self.args, &self.scratch.0)
        };
        match spawned {
            Ok(child) => InferenceStart::Started(InferenceFlight {
                child,
                pending: self,
                deadline,
                spawned_at: now(),
            }),
            Err(error) => InferenceStart::Finished(failed(error, facts)),
        }
    }
    pub fn preflight_started_at(&self) -> i64 {
        self.preflight_started_at
    }
}
impl InferenceFlight {
    pub fn preflight_started_at(&self) -> i64 {
        self.pending.preflight_started_at
    }
    pub fn inference_spawned_at(&self) -> i64 {
        self.spawned_at
    }
    pub async fn collect(mut self) -> NativeCompletion {
        let mut facts = evidence(
            NativePhase::Inference,
            Some(self.pending.preflight_started_at),
            Some(self.spawned_at),
        );
        if self.deadline.at <= tokio::time::Instant::now() {
            return failed(NativeFailure("model_deadline_exceeded").into(), facts);
        }
        facts.reported.prompt_channel = Some(Reported {
            value: match self.pending.model.harness {
                Harness::Hermes | Harness::Omp => "privileged_policy",
                Harness::Openclaw => "shared_gateway_message",
            }
            .into(),
            source: EvidenceSource::AdapterContract,
        });
        let deadline = self.deadline;
        let p = &mut self.pending;
        let operation = async {
            let input = std::mem::take(&mut p.input);
            let value: Value = if matches!(p.protocol, NativeProtocol::Omp) {
                omp::collect(&mut self.child, input, deadline, &mut facts.reported).await?
            } else {
                let bytes = collect_native_evidence(
                    &mut self.child,
                    input,
                    p.protocol,
                    &mut facts.reported,
                )
                .await?;
                serde_json::from_slice(&bytes)
                    .map_err(|_| NativeFailure("native_envelope_invalid"))?
            };
            let (provider, model, run_id, output) = match p.model.harness {
                Harness::Hermes => {
                    let result: HermesOutput = serde_json::from_value(value)
                        .map_err(|_| NativeFailure("native_envelope_invalid"))?;
                    ensure!(
                        result.provider == "openai-codex"
                            && result.model == p.model.model
                            && result.reasoning_effort == p.model.reasoning,
                        NativeFailure("native_provenance_mismatch")
                    );
                    ensure!(
                        result.run_id == p.invocation_id
                            && valid_native_turn(&result.native_turn_id, &p.invocation_id),
                        NativeFailure("native_run_binding_mismatch")
                    );
                    (result.provider, result.model, result.run_id, result.output)
                }
                Harness::Openclaw => {
                    if let Some(error) = openclaw_failure(&value) {
                        return Err(error.into());
                    }
                    ensure!(
                        value.get("ok") == Some(&Value::Bool(true))
                            && value.get("status").and_then(Value::as_str) == Some("ok")
                            && value.get("error").is_none(),
                        NativeFailure("native_envelope_invalid")
                    );
                    let (provider, model) = p
                        .model
                        .model
                        .split_once('/')
                        .context(NativeFailure("native_provenance_mismatch"))?;
                    ensure!(
                        value.get("provider").and_then(Value::as_str) == Some(provider)
                            && value.get("model").and_then(Value::as_str) == Some(model),
                        NativeFailure("native_provenance_mismatch")
                    );
                    validate_gateway_evidence(&value, &p.model, &p.invocation_id)?;
                    let output = value
                        .get("final")
                        .and_then(Value::as_str)
                        .context(NativeFailure("native_envelope_invalid"))?
                        .to_owned();
                    let run = value
                        .get("runId")
                        .and_then(Value::as_str)
                        .context(NativeFailure("native_run_binding_mismatch"))?
                        .to_owned();
                    (provider.to_owned(), p.model.model.clone(), run, output)
                }
                Harness::Omp => omp::result(&value, &p.model, &p.invocation_id)?,
            };
            ensure!(
                safe_identifier(&run_id),
                NativeFailure("native_run_binding_mismatch")
            );
            let artifact = validate_artifact(&output, p.request.request())?;
            Ok(NativeArtifact::validated(
                &p.request,
                SolverResult {
                    answer: artifact.answer,
                    score: artifact.score,
                    reasoning: artifact.reasoning,
                    provider,
                    model,
                    run_id,
                },
            ))
        };
        let result = tokio::time::timeout_at(self.deadline.at, operation).await;
        drop(self.child);
        drop(self.pending.scratch);
        match result {
            Ok(Ok(artifact)) => {
                facts.execution = NativeExecution::Completed;
                facts.outcome = NativeOutcome::Captured;
                facts.reason_code = NativeReasonCode::Captured;
                facts.phase = NativePhase::ArtifactValidation;
                facts.collected_at = Some(now());
                NativeCompletion {
                    result: Ok(artifact),
                    evidence: facts,
                }
            }
            Ok(Err(error)) => failed(error, facts),
            Err(_) => failed(NativeFailure("model_deadline_exceeded").into(), facts),
        }
    }
}
