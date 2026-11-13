//! Validated model data and bounded, sourced completion facts; no admission authority.
use super::*;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AnswerTask(Arc<SolverRequest>);
#[derive(Clone, Debug)]
pub struct GradeTask(Arc<SolverRequest>);
macro_rules! task {
    ($name:ident, $kind:ident) => {
        impl $name {
            pub fn new(request: SolverRequest) -> Result<Self> {
                ensure!(request.kind == LaneId::$kind, "task role mismatch");
                ensure!(
                    safe_identifier(&request.id),
                    SolverNotStarted("invalid_solver_setup")
                );
                validate_request(&request)
                    .map_err(|_| anyhow::Error::new(SolverNotStarted("invalid_solver_setup")))?;
                ensure!(
                    !request.core_guidance.trim().is_empty(),
                    SolverNotStarted("core_guidance_missing")
                );
                encode_request(&request)
                    .map_err(|_| anyhow::Error::new(SolverNotStarted("invalid_solver_setup")))?;
                Ok(Self(Arc::new(request)))
            }
            pub fn request(&self) -> &SolverRequest {
                &self.0
            }
        }
    };
}
task!(AnswerTask, Answer);
task!(GradeTask, Judge);
#[derive(Clone, Debug)]
pub enum NativeRequest {
    Answer(AnswerTask),
    Grade(GradeTask),
}
impl NativeRequest {
    pub fn request(&self) -> &SolverRequest {
        match self {
            Self::Answer(t) => t.request(),
            Self::Grade(t) => t.request(),
        }
    }
    pub fn digest(&self) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(encode_request(self.request())?)
        ))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSelection {
    harness: Harness,
    provider: String,
    model: String,
    reasoning_effort: String,
    native_route: PathBuf,
    hermes_api_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    omp: Option<crate::config::OmpConfig>,
}
impl ModelSelection {
    pub fn new(model: &ModelConfig) -> Result<Self> {
        let (provider, name) = match model.harness {
            Harness::Hermes => ("openai-codex", model.model.as_str()),
            Harness::Openclaw | Harness::Omp => model
                .model
                .split_once('/')
                .context("model route missing provider")?,
        };
        ensure!(
            model.executable.as_os_str().len() <= 4096
                && !model.executable.as_os_str().is_empty()
                && (model.harness == Harness::Omp
                    || (model.hermes_api_url.len() <= 2048
                        && !model.hermes_api_url.chars().any(char::is_control))),
            "invalid native route"
        );
        ensure!(
            safe_identifier(provider) && safe_identifier(name) && safe_identifier(&model.reasoning),
            "invalid model selection"
        );
        ensure!(
            model.harness != Harness::Openclaw || (provider == "openai" && !name.contains('/')),
            "unsupported provider"
        );
        ensure!(
            model.harness == Harness::Omp || model.omp.is_none(),
            "omp settings require the omp harness"
        );
        if let Some(omp) = &model.omp {
            omp.validate()?;
            ensure!(
                omp.agent_dir
                    .iter()
                    .chain(omp.provider_discovery_cwd.iter())
                    .all(|path| path.is_absolute()),
                "omp native paths must be resolved"
            );
        }
        Ok(Self {
            harness: model.harness,
            provider: provider.into(),
            model: name.into(),
            reasoning_effort: model.reasoning.clone(),
            native_route: model.executable.clone(),
            hermes_api_url: if model.harness == Harness::Omp {
                String::new()
            } else {
                model.hermes_api_url.clone()
            },
            omp: model.omp.clone(),
        })
    }
    pub fn harness(&self) -> Harness {
        self.harness
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn reasoning_effort(&self) -> &str {
        &self.reasoning_effort
    }
    pub fn native_route(&self) -> &Path {
        &self.native_route
    }
    pub(super) fn config(&self) -> ModelConfig {
        ModelConfig {
            harness: self.harness,
            executable: self.native_route.clone(),
            model: if matches!(self.harness, Harness::Openclaw | Harness::Omp) {
                format!("{}/{}", self.provider, self.model)
            } else {
                self.model.clone()
            },
            reasoning: self.reasoning_effort.clone(),
            hermes_api_url: self.hermes_api_url.clone(),
            omp: self.omp.clone(),
            guidance_file: None,
            core_guidance_file: None,
            guidance: Default::default(),
            core_guidance: Default::default(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct AnswerArtifact(SolverResult);
#[derive(Clone, Debug)]
pub struct GradeArtifact(SolverResult);
macro_rules! artifact {
    ($name:ident) => {
        impl $name {
            pub fn result(&self) -> &SolverResult {
                &self.0
            }
            pub fn into_result(self) -> SolverResult {
                self.0
            }
        }
    };
}
artifact!(AnswerArtifact);
artifact!(GradeArtifact);
#[derive(Clone, Debug)]
pub enum NativeArtifact {
    Answer(AnswerArtifact),
    Grade(GradeArtifact),
}
impl NativeArtifact {
    pub fn result(&self) -> &SolverResult {
        match self {
            Self::Answer(a) => a.result(),
            Self::Grade(a) => a.result(),
        }
    }
    pub fn into_result(self) -> SolverResult {
        match self {
            Self::Answer(a) => a.into_result(),
            Self::Grade(a) => a.into_result(),
        }
    }
    pub(super) fn validated(request: &NativeRequest, result: SolverResult) -> Self {
        match request {
            NativeRequest::Answer(_) => Self::Answer(AnswerArtifact(result)),
            NativeRequest::Grade(_) => Self::Grade(GradeArtifact(result)),
        }
    }
}
macro_rules! codes {
    ($name:ident { $($variant:ident),* $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all="snake_case")]
        pub enum $name { $($variant),* }
    };
}
codes!(NativePhase {
    Preflight,
    Inference,
    ArtifactValidation,
    Recovery
});
codes!(NativeExecution {
    NotStarted,
    Completed,
    Unknown
});
codes!(NativeOutcome {
    Captured,
    Invalid,
    NotStarted,
    Unknown
});
codes!(EvidenceSource {
    NativeEnvelope,
    AdapterContract,
    LocalProcessObservation
});
codes!(LocalProcessStop {
    Observed,
    Unknown,
    NotRequested
});
codes!(RemoteRunStop {
    Acknowledged,
    Unknown,
    NotRequested
});
codes!(NativeReasonCode {
    Captured,
    InvalidSolverSetup,
    CoreGuidanceMissing,
    ExecutableUnavailable,
    UnsupportedHarnessVersion,
    ModelDeadlineExceeded,
    NativeEnvelopeInvalid,
    NativeProvenanceMismatch,
    NativeRunBindingMismatch,
    NativeArtifactInvalid,
    NativeProcessFailed,
    NativeProcessCancelled,
    NativePipeFailed,
    NativeApiUnsupported,
    NativeAuthUnavailable,
    NativeRouteMismatch,
    NativeFailure,
    Interrupted,
    PendingRetired,
    HermesTimeout,
    HermesCancelled,
    HermesIncomplete,
    HermesException,
    OpenclawTimeout,
    OpenclawAborted,
    OpenclawErrorPayload,
    OpenclawException,
    OpenclawExecutionFailed,
    ArtifactJsonInvalid,
    ArtifactVersionMismatch,
    ArtifactRequestIdMismatch,
    ArtifactRequestDigestMismatch,
    ArtifactKindMismatch,
    NativeExecutionEvidenceMismatch,
    NativeOutputLimit
});
impl NativeReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeExecutionEvidenceMismatch => "native_execution_evidence_mismatch",
            Self::NativeOutputLimit => "native_output_limit",
            Self::CoreGuidanceMissing => "core_guidance_missing",
            Self::HermesTimeout => "hermes_timeout",
            Self::HermesCancelled => "hermes_cancelled",
            Self::HermesIncomplete => "hermes_incomplete",
            Self::HermesException => "hermes_exception",
            Self::OpenclawTimeout => "openclaw_timeout",
            Self::OpenclawAborted => "openclaw_aborted",
            Self::OpenclawErrorPayload => "openclaw_error_payload",
            Self::OpenclawException => "openclaw_exception",
            Self::OpenclawExecutionFailed => "openclaw_execution_failed",
            Self::ArtifactJsonInvalid => "artifact_json_invalid",
            Self::ArtifactVersionMismatch => "artifact_version_mismatch",
            Self::ArtifactRequestIdMismatch => "artifact_request_id_mismatch",
            Self::ArtifactRequestDigestMismatch => "artifact_request_digest_mismatch",
            Self::ArtifactKindMismatch => "artifact_kind_mismatch",
            Self::PendingRetired => "pending_retired",
            Self::Captured => "captured",
            Self::InvalidSolverSetup => "invalid_solver_setup",
            Self::ExecutableUnavailable => "executable_unavailable",
            Self::UnsupportedHarnessVersion => "unsupported_harness_version",
            Self::ModelDeadlineExceeded => "model_deadline_exceeded",
            Self::NativeEnvelopeInvalid => "native_envelope_invalid",
            Self::NativeProvenanceMismatch => "native_provenance_mismatch",
            Self::NativeRunBindingMismatch => "native_run_binding_mismatch",
            Self::NativeArtifactInvalid => "native_artifact_invalid",
            Self::NativeProcessFailed => "native_process_failed",
            Self::NativeProcessCancelled => "native_process_cancelled",
            Self::NativePipeFailed => "native_pipe_failed",
            Self::NativeApiUnsupported => "native_api_unsupported",
            Self::NativeAuthUnavailable => "native_auth_unavailable",
            Self::NativeRouteMismatch => "native_route_mismatch",
            Self::NativeFailure => "native_failure",
            Self::Interrupted => "interrupted",
        }
    }
    pub(super) fn from_error(error: &anyhow::Error) -> Self {
        match failure_code(error) {
            "native_execution_evidence_mismatch" => Self::NativeExecutionEvidenceMismatch,
            "native_output_limit" => Self::NativeOutputLimit,
            "core_guidance_missing" => Self::CoreGuidanceMissing,
            "invalid_solver_setup" => Self::InvalidSolverSetup,
            "hermes_timeout" => Self::HermesTimeout,
            "hermes_cancelled" => Self::HermesCancelled,
            "hermes_incomplete" => Self::HermesIncomplete,
            "hermes_exception" => Self::HermesException,
            "openclaw_timeout" => Self::OpenclawTimeout,
            "openclaw_aborted" => Self::OpenclawAborted,
            "openclaw_error_payload" => Self::OpenclawErrorPayload,
            "openclaw_exception" => Self::OpenclawException,
            "openclaw_execution_failed" => Self::OpenclawExecutionFailed,
            "artifact_json_invalid" => Self::ArtifactJsonInvalid,
            "artifact_version_mismatch" => Self::ArtifactVersionMismatch,
            "artifact_request_id_mismatch" => Self::ArtifactRequestIdMismatch,
            "artifact_request_digest_mismatch" => Self::ArtifactRequestDigestMismatch,
            "artifact_kind_mismatch" => Self::ArtifactKindMismatch,
            "executable_unavailable" => Self::ExecutableUnavailable,
            "unsupported_harness_version" => Self::UnsupportedHarnessVersion,
            "model_deadline_exceeded" => Self::ModelDeadlineExceeded,
            "native_envelope_invalid" => Self::NativeEnvelopeInvalid,
            "native_provenance_mismatch" => Self::NativeProvenanceMismatch,
            "native_run_binding_mismatch" => Self::NativeRunBindingMismatch,
            "native_artifact_invalid" | "protocol_output_invalid" => Self::NativeArtifactInvalid,
            "native_process_cancelled" => Self::NativeProcessCancelled,
            "native_api_unsupported" => Self::NativeApiUnsupported,
            "native_auth_unavailable" => Self::NativeAuthUnavailable,
            "native_route_mismatch" => Self::NativeRouteMismatch,
            "native_pipe_failed" => Self::NativePipeFailed,
            "native_process_failed" => Self::NativeProcessFailed,
            _ => Self::NativeFailure,
        }
    }
}
impl std::fmt::Display for NativeReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for NativeReasonCode {}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reported<T> {
    pub value: T,
    pub source: EvidenceSource,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeReportedEvidence {
    pub provider: Option<Reported<String>>,
    pub model: Option<Reported<String>>,
    pub reasoning_effort: Option<Reported<String>>,
    pub run_id: Option<Reported<String>>,
    pub fallback_used: Option<Reported<bool>>,
    pub winner_provider: Option<Reported<String>>,
    pub winner_model: Option<Reported<String>>,
    pub tool_count: Option<Reported<u64>>,
    pub bootstrap_file_count: Option<Reported<u64>>,
    pub prompt_channel: Option<Reported<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationEvidence {
    pub requested_at: Option<i64>,
    pub local_process_stop: LocalProcessStop,
    pub remote_run_stop: RemoteRunStop,
}
impl Default for CancellationEvidence {
    fn default() -> Self {
        Self {
            requested_at: None,
            local_process_stop: LocalProcessStop::NotRequested,
            remote_run_stop: RemoteRunStop::NotRequested,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAttemptCompletion {
    pub phase: NativePhase,
    pub execution: NativeExecution,
    pub outcome: NativeOutcome,
    pub reason_code: NativeReasonCode,
    pub collected_at: Option<i64>,
    pub preflight_started_at: Option<i64>,
    pub inference_spawned_at: Option<i64>,
    pub reported: NativeReportedEvidence,
    pub cancellation: CancellationEvidence,
}
#[derive(Debug)]
pub struct NativeCompletion {
    pub result: std::result::Result<NativeArtifact, NativeReasonCode>,
    pub evidence: NativeAttemptCompletion,
}
pub(super) fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
pub(super) fn reported(value: &Value) -> NativeReportedEvidence {
    let text = |key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| safe_identifier(v))
            .map(|v| Reported {
                value: v.to_owned(),
                source: EvidenceSource::NativeEnvelope,
            })
    };
    let count = |key| {
        value
            .get(key)
            .and_then(Value::as_u64)
            .filter(|v| *v <= 1_000_000)
            .map(|v| Reported {
                value: v,
                source: EvidenceSource::NativeEnvelope,
            })
    };
    NativeReportedEvidence {
        provider: text("provider"),
        model: text("model"),
        reasoning_effort: text("reasoning_effort").or_else(|| text("reasoning")),
        run_id: text("run_id").or_else(|| text("runId")),
        fallback_used: value
            .get("fallback_used")
            .or_else(|| value.get("fallbackUsed"))
            .and_then(Value::as_bool)
            .map(|v| Reported {
                value: v,
                source: EvidenceSource::NativeEnvelope,
            }),
        winner_provider: text("winner_provider").or_else(|| text("winnerProvider")),
        winner_model: text("winner_model").or_else(|| text("winnerModel")),
        tool_count: count("tool_count").or_else(|| count("toolCount")),
        bootstrap_file_count: count("bootstrap_file_count").or_else(|| count("bootstrapFileCount")),
        prompt_channel: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_selection_identity_survives_launch_recipe_round_trip() {
        let recorded = r#"{"harness":"openclaw","provider":"openai","model":"fixture","reasoning_effort":"high","native_route":"/native/fixture","hermes_api_url":"https://example.invalid"}"#;
        let selection: ModelSelection = serde_json::from_str(recorded).unwrap();
        let reconstructed = ModelSelection::new(&selection.config()).unwrap();
        assert_eq!(serde_json::to_string(&reconstructed).unwrap(), recorded);
    }
}
