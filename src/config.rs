use crate::endpoints::{ApiEndpoints, network_defaults};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub(crate) fn default_hermes_api_url() -> String {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Defaults {
        hermes_api_url: String,
    }
    static DEFAULTS: std::sync::LazyLock<Defaults> = std::sync::LazyLock::new(|| {
        toml::from_str(include_str!("../defaults/model.toml"))
            .expect("valid bundled model defaults")
    });
    DEFAULTS.hermes_api_url.clone()
}

pub(crate) const MAX_GUIDANCE_BYTES: usize = 64 * 1024;

/// Only source-defined selectors and messages may cross the CLI error boundary.
/// Parser errors, file paths and configuration values are deliberately excluded.
#[derive(Debug, Serialize)]
pub struct ConfigDiagnostic {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<WorkKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    layer: Option<&'static str>,
    #[serde(skip)]
    message: &'static str,
}

impl ConfigDiagnostic {
    fn new(reason: &'static str, message: &'static str) -> Self {
        Self {
            reason,
            field: None,
            kind: None,
            layer: None,
            message,
        }
    }

    fn model(kind: WorkKind, field: &'static str, message: &'static str) -> Self {
        Self {
            kind: Some(kind),
            ..Self::field(field, message)
        }
    }

    fn field(field: &'static str, message: &'static str) -> Self {
        Self {
            field: Some(field),
            ..Self::new("field_invalid", message)
        }
    }

    fn guidance(
        reason: &'static str,
        kind: WorkKind,
        layer: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            kind: Some(kind),
            layer: Some(layer),
            ..Self::new(reason, message)
        }
    }

    pub fn is_missing(&self) -> bool {
        self.reason == "file_missing"
    }

    pub fn guidance_selector(&self) -> Option<(WorkKind, &'static str)> {
        self.kind.zip(self.layer)
    }
}

impl std::fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for ConfigDiagnostic {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Active,
    ReadOnly,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    Answer,
    Judge,
    Mine,
}
impl WorkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Judge => "judge",
            Self::Mine => "mine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Harness {
    Hermes,
    Openclaw,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub harness: Harness,
    pub executable: PathBuf,
    pub model: String,
    pub reasoning: String,
    #[serde(default = "default_hermes_api_url")]
    pub hermes_api_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_guidance_file: Option<PathBuf>,
    #[serde(skip)]
    pub(crate) core_guidance: Arc<str>,
    #[serde(skip)]
    pub(crate) guidance: Arc<str>,
}
impl std::fmt::Debug for ModelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelConfig")
            .field("harness", &self.harness)
            .field("executable", &self.executable)
            .field("model", &self.model)
            .field("reasoning", &self.reasoning)
            .field("guidance_file", &self.guidance_file)
            .field("core_guidance_file", &self.core_guidance_file)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub base_url: String,
    pub chain: String,
    pub address: String,
    pub credential_file: PathBuf,
    pub trusted_origins: Vec<String>,
    pub api: ApiEndpoints,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        let defaults = network_defaults();
        Self {
            base_url: defaults.base_url.clone(),
            chain: defaults.chain.clone(),
            address: String::new(),
            credential_file: PathBuf::new(),
            trusted_origins: defaults.trusted_origins.clone(),
            api: defaults.api.clone(),
        }
    }
}
impl NetworkConfig {
    pub fn origin(&self) -> Result<reqwest::Url> {
        validate_origin_with_trust(&self.base_url, &self.trusted_origins)
    }
    /// A reusable network-only profile, or the network table from full configuration.
    pub fn read_profile(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|_| anyhow::anyhow!("cannot read network configuration"))?;
        let mut text = String::new();
        file.take(65537)
            .read_to_string(&mut text)
            .map_err(|_| anyhow::anyhow!("cannot read network configuration"))?;
        ensure!(text.len() <= 65536, "network configuration exceeds 64 KiB");
        let value: toml::Value =
            toml::from_str(&text).map_err(|_| anyhow::anyhow!("invalid network configuration"))?;
        let network: Self = value
            .get("network")
            .cloned()
            .unwrap_or(value)
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid network configuration"))?;
        network.origin()?;
        network.api.validate()?;
        ensure!(safe_segment(&network.chain, 64), "invalid network chain");
        Ok(network)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub answer: Mode,
    pub judge: Mode,
    pub mine: Mode,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolverConfig {
    pub answer: ModelConfig,
    pub judge: ModelConfig,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    pub http_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_http_seconds: Option<u64>,
    pub model_seconds: u64,
    pub shutdown_seconds: u64,
}
impl Timeouts {
    pub fn effective_read_http_seconds(&self) -> u64 {
        self.read_http_seconds.unwrap_or(self.http_seconds)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub poll_seconds: u64,
    pub mine_seconds: u64,
    #[serde(default)]
    pub mine_each_epoch: bool,
    pub retry_seconds: u64,
    #[serde(default = "default_backoff_max_seconds")]
    pub backoff_max_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_retry_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_backoff_max_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignments_retry_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignments_backoff_max_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_job_polling: Option<QueuedJobPolling>,
    #[serde(default = "default_jitter_seconds")]
    pub jitter_seconds: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedJobPolling {
    pub initial_seconds: u64,
    pub max_seconds: u64,
}
fn default_backoff_max_seconds() -> u64 {
    900
}
fn default_jitter_seconds() -> u64 {
    30
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Preparation {
    /// One answer and one judge task may run locally; remote cancellation is not guaranteed.
    pub answer_while_blocked: bool,
    pub retry_uncertain: bool,
    pub max_attempts_per_work: u32,
}
impl Default for Preparation {
    fn default() -> Self {
        Self {
            answer_while_blocked: true,
            retry_uncertain: false,
            max_attempts_per_work: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipationMode {
    #[default]
    Strict,
    ParticipationFirst,
    Manual,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalAnswerCapacity {
    #[default]
    Bounded,
    /// Retain unlimited historical uncertainty without charging active capacity.
    AcceptedLinked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Participation {
    pub mode: ParticipationMode,
    pub uncertainty_grace_seconds: u64,
    pub max_unresolved_operations: u32,
    /// Additional bounded capacity for directly linked, still-unknown answers.
    pub max_historical_unknown_answers: u32,
    pub historical_unknown_answer_capacity: HistoricalAnswerCapacity,
    pub answer_reserved_slots: u32,
    pub allow_answer: bool,
    pub allow_mine: bool,
    pub allow_judge: bool,
    pub retry_uncertain_answers: bool,
    pub uncertain_answer_retry_seconds: u64,
    pub max_answer_attempts_per_epoch: u32,
}
impl Default for Participation {
    fn default() -> Self {
        Self {
            mode: ParticipationMode::Strict,
            uncertainty_grace_seconds: 300,
            max_unresolved_operations: 4,
            max_historical_unknown_answers: 0,
            historical_unknown_answer_capacity: HistoricalAnswerCapacity::Bounded,
            answer_reserved_slots: 0,
            allow_answer: true,
            allow_mine: true,
            allow_judge: false,
            retry_uncertain_answers: false,
            uncertain_answer_retry_seconds: 600,
            max_answer_attempts_per_epoch: 2,
        }
    }
}
impl Participation {
    pub(crate) fn unresolved_limit(&self, kind: WorkKind) -> u32 {
        if kind == WorkKind::Answer {
            self.max_unresolved_operations
        } else {
            self.max_unresolved_operations
                .saturating_sub(self.answer_reserved_slots)
        }
    }

    pub(crate) fn allows(&self, kind: WorkKind) -> bool {
        match kind {
            WorkKind::Answer => self.allow_answer,
            WorkKind::Judge => self.allow_judge,
            WorkKind::Mine => self.allow_mine,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub network: NetworkConfig,
    pub state_dir: PathBuf,
    pub capabilities: Capabilities,
    pub solver: SolverConfig,
    pub timeouts: Timeouts,
    pub schedule: Schedule,
    pub preparation: Preparation,
    pub participation: Participation,
    /// Assignment transaction IDs that must never start new judging work.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub excluded_judging_assignments: Vec<String>,
    #[serde(skip)]
    pub(crate) guidance_loaded: bool,
}
impl Default for Config {
    fn default() -> Self {
        let model = ModelConfig {
            harness: Harness::Hermes,
            executable: PathBuf::from("hermes"),
            model: "gpt-6.1-sol".into(),
            reasoning: "high".into(),
            hermes_api_url: default_hermes_api_url(),
            guidance_file: None,
            core_guidance_file: None,
            core_guidance: Arc::from(""),
            guidance: Arc::from(""),
        };
        Self {
            guidance_loaded: true,
            preparation: Preparation::default(),
            participation: Participation::default(),
            excluded_judging_assignments: Vec::new(),
            network: NetworkConfig::default(),
            state_dir: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("agmi"),
            capabilities: Capabilities {
                answer: Mode::ReadOnly,
                judge: Mode::ReadOnly,
                mine: Mode::ReadOnly,
            },
            solver: SolverConfig {
                answer: model.clone(),
                judge: model,
            },
            timeouts: Timeouts {
                http_seconds: 30,
                read_http_seconds: None,
                model_seconds: 300,
                shutdown_seconds: 30,
            },
            schedule: Schedule {
                poll_seconds: 120,
                mine_seconds: 86400,
                mine_each_epoch: false,
                retry_seconds: 180,
                backoff_max_seconds: default_backoff_max_seconds(),
                challenge_retry_seconds: None,
                challenge_backoff_max_seconds: None,
                assignments_retry_seconds: None,
                assignments_backoff_max_seconds: None,
                queued_job_polling: None,
                jitter_seconds: default_jitter_seconds(),
            },
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_config(path, true)
    }

    /// Local controls must not depend on optional model-input files being usable.
    pub fn load_metadata(path: &Path) -> Result<Self> {
        Self::load_config(path, false)
    }

    fn load_config(path: &Path, load_guidance: bool) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|error| {
            ConfigDiagnostic::new(
                if error.kind() == std::io::ErrorKind::NotFound {
                    "file_missing"
                } else {
                    "file_unreadable"
                },
                "Cannot open configuration; inspect the selected file and its access permissions.",
            )
        })?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigDiagnostic::new("file_unreadable", "Cannot read configuration."))?;
        Self::parse_bytes(path, &bytes, load_guidance)
    }

    pub(crate) fn parse_bytes(path: &Path, bytes: &[u8], load_guidance: bool) -> Result<Self> {
        ensure!(
            bytes.len() <= 65536,
            ConfigDiagnostic::new("file_too_large", "Configuration exceeds 64 KiB.")
        );
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ConfigDiagnostic::new("file_not_utf8", "Configuration must be UTF-8."))?;
        // Never expose parser diagnostics: even unknown field names may contain secrets.
        let mut config: Self = toml::from_str(text).map_err(|_| {
            ConfigDiagnostic::new(
                "parse_invalid",
                "Invalid configuration syntax, field names, types or enum values.",
            )
        })?;
        config.validate_fields(load_guidance)?;
        for id in &mut config.excluded_judging_assignments {
            id.make_ascii_lowercase();
        }
        config.excluded_judging_assignments.sort();
        config.excluded_judging_assignments.dedup();
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| {
                    ConfigDiagnostic::new(
                        "location_unavailable",
                        "Cannot resolve the configuration directory.",
                    )
                })?
                .join(path)
        };
        let root = absolute.parent().ok_or_else(|| {
            ConfigDiagnostic::new(
                "location_unavailable",
                "Configuration has no parent directory.",
            )
        })?;
        config.state_dir = resolve_path(root, &config.state_dir);
        if !config.network.credential_file.as_os_str().is_empty() {
            config.network.credential_file = resolve_path(root, &config.network.credential_file);
        }
        for model in [&mut config.solver.answer, &mut config.solver.judge] {
            // Bare entrypoints intentionally use PATH; explicit relative paths are config-relative.
            if model.executable.components().count() > 1 {
                model.executable = resolve_path(root, &model.executable);
            }
            for path in [&mut model.guidance_file, &mut model.core_guidance_file]
                .into_iter()
                .flatten()
            {
                *path = resolve_path(root, path);
            }
        }
        config.guidance_loaded = [&config.solver.answer, &config.solver.judge]
            .iter()
            .all(|model| model.guidance_file.is_none() && model.core_guidance_file.is_none());
        if load_guidance {
            for (kind, model) in [
                (WorkKind::Answer, &mut config.solver.answer),
                (WorkKind::Judge, &mut config.solver.judge),
            ] {
                if let Some(path) = &model.guidance_file {
                    model.guidance = read_guidance(path, kind, "user")?;
                }
                if let Some(path) = &model.core_guidance_file {
                    model.core_guidance = read_guidance(path, kind, "core")?;
                    ensure!(
                        !model.core_guidance.trim().is_empty(),
                        ConfigDiagnostic::guidance(
                            "guidance_empty",
                            kind,
                            "core",
                            "Core guidance must not be empty."
                        )
                    );
                }
            }
            config.validate_core_guidance()?;
            config.guidance_loaded = true;
        }
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_fields(true)
    }

    fn validate_fields(&self, check_guidance_paths: bool) -> Result<()> {
        for (field, limit) in [
            (
                "participation.max_unresolved_operations",
                self.participation.max_unresolved_operations,
            ),
            (
                "participation.max_answer_attempts_per_epoch",
                self.participation.max_answer_attempts_per_epoch,
            ),
        ] {
            ensure!(
                limit > 0,
                ConfigDiagnostic::field(field, "Participation limits must be positive.")
            );
        }
        ensure!(
            self.participation.answer_reserved_slots < self.participation.max_unresolved_operations,
            ConfigDiagnostic::field(
                "participation.answer_reserved_slots",
                "Reserved slots must be below max_unresolved_operations."
            )
        );
        ensure!(
            (1..=8).contains(&self.preparation.max_attempts_per_work),
            ConfigDiagnostic::field(
                "preparation.max_attempts_per_work",
                "Preparation attempts must be between 1 and 8."
            )
        );
        ensure!(
            self.excluded_judging_assignments
                .iter()
                .all(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())),
            ConfigDiagnostic::field(
                "excluded_judging_assignments",
                "Excluded assignments must be 64-character hexadecimal transaction IDs."
            )
        );
        self.network.origin().map_err(|_| ConfigDiagnostic::field("network.base_url", "Inspect base_url and trusted_origins: use explicitly trusted HTTPS or loopback HTTP origins without paths, credentials, query or fragment."))?;
        self.network.api.validate().map_err(|_| {
            ConfigDiagnostic::field(
                "network.api",
                "Invalid API endpoint paths; inspect the endpoint schema.",
            )
        })?;
        ensure!(
            safe_segment(&self.network.chain, 64),
            ConfigDiagnostic::field("network.chain", "Invalid network chain.")
        );
        ensure!(
            self.network.address.is_empty() || valid_address(&self.network.address),
            ConfigDiagnostic::field("network.address", "Invalid account address.")
        );
        ensure!(
            !self.state_dir.as_os_str().is_empty(),
            ConfigDiagnostic::field("state_dir", "State directory is empty.")
        );
        for (field, path) in [
            ("state_dir", &self.state_dir),
            ("network.credential_file", &self.network.credential_file),
            ("solver.answer.executable", &self.solver.answer.executable),
            ("solver.judge.executable", &self.solver.judge.executable),
        ] {
            ensure!(
                !path
                    .as_os_str()
                    .to_string_lossy()
                    .chars()
                    .any(char::is_control),
                ConfigDiagnostic::field(field, "Path contains control characters.")
            );
            ensure!(
                !path.starts_with("~"),
                ConfigDiagnostic::field(
                    field,
                    "Use an absolute or config-relative path, not a tilde."
                )
            );
        }
        for (kind, model) in [
            (WorkKind::Answer, &self.solver.answer),
            (WorkKind::Judge, &self.solver.judge),
        ] {
            let api_url = reqwest::Url::parse(&model.hermes_api_url).map_err(|_| {
                ConfigDiagnostic::model(kind, "hermes_api_url", "Invalid Hermes API URL.")
            })?;
            ensure!(
                model.hermes_api_url.len() <= 2048
                    && !model
                        .hermes_api_url
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
                    && !model.hermes_api_url.contains('\\')
                    && api_url.scheme() == "https"
                    && api_url.username().is_empty()
                    && api_url.password().is_none()
                    && api_url.query().is_none()
                    && api_url.fragment().is_none(),
                ConfigDiagnostic::model(
                    kind,
                    "hermes_api_url",
                    "Hermes API URL requires HTTPS without credentials, query or fragment."
                )
            );
            if check_guidance_paths {
                for (layer, path) in [
                    ("user", &model.guidance_file),
                    ("core", &model.core_guidance_file),
                ] {
                    let Some(path) = path else { continue };
                    ensure!(
                        !path.as_os_str().is_empty()
                            && !path.starts_with("~")
                            && !path
                                .as_os_str()
                                .to_string_lossy()
                                .chars()
                                .any(char::is_control),
                        ConfigDiagnostic::guidance(
                            "guidance_path_invalid",
                            kind,
                            layer,
                            "Guidance paths must be nonempty absolute or config-relative paths without control characters or a tilde."
                        )
                    );
                }
            }
            ensure!(
                !model.executable.as_os_str().is_empty(),
                ConfigDiagnostic::model(kind, "executable", "Model executable is empty.")
            );
            for (field, value) in [("model", &model.model), ("reasoning", &model.reasoning)] {
                ensure!(
                    !value.trim().is_empty()
                        && value.len() <= 256
                        && !value.chars().any(char::is_control),
                    ConfigDiagnostic::model(
                        kind,
                        field,
                        "Model and reasoning settings must be nonempty, at most 256 bytes and contain no control characters."
                    )
                );
            }
        }
        if let Some(policy) = &self.schedule.queued_job_polling {
            ensure!(
                policy.initial_seconds <= policy.max_seconds,
                ConfigDiagnostic::field(
                    "schedule.queued_job_polling",
                    "Queued job polling initial interval must not exceed its maximum."
                )
            );
        }
        for (field, seconds, allow_zero) in [
            ("timeouts.http_seconds", self.timeouts.http_seconds, false),
            (
                "timeouts.read_http_seconds",
                self.timeouts.effective_read_http_seconds(),
                false,
            ),
            (
                "participation.uncertainty_grace_seconds",
                self.participation.uncertainty_grace_seconds,
                true,
            ),
            (
                "participation.uncertain_answer_retry_seconds",
                self.participation.uncertain_answer_retry_seconds,
                true,
            ),
            ("timeouts.model_seconds", self.timeouts.model_seconds, false),
            (
                "timeouts.shutdown_seconds",
                self.timeouts.shutdown_seconds,
                false,
            ),
            ("schedule.poll_seconds", self.schedule.poll_seconds, false),
            ("schedule.mine_seconds", self.schedule.mine_seconds, false),
            ("schedule.retry_seconds", self.schedule.retry_seconds, false),
            (
                "schedule.backoff_max_seconds",
                self.schedule.backoff_max_seconds,
                false,
            ),
            (
                "schedule.challenge_retry_seconds",
                self.schedule
                    .challenge_retry_seconds
                    .unwrap_or(self.schedule.retry_seconds),
                false,
            ),
            (
                "schedule.challenge_backoff_max_seconds",
                self.schedule
                    .challenge_backoff_max_seconds
                    .unwrap_or(self.schedule.backoff_max_seconds),
                false,
            ),
            (
                "schedule.assignments_retry_seconds",
                self.schedule
                    .assignments_retry_seconds
                    .unwrap_or(self.schedule.retry_seconds),
                false,
            ),
            (
                "schedule.assignments_backoff_max_seconds",
                self.schedule
                    .assignments_backoff_max_seconds
                    .unwrap_or(self.schedule.backoff_max_seconds),
                false,
            ),
            (
                "schedule.queued_job_polling.initial_seconds",
                self.schedule
                    .queued_job_polling
                    .as_ref()
                    .map_or(1, |policy| policy.initial_seconds),
                false,
            ),
            (
                "schedule.queued_job_polling.max_seconds",
                self.schedule
                    .queued_job_polling
                    .as_ref()
                    .map_or(1, |policy| policy.max_seconds),
                false,
            ),
            (
                "schedule.jitter_seconds",
                self.schedule.jitter_seconds,
                true,
            ),
            (
                "schedule",
                self.schedule
                    .poll_seconds
                    .saturating_add(self.schedule.jitter_seconds),
                false,
            ),
            (
                "schedule",
                self.schedule
                    .backoff_max_seconds
                    .max(self.schedule.retry_seconds)
                    .saturating_add(self.schedule.jitter_seconds),
                false,
            ),
            (
                "schedule",
                self.schedule
                    .challenge_backoff_max_seconds
                    .unwrap_or(self.schedule.backoff_max_seconds)
                    .max(
                        self.schedule
                            .challenge_retry_seconds
                            .unwrap_or(self.schedule.retry_seconds),
                    )
                    .saturating_add(self.schedule.jitter_seconds),
                false,
            ),
            (
                "schedule",
                self.schedule
                    .assignments_backoff_max_seconds
                    .unwrap_or(self.schedule.backoff_max_seconds)
                    .max(
                        self.schedule
                            .assignments_retry_seconds
                            .unwrap_or(self.schedule.retry_seconds),
                    )
                    .saturating_add(self.schedule.jitter_seconds),
                false,
            ),
        ] {
            ensure!(
                seconds > 0 || allow_zero,
                ConfigDiagnostic::field(
                    field,
                    "Timeouts and schedule intervals must be positive; jitter and uncertainty grace/retry may be zero."
                )
            );
            let duration = std::time::Duration::from_secs(seconds);
            ensure!(
                std::time::Instant::now().checked_add(duration).is_some()
                    && std::time::SystemTime::now()
                        .checked_add(duration)
                        .and_then(|deadline| deadline.duration_since(std::time::UNIX_EPOCH).ok())
                        .is_some_and(|deadline| deadline.as_millis() <= i64::MAX as u128),
                ConfigDiagnostic::field(
                    field,
                    "Timeout or schedule interval (including jitter) overflows a representable deadline."
                )
            );
        }
        if [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine]
            .iter()
            .any(|&kind| self.mode(kind) == Mode::Active)
        {
            ensure!(
                !self.network.address.is_empty(),
                ConfigDiagnostic::field(
                    "network.address",
                    "Active capabilities require an account address."
                )
            );
            ensure!(
                !self.network.credential_file.as_os_str().is_empty(),
                ConfigDiagnostic::field(
                    "network.credential_file",
                    "Active capabilities require a credential file."
                )
            );
        }
        Ok(())
    }
    pub(crate) fn validate_core_guidance(&self) -> Result<()> {
        for (kind, model) in [
            (WorkKind::Answer, &self.solver.answer),
            (WorkKind::Judge, &self.solver.judge),
        ] {
            ensure!(
                self.mode(kind) != Mode::Active
                    || (model.core_guidance_file.is_some()
                        && !model.core_guidance.trim().is_empty()),
                ConfigDiagnostic::guidance(
                    "guidance_required",
                    kind,
                    "core",
                    "Active model routes require a nonempty core_guidance_file."
                )
            );
        }
        Ok(())
    }
    pub fn revision(&self) -> Result<String> {
        ensure!(self.guidance_loaded, "model guidance has not been loaded");
        let mut digest = Sha256::new();
        digest.update(serde_json::to_vec(self)?);
        for model in [&self.solver.answer, &self.solver.judge] {
            digest.update((model.guidance.len() as u64).to_le_bytes());
            digest.update(model.guidance.as_bytes());
            digest.update((model.core_guidance.len() as u64).to_le_bytes());
            digest.update(model.core_guidance.as_bytes());
        }
        Ok(format!("{:x}", digest.finalize()))
    }
    pub fn optional_revision(&self) -> Result<Option<String>> {
        self.guidance_loaded.then(|| self.revision()).transpose()
    }
    pub(crate) fn judging_assignment_excluded(&self, id: &str) -> bool {
        self.excluded_judging_assignments
            .iter()
            .any(|excluded| excluded.eq_ignore_ascii_case(id))
    }
    pub fn mode(&self, kind: WorkKind) -> Mode {
        match kind {
            WorkKind::Answer => self.capabilities.answer,
            WorkKind::Judge => self.capabilities.judge,
            WorkKind::Mine => self.capabilities.mine,
        }
    }
}

fn read_guidance(path: &Path, kind: WorkKind, layer: &'static str) -> Result<Arc<str>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| {
        ConfigDiagnostic::guidance(
            if error.kind() == std::io::ErrorKind::NotFound {
                "guidance_missing"
            } else {
                "guidance_unreadable"
            },
            kind,
            layer,
            "Cannot open model guidance; inspect the configured file and its access permissions.",
        )
    })?;
    let metadata = file.metadata().map_err(|_| {
        ConfigDiagnostic::guidance(
            "guidance_unreadable",
            kind,
            layer,
            "Cannot inspect model guidance file.",
        )
    })?;
    ensure!(
        metadata.is_file(),
        ConfigDiagnostic::guidance(
            "guidance_not_regular",
            kind,
            layer,
            "Model guidance must be a regular file."
        )
    );
    ensure!(
        metadata.len() <= MAX_GUIDANCE_BYTES as u64,
        ConfigDiagnostic::guidance(
            "guidance_too_large",
            kind,
            layer,
            "Model guidance exceeds 64 KiB."
        )
    );
    let mut bytes = Vec::new();
    file.take((MAX_GUIDANCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            ConfigDiagnostic::guidance(
                "guidance_unreadable",
                kind,
                layer,
                "Cannot read model guidance file.",
            )
        })?;
    ensure!(
        bytes.len() <= MAX_GUIDANCE_BYTES,
        ConfigDiagnostic::guidance(
            "guidance_too_large",
            kind,
            layer,
            "Model guidance exceeds 64 KiB."
        )
    );
    validate_guidance_bytes(&bytes).map_err(|_| {
        ConfigDiagnostic::guidance(
            "guidance_not_utf8",
            kind,
            layer,
            "Model guidance must be UTF-8.",
        )
        .into()
    })
}

pub(crate) fn validate_guidance_bytes(bytes: &[u8]) -> Result<Arc<str>> {
    ensure!(
        bytes.len() <= MAX_GUIDANCE_BYTES,
        "model guidance exceeds 64 KiB"
    );
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("model guidance must be UTF-8"))?;
    Ok(Arc::from(text))
}
pub(crate) fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
pub(crate) fn safe_segment(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub(crate) fn valid_address(value: &str) -> bool {
    // The reference client encodes a 32-byte Ed25519 key in base58 after poa1.
    let Some(encoded) = value.strip_prefix("poa1") else {
        return false;
    };
    if !(32..=44).contains(&encoded.len()) {
        return false;
    }
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes = [0u8; 32];
    for digit in encoded.bytes() {
        let Some(index) = ALPHABET.iter().position(|&c| c == digit) else {
            return false;
        };
        let mut carry = index as u32;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return false;
        }
    }
    let leading = encoded.bytes().take_while(|&b| b == b'1').count();
    let significant = bytes.iter().position(|&b| b != 0).map_or(0, |i| 32 - i);
    leading + significant == 32
}
#[cfg(test)]
pub(crate) fn validate_origin(value: &str) -> Result<reqwest::Url> {
    validate_origin_with_trust(value, &network_defaults().trusted_origins)
}

pub fn validate_origin_with_trust(value: &str, trusted_origins: &[String]) -> Result<reqwest::Url> {
    ensure!(
        !trusted_origins.is_empty() && trusted_origins.len() <= 16,
        "configure between one and sixteen trusted origins"
    );
    let url = parse_origin(value)?;
    let mut trusted = false;
    for origin in trusted_origins {
        trusted |= parse_origin(origin)?.origin() == url.origin();
    }
    // Explicit loopback URLs remain the isolated development/fixture boundary.
    let loopback = url.scheme() == "http" && is_loopback(&url);
    ensure!(
        trusted || loopback,
        "network origin is not explicitly trusted"
    );
    Ok(url)
}

fn is_loopback(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

fn parse_origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid network origin"))?;
    let authority = value.split_once("://").map(|(_, rest)| rest).unwrap_or("");
    ensure!(
        !authority.contains('@')
            && authority
                .split_once('/')
                .is_none_or(|(_, path)| path.is_empty()),
        "base_url must be an origin without a path"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "origin must not contain credentials, query or fragment"
    );
    ensure!(
        url.path() == "/"
            && url.host_str().is_some()
            && !value.contains('\\')
            && !value
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control()),
        "base_url must be an origin without a path"
    );
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&url)),
        "network origin requires HTTPS or an explicit loopback HTTP development origin"
    );
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_job_polling_is_optional_bounded_and_serialized() {
        let mut config = Config::default();
        assert_eq!(config.schedule.queued_job_polling, None);
        let original_revision = config.revision().unwrap();
        assert!(
            !toml::to_string(&config)
                .unwrap()
                .contains("queued_job_polling")
        );
        config.schedule.queued_job_polling = Some(QueuedJobPolling {
            initial_seconds: 2,
            max_seconds: 30,
        });
        config.validate().unwrap();
        assert_ne!(original_revision, config.revision().unwrap());
        let decoded: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(decoded.schedule, config.schedule);
        for (initial_seconds, max_seconds) in [(0, 30), (2, 0), (31, 30), (1, u64::MAX)] {
            config.schedule.queued_job_polling = Some(QueuedJobPolling {
                initial_seconds,
                max_seconds,
            });
            assert!(config.validate().is_err());
        }
        config.schedule.queued_job_polling = Some(QueuedJobPolling {
            initial_seconds: 1,
            max_seconds: 1,
        });
        config.validate().unwrap();
        assert!(
            toml::from_str::<Config>("[schedule.queued_job_polling]\ninitial_seconds=2").is_err()
        );
    }

    #[test]
    fn challenge_policy_and_answer_reserve_are_opt_in_and_validated() {
        let mut config = Config::default();
        assert_eq!(config.participation.answer_reserved_slots, 0);
        assert_eq!(config.schedule.challenge_retry_seconds, None);
        assert_eq!(config.schedule.challenge_backoff_max_seconds, None);
        config.participation.max_unresolved_operations = 8;
        config.participation.answer_reserved_slots = 2;
        config.schedule.challenge_retry_seconds = Some(2);
        config.schedule.challenge_backoff_max_seconds = Some(8);
        config.validate().unwrap();
        let decoded: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(decoded.participation, config.participation);
        assert_eq!(decoded.schedule, config.schedule);
        config.participation.answer_reserved_slots = 8;
        assert!(config.validate().is_err());
        config.participation.answer_reserved_slots = 2;
        config.schedule.challenge_retry_seconds = Some(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn participation_and_read_timeout_defaults_and_bounds() {
        let original = Config::default();
        assert_eq!(original.participation.mode, ParticipationMode::Strict);
        assert!(!original.participation.retry_uncertain_answers);
        assert!(!original.schedule.mine_each_epoch);
        assert_eq!(
            original.timeouts.effective_read_http_seconds(),
            original.timeouts.http_seconds
        );
        let mut changed = original.clone();
        changed.participation.mode = ParticipationMode::ParticipationFirst;
        changed.participation.uncertainty_grace_seconds = 0;
        changed.participation.uncertain_answer_retry_seconds = 0;
        changed.participation.max_unresolved_operations = 100;
        changed.timeouts.read_http_seconds = Some(75);
        changed.schedule.mine_each_epoch = true;
        changed.validate().unwrap();
        assert_eq!(changed.timeouts.effective_read_http_seconds(), 75);
        assert_ne!(changed.revision().unwrap(), original.revision().unwrap());
        let encoded = toml::to_string(&changed).unwrap();
        let decoded = toml::from_str::<Config>(&encoded).unwrap();
        assert_eq!(decoded.participation, changed.participation);
        assert_eq!(decoded.timeouts, changed.timeouts);
        assert_eq!(decoded.schedule, changed.schedule);
        changed.participation.max_unresolved_operations = 0;
        assert!(changed.validate().is_err());
        changed.participation.max_unresolved_operations = 4;
        changed.participation.max_answer_attempts_per_epoch = 0;
        assert!(changed.validate().is_err());
        changed.participation.max_answer_attempts_per_epoch = 2;
        changed.timeouts.read_http_seconds = Some(0);
        assert!(changed.validate().is_err());
        changed.timeouts.read_http_seconds = Some(u64::MAX);
        assert!(changed.validate().is_err());
        assert!(toml::from_str::<Config>("[participation]\nmode='optimistic'").is_err());
        assert!(toml::from_str::<Config>("[participation]\nretry_uncertain_answer=true").is_err());
    }
    #[test]
    fn judging_exclusions_default_empty_validate_and_change_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        let original = Config::load(&path).unwrap();
        assert!(original.excluded_judging_assignments.is_empty());
        let id = "aB".repeat(32);
        std::fs::write(&path, format!("excluded_judging_assignments = ['{id}']\n")).unwrap();
        let changed = Config::load(&path).unwrap();
        assert_eq!(
            changed.excluded_judging_assignments,
            vec![id.to_ascii_lowercase()]
        );
        assert!(changed.judging_assignment_excluded(&id.to_lowercase()));
        assert!(!changed.judging_assignment_excluded(&"c".repeat(64)));
        assert_ne!(original.revision().unwrap(), changed.revision().unwrap());
        assert_eq!(
            Config::load_metadata(&path).unwrap().revision().unwrap(),
            changed.revision().unwrap()
        );
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            format!("{} ", "a".repeat(63)),
            "é".repeat(32),
            "private-exclusion-canary".into(),
        ] {
            std::fs::write(
                &path,
                format!("excluded_judging_assignments = ['{invalid}']\n"),
            )
            .unwrap();
            let error = Config::load(&path).unwrap_err().to_string();
            assert!(!error.contains(&invalid) || invalid.is_empty());
            assert!(Config::load_metadata(&path).is_err());
        }
        // The existing whole-configuration size bound is the only count limit.
        let mut many = original.clone();
        many.excluded_judging_assignments = (0..512).map(|n| format!("{n:064x}")).collect();
        std::fs::write(&path, toml::to_string(&many).unwrap()).unwrap();
        assert_eq!(
            Config::load(&path)
                .unwrap()
                .excluded_judging_assignments
                .len(),
            512
        );
    }

    #[test]
    fn active_requires_identity_and_timings_are_bounded() {
        let mut config = Config::default();
        config.capabilities.answer = Mode::Active;
        assert!(config.validate().is_err());
        config.capabilities.answer = Mode::Off;
        config.schedule.poll_seconds = 0;
        assert!(config.validate().is_err());
        config.schedule.poll_seconds = 60;
        config.timeouts.http_seconds = u64::MAX;
        assert!(config.validate().is_err());
        config.timeouts.http_seconds = 86400;
        config.timeouts.model_seconds = 86400;
        config.schedule.mine_seconds = 365 * 86400;
        assert!(config.validate().is_ok());
    }
    #[test]
    fn unsafe_origins_and_paths_are_rejected() {
        for origin in [
            "http://example.com",
            "https://example.com",
            "https://minepoa.com:8443",
            "https://sub.minepoa.com",
            "https://user:secret@example.com",
            "https://example.com/api",
            "https://example.com?key=secret",
            "https://example.com/#x",
            "https://example.com/../",
        ] {
            assert!(validate_origin(origin).is_err(), "{origin}");
        }
        for origin in [
            "https://minepoa.com",
            "https://minepoa.com:443",
            "http://127.0.0.1:8123",
            "http://[::1]:8123",
        ] {
            assert!(validate_origin(origin).is_ok(), "{origin}");
        }
        assert!(!safe_segment("../mainnet", 64));
        assert!(!valid_address("poa1invalid/path"));
        assert!(valid_address(&format!("poa1{}", "1".repeat(32))));
    }
    #[test]
    fn nested_unknown_fields_fail_and_paths_are_config_relative() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        let mut config = Config {
            state_dir: "data".into(),
            ..Config::default()
        };
        config.network.credential_file = "key".into();
        config.solver.answer.executable = "./adapter".into();
        let text = toml::to_string(&config).unwrap();
        std::fs::write(&file, &text).unwrap();
        let loaded = Config::load(&file).unwrap();
        assert_eq!(loaded.state_dir, dir.path().join("data"));
        assert_eq!(loaded.network.credential_file, dir.path().join("key"));
        assert_eq!(loaded.solver.answer.executable, dir.path().join("adapter"));
        std::fs::write(
            &file,
            text.replace("[network]", "[network]\napi_key = 'never-print-this'"),
        )
        .unwrap();
        let error = Config::load(&file).unwrap_err().to_string();
        assert!(!error.contains("never-print-this"));
        assert!(toml::from_str::<Config>("unknown = 1").is_err());
    }

    #[test]
    fn guidance_edits_change_revision_without_mutating_snapshots_or_exposing_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let guidance = dir.path().join("voice.md");
        let mut config = Config::default();
        config.solver.answer.guidance_file = Some("voice.md".into());
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        std::fs::write(
            &guidance,
            "private-guidance-canary: emphasize verification costs",
        )
        .unwrap();
        let first = Config::load(&path).unwrap();
        assert_eq!(first.solver.answer.guidance_file.as_ref(), Some(&guidance));
        assert!(first.solver.answer.guidance.contains("verification costs"));
        assert!(first.solver.judge.guidance.is_empty());
        let public = format!("{} {first:?}", serde_json::to_string(&first).unwrap());
        assert!(!public.contains("private-guidance-canary"));
        std::fs::write(&guidance, "emphasize credible failure modes").unwrap();
        let second = Config::load(&path).unwrap();
        assert_ne!(first.revision().unwrap(), second.revision().unwrap());
        assert!(first.solver.answer.guidance.contains("verification costs"));
        assert_eq!(
            &*second.solver.answer.guidance,
            "emphasize credible failure modes"
        );
        std::fs::write(&guidance, "").unwrap();
        assert!(
            Config::load(&path)
                .unwrap()
                .solver
                .answer
                .guidance
                .is_empty()
        );
        std::fs::remove_file(&guidance).unwrap();
        assert!(Config::load(&path).is_err());
        let metadata = Config::load_metadata(&path).unwrap();
        assert!(metadata.optional_revision().unwrap().is_none());
        assert!(metadata.revision().is_err());
    }

    #[test]
    fn schedule_rejects_unrepresentable_waits_and_allows_disabling_stagger() {
        let mut config = Config::default();
        config.schedule.jitter_seconds = 0;
        config.schedule.retry_seconds = 1200;
        config.schedule.backoff_max_seconds = 900;
        config.validate().unwrap();
        config.schedule.jitter_seconds = u64::MAX;
        assert!(config.validate().is_err());
        config.schedule.jitter_seconds = 0;
        config.schedule.backoff_max_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn core_guidance_requires_active_routes_and_remains_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_ok());
        config.capabilities.answer = Mode::Active;
        config.network.address = format!("poa1{}", "1".repeat(32));
        config.network.credential_file = "credential".into();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
        assert!(Config::load_metadata(&path).is_ok());
        config.solver.answer.core_guidance_file = Some("core.md".into());
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(dir.path().join("core.md"), " \n").unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(dir.path().join("core.md"), "Produce an original mechanism.").unwrap();
        assert!(Config::load(&path).is_ok());
        config.capabilities.judge = Mode::Active;
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
        assert!(Config::load_metadata(&path).is_ok());
    }

    #[test]
    fn core_edits_reload_both_routes_without_exposing_or_mutating_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.solver.answer.core_guidance_file = Some("answer-core.md".into());
        config.solver.judge.core_guidance_file = Some("judge-core.md".into());
        std::fs::write(
            dir.path().join("answer-core.md"),
            "private-answer-core-canary",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("judge-core.md"),
            "private-judge-core-canary",
        )
        .unwrap();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let first = Config::load(&path).unwrap();
        assert_eq!(
            first.solver.answer.core_guidance_file,
            Some(dir.path().join("answer-core.md"))
        );
        let public = format!("{} {first:?}", serde_json::to_string(&first).unwrap());
        assert!(!public.contains("private-answer-core-canary"));
        assert!(!public.contains("private-judge-core-canary"));
        std::fs::write(
            dir.path().join("answer-core.md"),
            "Updated answer instructions.",
        )
        .unwrap();
        let second = Config::load(&path).unwrap();
        assert_ne!(first.revision().unwrap(), second.revision().unwrap());
        assert_eq!(
            &*first.solver.answer.core_guidance,
            "private-answer-core-canary"
        );
        std::fs::write(
            dir.path().join("judge-core.md"),
            "Updated judging instructions.",
        )
        .unwrap();
        let third = Config::load(&path).unwrap();
        assert_ne!(second.revision().unwrap(), third.revision().unwrap());
        assert_eq!(
            &*second.solver.judge.core_guidance,
            "private-judge-core-canary"
        );
        assert!(
            Config::load_metadata(&path)
                .unwrap()
                .optional_revision()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn guidance_rejects_binary_oversized_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guidance");
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_guidance(&path, WorkKind::Answer, "user").is_err());
        std::fs::write(&path, vec![b'a'; MAX_GUIDANCE_BYTES + 1]).unwrap();
        assert!(read_guidance(&path, WorkKind::Answer, "user").is_err());
        assert!(read_guidance(dir.path(), WorkKind::Answer, "user").is_err());
    }
}
