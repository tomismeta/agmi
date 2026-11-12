use crate::capability::LaneId;
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
    kind: Option<LaneId>,
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

    fn model(kind: LaneId, field: &'static str, message: &'static str) -> Self {
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
        kind: LaneId,
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

    pub fn guidance_selector(&self) -> Option<(LaneId, &'static str)> {
        self.kind.zip(self.layer)
    }
}

impl std::fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for ConfigDiagnostic {}

/// A finite count policy or an explicit absence of a cumulative count ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountLimit {
    Bounded(u32),
    Unbounded,
}

impl CountLimit {
    pub fn finite(self) -> Option<u32> {
        match self {
            Self::Bounded(value) => Some(value),
            Self::Unbounded => None,
        }
    }

    pub fn allows(self, used: u64) -> bool {
        self.finite().is_none_or(|limit| used < u64::from(limit))
    }

    pub fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bounded(a), Self::Bounded(b)) => Self::Bounded(a.min(b)),
            (Self::Unbounded, limit) | (limit, Self::Unbounded) => limit,
        }
    }
}

impl From<u32> for CountLimit {
    fn from(value: u32) -> Self {
        Self::Bounded(value)
    }
}

impl Serialize for CountLimit {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Bounded(0) => Err(serde::ser::Error::custom("count limit must be positive")),
            Self::Bounded(value) => serializer.serialize_u32(*value),
            Self::Unbounded => serializer.serialize_str("unbounded"),
        }
    }
}

impl<'de> Deserialize<'de> for CountLimit {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = CountLimit;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a positive u32 or \"unbounded\"")
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                u32::try_from(value)
                    .ok()
                    .filter(|value| *value > 0)
                    .map(CountLimit::Bounded)
                    .ok_or_else(|| E::custom("count limit must be a positive u32"))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                self.visit_u64(
                    u64::try_from(value).map_err(|_| E::custom("count limit must be positive"))?,
                )
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                if value == "unbounded" {
                    Ok(CountLimit::Unbounded)
                } else {
                    Err(E::custom("expected \"unbounded\""))
                }
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Active,
    #[default]
    ReadOnly,
    Off,
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capabilities {
    pub answer: AnswerConfig,
    pub judge: JudgeConfig,
    pub mine: MineConfig,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            harness: Harness::Hermes,
            executable: PathBuf::from("hermes"),
            model: "gpt-6.1-sol".into(),
            reasoning: "high".into(),
            hermes_api_url: default_hermes_api_url(),
            guidance_file: None,
            core_guidance_file: None,
            core_guidance: Arc::from(""),
            guidance: Arc::from(""),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnswerConfig {
    pub mode: Mode,
    pub model: ModelConfig,
    pub timeouts: ModelTimeouts,
    pub schedule: Schedule,
    pub preparation: Preparation,
    pub participation: AnswerParticipation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JudgeConfig {
    pub mode: Mode,
    pub model: ModelConfig,
    pub timeouts: ModelTimeouts,
    pub schedule: Schedule,
    #[serde(deserialize_with = "deserialize_judge_preparation")]
    pub preparation: Preparation,
    pub participation: Participation,
    pub excluded_assignments: Vec<String>,
}
impl Default for JudgeConfig {
    fn default() -> Self {
        Self {
            mode: Mode::ReadOnly,
            model: ModelConfig::default(),
            timeouts: ModelTimeouts::default(),
            schedule: Schedule::default(),
            preparation: Preparation {
                while_blocked: false,
                ..Preparation::default()
            },
            participation: Participation::default(),
            excluded_assignments: Vec::new(),
        }
    }
}

// Judge's partial preparation table must not inherit answer's cost permission.
fn deserialize_judge_preparation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Preparation, D::Error> {
    #[derive(Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct JudgePreparation {
        while_blocked: bool,
        retry_uncertain: bool,
        max_attempts_per_work: CountLimit,
        max_uncertain_replacements_per_work: u32,
    }
    impl Default for JudgePreparation {
        fn default() -> Self {
            Self {
                while_blocked: false,
                retry_uncertain: false,
                max_attempts_per_work: CountLimit::Bounded(2),
                max_uncertain_replacements_per_work: 1,
            }
        }
    }
    let value = JudgePreparation::deserialize(deserializer)?;
    Ok(Preparation {
        while_blocked: value.while_blocked,
        retry_uncertain: value.retry_uncertain,
        max_attempts_per_work: value.max_attempts_per_work,
        max_uncertain_replacements_per_work: value.max_uncertain_replacements_per_work,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MineConfig {
    pub mode: Mode,
    pub timeouts: HttpTimeouts,
    pub schedule: MineSchedule,
    pub participation: Participation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimePolicy {
    pub shutdown_seconds: u64,
}
impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            shutdown_seconds: 30,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityPolicy {
    pub read_http_seconds: u64,
    pub retry_seconds: u64,
    pub backoff_max_seconds: u64,
    pub jitter_seconds: u64,
}
impl Default for IdentityPolicy {
    fn default() -> Self {
        Self {
            read_http_seconds: 90,
            retry_seconds: 180,
            backoff_max_seconds: 900,
            jitter_seconds: 30,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpTimeouts {
    pub read_http_seconds: u64,
    pub http_seconds: u64,
}
impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            read_http_seconds: 90,
            http_seconds: 90,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelTimeouts {
    pub read_http_seconds: u64,
    pub http_seconds: u64,
    pub model_seconds: u64,
}
impl Default for ModelTimeouts {
    fn default() -> Self {
        Self {
            read_http_seconds: 90,
            http_seconds: 90,
            model_seconds: 300,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Schedule {
    pub poll_seconds: u64,
    pub retry_seconds: u64,
    pub backoff_max_seconds: u64,
    pub jitter_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_retry_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_backoff_max_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_job_polling: Option<QueuedJobPolling>,
}
impl Default for Schedule {
    fn default() -> Self {
        Self {
            poll_seconds: 120,
            retry_seconds: 180,
            backoff_max_seconds: 900,
            jitter_seconds: 30,
            discovery_retry_seconds: None,
            discovery_backoff_max_seconds: None,
            queued_job_polling: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MineSchedule {
    pub poll_seconds: u64,
    pub retry_seconds: u64,
    pub backoff_max_seconds: u64,
    pub jitter_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_retry_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_backoff_max_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_job_polling: Option<QueuedJobPolling>,
    pub interval_seconds: u64,
    pub each_epoch: bool,
}
impl Default for MineSchedule {
    fn default() -> Self {
        Self {
            poll_seconds: 120,
            retry_seconds: 180,
            backoff_max_seconds: 900,
            jitter_seconds: 30,
            discovery_retry_seconds: None,
            discovery_backoff_max_seconds: None,
            queued_job_polling: None,
            interval_seconds: 86400,
            each_epoch: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedJobPolling {
    pub initial_seconds: u64,
    pub max_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Preparation {
    pub while_blocked: bool,
    pub retry_uncertain: bool,
    pub max_attempts_per_work: CountLimit,
    #[serde(skip_serializing_if = "is_one")]
    pub max_uncertain_replacements_per_work: u32,
}
impl Default for Preparation {
    fn default() -> Self {
        Self {
            while_blocked: true,
            retry_uncertain: false,
            max_attempts_per_work: CountLimit::Bounded(2),
            max_uncertain_replacements_per_work: 1,
        }
    }
}

fn is_one(value: &u32) -> bool {
    *value == 1
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
    AcceptedLinked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Participation {
    pub mode: ParticipationMode,
    pub uncertainty_grace_seconds: u64,
    pub max_unresolved_operations: CountLimit,
}
impl Default for Participation {
    fn default() -> Self {
        Self {
            mode: ParticipationMode::Strict,
            uncertainty_grace_seconds: 300,
            max_unresolved_operations: CountLimit::Bounded(4),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnswerParticipation {
    pub mode: ParticipationMode,
    pub uncertainty_grace_seconds: u64,
    pub max_unresolved_operations: CountLimit,
    pub retry_uncertain_answers: bool,
    pub uncertain_answer_retry_seconds: u64,
    pub max_answer_attempts_per_epoch: u32,
    pub max_historical_unknown_answers: u32,
    pub historical_unknown_answer_capacity: HistoricalAnswerCapacity,
}
impl Default for AnswerParticipation {
    fn default() -> Self {
        Self {
            mode: ParticipationMode::Strict,
            uncertainty_grace_seconds: 300,
            max_unresolved_operations: CountLimit::Bounded(4),
            retry_uncertain_answers: false,
            uncertain_answer_retry_seconds: 600,
            max_answer_attempts_per_epoch: 2,
            max_historical_unknown_answers: 0,
            historical_unknown_answer_capacity: HistoricalAnswerCapacity::Bounded,
        }
    }
}

fn deserialize_schema_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    if version != 2 {
        return Err(serde::de::Error::custom("schema_version must be 2"));
    }
    Ok(version)
}
fn default_state_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("agmi")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub runtime: RuntimePolicy,
    #[serde(default)]
    pub identity: IdentityPolicy,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(skip)]
    pub(crate) guidance_loaded: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 2,
            network: NetworkConfig::default(),
            state_dir: default_state_dir(),
            runtime: RuntimePolicy::default(),
            identity: IdentityPolicy::default(),
            capabilities: Capabilities::default(),
            guidance_loaded: true,
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
        for id in &mut config.capabilities.judge.excluded_assignments {
            id.make_ascii_lowercase();
        }
        config.capabilities.judge.excluded_assignments.sort();
        config.capabilities.judge.excluded_assignments.dedup();
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
        for model in [
            &mut config.capabilities.answer.model,
            &mut config.capabilities.judge.model,
        ] {
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
        config.guidance_loaded = [
            &config.capabilities.answer.model,
            &config.capabilities.judge.model,
        ]
        .iter()
        .all(|model| model.guidance_file.is_none() && model.core_guidance_file.is_none());
        if load_guidance {
            for (kind, model) in [
                (LaneId::Answer, &mut config.capabilities.answer.model),
                (LaneId::Judge, &mut config.capabilities.judge.model),
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
        ensure!(
            self.schema_version == 2,
            ConfigDiagnostic::field("schema_version", "Configuration schema_version must be 2.")
        );
        for kind in LaneId::ALL {
            ensure!(
                self.participation(kind).max_unresolved_operations.finite() != Some(0),
                ConfigDiagnostic::model(
                    kind,
                    "participation.max_unresolved_operations",
                    "Participation limits must be positive."
                )
            );
            if let Some(preparation) = self.preparation(kind) {
                ensure!(
                    preparation
                        .max_attempts_per_work
                        .finite()
                        .is_none_or(|limit| (1..=8).contains(&limit)),
                    ConfigDiagnostic::model(
                        kind,
                        "preparation.max_attempts_per_work",
                        "Preparation attempts must be between 1 and 8 or unbounded."
                    )
                );
                ensure!(
                    preparation.max_uncertain_replacements_per_work <= 8,
                    ConfigDiagnostic::model(
                        kind,
                        "preparation.max_uncertain_replacements_per_work",
                        "Uncertain replacements must be between 0 and 8."
                    )
                );
            }
        }
        ensure!(
            self.capabilities
                .answer
                .participation
                .max_answer_attempts_per_epoch
                > 0,
            ConfigDiagnostic::field(
                "capabilities.answer.participation.max_answer_attempts_per_epoch",
                "Participation limits must be positive."
            )
        );
        ensure!(
            self.capabilities
                .judge
                .excluded_assignments
                .iter()
                .all(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())),
            ConfigDiagnostic::field(
                "capabilities.judge.excluded_assignments",
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
            (
                "capabilities.answer.model.executable",
                &self.capabilities.answer.model.executable,
            ),
            (
                "capabilities.judge.model.executable",
                &self.capabilities.judge.model.executable,
            ),
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
            (LaneId::Answer, &self.capabilities.answer.model),
            (LaneId::Judge, &self.capabilities.judge.model),
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
        for kind in LaneId::ALL {
            let schedule = self.schedule(kind);
            let timeouts = self.timeouts(kind);
            if let Some(policy) = schedule.queued_job_polling {
                ensure!(
                    policy.initial_seconds <= policy.max_seconds,
                    ConfigDiagnostic::model(
                        kind,
                        "schedule.queued_job_polling",
                        "Queued job polling initial interval must not exceed its maximum."
                    )
                );
            }
            for (field, seconds, allow_zero) in [
                ("timeouts.http_seconds", timeouts.http_seconds, false),
                (
                    "timeouts.read_http_seconds",
                    timeouts.read_http_seconds,
                    false,
                ),
                (
                    "timeouts.model_seconds",
                    self.model_seconds(kind).unwrap_or(1),
                    false,
                ),
                (
                    "participation.uncertainty_grace_seconds",
                    self.participation(kind).uncertainty_grace_seconds,
                    true,
                ),
                ("schedule.poll_seconds", schedule.poll_seconds, false),
                ("schedule.retry_seconds", schedule.retry_seconds, false),
                (
                    "schedule.backoff_max_seconds",
                    schedule.backoff_max_seconds,
                    false,
                ),
                (
                    "schedule.discovery_retry_seconds",
                    schedule
                        .discovery_retry_seconds
                        .unwrap_or(schedule.retry_seconds),
                    false,
                ),
                (
                    "schedule.discovery_backoff_max_seconds",
                    schedule
                        .discovery_backoff_max_seconds
                        .unwrap_or(schedule.backoff_max_seconds),
                    false,
                ),
                (
                    "schedule.queued_job_polling.initial_seconds",
                    schedule.queued_job_polling.map_or(1, |p| p.initial_seconds),
                    false,
                ),
                (
                    "schedule.queued_job_polling.max_seconds",
                    schedule.queued_job_polling.map_or(1, |p| p.max_seconds),
                    false,
                ),
                ("schedule.jitter_seconds", schedule.jitter_seconds, true),
                (
                    "schedule",
                    schedule
                        .poll_seconds
                        .saturating_add(schedule.jitter_seconds),
                    false,
                ),
                (
                    "schedule",
                    schedule
                        .backoff_max_seconds
                        .max(schedule.retry_seconds)
                        .saturating_add(schedule.jitter_seconds),
                    false,
                ),
                (
                    "schedule",
                    schedule
                        .discovery_backoff_max_seconds
                        .unwrap_or(schedule.backoff_max_seconds)
                        .max(
                            schedule
                                .discovery_retry_seconds
                                .unwrap_or(schedule.retry_seconds),
                        )
                        .saturating_add(schedule.jitter_seconds),
                    false,
                ),
                (
                    "schedule.queued_job_polling",
                    schedule
                        .queued_job_polling
                        .map_or(1, |p| p.max_seconds)
                        .saturating_add(schedule.jitter_seconds),
                    false,
                ),
            ] {
                validate_duration(field, seconds, allow_zero).map_err(|_| ConfigDiagnostic::model(
                    kind, field, "Lane duration must be positive and representable; jitter and uncertainty grace may be zero."
                ))?;
            }
        }
        for (field, seconds, allow_zero) in [
            (
                "runtime.shutdown_seconds",
                self.runtime.shutdown_seconds,
                false,
            ),
            (
                "identity.read_http_seconds",
                self.identity.read_http_seconds,
                false,
            ),
            ("identity.retry_seconds", self.identity.retry_seconds, false),
            (
                "identity.backoff_max_seconds",
                self.identity.backoff_max_seconds,
                false,
            ),
            (
                "identity.jitter_seconds",
                self.identity.jitter_seconds,
                true,
            ),
            (
                "identity",
                self.identity
                    .retry_seconds
                    .max(self.identity.backoff_max_seconds)
                    .saturating_add(self.identity.jitter_seconds),
                false,
            ),
            (
                "capabilities.mine.schedule.interval_seconds",
                self.capabilities.mine.schedule.interval_seconds,
                false,
            ),
            (
                "capabilities.mine.schedule",
                self.capabilities
                    .mine
                    .schedule
                    .interval_seconds
                    .saturating_add(self.capabilities.mine.schedule.jitter_seconds),
                false,
            ),
            (
                "capabilities.answer.participation.uncertain_answer_retry_seconds",
                self.capabilities
                    .answer
                    .participation
                    .uncertain_answer_retry_seconds,
                true,
            ),
        ] {
            validate_duration(field, seconds, allow_zero)?;
        }
        if LaneId::ALL
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
            (LaneId::Answer, &self.capabilities.answer.model),
            (LaneId::Judge, &self.capabilities.judge.model),
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
        for model in [
            &self.capabilities.answer.model,
            &self.capabilities.judge.model,
        ] {
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
        self.capabilities
            .judge
            .excluded_assignments
            .iter()
            .any(|excluded| excluded.eq_ignore_ascii_case(id))
    }
    pub fn mode(&self, kind: LaneId) -> Mode {
        match kind {
            LaneId::Answer => self.capabilities.answer.mode,
            LaneId::Judge => self.capabilities.judge.mode,
            LaneId::Mine => self.capabilities.mine.mode,
        }
    }
    pub fn model(&self, kind: LaneId) -> Option<&ModelConfig> {
        match kind {
            LaneId::Answer => Some(&self.capabilities.answer.model),
            LaneId::Judge => Some(&self.capabilities.judge.model),
            LaneId::Mine => None,
        }
    }
    pub fn timeouts(&self, kind: LaneId) -> HttpTimeouts {
        let model = match kind {
            LaneId::Answer => self.capabilities.answer.timeouts,
            LaneId::Judge => self.capabilities.judge.timeouts,
            LaneId::Mine => return self.capabilities.mine.timeouts,
        };
        HttpTimeouts {
            read_http_seconds: model.read_http_seconds,
            http_seconds: model.http_seconds,
        }
    }
    pub fn model_seconds(&self, kind: LaneId) -> Option<u64> {
        match kind {
            LaneId::Answer => Some(self.capabilities.answer.timeouts.model_seconds),
            LaneId::Judge => Some(self.capabilities.judge.timeouts.model_seconds),
            LaneId::Mine => None,
        }
    }
    pub fn schedule(&self, kind: LaneId) -> Schedule {
        match kind {
            LaneId::Answer => self.capabilities.answer.schedule,
            LaneId::Judge => self.capabilities.judge.schedule,
            LaneId::Mine => {
                let mine = self.capabilities.mine.schedule;
                Schedule {
                    poll_seconds: mine.poll_seconds,
                    retry_seconds: mine.retry_seconds,
                    backoff_max_seconds: mine.backoff_max_seconds,
                    jitter_seconds: mine.jitter_seconds,
                    discovery_retry_seconds: mine.discovery_retry_seconds,
                    discovery_backoff_max_seconds: mine.discovery_backoff_max_seconds,
                    queued_job_polling: mine.queued_job_polling,
                }
            }
        }
    }
    pub fn preparation(&self, kind: LaneId) -> Option<Preparation> {
        match kind {
            LaneId::Answer => Some(self.capabilities.answer.preparation),
            LaneId::Judge => Some(self.capabilities.judge.preparation),
            LaneId::Mine => None,
        }
    }
    pub fn participation(&self, kind: LaneId) -> Participation {
        match kind {
            LaneId::Answer => {
                let answer = self.capabilities.answer.participation;
                Participation {
                    mode: answer.mode,
                    uncertainty_grace_seconds: answer.uncertainty_grace_seconds,
                    max_unresolved_operations: answer.max_unresolved_operations,
                }
            }
            LaneId::Judge => self.capabilities.judge.participation,
            LaneId::Mine => self.capabilities.mine.participation,
        }
    }
    pub fn producer_revision(&self, kind: LaneId) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(self.schema_version.to_le_bytes());
        digest.update(kind.as_str().as_bytes());
        if let Some(model) = self.model(kind) {
            ensure!(self.guidance_loaded, "model guidance has not been loaded");
            digest.update(serde_json::to_vec(&(
                model.harness,
                &model.executable,
                &model.model,
                &model.reasoning,
                &model.hermes_api_url,
            ))?);
            for guidance in [&model.guidance, &model.core_guidance] {
                digest.update((guidance.len() as u64).to_le_bytes());
                digest.update(guidance.as_bytes());
            }
        }
        Ok(format!("{:x}", digest.finalize()))
    }
    pub fn lane_revision(&self, kind: LaneId) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(self.schema_version.to_le_bytes());
        digest.update(kind.as_str().as_bytes());
        digest.update(match kind {
            LaneId::Answer => serde_json::to_vec(&self.capabilities.answer)?,
            LaneId::Judge => serde_json::to_vec(&self.capabilities.judge)?,
            LaneId::Mine => serde_json::to_vec(&self.capabilities.mine)?,
        });
        if let Some(model) = self.model(kind) {
            ensure!(self.guidance_loaded, "model guidance has not been loaded");
            for guidance in [&model.guidance, &model.core_guidance] {
                digest.update((guidance.len() as u64).to_le_bytes());
                digest.update(guidance.as_bytes());
            }
        }
        Ok(format!("{:x}", digest.finalize()))
    }
}

fn validate_duration(field: &'static str, seconds: u64, allow_zero: bool) -> Result<()> {
    ensure!(
        seconds > 0 || allow_zero,
        ConfigDiagnostic::field(field, "Duration must be positive.")
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
            "Duration including jitter overflows a representable deadline."
        )
    );
    Ok(())
}

pub(crate) fn read_guidance(path: &Path, kind: LaneId, layer: &'static str) -> Result<Arc<str>> {
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
    fn count_limits_are_explicit_and_preserve_numeric_serialization() {
        for (text, limit) in [
            ("4", CountLimit::Bounded(4)),
            ("\"unbounded\"", CountLimit::Unbounded),
        ] {
            assert_eq!(serde_json::from_str::<CountLimit>(text).unwrap(), limit);
            assert_eq!(serde_json::to_string(&limit).unwrap(), text);
        }
        for text in [
            "0",
            "-1",
            "4294967296",
            "1.5",
            "\"4\"",
            "\"Unlimited\"",
            "null",
        ] {
            assert!(serde_json::from_str::<CountLimit>(text).is_err(), "{text}");
        }
        let finite = CountLimit::Bounded(4);
        assert!(finite.allows(3));
        assert!(!finite.allows(4));
        assert!(CountLimit::Unbounded.allows(u64::MAX));
        assert_eq!(finite.intersect(CountLimit::Unbounded), finite);
        assert_eq!(CountLimit::Unbounded.intersect(finite), finite);
        assert_eq!(finite.intersect(2.into()), CountLimit::Bounded(2));
        assert_eq!(CountLimit::Unbounded.finite(), None);
    }

    #[test]
    fn unbounded_and_uncertain_replacement_defaults_are_independent() {
        let config: Config = toml::from_str("schema_version=2\n[capabilities.judge.preparation]\nmax_attempts_per_work='unbounded'\n[capabilities.answer.participation]\nmax_unresolved_operations='unbounded'").unwrap();
        config.validate().unwrap();
        assert!(!config.capabilities.judge.preparation.while_blocked);
        assert!(!config.capabilities.judge.preparation.retry_uncertain);
        assert_eq!(
            config
                .capabilities
                .judge
                .preparation
                .max_uncertain_replacements_per_work,
            1
        );
        assert_eq!(
            config.capabilities.answer.participation.mode,
            ParticipationMode::Strict
        );
        let mut preparation = config.capabilities.judge.preparation;
        assert!(
            serde_json::to_value(preparation)
                .unwrap()
                .get("max_uncertain_replacements_per_work")
                .is_none()
        );
        preparation.max_uncertain_replacements_per_work = 0;
        assert_eq!(
            serde_json::to_value(preparation).unwrap()["max_uncertain_replacements_per_work"],
            0
        );
        let mut invalid = config;
        invalid
            .capabilities
            .judge
            .preparation
            .max_uncertain_replacements_per_work = 9;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn producer_revision_ignores_policy_but_binds_route_and_guidance() {
        let original = Config::default();
        let revision = original.producer_revision(LaneId::Answer).unwrap();
        let mut changed = original.clone();
        changed.capabilities.answer.mode = Mode::Off;
        changed.capabilities.answer.schedule.retry_seconds += 1;
        changed.capabilities.answer.timeouts.model_seconds += 1;
        changed
            .capabilities
            .answer
            .preparation
            .max_attempts_per_work = CountLimit::Unbounded;
        changed
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = CountLimit::Unbounded;
        assert_eq!(changed.producer_revision(LaneId::Answer).unwrap(), revision);
        assert_ne!(
            changed.lane_revision(LaneId::Answer).unwrap(),
            original.lane_revision(LaneId::Answer).unwrap()
        );
        changed.capabilities.answer.model.guidance = Arc::from("new guidance");
        assert_ne!(changed.producer_revision(LaneId::Answer).unwrap(), revision);
        changed = original.clone();
        changed
            .capabilities
            .answer
            .model
            .model
            .push_str("-different");
        assert_ne!(changed.producer_revision(LaneId::Answer).unwrap(), revision);
        changed.guidance_loaded = false;
        assert!(changed.producer_revision(LaneId::Answer).is_err());
    }

    #[test]
    fn schema_version_is_required_and_legacy_and_inappropriate_fields_reject() {
        for text in [
            "",
            "schema_version=1",
            "schema_version=3",
            "schema_version='2'",
        ] {
            assert!(toml::from_str::<Config>(text).is_err());
        }
        let defaults: Config = toml::from_str("schema_version=2").unwrap();
        defaults.validate().unwrap();
        for table in [
            "[solver]",
            "[timeouts]",
            "[schedule]",
            "[preparation]",
            "[participation]",
            "[capabilities.mine.model]",
            "[capabilities.mine.preparation]",
            "[capabilities.mine.timeouts]\nmodel_seconds=1",
            "[capabilities.judge.participation]\nretry_uncertain_answers=true",
            "[capabilities.mine.participation]\nmax_historical_unknown_answers=1",
            "[capabilities.answer.participation]\nanswer_reserved_slots=1",
            "[capabilities.answer.participation]\nallow_answer=true",
            "[capabilities.answer.schedule]\ninterval_seconds=1",
            "[capabilities.judge.schedule]\neach_epoch=true",
            "[capabilities]\nanswer='active'",
            "excluded_judging_assignments=[]",
        ] {
            assert!(
                toml::from_str::<Config>(&format!("schema_version=2\n{table}")).is_err(),
                "{table}"
            );
        }
    }

    #[test]
    fn defaults_and_partial_tables_preserve_lane_permissions() {
        let config: Config = toml::from_str("schema_version=2\n[capabilities.judge.preparation]\nmax_attempts_per_work=3\n[capabilities.answer.timeouts]\nhttp_seconds=17").unwrap();
        for kind in LaneId::ALL {
            assert_eq!(config.mode(kind), Mode::ReadOnly);
            assert_eq!(config.participation(kind).mode, ParticipationMode::Strict);
            assert_eq!(
                config.participation(kind).max_unresolved_operations,
                CountLimit::Bounded(4)
            );
            assert_eq!(config.timeouts(kind).read_http_seconds, 90);
        }
        assert!(config.capabilities.answer.preparation.while_blocked);
        assert!(!config.capabilities.judge.preparation.while_blocked);
        assert_eq!(
            config.capabilities.judge.preparation.max_attempts_per_work,
            CountLimit::Bounded(3)
        );
        assert!(
            !config
                .capabilities
                .answer
                .participation
                .retry_uncertain_answers
        );
        assert!(!config.capabilities.mine.schedule.each_epoch);
        assert_eq!(config.timeouts(LaneId::Answer).http_seconds, 17);
        assert_eq!(config.timeouts(LaneId::Judge).http_seconds, 90);
        assert!(config.model(LaneId::Mine).is_none());
        assert!(config.preparation(LaneId::Mine).is_none());
    }

    #[test]
    fn independent_policies_and_lane_digests_round_trip() {
        let original = Config::default();
        let mut changed = original.clone();
        changed.capabilities.answer.model.model = "exact-provider/model".into();
        changed.capabilities.answer.timeouts.model_seconds = 42;
        changed.capabilities.answer.schedule.discovery_retry_seconds = Some(7);
        changed
            .capabilities
            .answer
            .preparation
            .max_attempts_per_work = 8.into();
        changed.capabilities.answer.participation.mode = ParticipationMode::ParticipationFirst;
        changed
            .capabilities
            .answer
            .participation
            .max_unresolved_operations = 9.into();
        changed.validate().unwrap();
        assert_ne!(
            changed.lane_revision(LaneId::Answer).unwrap(),
            original.lane_revision(LaneId::Answer).unwrap()
        );
        for kind in [LaneId::Judge, LaneId::Mine] {
            assert_eq!(
                changed.lane_revision(kind).unwrap(),
                original.lane_revision(kind).unwrap()
            );
            assert_eq!(changed.schedule(kind), original.schedule(kind));
            assert_eq!(changed.participation(kind), original.participation(kind));
        }
        assert_ne!(changed.revision().unwrap(), original.revision().unwrap());
        let decoded: Config = toml::from_str(&toml::to_string(&changed).unwrap()).unwrap();
        assert_eq!(decoded.capabilities, changed.capabilities);
        changed.identity.retry_seconds = 22;
        changed.runtime.shutdown_seconds = 12;
        assert_eq!(
            changed.lane_revision(LaneId::Mine).unwrap(),
            original.lane_revision(LaneId::Mine).unwrap()
        );
    }

    #[test]
    fn queued_policy_and_all_lane_budget_bounds_validate() {
        let mut config = Config::default();
        for kind in LaneId::ALL {
            assert_eq!(config.schedule(kind).queued_job_polling, None);
        }
        for (initial_seconds, max_seconds) in [(0, 30), (2, 0), (31, 30), (1, u64::MAX)] {
            config.capabilities.judge.schedule.queued_job_polling = Some(QueuedJobPolling {
                initial_seconds,
                max_seconds,
            });
            assert!(config.validate().is_err());
        }
        config.capabilities.judge.schedule.queued_job_polling = Some(QueuedJobPolling {
            initial_seconds: 2,
            max_seconds: 30,
        });
        config.validate().unwrap();
        assert_eq!(config.schedule(LaneId::Answer).queued_job_polling, None);
        assert!(toml::from_str::<Config>("schema_version=2\n[capabilities.mine.schedule.queued_job_polling]\ninitial_seconds=2").is_err());
        for cap in [0, 9] {
            config.capabilities.judge.preparation.max_attempts_per_work = cap.into();
            assert!(config.validate().is_err());
        }
        config.capabilities.judge.preparation.max_attempts_per_work = 2.into();
        config
            .capabilities
            .mine
            .participation
            .max_unresolved_operations = 0.into();
        assert!(config.validate().is_err());
        config
            .capabilities
            .mine
            .participation
            .max_unresolved_operations = 1.into();
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 0;
        assert!(config.validate().is_err());
        config
            .capabilities
            .answer
            .participation
            .max_answer_attempts_per_epoch = 2;
        config.capabilities.answer.schedule.discovery_retry_seconds = Some(0);
        assert!(config.validate().is_err());
        config.capabilities.answer.schedule.discovery_retry_seconds = None;
        config.identity.read_http_seconds = 0;
        assert!(config.validate().is_err());
    }
    #[test]
    fn judging_exclusions_default_empty_validate_and_change_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "schema_version=2\n").unwrap();
        let original = Config::load(&path).unwrap();
        assert!(original.capabilities.judge.excluded_assignments.is_empty());
        let id = "aB".repeat(32);
        std::fs::write(
            &path,
            format!(
                "schema_version=2\n[capabilities.judge]\nexcluded_assignments = ['{id}', '{id}']\n"
            ),
        )
        .unwrap();
        let changed = Config::load(&path).unwrap();
        assert_eq!(
            changed.capabilities.judge.excluded_assignments,
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
                format!(
                    "schema_version=2\n[capabilities.judge]\nexcluded_assignments = ['{invalid}']\n"
                ),
            )
            .unwrap();
            let error = Config::load(&path).unwrap_err().to_string();
            assert!(!error.contains(&invalid) || invalid.is_empty());
            assert!(Config::load_metadata(&path).is_err());
        }
        // The existing whole-configuration size bound is the only count limit.
        let mut many = original.clone();
        many.capabilities.judge.excluded_assignments =
            (0..512).map(|n| format!("{n:064x}")).collect();
        std::fs::write(&path, toml::to_string(&many).unwrap()).unwrap();
        assert_eq!(
            Config::load(&path)
                .unwrap()
                .capabilities
                .judge
                .excluded_assignments
                .len(),
            512
        );
    }

    #[test]
    fn active_requires_identity_and_timings_are_bounded() {
        let mut config = Config::default();
        config.capabilities.answer.mode = Mode::Active;
        assert!(config.validate().is_err());
        config.capabilities.answer.mode = Mode::Off;
        config.capabilities.answer.schedule.poll_seconds = 0;
        assert!(config.validate().is_err());
        config.capabilities.answer.schedule.poll_seconds = 60;
        config.capabilities.answer.timeouts.http_seconds = u64::MAX;
        assert!(config.validate().is_err());
        config.capabilities.answer.timeouts.http_seconds = 86400;
        config.capabilities.answer.timeouts.model_seconds = 86400;
        config.capabilities.mine.schedule.interval_seconds = 365 * 86400;
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
        config.capabilities.answer.model.executable = "./adapter".into();
        let text = toml::to_string(&config).unwrap();
        std::fs::write(&file, &text).unwrap();
        let loaded = Config::load(&file).unwrap();
        assert_eq!(loaded.state_dir, dir.path().join("data"));
        assert_eq!(loaded.network.credential_file, dir.path().join("key"));
        assert_eq!(
            loaded.capabilities.answer.model.executable,
            dir.path().join("adapter")
        );
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
        config.capabilities.answer.model.guidance_file = Some("voice.md".into());
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        std::fs::write(
            &guidance,
            "private-guidance-canary: emphasize verification costs",
        )
        .unwrap();
        let first = Config::load(&path).unwrap();
        assert_eq!(
            first.capabilities.answer.model.guidance_file.as_ref(),
            Some(&guidance)
        );
        assert!(
            first
                .capabilities
                .answer
                .model
                .guidance
                .contains("verification costs")
        );
        assert!(first.capabilities.judge.model.guidance.is_empty());
        let public = format!("{} {first:?}", serde_json::to_string(&first).unwrap());
        assert!(!public.contains("private-guidance-canary"));
        std::fs::write(&guidance, "emphasize credible failure modes").unwrap();
        let second = Config::load(&path).unwrap();
        assert_ne!(first.revision().unwrap(), second.revision().unwrap());
        assert_ne!(
            first.lane_revision(LaneId::Answer).unwrap(),
            second.lane_revision(LaneId::Answer).unwrap()
        );
        assert_eq!(
            first.lane_revision(LaneId::Judge).unwrap(),
            second.lane_revision(LaneId::Judge).unwrap()
        );
        assert_eq!(
            first.lane_revision(LaneId::Mine).unwrap(),
            second.lane_revision(LaneId::Mine).unwrap()
        );
        assert!(
            first
                .capabilities
                .answer
                .model
                .guidance
                .contains("verification costs")
        );
        assert_eq!(
            &*second.capabilities.answer.model.guidance,
            "emphasize credible failure modes"
        );
        std::fs::write(&guidance, "").unwrap();
        assert!(
            Config::load(&path)
                .unwrap()
                .capabilities
                .answer
                .model
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
        config.capabilities.answer.schedule.jitter_seconds = 0;
        config.capabilities.answer.schedule.retry_seconds = 1200;
        config.capabilities.answer.schedule.backoff_max_seconds = 900;
        config.validate().unwrap();
        config.capabilities.answer.schedule.jitter_seconds = u64::MAX;
        assert!(config.validate().is_err());
        config.capabilities.answer.schedule.jitter_seconds = 0;
        config.capabilities.answer.schedule.backoff_max_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn core_guidance_requires_active_routes_and_remains_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_ok());
        config.capabilities.answer.mode = Mode::Active;
        config.network.address = format!("poa1{}", "1".repeat(32));
        config.network.credential_file = "credential".into();
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
        assert!(Config::load_metadata(&path).is_ok());
        config.capabilities.answer.model.core_guidance_file = Some("core.md".into());
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(dir.path().join("core.md"), " \n").unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(dir.path().join("core.md"), "Produce an original mechanism.").unwrap();
        assert!(Config::load(&path).is_ok());
        config.capabilities.judge.mode = Mode::Active;
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
        assert!(Config::load_metadata(&path).is_ok());
    }

    #[test]
    fn core_edits_reload_both_routes_without_exposing_or_mutating_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.capabilities.answer.model.core_guidance_file = Some("answer-core.md".into());
        config.capabilities.judge.model.core_guidance_file = Some("judge-core.md".into());
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
            first.capabilities.answer.model.core_guidance_file,
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
        assert_ne!(
            first.lane_revision(LaneId::Answer).unwrap(),
            second.lane_revision(LaneId::Answer).unwrap()
        );
        assert_eq!(
            first.lane_revision(LaneId::Judge).unwrap(),
            second.lane_revision(LaneId::Judge).unwrap()
        );
        assert_eq!(
            &*first.capabilities.answer.model.core_guidance,
            "private-answer-core-canary"
        );
        std::fs::write(
            dir.path().join("judge-core.md"),
            "Updated judging instructions.",
        )
        .unwrap();
        let third = Config::load(&path).unwrap();
        assert_ne!(second.revision().unwrap(), third.revision().unwrap());
        assert_ne!(
            second.lane_revision(LaneId::Judge).unwrap(),
            third.lane_revision(LaneId::Judge).unwrap()
        );
        assert_eq!(
            second.lane_revision(LaneId::Answer).unwrap(),
            third.lane_revision(LaneId::Answer).unwrap()
        );
        assert_eq!(
            &*second.capabilities.judge.model.core_guidance,
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
        assert!(read_guidance(&path, LaneId::Answer, "user").is_err());
        std::fs::write(&path, vec![b'a'; MAX_GUIDANCE_BYTES + 1]).unwrap();
        assert!(read_guidance(&path, LaneId::Answer, "user").is_err());
        assert!(read_guidance(dir.path(), LaneId::Answer, "user").is_err());
    }
}
