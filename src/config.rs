use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub(crate) const MAX_GUIDANCE_BYTES: usize = 64 * 1024;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance_file: Option<PathBuf>,
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
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub base_url: String,
    pub chain: String,
    pub address: String,
    pub credential_file: PathBuf,
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
    #[serde(default = "default_jitter_seconds")]
    pub jitter_seconds: u64,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Participation {
    pub mode: ParticipationMode,
    pub uncertainty_grace_seconds: u64,
    pub max_unresolved_operations: u32,
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
            guidance_file: None,
            guidance: Arc::from(""),
        };
        Self {
            guidance_loaded: true,
            preparation: Preparation::default(),
            participation: Participation::default(),
            excluded_judging_assignments: Vec::new(),
            network: NetworkConfig {
                base_url: "https://minepoa.com".into(),
                chain: "poa-mainnet-1".into(),
                address: String::new(),
                credential_file: PathBuf::new(),
            },
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
        let file =
            std::fs::File::open(path).map_err(|_| anyhow::anyhow!("cannot read configuration"))?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("cannot read configuration"))?;
        Self::parse_bytes(path, &bytes, load_guidance)
    }

    pub(crate) fn parse_bytes(path: &Path, bytes: &[u8], load_guidance: bool) -> Result<Self> {
        ensure!(bytes.len() <= 65536, "configuration exceeds 64 KiB");
        let text = std::str::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("configuration must be UTF-8"))?;
        // Parser diagnostics may echo secrets accidentally placed in an unknown field.
        let mut config: Self = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid configuration: check field names, types and enum values")
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
            std::env::current_dir()?.join(path)
        };
        let root = absolute
            .parent()
            .context("configuration has no parent directory")?;
        config.state_dir = resolve_path(root, &config.state_dir);
        if !config.network.credential_file.as_os_str().is_empty() {
            config.network.credential_file = resolve_path(root, &config.network.credential_file);
        }
        for model in [&mut config.solver.answer, &mut config.solver.judge] {
            // Bare entrypoints intentionally use PATH; explicit relative paths are config-relative.
            if model.executable.components().count() > 1 {
                model.executable = resolve_path(root, &model.executable);
            }
            if let Some(path) = &mut model.guidance_file {
                *path = resolve_path(root, path);
            }
        }
        config.guidance_loaded = config.solver.answer.guidance_file.is_none()
            && config.solver.judge.guidance_file.is_none();
        if load_guidance {
            for model in [&mut config.solver.answer, &mut config.solver.judge] {
                if let Some(path) = &model.guidance_file {
                    model.guidance = read_guidance(path)?;
                }
            }
            config.guidance_loaded = true;
        }
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_fields(true)
    }

    fn validate_fields(&self, check_guidance_paths: bool) -> Result<()> {
        ensure!(
            self.participation.max_unresolved_operations > 0
                && self.participation.max_answer_attempts_per_epoch > 0,
            "participation operation and answer attempt limits must be positive"
        );
        ensure!(
            self.participation.answer_reserved_slots < self.participation.max_unresolved_operations,
            "participation.answer_reserved_slots must be below max_unresolved_operations"
        );
        ensure!(
            (1..=8).contains(&self.preparation.max_attempts_per_work),
            "preparation.max_attempts_per_work must be between 1 and 8"
        );
        ensure!(
            self.excluded_judging_assignments
                .iter()
                .all(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())),
            "excluded_judging_assignments must contain 64-character hexadecimal transaction IDs"
        );
        validate_origin(&self.network.base_url)?;
        ensure!(
            safe_segment(&self.network.chain, 64),
            "invalid network chain"
        );
        ensure!(
            self.network.address.is_empty() || valid_address(&self.network.address),
            "invalid account address"
        );
        ensure!(
            !self.state_dir.as_os_str().is_empty(),
            "state directory is empty"
        );
        for path in [
            &self.state_dir,
            &self.network.credential_file,
            &self.solver.answer.executable,
            &self.solver.judge.executable,
        ] {
            ensure!(
                !path
                    .as_os_str()
                    .to_string_lossy()
                    .chars()
                    .any(char::is_control),
                "path contains control characters"
            );
            ensure!(
                !path.starts_with("~"),
                "use an absolute or config-relative path, not a tilde"
            );
        }
        for model in [&self.solver.answer, &self.solver.judge] {
            if check_guidance_paths && let Some(path) = &model.guidance_file {
                ensure!(
                    !path.as_os_str().is_empty()
                        && !path.starts_with("~")
                        && !path
                            .as_os_str()
                            .to_string_lossy()
                            .chars()
                            .any(char::is_control),
                    "guidance_file must be an absolute or config-relative path"
                );
            }
            ensure!(
                !model.executable.as_os_str().is_empty(),
                "model executable is empty"
            );
            for value in [&model.model, &model.reasoning] {
                ensure!(
                    !value.trim().is_empty()
                        && value.len() <= 256
                        && !value.chars().any(char::is_control),
                    "invalid model or reasoning setting"
                );
            }
        }
        for (seconds, allow_zero) in [
            (self.timeouts.http_seconds, false),
            (self.timeouts.effective_read_http_seconds(), false),
            (self.participation.uncertainty_grace_seconds, true),
            (self.participation.uncertain_answer_retry_seconds, true),
            (self.timeouts.model_seconds, false),
            (self.timeouts.shutdown_seconds, false),
            (self.schedule.poll_seconds, false),
            (self.schedule.mine_seconds, false),
            (self.schedule.retry_seconds, false),
            (self.schedule.backoff_max_seconds, false),
            (
                self.schedule
                    .challenge_retry_seconds
                    .unwrap_or(self.schedule.retry_seconds),
                false,
            ),
            (
                self.schedule
                    .challenge_backoff_max_seconds
                    .unwrap_or(self.schedule.backoff_max_seconds),
                false,
            ),
            (self.schedule.jitter_seconds, true),
            (
                self.schedule
                    .poll_seconds
                    .saturating_add(self.schedule.jitter_seconds),
                false,
            ),
            (
                self.schedule
                    .backoff_max_seconds
                    .max(self.schedule.retry_seconds)
                    .saturating_add(self.schedule.jitter_seconds),
                false,
            ),
            (
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
        ] {
            ensure!(
                seconds > 0 || allow_zero,
                "timeouts and schedule intervals must be positive (jitter may be zero)"
            );
            let duration = std::time::Duration::from_secs(seconds);
            ensure!(
                std::time::Instant::now().checked_add(duration).is_some()
                    && std::time::SystemTime::now()
                        .checked_add(duration)
                        .and_then(|deadline| deadline.duration_since(std::time::UNIX_EPOCH).ok())
                        .is_some_and(|deadline| deadline.as_millis() <= i64::MAX as u128),
                "timeout or schedule interval overflows a representable deadline"
            );
        }
        if [WorkKind::Answer, WorkKind::Judge, WorkKind::Mine]
            .iter()
            .any(|&kind| self.mode(kind) == Mode::Active)
        {
            ensure!(
                !self.network.address.is_empty()
                    && !self.network.credential_file.as_os_str().is_empty(),
                "active capabilities require an address and credential file"
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

fn read_guidance(path: &Path) -> Result<Arc<str>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("cannot open model guidance file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("cannot inspect model guidance file"))?;
    ensure!(metadata.is_file(), "model guidance must be a regular file");
    ensure!(
        metadata.len() <= MAX_GUIDANCE_BYTES as u64,
        "model guidance exceeds 64 KiB"
    );
    let mut bytes = Vec::new();
    file.take((MAX_GUIDANCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("cannot read model guidance file"))?;
    validate_guidance_bytes(&bytes)
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
pub(crate) fn validate_origin(value: &str) -> Result<reqwest::Url> {
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
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    let production = url.scheme() == "https"
        && url.host_str() == Some("minepoa.com")
        && url.port_or_known_default() == Some(443);
    if !(production || (url.scheme() == "http" && loopback)) {
        bail!(
            "trusted origin must be https://minepoa.com or explicit loopback HTTP development origin"
        );
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn guidance_rejects_binary_oversized_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guidance");
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_guidance(&path).is_err());
        std::fs::write(&path, vec![b'a'; MAX_GUIDANCE_BYTES + 1]).unwrap();
        assert!(read_guidance(&path).is_err());
        assert!(read_guidance(dir.path()).is_err());
    }
}
