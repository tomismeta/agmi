//! Local, private administration. No journal initialization, provider or network calls.
use crate::config::{Config, resolve_path, validate_guidance_bytes};
use crate::store::{AdmissionGuard, admin_identity_initialized};
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_INPUT_BYTES: usize = 65536;
const MAX_DEPTH: usize = 32;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct AdminError(&'static str, &'static str);
impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}
impl std::error::Error for AdminError {}
fn error(code: &'static str, message: &'static str) -> anyhow::Error {
    AdminError(code, message).into()
}
fn invalid() -> anyhow::Error {
    error(
        "admin_validation",
        "Invalid configuration, patch or guidance; check schema, types, bounds and file references.",
    )
}
fn unsafe_file() -> anyhow::Error {
    error(
        "admin_unsafe_file",
        "Administration requires owned regular files without symlinks or hardlinks; guidance files must be private.",
    )
}
fn io_error() -> anyhow::Error {
    error(
        "admin_io",
        "Cannot read or persist administration files; a save may have completed. Reread config and guidance revisions before retrying.",
    )
}
fn conflict() -> anyhow::Error {
    error(
        "admin_revision_conflict",
        "Revision conflict; read the current revision before retrying.",
    )
}
pub fn error_code(error: &anyhow::Error) -> Option<&'static str> {
    error.downcast_ref::<AdminError>().map(|error| error.0)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn check_revision(expected: &str, actual: &str) -> Result<()> {
    if expected != actual {
        return Err(conflict());
    }
    Ok(())
}
fn check_input(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(error(
            "admin_input_too_large",
            "Administration input exceeds 64 KiB.",
        ));
    }
    Ok(())
}

// Canonicalize only the parent: the target itself must never follow a symlink.
fn absolute_target(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(unsafe_file)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| io_error())?;
    Ok(parent.join(name))
}
struct DirectoryLock {
    path: PathBuf,
    _file: File,
}
impl DirectoryLock {
    fn acquire(path: &Path, blocking: bool) -> Result<Self> {
        let parent = path.parent().ok_or_else(unsafe_file)?;
        let file = File::open(parent).map_err(|_| io_error())?;
        let metadata = file.metadata().map_err(|_| io_error())?;
        if !metadata.is_dir() {
            return Err(unsafe_file());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                return Err(unsafe_file());
            }
        }
        if blocking {
            file.lock().map_err(|_| io_error())?;
        } else {
            file.try_lock().map_err(|_| {
                error(
                    "admin_busy",
                    "Another administration command owns the target directory; retry.",
                )
            })?;
        }
        Ok(Self {
            path: parent.to_path_buf(),
            _file: file,
        })
    }
    fn additional(&self, target: &Path) -> Result<Option<Self>> {
        if target.parent() == Some(self.path.as_path()) {
            Ok(None)
        } else {
            // Never wait while holding a different directory: cross-referenced
            // guidance files must not introduce an administration deadlock.
            Self::acquire(target, false).map(Some)
        }
    }
}

/// Hold across the initial configuration read and durable account binding.
/// Acquire before account admission guards; never acquire during guarded reload.
pub struct ConfigDirectoryGuard {
    _lock: DirectoryLock,
}
impl ConfigDirectoryGuard {
    pub(crate) fn additional(&self, path: &Path) -> Result<Option<Self>> {
        let target = absolute_target(path)?;
        self._lock
            .additional(&target)
            .map(|lock| lock.map(|lock| Self { _lock: lock }))
    }
}
pub fn lock_config_directory(path: &Path) -> Result<ConfigDirectoryGuard> {
    let path = absolute_target(path)?;
    Ok(ConfigDirectoryGuard {
        _lock: DirectoryLock::acquire(&path, true)?,
    })
}
fn regular(metadata: &fs::Metadata, private: bool) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(unsafe_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || (private && metadata.mode() & 0o077 != 0)
        {
            return Err(unsafe_file());
        }
    }
    Ok(())
}
pub(crate) fn read_optional(path: &Path, private: bool) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => regular(&metadata, private)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(io_error()),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| unsafe_file())?;
    let metadata = file.metadata().map_err(|_| io_error())?;
    regular(&metadata, private)?;
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| io_error())?;
    check_input(&bytes)?;
    Ok(Some(bytes))
}
fn config_bytes(path: &Path) -> Result<Vec<u8>> {
    read_optional(path, false)?.ok_or_else(|| {
        error(
            "admin_config_missing",
            "Configuration does not exist; initialize it first.",
        )
    })
}
fn parse(path: &Path, bytes: &[u8]) -> Result<Config> {
    Config::parse_bytes(path, bytes, false).map_err(|_| invalid())
}
fn raw_config(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let value: toml::Value = toml::from_str(text).map_err(|_| invalid())?;
    serde_json::to_value(value).map_err(|_| invalid())
}
fn encode(value: Value) -> Result<Vec<u8>> {
    let value: toml::Value = serde_json::from_value(value).map_err(|_| invalid())?;
    let bytes = toml::to_string_pretty(&value)
        .map_err(|_| invalid())?
        .into_bytes();
    check_input(&bytes)?;
    Ok(bytes)
}
fn immutable_changed(old: &Config, new: &Config) -> bool {
    old.network != new.network || old.state_dir != new.state_dir
}
fn identity_guard(old: &Config, new: &Config, dry_run: bool) -> Result<Vec<AdmissionGuard>> {
    let mut guards = Vec::new();
    if !dry_run {
        let key = |config: &Config| {
            digest(format!("{}\n{}", config.network.chain, config.network.address).as_bytes())
        };
        let old_key = key(old);
        let new_key = key(new);
        let (first, second) = if old_key <= new_key {
            (old, new)
        } else {
            (new, old)
        };
        for (index, config) in [first, second].into_iter().enumerate() {
            // An empty account cannot initialize a writer. Do not create a
            // shared default-account gate while populating a fresh template.
            if config.network.address.is_empty() || (index == 1 && old_key == new_key) {
                continue;
            }
            guards.push(AdmissionGuard::acquire(config).map_err(|_| {
                error(
                    "admin_identity_unavailable",
                    "Cannot establish the account identity boundary.",
                )
            })?);
        }
    }
    if !immutable_changed(old, new) {
        return Ok(guards);
    }
    if admin_identity_initialized(old).map_err(|_| {
        error(
            "admin_identity_unavailable",
            "Cannot verify existing account identity; no changes saved.",
        )
    })? || admin_identity_initialized(new).map_err(|_| {
        error(
            "admin_identity_unavailable",
            "Cannot verify candidate account identity; no changes saved.",
        )
    })? {
        return Err(error(
            "admin_identity_immutable",
            "Initialized account, origin, chain, credential reference and state directory cannot be changed.",
        ));
    }
    Ok(guards)
}
fn guidance_target(config_path: &Path, config: &Config, target: &Path) -> Result<PathBuf> {
    let target = absolute_target(target)?;
    let credential = &config.network.credential_file;
    let credential_target = if credential.as_os_str().is_empty() {
        None
    } else {
        // A missing credential parent must not prevent local guidance setup.
        // Existing symlink aliases still reserve their actual credential target.
        Some(
            fs::canonicalize(credential)
                .ok()
                .or_else(|| absolute_target(credential).ok())
                .unwrap_or_else(|| credential.clone()),
        )
    };
    // The whole journal directory is reserved, including SQLite companions and locks.
    let state = fs::canonicalize(&config.state_dir).unwrap_or_else(|_| config.state_dir.clone());
    if target == config_path
        || credential_target.as_ref() == Some(&target)
        || target.starts_with(state)
    {
        return Err(error(
            "admin_unsafe_target",
            "Guidance cannot target configuration, credentials or durable state files.",
        ));
    }
    Ok(target)
}
fn validate_complete(path: &Path, config: &mut Config) -> Result<()> {
    config.validate().map_err(|_| invalid())?;
    let load = |target: &Option<PathBuf>, core: bool| -> Result<std::sync::Arc<str>> {
        if let Some(target) = target {
            let target = guidance_target(path, config, target)?;
            let bytes = read_optional(&target, true)?.ok_or_else(|| {
                error(
                    "admin_guidance_missing",
                    "A configured guidance file is missing.",
                )
            })?;
            let text = validate_guidance_bytes(&bytes).map_err(|_| invalid())?;
            if core && text.trim().is_empty() {
                return Err(invalid());
            }
            Ok(text)
        } else {
            Ok(std::sync::Arc::from(""))
        }
    };
    let answer = load(&config.solver.answer.guidance_file, false)?;
    let judge = load(&config.solver.judge.guidance_file, false)?;
    let answer_core = load(&config.solver.answer.core_guidance_file, true)?;
    let judge_core = load(&config.solver.judge.core_guidance_file, true)?;
    config.solver.answer.guidance = answer;
    config.solver.judge.guidance = judge;
    config.solver.answer.core_guidance = answer_core;
    config.solver.judge.core_guidance = judge_core;
    config.validate_core_guidance().map_err(|_| invalid())?;
    config.guidance_loaded = true;
    Ok(())
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub(crate) fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(unsafe_file)?;
    let (temporary, mut file) = loop {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let name = parent.join(format!(".agmi-admin-{}-{serial}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        match options.open(&name) {
            Ok(file) => break (Temporary(name), file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(io_error()),
        }
    };
    file.write_all(bytes).map_err(|_| io_error())?;
    file.sync_all().map_err(|_| io_error())?;
    fs::rename(&temporary.0, path).map_err(|_| io_error())?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    Ok(())
}
fn defaults() -> Value {
    let mut value =
        serde_json::to_value(Config::default()).expect("Config serialization is infallible");
    value["timeouts"]["read_http_seconds"] = Value::Null;
    value["schedule"]["challenge_retry_seconds"] = Value::Null;
    value["schedule"]["challenge_backoff_max_seconds"] = Value::Null;
    value["schedule"]["queued_job_polling"] = Value::Null;
    value["solver"]["answer"]["guidance_file"] = Value::Null;
    value["solver"]["judge"]["guidance_file"] = Value::Null;
    value["solver"]["answer"]["core_guidance_file"] = Value::Null;
    value["solver"]["judge"]["core_guidance_file"] = Value::Null;
    value["excluded_judging_assignments"] = json!([]);
    value
}
fn patch_shape() -> Value {
    let mut shape = defaults();
    // Optional objects have no enabled default, but their fields still belong
    // to the patch allowlist. Config validation owns types and bounds.
    shape["schedule"]["queued_job_polling"] = json!({"initial_seconds":1,"max_seconds":1});
    shape
}
fn describe(path: &str, value: &Value, settings: &mut Vec<Value>) {
    if let Some(object) = value.as_object() {
        for (name, value) in object {
            let child = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            describe(&child, value, settings);
        }
        return;
    }
    let kind = match value {
        Value::Bool(_) => "boolean",
        Value::Number(_) => "integer",
        Value::Array(_) => "array<string>",
        Value::Null if path == "schedule.queued_job_polling" => "object|null",
        Value::Null
            if matches!(
                path,
                "timeouts.read_http_seconds"
                    | "schedule.challenge_retry_seconds"
                    | "schedule.challenge_backoff_max_seconds"
            ) =>
        {
            "integer|null"
        }
        Value::Null => "string|null",
        _ => "string",
    };
    let choices = if path.starts_with("capabilities.") {
        json!(["active", "read_only", "off"])
    } else if path.ends_with(".harness") {
        json!(["hermes", "openclaw"])
    } else if path == "participation.mode" {
        json!(["strict", "participation_first", "manual"])
    } else {
        Value::Null
    };
    let mut setting = json!({"path":path,"type":kind,"default":value,"enum":choices,
            "immutable_when_initialized":path.starts_with("network.") || path == "state_dir"});
    if path == "schedule.queued_job_polling" {
        setting["properties"] = json!({
            "initial_seconds":{"type":"integer","minimum":1},
            "max_seconds":{"type":"integer","minimum":1}
        });
        setting["required"] = json!(["initial_seconds", "max_seconds"]);
        setting["constraint"] = json!("initial_seconds <= max_seconds; null disables the policy");
    }
    settings.push(setting);
}
pub fn schema() -> Value {
    let defaults = defaults();
    let mut settings = Vec::new();
    describe("", &defaults, &mut settings);
    json!({"schema":"agmi.config.v1","settings":settings,"defaults":defaults,
        "guidance":{"layers":["core","user"],"default_layer":"user",
            "core":"Required nonempty core_guidance_file for active answer/judge routes; no embedded fallback.",
            "user":"Optional guidance_file; voice and preferences subordinate to core guidance.",
            "reload":"Both files reload with configuration; each model attempt captures both layers privately."},
        "max_input_bytes":MAX_INPUT_BYTES,"patch":"nested JSON merge patch; null removes a field; the resulting TOML must pass Config validation",
        "persistence":"canonical TOML; comments and formatting are not preserved",
        "runtime_applied":null,"runtime_application":"unverified","note":"Saved files are loaded by the runtime separately; status reports its effective revision."})
}
fn validate_patch(patch: &Value, shape: &Value, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid());
    }
    if let Some(object) = patch.as_object() {
        let fields = shape.as_object().ok_or_else(invalid)?;
        for (key, value) in object {
            let field = fields.get(key).ok_or_else(invalid)?;
            validate_patch(value, field, depth + 1)?;
        }
    } else if let Some(array) = patch.as_array()
        && (!shape.is_array() || array.iter().any(|v| !v.is_string()))
    {
        return Err(invalid());
    }
    Ok(())
}
fn merge(target: &mut Value, patch: Value) {
    if let Value::Object(patch) = patch {
        if !target.is_object() {
            *target = json!({});
        }
        let object = target.as_object_mut().expect("object initialized");
        for (key, value) in patch {
            if value.is_null() {
                object.remove(&key);
            } else {
                merge(object.entry(key).or_insert(Value::Null), value);
            }
        }
    } else {
        *target = patch;
    }
}
pub fn file_revision(path: &Path) -> Result<String> {
    let path = absolute_target(path)?;
    let _lock = DirectoryLock::acquire(&path, true)?;
    Ok(digest(&config_bytes(&path)?))
}
pub fn show(path: &Path) -> Result<Value> {
    let source_path = path;
    let path = absolute_target(path)?;
    let _lock = DirectoryLock::acquire(&path, true)?;
    let bytes = config_bytes(&path)?;
    let config = parse(source_path, &bytes)?;
    Ok(json!({"config":config,"file_revision":digest(&bytes),
        "revision":config.optional_revision().map_err(|_| invalid())?,"guidance_validation":"not_loaded"}))
}
pub fn apply(
    path: &Path,
    expected_revision: &str,
    patch_bytes: &[u8],
    dry_run: bool,
) -> Result<Value> {
    check_input(patch_bytes)?;
    let patch: Value = serde_json::from_slice(patch_bytes).map_err(|_| invalid())?;
    if !patch.is_object() {
        return Err(invalid());
    }
    validate_patch(&patch, &patch_shape(), 0)?;
    let source_path = path;
    let path = absolute_target(path)?;
    let _lock = DirectoryLock::acquire(&path, true)?;
    let old_bytes = config_bytes(&path)?;
    let old_revision = digest(&old_bytes);
    check_revision(expected_revision, &old_revision)?;
    let old = parse(source_path, &old_bytes)?;
    let mut value = raw_config(&old_bytes)?;
    merge(&mut value, patch);
    let bytes = encode(value)?;
    let mut candidate = parse(source_path, &bytes)?;
    validate_complete(&path, &mut candidate)?;
    let revision = candidate.revision().map_err(|_| invalid())?;
    let _identity = identity_guard(&old, &candidate, dry_run)?;
    if !dry_run {
        persist(&path, &bytes)?;
    }
    Ok(
        json!({"saved":!dry_run,"dry_run":dry_run,"file_revision":if dry_run { old_revision.clone() } else { digest(&bytes) },
        "previous_file_revision":old_revision,"candidate_file_revision":digest(&bytes),"revision":revision,
        "runtime_applied":null,"runtime_application":"unverified",
        "note":"Configuration is canonicalized on save. Runtime status reports the effective loaded revision; dry-run validates a snapshot only."}),
    )
}
fn model<'a>(config: &'a Config, kind: &str) -> Result<&'a crate::config::ModelConfig> {
    match kind {
        "answer" => Ok(&config.solver.answer),
        "judge" => Ok(&config.solver.judge),
        _ => Err(invalid()),
    }
}
fn guidance_field(layer: &str) -> Result<&'static str> {
    match layer {
        "core" => Ok("core_guidance_file"),
        "user" => Ok("guidance_file"),
        _ => Err(invalid()),
    }
}
fn conventional_guidance(kind: &str, layer: &str) -> String {
    if layer == "core" {
        format!("{kind}-core-guidance.md")
    } else {
        format!("{kind}-guidance.md")
    }
}
fn selected_target(
    path: &Path,
    config: &Config,
    kind: &str,
    layer: &str,
) -> Result<(PathBuf, bool)> {
    guidance_field(layer)?;
    let selected = model(config, kind)?;
    let reference = if layer == "core" {
        &selected.core_guidance_file
    } else {
        &selected.guidance_file
    };
    let configured = reference.is_some();
    let target = reference.clone().unwrap_or_else(|| {
        resolve_path(
            path.parent().expect("absolute parent"),
            Path::new(&conventional_guidance(kind, layer)),
        )
    });
    Ok((guidance_target(path, config, &target)?, configured))
}
pub fn guidance_show(path: &Path, kind: &str, layer: &str) -> Result<Value> {
    let source_path = path;
    let path = absolute_target(path)?;
    let lock = DirectoryLock::acquire(&path, true)?;
    let bytes = config_bytes(&path)?;
    let config = parse(source_path, &bytes)?;
    let (target, configured) = selected_target(&path, &config, kind, layer)?;
    let _guidance_lock = lock.additional(&target)?;
    let guidance = read_optional(&target, true)?;
    let content = guidance
        .as_ref()
        .map(|b| validate_guidance_bytes(b).map(|s| s.to_string()))
        .transpose()
        .map_err(|_| invalid())?;
    Ok(
        json!({"private":true,"kind":kind,"layer":layer,"configured":configured,
        "status":if !configured { "unconfigured" } else if guidance.is_none() { "missing" } else { "present" },
        "guidance_revision":guidance.as_ref().map(|b| digest(b)).unwrap_or_else(|| "missing".into()),
        "config_file_revision":digest(&bytes),"content":content,
        "note":"Private guidance content; never forward to public events. Unconfigured content, if present, is an inactive conventional file."}),
    )
}
pub fn guidance_set(
    path: &Path,
    kind: &str,
    layer: &str,
    expected_config_revision: &str,
    expected_guidance_revision: &str,
    content_bytes: &[u8],
    dry_run: bool,
) -> Result<Value> {
    check_input(content_bytes)?;
    let content = validate_guidance_bytes(content_bytes).map_err(|_| invalid())?;
    let field = guidance_field(layer)?;
    if layer == "core" && content.trim().is_empty() {
        return Err(invalid());
    }
    let source_path = path;
    let path = absolute_target(path)?;
    let lock = DirectoryLock::acquire(&path, true)?;
    let bytes = config_bytes(&path)?;
    check_revision(expected_config_revision, &digest(&bytes))?;
    let config = parse(source_path, &bytes)?;
    config.validate().map_err(|_| invalid())?;
    let (target, configured) = selected_target(&path, &config, kind, layer)?;
    let _guidance_lock = lock.additional(&target)?;
    let old = read_optional(&target, true)?;
    let old_revision = old
        .as_ref()
        .map(|b| digest(b))
        .unwrap_or_else(|| "missing".into());
    check_revision(expected_guidance_revision, &old_revision)?;
    let next_config = if configured {
        None
    } else {
        let mut value = raw_config(&bytes)?;
        let mut patch = json!({"solver":{}});
        patch["solver"][kind] = json!({(field):conventional_guidance(kind, layer)});
        merge(&mut value, patch);
        let next = encode(value)?;
        parse(source_path, &next)?
            .validate()
            .map_err(|_| invalid())?;
        Some(next)
    };
    if !dry_run {
        // Content is durable before activating its reference. A crash can leave
        // an inactive conventional file, never an active partial/missing file.
        persist(&target, content_bytes)?;
        if let Some(next) = &next_config {
            persist(&path, next)?;
        }
    }
    let current_config = if dry_run {
        &bytes
    } else {
        next_config.as_ref().unwrap_or(&bytes)
    };
    Ok(
        json!({"private":true,"kind":kind,"layer":layer,"saved":!dry_run,"dry_run":dry_run,
        "guidance_revision":if dry_run { old_revision } else { digest(content_bytes) },
        "candidate_guidance_revision":digest(content_bytes),"config_file_revision":digest(current_config),
        "candidate_config_file_revision":digest(next_config.as_ref().unwrap_or(&bytes)),
        "configured":configured || !dry_run,"runtime_applied":null,"runtime_application":"unverified",
        "note":"Private guidance saved locally only; runtime status reports the effective loaded revision."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_layers_are_discoverable_and_updated_independently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, toml::to_string(&Config::default()).unwrap()).unwrap();
        assert_eq!(schema()["guidance"]["layers"], json!(["core", "user"]));
        for kind in ["answer", "judge"] {
            for layer in ["core", "user"] {
                let before = guidance_show(&path, kind, layer).unwrap();
                assert_eq!(before["status"], "unconfigured");
                let config_revision = before["config_file_revision"].as_str().unwrap();
                let content = format!("{kind} {layer} private instructions");
                let preview = guidance_set(
                    &path,
                    kind,
                    layer,
                    config_revision,
                    "missing",
                    content.as_bytes(),
                    true,
                )
                .unwrap();
                assert_eq!(preview["saved"], false);
                assert!(!dir.path().join(conventional_guidance(kind, layer)).exists());
                guidance_set(
                    &path,
                    kind,
                    layer,
                    config_revision,
                    "missing",
                    content.as_bytes(),
                    false,
                )
                .unwrap();
                let after = guidance_show(&path, kind, layer).unwrap();
                assert_eq!(after["status"], "present");
                assert_eq!(after["layer"], layer);
                assert_eq!(after["content"], content);
                assert!(
                    guidance_set(
                        &path,
                        kind,
                        layer,
                        config_revision,
                        "missing",
                        b"stale",
                        false,
                    )
                    .is_err()
                );
            }
        }
        let loaded = Config::load(&path).unwrap();
        assert_eq!(
            &*loaded.solver.answer.core_guidance,
            "answer core private instructions"
        );
        assert_eq!(
            &*loaded.solver.answer.guidance,
            "answer user private instructions"
        );
        assert_eq!(
            &*loaded.solver.judge.core_guidance,
            "judge core private instructions"
        );
        assert_eq!(
            &*loaded.solver.judge.guidance,
            "judge user private instructions"
        );
        let current = guidance_show(&path, "answer", "core").unwrap();
        assert!(
            guidance_set(
                &path,
                "answer",
                "core",
                current["config_file_revision"].as_str().unwrap(),
                current["guidance_revision"].as_str().unwrap(),
                b" \n",
                false,
            )
            .is_err()
        );
        assert!(guidance_show(&path, "answer", "unknown").is_err());
    }
}
