//! Explicit hosted registration. Immutable intent fences replay, not key loss:
//! remote creation can precede durable local capture and permanently lose access.
use crate::{
    admin,
    config::{Config, NetworkConfig, safe_segment, valid_address, validate_origin_with_trust},
    endpoints::{ApiEndpoints, Endpoint},
    protocol,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_BODY: usize = 1024 * 1024;
const MAX_CAPTURE: usize = MAX_BODY * 5 + 65536;
const MAX_ATTEMPTS: u32 = 10000;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const RISK: &str = "Remote creation can succeed before its one-time API key is durable locally. A crash or lost response in that interval can permanently lose access. A retained intent prevents another POST, but cannot recover a lost key. This creates a hosted identity, not a self-custody key.";

pub struct CreateOptions {
    pub label: String,
    pub chain: String,
    pub base_url: String,
    pub invited_by: Option<String>,
    pub pow_seconds: u64,
    pub http_seconds: u64,
    pub max_pow_bits: u32,
    pub max_pow_hashes: u64,
    pub expected_pow_algo: Option<String>,
    pub retry_rejected: bool,
    pub api: ApiEndpoints,
    pub trusted_origins: Vec<String>,
}

#[derive(Debug)]
struct RegistrationError {
    code: &'static str,
    message: &'static str,
    details: Value,
}
impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for RegistrationError {}
pub fn error_details(error: &anyhow::Error) -> Option<(&'static str, &'static str, Value)> {
    error
        .downcast_ref::<RegistrationError>()
        .map(|error| (error.code, error.message, error.details.clone()))
}
fn error(code: &'static str, message: &'static str, details: Value) -> anyhow::Error {
    RegistrationError {
        code,
        message,
        details,
    }
    .into()
}
fn unsafe_file() -> anyhow::Error {
    error(
        "registration_unsafe_file",
        "Registration requires owned private directories and regular single-link files without symlinks; nothing is overwritten.",
        json!({}),
    )
}
fn io_error() -> anyhow::Error {
    error(
        "registration_io",
        "Registration storage is unavailable. Files may already be retained; inspect identity status locally before taking further action.",
        json!({}),
    )
}
fn conflict() -> anyhow::Error {
    error(
        "registration_conflict",
        "Existing identity or registration evidence conflicts with this request. Keep all files; registration never replaces identity or evidence.",
        json!({}),
    )
}
fn unknown() -> anyhow::Error {
    error(
        "registration_outcome_unknown",
        "Registration outcome is unknown. Another POST is forbidden; retain all evidence. A remote identity may exist with an unrecoverable key.",
        json!({"stage":"outcome_unknown","retry_allowed":false}),
    )
}
fn sanitize(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<RegistrationError>().is_some() {
        error
    } else {
        io_error()
    }
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| io_error())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct Paths {
    config: PathBuf,
    parent: PathBuf,
    credential: PathBuf,
    metadata: PathBuf,
    network: PathBuf,
    state: PathBuf,
}
impl Paths {
    fn new(config: &Path) -> Result<Self> {
        let config = if config.is_absolute() {
            config.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| io_error())?
                .join(config)
        };
        let parent = config.parent().ok_or_else(unsafe_file)?.to_path_buf();
        let name = config
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(unsafe_file)?;
        if name == "credential"
            || name == "state"
            || name == "network.toml"
            || name.starts_with("registration")
        {
            return Err(conflict());
        }
        Ok(Self {
            credential: parent.join("credential"),
            metadata: parent.join("registration.json"),
            network: parent.join("network.toml"),
            state: parent.join("state"),
            config,
            parent,
        })
    }
    fn intent(&self, attempt: u32) -> PathBuf {
        self.parent
            .join(format!("registration-{attempt:06}.intent.json"))
    }
    fn capture(&self, attempt: u32) -> PathBuf {
        self.parent
            .join(format!("registration-{attempt:06}.capture.json"))
    }
}
fn regular(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(unsafe_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(unsafe_file());
        }
    }
    Ok(())
}
fn parent_exists(paths: &Paths) -> Result<bool> {
    let metadata = match fs::symlink_metadata(&paths.parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(io_error()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(unsafe_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(unsafe_file());
        }
    }
    Ok(true)
}
fn read_private(path: &Path, maximum: usize) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => regular(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
    regular(&metadata)?;
    if metadata.len() > maximum as u64 {
        return Err(unknown());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| io_error())?;
    if bytes.len() > maximum {
        return Err(unknown());
    }
    Ok(Some(bytes))
}
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())
}

fn create_parent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => return Ok(()),
        Ok(_) => return Err(unsafe_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(io_error()),
    }
    let parent = path.parent().ok_or_else(unsafe_file)?;
    create_parent(parent)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| io_error())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(unsafe_file());
            }
        }
        Err(_) => return Err(io_error()),
    }
    sync_directory(path)?;
    sync_directory(parent)
}
/// Direct create-only files intentionally retain partial writes as a fence.
fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|_| io_error())?;
    regular(&file.metadata().map_err(|_| io_error())?)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| io_error())?;
    sync_directory(path.parent().ok_or_else(unsafe_file)?)
}
fn sync_private(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| unsafe_file())?;
    regular(&file.metadata().map_err(|_| io_error())?)?;
    file.sync_all().map_err(|_| io_error())?;
    sync_directory(path.parent().ok_or_else(unsafe_file)?)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Unlike intent/capture fences, derived files must become visible only when complete.
fn publish_derived(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(unsafe_file)?;
    let (temporary, mut file) = loop {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let name = parent.join(format!(
            ".agmi-registration-{}-{serial}.tmp",
            std::process::id()
        ));
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
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(io_error()),
        }
    };
    regular(&file.metadata().map_err(|_| io_error())?)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| io_error())?;
    rename_no_replace(&temporary.0, path)?;
    sync_directory(parent)
}

fn rename_no_replace(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| unsafe_file())?;
        let destination =
            CString::new(destination.as_os_str().as_bytes()).map_err(|_| unsafe_file())?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result =
            unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
        if result == 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
            return Err(conflict());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (source, destination);
    // Never fall back to overwrite or link/unlink (a crash could retain two links).
    Err(io_error())
}
fn publish_matching(path: &Path, bytes: &[u8]) -> Result<()> {
    match read_private(path, MAX_CAPTURE)? {
        Some(existing) if existing == bytes => sync_private(path),
        Some(_) => Err(conflict()),
        None => publish_derived(path, bytes),
    }
}
fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(conflict()),
        Err(_) => Err(io_error()),
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    config_file: PathBuf,
    credential_file: PathBuf,
    state_dir: PathBuf,
    label: String,
    chain: String,
    base_url: String,
    invited_by: Option<String>,
    api: ApiEndpoints,
    trusted_origins: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: u32,
    attempt: u32,
    created_at: u64,
    binding: Binding,
    challenge: String,
    nonce: String,
    bits: u32,
    expires_ts: u64,
    algo: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: u32,
    intent_sha256: String,
    status: u16,
    received_at: u64,
    retry_after_seconds: Option<u64>,
    retry_after_invalid: bool,
    body_sha256: String,
    body_len: usize,
    body: Vec<u8>,
    complete: bool,
}
struct Saved {
    intent: Intent,
    intent_hash: String,
    capture: Option<Capture>,
}
enum Outcome {
    Created {
        address: String,
        key: String,
    },
    Rejected {
        code: &'static str,
        retry_not_before: u64,
    },
    Unknown,
}
fn classify(saved: &Saved) -> Outcome {
    let Some(capture) = &saved.capture else {
        return Outcome::Unknown;
    };
    let Ok(body) = serde_json::from_slice::<Value>(&capture.body) else {
        return Outcome::Unknown;
    };
    let Some(object) = body.as_object() else {
        return Outcome::Unknown;
    };
    if capture.status == 200 && body.get("ok").and_then(Value::as_bool) == Some(true) {
        let (Some(address), Some(key)) = (
            body.get("address").and_then(Value::as_str),
            body.get("api_key").and_then(Value::as_str),
        ) else {
            return Outcome::Unknown;
        };
        if valid_address(address)
            && key.starts_with("pk_")
            && key.len() >= 4
            && safe_segment(key, 4096)
            && body
                .get("chain_id")
                .is_none_or(|value| value.as_str() == Some(saved.intent.binding.chain.as_str()))
        {
            return Outcome::Created {
                address: address.into(),
                key: key.into(),
            };
        }
        return Outcome::Unknown;
    }
    // Only complete documented rejection shapes grant a fresh-attempt authority.
    if ["address", "api_key", "join_txid"]
        .iter()
        .any(|key| object.contains_key(*key))
        || body
            .get("ok")
            .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Outcome::Unknown;
    }
    let body_delay = body.get("retry_after_seconds").and_then(Value::as_u64);
    if capture.retry_after_invalid
        || (body.get("retry_after_seconds").is_some() && body_delay.is_none())
    {
        return Outcome::Unknown;
    }
    let delay = capture
        .retry_after_seconds
        .unwrap_or(0)
        .max(body_delay.unwrap_or(0));
    let code = if capture.status == 403
        && body
            .get("required_bits")
            .and_then(Value::as_u64)
            .is_some_and(|bits| bits <= 256)
        && body
            .get("get_challenge")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
    {
        "proof_rejected"
    } else if capture.status == 429 && body_delay.is_some() {
        "rate_limited"
    } else {
        return Outcome::Unknown;
    };
    // Epoch seconds round down; add one second for any nonzero server minimum.
    Outcome::Rejected {
        code,
        retry_not_before: capture
            .received_at
            .saturating_add(delay)
            .saturating_add(u64::from(delay != 0)),
    }
}
fn last_attempt(paths: &Paths) -> Result<Option<Saved>> {
    if !parent_exists(paths)? {
        return Ok(None);
    }
    let mut files = std::collections::BTreeMap::<u32, (bool, bool)>::new();
    for entry in fs::read_dir(&paths.parent).map_err(|_| io_error())? {
        let entry = entry.map_err(|_| io_error())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("registration-") {
            continue;
        }
        let (number, capture) = if let Some(number) = name
            .strip_prefix("registration-")
            .and_then(|name| name.strip_suffix(".intent.json"))
        {
            (number, false)
        } else if let Some(number) = name
            .strip_prefix("registration-")
            .and_then(|name| name.strip_suffix(".capture.json"))
        {
            (number, true)
        } else {
            return Err(unknown());
        };
        let attempt = number.parse::<u32>().map_err(|_| unknown())?;
        if attempt == 0 || attempt > MAX_ATTEMPTS || number != format!("{attempt:06}") {
            return Err(unknown());
        }
        let presence = files.entry(attempt).or_default();
        if capture {
            presence.1 = true;
        } else {
            presence.0 = true;
        }
    }
    let mut saved: Option<Saved> = None;
    for (index, (attempt, (has_intent, has_capture))) in files.into_iter().enumerate() {
        if saved
            .as_ref()
            .is_some_and(|previous| !matches!(classify(previous), Outcome::Rejected { .. }))
        {
            return Err(unknown());
        }
        drop(saved.take());
        if !has_intent || attempt as usize != index + 1 {
            return Err(unknown());
        }
        let bytes = read_private(&paths.intent(attempt), 65536)?.ok_or_else(unknown)?;
        let intent: Intent = serde_json::from_slice(&bytes).map_err(|_| unknown())?;
        if intent.schema != 1
            || intent.attempt != attempt
            || intent.binding.config_file != paths.config
            || intent.binding.credential_file != paths.credential
            || intent.binding.state_dir != paths.state
        {
            return Err(unknown());
        }
        let intent_hash = digest(&bytes);
        let capture = if has_capture {
            let bytes = read_private(&paths.capture(attempt), MAX_CAPTURE)?.ok_or_else(unknown)?;
            let capture: Capture = serde_json::from_slice(&bytes).map_err(|_| unknown())?;
            if capture.schema != 1
                || !capture.complete
                || capture.intent_sha256 != intent_hash
                || capture.body_len != capture.body.len()
                || capture.body.len() > MAX_BODY
                || capture.body_sha256 != digest(&capture.body)
                || !(100..=599).contains(&capture.status)
            {
                return Err(unknown());
            }
            Some(capture)
        } else {
            None
        };
        saved = Some(Saved {
            intent,
            intent_hash,
            capture,
        });
    }
    Ok(saved)
}
fn binding(paths: &Paths, options: &CreateOptions) -> Result<Binding> {
    options.api.validate().map_err(|_| {
        error(
            "registration_invalid_routes",
            "Registration requires complete, chain-pinned validated endpoint templates.",
            json!({}),
        )
    })?;
    let origin =
        validate_origin_with_trust(&options.base_url, &options.trusted_origins).map_err(|_| {
            error(
                "registration_invalid_options",
                "Use a trusted network origin and valid finite registration limits.",
                json!({}),
            )
        })?;
    if !safe_segment(&options.chain, 64)
        || options.label.is_empty()
        || options.label.len() > 256
        || options.label.chars().any(char::is_control)
        || options
            .invited_by
            .as_ref()
            .is_some_and(|value| !valid_address(value))
        || !(1..=3600).contains(&options.pow_seconds)
        || !(1..=3600).contains(&options.http_seconds)
        || options.max_pow_bits > 256
        || !(1..=(1u64 << 40)).contains(&options.max_pow_hashes)
        || options.expected_pow_algo.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
        })
    {
        return Err(error(
            "registration_invalid_options",
            "Use a nonempty label, valid chain/referral, and finite registration limits (seconds 1..3600, bits 0..256, hashes 1..1099511627776).",
            json!({}),
        ));
    }
    Ok(Binding {
        config_file: paths.config.clone(),
        credential_file: paths.credential.clone(),
        state_dir: paths.state.clone(),
        label: options.label.clone(),
        chain: options.chain.clone(),
        base_url: origin.as_str().trim_end_matches('/').into(),
        invited_by: options.invited_by.clone(),
        api: options.api.clone(),
        trusted_origins: options.trusted_origins.clone(),
    })
}

struct Proof {
    challenge: String,
    bits: u32,
    expires_ts: u64,
    algo: String,
}
fn proof(body: &[u8], options: &CreateOptions) -> Result<Proof> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        error(
            "registration_invalid_challenge",
            "Challenge is malformed; no registration was sent.",
            json!({}),
        )
    })?;
    let invalid = || {
        error(
            "registration_invalid_challenge",
            "Challenge is malformed or expired; no registration was sent.",
            json!({}),
        )
    };
    let challenge = value
        .get("challenge")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4096)
        .ok_or_else(invalid)?;
    let bits = value
        .get("bits")
        .and_then(Value::as_u64)
        .filter(|bits| *bits <= 256)
        .ok_or_else(invalid)? as u32;
    let expires_ts = value
        .get("expires_ts")
        .and_then(Value::as_u64)
        .filter(|time| *time > now().unwrap_or(u64::MAX))
        .ok_or_else(invalid)?;
    let algo = value
        .get("algo")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(invalid)?;
    if options.expected_pow_algo.as_deref() != Some(algo) {
        let safe_tag = (safe_segment(algo, 128) && !algo.starts_with("pk_")).then_some(algo);
        return Err(error(
            "registration_pow_algorithm_unbound",
            "No upstream algorithm tag is assumed. Verify this tag denotes SHA256(challenge + ':' + decimal nonce) leading-zero bits, then explicitly bind --expected-pow-algo. No registration was sent.",
            json!({"negotiated_pow_algo":safe_tag,"expected_tag_matches":false}),
        ));
    }
    if bits > options.max_pow_bits {
        return Err(error(
            "registration_pow_difficulty",
            "Challenge exceeds the explicit difficulty limit; no registration was sent and the limit was not raised.",
            json!({"bits":bits,"max_pow_bits":options.max_pow_bits}),
        ));
    }
    Ok(Proof {
        challenge: challenge.into(),
        bits,
        expires_ts,
        algo: algo.into(),
    })
}
fn decimal(mut value: u64, buffer: &mut [u8; 20]) -> &[u8] {
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &buffer[start..];
        }
    }
}
fn leading_zero_bits(hash: &[u8], bits: u32) -> bool {
    let bytes = (bits / 8) as usize;
    let remainder = bits % 8;
    hash[..bytes].iter().all(|byte| *byte == 0)
        && (remainder == 0 || hash[bytes].leading_zeros() >= remainder)
}
async fn mine(proof: &Proof, options: &CreateOptions) -> Result<String> {
    let start = Instant::now();
    let mut prefix = Sha256::new();
    prefix.update(proof.challenge.as_bytes());
    prefix.update(b":");
    let mut buffer = [0u8; 20];
    for nonce in 0..options.max_pow_hashes {
        if nonce % 1024 == 0 {
            tokio::task::yield_now().await;
            if start.elapsed() >= Duration::from_secs(options.pow_seconds)
                || now()? >= proof.expires_ts
            {
                return Err(error(
                    "registration_pow_deadline",
                    "Mining deadline or challenge expiry reached; no registration was sent. No challenge was automatically replaced.",
                    json!({}),
                ));
            }
        }
        let digits = decimal(nonce, &mut buffer);
        let mut hash = prefix.clone();
        hash.update(digits);
        if leading_zero_bits(&hash.finalize(), proof.bits) {
            if start.elapsed() >= Duration::from_secs(options.pow_seconds)
                || now()? >= proof.expires_ts
            {
                return Err(error(
                    "registration_pow_deadline",
                    "Mining deadline or challenge expiry reached; no registration was sent.",
                    json!({}),
                ));
            }
            return Ok(std::str::from_utf8(digits).expect("decimal ASCII").into());
        }
    }
    Err(error(
        "registration_pow_exhausted",
        "The hash budget was exhausted; no registration was sent and no challenge was automatically replaced.",
        json!({"max_pow_hashes":options.max_pow_hashes}),
    ))
}

fn init_action(saved: &Saved, address: &str) -> Value {
    let binding = &saved.intent.binding;
    json!({"kind":"command","authorization_required":true,"argv":["agmi","--config",binding.config_file,"init","--network-config",binding.config_file.parent().map(|parent| parent.join("network.toml")),"--account",address,"--chain",binding.chain,"--base-url",binding.base_url,"--api-key-file",binding.credential_file,"--state-dir",binding.state_dir],"description":"Verify the saved hosted credential and initialize a paused local configuration; no additional registration."})
}
fn resume_action(paths: &Paths) -> Value {
    json!({"kind":"command","authorization_required":true,"argv":["agmi","--config",paths.config,"identity","resume","--confirm"],"description":"Validate the retained successful response and finish create-only local publication; no network requests or new registration."})
}
fn summary(
    paths: &Paths,
    saved: &Saved,
    outcome: Outcome,
    publish_identity: bool,
) -> Result<Value> {
    match outcome {
        Outcome::Unknown => Ok(
            json!({"stage":"outcome_unknown","attempt":saved.intent.attempt,"retry_allowed":false,"credential_saved":false,"note":"Retain all evidence. Another registration POST is forbidden; the remote identity and one-time key may be unrecoverable."}),
        ),
        Outcome::Rejected {
            code,
            retry_not_before,
        } => Ok(
            json!({"stage":"rejected","attempt":saved.intent.attempt,"rejection":code,"retry_not_before":retry_not_before,"retry_after_seconds":retry_not_before.saturating_sub(now()?),"retry_allowed":now()? >= retry_not_before,"created":false,"note":"A fresh attempt requires explicit identity create --confirm --retry-rejected after the retained deadline, with the same identity options. Previous evidence is preserved."}),
        ),
        Outcome::Created { address, key } => {
            let metadata = json!({"schema":1,"attempt":saved.intent.attempt,"intent_sha256":saved.intent_hash,"account":address,"chain":saved.intent.binding.chain,"base_url":saved.intent.binding.base_url,"credential_file":paths.credential,"config_file":paths.config,"state_dir":paths.state});
            let metadata_bytes = serde_json::to_vec(&metadata).map_err(|_| io_error())?;
            let existing_key = read_private(&paths.credential, 4096)?;
            let credential_matches_capture =
                existing_key.as_deref().map(|bytes| bytes == key.as_bytes());
            if publish_identity && credential_matches_capture == Some(false) {
                return Err(conflict());
            }
            let existing_metadata = read_private(&paths.metadata, 65536)?;
            if existing_metadata
                .as_deref()
                .is_some_and(|bytes| bytes != metadata_bytes.as_slice())
            {
                return Err(conflict());
            }
            let bound = &saved.intent.binding;
            if !safe_segment(&bound.chain, 64)
                || bound.api.validate().is_err()
                || validate_origin_with_trust(&bound.base_url, &bound.trusted_origins).is_err()
            {
                return Err(conflict());
            }
            let network = NetworkConfig {
                base_url: bound.base_url.clone(),
                chain: bound.chain.clone(),
                address: String::new(),
                credential_file: PathBuf::new(),
                api: bound.api.clone(),
                trusted_origins: bound.trusted_origins.clone(),
            };
            let network_bytes = toml::to_string_pretty(&network)
                .map_err(|_| io_error())?
                .into_bytes();
            let existing_network = read_private(&paths.network, 65536)?;
            if existing_network
                .as_deref()
                .is_some_and(|bytes| bytes != network_bytes.as_slice())
            {
                return Err(conflict());
            }
            let config = admin::read_optional(&paths.config, false).map_err(|_| unsafe_file())?;
            if let Some(bytes) = &config {
                let config =
                    Config::parse_bytes(&paths.config, bytes, false).map_err(|_| conflict())?;
                if config.network.address != address
                    || config.network.chain != saved.intent.binding.chain
                    || config
                        .network
                        .origin()
                        .map_err(|_| conflict())?
                        .as_str()
                        .trim_end_matches('/')
                        != saved.intent.binding.base_url
                    || config.network.credential_file != paths.credential
                    || config.state_dir != paths.state
                    || config.network.api != bound.api
                    || config.network.trusted_origins != bound.trusted_origins
                {
                    return Err(conflict());
                }
            }
            if publish_identity {
                publish_matching(&paths.credential, key.as_bytes())?;
                publish_matching(&paths.metadata, &metadata_bytes)?;
                publish_matching(&paths.network, &network_bytes)?;
            }
            let credential_saved = publish_identity || existing_key.is_some();
            let complete = credential_saved
                && (publish_identity || existing_metadata.is_some())
                && (publish_identity || existing_network.is_some());
            let stage = if config.is_some() && complete {
                "configured"
            } else if complete {
                "created"
            } else {
                "response_captured"
            };
            let note = if !publish_identity && credential_matches_capture == Some(false) {
                "Historical registration succeeded, but the current credential differs from its captured response. This history does not verify the current credential or establish why it changed; local publication will not overwrite it."
            } else if complete {
                "Hosted registration is not verified initialization, controller liveness, participation or ledger finality."
            } else {
                "The complete response is retained privately. Confirm identity resume to finish local-only publication from retained evidence; no registration is resent."
            };
            Ok(
                json!({"stage":stage,"attempt":saved.intent.attempt,"created":true,"credential_saved":credential_saved,"current_credential_matches_registration":if publish_identity { Some(true) } else { credential_matches_capture },"current_credential_verified":false,"metadata_saved":publish_identity || existing_metadata.is_some(),"network_config_saved":publish_identity || existing_network.is_some(),"network_config_file":paths.network,"account":address,"chain":saved.intent.binding.chain,"base_url":saved.intent.binding.base_url,"credential_file":paths.credential,"identity_verified":false,"ready_for_participation":false,"next_actions":if !complete && credential_matches_capture != Some(false) { vec![resume_action(paths)] } else if complete && config.is_none() { vec![init_action(saved, &address)] } else { Vec::new() },"note":note}),
            )
        }
    }
}

/// Local inspection only: no mkdir, lockfile, network, hashing search or publication.
pub fn status(config_path: &Path) -> Result<Value> {
    status_inner(config_path).map_err(sanitize)
}
fn status_inner(config_path: &Path) -> Result<Value> {
    let paths = Paths::new(config_path)?;
    let saved = last_attempt(&paths)?;
    if let Some(saved) = saved.as_ref() {
        return summary(&paths, saved, classify(saved), false);
    }
    if !parent_exists(&paths)? {
        return Ok(json!({"stage":"clean","created":false,"credential_saved":false}));
    }
    for path in [
        &paths.config,
        &paths.credential,
        &paths.metadata,
        &paths.network,
        &paths.state,
    ] {
        ensure_absent(path)?;
    }
    Ok(json!({"stage":"clean","created":false,"credential_saved":false}))
}

/// Resume only retained local publication; never request a challenge or registration.
pub fn resume(config_path: &Path, confirm: bool) -> Result<Value> {
    resume_inner(config_path, confirm).map_err(sanitize)
}
fn resume_inner(config_path: &Path, confirm: bool) -> Result<Value> {
    if !confirm {
        let status = status_inner(config_path)?;
        if status["current_credential_matches_registration"] == false {
            return Err(conflict());
        }
        return Ok(
            json!({"stage":"plan","confirmed":false,"local_only":true,"status":status,"effects":["validate the retained intent and complete successful response","create-only local credential, identity metadata and network profile publication; no HTTP, proof search, init or participation"]}),
        );
    }
    let paths = Paths::new(config_path)?;
    let unavailable = || {
        error(
            "registration_resume_unavailable",
            "Local resume requires a retained successful registration response; no registration was sent.",
            json!({"retry_allowed":false}),
        )
    };
    if !parent_exists(&paths)? {
        return Err(unavailable());
    }
    let _guard = admin::lock_config_directory(&paths.config).map_err(|_| io_error())?;
    let saved = last_attempt(&paths)?.ok_or_else(unavailable)?;
    match classify(&saved) {
        outcome @ Outcome::Created { .. } => {
            sync_private(&paths.intent(saved.intent.attempt))?;
            sync_private(&paths.capture(saved.intent.attempt))?;
            summary(&paths, &saved, outcome, true)
        }
        Outcome::Unknown => Err(unknown()),
        outcome @ Outcome::Rejected { .. } => summary(&paths, &saved, outcome, false),
    }
}

pub async fn create(config_path: &Path, options: CreateOptions, confirmed: bool) -> Result<Value> {
    let future = create_inner(config_path, &options, confirmed);
    tokio::pin!(future);
    tokio::select! {
        result = &mut future => result.map_err(sanitize),
        _ = tokio::signal::ctrl_c() => Err(error("registration_interrupted", "Registration interrupted. Inspect identity status locally; a retained intent forbids another POST even if transmission had not begun.", json!({}))),
    }
}
async fn create_inner(
    config_path: &Path,
    options: &CreateOptions,
    confirmed: bool,
) -> Result<Value> {
    let paths = Paths::new(config_path)?;
    let binding = binding(&paths, options)?;
    // Route validation and client construction happen before any durable intent.
    let origin = validate_origin_with_trust(&binding.base_url, &binding.trusted_origins)
        .map_err(|_| conflict())?;
    let challenge_url = binding
        .api
        .url(&origin, &binding.chain, Endpoint::JoinPow, None)
        .map_err(|_| conflict())?;
    let register_url = binding
        .api
        .url(&origin, &binding.chain, Endpoint::Register, None)
        .map_err(|_| conflict())?;
    if !confirmed {
        return Ok(
            json!({"stage":"plan","confirmed":false,"created":false,"credential_saved":false,"risk":RISK,"status":status_inner(config_path)?,"chain":binding.chain,"base_url":binding.base_url,"credential_file":paths.credential,"max_pow_bits":options.max_pow_bits,"max_pow_hashes":options.max_pow_hashes,"pow_seconds":options.pow_seconds,"http_seconds":options.http_seconds,"expected_pow_algo":options.expected_pow_algo,"effects":["one challenge GET and bounded SHA256 search","private durable intent before at most one registration POST per attempt","private complete response capture before parsing","create-only credential and identity metadata; no init or participation"]}),
        );
    }
    if !parent_exists(&paths)? {
        create_parent(&paths.parent)?;
    }
    parent_exists(&paths)?;
    let _guard = admin::lock_config_directory(&paths.config).map_err(|_| io_error())?;
    let saved = last_attempt(&paths)?;
    let next_attempt = if let Some(last) = saved.as_ref() {
        if last.intent.binding != binding {
            return Err(conflict());
        }
        match classify(last) {
            outcome @ Outcome::Created { .. } => {
                sync_private(&paths.intent(last.intent.attempt))?;
                sync_private(&paths.capture(last.intent.attempt))?;
                return summary(&paths, last, outcome, true);
            }
            Outcome::Unknown => return Err(unknown()),
            outcome @ Outcome::Rejected {
                retry_not_before, ..
            } => {
                if !options.retry_rejected {
                    return summary(&paths, last, outcome, false);
                }
                if now()? < retry_not_before {
                    return Err(error(
                        "registration_retry_floor",
                        "A fresh registration attempt is not yet permitted by the retained rejection deadline.",
                        json!({"retry_not_before":retry_not_before,"retry_after_seconds":retry_not_before.saturating_sub(now()?)}),
                    ));
                }
                sync_private(&paths.intent(last.intent.attempt))?;
                sync_private(&paths.capture(last.intent.attempt))?;
                last.intent
                    .attempt
                    .checked_add(1)
                    .filter(|attempt| *attempt <= MAX_ATTEMPTS)
                    .ok_or_else(conflict)?
            }
        }
    } else {
        if options.retry_rejected {
            return Err(error(
                "registration_retry_unavailable",
                "Explicit retry requires a retained definitive rejection; no registration was sent.",
                json!({}),
            ));
        }
        1
    };
    for path in [
        &paths.config,
        &paths.credential,
        &paths.metadata,
        &paths.network,
        &paths.state,
    ] {
        ensure_absent(path)?;
    }
    let timeout = Duration::from_secs(options.http_seconds);
    let client = protocol::private_http_client(timeout, timeout).map_err(|_| io_error())?;
    let challenge = protocol::complete_raw_response(client.get(challenge_url)).await.map_err(|_| error("registration_challenge_unavailable", "Admission challenge unavailable; no registration was sent and no retry was attempted.", json!({})))?;
    if challenge.status != 200 {
        return Err(error(
            "registration_challenge_unavailable",
            "Admission challenge unavailable; no registration was sent and no retry was attempted.",
            json!({"http_status":challenge.status,"retry_after_seconds":challenge.retry_after_seconds}),
        ));
    }
    let proof = proof(&challenge.bytes, options)?;
    let nonce = mine(&proof, options).await?;
    if now()? >= proof.expires_ts {
        return Err(error(
            "registration_pow_deadline",
            "Challenge expired before intent; no registration was sent.",
            json!({}),
        ));
    }
    let mut payload =
        json!({"label":binding.label,"pow":{"challenge":proof.challenge,"nonce":nonce}});
    if let Some(invited_by) = &binding.invited_by {
        payload["invited_by"] = json!(invited_by);
    }
    let request = client.post(register_url).json(&payload);
    let intent = Intent {
        schema: 1,
        attempt: next_attempt,
        created_at: now()?,
        binding,
        challenge: proof.challenge,
        nonce,
        bits: proof.bits,
        expires_ts: proof.expires_ts,
        algo: proof.algo,
    };
    let bytes = serde_json::to_vec(&intent).map_err(|_| io_error())?;
    if bytes.len() > 65536 {
        return Err(error(
            "registration_invalid_options",
            "Registration intent exceeds its bounded storage size; no registration was sent.",
            json!({}),
        ));
    }
    publish(&paths.intent(next_attempt), &bytes)?;
    // Even expiry/cancellation here leaves the irreversible conservative fence.
    if now()? >= intent.expires_ts {
        return Err(unknown());
    }
    let raw = protocol::complete_raw_response(request)
        .await
        .map_err(|_| unknown())?;
    let capture = Capture {
        schema: 1,
        intent_sha256: digest(&bytes),
        status: raw.status,
        received_at: now()?,
        retry_after_seconds: raw.retry_after_seconds,
        retry_after_invalid: raw.retry_after_invalid,
        body_sha256: digest(&raw.bytes),
        body_len: raw.bytes.len(),
        body: raw.bytes,
        complete: true,
    };
    // The first parse of a registration response occurs only after both fsyncs.
    publish(
        &paths.capture(next_attempt),
        &serde_json::to_vec(&capture).map_err(|_| io_error())?,
    )?;
    let saved = Saved {
        intent,
        intent_hash: capture.intent_sha256.clone(),
        capture: Some(capture),
    };
    let outcome = classify(&saved);
    if matches!(&outcome, Outcome::Unknown) {
        return Err(unknown());
    }
    summary(&paths, &saved, outcome, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> CreateOptions {
        CreateOptions {
            label: "fixture".into(),
            chain: "fixture-chain".into(),
            base_url: "http://127.0.0.1:1".into(),
            invited_by: None,
            pow_seconds: 30,
            http_seconds: 30,
            max_pow_bits: 24,
            max_pow_hashes: 67_108_864,
            expected_pow_algo: Some("fixture-sha256-bits".into()),
            retry_rejected: false,
            api: ApiEndpoints::default(),
            trusted_origins: NetworkConfig::default().trusted_origins,
        }
    }
    fn fixture(paths: &Paths, body: Value, status: u16, header_delay: Option<u64>) -> Saved {
        let intent = Intent {
            schema: 1,
            attempt: 1,
            created_at: 100,
            binding: binding(paths, &options()).unwrap(),
            challenge: "fixture".into(),
            nonce: "1".into(),
            bits: 3,
            expires_ts: 200,
            algo: "fixture-sha256-bits".into(),
        };
        let intent_hash = digest(&serde_json::to_vec(&intent).unwrap());
        let body = serde_json::to_vec(&body).unwrap();
        let capture = Capture {
            schema: 1,
            intent_sha256: intent_hash.clone(),
            status,
            received_at: 100,
            retry_after_seconds: header_delay,
            retry_after_invalid: false,
            body_sha256: digest(&body),
            body_len: body.len(),
            body,
            complete: true,
        };
        Saved {
            intent,
            intent_hash,
            capture: Some(capture),
        }
    }
    fn private_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
    fn write_saved(paths: &Paths, saved: &Saved) {
        publish(
            &paths.intent(1),
            &serde_json::to_vec(&saved.intent).unwrap(),
        )
        .unwrap();
        publish(
            &paths.capture(1),
            &serde_json::to_vec(saved.capture.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn exact_sha256_decimal_and_bit_boundaries() {
        assert_eq!(
            digest(b"fixture:1"),
            "185ec7f262f0e81d4c419661f74a60947364a28ae0d024d68570db34fe5995ed"
        );
        let hash = Sha256::digest(b"fixture:1");
        assert!(leading_zero_bits(&hash, 3));
        assert!(!leading_zero_bits(&hash, 4));
        for bits in [0, 1, 7, 8, 9, 255, 256] {
            assert!(leading_zero_bits(&[0; 32], bits));
        }
        let mut hash = [0; 32];
        hash[1] = 0x40;
        assert!(leading_zero_bits(&hash, 9));
        assert!(!leading_zero_bits(&hash, 10));
        let mut bytes = [0; 20];
        for number in [0, 9, 10, 42, u64::MAX] {
            assert_eq!(decimal(number, &mut bytes), number.to_string().as_bytes());
        }
    }
    #[tokio::test]
    async fn mining_bounds_and_expiry() {
        let mut options = options();
        let mut proof = Proof {
            challenge: "fixture".into(),
            bits: 3,
            expires_ts: now().unwrap() + 60,
            algo: "fixture-sha256-bits".into(),
        };
        options.max_pow_hashes = 2;
        assert_eq!(mine(&proof, &options).await.unwrap(), "1");
        options.max_pow_hashes = 1;
        assert_eq!(
            error_details(&mine(&proof, &options).await.unwrap_err())
                .unwrap()
                .0,
            "registration_pow_exhausted"
        );
        proof.expires_ts = 0;
        assert_eq!(
            error_details(&mine(&proof, &options).await.unwrap_err())
                .unwrap()
                .0,
            "registration_pow_deadline"
        );
    }
    #[test]
    fn algorithm_requires_explicit_exact_binding() {
        let mut options = options();
        let body = json!({"challenge":"fixture","bits":3,"expires_ts":now().unwrap()+60,"algo":"fixture-sha256-bits"});
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(proof(&bytes, &options).is_ok());
        options.expected_pow_algo = None;
        assert_eq!(
            error_details(&proof(&bytes, &options).err().unwrap())
                .unwrap()
                .0,
            "registration_pow_algorithm_unbound"
        );
        options.expected_pow_algo = Some("different".into());
        assert!(proof(&bytes, &options).is_err());
        options.expected_pow_algo = Some("fixture-sha256-bits".into());
        options.max_pow_bits = 2;
        assert_eq!(
            error_details(&proof(&bytes, &options).err().unwrap())
                .unwrap()
                .0,
            "registration_pow_difficulty"
        );
        for bits in [json!(-1), json!(257), json!("3"), json!(3.5)] {
            let mut malformed = body.clone();
            malformed["bits"] = bits;
            assert!(proof(&serde_json::to_vec(&malformed).unwrap(), &options).is_err());
        }
    }
    #[test]
    fn rejection_requires_documented_shape_and_retains_larger_floor() {
        let root = private_root();
        let paths = Paths::new(&root.path().join("config.toml")).unwrap();
        for (header, body, expected) in [(Some(20), 10, 121), (Some(5), 30, 131)] {
            let saved = fixture(
                &paths,
                json!({"ok":false,"retry_after_seconds":body}),
                429,
                header,
            );
            assert!(
                matches!(classify(&saved), Outcome::Rejected { retry_not_before, .. } if retry_not_before == expected)
            );
        }
        for (status, body) in [
            (500, json!({"ok":false})),
            (429, json!({"ok":false})),
            (403, json!({"error":"forbidden"})),
            (
                403,
                json!({"ok":false,"required_bits":3,"get_challenge":"/api/join-pow","api_key":"pk_untrusted"}),
            ),
        ] {
            assert!(matches!(
                classify(&fixture(&paths, body, status, None)),
                Outcome::Unknown
            ));
        }
        assert!(matches!(
            classify(&fixture(
                &paths,
                json!({"ok":false,"required_bits":3,"get_challenge":"/api/join-pow"}),
                403,
                None
            )),
            Outcome::Rejected { .. }
        ));
    }
    #[test]
    fn capture_binding_partial_capture_and_local_publication() {
        let root = private_root();
        let paths = Paths::new(&root.path().join("config.toml")).unwrap();
        let saved = fixture(
            &paths,
            json!({"ok":true,"address":format!("poa1{}", "1".repeat(32)),"api_key":"pk_registration_fixture"}),
            200,
            None,
        );
        write_saved(&paths, &saved);
        let loaded = last_attempt(&paths).unwrap().unwrap();
        assert_eq!(
            summary(&paths, &loaded, classify(&loaded), false).unwrap()["stage"],
            "response_captured"
        );
        assert!(!paths.credential.exists());
        let output = summary(&paths, &loaded, classify(&loaded), true).unwrap();
        assert_eq!(output["stage"], "created");
        assert!(!output.to_string().contains("pk_registration_fixture"));
        assert_eq!(
            fs::read(&paths.credential).unwrap(),
            b"pk_registration_fixture"
        );
        assert_eq!(
            summary(&paths, &loaded, classify(&loaded), true).unwrap(),
            output
        );
        fs::write(paths.capture(1), b"{\"partial\":").unwrap();
        assert_eq!(
            error_details(&last_attempt(&paths).err().unwrap())
                .unwrap()
                .0,
            "registration_outcome_unknown"
        );
    }
    #[test]
    fn intent_without_capture_fences_reentry() {
        let root = private_root();
        let paths = Paths::new(&root.path().join("config.toml")).unwrap();
        let saved = fixture(&paths, json!({}), 500, None);
        publish(
            &paths.intent(1),
            &serde_json::to_vec(&saved.intent).unwrap(),
        )
        .unwrap();
        assert_eq!(status(&paths.config).unwrap()["stage"], "outcome_unknown");
        assert!(publish(&paths.intent(1), b"replace").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_files_and_conflicting_key_never_overwrite() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = private_root();
        let target = root.path().join("private");
        publish(&target, b"original").unwrap();
        let alias = root.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert!(read_private(&alias, 100).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&target, &alias).unwrap();
        assert!(read_private(&target, 100).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&target, 100).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(publish_matching(&target, b"replacement").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }
}
