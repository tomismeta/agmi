//! Durable, passive publisher restriction evidence. Never installation authority.
use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

const LIMIT: u64 = 128 * 1024;
const INTERVAL: i64 = 6 * 60 * 60;

// Scoped only by the advisory owner, never by installation discovery.
tokio::task_local! {
    static CHECK_STOP: watch::Receiver<bool>;
}

pub(super) fn request_guard() -> Result<()> {
    ensure!(
        !CHECK_STOP
            .try_with(|stop| *stop.borrow() || stop.has_changed().is_err())
            .unwrap_or(false),
        failure("check_cancelled")
    );
    Ok(())
}

async fn cancel_on_stop<T>(work: impl Future<Output = Result<T>>) -> Result<T> {
    let stop = CHECK_STOP.try_with(Clone::clone).ok();
    let cancelled = async move {
        if let Some(mut stop) = stop {
            let _ = stop.wait_for(|value| *value).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! { biased;
        result = work => result,
        _ = cancelled => Err(failure("check_cancelled")),
    }
}

#[derive(Debug)]
pub(super) struct SourceFailure {
    pub floor: Option<i64>,
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("update_source_throttled")
    }
}
impl std::error::Error for SourceFailure {}

const MAX_RETRY_FLOOR_SECONDS: i64 = 7 * 86_400;

#[cfg(test)]
pub(super) fn source_failure(status: u16, retry_after: Option<&str>) -> Option<SourceFailure> {
    source_failure_with_headers(status, retry_after, None, None)
}

pub(super) fn source_failure_with_headers(
    status: u16,
    retry_after: Option<&str>,
    ratelimit_remaining: Option<&str>,
    ratelimit_reset: Option<&str>,
) -> Option<SourceFailure> {
    if matches!(status, 429 | 503) {
        return Some(SourceFailure {
            floor: retry_after.and_then(retry_floor),
        });
    }
    // GitHub API reports primary (X-RateLimit-Remaining: 0) and secondary (Retry-After)
    // rate limits via HTTP 403.
    if status == 403 && (ratelimit_remaining.map(str::trim) == Some("0") || retry_after.is_some()) {
        let reset = ratelimit_reset
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|ts| {
                (ts.min(i64::MAX as u64) as i64).min(now().saturating_add(MAX_RETRY_FLOOR_SECONDS))
            });
        return Some(SourceFailure {
            floor: retry_after.and_then(retry_floor).or(reset),
        });
    }
    None
}
pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
pub(super) fn retry_floor(value: &str) -> Option<i64> {
    let cap = now().saturating_add(MAX_RETRY_FLOOR_SECONDS);
    value
        .parse::<u64>()
        .ok()
        .map(|seconds| {
            now()
                .saturating_add(seconds.min(i64::MAX as u64) as i64)
                .min(cap)
        })
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| (d.as_secs().min(i64::MAX as u64) as i64).min(cap))
        })
}
pub(super) async fn request_budget<T>(
    bounded: bool,
    request: impl Future<Output = Result<T>>,
) -> Result<T> {
    if bounded {
        tokio::time::timeout(Duration::from_secs(5), request)
            .await
            .map_err(|_| failure("update_request_timeout"))?
    } else {
        request.await
    }
}

#[derive(Clone)]
pub(crate) struct LocalUpdateContext {
    config_path: PathBuf,
    selected: Value,
    identity: Option<Identity>,
}
impl LocalUpdateContext {
    fn observe(config_path: &Path) -> Self {
        let selected =
            serde_json::to_value(installer::observe_selected(config_path)).unwrap_or(Value::Null);
        let identity = selected["manifest"]
            .as_str()
            .and_then(|s| Identity::parse(s, false).ok());
        Self {
            config_path: config_path.into(),
            selected,
            identity,
        }
    }
    fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.selected["ownership"],
            self.selected["root"],
            self.selected["release"],
            self.selected["image"],
            self.identity
                .as_ref()
                .map(|i| i.report())
                .unwrap_or(Value::Null)
        )
    }
    fn managed(&self) -> bool {
        self.selected["ownership"] == "managed" && self.identity.is_some()
    }
}
#[derive(Clone, Copy)]
pub(crate) enum CheckTrigger {
    Explicit,
    Automatic,
}
pub(crate) type AdvisoryView = Value;
pub(crate) type CheckReport = Value;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u8,
    source: String,
    context: String,
    started_at: i64,
    finished_at: Option<i64>,
    attempt_id: String,
    outcome: String,
    reason: String,
    next_due_at: i64,
    retry_not_before: Option<i64>,
    good: Option<Good>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adoption: Option<Adoption>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Adoption {
    phase: String,
    legacy_path: PathBuf,
    source_sha256: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Good {
    checked_at: i64,
    context: String,
    availability: String,
    reason: String,
    manifest: String,
    tag: String,
    archive_sha256: String,
}

pub(crate) fn background_policy() -> Value {
    match std::env::var("AGMI_UPDATE_CHECKS") {
        Err(std::env::VarError::NotPresent) => json!({"enabled":true,"reason":"enabled"}),
        Ok(value) if value == "1" => json!({"enabled":true,"reason":"enabled"}),
        Ok(value) if value == "0" => json!({"enabled":false,"reason":"disabled_by_environment"}),
        _ => json!({"enabled":false,"reason":"invalid_environment"}),
    }
}
fn record_path() -> Option<PathBuf> {
    crate::store::account_home()
        .ok()
        .map(|home| durable_path(&home))
}

fn durable_path(home: &Path) -> PathBuf {
    home.join(".local/share/agmi/update-advisory/update.json")
}

fn legacy_path() -> Result<PathBuf> {
    resolve_legacy_path(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))
}

fn resolve_legacy_path(
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    let root = xdg
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|h| PathBuf::from(h).join(".cache")))
        .context("legacy_source_unavailable")?;
    ensure!(root.is_absolute(), "legacy_source_unavailable");
    Ok(root.join("agmi/update.json"))
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn safe_metadata(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "unsafe record type"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == if directory { 0o700 } else { 0o600 },
            "unsafe record ownership"
        );
        if !directory {
            ensure!(metadata.nlink() == 1, "unsafe record links");
        }
    }
    Ok(())
}
fn read_record(path: &Path) -> Result<Record> {
    let bytes = read_bytes(path)?;
    let cache: Record = serde_json::from_slice(&bytes)?;
    validate_record(&cache)?;
    Ok(cache)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    safe_metadata(path.parent().context("cache parent")?, true)?;
    safe_base(path.parent().context("record parent")?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    safe_metadata(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        ensure!(
            opened.dev() == named.dev()
                && opened.ino() == named.ino()
                && opened.uid() == unsafe { libc::geteuid() }
                && opened.mode() & 0o077 == 0
                && opened.nlink() == 1,
            "cache changed"
        );
    }
    ensure!(file.metadata()?.len() <= LIMIT, "cache too large");
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "cache too large");
    Ok(bytes)
}

fn validate_record(cache: &Record) -> Result<()> {
    ensure!(cache.source == API, "foreign record");
    ensure!(
        matches!(
            cache.outcome.as_str(),
            "" | "in_progress" | "success" | "failure"
        ),
        "invalid outcome"
    );
    ensure!(
        (cache.outcome == "in_progress")
            == (cache.finished_at.is_none() && !cache.outcome.is_empty()),
        "invalid completion"
    );
    if cache.outcome.is_empty() {
        ensure!(
            cache.format == 2
                && cache.started_at == 0
                && cache.finished_at.is_none()
                && cache.attempt_id.is_empty()
                && cache.reason.is_empty()
                && cache.context.is_empty()
                && cache.next_due_at == 0
                && cache.retry_not_before.is_none()
                && cache.good.is_none()
                && cache
                    .adoption
                    .as_ref()
                    .is_some_and(|a| a.source_sha256.is_none()),
            "invalid empty record"
        );
    }
    ensure!(
        cache.started_at >= 0
            && cache.next_due_at >= 0
            && cache.finished_at.is_none_or(|finished| {
                finished >= 0
                    && (finished >= cache.started_at
                        || (cache.outcome == "failure" && cache.reason == "clock_regressed"))
            })
            && cache.retry_not_before.is_none_or(|floor| floor >= 0),
        "invalid record time"
    );
    match (cache.format, &cache.adoption) {
        (1, None) => (),
        (2, Some(adoption)) => {
            ensure!(
                matches!(adoption.phase.as_str(), "adopting" | "ready")
                    && adoption.legacy_path.is_absolute()
                    && adoption.source_sha256.as_ref().is_none_or(|v| hex(v, 64)),
                "invalid adoption"
            );
        }
        _ => anyhow::bail!("unsupported record"),
    }
    if let Some(good) = &cache.good {
        let identity = Identity::parse(&good.manifest, true)?;
        ensure!(
            identity.update_protocol == 1
                && good.tag == format!("v{}", identity.version)
                && hex(&good.archive_sha256, 64)
                && matches!(good.availability.as_str(), "current" | "available"),
            "invalid proof"
        );
    }
    if cache.outcome == "success" {
        ensure!(
            cache
                .good
                .as_ref()
                .is_some_and(|g| g.context == cache.context
                    && g.checked_at >= cache.started_at
                    && cache.finished_at.is_some_and(|t| t >= g.checked_at)),
            "incomplete success proof"
        );
    }
    Ok(())
}
fn safe_base(parent: &Path) -> Result<()> {
    let base = parent.parent().context("record base")?;
    let metadata = fs::symlink_metadata(base)?;
    ensure!(metadata.is_dir(), "unsafe record base");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
            "unsafe record base"
        );
    }
    Ok(())
}

fn initialize(path: &Path) -> Result<()> {
    let parent = path.parent().context("record parent")?;
    let mut missing = Vec::new();
    let mut ancestor = parent;
    while !present(ancestor)? {
        missing.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().context("record ancestor")?;
    }
    for directory in missing.iter().rev() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(directory) {
            Ok(()) => File::open(directory.parent().context("record ancestor")?)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    safe_base(parent)?;
    safe_metadata(parent, true)
}

fn account_ancestors(path: &Path, home: &Path) -> Result<()> {
    ensure!(path.starts_with(home), "record outside account home");
    let mut current = home.to_path_buf();
    for component in path.strip_prefix(home)?.components() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if present(&current)? {
                let metadata = fs::symlink_metadata(&current)?;
                ensure!(
                    metadata.is_dir()
                        && metadata.uid() == unsafe { libc::geteuid() }
                        && metadata.mode() & 0o022 == 0,
                    "unsafe record ancestor"
                );
            }
        }
        current.push(component);
    }
    Ok(())
}

fn source_snapshot(path: &Path) -> Result<Option<(Record, String)>> {
    if let Some(parent) = path.parent()
        && present(parent)?
    {
        safe_metadata(parent, true)?;
        safe_base(parent)?;
    }
    if !present(path)? {
        return Ok(None);
    }
    let bytes = read_bytes(path)?;
    let record: Record = serde_json::from_slice(&bytes)?;
    validate_record(&record)?;
    ensure!(record.format == 1, "legacy_source_conflict");
    Ok(Some((record, format!("{:x}", Sha256::digest(&bytes)))))
}

// Lock order is install -> legacy -> durable; all work finishes before release.
fn adopt_locked(path: &Path, source: &Path, canonical_source: &Path) -> Result<()> {
    if source != canonical_source {
        ensure!(
            !present(canonical_source)?
                && !present(&canonical_source.with_file_name("update.lock"))?,
            "legacy_source_conflict"
        );
    }
    let source_footprint = present(source)? || present(&source.with_file_name("update.lock"))?;
    let _legacy = if source_footprint {
        Some(acquire(source)?.context("advisory_adoption_deferred")?)
    } else {
        None
    };
    let snapshot = source_snapshot(source)?;
    ensure!(
        snapshot.is_some() || !source_footprint || present(path)?,
        "legacy_source_unavailable"
    );
    let durable_existed = present(path.parent().context("record parent")?)?;
    let _durable = acquire(path)?.context("advisory_adoption_deferred")?;
    if let Some(legacy) = &_legacy {
        verify_lease(source, legacy)?;
    }
    #[cfg(unix)]
    let source_metadata = if snapshot.is_some() {
        Some(fs::symlink_metadata(source)?)
    } else {
        None
    };
    let source_parent = source.parent().context("legacy parent")?;
    let source_directory = if present(source_parent)? {
        Some(open_directory(source_parent)?)
    } else {
        None
    };
    let mut record = if present(path)? {
        let record = read_record(path)?;
        ensure!(record.format == 2, "advisory_record_invalid");
        let adoption = record
            .adoption
            .as_ref()
            .context("advisory_record_invalid")?;
        ensure!(adoption.legacy_path == source, "legacy_source_conflict");
        if adoption.phase == "ready" {
            ensure!(snapshot.is_none(), "legacy_source_conflict");
            return Ok(());
        }
        ensure!(
            snapshot
                .as_ref()
                .is_none_or(|(_, digest)| Some(digest) == adoption.source_sha256.as_ref()),
            "legacy_source_conflict"
        );
        record
    } else {
        ensure!(!durable_existed, "advisory_record_missing");
        let digest = snapshot.as_ref().map(|(_, digest)| digest.clone());
        let mut record = snapshot
            .as_ref()
            .map(|(record, _)| record.clone())
            .unwrap_or_else(|| Record {
                source: API.into(),
                ..Record::default()
            });
        record.format = 2;
        record.adoption = Some(Adoption {
            phase: "adopting".into(),
            legacy_path: source.into(),
            source_sha256: digest,
        });
        persist(path, &record)?;
        record
    };
    verify_lease(path, &_durable)?;
    if let Some(legacy) = &_legacy {
        verify_lease(source, legacy)?;
    }
    if let Some((_, digest)) = snapshot {
        ensure!(
            source_snapshot(source)?.is_some_and(|(_, current)| current == digest),
            "legacy_source_conflict"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let original = source_metadata.as_ref().context("legacy_source_conflict")?;
            let current = fs::symlink_metadata(source)?;
            ensure!(
                original.dev() == current.dev() && original.ino() == current.ino(),
                "legacy_source_conflict"
            );
        }
        #[cfg(test)]
        filesystem_boundary()?;
        verify_directory(
            source_parent,
            source_directory
                .as_ref()
                .context("legacy_source_conflict")?,
        )?;
        fs::remove_file(source)?;
        #[cfg(test)]
        filesystem_boundary()?;
    }
    if let Some(directory) = source_directory {
        #[cfg(test)]
        filesystem_boundary()?;
        verify_directory(source_parent, &directory)?;
        directory.sync_all()?;
        #[cfg(test)]
        filesystem_boundary()?;
    }
    verify_lease(path, &_durable)?;
    if let Some(legacy) = &_legacy {
        verify_lease(source, legacy)?;
    }
    record
        .adoption
        .as_mut()
        .context("advisory_record_invalid")?
        .phase = "ready".into();
    persist(path, &record)
}

fn prepare_record(path: &Path) -> Result<()> {
    let home = crate::store::account_home()?;
    account_ancestors(path, &home)?;
    let canonical_source = home.join(".cache/agmi/update.json");
    if present(path)? {
        let record = read_record(path)?;
        ensure!(record.format == 2, "advisory_record_invalid");
        if record.adoption.as_ref().is_some_and(|a| a.phase == "ready") {
            ensure!(
                !present(
                    &record
                        .adoption
                        .as_ref()
                        .context("advisory_record_invalid")?
                        .legacy_path
                )?,
                "legacy_source_conflict"
            );
            ensure!(!present(&canonical_source)?, "legacy_source_conflict");
            return Ok(());
        }
    }
    let source = legacy_path()?;
    installer::with_advisory_owner(|| adopt_locked(path, &source, &canonical_source))
}
fn acquire(path: &Path) -> Result<Option<File>> {
    initialize(path)?;
    let lock_path = path.with_file_name("update.lock");
    ensure!(
        !present(path)? || present(&lock_path)?,
        "advisory_record_missing"
    );
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(&lock_path)?;
    safe_metadata(&lock_path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = file.metadata()?;
        let b = fs::symlink_metadata(&lock_path)?;
        ensure!(a.dev() == b.dev() && a.ino() == b.ino(), "lock changed");
    }
    match file.try_lock() {
        Ok(()) => {
            verify_lease(path, &file)?;
            file.sync_all()?;
            open_directory(path.parent().context("record parent")?)?.sync_all()?;
            Ok(Some(file))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}
fn verify_directory(path: &Path, file: &File) -> Result<()> {
    safe_metadata(path, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        ensure!(
            opened.dev() == named.dev() && opened.ino() == named.ino(),
            "advisory directory changed"
        );
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let directory = options.open(path)?;
    verify_directory(path, &directory)?;
    Ok(directory)
}

fn verify_lease(path: &Path, file: &File) -> Result<()> {
    let lock = path.with_file_name("update.lock");
    safe_metadata(&lock, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        let named = fs::symlink_metadata(lock)?;
        ensure!(
            opened.dev() == named.dev() && opened.ino() == named.ino() && opened.nlink() == 1,
            "advisory lease changed"
        );
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FILESYSTEM_FAULT: std::cell::Cell<Option<(usize, usize)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn filesystem_boundary() -> Result<()> {
    FILESYSTEM_FAULT.with(|fault| {
        if let Some((target, seen)) = fault.get() {
            fault.set(Some((target, seen + 1)));
            ensure!(target != seen + 1, "injected_filesystem_failure");
        }
        Ok(())
    })
}

fn persist(path: &Path, cache: &Record) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    validate_record(cache)?;
    let parent = path.parent().context("record parent")?;
    safe_metadata(parent, true)?;
    safe_base(parent)?;
    let previous_target = if present(path)? {
        safe_metadata(path, false)?;
        Some(fs::symlink_metadata(path)?)
    } else {
        None
    };
    let bytes = serde_json::to_vec(cache)?;
    ensure!(bytes.len() as u64 <= LIMIT, "record too large");
    let directory = open_directory(parent)?;
    let (temporary, mut file) = loop {
        let temporary = parent.join(format!(
            ".update-{}-{}.tmp",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
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
        match options.open(&temporary) {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        #[cfg(test)]
        filesystem_boundary()?;
        file.sync_all()?;
        #[cfg(test)]
        filesystem_boundary()?;
        safe_metadata(parent, true)?;
        safe_metadata(&temporary, false)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let opened = directory.metadata()?;
            let named = fs::symlink_metadata(parent)?;
            let opened_file = file.metadata()?;
            let named_file = fs::symlink_metadata(&temporary)?;
            ensure!(
                opened.dev() == named.dev()
                    && opened.ino() == named.ino()
                    && opened_file.dev() == named_file.dev()
                    && opened_file.ino() == named_file.ino()
                    && opened_file.nlink() == 1,
                "record publication changed"
            );
        }
        match (&previous_target, present(path)?) {
            (None, false) => (),
            (Some(previous), true) => {
                safe_metadata(path, false)?;
                let current = fs::symlink_metadata(path)?;
                ensure!(
                    previous.len() == current.len()
                        && previous.modified()? == current.modified()?,
                    "record target changed"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    ensure!(
                        previous.dev() == current.dev()
                            && previous.ino() == current.ino()
                            && previous.ctime() == current.ctime()
                            && previous.ctime_nsec() == current.ctime_nsec(),
                        "record target changed"
                    );
                }
            }
            _ => anyhow::bail!("record target changed"),
        }
        #[cfg(test)]
        filesystem_boundary()?;
        verify_directory(parent, &directory)?;
        fs::rename(&temporary, path)?;
        #[cfg(test)]
        filesystem_boundary()?;
        #[cfg(test)]
        filesystem_boundary()?;
        verify_directory(parent, &directory)?;
        directory.sync_all()?;
        #[cfg(test)]
        filesystem_boundary()?;
        Ok(())
    })();
    // Only this operation's create-new temporary is disposable.
    let _ = fs::remove_file(temporary);
    result
}
fn offset(context: &LocalUpdateContext) -> i64 {
    let hash = Sha256::digest(
        context.selected["root"]
            .as_str()
            .unwrap_or("unmanaged")
            .as_bytes(),
    );
    i64::from(u16::from_be_bytes([hash[0], hash[1]])) % 301
}
fn record_view(context: &LocalUpdateContext, cache: Option<&Record>, at: i64) -> Value {
    let mut result = json!({"availability":"unknown","freshness":"missing","reason":"no_compatible_evidence","checked_at":null,"latest_version":null,"background":background_policy(),"owner":context.selected["ownership"],"selected_running_relation":"not_assessed","next_action":{"kind":"use_install_owner"},"installability":"not_assessed","last_good":null});
    result["storage"] = json!("unknown");
    result["adoption_required"] = json!(false);
    if context.managed() {
        result["next_action"] = json!({"kind":"check","argv":["agmi","update","--check"]});
    }
    if context.selected["ownership"] != "managed" && context.selected["ownership"] != "unmanaged" {
        result["next_action"] = json!({"kind":"unavailable"});
    }
    let Some(cache) = cache else { return result };
    result["storage"] = json!(if cache.format == 1 {
        "legacy"
    } else {
        "durable"
    });
    result["next_due_at"] = json!(cache.next_due_at.max(cache.retry_not_before.unwrap_or(0)));
    result["retry_not_before"] = json!(cache.retry_not_before);
    result["adoption_required"] = json!(
        cache.format == 1
            || cache
                .adoption
                .as_ref()
                .is_some_and(|a| a.phase == "adopting")
    );
    if cache
        .adoption
        .as_ref()
        .is_some_and(|a| a.phase == "adopting")
    {
        result["freshness"] = json!("unavailable");
        result["reason"] = json!("advisory_adoption_in_progress");
        result["next_action"] =
            json!({"kind":"unavailable","reason":"advisory_adoption_in_progress"});
        return result;
    }
    // Keep source floors and unfinished-attempt evidence visible during adoption.
    let incomplete = cache.outcome == "in_progress" && cache.finished_at.is_none();
    result["reason"] = json!(cache.reason);
    if cache.retry_not_before.is_some_and(|floor| floor > at) {
        result["reason"] = json!("source_retry_not_before");
    } else if incomplete {
        result["reason"] = json!("previous_attempt_incomplete");
    }
    if incomplete {
        result["next_action"] =
            json!({"kind":"unavailable","reason":"previous_attempt_incomplete"});
    }
    result["freshness"] = json!("unavailable");
    if let Some(good) = &cache.good {
        let publication = Identity::parse(&good.manifest, true).ok();
        let selected_is_publication = context
            .identity
            .as_ref()
            .zip(publication.as_ref())
            .is_some_and(|(base, published)| base.digest == published.digest);
        if good.context == context.key() || selected_is_publication {
            let age_valid = good.checked_at <= at && good.checked_at > 0;
            let fresh = age_valid
                && at < cache.next_due_at
                && cache
                    .finished_at
                    .is_some_and(|t| t <= at && t >= good.checked_at)
                && cache.outcome == "success";
            result["freshness"] = json!(if fresh { "fresh" } else { "stale" });
            result["checked_at"] = json!(good.checked_at);
            result["latest_version"] = json!(
                Identity::parse(&good.manifest, true)
                    .unwrap()
                    .version
                    .to_string()
            );
            result["last_good"] =
                json!({"availability":good.availability,"checked_at":good.checked_at});
            if fresh {
                result["availability"] = json!(if selected_is_publication {
                    "current"
                } else {
                    &good.availability
                });
            }
            if fresh
                && !selected_is_publication
                && good.availability == "available"
                && context.managed()
            {
                result["next_action"] = json!({"kind":"update","argv":["agmi","update"]});
            }
        }
    }
    result
}
fn read_view_record(home: &Path, legacy: Result<PathBuf>) -> Result<Option<Record>> {
    let path = durable_path(home);
    account_ancestors(&path, home)?;
    let canonical = home.join(".cache/agmi/update.json");
    if present(&path)? {
        let record = read_record(&path)?;
        ensure!(record.format == 2, "advisory_record_invalid");
        if let Some(adoption) = &record.adoption {
            ensure!(
                adoption.phase == "adopting"
                    || (!present(&adoption.legacy_path)? && !present(&canonical)?),
                "legacy_source_conflict"
            );
        }
        return Ok(Some(record));
    }
    ensure!(
        !present(path.parent().context("record parent")?)?,
        "advisory_record_missing"
    );
    let source = legacy?;
    if source != canonical {
        ensure!(
            !present(&canonical)? && !present(&canonical.with_file_name("update.lock"))?,
            "legacy_source_conflict"
        );
    }
    let snapshot = source_snapshot(&source)?;
    ensure!(
        snapshot.is_some() || !present(&source.with_file_name("update.lock"))?,
        "legacy_source_unavailable"
    );
    Ok(snapshot.map(|(record, _)| record))
}

pub(crate) fn view(context: &LocalUpdateContext, at: i64) -> AdvisoryView {
    let observed =
        crate::store::account_home().and_then(|home| read_view_record(&home, legacy_path()));
    match observed {
        Ok(Some(record)) => record_view(context, Some(&record), at),
        Ok(None) => record_view(context, None, at),
        Err(error) => {
            let mut value = record_view(context, None, at);
            value["freshness"] = json!("unavailable");
            let reason = storage_reason(&error);
            value["reason"] = json!(reason);
            value["next_action"] = json!({"kind":"unavailable","reason":reason});
            value
        }
    }
}

fn storage_reason(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "legacy_source_conflict" => "legacy_source_conflict",
        "legacy_source_unavailable" => "legacy_source_unavailable",
        "advisory_record_missing" => "advisory_record_missing",
        "advisory_adoption_deferred" => "advisory_adoption_deferred",
        _ => "advisory_record_invalid",
    }
}
pub(crate) fn diagnostic_view(
    config_path: &Path,
    selected: &Value,
    process: &Value,
    at: i64,
) -> Value {
    let context = LocalUpdateContext {
        config_path: config_path.into(),
        selected: selected.clone(),
        identity: selected["manifest"]
            .as_str()
            .and_then(|s| Identity::parse(s, false).ok()),
    };
    let mut result = view(&context, at);
    result["selected_running_relation"] = process
        .get("image_relation")
        .cloned()
        .unwrap_or(json!("not_assessed"));
    if process["image_relation"] == "different_object" {
        result["next_action"] =
            json!({"kind":"inspect_service","argv":["agmi","service","status"]});
    }
    result
}

async fn discover(context: &LocalUpdateContext) -> Result<Good> {
    let client = Client::builder()
        .user_agent("agmi-stable-update")
        .https_only(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let publication = super::discover_publication(&client, true).await?;
    let published = &publication.published;
    let compatible = cfg!(all(target_os = "linux", target_arch = "x86_64"))
        && published.target == "x86_64-unknown-linux-musl"
        || cfg!(all(target_os = "linux", target_arch = "aarch64"))
            && published.target == "aarch64-unknown-linux-musl";
    ensure!(compatible, failure("published_target_incompatible"));
    let archive_name = format!("agmi-v{}-{}.tar.gz", published.version, published.target);
    publication.release.asset(&archive_name, ARCHIVE_LIMIT)?;
    let archive_sha256 = checksum(&publication.sums, &archive_name)?;
    let current = context
        .identity
        .as_ref()
        .context("current_identity_unavailable")?;
    let mut order = ordering(current, published);
    if order == Ordering::Compare {
        order = request_budget(true, ancestry(&client, current, published)).await?;
    }
    let (availability, reason) = match order {
        Ordering::Available => ("available", "published_release_descends_current"),
        Ordering::Current(reason) => ("current", reason),
        Ordering::Refused(reason) => return Err(failure(reason)),
        Ordering::Compare => unreachable!(),
    };
    Ok(Good {
        checked_at: now(),
        context: context.key(),
        availability: availability.into(),
        reason: reason.into(),
        manifest: publication.build_info,
        tag: publication.release.tag_name,
        archive_sha256,
    })
}
fn reason(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    [
        "check_cancelled",
        "current_identity_unavailable",
        "update_request_timeout",
        "update_overall_timeout",
        "update_digest_mismatch",
        "update_ordering_unverified",
        "published_target_incompatible",
        "installed_dirty_build_preserved",
        "installed_unreleased_build_preserved",
        "published_installer_protocol_unsupported",
        "same_commit_different_build_preserved",
        "commit_ordering_unverified",
    ]
    .into_iter()
    .find(|s| *s == text)
    .unwrap_or(if error.downcast_ref::<SourceFailure>().is_some() {
        "update_source_throttled"
    } else {
        "update_discovery_unverified"
    })
}
fn report(context: &LocalUpdateContext, cache: Option<&Record>, success: bool, why: &str) -> Value {
    let mut advisory = record_view(context, cache, now());
    if !success {
        advisory["availability"] = json!("unknown");
        advisory["reason"] = json!(why);
        if advisory["freshness"] == "fresh" {
            advisory["freshness"] = json!("stale");
        }
        if why == "check_in_progress" || advisory["next_action"]["kind"] != "unavailable" {
            advisory["next_action"] = if context.managed() {
                json!({"kind":"check","argv":["agmi","update","--check"]})
            } else if context.selected["ownership"] == "unmanaged" {
                json!({"kind":"use_install_owner"})
            } else {
                json!({"kind":"unavailable"})
            };
        }
        if matches!(
            why,
            "previous_attempt_incomplete"
                | "advisory_record_missing"
                | "advisory_record_invalid"
                | "advisory_storage_unavailable"
                | "advisory_persistence_failed"
                | "legacy_source_unavailable"
                | "legacy_source_conflict"
        ) {
            advisory["next_action"] = json!({"kind":"unavailable","reason":why});
        }
    }
    json!({"success":success,"discovery_success":cache.is_some_and(|c|c.outcome=="success") && (success || why=="advisory_persistence_failed"),"update":{"check":true,"status":if success { advisory["availability"].as_str().unwrap_or("unknown") } else { "unknown" },"reason":why,"source":"github_latest_stable","current_source":if context.managed() {"managed_selected_release"} else if context.selected["ownership"] == "unmanaged" {"unmanaged_invoker"} else {"unavailable"}},"release_advisory":advisory})
}
pub(crate) async fn check(context: LocalUpdateContext, trigger: CheckTrigger) -> CheckReport {
    let deadline = Instant::now() + Duration::from_secs(20);
    check_until(context, trigger, deadline).await
}
async fn check_until(
    context: LocalUpdateContext,
    trigger: CheckTrigger,
    deadline: Instant,
) -> Value {
    if request_guard().is_err() {
        return report(&context, None, false, "check_cancelled");
    }
    if Instant::now() >= deadline {
        return report(&context, None, false, "update_overall_timeout");
    }
    let Some(path) = record_path() else {
        return report(&context, None, false, "advisory_storage_unavailable");
    };
    let adoption_path = path.clone();
    let prepared = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        tokio::task::spawn_blocking(move || prepare_record(&adoption_path)),
    )
    .await;
    match prepared {
        Ok(Ok(Ok(()))) => (),
        Ok(Ok(Err(error))) => return report(&context, None, false, storage_reason(&error)),
        _ => return report(&context, None, false, "advisory_adoption_deferred"),
    }
    check_path(context, trigger, deadline, path).await
}
fn finish_attempt(cache: &mut Record, good: Option<Good>, at: i64) {
    if at < cache.started_at
        || good
            .as_ref()
            .is_some_and(|good| good.checked_at < cache.started_at || good.checked_at > at)
    {
        cache.outcome = "failure".into();
        cache.reason = "clock_regressed".into();
    } else if cache.outcome == "success" {
        cache.good = good;
    }
    // Preserve the observed wall time, not a fabricated ordered timestamp.
    cache.finished_at = Some(at);
}

async fn check_path(
    context: LocalUpdateContext,
    trigger: CheckTrigger,
    deadline: Instant,
    path: PathBuf,
) -> Value {
    let invoked_at = now();
    let previous = match read_record(&path) {
        Ok(record) => Some(record),
        Err(_) if present(&path).unwrap_or(true) => {
            return report(&context, None, false, "advisory_record_invalid");
        }
        Err(_) => None,
    };
    let previous_attempt = previous.as_ref().map(|c| c.attempt_id.clone());
    let previous_finished = previous.as_ref().and_then(|c| c.finished_at);
    let lease = loop {
        if request_guard().is_err() {
            return report(&context, previous.as_ref(), false, "check_cancelled");
        }
        match acquire(&path) {
            Ok(Some(lease)) => break lease,
            Ok(None) if matches!(trigger, CheckTrigger::Explicit) => {
                let cache = read_record(&path).ok();
                if let Some(cache) = &cache
                    && (Some(&cache.attempt_id) != previous_attempt.as_ref()
                        || previous_finished.is_none())
                    && cache.finished_at.is_some_and(|t| t >= invoked_at)
                    && cache.context == context.key()
                {
                    return completed_report(&context, cache);
                }
                if Instant::now() + Duration::from_millis(50) >= deadline {
                    return report(&context, cache.as_ref(), false, "check_in_progress");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(None) => return report(&context, previous.as_ref(), false, "check_in_progress"),
            Err(_) => {
                return report(
                    &context,
                    previous.as_ref(),
                    false,
                    "advisory_storage_unavailable",
                );
            }
        }
    };
    let lease = std::sync::Arc::new(lease);
    let mut cache = match read_record(&path) {
        Ok(record)
            if record.format == 2
                && record.adoption.as_ref().is_some_and(|a| a.phase == "ready") =>
        {
            record
        }
        _ => return report(&context, None, false, "advisory_record_invalid"),
    };
    if matches!(trigger, CheckTrigger::Explicit)
        && (Some(&cache.attempt_id) != previous_attempt.as_ref() || previous_finished.is_none())
        && cache.finished_at.is_some_and(|t| t >= invoked_at)
        && cache.context == context.key()
    {
        return completed_report(&context, &cache);
    }
    let at = now();
    if cache.retry_not_before.is_some_and(|floor| floor > at) {
        return report(&context, Some(&cache), false, "source_retry_not_before");
    }
    // An interrupted commit may have lost a source floor. Never spend another
    // request on that uncertainty; the durable record needs operator inspection.
    if cache.outcome == "in_progress" && cache.finished_at.is_none() {
        return report(&context, Some(&cache), false, "previous_attempt_incomplete");
    }
    // A wall-clock rollback must not turn a future persisted due time into permission.
    if matches!(trigger, CheckTrigger::Automatic)
        && cache.next_due_at > at
        && cache.next_due_at <= cache.started_at.saturating_add(INTERVAL + 300)
    {
        return report(&context, Some(&cache), false, "not_due");
    }
    if request_guard().is_err() {
        return report(&context, Some(&cache), false, "check_cancelled");
    }
    cache.format = 2;
    cache.source = API.into();
    cache.context = context.key();
    cache.started_at = at;
    cache.finished_at = None;
    cache.outcome = "in_progress".into();
    cache.reason = "check_in_progress".into();
    cache.attempt_id = format!("{}-{}-{:?}", at, std::process::id(), Instant::now());
    cache.next_due_at = at.saturating_add(INTERVAL + offset(&context));
    let initial_saved = bounded_persist(&path, &cache, lease.clone(), deadline).await;
    if !initial_saved {
        return report(&context, Some(&cache), false, "advisory_persistence_failed");
    }
    let discovery = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        cancel_on_stop(async {
            request_guard()?;
            if context.managed() {
                let (_, identity) = tokio::task::spawn_blocking(super::installed)
                    .await
                    .map_err(|_| failure("current_identity_unavailable"))?
                    .map_err(|_| failure("current_identity_unavailable"))?;
                ensure!(
                    context
                        .identity
                        .as_ref()
                        .is_some_and(|base| base.report() == identity.report()),
                    failure("current_identity_unavailable")
                );
            }
            request_guard()?;
            discover(&context).await
        }),
    )
    .await;
    let result = match discovery {
        Ok(result) => result,
        Err(_) => Err(failure("update_overall_timeout")),
    };
    let mut replacement_good = None;
    match result {
        Ok(good) => {
            let observed = LocalUpdateContext::observe(&context.config_path);
            // Unmanaged explicit identity is the invoker, not a selected release.
            if context.managed() && observed.key() != context.key() {
                cache.outcome = "failure".into();
                cache.reason = "context_changed".into();
            } else {
                cache.reason = good.reason.clone();
                replacement_good = Some(good);
                cache.outcome = "success".into();
            }
        }
        Err(error) => {
            cache.outcome = "failure".into();
            cache.reason = reason(&error).into();
            if let Some(floor) = error.downcast_ref::<SourceFailure>().and_then(|f| f.floor) {
                cache.retry_not_before = Some(cache.retry_not_before.unwrap_or(0).max(floor));
            }
        }
    }
    if request_guard().is_err() {
        cache.outcome = "failure".into();
        cache.reason = "check_cancelled".into();
    }
    finish_attempt(&mut cache, replacement_good, now());
    let saved = bounded_persist(&path, &cache, lease.clone(), deadline).await && initial_saved;
    drop(lease);
    report(
        &context,
        Some(&cache),
        cache.outcome == "success" && saved,
        if saved {
            &cache.reason
        } else {
            "advisory_persistence_failed"
        },
    )
}

pub async fn standalone_check(config_path: &Path) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut context = LocalUpdateContext::observe(config_path);
    let canonical = crate::store::account_home()?.join(".config/agmi/config.toml");
    let canonical_owner = installer::observe_selected(&canonical);
    let canonical_owner = serde_json::to_value(canonical_owner)?;
    if context.selected["ownership"] == "unmanaged" && canonical_owner["ownership"] != "unmanaged" {
        return Ok(report(
            &context,
            None,
            false,
            "managed_installation_unverified",
        ));
    }
    if context.selected["ownership"] != "managed" && context.selected["ownership"] != "unmanaged" {
        return Ok(report(
            &context,
            None,
            false,
            "managed_installation_unverified",
        ));
    }
    if context.selected["ownership"] == "unmanaged" {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let identity = tokio::time::timeout(
            remaining,
            tokio::task::spawn_blocking(move || -> Result<Identity> {
                let file = File::open(std::env::current_exe()?)?;
                let before = file.metadata()?;
                ensure!(
                    before.is_file() && before.len() <= ARCHIVE_LIMIT as u64,
                    "invoker too large"
                );
                let mut hash = Sha256::new();
                let mut reader = file;
                let mut buffer = [0u8; 65536];
                let deadline = Instant::now() + remaining;
                loop {
                    ensure!(Instant::now() < deadline, "identity timeout");
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buffer[..n]);
                }
                let after = reader.metadata()?;
                ensure!(
                    before.len() == after.len() && before.modified()? == after.modified()?,
                    "invoker changed"
                );
                Identity::parse(
                    &format!(
                        "{}binary_sha256={:x}\n",
                        include_str!(env!("AGMI_BUILD_MANIFEST_PATH")),
                        hash.finalize()
                    ),
                    false,
                )
            }),
        )
        .await;
        context.identity = match identity {
            Ok(Ok(Ok(identity))) => Some(identity),
            _ => {
                return Ok(report(
                    &context,
                    None,
                    false,
                    "current_identity_unavailable",
                ));
            }
        };
    }
    if context.identity.is_none() {
        return Ok(report(
            &context,
            None,
            false,
            "current_identity_unavailable",
        ));
    }
    Ok(check_until(context, CheckTrigger::Explicit, deadline).await)
}

pub(crate) async fn finish_background(mut task: tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(Duration::from_millis(2500), &mut task)
        .await
        .is_err()
    {
        // Abnormal/stalled local persistence: retain its unfinished record,
        // never pretend cancellation was durably completed.
        task.abort();
    }
}

pub(crate) async fn run(config_path: PathBuf, mut stop: watch::Receiver<bool>) {
    if *stop.borrow() || stop.has_changed().is_err() || background_policy()["enabled"] != true {
        return;
    }
    let context = LocalUpdateContext::observe(&config_path);
    if !context.managed() {
        return;
    }
    let mut delay = Duration::from_secs(offset(&context) as u64);
    loop {
        tokio::select! { biased;
            _ = stop.changed() => return,
            _ = tokio::time::sleep(delay) => (),
        }
        if *stop.borrow() {
            return;
        }
        let context = LocalUpdateContext::observe(&config_path);
        if !context.managed() {
            return;
        }
        CHECK_STOP
            .scope(
                stop.clone(),
                check(context.clone(), CheckTrigger::Automatic),
            )
            .await;
        if *stop.borrow() || stop.has_changed().is_err() {
            return;
        }
        let at = now();
        let due = record_path()
            .and_then(|p| read_record(&p).ok())
            .map(|c| {
                c.next_due_at
                    .min(at.saturating_add(INTERVAL + 300))
                    .max(c.retry_not_before.unwrap_or(0))
            })
            .unwrap_or(at.saturating_add(INTERVAL + offset(&context)));
        delay = Duration::from_secs(due.saturating_sub(at).max(60) as u64);
    }
}

#[cfg(test)]
struct TestRequest {
    starts: std::sync::atomic::AtomicUsize,
    started: tokio::sync::Notify,
    throttle: Option<(u16, watch::Sender<bool>)>,
}

#[cfg(test)]
struct TestCommit {
    writes: std::sync::atomic::AtomicUsize,
    started: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    release: std::sync::Condvar,
}

#[cfg(test)]
tokio::task_local! {
    static TEST_REQUEST: std::sync::Arc<TestRequest>;
    static TEST_COMMIT: std::sync::Arc<TestCommit>;
}

#[cfg(test)]
pub(super) async fn test_request() -> Option<Result<Vec<u8>>> {
    let request = TEST_REQUEST.try_with(Clone::clone).ok()?;
    request
        .starts
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    request.started.notify_one();
    if let Some((status, stop)) = &request.throttle {
        let failure = source_failure(*status, Some("3600")).unwrap();
        let _ = stop.send(true);
        Some(Err(failure.into()))
    } else {
        std::future::pending().await
    }
}

#[cfg(test)]
fn test_adoption() -> Adoption {
    Adoption {
        phase: "ready".into(),
        legacy_path: PathBuf::from("/isolated-unused-legacy/update.json"),
        source_sha256: None,
    }
}

#[cfg(test)]
fn test_record_path(home: &Path) -> PathBuf {
    let path = durable_path(home);
    let source = home.join(".cache/agmi/update.json");
    adopt_locked(&path, &source, &source).unwrap();
    path
}

// Always initiate the commit, even when HTTP consumed the caller's deadline.
// A cancelled/timed-out fsync retains the OS lease until it finishes. If disk
// failure/crash prevents a floor commit, the durable unfinished attempt fails
// closed even if the record disappears while its durable ownership remains.
// No account, installer, credential, or model state enters this blocking task.
#[cfg(test)]
tokio::task_local! {
    pub(super) static TEST_TRANSPORT: BTreeMap<String, Vec<u8>>;
}

async fn bounded_persist(
    path: &Path,
    cache: &Record,
    lease: std::sync::Arc<File>,
    deadline: Instant,
) -> bool {
    let path = path.to_path_buf();
    let cache = cache.clone();
    #[cfg(test)]
    let gate = TEST_COMMIT.try_with(Clone::clone).ok();
    matches!(
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            tokio::task::spawn_blocking(move || {
                let _lease = lease;
                #[cfg(test)]
                if let Some(gate) = gate
                    && gate
                        .writes
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        == 0
                {
                    gate.started.notify_one();
                    let released = gate.released.lock().unwrap();
                    drop(
                        gate.release
                            .wait_timeout_while(released, Duration::from_secs(5), |released| {
                                !*released
                            })
                            .unwrap(),
                    );
                }
                verify_lease(&path, &_lease)?;
                persist(&path, &cache)
            })
        )
        .await,
        Ok(Ok(Ok(())))
    )
}

fn completed_report(context: &LocalUpdateContext, cache: &Record) -> Value {
    if context.managed() && LocalUpdateContext::observe(&context.config_path).key() != context.key()
    {
        report(context, Some(cache), false, "context_changed")
    } else {
        report(
            context,
            Some(cache),
            cache.outcome == "success",
            &cache.reason,
        )
    }
}

#[cfg(test)]
#[path = "advisory_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "advisory_discovery_tests.rs"]
mod discovery_tests;
