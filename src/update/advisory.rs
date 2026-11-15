//! Disposable, passive publisher evidence. Never an installation authority.
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

pub(super) fn source_failure(status: u16, retry_after: Option<&str>) -> Option<SourceFailure> {
    matches!(status, 429 | 503).then(|| SourceFailure {
        floor: retry_after.and_then(retry_floor),
    })
}
pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
pub(super) fn retry_floor(value: &str) -> Option<i64> {
    value
        .parse::<u64>()
        .ok()
        .map(|seconds| now().saturating_add(seconds.min(i64::MAX as u64) as i64))
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
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
struct Cache {
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
fn cache_path() -> Option<PathBuf> {
    let root = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    root.is_absolute().then(|| root.join("agmi/update.json"))
}
fn safe_metadata(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "unsafe cache type"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "unsafe cache ownership"
        );
        if !directory {
            ensure!(metadata.nlink() == 1, "unsafe cache links");
        }
    }
    Ok(())
}
fn read_cache(path: &Path) -> Result<Cache> {
    safe_metadata(path.parent().context("cache parent")?, true)?;
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
    let cache: Cache = serde_json::from_slice(&bytes)?;
    ensure!(cache.format == 1 && cache.source == API, "foreign cache");
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
    Ok(cache)
}
fn initialize(path: &Path) -> Result<()> {
    let parent = path.parent().context("cache parent")?;
    // Only the standard cache base may be created; never follow an existing agmi symlink.
    let base = parent.parent().context("cache base")?;
    if !base.exists() {
        fs::create_dir_all(base)?;
    }
    let metadata = fs::symlink_metadata(base)?;
    ensure!(metadata.is_dir(), "unsafe cache base");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
            "unsafe cache base"
        );
    }
    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(parent) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    safe_metadata(parent, true)
}
fn acquire(path: &Path) -> Result<Option<File>> {
    initialize(path)?;
    let lock_path = path.with_file_name("update.lock");
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
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}
fn persist(path: &Path, cache: &Cache) -> Result<()> {
    safe_metadata(path.parent().context("cache parent")?, true)?;
    let bytes = serde_json::to_vec(cache)?;
    ensure!(bytes.len() as u64 <= LIMIT, "cache too large");
    crate::admin::persist(path, &bytes)
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
fn cache_view(context: &LocalUpdateContext, cache: Option<&Cache>, at: i64) -> Value {
    let mut result = json!({"availability":"unknown","freshness":"missing","reason":"no_compatible_evidence","checked_at":null,"latest_version":null,"background":background_policy(),"owner":context.selected["ownership"],"selected_running_relation":"not_assessed","next_action":{"kind":"use_install_owner"},"installability":"not_assessed","last_good":null});
    if context.managed() {
        result["next_action"] = json!({"kind":"check","argv":["agmi","update","--check"]});
    }
    if context.selected["ownership"] != "managed" && context.selected["ownership"] != "unmanaged" {
        result["next_action"] = json!({"kind":"unavailable"});
    }
    let Some(cache) = cache else { return result };
    result["next_due_at"] = json!(cache.next_due_at.max(cache.retry_not_before.unwrap_or(0)));
    result["reason"] = json!(cache.reason);
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
pub(crate) fn view(context: &LocalUpdateContext, at: i64) -> AdvisoryView {
    let Some(path) = cache_path() else {
        let mut value = cache_view(context, None, at);
        value["freshness"] = json!("unavailable");
        value["reason"] = json!("cache_unavailable");
        return value;
    };
    match read_cache(&path) {
        Ok(cache) => cache_view(context, Some(&cache), at),
        Err(error) => {
            let mut value = cache_view(context, None, at);
            if error
                .downcast_ref::<std::io::Error>()
                .is_none_or(|e| e.kind() != std::io::ErrorKind::NotFound)
            {
                value["freshness"] = json!("unavailable");
                value["reason"] = json!("cache_invalid");
            }
            value
        }
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
fn report(context: &LocalUpdateContext, cache: Option<&Cache>, success: bool, why: &str) -> Value {
    let mut advisory = cache_view(context, cache, now());
    if !success {
        advisory["availability"] = json!("unknown");
        advisory["reason"] = json!(why);
        if advisory["freshness"] == "fresh" {
            advisory["freshness"] = json!("stale");
        }
        advisory["next_action"] = if context.managed() {
            json!({"kind":"check","argv":["agmi","update","--check"]})
        } else if context.selected["ownership"] == "unmanaged" {
            json!({"kind":"use_install_owner"})
        } else {
            json!({"kind":"unavailable"})
        };
        if why == "previous_attempt_incomplete" {
            advisory["next_action"] =
                json!({"kind":"unavailable","reason":"previous_attempt_incomplete"});
        }
    }
    json!({"success":success,"discovery_success":cache.is_some_and(|c|c.outcome=="success") && (success || why=="cache_persistence_failed"),"update":{"check":true,"status":if success { advisory["availability"].as_str().unwrap_or("unknown") } else { "unknown" },"reason":why,"source":"github_latest_stable","current_source":if context.managed() {"managed_selected_release"} else if context.selected["ownership"] == "unmanaged" {"unmanaged_invoker"} else {"unavailable"}},"release_advisory":advisory})
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
    let Some(path) = cache_path() else {
        return report(&context, None, false, "cache_unavailable");
    };
    check_path(context, trigger, deadline, path).await
}
async fn check_path(
    context: LocalUpdateContext,
    trigger: CheckTrigger,
    deadline: Instant,
    path: PathBuf,
) -> Value {
    let invoked_at = now();
    let previous = read_cache(&path).ok();
    let previous_attempt = previous.as_ref().map(|c| c.attempt_id.clone());
    let previous_finished = previous.as_ref().and_then(|c| c.finished_at);
    let lease = loop {
        if request_guard().is_err() {
            return report(&context, previous.as_ref(), false, "check_cancelled");
        }
        match acquire(&path) {
            Ok(Some(lease)) => break lease,
            Ok(None) if matches!(trigger, CheckTrigger::Explicit) => {
                let cache = read_cache(&path).ok();
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
            Err(_) => return report(&context, previous.as_ref(), false, "cache_unavailable"),
        }
    };
    let lease = std::sync::Arc::new(lease);
    let mut cache = read_cache(&path).unwrap_or_default();
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
    // request on that uncertainty; the disposable cache needs operator inspection.
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
    cache.format = 1;
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
        return report(&context, Some(&cache), false, "cache_persistence_failed");
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
    match result {
        Ok(good) => {
            let observed = LocalUpdateContext::observe(&context.config_path);
            // Unmanaged explicit identity is the invoker, not a selected release.
            if context.managed() && observed.key() != context.key() {
                cache.outcome = "failure".into();
                cache.reason = "context_changed".into();
            } else {
                cache.reason = good.reason.clone();
                cache.good = Some(good);
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
    cache.finished_at = Some(now());
    let saved = bounded_persist(&path, &cache, lease.clone(), deadline).await && initial_saved;
    drop(lease);
    report(
        &context,
        Some(&cache),
        cache.outcome == "success" && saved,
        if saved {
            &cache.reason
        } else {
            "cache_persistence_failed"
        },
    )
}

pub async fn standalone_check(config_path: &Path) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut context = LocalUpdateContext::observe(config_path);
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
    if tokio::time::timeout(Duration::from_millis(500), &mut task)
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
        let due = cache_path()
            .and_then(|p| read_cache(&p).ok())
            .map(|c| {
                c.next_due_at
                    .min(at.saturating_add(INTERVAL + 300))
                    .max(c.retry_not_before.unwrap_or(0))
            })
            .unwrap_or(at.saturating_add(INTERVAL + offset(&context)));
        delay = Duration::from_secs(due.saturating_sub(at).max(INTERVAL) as u64);
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
mod tests {
    use super::*;

    fn unmanaged_context() -> LocalUpdateContext {
        LocalUpdateContext {
            config_path: "/unused".into(),
            selected: json!({"ownership":"unmanaged"}),
            identity: None,
        }
    }

    fn pending_request() -> std::sync::Arc<TestRequest> {
        std::sync::Arc::new(TestRequest {
            starts: std::sync::atomic::AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            throttle: None,
        })
    }

    #[tokio::test]
    async fn automatic_clock_rollback_preserves_due_without_contacting_publisher() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let context = unmanaged_context();
        let started = now() + 3600;
        let cache = Cache {
            format: 1,
            source: API.into(),
            context: context.key(),
            started_at: started,
            finished_at: Some(started + 1),
            next_due_at: started + INTERVAL,
            outcome: "failure".into(),
            reason: "release_query_failed".into(),
            attempt_id: "before-clock-rollback".into(),
            ..Cache::default()
        };
        let lease = acquire(&path).unwrap().unwrap();
        persist(&path, &cache).unwrap();
        drop(lease);
        let request = pending_request();
        let result = TEST_REQUEST
            .scope(
                request.clone(),
                check_path(
                    context,
                    CheckTrigger::Automatic,
                    Instant::now() + Duration::from_secs(1),
                    path.clone(),
                ),
            )
            .await;
        assert_eq!(result["update"]["reason"], "not_due");
        assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(read_cache(&path).unwrap().attempt_id, cache.attempt_id);
    }

    #[tokio::test]
    async fn stop_cancels_pending_http_and_restart_is_not_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let (sender, stop) = watch::channel(false);
        let request = pending_request();
        let task = tokio::spawn(CHECK_STOP.scope(
            stop,
            TEST_REQUEST.scope(
                request.clone(),
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Explicit,
                    Instant::now() + Duration::from_secs(20),
                    path.clone(),
                ),
            ),
        ));
        tokio::time::timeout(Duration::from_secs(2), request.started.notified())
            .await
            .unwrap();
        sender.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["update"]["reason"], "check_cancelled");
        assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 1);
        let cache = read_cache(&path).unwrap();
        assert_eq!(cache.outcome, "failure");
        assert_eq!(cache.reason, "check_cancelled");
        assert!(cache.finished_at.is_some());
        assert!(cache.next_due_at >= cache.started_at + INTERVAL);
        let automatic = TEST_TRANSPORT
            .scope(
                BTreeMap::new(),
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Automatic,
                    Instant::now() + Duration::from_secs(1),
                    path.clone(),
                ),
            )
            .await;
        assert_eq!(automatic["update"]["reason"], "not_due");
        let restarted = TEST_TRANSPORT
            .scope(
                BTreeMap::new(),
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Explicit,
                    Instant::now() + Duration::from_secs(1),
                    path,
                ),
            )
            .await;
        assert_eq!(restarted["update"]["reason"], "update_discovery_unverified");
    }

    #[tokio::test]
    async fn parsed_throttle_floor_survives_simultaneously_ready_stop() {
        for status in [429, 503] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("agmi/update.json");
            let (sender, stop) = watch::channel(false);
            let request = std::sync::Arc::new(TestRequest {
                starts: std::sync::atomic::AtomicUsize::new(0),
                started: tokio::sync::Notify::new(),
                throttle: Some((status, sender)),
            });
            let before = now();
            let result = CHECK_STOP
                .scope(
                    stop,
                    TEST_REQUEST.scope(
                        request.clone(),
                        check_path(
                            unmanaged_context(),
                            CheckTrigger::Explicit,
                            Instant::now() + Duration::from_secs(2),
                            path.clone(),
                        ),
                    ),
                )
                .await;
            assert_eq!(result["update"]["reason"], "check_cancelled");
            assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 1);
            let cache = read_cache(&path).unwrap();
            assert_eq!(cache.reason, "check_cancelled");
            assert!(cache.finished_at.is_some());
            assert!(cache.retry_not_before.unwrap() >= before + 3600);
            let result = TEST_TRANSPORT
                .scope(
                    BTreeMap::new(),
                    check_path(
                        unmanaged_context(),
                        CheckTrigger::Explicit,
                        Instant::now() + Duration::from_secs(1),
                        path,
                    ),
                )
                .await;
            assert_eq!(result["update"]["reason"], "source_retry_not_before");
        }
    }

    #[tokio::test]
    async fn stop_during_initial_commit_serializes_cancelled_finalizer_without_http() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let (sender, stop) = watch::channel(false);
        let request = pending_request();
        let gate = std::sync::Arc::new(TestCommit {
            writes: std::sync::atomic::AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            released: std::sync::Mutex::new(false),
            release: std::sync::Condvar::new(),
        });
        let task = tokio::spawn(CHECK_STOP.scope(
            stop,
            TEST_REQUEST.scope(
                request.clone(),
                TEST_COMMIT.scope(
                    gate.clone(),
                    check_path(
                        unmanaged_context(),
                        CheckTrigger::Explicit,
                        Instant::now() + Duration::from_secs(20),
                        path.clone(),
                    ),
                ),
            ),
        ));
        tokio::time::timeout(Duration::from_secs(2), gate.started.notified())
            .await
            .unwrap();
        sender.send(true).unwrap();
        assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(acquire(&path).unwrap().is_none());
        *gate.released.lock().unwrap() = true;
        gate.release.notify_one();
        let result = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["update"]["reason"], "check_cancelled");
        assert_eq!(gate.writes.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(request.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        let cache = read_cache(&path).unwrap();
        assert_eq!(cache.reason, "check_cancelled");
        assert!(cache.finished_at.is_some());
    }

    #[tokio::test]
    async fn prestart_stop_creates_no_cache_or_lease() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let (_sender, stop) = watch::channel(true);
        let result = CHECK_STOP
            .scope(
                stop,
                check_path(
                    unmanaged_context(),
                    CheckTrigger::Explicit,
                    Instant::now() + Duration::from_secs(1),
                    path,
                ),
            )
            .await;
        assert_eq!(result["update"]["reason"], "check_cancelled");
        assert!(!dir.path().join("agmi").exists());
    }

    #[tokio::test]
    async fn host_finalization_allowance_aborts_stalled_task_without_fake_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let lease = acquire(&path).unwrap().unwrap();
        persist(
            &path,
            &Cache {
                format: 1,
                source: API.into(),
                outcome: "in_progress".into(),
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease);
        let task = tokio::spawn(std::future::pending::<()>());
        tokio::time::timeout(Duration::from_secs(1), finish_background(task))
            .await
            .unwrap();
        let cache = read_cache(&path).unwrap();
        assert_eq!(cache.outcome, "in_progress");
        assert!(cache.finished_at.is_none());
    }
    #[test]
    fn lease_is_kernel_owned_and_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let first = acquire(&path).unwrap().unwrap();
        assert!(acquire(&path).unwrap().is_none());
        drop(first);
        assert!(path.with_file_name("update.lock").exists());
        assert!(acquire(&path).unwrap().is_some());
    }
    #[test]
    fn cache_rejects_oversized_and_foreign_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let _lease = acquire(&path).unwrap().unwrap();
        let cache = Cache {
            format: 2,
            source: API.into(),
            ..Default::default()
        };
        persist(&path, &cache).unwrap();
        assert!(read_cache(&path).is_err());
        crate::admin::persist(&path, &vec![b'x'; LIMIT as usize + 1]).unwrap();
        assert!(read_cache(&path).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn cache_symlink_and_hardlink_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let _lease = acquire(&path).unwrap().unwrap();
        let target = dir.path().join("target");
        crate::admin::persist(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_cache(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(read_cache(&path).is_err());
    }
    #[tokio::test]
    async fn attempt_persistence_failure_refuses_explicit_and_automatic_http() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        initialize(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let context = LocalUpdateContext {
            config_path: dir.path().join("not-created/config.toml"),
            selected: json!({"ownership":"unmanaged"}),
            identity: None,
        };
        for trigger in [CheckTrigger::Explicit, CheckTrigger::Automatic] {
            let result = TEST_TRANSPORT
                .scope(
                    BTreeMap::new(),
                    check_path(
                        context.clone(),
                        trigger,
                        Instant::now() + Duration::from_secs(1),
                        path.clone(),
                    ),
                )
                .await;
            assert_eq!(result["success"], false);
            assert_eq!(result["update"]["reason"], "cache_persistence_failed");
            assert!(!dir.path().join("not-created").exists());
        }
    }

    #[tokio::test]
    async fn expired_caller_still_commits_shared_source_floor_under_lease() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let lease = std::sync::Arc::new(acquire(&path).unwrap().unwrap());
        let floor = now() + 3600;
        let cache = Cache {
            format: 1,
            source: API.into(),
            outcome: "failure".into(),
            reason: "update_source_throttled".into(),
            retry_not_before: Some(floor),
            finished_at: Some(now()),
            ..Default::default()
        };
        // A 429/503 learned at the deadline must start its commit, not skip it.
        let _ = bounded_persist(&path, &cache, lease.clone(), Instant::now()).await;
        drop(lease);
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(lease) = acquire(&path).unwrap() {
                assert_eq!(read_cache(&path).unwrap().retry_not_before, Some(floor));
                drop(lease);
                break;
            }
            assert!(
                Instant::now() < until,
                "floor commit did not release its lease"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let context = LocalUpdateContext {
            config_path: "/unused".into(),
            selected: json!({"ownership":"unmanaged"}),
            identity: None,
        };
        let result = TEST_TRANSPORT
            .scope(
                BTreeMap::new(),
                check_path(context, CheckTrigger::Explicit, until, path),
            )
            .await;
        assert_eq!(result["update"]["reason"], "source_retry_not_before");
        assert_eq!(result["success"], false);
    }

    #[tokio::test]
    async fn unfinished_attempt_fails_closed_when_floor_commit_was_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let lease = acquire(&path).unwrap().unwrap();
        persist(
            &path,
            &Cache {
                format: 1,
                source: API.into(),
                outcome: "in_progress".into(),
                started_at: now() - INTERVAL * 2,
                ..Default::default()
            },
        )
        .unwrap();
        drop(lease);
        let context = LocalUpdateContext {
            config_path: "/unused".into(),
            selected: json!({"ownership":"unmanaged"}),
            identity: None,
        };
        for trigger in [CheckTrigger::Explicit, CheckTrigger::Automatic] {
            let result = TEST_TRANSPORT
                .scope(
                    BTreeMap::new(),
                    check_path(
                        context.clone(),
                        trigger,
                        Instant::now() + Duration::from_secs(1),
                        path.clone(),
                    ),
                )
                .await;
            assert_eq!(result["update"]["reason"], "previous_attempt_incomplete");
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static TEST_TRANSPORT: BTreeMap<String, Vec<u8>>;
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    fn fixture() -> (LocalUpdateContext, BTreeMap<String, Vec<u8>>) {
        let mut manifest = String::new();
        for key in IDENTITY_FIELDS {
            let value = match *key {
                "build_format" | "update_protocol" => "1".into(),
                "package_version" => "0.5.0".into(),
                "commit" => "a".repeat(40),
                "source_dirty" => "clean".into(),
                "target" => "x86_64-unknown-linux-musl".into(),
                "profile" => "release".into(),
                "journal_schema" => "4".into(),
                "stop_timeout" => "infinity".into(),
                _ => "b".repeat(64),
            };
            manifest.push_str(&format!("{key}={value}\n"));
        }
        manifest.push_str(&format!("binary_sha256={}\n", "c".repeat(64)));
        let published = Identity::parse(&manifest, true).unwrap();
        let mut current = published.clone();
        current.version = Version::parse("0.4.0").unwrap();
        current.commit = "d".repeat(40);
        current.digest = "e".repeat(64);
        let context = LocalUpdateContext {
            config_path: "/unused".into(),
            selected: json!({"ownership":"managed","root":"/release","release":"base"}),
            identity: Some(current),
        };
        let archive = "agmi-v0.5.0-x86_64-unknown-linux-musl.tar.gz";
        let sums = format!(
            "{:x}  BUILD-INFO.txt\n{}  {archive}\n",
            Sha256::digest(manifest.as_bytes()),
            "f".repeat(64)
        );
        let assets=[("SHA256SUMS",sums.len()),("BUILD-INFO.txt",manifest.len()),(archive,42)].map(|(name,size)|json!({"name":name,"size":size,"state":"uploaded","browser_download_url":format!("{DOWNLOAD}/v0.5.0/{name}")}));
        let mut responses = BTreeMap::new();
        responses.insert(format!("{API}/releases/latest"),serde_json::to_vec(&json!({"tag_name":"v0.5.0","draft":false,"prerelease":false,"published_at":"2026-01-01","assets":assets})).unwrap());
        responses.insert(format!("{DOWNLOAD}/v0.5.0/SHA256SUMS"), sums.into_bytes());
        responses.insert(
            format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt"),
            manifest.into_bytes(),
        );
        let base = context.identity.as_ref().unwrap().commit.clone();
        responses.insert(format!("{API}/compare/{base}...{}",published.commit),serde_json::to_vec(&json!({"url":format!("{API}/compare/{base}...{}",published.commit),"base_commit":{"sha":base},"merge_base_commit":{"sha":base},"status":"ahead","behind_by":0,"ahead_by":1})).unwrap());
        (context, responses)
    }
    #[tokio::test]
    async fn higher_version_still_requires_exact_ancestry() {
        let (context, mut responses) = fixture();
        let client = Client::new();
        TEST_TRANSPORT
            .scope(responses.clone(), async {
                let publication = super::super::discover_publication(&client, true)
                    .await
                    .unwrap();
                assert_eq!(
                    ordering(context.identity.as_ref().unwrap(), &publication.published),
                    Ordering::Compare
                );
                assert_eq!(
                    ancestry(
                        &client,
                        context.identity.as_ref().unwrap(),
                        &publication.published
                    )
                    .await
                    .unwrap(),
                    Ordering::Available
                );
            })
            .await;
        let compare = responses
            .keys()
            .find(|k| k.contains("/compare/"))
            .unwrap()
            .clone();
        responses.insert(compare, b"{}".to_vec());
        TEST_TRANSPORT
            .scope(responses, async {
                let publication = super::super::discover_publication(&client, true)
                    .await
                    .unwrap();
                assert!(
                    ancestry(
                        &client,
                        context.identity.as_ref().unwrap(),
                        &publication.published
                    )
                    .await
                    .is_err()
                );
            })
            .await;
    }
    #[tokio::test]
    async fn checksum_failure_is_not_a_publication() {
        let (_, mut responses) = fixture();
        responses.insert(
            format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt"),
            b"untrusted".to_vec(),
        );
        TEST_TRANSPORT
            .scope(responses, async {
                assert!(
                    super::super::discover_publication(&Client::new(), true)
                        .await
                        .is_err()
                );
            })
            .await;
    }
    #[test]
    fn failed_attempt_future_clock_and_changed_base_do_not_offer_old_good() {
        let (context, responses) = fixture();
        let manifest =
            String::from_utf8(responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone())
                .unwrap();
        let good = Good {
            checked_at: 100,
            context: context.key(),
            availability: "available".into(),
            reason: "verified".into(),
            manifest,
            tag: "v0.5.0".into(),
            archive_sha256: "f".repeat(64),
        };
        let mut cache = Cache {
            format: 1,
            source: API.into(),
            context: context.key(),
            started_at: 99,
            finished_at: Some(100),
            attempt_id: "one".into(),
            outcome: "success".into(),
            reason: "verified".into(),
            next_due_at: 1000,
            retry_not_before: None,
            good: Some(good),
        };
        assert_eq!(
            cache_view(&context, Some(&cache), 200)["availability"],
            "available"
        );
        assert_eq!(
            cache_view(&context, Some(&cache), 99)["availability"],
            "unknown"
        );
        cache.outcome = "failure".into();
        let view = cache_view(&context, Some(&cache), 200);
        assert_eq!(view["availability"], "unknown");
        assert_eq!(view["last_good"]["checked_at"], 100);
        cache.outcome = "success".into();
        let mut other = context.clone();
        other.identity.as_mut().unwrap().commit = "1".repeat(40);
        assert_eq!(
            cache_view(&other, Some(&cache), 200)["availability"],
            "unknown"
        );
        other.identity =
            Some(Identity::parse(&cache.good.as_ref().unwrap().manifest, true).unwrap());
        assert_eq!(
            cache_view(&other, Some(&cache), 200)["availability"],
            "current"
        );
    }
    #[test]
    fn canonical_check_reports_preserve_owner_specific_actions() {
        let (mut context, responses) = fixture();
        let stamp = now();
        let mut cache = Cache {
            format: 1,
            source: API.into(),
            context: context.key(),
            started_at: stamp,
            finished_at: Some(stamp),
            outcome: "success".into(),
            next_due_at: stamp + INTERVAL,
            good: Some(Good {
                checked_at: stamp,
                context: context.key(),
                availability: "available".into(),
                reason: "verified".into(),
                manifest: String::from_utf8(
                    responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone(),
                )
                .unwrap(),
                tag: "v0.5.0".into(),
                archive_sha256: "f".repeat(64),
            }),
            ..Default::default()
        };
        let managed = report(&context, Some(&cache), true, "verified");
        assert_eq!(managed["update"]["status"], "available");
        assert_eq!(
            managed["release_advisory"]["next_action"],
            json!({"kind":"update","argv":["agmi","update"]})
        );
        assert_eq!(
            managed["release_advisory"]["installability"],
            "not_assessed"
        );
        assert!(managed.get("installation").is_none());
        assert!(managed.get("readiness").is_none());
        context.selected["ownership"] = json!("unmanaged");
        cache.context = context.key();
        cache.good.as_mut().unwrap().context = context.key();
        let unmanaged = report(&context, Some(&cache), true, "verified");
        assert_eq!(unmanaged["update"]["status"], "available");
        assert_eq!(
            unmanaged["release_advisory"]["next_action"]["kind"],
            "use_install_owner"
        );
        let failed = report(&context, Some(&cache), false, "cache_persistence_failed");
        assert_eq!(failed["release_advisory"]["availability"], "unknown");
        assert_eq!(
            failed["release_advisory"]["next_action"]["kind"],
            "use_install_owner"
        );
        context.selected["ownership"] = json!("unavailable");
        let unavailable = report(&context, None, false, "managed_installation_unverified");
        assert_eq!(
            unavailable["release_advisory"]["next_action"]["kind"],
            "unavailable"
        );
    }
    #[tokio::test]
    async fn explicit_busy_waits_for_new_completion_not_old_success() {
        let (mut context, responses) = fixture();
        context.selected["ownership"] = json!("unmanaged");
        let manifest =
            String::from_utf8(responses[&format!("{DOWNLOAD}/v0.5.0/BUILD-INFO.txt")].clone())
                .unwrap();
        let stamp = now();
        let good = Good {
            checked_at: stamp,
            context: context.key(),
            availability: "available".into(),
            reason: "verified".into(),
            manifest,
            tag: "v0.5.0".into(),
            archive_sha256: "f".repeat(64),
        };
        let mut cache = Cache {
            format: 1,
            source: API.into(),
            context: context.key(),
            started_at: stamp,
            finished_at: Some(stamp),
            attempt_id: "old".into(),
            outcome: "success".into(),
            reason: "verified".into(),
            next_due_at: stamp + INTERVAL,
            retry_not_before: None,
            good: Some(good),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agmi/update.json");
        let lease = acquire(&path).unwrap().unwrap();
        persist(&path, &cache).unwrap();
        let result = check_path(
            context.clone(),
            CheckTrigger::Explicit,
            Instant::now() + Duration::from_millis(10),
            path.clone(),
        )
        .await;
        assert_eq!(result["success"], false);
        assert_eq!(result["update"]["reason"], "check_in_progress");
        cache.finished_at = None;
        cache.outcome = "in_progress".into();
        persist(&path, &cache).unwrap();
        let destination = path.clone();
        let completed = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cache.finished_at = Some(now());
            cache.outcome = "success".into();
            persist(&destination, &cache).unwrap();
            drop(lease);
        });
        let result = check_path(
            context,
            CheckTrigger::Explicit,
            Instant::now() + Duration::from_secs(1),
            path,
        )
        .await;
        completed.await.unwrap();
        assert_eq!(result["success"], true);
    }
}

// Always initiate the commit, even when HTTP consumed the caller's deadline.
// A cancelled/timed-out fsync retains the OS lease until it finishes. If disk
// failure/crash prevents a floor commit, the durable unfinished attempt fails
// closed on subsequent checks. This cannot survive cache deletion or disk loss.
// No account, installer, credential, or model state enters this blocking task.
async fn bounded_persist(
    path: &Path,
    cache: &Cache,
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
                persist(&path, &cache)
            })
        )
        .await,
        Ok(Ok(Ok(())))
    )
}

fn completed_report(context: &LocalUpdateContext, cache: &Cache) -> Value {
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
