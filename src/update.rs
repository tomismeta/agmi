//! Explicit latest-stable discovery and verified handoff to the canonical installer.
//! GitHub HTTPS authenticates the publisher origin; checksums are not signatures.
use crate::{doctor, installer, lifecycle};
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url};
use semver::Version;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt;

pub mod advisory;

const API: &str = "https://api.github.com/repos/tomismeta/agmi";
const DOWNLOAD: &str = "https://github.com/tomismeta/agmi/releases/download";
const METADATA_LIMIT: usize = 2 * 1024 * 1024;
const TEXT_LIMIT: usize = 64 * 1024;
const ARCHIVE_LIMIT: usize = 128 * 1024 * 1024;
const EXPANDED_LIMIT: u64 = 256 * 1024 * 1024;
const CHILD_LIMIT: usize = doctor::DIAGNOSTIC_CHILD_LIMIT;
const IDENTITY_FIELDS: &[&str] = &[
    "build_format",
    "package_version",
    "commit",
    "source_dirty",
    "target",
    "profile",
    "journal_schema",
    "stop_timeout",
    "update_protocol",
    "unit_agmi_service_sha256",
    "unit_agmi_health_service_sha256",
    "unit_agmi_health_timer_sha256",
    "adapter_hermes_sha256",
    "adapter_openclaw_sha256",
];

pub struct Options<'a> {
    pub release: Option<&'a str>,
    pub binary: Option<&'a Path>,
    pub sha256: Option<&'a str>,
    pub check: bool,
    pub dry_run: bool,
    pub repair: bool,
    pub stopped: bool,
    pub migration_only: bool,
    pub migrate: bool,
    pub proposal: Option<&'a Value>,
    pub expected_token: Option<&'a str>,
    pub accept_risk_change: Option<&'a str>,
    /// Internal incoming-installer fence; not a release-selection override.
    pub expected_release: Option<&'a str>,
}

fn failure(code: &'static str) -> anyhow::Error {
    lifecycle::LifecycleError {
        code,
        message: "Update could not safely complete. Inspect the update outcome; no unverified release is activated.",
    }.into()
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn fields(text: &str) -> Result<BTreeMap<&str, &str>> {
    ensure!(text.len() <= TEXT_LIMIT, "manifest too large");
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').context("invalid manifest")?;
        ensure!(
            !key.is_empty() && !value.is_empty() && values.insert(key, value).is_none(),
            "duplicate manifest field"
        );
    }
    Ok(values)
}

#[derive(Clone, Debug)]
struct Identity {
    version: Version,
    commit: String,
    dirty: bool,
    target: String,
    digest: String,
    update_protocol: u64,
}
impl Identity {
    fn parse(text: &str, published: bool) -> Result<Self> {
        let map = fields(text)?;
        let get = |key| map.get(key).copied().context("missing identity field");
        ensure!(get("build_format")? == "1", "unsupported build format");
        let journal = get("journal_schema")?;
        let journal_format = journal.parse::<u32>()?;
        ensure!(
            journal_format > 0
                && journal.bytes().all(|byte| byte.is_ascii_digit())
                && get("stop_timeout")? == "infinity",
            "incompatible release policy"
        );
        let version = Version::parse(get("package_version")?)?;
        let commit = get("commit")?;
        let digest = get("binary_sha256")?;
        ensure!(hex(commit, 40) && hex(digest, 64), "invalid build identity");
        let dirty = match get("source_dirty")? {
            "clean" => false,
            "dirty" => true,
            _ => anyhow::bail!("unknown source identity"),
        };
        if published {
            ensure!(
                !dirty
                    && version.pre.is_empty()
                    && version.build.is_empty()
                    && get("profile")? == "release",
                "not a stable publisher build"
            );
            for key in IDENTITY_FIELDS
                .iter()
                .filter(|key| key.ends_with("_sha256"))
            {
                ensure!(hex(get(key)?, 64), "invalid embedded checksum");
            }
        }
        Ok(Self {
            version,
            commit: commit.into(),
            dirty,
            target: get("target")?.into(),
            digest: digest.into(),
            update_protocol: map.get("update_protocol").copied().unwrap_or("0").parse()?,
        })
    }
    fn report(&self) -> Value {
        json!({"version":self.version.to_string(),"commit":self.commit,"source_dirty":if self.dirty {"dirty"} else {"clean"},"target":self.target,"binary_sha256":self.digest,"update_protocol":self.update_protocol})
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Ordering {
    Current(&'static str),
    Available,
    Compare,
    Refused(&'static str),
}
fn ordering(current: &Identity, published: &Identity) -> Ordering {
    if published.update_protocol != 1 {
        return Ordering::Refused("published_installer_protocol_unsupported");
    }
    if current.digest == published.digest {
        return Ordering::Current("published_binary_already_installed");
    }
    if current.version > published.version {
        return Ordering::Current("installed_version_newer");
    }
    if current.dirty {
        return Ordering::Refused("installed_dirty_build_preserved");
    }
    if !current.version.pre.is_empty() || !current.version.build.is_empty() {
        return Ordering::Refused("installed_unreleased_build_preserved");
    }
    if current.commit == published.commit {
        return Ordering::Refused("same_commit_different_build_preserved");
    }
    // Version alone does not prove source ordering, including a higher release tag.
    Ordering::Compare
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    published_at: Option<String>,
    assets: Vec<Asset>,
}
struct Publication {
    release: Release,
    published: Identity,
    build_info: String,
    sums: String,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    browser_download_url: String,
    state: String,
}
impl Release {
    fn version(&self) -> Result<Version> {
        ensure!(
            !self.draft && !self.prerelease && self.published_at.is_some(),
            "release is not published stable"
        );
        let version = Version::parse(
            self.tag_name
                .strip_prefix('v')
                .context("invalid stable tag")?,
        )?;
        ensure!(
            version.pre.is_empty()
                && version.build.is_empty()
                && self.tag_name == format!("v{version}"),
            "noncanonical stable tag"
        );
        Ok(version)
    }
    fn asset(&self, name: &str, limit: usize) -> Result<&Asset> {
        let mut found = self.assets.iter().filter(|asset| asset.name == name);
        let asset = found.next().context("release asset unavailable")?;
        ensure!(
            found.next().is_none()
                && asset.state == "uploaded"
                && asset.size > 0
                && asset.size <= limit as u64,
            "invalid release asset"
        );
        ensure!(
            asset.browser_download_url == format!("{DOWNLOAD}/{}/{name}", self.tag_name),
            "untrusted asset origin"
        );
        Ok(asset)
    }
}

fn secure(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.fragment().is_none()
}
fn asset_redirect(url: &Url) -> bool {
    let valid_path = url.path().starts_with("/github-production-release-asset/")
        || url
            .path()
            .strip_prefix("/github-production-release-asset-")
            .is_some_and(|rest| {
                rest.split_once('/').is_some_and(|(id, _)| {
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit())
                })
            });
    secure(url)
        && matches!(
            url.host_str(),
            Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com")
        )
        && valid_path
}
fn client() -> Result<Client> {
    Client::builder()
        .user_agent("agmi-stable-update")
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| failure("update_transport_unavailable"))
}

async fn response(client: &Client, initial: &str, asset: bool) -> Result<reqwest::Response> {
    let mut url = Url::parse(initial).map_err(|_| failure("update_origin_refused"))?;
    ensure!(secure(&url), failure("update_origin_refused"));
    if asset {
        ensure!(
            initial.starts_with(&format!("{DOWNLOAD}/")) && url.query().is_none(),
            failure("update_origin_refused")
        );
    } else {
        ensure!(
            initial.starts_with(&format!("{API}/")) && url.query().is_none(),
            failure("update_origin_refused")
        );
    }
    for redirects in 0..=3 {
        advisory::request_guard()?;
        let response = client
            .get(url.clone())
            .header(
                "Accept",
                if asset {
                    "application/octet-stream"
                } else {
                    "application/vnd.github+json"
                },
            )
            .send()
            .await
            .map_err(|_| failure("update_network_unavailable"))?;
        if response.status().is_redirection() {
            ensure!(asset && redirects < 3, failure("update_redirect_refused"));
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| failure("update_redirect_refused"))?;
            let next = url
                .join(location)
                .map_err(|_| failure("update_redirect_refused"))?;
            ensure!(asset_redirect(&next), failure("update_redirect_refused"));
            url = next;
            continue;
        }
        if let Some(failure) = advisory::source_failure_with_headers(
            response.status().as_u16(),
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            response
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok()),
            response
                .headers()
                .get("x-ratelimit-reset")
                .and_then(|v| v.to_str().ok()),
        ) {
            return Err(failure.into());
        }
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            failure("update_network_unavailable")
        );
        return Ok(response);
    }
    Err(failure("update_redirect_refused"))
}

async fn fetch(
    client: &Client,
    url: &str,
    asset: bool,
    limit: usize,
    expected_size: Option<u64>,
) -> Result<Vec<u8>> {
    advisory::request_guard()?;
    #[cfg(test)]
    if let Some(result) = advisory::test_request().await {
        return result;
    }
    #[cfg(test)]
    if let Ok(result) = advisory::TEST_TRANSPORT.try_with(|responses| {
        responses
            .get(url)
            .cloned()
            .ok_or_else(|| failure("unexpected_test_request"))
    }) {
        let bytes = result?;
        ensure!(
            bytes.len() <= limit && expected_size.is_none_or(|n| n == bytes.len() as u64),
            failure("update_download_size_invalid")
        );
        return Ok(bytes);
    }
    let mut response = response(client, url, asset).await?;
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= limit as u64
                && expected_size.is_none_or(|expected| expected == size)),
        failure("update_download_size_invalid")
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("update_download_failed"))?
    {
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            failure("update_download_size_invalid")
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(
        expected_size.is_none_or(|expected| expected == bytes.len() as u64),
        failure("update_download_size_invalid")
    );
    Ok(bytes)
}
async fn asset_text(client: &Client, asset: &Asset) -> Result<String> {
    let bytes = fetch(
        client,
        &asset.browser_download_url,
        true,
        TEXT_LIMIT,
        Some(asset.size),
    )
    .await?;
    String::from_utf8(bytes).map_err(|_| failure("update_metadata_invalid"))
}
fn checksum(sums: &str, name: &str) -> Result<String> {
    let mut selected = None;
    let mut names = BTreeSet::new();
    for line in sums.lines() {
        ensure!(line.len() >= 67 && line.is_ascii(), "invalid checksum list");
        let hash = &line[..64];
        let separator = &line[64..66];
        let filename = &line[66..];
        ensure!(
            hex(hash, 64)
                && matches!(separator, "  " | " *")
                && !filename.is_empty()
                && names.insert(filename),
            "invalid checksum entry"
        );
        if filename == name {
            selected = Some(hash.to_owned());
        }
    }
    selected.context("checksum not listed")
}
fn verify(bytes: &[u8], expected: &str) -> Result<()> {
    ensure!(
        format!("{:x}", Sha256::digest(bytes)) == expected,
        failure("update_digest_mismatch")
    );
    Ok(())
}

async fn ancestry(client: &Client, current: &Identity, published: &Identity) -> Result<Ordering> {
    let bytes = fetch(
        client,
        &format!("{API}/compare/{}...{}", current.commit, published.commit),
        false,
        METADATA_LIMIT,
        None,
    )
    .await?;
    ancestry_result(&bytes, current, published)
}

fn ancestry_result(bytes: &[u8], current: &Identity, published: &Identity) -> Result<Ordering> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| failure("update_ordering_unverified"))?;
    ensure!(
        value["url"] == format!("{API}/compare/{}...{}", current.commit, published.commit)
            && value["base_commit"]["sha"] == current.commit
            && value["merge_base_commit"]["sha"]
                .as_str()
                .is_some_and(|value| hex(value, 40)),
        failure("update_ordering_unverified")
    );
    match value["status"].as_str() {
        Some("ahead")
            if value["merge_base_commit"]["sha"] == current.commit
                && value["behind_by"] == 0
                && value["ahead_by"].as_u64().is_some_and(|n| n > 0) =>
        {
            Ok(Ordering::Available)
        }
        Some("behind") => Ok(Ordering::Current("installed_commit_newer")),
        _ => Ok(Ordering::Refused("commit_ordering_unverified")),
    }
}

// Never unpack the archive. Only copy the single regular root binary into our
// private directory; validate all paths/types and bound the entire inflated stream.
fn extract(archive: File, binary: &Path, build_info: &str, expected: &str) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder.take(EXPANDED_LIMIT + 1));
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut found_binary = false;
    let mut found_manifest = false;
    for entry in tar.entries()? {
        let mut entry = entry?;
        ensure!(names.len() < 4096, "too many archive entries");
        let path = entry.path()?.into_owned();
        ensure!(
            !path.as_os_str().is_empty()
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                && names.insert(path.clone()),
            "unsafe or duplicate archive path"
        );
        ensure!(
            entry.header().entry_type().is_file() || entry.header().entry_type().is_dir(),
            "unsupported archive entry"
        );
        let size = entry.size();
        total = total.checked_add(size).context("archive size overflow")?;
        ensure!(total <= EXPANDED_LIMIT, "archive expansion too large");
        if path == Path::new("agmi") {
            ensure!(
                entry.header().entry_type().is_file() && size > 0 && size <= ARCHIVE_LIMIT as u64,
                "invalid executable entry"
            );
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(binary)?;
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 65_536];
            loop {
                let count = entry.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
                file.write_all(&buffer[..count])?;
            }
            file.sync_all()?;
            ensure!(
                format!("{:x}", hash.finalize()) == expected,
                "binary checksum mismatch"
            );
            found_binary = true;
        } else if path == Path::new("BUILD-INFO.txt") {
            ensure!(
                entry.header().entry_type().is_file() && size <= TEXT_LIMIT as u64,
                "invalid archive manifest"
            );
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            ensure!(text == build_info, "archive manifest differs");
            found_manifest = true;
        }
    }
    ensure!(found_binary && found_manifest, "missing release artifacts");
    // Finish the gzip stream to enforce its checksum, including after tar EOF.
    let mut limited = tar.into_inner();
    std::io::copy(&mut limited, &mut std::io::sink())?;
    ensure!(limited.limit() > 0, "archive expansion too large");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn bounded_pipe(
    mut pipe: impl tokio::io::AsyncRead + Unpin,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut buffer = [0u8; 8192];
    loop {
        let count = pipe.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let retain = count.min(CHILD_LIMIT.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retain]);
        overflow |= retain != count;
    }
    Ok((bytes, overflow))
}
async fn child(binary: &Path, args: &[&str], timeout: bool) -> Result<(bool, Vec<u8>)> {
    let mut child = tokio::process::Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| failure("update_child_unavailable"))?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;
    let capture = async {
        let (status, out, err) =
            tokio::join!(child.wait(), bounded_pipe(stdout), bounded_pipe(stderr));
        let status = status.map_err(|_| failure("update_child_failed"))?;
        let (out, overflow) = out.map_err(|_| failure("update_child_failed"))?;
        let (_, error_overflow) = err.map_err(|_| failure("update_child_failed"))?;
        ensure!(
            !overflow && !error_overflow,
            failure("update_child_output_invalid")
        );
        Ok((status.success(), out))
    };
    if timeout {
        tokio::time::timeout(Duration::from_secs(30), capture)
            .await
            .map_err(|_| failure("update_child_timeout"))?
    } else {
        // Existing repair owns graceful infinite stop/restoration. Do not kill it
        // on a guessed deadline and strand the managed runtime mid-restoration.
        capture.await
    }
}
async fn embedded_identity(binary: &Path, published: &str) -> Result<()> {
    let (success, bytes) = child(binary, &["build-info", "--manifest"], true).await?;
    ensure!(success, failure("update_binary_identity_invalid"));
    let text =
        std::str::from_utf8(&bytes).map_err(|_| failure("update_binary_identity_invalid"))?;
    verify_embedded_identity(text, published)
}

fn verify_embedded_identity(text: &str, published: &str) -> Result<()> {
    let actual = fields(text).map_err(|_| failure("update_binary_identity_invalid"))?;
    let expected = fields(published).map_err(|_| failure("update_binary_identity_invalid"))?;
    ensure!(
        actual.len() == IDENTITY_FIELDS.len()
            && IDENTITY_FIELDS
                .iter()
                .all(|key| actual.contains_key(key) && actual.get(key) == expected.get(key)),
        failure("update_binary_identity_invalid")
    );
    Ok(())
}

fn report(options: &Options<'_>, source: &str) -> Value {
    json!({"success":true,"update":{"status":"not_started","reason":"not_started","source":source,
        "check":options.check,"dry_run":options.dry_run,"migrate":options.migrate,"repository":"tomismeta/agmi",
        "trust":"GitHub HTTPS publisher origin; SHA256 integrity is not an independent signature"},
        "repair":{"status":if options.repair && options.dry_run {"planned"} else if options.repair {"pending"} else {"not_requested"}},
        "compatibility":{"classification":"not_assessed","migration_required":false,"target_journal_format":null},
        "migration":{"phase":"unknown","participation_resumed":false},
        "readiness":null})
}
fn outcome(report: &mut Value, success: bool, status: &str, reason: &str) {
    report["success"] = json!(success);
    report["update"]["status"] = json!(status);
    report["update"]["reason"] = json!(reason);
    report["update"]["availability"] = json!(match status {
        "available" => "available",
        "current" | "updated" => "not_available",
        _ => "unknown",
    });
    if !success && report["repair"]["status"] == "pending" {
        report["repair"]["status"] = json!("not_run");
    }
}

fn installed() -> Result<(installer::InstalledIdentity, Identity)> {
    let current =
        installer::installed_identity().map_err(|_| failure("update_installation_unverified"))?;
    let identity = Identity::parse(&current.manifest, false)
        .map_err(|_| failure("update_installed_identity_invalid"))?;
    Ok((current, identity))
}

fn enum_member<'a>(value: &'a Value, allowed: &[&str]) -> Option<&'a str> {
    value.as_str().filter(|value| allowed.contains(value))
}

fn safe_enum(value: &Value, allowed: &[&str], fallback: &str) -> Value {
    json!(enum_member(value, allowed).unwrap_or(fallback))
}

fn diagnostic_reason(value: &Value) -> Option<&str> {
    enum_member(value, crate::health::vocabulary::DIAGNOSTIC_REASONS)
}

fn nonnegative(value: &Value) -> Option<i64> {
    value.as_i64().filter(|value| *value >= 0)
}

fn local_id(value: &Value) -> Option<i64> {
    value.as_i64().filter(|value| *value > 0)
}

fn safe_intervention(value: &Value) -> Value {
    let mut result = json!({
        "status":safe_enum(&value["status"], &["none_required", "automatic_recovery", "operator_required", "undetermined"], "undetermined"),
        "reason":diagnostic_reason(&value["reason"]).unwrap_or("activated_doctor_reason_unrecognized"),
        "next_action":safe_enum(&value["next_action"], crate::health::vocabulary::NEXT_ACTIONS, "inspect_local_evidence"),
        "evidence":"local_only"
    });
    for key in ["next_at", "observed_at"] {
        result[key] = json!(nonnegative(&value[key]));
    }
    for key in ["unattended", "evidence_fresh", "observation_fresh", "ready"] {
        result[key] = value[key].as_bool().map_or(Value::Null, Value::Bool);
    }
    if value["next_observation"].is_object() {
        result["next_observation"] = safe_observation(&value["next_observation"]);
    }
    if value["resolution"] == "polling_not_guaranteed" {
        result["resolution"] = value["resolution"].clone();
    }
    result
}

const STEP_STATES: &[&str] = &[
    "ready",
    "waiting_automatically",
    "needs_operator",
    "intentionally_inactive",
    "unknown",
];
const STEP_TARGETS: &[&str] = &[
    "discovery",
    "preparation",
    "reconciliation",
    "submission",
    "none",
];

fn safe_continuation(source: &Value) -> Value {
    let Some(state) = enum_member(&source["state"], STEP_STATES) else {
        return json!({"state":"unknown","target":null,"reason":null,"not_before":null,
            "operation_id":null,"condition":"unknown"});
    };
    json!({
        "state":state,
        "target":enum_member(&source["target"], STEP_TARGETS),
        "reason":diagnostic_reason(&source["reason"]),
        "not_before":nonnegative(&source["not_before"]),
        "operation_id":local_id(&source["operation_id"]),
        "condition":safe_enum(&source["condition"], &["fresh_work_required", "retry_eligibility",
            "poll_outcome_unknown", "admission_fenced", "none", "unknown"], "unknown"),
    })
}

fn safe_assessment(source: &Value) -> Value {
    let mut assessment = json!({
        "observed_at":nonnegative(&source["observed_at"]),
        "valid_until":nonnegative(&source["valid_until"]),
        "completeness":safe_enum(&source["completeness"],
            &["complete", "single_challenge", "bounded_partial", "partial", "expired", "stale", "unavailable", "unknown"], "unknown"),
        "observed_opportunities":source["observed_opportunities"].as_u64(),
        "eligible_candidates":source["eligible_candidates"].as_u64(),
        "locally_judgeable":source["locally_judgeable"].as_bool(),
        "locally_eligible":source["locally_eligible"].as_bool(),
        "exclusion_reason":enum_member(&source["exclusion_reason"], &["already_answered"]),
        "capped_work_proven":source["capped_work_proven"].as_bool(),
        "assessment_reason":diagnostic_reason(&source["assessment_reason"]),
    });
    if source["exclusions"].is_object() {
        let mut exclusions = serde_json::Map::new();
        for code in [
            "already_attempted",
            "already_settled",
            "configured_exclusion",
            "model_budget_exhausted",
            "assignment_read_backoff",
            "assignment_resource_restricted",
            "model_uncertain_retry_disabled",
            "model_uncertain_replacement_exhausted",
            "model_preparation_reserved",
            "model_retry_cooldown",
        ] {
            if let Some(count) = source["exclusions"][code].as_u64() {
                exclusions.insert(code.into(), json!(count));
            }
        }
        assessment["exclusions"] = Value::Object(exclusions);
    }
    assessment
}

fn safe_findings(source: &Value) -> Value {
    let Some(items) = source["items"].as_array() else {
        return Value::Null;
    };
    let projected: Vec<_> = items.iter().take(8).filter_map(|item| {
        let target = enum_member(&item["target"], STEP_TARGETS).or_else(||
            enum_member(&item["target"], &["lane", "current_inventory", "controller"]))?;
        let state = enum_member(&item["state"], STEP_STATES).or_else(||
            enum_member(&item["state"], &["blocked", "degraded", "healthy", "inactive", "exhausted", "fenced", "waiting"]))?;
        let mut finding = json!({"target":target,"state":state,"reason":diagnostic_reason(&item["reason"]),
            "operation_id":local_id(&item["operation_id"]),"count":item["count"].as_u64(),
            "http_status":item["http_status"].as_u64().filter(|status| (100..=599).contains(status)),
            "dependency":enum_member(&item["dependency"], &["model_attempt", "public_assignment_read",
                "lane_discovery", "job", "receipt", "identity"])});
        for key in ["observed_at", "valid_until", "not_before"] {
            finding[key] = json!(nonnegative(&item[key]));
        }
        Some(finding)
    }).collect();
    let truncated = projected.len() < items.len() || source["truncated"] != false;
    let mut result = json!({"truncated":truncated});
    result["items"] = Value::Array(projected);
    result
}

fn safe_background(source: &Value) -> Value {
    let mut result = json!({
        "count":source["count"].as_u64(),"bound_count":source["bound_count"].as_u64(),
        "unbound_count":source["unbound_count"].as_u64(),
        "required_for_participation":source["required_for_participation"].as_bool().filter(|flag| !*flag),
        "next_action":enum_member(&source["next_action"], &["none", "await_reconciliation", "inspect_operations"]),
        "next_at":nonnegative(&source["next_at"]),
    });
    for key in ["next_observation", "missing_observation"] {
        let row = &source[key];
        if row.is_object() {
            result[key] = safe_observation(row);
        }
    }
    result
}

fn safe_observation(row: &Value) -> Value {
    json!({
        "status":safe_enum(&row["status"], &["in_flight", "waiting", "eligible", "truncated",
            "unavailable", "dispatch_in_flight", "not_assessed", "no_safe_binding", "authentication_failed"], "unknown"),
        "owner":enum_member(&row["owner"], &["account", "answer", "judge", "mine"]),
        "purpose":enum_member(&row["purpose"], &["identity", "job", "receipt"]),
        "operation_id":local_id(&row["operation_id"]),
        "binding_revision":nonnegative(&row["binding_revision"]),
        "not_before":nonnegative(&row["not_before"]),
        "floor_kind":enum_member(&row["floor_kind"], &["operation_poll", "reconciliation_service",
            "historical_missing_binding", "server_restriction", "local_backoff", "retained_floor",
            "shared_restriction"]),
        "http_status":row["http_status"].as_u64().filter(|status| (100..=599).contains(status)),
        "scope":enum_member(&row["scope"], &["background", "current", "unassessed"]),
        "historical_cadence_qualified":row["historical_cadence_qualified"].as_bool(),
        "cadence_seconds":row["cadence_seconds"].as_u64(),
        "binding_age_seconds":row["binding_age_seconds"].as_u64(),
        "consecutive_404":row["consecutive_404"].as_u64(),
    })
}

// Do not relay opaque argv, paths, tokens, or child instructions. A known
// command is copied as-is; stripping arguments could change its target.
fn allowed_action_argv(argv: &Value, authorized: Option<bool>, inspection_only: bool) -> bool {
    let Some((program, args)) = argv.as_array().and_then(|args| args.split_first()) else {
        return false;
    };
    program == "agmi"
        && match args {
            [cmd] => match cmd.as_str() {
                Some("status" | "health" | "reads" | "doctor") => true,
                Some("resume" | "recover-model") => !inspection_only && authorized == Some(true),
                _ => false,
            },
            [cmd, arg] => match (cmd.as_str(), arg.as_str()) {
                (Some("operations"), Some("list"))
                | (Some("config"), Some("show"))
                | (Some("service"), Some("status")) => true,
                (Some("doctor"), Some("--repair")) => !inspection_only && authorized == Some(true),
                (Some("run"), Some("--help")) => authorized == Some(false),
                _ => false,
            },
            [cmd, sub, flag] => cmd == "recover" && sub == "authorize" && flag == "--help",
            _ => false,
        }
}

fn safe_actions(source: &Value, inspection_only: bool) -> Value {
    let Some(actions) = source.as_array() else {
        return Value::Null;
    };
    Value::Array(actions.iter().take(8).filter_map(|row| {
        let kind = enum_member(&row["kind"], &["command", "instruction", "wait"])?;
        let authorized = row["authorization_required"].as_bool();
        let allowed = kind == "command" && allowed_action_argv(&row["argv"], authorized, inspection_only);
        if inspection_only && !(allowed && authorized == Some(false)) {
            return None;
        }
        let mut action = json!({
            "kind":kind,
            "disposition":if inspection_only { Some("inspect") } else {
                enum_member(&row["disposition"], &["inspect","wait","change_intent","repair"])
            },
            "authorization_required":authorized,
        });
        match kind {
            "command" if allowed => action["argv"] = row["argv"].clone(),
            "command" => action["unavailable_reason"] = json!("child_argv_not_allowlisted"),
            "wait" => {
                action["until"] = json!(nonnegative(&row["until"]));
                action["clock"] = json!(enum_member(&row["clock"], &["unix_seconds"]));
                action["evidence"] = json!(enum_member(&row["evidence"], &["reported_local_deadline_not_a_success_guarantee"]));
            }
            _ => action["unavailable_reason"] = json!("child_instruction_not_forwarded"),
        }
        Some(action)
    }).collect())
}

fn repair_counts(repairs: &Value) -> Option<[Option<u64>; doctor::REPAIR_ARRAYS.len()]> {
    let mut exact = [None; doctor::REPAIR_ARRAYS.len()];
    for (slot, key) in exact.iter_mut().zip(doctor::REPAIR_ARRAYS) {
        let count = repairs["counts"].get(key)?;
        if !count.is_null() {
            *slot = Some(count.as_u64()?);
        }
    }
    Some(exact)
}

fn repair_detail(row: &Value) -> Option<Value> {
    let reason = row["reason"].as_str().and_then(doctor::known_repair_reason);
    if row["kind"] == "identity"
        && row["classification"] == "legacy_identity_evidence_normalization"
    {
        return Some(
            json!({"kind":"identity","classification":"legacy_identity_evidence_normalization",
            "reason":reason.unwrap_or("unavailable")}),
        );
    }
    let id = row["operation_id"].as_i64().filter(|id| *id > 0)?;
    Some(json!({
        "operation_id":id,
        "kind":safe_enum(&row["kind"], &["answer", "judge", "mine"], "unknown"),
        "classification":safe_enum(&row["classification"],
            &["legacy_429_policy_refusal", "submit_429_pre_enqueue", "submit_503_halt_middleware"], "unavailable"),
        "reason":reason.unwrap_or("unavailable"),
    }))
}

fn repair_receipt(data: &Value) -> Value {
    const DETAIL_LIMIT: usize = 256;
    let repairs = &data["repairs"];
    let parsed_counts = repair_counts(repairs);
    let counts = parsed_counts.unwrap_or_default();
    let failure = repairs["failure"]
        .as_str()
        .and_then(doctor::known_repair_reason);
    // Success accounts for the entire frozen preview. A reported failure may
    // have stopped early, so its exact observed counts can be incomplete.
    let accounted = match counts {
        [Some(eligible), Some(_), Some(applied), Some(skipped)]
            if applied.checked_add(skipped) == Some(eligible)
                && repairs.get("execution").is_none_or(|execution| {
                    execution
                        == if eligible == 0 {
                            "not_needed"
                        } else {
                            "complete"
                        }
                }) =>
        {
            Some(if applied > 0 {
                "applied"
            } else if skipped > 0 {
                "skipped"
            } else {
                "no_eligible_repairs"
            })
        }
        _ => None,
    };
    let observed = if data["repair_requested"] == true {
        match (data["repair_outcome"].as_str(), repairs.get("failure")) {
            (Some("failed"), _) if failure.is_some() && parsed_counts.is_some() => Some("failed"),
            (Some(outcome), Some(Value::Null)) if accounted == Some(outcome) => accounted,
            _ => None,
        }
    } else {
        None
    };
    let verified = repairs["restoration"]["verified"].as_bool();
    let mut receipt = json!({
        "status":observed.unwrap_or("unknown"),
        "outcome":observed.unwrap_or("unknown"),
        "receipt_status":if observed.is_some() {"complete"} else {"unavailable"},
        "preview":safe_enum(&repairs["preview"], &["complete","unavailable"], "unknown"),
        "execution":safe_enum(&repairs["execution"],
            &["not_requested","not_needed","not_started","complete","partial"], "unknown"),
        "restoration_verified":verified,
        "restoration":{
            "verified":verified,
            "runtime":safe_enum(&repairs["restoration"]["runtime"],
                &["unknown", "unchanged", "restored", "caller_managed", "stopped"], "unknown"),
            "manager_action":safe_enum(&repairs["restoration"]["manager_action"],
                &["none", "runtime_stop", "runtime_stop_attempted"], "unrecognized"),
        },
        "evidence_limit":"Retained local evidence only; no new network verification was performed. Identity normalization retains legacy uncertainty and recorded rejection; it does not verify identity or repair credentials. Refusal response bodies were not retained. Legacy 429 repairs apply the developer's all-429 pre-enqueue refusal contract; hidden body contradictions cannot be ruled out.",
    });
    if receipt["status"] == "failed" {
        receipt["reason"] = json!(failure.expect("observed failure has a known code"));
    } else if observed.is_none() {
        receipt["reason"] = json!("update_doctor_report_invalid");
    }
    let mut truncated = repairs["details_truncated"] == true;
    for (key, count) in doctor::REPAIR_ARRAYS.into_iter().zip(counts) {
        receipt[format!("{key}_count")] = json!(count);
        let mut visible = 0;
        if let Some(rows) = repairs[key].as_array() {
            let projected: Vec<_> = rows
                .iter()
                .take(DETAIL_LIMIT)
                .filter_map(repair_detail)
                .collect();
            visible = projected.len();
            truncated |= visible < rows.len();
            receipt[key] = Value::Array(projected);
        }
        truncated |= count.is_some_and(|count| count > visible as u64);
    }
    receipt["details_truncated"] = json!(if truncated {
        Some(true)
    } else if counts.iter().all(Option::is_some) {
        Some(false)
    } else {
        repairs["details_truncated"].as_bool()
    });
    receipt
}

// Only bounded structured readiness crosses the process boundary. In particular,
// child stderr, raw reports, diagnostic messages and arbitrary strings never do.
fn doctor_outcome(report: &mut Value, data: &Value, repair: bool, exited: bool) {
    let mut inspection_only = false;
    if repair {
        report["repair"] = repair_receipt(data);
        inspection_only = report["repair"]["receipt_status"] == "unavailable";
        if inspection_only || report["repair"]["status"] == "failed" {
            report["success"] = json!(false);
        }
    }
    let mut readiness = json!({"evidence":"local_only","source":"selected_executable"});
    for key in ["healthy", "attention_required", "initialized", "paused"] {
        if let Some(value) = data[key].as_bool() {
            readiness[key] = json!(value);
        }
    }
    let identity = crate::health::hosted_identity(data);
    readiness["hosted_identity"] = identity.value();
    readiness["hosted_identity_verified"] = json!(identity.verified());
    // Older executables emitted only a boolean. Neither value proves a current
    // permit or rejection; translate it only at this subprocess boundary.
    if !data["hosted_identity"].is_object()
        && data["initialized"] != false
        && let Some(verified) = data["hosted_identity_verified"].as_bool()
    {
        readiness["hosted_identity"] = json!({"status":"legacy_unknown","rejection":null,
            "observed_at":null,"last_verified_at":null,"legacy_failure":!verified});
    }
    let legacy_identity =
        !data["hosted_identity"].is_object() && data["hosted_identity_verified"] == false;
    let legacy_root =
        legacy_identity && data["intervention"]["reason"] == "hosted_identity_unverified";
    let intervention = |value: &Value| {
        let mut bounded = safe_intervention(value);
        if legacy_identity && value["reason"] == "hosted_identity_unverified" {
            bounded["status"] = json!("undetermined");
            bounded["reason"] = json!("hosted_identity_legacy_unknown");
            bounded["next_action"] = json!("inspect_local_evidence");
            bounded["next_at"] = Value::Null;
            bounded["unattended"] = Value::Null;
        }
        bounded
    };
    if data["intervention"].is_object() {
        readiness["intervention"] = intervention(&data["intervention"]);
        if let Some(owner) = enum_member(
            &data["intervention"]["owner"],
            &["controller", "answer", "judge", "mine"],
        ) {
            readiness["intervention"]["owner"] = json!(owner);
        }
        let controller = &data["intervention"]["controller"];
        let mut projected = intervention(controller);
        projected["owner"] = safe_enum(
            &controller["owner"],
            &["managed", "foreground", "unknown"],
            "unknown",
        );
        projected["run_mode"] = safe_enum(
            &controller["run_mode"],
            &["continuous", "once", "unknown"],
            "unknown",
        );
        projected["state"] = safe_enum(
            &controller["state"],
            &["running", "stopped", "stale", "unknown"],
            "unknown",
        );
        if readiness["intervention"]["unattended"] == true
            && !(matches!(projected["owner"].as_str(), Some("managed" | "foreground"))
                && projected["run_mode"] == "continuous"
                && projected["state"] == "running"
                && projected["ready"] == true)
        {
            readiness["intervention"]["unattended"] = Value::Null;
        }
        readiness["intervention"]["controller"] = projected;
        for lane in ["answer", "judge", "mine"] {
            readiness["intervention"]["lanes"][lane] = safe_enum(
                &data["intervention"]["lanes"][lane],
                &[
                    "none_required",
                    "automatic_recovery",
                    "operator_required",
                    "undetermined",
                ],
                "undetermined",
            );
            let work = &data["work"][lane];
            let intent = &work["intent"];
            let admission = &work["admission"];
            let step = &work["automatic_step"];
            let modes = &["active", "read_only", "off"];
            readiness["work"][lane] = json!({
                "phase":safe_enum(&work["phase"], &["stopped", "blocked", "preparing", "prepared", "generating", "dispatching",
                    "queued", "observing", "answered", "completed", "included", "waiting"], "unknown"),
                "progress":safe_enum(&work["progress"], &["waiting", "blocked", "working", "idle", "complete"], "undetermined"),
                "intervention":intervention(&work["intervention"]),
                "intent":{
                    "requested_mode":enum_member(&intent["requested_mode"], modes),
                    "effective_mode":enum_member(&intent["effective_mode"], modes),
                    "paused":intent["paused"].as_bool(),
                    "configuration":safe_enum(&intent["configuration"], &["loaded","pending","rejected","unknown"], "unknown"),
                },
                "admission":{
                    "state":safe_enum(&admission["state"], &["not_fenced","fenced","not_applicable","unknown"], "unknown"),
                    "allowed":admission["allowed"].as_bool(),
                    "reason":diagnostic_reason(&admission["reason"]),
                    "not_before":nonnegative(&admission["not_before"]),
                },
                "assessment":safe_assessment(&work["assessment"]),
                "continuation":safe_continuation(&work["continuation"]),
                "automatic_step":if matches!(step["state"].as_str(), Some("ready" | "waiting_automatically")) {
                    safe_continuation(step)
                } else { Value::Null },
                "findings":safe_findings(&work["findings"]),
                "background_recovery":safe_background(&work["background_recovery"]),
                "next_actions":safe_actions(&work["next_actions"], inspection_only),
            });
            if legacy_identity
                && (work["intervention"]["reason"] == "hosted_identity_unverified"
                    || (legacy_root && !work["intervention"].is_object()))
            {
                readiness["intervention"]["lanes"][lane] =
                    readiness["work"][lane]["intervention"]["status"].clone();
            }
            // Removing an unproven legacy rejection must not hide an independently
            // reported operator requirement from another lane.
            if legacy_root
                && readiness["intervention"]["status"] != "operator_required"
                && readiness["work"][lane]["intervention"]["status"] == "operator_required"
            {
                for key in ["status", "reason", "next_action", "next_at"] {
                    readiness["intervention"][key] =
                        readiness["work"][lane]["intervention"][key].clone();
                }
                readiness["intervention"]["owner"] = json!(lane);
                readiness["intervention"]["unattended"] = json!(false);
            }
        }
    }
    readiness["next_actions"] = safe_actions(&data["next_actions"], inspection_only);
    report["readiness"] = readiness;
    // Doctor exits nonzero for unhealthy readiness too. That does not negate a
    // completed update/repair. A missing report, unlike unhealthy data, is failure.
    report["update"]["doctor_exit_success"] = json!(exited);
}
fn qualify_diagnosis(
    report: &mut Value,
    before: &installer::InstalledIdentity,
    after: Option<&installer::InstalledIdentity>,
) {
    report["update"]["doctor_release"] = json!(before.release);
    if after.is_some_and(|after| after.release == before.release && after.digest == before.digest) {
        report["update"]["doctor_status"] = json!("complete");
        report["readiness"]["release"] = json!(before.release);
    } else {
        // Preserve completed repair effects, but never present stale health as
        // evidence about a different (or no longer verifiable) installation.
        report["update"]["doctor_status"] = json!("stale");
        report["readiness"] = Value::Null;
    }
}
async fn diagnose(report: &mut Value, repair: bool, target: Option<&str>) {
    let mut repair_invoked = false;
    let result = async {
        let (current, _) = installed()?;
        ensure!(
            target.is_none_or(|target| current.release == target),
            failure("update_diagnostic_target_changed")
        );
        let args = if repair {
            vec!["--json", "doctor", "--repair"]
        } else {
            vec!["--json", "doctor"]
        };
        repair_invoked = repair;
        let (exited, bytes) = child(&current.binary, &args, !repair).await?;
        let envelope: Value =
            serde_json::from_slice(&bytes).map_err(|_| failure("update_doctor_report_invalid"))?;
        ensure!(
            envelope["schema"] == "agmi.cli.v1"
                && envelope["type"] == "doctor"
                && envelope["data"].is_object()
                && envelope["data"]["healthy"].is_boolean(),
            failure("update_doctor_report_invalid")
        );
        doctor_outcome(report, &envelope["data"], repair, exited);
        let after = installed().ok();
        qualify_diagnosis(
            report,
            &current,
            after.as_ref().map(|(identity, _)| identity),
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        report["update"]["doctor_status"] = json!("unavailable");
        if repair {
            report["success"] = json!(false);
            // Once the child could have run, loss of its receipt cannot establish
            // no effect, rollback, or that it is safe to repeat the repair.
            let may_have_run = repair_invoked
                && error
                    .downcast_ref::<lifecycle::LifecycleError>()
                    .is_none_or(|error| error.code != "update_child_unavailable");
            report["repair"] = json!({
                "status":if may_have_run {"unknown"} else {"not_run"},
                "reason":"activated_doctor_unavailable","receipt_status":"unavailable",
                "outcome":if may_have_run {"unknown"} else {"not_run"},
                "eligible_count":null,"ineligible_count":null,"applied_count":null,"skipped_count":null,
                "details_truncated":null,"restoration_verified":null,
            });
        }
    }
}

// Keep process-boundary metadata bounded independently of private preview data.
fn installer_outcome(
    report: &mut Value,
    result: &Value,
    success: bool,
    dry_run: bool,
    private_preparation: bool,
) {
    let installation = result.get("installation").unwrap_or(result);
    report["installation"] = lifecycle::installer_evidence(Some(installation));
    let metadata = lifecycle::installer_evidence(Some(result));
    for key in ["compatibility", "migration", "restoration"] {
        if let Some(value) = metadata
            .get(key)
            .or_else(|| report["installation"].get(key))
            .filter(|value| !dry_run && value.is_object())
            .cloned()
        {
            report[key] = value;
        }
    }
    if report["restoration"]["status"] == "cancelled"
        && report["installation"]["service"] == "previous_intent_restored"
    {
        report["installation"]["service"] = json!("unknown");
    }
    // Neither arbitrary child output nor an apply's input belongs in the report.
    if private_preparation
        && success
        && !dry_run
        && matches!(
            report["migration"]["phase"].as_str(),
            Some("prepared" | "decision_required")
        )
        && result["private"] == true
        && let Some(preview) = result.get("preview").filter(|value| value.is_object())
    {
        report["private"] = json!(true);
        report["preview"] = preview.clone();
    }
    let (status, reason) = if dry_run && success {
        ("planned", "installer_plan_only")
    } else if report["installation"]["failure_code"] == "decision_required"
        || report["installation"]["status"] == "decision_required"
        || result["status"] == "decision_required"
        || report["migration"]["phase"] == "decision_required"
        || report["migration"]["phase"] == "prepared"
    {
        ("decision_required", "migration_approval_required")
    } else if result["status"] == "conflict" || report["installation"]["status"] == "conflict" {
        ("conflict", "update_transaction_conflict")
    } else if result["status"] == "recovery_required"
        || report["installation"]["status"] == "recovery_required"
        || report["installation"]["failure_code"] == "recovery_required"
    {
        ("recovery_required", "migration_recovery_required")
    } else if result["status"] == "restoration_incomplete"
        || report["installation"]["status"] == "restoration_incomplete"
    {
        ("restoration_incomplete", "previous_intent_not_restored")
    } else if report["installation"]["failure_code"] == "target_replay_fence_required" {
        ("refused", "target_replay_fence_required")
    } else if report["installation"]["failure_code"] == "migration_required"
        || report["migration"]["phase"] == "required"
    {
        ("migration_required", "migration_required")
    } else if matches!(
        report["migration"]["phase"].as_str(),
        Some("recovery_required" | "journal_ready")
    ) || report["migration"]["further_migration_required"] == true
        || report["migration"]["recovery_prerequisite"] == "authority_adoption"
    {
        ("recovery_required", "migration_recovery_required")
    } else if success
        && report["restoration"]["status"] == "cancelled"
        && matches!(
            report["migration"]["phase"].as_str(),
            Some("complete" | "not_required")
        )
    {
        ("updated", "installer_completed_restoration_cancelled")
    } else if report["restoration"].is_object()
        && !(report["restoration"]["status"] == "not_needed"
            || (report["restoration"]["status"] == "restored"
                && report["restoration"]["verified"] == true))
    {
        ("restoration_incomplete", "previous_intent_not_restored")
    } else if !success || report["migration"]["phase"] == "failed" {
        ("failed", "installer_failed")
    } else if report["migration"]["phase"] == "complete"
        && (report["installation"]["operation_mode"] == "maintenance"
            || (report["installation"]["operation_mode"] == "unknown"
                && report["update"]["migrate"] == true))
    {
        (
            "migration_complete_stopped",
            "migration_completed_participation_not_resumed",
        )
    } else if result["status"] == "current" || report["installation"]["status"] == "current" {
        ("current", "installer_completed")
    } else {
        ("updated", "installer_completed")
    };
    outcome(
        report,
        success
            && !matches!(
                status,
                "migration_required"
                    | "refused"
                    | "decision_required"
                    | "recovery_required"
                    | "restoration_incomplete"
                    | "conflict"
                    | "failed"
            ),
        status,
        reason,
    );
}

fn install(
    report: &mut Value,
    arguments: &[String],
    dry_run: bool,
    private_preparation: bool,
) -> bool {
    match lifecycle::installer(arguments, dry_run) {
        Ok(result) => installer_outcome(report, &result, true, dry_run, private_preparation),
        Err(error) => {
            let evidence = error
                .downcast_ref::<lifecycle::InstallerError>()
                .map(|error| error.evidence.clone())
                .unwrap_or(Value::Null);
            installer_outcome(report, &evidence, false, dry_run, false);
        }
    }
    report["success"] == true
        && matches!(
            report["update"]["status"].as_str(),
            Some("updated" | "current")
        )
}

// Own this private file until the synchronous installer (including handoff) ends.
// The public CLI has already consumed explicit stdin; children receive only a path.
fn migration_arguments(
    options: &Options<'_>,
    arguments: &mut Vec<String>,
) -> Result<Option<tempfile::NamedTempFile>> {
    if options.migrate {
        arguments.push("--migrate".into());
    }
    let proposal = if let Some(value) = options
        .proposal
        .filter(|_| !options.dry_run && !options.check)
    {
        let mut file = tempfile::Builder::new()
            .prefix("agmi-update-proposal-")
            .tempfile()
            .map_err(|_| failure("update_proposal_unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| failure("update_proposal_unavailable"))?;
        }
        serde_json::to_writer(file.as_file_mut(), value)
            .map_err(|_| failure("update_invalid_proposal"))?;
        ensure!(
            file.as_file()
                .metadata()
                .map_err(|_| failure("update_proposal_unavailable"))?
                .len()
                <= TEXT_LIMIT as u64,
            failure("update_invalid_proposal")
        );
        file.as_file_mut()
            .flush()
            .map_err(|_| failure("update_proposal_unavailable"))?;
        arguments.extend([
            "--proposal".into(),
            file.path()
                .to_str()
                .ok_or_else(|| failure("update_proposal_unavailable"))?
                .into(),
        ]);
        Some(file)
    } else {
        None
    };
    if let Some(token) = options.expected_token {
        arguments.extend(["--expected-token".into(), token.into()]);
    }
    if let Some(token) = options.accept_risk_change {
        arguments.extend(["--accept-risk-change".into(), token.into()]);
    }
    Ok(proposal)
}

fn validate_pending_target(options: &Options<'_>, target: &str) -> Result<()> {
    ensure!(
        options.release.is_none_or(|release| release == target)
            && options
                .binary
                .is_none_or(|_| options.sha256 == target.strip_prefix("r-")),
        failure("update_pending_target_conflict")
    );
    Ok(())
}

/// Discover the fixed publisher's latest stable release, or explicitly select a
/// local release. Preview paths do not initialize or mutate any user state.
pub async fn run(config_path: &Path, options: Options<'_>) -> Result<Value> {
    ensure!(
        !(options.release.is_some() && (options.binary.is_some() || options.sha256.is_some()))
            && options.binary.is_some() == options.sha256.is_some(),
        failure("update_invalid_arguments")
    );
    ensure!(
        !options.migration_only
            || (options.stopped
                && (options.binary.is_some() || options.release.is_some())
                && !options.check
                && !options.repair),
        failure("update_invalid_arguments")
    );
    ensure!(
        (!options.migrate || (!options.repair && !options.migration_only))
            && (!options.migration_only
                || (options.proposal.is_none() && options.expected_token.is_none()))
            && (options.proposal.is_none() || options.proposal.is_some_and(Value::is_object))
            && (options.expected_token.is_none()
                || (options.release.is_some() && !options.check && !options.dry_run))
            && (options.accept_risk_change.is_none()
                || (options.expected_token.is_some()
                    && options.accept_risk_change == options.expected_token)),
        failure("update_invalid_arguments")
    );
    ensure!(
        !options.check
            || !(options.release.is_some()
                || options.binary.is_some()
                || options.stopped
                || options.repair
                || options.proposal.is_some()
                || options.dry_run),
        failure("update_invalid_arguments")
    );
    ensure!(
        options.expected_release.is_none_or(|release| {
            release
                .strip_prefix("r-")
                .is_some_and(|digest| hex(digest, 64))
                && (options.binary.is_some() || options.release.is_some())
                && !options.repair
                && !options.dry_run
                && !options.check
        }),
        failure("update_invalid_expected_release")
    );
    if options.check {
        return advisory::standalone_check(config_path).await;
    }
    // Recovery routing is deliberately before release discovery, no-op handling,
    // or any interpretation of configuration/journal data by this executable.
    let pending = if options.dry_run {
        None
    } else {
        installer::pending_update_target(config_path)?
    };
    if let Some(target) = pending.as_deref() {
        validate_pending_target(&options, target)?;
    }
    let release = pending.as_deref().or(options.release);
    if release.is_some() || options.binary.is_some() {
        let mut arguments = if let Some(release) = release {
            ensure!(
                release
                    .strip_prefix("r-")
                    .is_some_and(|digest| hex(digest, 64)),
                failure("update_invalid_release_identity")
            );
            vec!["activate".into(), release.into()]
        } else {
            let digest = options.sha256.context("missing digest")?;
            ensure!(hex(digest, 64), failure("update_invalid_release_digest"));
            let binary = std::path::absolute(options.binary.context("missing binary")?)
                .map_err(|_| failure("update_binary_path_unavailable"))?;
            vec![
                "update".into(),
                binary
                    .to_str()
                    .ok_or_else(|| failure("update_binary_path_unavailable"))?
                    .into(),
                "--sha256".into(),
                digest.into(),
            ]
        };
        let target = release
            .map(str::to_owned)
            .unwrap_or_else(|| format!("r-{}", options.sha256.unwrap_or_default()));
        if options.stopped {
            arguments.push("--stopped".into());
        }
        if options.migration_only {
            arguments.push("--migration-only".into());
        }
        if let Some(expected) = options.expected_release {
            arguments.extend(["--expected-release".into(), expected.into()]);
        }
        let mut report = report(
            &options,
            if pending.is_some() {
                "pending_transaction"
            } else {
                "operator_selected_local"
            },
        );
        let _proposal = migration_arguments(&options, &mut arguments)?;
        if install(
            &mut report,
            &arguments,
            options.dry_run,
            options.proposal.is_some() && options.expected_token.is_none() && !options.dry_run,
        ) && !options.dry_run
            && options.expected_release.is_none()
            && !options.migration_only
            && !options.migrate
            && report["installation"]["operation_mode"] != "maintenance"
        {
            diagnose(&mut report, options.repair, Some(&target)).await;
        }
        return Ok(report);
    }
    let mut report = report(&options, "github_latest_stable");
    let current = installed();
    report["update"]["current_source"] = json!(if current.is_ok() {
        "managed_selected_release"
    } else {
        "unavailable"
    });
    report["update"]["invoker"] = crate::runtime::build_info();
    if let Ok((selected, identity)) = &current {
        report["update"]["current"] = identity.report();
        report["update"]["current"]["release"] = json!(selected.release);
    }
    let client = client()?;
    let Publication {
        release,
        published,
        build_info,
        sums,
    } = discover_publication(&client, false).await?;
    complete_discovery(
        options,
        report,
        current,
        &client,
        Publication {
            release,
            published,
            build_info,
            sums,
        },
    )
    .await
}

// Installation and advisory share all publisher/manifest/checksum validation.
async fn discover_publication(client: &Client, bounded: bool) -> Result<Publication> {
    let metadata = advisory::request_budget(
        bounded,
        fetch(
            client,
            &format!("{API}/releases/latest"),
            false,
            METADATA_LIMIT,
            None,
        ),
    )
    .await?;
    let release: Release =
        serde_json::from_slice(&metadata).map_err(|_| failure("update_metadata_invalid"))?;
    let version = release
        .version()
        .map_err(|_| failure("update_metadata_invalid"))?;
    let sums = advisory::request_budget(
        bounded,
        asset_text(client, release.asset("SHA256SUMS", TEXT_LIMIT)?),
    )
    .await?;
    let build_info = advisory::request_budget(
        bounded,
        asset_text(client, release.asset("BUILD-INFO.txt", TEXT_LIMIT)?),
    )
    .await?;
    verify(build_info.as_bytes(), &checksum(&sums, "BUILD-INFO.txt")?)?;
    let published =
        Identity::parse(&build_info, true).map_err(|_| failure("update_manifest_invalid"))?;
    ensure!(
        published.version == version,
        failure("update_manifest_invalid")
    );
    Ok(Publication {
        release,
        published,
        build_info,
        sums,
    })
}

async fn complete_discovery(
    options: Options<'_>,
    mut report: Value,
    current: Result<(installer::InstalledIdentity, Identity)>,
    client: &Client,
    publication: Publication,
) -> Result<Value> {
    let Publication {
        release,
        published,
        build_info,
        sums,
    } = publication;
    report["update"]["published"] = published.report();
    report["update"]["published"]["tag"] = json!(release.tag_name);
    // A musl Linux binary is also compatible with a glibc Linux host. Never infer
    // compatibility merely from the architecture of an arbitrary asset filename.
    let compatible = cfg!(all(target_os = "linux", target_arch = "x86_64"))
        && published.target == "x86_64-unknown-linux-musl"
        || cfg!(all(target_os = "linux", target_arch = "aarch64"))
            && published.target == "aarch64-unknown-linux-musl";
    report["update"]["target_compatible"] = json!(compatible);
    let archive_name = format!("agmi-v{}-{}.tar.gz", published.version, published.target);
    let asset = release
        .asset(&archive_name, ARCHIVE_LIMIT)
        .map_err(|_| failure("update_asset_unavailable"))?;
    let archive_digest =
        checksum(&sums, &archive_name).map_err(|_| failure("update_metadata_invalid"))?;
    if !compatible {
        outcome(
            &mut report,
            options.dry_run,
            "unavailable",
            "published_target_incompatible",
        );
        if options.repair && !options.dry_run {
            report["repair"]["status"] = json!("not_run");
        }
        return Ok(report);
    }
    let (selected, identity) = match current {
        Ok(current) => current,
        Err(_) => {
            outcome(
                &mut report,
                options.dry_run,
                "refused",
                "managed_installation_unverified",
            );
            return Ok(report);
        }
    };
    let mut order = ordering(&identity, &published);
    if order == Ordering::Compare {
        order = ancestry(client, &identity, &published)
            .await
            .unwrap_or(Ordering::Refused("commit_ordering_unverified"));
    }
    match order {
        Ordering::Current(reason) => {
            outcome(&mut report, true, "current", reason);
            if !options.dry_run {
                let mut arguments = vec!["activate".into(), selected.release.clone()];
                arguments.extend(["--expected-release".into(), selected.release.clone()]);
                if options.stopped {
                    arguments.push("--stopped".into());
                }
                let _proposal = migration_arguments(&options, &mut arguments)?;
                if install(
                    &mut report,
                    &arguments,
                    false,
                    options.proposal.is_some() && options.expected_token.is_none(),
                ) && !options.migrate
                    && report["installation"]["operation_mode"] != "maintenance"
                {
                    diagnose(&mut report, options.repair, Some(&selected.release)).await;
                }
            }
            return Ok(report);
        }
        Ordering::Refused(reason) => {
            outcome(&mut report, options.dry_run, "refused", reason);
            return Ok(report);
        }
        Ordering::Available => {}
        Ordering::Compare => unreachable!(),
    }
    outcome(
        &mut report,
        true,
        "available",
        "published_release_descends_installed",
    );
    if options.dry_run {
        return Ok(report);
    }
    // Temporary download storage is separate from configuration, releases and the
    // durable journal. The canonical installer is the only activation primitive.
    let directory = tempfile::Builder::new()
        .prefix("agmi-update-")
        .tempdir()
        .map_err(|_| failure("update_staging_unavailable"))?;
    let archive_path = directory.path().join("release.tar.gz");
    let mut archive =
        File::create(&archive_path).map_err(|_| failure("update_staging_unavailable"))?;
    let mut response = response(client, &asset.browser_download_url, true).await?;
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size == asset.size),
        failure("update_download_size_invalid")
    );
    let mut count = 0u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("update_download_failed"))?
    {
        count += chunk.len() as u64;
        ensure!(
            count <= asset.size && count <= ARCHIVE_LIMIT as u64,
            failure("update_download_size_invalid")
        );
        hash.update(&chunk);
        archive
            .write_all(&chunk)
            .map_err(|_| failure("update_staging_unavailable"))?;
    }
    ensure!(count == asset.size, failure("update_download_size_invalid"));
    ensure!(
        format!("{:x}", hash.finalize()) == archive_digest,
        failure("update_digest_mismatch")
    );
    drop(archive);
    let binary = directory.path().join("agmi");
    extract(
        File::open(&archive_path).map_err(|_| failure("update_staging_unavailable"))?,
        &binary,
        &build_info,
        &published.digest,
    )
    .map_err(|_| failure("update_archive_invalid"))?;
    embedded_identity(&binary, &build_info).await?;
    let (latest, _) = installed()?;
    ensure!(
        latest.release == selected.release && latest.digest == selected.digest,
        failure("update_installation_changed")
    );
    let target = format!("r-{}", published.digest);
    let mut arguments = vec![
        "update".into(),
        binary
            .to_str()
            .ok_or_else(|| failure("update_staging_unavailable"))?
            .into(),
        "--sha256".into(),
        published.digest,
    ];
    arguments.extend(["--expected-release".into(), selected.release]);
    if options.stopped {
        arguments.push("--stopped".into());
    }
    let _proposal = migration_arguments(&options, &mut arguments)?;
    if install(
        &mut report,
        &arguments,
        false,
        options.proposal.is_some() && options.expected_token.is_none(),
    ) && !options.migrate
        && report["installation"]["operation_mode"] != "maintenance"
    {
        diagnose(&mut report, options.repair, Some(&target)).await;
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
