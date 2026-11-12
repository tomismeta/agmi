//! Explicit latest-stable discovery and verified handoff to the canonical installer.
//! GitHub HTTPS authenticates the publisher origin; checksums are not signatures.
use crate::{installer, lifecycle};
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

const API: &str = "https://api.github.com/repos/tomismeta/agmi";
const DOWNLOAD: &str = "https://github.com/tomismeta/agmi/releases/download";
const METADATA_LIMIT: usize = 2 * 1024 * 1024;
const TEXT_LIMIT: usize = 64 * 1024;
const ARCHIVE_LIMIT: usize = 128 * 1024 * 1024;
const EXPANDED_LIMIT: u64 = 256 * 1024 * 1024;
const CHILD_LIMIT: usize = 2 * 1024 * 1024;
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
    fn parse(text: &str, published: bool, retained: bool) -> Result<Self> {
        let map = fields(text)?;
        let get = |key| map.get(key).copied().context("missing identity field");
        ensure!(get("build_format")? == "1", "unsupported build format");
        ensure!(
            (get("journal_schema")?.parse::<i64>()? == crate::journal::CURRENT_JOURNAL_FORMAT
                || (retained && matches!(get("journal_schema")?, "2" | "3")))
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
    if published.update_protocol != 1 {
        return Ordering::Refused("published_installer_protocol_unsupported");
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
    secure(url)
        && matches!(
            url.host_str(),
            Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com")
        )
        && url.path().starts_with("/github-production-release-asset/")
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
        "check":options.check,"dry_run":options.dry_run,"repository":"tomismeta/agmi",
        "trust":"GitHub HTTPS publisher origin; SHA256 integrity is not an independent signature"},
        "repair":{"status":if options.repair && options.dry_run {"planned"} else if options.repair {"pending"} else {"not_requested"}},
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
    let identity = Identity::parse(&current.manifest, false, true)
        .map_err(|_| failure("update_installed_identity_invalid"))?;
    Ok((current, identity))
}

fn safe_enum(value: &Value, allowed: &[&str], fallback: &str) -> Value {
    json!(
        value
            .as_str()
            .filter(|value| allowed.contains(value))
            .unwrap_or(fallback)
    )
}

fn safe_intervention(value: &Value) -> Value {
    let mut result = json!({
        "status":safe_enum(&value["status"], &["none_required", "automatic_recovery", "operator_required", "undetermined"], "undetermined"),
        "reason":safe_enum(&value["reason"], &[
            "not_initialized", "local_evidence_unavailable", "identity_mismatch", "api_routing_mismatch",
            "config_reload_rejected", "controller_stopped", "clock_regressed", "effective_policy_unavailable",
            "controller_unobserved", "controller_stale", "controller_evidence_unavailable", "controller_recent",
            "bound_reconciliation_pending", "reconciliation_evidence_unavailable", "reconciliation_authentication_failed",
            "unbound_uncertainty", "capacity_evidence_unavailable", "participation_policy_unavailable",
            "manual_authorization_required", "manual_authorization_unobserved", "participation_disabled",
            "retry_deadline_unavailable", "uncertainty_grace", "retained_retry_minimum", "uncertain_answer_retry_delay",
            "answer_attempt_budget_exhausted", "generation_changed", "effect_in_flight", "admission_paused",
            "hosted_identity_unverified", "read_authentication_failed", "read_authentication_evidence_stale",
            "in_flight_outcome_overdue", "hosted_identity_unobserved", "no_eligible_assignments_observed",
            "hosted_identity_authentication_failed", "hosted_identity_mismatch",
            "hosted_identity_unavailable", "hosted_identity_invalid_response", "hosted_identity_legacy_unknown",
            "model_authentication_failed", "model_configuration_failed", "model_attempt_budget_exhausted",
            "admission_recovery_unproven", "model_retry_eligible", "model_uncertain", "model_retry_unavailable",
            "model_retry_evidence_unavailable", "unbound_outcome_requires_evidence", "admission_evidence_unavailable",
            "read_outcome_overdue", "read_in_flight", "read_backoff", "completion_evidence_stale",
            "capability_read_only", "capability_off", "work_evidence_unavailable", "effective_mode_unavailable",
            "answer_retry_reserved", "answer_retry_blocked", "answer_retry_progress_unproven",
            "runtime_restored_observation_pending", "doctor_repair_unavailable", "state_disk_space_low",
            "config_changed_during_doctor",
        ], "activated_doctor_reason_unrecognized"),
        "next_action":safe_enum(&value["next_action"], &[
            "none", "inspect_local_evidence", "initialize_controller", "repair_config", "start_controller",
            "await_reconciliation", "review_credentials", "inspect_operations", "authorize",
            "review_participation_policy", "await_retry_eligibility", "discard_unsent", "await_effect",
            "resume", "read_job", "read_receipt", "review_model_configuration", "inspect_model_attempts",
            "retry_model", "recover_model", "await_assignments", "await_challenge", "observe_assignments",
            "observe_challenge", "await_answer_retry", "inspect_answer_retry", "inspect_repair_failure",
            "inspect_state_filesystem", "await_identity",
        ], "inspect_local_evidence"),
        "evidence":"local_only"
    });
    for key in ["next_at", "observed_at"] {
        result[key] = value[key]
            .as_i64()
            .filter(|time| *time >= 0)
            .map_or(Value::Null, |time| json!(time));
    }
    for key in ["unattended", "evidence_fresh", "observation_fresh", "ready"] {
        result[key] = value[key].as_bool().map_or(Value::Null, Value::Bool);
    }
    result
}

// Only bounded structured readiness crosses the process boundary. In particular,
// child stderr, raw reports, diagnostic messages and arbitrary strings never do.
fn doctor_outcome(report: &mut Value, data: &Value, repair: bool, exited: bool) {
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
        readiness["intervention"]["controller"] = intervention(&data["intervention"]["controller"]);
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
            readiness["work"][lane] = json!({
                "phase":safe_enum(&work["phase"], &["stopped", "blocked", "preparing", "prepared", "generating", "dispatching",
                    "queued", "observing", "answered", "completed", "included", "waiting"], "unknown"),
                "progress":safe_enum(&work["progress"], &["waiting", "blocked", "working", "idle", "complete"], "waiting"),
                "intervention":intervention(&work["intervention"]),
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
                && readiness["work"][lane]["intervention"]["status"] == "operator_required"
            {
                for key in ["status", "reason", "next_action", "next_at"] {
                    readiness["intervention"][key] =
                        readiness["work"][lane]["intervention"][key].clone();
                }
                readiness["intervention"]["unattended"] = json!(false);
            }
        }
    }
    report["readiness"] = readiness;
    if repair {
        let complete = data["repair_requested"] == true
            && data["repairs"].get("failure").is_some()
            && ["eligible", "ineligible", "applied", "skipped"]
                .iter()
                .all(|key| data["repairs"][*key].is_array());
        let status = match data["repair_outcome"].as_str() {
            Some("applied")
                if complete
                    && data["repairs"]["applied"]
                        .as_array()
                        .is_some_and(|rows| !rows.is_empty()) =>
            {
                "applied"
            }
            Some("no_eligible_repairs")
                if complete
                    && data["repairs"]["eligible"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                    && data["repairs"]["applied"]
                        .as_array()
                        .is_some_and(Vec::is_empty) =>
            {
                "no_eligible_repairs"
            }
            Some("skipped")
                if complete
                    && data["repairs"]["skipped"]
                        .as_array()
                        .is_some_and(|rows| !rows.is_empty())
                    && data["repairs"]["applied"]
                        .as_array()
                        .is_some_and(Vec::is_empty) =>
            {
                "skipped"
            }
            _ => "failed",
        };
        report["repair"]["status"] = json!(status);
        for key in ["eligible", "ineligible", "applied", "skipped"] {
            if let Some(rows) = data["repairs"][key].as_array() {
                report["repair"][format!("{key}_count")] = json!(rows.len());
                report["repair"][key] = Value::Array(rows.iter().take(256).filter_map(|row| {
                    if row["kind"] == "identity"
                        && row["classification"] == "legacy_identity_evidence_normalization"
                    {
                        return Some(json!({"kind":"identity",
                            "classification":"legacy_identity_evidence_normalization",
                            "reason":safe_enum(&row["reason"], &["eligible", "already_resolved",
                                "identity_evidence_changed", "legacy_identity_evidence_normalized",
                                "not_legacy_identity_failure"], "unavailable")}));
                    }
                    let id = row["operation_id"].as_i64().filter(|id| *id > 0)?;
                    Some(json!({
                        "operation_id":id,
                        "kind":safe_enum(&row["kind"], &["answer", "judge", "mine"], "unknown"),
                        "classification":safe_enum(&row["classification"],
                            &["legacy_429_policy_refusal", "submit_429_pre_enqueue", "submit_503_halt_middleware"], "unavailable"),
                    }))
                }).collect());
                if rows.len() > 256 {
                    report["repair"]["details_truncated"] = json!(true);
                }
            }
        }
        report["repair"]["restoration_verified"] = data["repairs"]["restoration"]["verified"]
            .as_bool()
            .map_or(Value::Null, Value::Bool);
        report["repair"]["restoration"] = json!({
            "verified":report["repair"]["restoration_verified"],
            "runtime":safe_enum(&data["repairs"]["restoration"]["runtime"],
                &["unknown", "unchanged", "restored", "caller_managed", "stopped"], "unknown"),
            "manager_action":safe_enum(&data["repairs"]["restoration"]["manager_action"],
                &["none", "runtime_stop_attempted"], "unrecognized"),
        });
        report["repair"]["evidence_limit"] = json!(
            "Retained local evidence only; no new network verification was performed. Identity normalization retains legacy uncertainty and recorded rejection; it does not verify identity or repair credentials. Refusal response bodies were not retained. Legacy 429 repairs apply the developer's all-429 pre-enqueue refusal contract; hidden body contradictions cannot be ruled out."
        );
        if status == "failed" || !data["repairs"]["failure"].is_null() {
            report["success"] = json!(false);
            report["repair"]["status"] = json!("failed");
            report["repair"]["reason"] = safe_enum(
                &data["repairs"]["failure"],
                &[
                    "repair_report_invalid",
                    "repair_action_failed",
                    "repair_runtime_unavailable",
                    "repair_runtime_stop_failed",
                    "repair_runtime_restore_failed",
                    "repair_interrupted",
                    "doctor_recovery_unavailable",
                    "doctor_account_unavailable",
                    "refusal_recovery_schema",
                    "refusal_recovery_conflict",
                    "refusal_recovery_failed",
                    "identity_evidence_changed",
                    "identity_normalization_failed",
                    "refusal_recovery_ineligible",
                ],
                "doctor_repair_failed",
            );
        }
    }
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
async fn diagnose(report: &mut Value, repair: bool) {
    let result = async {
        let (current, _) = installed()?;
        let args = if repair {
            vec!["--json", "doctor", "--repair"]
        } else {
            vec!["--json", "doctor"]
        };
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
    if result.is_err() {
        report["update"]["doctor_status"] = json!("unavailable");
        if repair {
            report["success"] = json!(false);
            report["repair"] = json!({"status":"failed","reason":"activated_doctor_unavailable","outcome":"unknown"});
        }
    }
}

fn install(report: &mut Value, arguments: &[String], dry_run: bool) -> bool {
    match lifecycle::installer(arguments, dry_run) {
        Ok(result) => {
            report["installation"] = result
                .get("installation")
                .cloned()
                .unwrap_or_else(|| lifecycle::installer_evidence(Some(&result)));
            outcome(
                report,
                true,
                if dry_run { "planned" } else { "updated" },
                if dry_run {
                    "installer_plan_only"
                } else {
                    "installer_completed"
                },
            );
            true
        }
        Err(error) => {
            if let Some(error) = error.downcast_ref::<lifecycle::InstallerError>() {
                report["installation"] = error.evidence.clone();
            }
            outcome(report, false, "failed", "installer_failed");
            false
        }
    }
}

/// Discover the fixed publisher's latest stable release, or explicitly select a
/// local release. Preview paths do not initialize or mutate any user state.
pub async fn run(_config_path: &Path, options: Options<'_>) -> Result<Value> {
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
        !options.check
            || !(options.release.is_some()
                || options.binary.is_some()
                || options.stopped
                || options.repair
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
                && !options.check
        }),
        failure("update_invalid_expected_release")
    );
    if options.release.is_some() || options.binary.is_some() {
        let mut arguments = if let Some(release) = options.release {
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
        if options.stopped {
            arguments.push("--stopped".into());
        }
        if options.migration_only {
            arguments.push("--migration-only".into());
        }
        if let Some(expected) = options.expected_release {
            arguments.extend(["--expected-release".into(), expected.into()]);
        }
        let mut report = report(&options, "operator_selected_local");
        if install(&mut report, &arguments, options.dry_run)
            && !options.dry_run
            && options.expected_release.is_none()
            && !options.migration_only
        {
            diagnose(&mut report, options.repair).await;
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
    let metadata = fetch(
        &client,
        &format!("{API}/releases/latest"),
        false,
        METADATA_LIMIT,
        None,
    )
    .await?;
    let release: Release =
        serde_json::from_slice(&metadata).map_err(|_| failure("update_metadata_invalid"))?;
    let version = release
        .version()
        .map_err(|_| failure("update_metadata_invalid"))?;
    let sums = asset_text(
        &client,
        release
            .asset("SHA256SUMS", TEXT_LIMIT)
            .map_err(|_| failure("update_metadata_invalid"))?,
    )
    .await?;
    let build_info = asset_text(
        &client,
        release
            .asset("BUILD-INFO.txt", TEXT_LIMIT)
            .map_err(|_| failure("update_metadata_invalid"))?,
    )
    .await?;
    verify(
        build_info.as_bytes(),
        &checksum(&sums, "BUILD-INFO.txt").map_err(|_| failure("update_metadata_invalid"))?,
    )?;
    let published = Identity::parse(&build_info, true, false)
        .map_err(|_| failure("update_manifest_invalid"))?;
    ensure!(
        published.version == version,
        failure("update_manifest_invalid")
    );
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
            options.check || options.dry_run,
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
                options.check || options.dry_run,
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
            if !options.check && !options.dry_run {
                diagnose(&mut report, options.repair).await;
            }
            return Ok(report);
        }
        Ordering::Refused(reason) => {
            outcome(
                &mut report,
                options.check || options.dry_run,
                "refused",
                reason,
            );
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
    if options.check || options.dry_run {
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
    if install(&mut report, &arguments, false) {
        diagnose(&mut report, options.repair).await;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_metadata_requires_stable_tag_fixed_origin_and_bounded_assets() {
        let mut release = Release {
            tag_name: "v0.2.0".into(),
            draft: false,
            prerelease: false,
            published_at: Some("published".into()),
            assets: vec![Asset {
                name: "BUILD-INFO.txt".into(),
                size: 857,
                state: "uploaded".into(),
                browser_download_url: format!("{DOWNLOAD}/v0.2.0/BUILD-INFO.txt"),
            }],
        };
        assert_eq!(release.version().unwrap(), Version::new(0, 2, 0));
        assert!(release.asset("BUILD-INFO.txt", TEXT_LIMIT).is_ok());
        release.assets[0].browser_download_url = "https://example.invalid/BUILD-INFO.txt".into();
        assert!(release.asset("BUILD-INFO.txt", TEXT_LIMIT).is_err());
        release.assets[0].browser_download_url = format!("{DOWNLOAD}/v0.2.0/BUILD-INFO.txt");
        release.assets[0].size = TEXT_LIMIT as u64 + 1;
        assert!(release.asset("BUILD-INFO.txt", TEXT_LIMIT).is_err());
        release.prerelease = true;
        assert!(release.version().is_err());
        release.prerelease = false;
        release.tag_name = "v0.2.0-rc.1".into();
        assert!(release.version().is_err());
        release.tag_name = "../v0.2.0".into();
        assert!(release.version().is_err());
    }

    #[test]
    fn ancestry_requires_an_actual_descendant_not_just_a_release_tag() {
        let current = identity("0.1.0", 'a', false);
        let published = identity("0.2.0", 'b', false);
        let evidence = |status: &str, base: &str, merge: &str, ahead: u64, behind: u64| {
            serde_json::to_vec(
                &json!({"url":format!("{API}/compare/{}...{}", current.commit, published.commit),
                "status":status,"base_commit":{"sha":base},
                "merge_base_commit":{"sha":merge},"ahead_by":ahead,"behind_by":behind}),
            )
            .unwrap()
        };
        assert_eq!(
            ancestry_result(
                &evidence("ahead", &current.commit, &current.commit, 1, 0),
                &current,
                &published
            )
            .unwrap(),
            Ordering::Available
        );
        assert_eq!(
            ancestry_result(
                &evidence("behind", &current.commit, &"b".repeat(40), 0, 1),
                &current,
                &published
            )
            .unwrap(),
            Ordering::Current("installed_commit_newer")
        );
        assert_eq!(
            ancestry_result(
                &evidence("diverged", &current.commit, &"b".repeat(40), 1, 1),
                &current,
                &published
            )
            .unwrap(),
            Ordering::Refused("commit_ordering_unverified")
        );
        assert_eq!(
            ancestry_result(
                &evidence("ahead", &current.commit, &"b".repeat(40), 1, 0),
                &current,
                &published
            )
            .unwrap(),
            Ordering::Refused("commit_ordering_unverified")
        );
        assert!(
            ancestry_result(
                &evidence("ahead", &"c".repeat(40), &current.commit, 1, 0),
                &current,
                &published
            )
            .is_err()
        );
        let bytes = evidence("ahead", &current.commit, &current.commit, 1, 0);
        assert!(ancestry_result(&bytes, &current, &identity("0.2.0", 'c', false)).is_err());
        let mut missing: Value = serde_json::from_slice(&bytes).unwrap();
        missing.as_object_mut().unwrap().remove("url");
        assert!(
            ancestry_result(&serde_json::to_vec(&missing).unwrap(), &current, &published).is_err()
        );
    }

    #[test]
    fn changed_selection_discards_readiness_without_erasing_repair_effects() {
        let before = installer::InstalledIdentity {
            manifest: String::new(),
            binary: Path::new("/not-executed").into(),
            release: format!("r-{}", "a".repeat(64)),
            digest: "a".repeat(64),
        };
        let after = installer::InstalledIdentity {
            manifest: String::new(),
            binary: Path::new("/not-executed").into(),
            release: format!("r-{}", "b".repeat(64)),
            digest: "b".repeat(64),
        };
        let initial = json!({"success":true,"update":{},"readiness":{"healthy":true},
            "repair":{"status":"applied","applied_count":1}});
        let mut report = initial.clone();
        qualify_diagnosis(&mut report, &before, Some(&before));
        assert_eq!(report["update"]["doctor_status"], "complete");
        assert_eq!(report["readiness"]["release"], before.release);
        for observed in [None, Some(&after)] {
            let mut report = initial.clone();
            qualify_diagnosis(&mut report, &before, observed);
            assert!(report["readiness"].is_null());
            assert_eq!(report["update"]["doctor_status"], "stale");
            assert_eq!(report["update"]["doctor_release"], before.release);
            assert_eq!(report["repair"]["applied_count"], 1);
            assert_eq!(report["repair"]["status"], "applied");
        }
    }

    #[tokio::test]
    async fn published_check_never_executes_or_writes_user_state() {
        let root = tempfile::tempdir().unwrap();
        let published = identity("0.1.0", 'a', false);
        let name = format!("agmi-v{}-{}.tar.gz", published.version, published.target);
        let publication = Publication {
            release: Release {
                tag_name: "v0.1.0".into(),
                draft: false,
                prerelease: false,
                published_at: Some("published".into()),
                assets: vec![Asset {
                    name: name.clone(),
                    size: 1,
                    browser_download_url: format!("{DOWNLOAD}/v0.1.0/{name}"),
                    state: "uploaded".into(),
                }],
            },
            sums: format!("{}  {name}\n", "b".repeat(64)),
            build_info: String::new(),
            published: published.clone(),
        };
        let current = installer::InstalledIdentity {
            manifest: String::new(),
            binary: root.path().join("must-not-be-executed"),
            release: format!("r-{}", published.digest),
            digest: published.digest.clone(),
        };
        let options = Options {
            release: None,
            binary: None,
            sha256: None,
            check: true,
            dry_run: false,
            repair: false,
            stopped: false,
            migration_only: false,
            expected_release: None,
        };
        let initial = report(&options, "github_latest_stable");
        let result = complete_discovery(
            options,
            initial,
            Ok((current, published)),
            &client().unwrap(),
            publication,
        )
        .await
        .unwrap();
        assert_eq!(result["success"], true);
        assert!(result["readiness"].is_null());
        assert!(result.get("installation").is_none());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn readiness_preserves_intervention_but_drops_unbounded_strings() {
        let options = Options {
            release: None,
            binary: None,
            sha256: None,
            check: false,
            dry_run: false,
            repair: false,
            stopped: false,
            migration_only: false,
            expected_release: None,
        };
        let mut result = report(&options, "test");
        let data = json!({"healthy":false,"intervention":{"status":"operator_required",
            "reason":"admission_paused","next_action":"resume","unattended":false,
            "controller":{"ready":true,"reason":"controller_recent"},
            "lanes":{"answer":"operator_required"}},"work":{"answer":{"progress":"blocked",
            "intervention":{"status":"operator_required","reason":"secret-response-body",
                "next_action":"https://credential@example.invalid"}}}});
        doctor_outcome(&mut result, &data, false, false);
        assert_eq!(result["readiness"]["intervention"]["unattended"], false);
        assert_eq!(
            result["readiness"]["intervention"]["controller"]["ready"],
            true
        );
        assert_eq!(
            result["readiness"]["work"]["answer"]["intervention"]["status"],
            "operator_required"
        );
        assert!(!result.to_string().contains("secret-response-body"));
        assert!(!result.to_string().contains("credential"));
    }

    #[test]
    fn legacy_child_boolean_neither_verifies_nor_rejects_identity() {
        for verified in [false, true] {
            let data = json!({"initialized":true,"hosted_identity_verified":verified});
            let mut report = json!({"success":true});
            doctor_outcome(&mut report, &data, false, false);
            let identity = &report["readiness"]["hosted_identity"];
            assert_eq!(identity["status"], "legacy_unknown");
            assert_eq!(identity["rejection"], Value::Null);
            assert_eq!(identity["legacy_failure"], !verified);
            assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
        }
    }

    #[test]
    fn legacy_child_identity_is_uncertain_without_hiding_independent_operator_work() {
        let old = json!({"status":"operator_required","reason":"hosted_identity_unverified",
            "next_action":"review_credentials","unattended":false});
        let mut data = json!({"initialized":true,"hosted_identity_verified":false,
            "intervention":old,"work":{}});
        for lane in ["answer", "judge", "mine"] {
            data["work"][lane]["intervention"] = old.clone();
            data["intervention"]["lanes"][lane] = json!("operator_required");
        }
        let mut report = json!({"success":true});
        doctor_outcome(&mut report, &data, false, false);
        let readiness = &report["readiness"];
        assert_eq!(readiness["hosted_identity"]["status"], "legacy_unknown");
        assert_eq!(readiness["hosted_identity_verified"], Value::Null);
        assert_eq!(readiness["intervention"]["status"], "undetermined");
        assert_eq!(readiness["intervention"]["unattended"], Value::Null);
        assert_eq!(
            readiness["intervention"]["next_action"],
            "inspect_local_evidence"
        );
        for lane in ["answer", "judge", "mine"] {
            assert_eq!(readiness["intervention"]["lanes"][lane], "undetermined");
            assert_ne!(
                readiness["work"][lane]["intervention"]["next_action"],
                "review_credentials"
            );
        }
        data["work"]["judge"]["intervention"] = json!({"status":"operator_required",
            "reason":"model_authentication_failed","next_action":"review_model_configuration"});
        doctor_outcome(&mut report, &data, false, false);
        assert_eq!(
            report["readiness"]["intervention"]["status"],
            "operator_required"
        );
        assert_eq!(report["readiness"]["intervention"]["unattended"], false);
        assert_eq!(
            report["readiness"]["intervention"]["reason"],
            "model_authentication_failed"
        );
        assert_eq!(
            report["readiness"]["intervention"]["next_action"],
            "review_model_configuration"
        );
    }

    #[test]
    fn identity_repairs_survive_without_operation_ids_and_remain_bounded() {
        let identity = json!({"kind":"identity","classification":"legacy_identity_evidence_normalization",
            "evidence":"private-evidence","credential":"private-credential"});
        let data = json!({"healthy":false,"initialized":true,"repair_requested":true,
            "repair_outcome":"applied",
            "hosted_identity":{"status":"legacy_unknown","observed_at":100,
                "last_verified_at":null,"rejection":null,"legacy_failure":true,
                "raw":"private-upstream-body"},
            "intervention":{"status":"undetermined","reason":"hosted_identity_legacy_unknown",
                "next_action":"inspect_local_evidence"},
            "repairs":{"eligible":[identity.clone()],"ineligible":[identity.clone()],
                "applied":[identity.clone(),{"operation_id":7,"kind":"answer",
                    "classification":"submit_429_pre_enqueue"}],
                "skipped":[identity],"failure":null,"restoration":{"verified":true}}});
        let mut report = json!({"success":true,"update":{},"repair":{}});
        doctor_outcome(&mut report, &data, true, false);
        assert_eq!(report["success"], true);
        assert_eq!(report["repair"]["status"], "applied");
        assert_eq!(report["repair"]["applied_count"], 2);
        assert_eq!(report["repair"]["applied"][1]["operation_id"], 7);
        assert_eq!(
            report["readiness"]["hosted_identity"]["legacy_failure"],
            true
        );
        assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
        assert_eq!(
            report["readiness"]["intervention"]["reason"],
            "hosted_identity_legacy_unknown"
        );
        assert!(!report.to_string().contains("private-"));

        let mut data = data;
        data["hosted_identity"]["status"] = json!("unavailable");
        data["hosted_identity"]["rejection"] = json!("authentication_failed");
        data["intervention"] = json!({"status":"operator_required",
            "reason":"hosted_identity_authentication_failed","next_action":"review_credentials"});
        doctor_outcome(&mut report, &data, true, false);
        assert_eq!(report["readiness"]["hosted_identity_verified"], false);
        assert_eq!(
            report["readiness"]["intervention"]["reason"],
            "hosted_identity_authentication_failed"
        );
        data["hosted_identity"]["rejection"] = Value::Null;
        data["intervention"] = json!({"status":"automatic_recovery",
            "reason":"hosted_identity_unavailable","next_action":"await_identity","next_at":120});
        doctor_outcome(&mut report, &data, true, false);
        assert_eq!(
            report["readiness"]["intervention"]["next_action"],
            "await_identity"
        );
        assert_eq!(report["readiness"]["intervention"]["next_at"], 120);
        assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
        // New evidence can make the proposed repair unnecessary without making
        // the update fail or manufacturing successful identity verification.
        data["repair_outcome"] = json!("skipped");
        data["repairs"]["applied"] = json!([]);
        data["repairs"]["skipped"][0]["reason"] = json!("identity_evidence_changed");
        doctor_outcome(&mut report, &data, true, false);
        assert_eq!(report["success"], true);
        assert_eq!(report["repair"]["status"], "skipped");
        assert_eq!(
            report["repair"]["skipped"][0]["reason"],
            "identity_evidence_changed"
        );
        assert_eq!(report["readiness"]["hosted_identity_verified"], Value::Null);
    }

    fn identity(version: &str, commit: char, dirty: bool) -> Identity {
        Identity {
            version: Version::parse(version).unwrap(),
            commit: commit.to_string().repeat(40),
            dirty,
            target: "x86_64-unknown-linux-musl".into(),
            digest: commit.to_string().repeat(64),
            update_protocol: 1,
        }
    }
    #[test]
    fn never_replace_newer_dirty_or_same_commit_different_build() {
        let published = identity("0.1.0", 'a', false);
        assert_eq!(
            ordering(&identity("0.2.0", 'b', false), &published),
            Ordering::Current("installed_version_newer")
        );
        assert_eq!(
            ordering(&identity("0.1.0", 'b', true), &published),
            Ordering::Refused("installed_dirty_build_preserved")
        );
        assert_eq!(
            ordering(&identity("0.1.0", 'b', false), &published),
            Ordering::Compare
        );
        assert_eq!(
            ordering(&identity("0.0.1", 'b', false), &published),
            Ordering::Compare
        );
        let mut rebuilt = published.clone();
        rebuilt.digest = "b".repeat(64);
        assert_eq!(
            ordering(&rebuilt, &published),
            Ordering::Refused("same_commit_different_build_preserved")
        );
    }
    #[test]
    fn incompatible_incoming_installer_is_never_offered_for_activation() {
        let current = identity("0.1.0", 'a', false);
        let mut published = identity("0.2.0", 'b', false);
        for protocol in [0, 2] {
            published.update_protocol = protocol;
            assert_eq!(
                ordering(&current, &published),
                Ordering::Refused("published_installer_protocol_unsupported")
            );
        }
        published.update_protocol = 1;
        assert_eq!(ordering(&current, &published), Ordering::Compare);
    }
    #[test]
    fn redirect_allowlist_requires_exact_https_asset_hosts_and_paths() {
        for url in [
            "http://release-assets.githubusercontent.com/github-production-release-asset/a",
            "https://evil.example/github-production-release-asset/a",
            "https://release-assets.githubusercontent.com.evil.example/github-production-release-asset/a",
            "https://user@release-assets.githubusercontent.com/github-production-release-asset/a",
            "https://release-assets.githubusercontent.com:444/github-production-release-asset/a",
            "https://github.com/tomismeta/agmi/releases/download/v0.1.0/agmi",
            "https://release-assets.githubusercontent.com/other/a",
        ] {
            assert!(!asset_redirect(&Url::parse(url).unwrap()));
        }
        assert!(asset_redirect(&Url::parse("https://release-assets.githubusercontent.com/github-production-release-asset/1/2?signature=opaque").unwrap()));
    }
    #[test]
    fn checksum_rejects_duplicate_malformed_and_mismatching_entries() {
        let digest = format!("{:x}", Sha256::digest(b"hello"));
        let sums = format!("{digest}  BUILD-INFO.txt\n");
        assert_eq!(checksum(&sums, "BUILD-INFO.txt").unwrap(), digest);
        assert!(checksum(&(sums.clone() + &sums), "BUILD-INFO.txt").is_err());
        assert!(checksum("invalid", "BUILD-INFO.txt").is_err());
        assert!(checksum(&sums, "agmi").is_err());
        assert!(verify(b"changed", &digest).is_err());
    }
    #[test]
    fn manifest_requires_schema_target_digest_and_unique_identity() {
        let manifest = format!(
            "{}binary_sha256={}\n",
            include_str!(env!("AGMI_BUILD_MANIFEST_PATH")),
            "a".repeat(64)
        );
        assert!(
            Identity::parse(
                &manifest.replace(
                    &format!("journal_schema={}", crate::journal::CURRENT_JOURNAL_FORMAT),
                    "journal_schema=2",
                ),
                false,
                false
            )
            .is_err()
        );
        for schema in ["2", "3"] {
            let retained = manifest.replace(
                &format!("journal_schema={}", crate::journal::CURRENT_JOURNAL_FORMAT),
                &format!("journal_schema={schema}"),
            );
            assert!(Identity::parse(&retained, false, true).is_ok());
            assert!(Identity::parse(&retained, false, false).is_err());
        }
        assert!(
            Identity::parse(
                &manifest.replace("binary_sha256=", "not_a_digest="),
                false,
                false
            )
            .is_err()
        );
        assert!(Identity::parse(&(manifest.clone() + "target=other\n"), false, false).is_err());
        assert!(
            Identity::parse(
                &manifest.replace("stop_timeout=infinity", "stop_timeout=30"),
                false,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn partial_repair_failure_preserves_activation_and_separates_health() {
        let options = Options {
            release: None,
            binary: None,
            sha256: None,
            check: false,
            dry_run: false,
            repair: true,
            stopped: false,
            migration_only: false,
            expected_release: None,
        };
        let mut report = report(&options, "test");
        outcome(&mut report, true, "updated", "installer_completed");
        report["installation"] = json!({"activation":"loaded_verified"});
        doctor_outcome(
            &mut report,
            &json!({"healthy":false,"attention_required":true,"repair_outcome":"failed","repairs":{"applied":[1],"failure":"repair_runtime_restore_failed","restoration":{"verified":false}},"secret":"must_not_escape"}),
            true,
            false,
        );
        assert_eq!(report["success"], false);
        assert_eq!(report["update"]["status"], "updated");
        assert_eq!(report["installation"]["activation"], "loaded_verified");
        assert_eq!(report["repair"]["applied_count"], 1);
        assert_eq!(report["repair"]["reason"], "repair_runtime_restore_failed");
        doctor_outcome(
            &mut report,
            &json!({"healthy":false,"repair_outcome":"failed","repairs":{"failure":"private-unrecognized-error"}}),
            true,
            false,
        );
        assert_eq!(report["repair"]["reason"], "doctor_repair_failed");
        assert!(!report.to_string().contains("private-unrecognized-error"));
        assert!(!report.to_string().contains("must_not_escape"));
        // A health failure alone must not alter a successful operation.
        report["success"] = json!(true);
        doctor_outcome(
            &mut report,
            &json!({"healthy":false,"repair_requested":true,"repair_outcome":"no_eligible_repairs","repairs":{"failure":null,"eligible":[],"ineligible":[],"applied":[],"skipped":[]}}),
            true,
            false,
        );
        assert_eq!(report["success"], true);
    }
    #[tokio::test]
    async fn explicit_preview_does_not_create_config_or_state() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("absent/config.toml");
        let binary = root.path().join("absent/agmi");
        let digest = "a".repeat(64);
        let value = run(
            &config,
            Options {
                release: None,
                binary: Some(&binary),
                sha256: Some(&digest),
                check: false,
                dry_run: true,
                repair: true,
                stopped: false,
                migration_only: false,
                expected_release: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(value["success"], true);
        assert_eq!(value["repair"]["status"], "planned");
        assert!(value["readiness"].is_null());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
    #[test]
    fn archive_rejects_links_and_binary_digest_mismatch() {
        let root = tempfile::tempdir().unwrap();
        for link in [false, true] {
            let archive_path = root.path().join(if link { "link.gz" } else { "wrong.gz" });
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                File::create(&archive_path).unwrap(),
                flate2::Compression::fast(),
            ));
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            if link {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_link_name("/outside").unwrap();
                header.set_cksum();
                builder.append_data(&mut header, "agmi", &b""[..]).unwrap();
            } else {
                header.set_size(3);
                header.set_cksum();
                builder
                    .append_data(&mut header, "agmi", &b"bad"[..])
                    .unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
            assert!(
                extract(
                    File::open(archive_path).unwrap(),
                    &root.path().join(if link { "link" } else { "wrong" }),
                    "manifest",
                    &"a".repeat(64)
                )
                .is_err()
            );
        }
    }
}
