//! Read-only local epoch evidence and explicitly requested public-source refreshes.
use crate::config::Config;
use crate::protocol::reports::{self, ReportInterest, ReportSource};
use crate::store::Store;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CACHE_BYTES: usize = 1024 * 1024;
const COMPONENTS: [&str; 3] = ["settled", "close-report", "expiry-schedule"];
#[derive(Clone, Debug)]
pub struct EpochQuery {
    pub work_epoch: Option<u64>,
    pub close_epoch: Option<u64>,
    pub before: Option<i64>,
    pub limit: usize,
    pub private: bool,
}
impl Default for EpochQuery {
    fn default() -> Self {
        Self {
            work_epoch: None,
            close_epoch: None,
            before: None,
            limit: 50,
            private: false,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    format: u8,
    origin: String,
    chain: String,
    account: String,
    close_epoch: u64,
    components: BTreeMap<String, Component>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    last_attempt: Option<Attempt>,
    last_good: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    at: i64,
    outcome: String,
    reason: Option<String>,
    retry_not_before: Option<i64>,
}
impl Cache {
    fn new(config: &Config, epoch: u64) -> Self {
        Self {
            format: 1,
            origin: reports::ORIGIN.into(),
            chain: config.network.chain.clone(),
            account: config.network.address.clone(),
            close_epoch: epoch,
            components: BTreeMap::new(),
        }
    }
    fn matches(&self, config: &Config, epoch: u64) -> bool {
        self.format == 1
            && self.origin == reports::ORIGIN
            && self.chain == "poa-mainnet-1"
            && config.network.base_url.trim_end_matches('/') == reports::ORIGIN
            && self.chain == config.network.chain
            && self.account == config.network.address
            && self.close_epoch == epoch
            && self.components.len() <= 4
            && self
                .components
                .keys()
                .all(|k| COMPONENTS.contains(&k.as_str()) || k == "raw")
            && self.components.iter().all(|(name, c)| {
                c.last_good
                    .as_ref()
                    .is_none_or(|v| valid_good(name, v, epoch))
                    && c.last_attempt.as_ref().is_none_or(|a| {
                        a.at >= 0
                            && matches!(a.outcome.as_str(), "success" | "failed")
                            && a.reason.as_ref().is_none_or(|r| {
                                r == "incomplete_validation"
                                    || serde_json::from_value::<reports::FailureReason>(json!(r))
                                        .is_ok()
                            })
                    })
            })
    }
}
fn valid_good(name: &str, v: &Value, epoch: u64) -> bool {
    if !v.is_object()
        || v["checked_at"].as_i64().is_none_or(|at| at < 0)
        || !matches!(
            v["coverage"].as_str(),
            Some("partial" | "complete_source" | "aggregate_only" | "known_bindings_only")
        )
    {
        return false;
    }
    let hash_key = if name == "raw" {
        "body_hash"
    } else {
        "content_hash"
    };
    if v[hash_key]
        .as_str()
        .is_none_or(|s| !crate::protocol::valid_txid(s))
    {
        return false;
    }
    if name == "settled" && !v["rows"].is_array() {
        return false;
    }
    if name == "raw"
        && (!v["pending_matches"].is_object()
            || v["index_hash"]
                .as_str()
                .is_none_or(|s| !crate::protocol::valid_txid(s))
            || v["bytes"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > 64 * 1024 * 1024)
            || v["account_reward"]["integrity"] != "index_hash_verified"
            || v["account_reward"]["independent_ledger_verification"] != false
            || !matches!(
                v["account_reward"]["status"].as_str(),
                Some("node_reported" | "not_listed")
            )
            || (v["account_reward"]["status"] == "not_listed")
                != v["account_reward"]["amount"].is_null())
    {
        return false;
    }
    if name == "close-report"
        && (v["report"]["close_epoch"] != epoch
            || v["report"]["close_ts"].as_u64().is_none()
            || v["report"]["settled_count"].as_u64().is_none())
    {
        return false;
    }
    if name == "expiry-schedule"
        && (v["report"]["as_of_close"]
            .as_u64()
            .is_none_or(|n| n > epoch)
            || v["report"]["total_pending"].as_u64().is_none()
            || v["report"]["pending_ttl_epochs"].as_u64().is_none()
            || v["report"]["schedule"].as_array().is_none_or(|s| {
                s.len() > 4096
                    || s.iter().any(|r| {
                        r["expires_at_close"].as_u64().is_none() || r["total"].as_u64().is_none()
                    })
            }))
    {
        return false;
    }
    if let Some(rows) = v.get("rows") {
        let Some(rows) = rows.as_array() else {
            return false;
        };
        if rows.len() > reports::MAX_MATCHES || v["close_epoch"] != epoch {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            let Some(tx) = row["tx"].as_str() else {
                return false;
            };
            if crate::protocol::canonical_txid(tx).ok().as_deref() != Some(tx)
                || !seen.insert(tx)
                || (!row["outcome"].is_null()
                    && !matches!(
                        row["outcome"].as_str(),
                        Some("passed" | "failed" | "expired")
                    ))
                || (!row["jury_alignment"].is_null() && !row["jury_alignment"].is_boolean())
            {
                return false;
            }
        }
    }
    if let Some(pending) = v.get("pending_matches") {
        let Some(pending) = pending.as_object() else {
            return false;
        };
        if v["close_epoch"] != epoch
            || pending.len() > reports::MAX_MATCHES
            || pending.iter().any(|(tx, since)| {
                !crate::protocol::valid_txid(tx) || since.as_u64().is_none_or(|n| n > epoch)
            })
        {
            return false;
        }
        if !v["account_reward"]["amount"].is_null()
            && v["account_reward"]["amount"]
                .as_str()
                .and_then(reports::reward_units)
                .is_none()
        {
            return false;
        }
    }
    true
}
fn directory(config: &Config) -> PathBuf {
    config.state_dir.join("reports")
}
fn path(config: &Config, epoch: u64) -> PathBuf {
    directory(config).join(format!("epoch-{epoch}.json"))
}
fn private_metadata(path: &Path, directory: bool) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "unsafe_report_cache"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && (directory || metadata.nlink() == 1),
            "unsafe_report_cache"
        );
    }
    Ok(metadata)
}
fn open_private(path: &Path, create: bool) -> Result<File> {
    if path.try_exists()? {
        private_metadata(path, false)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    let current = private_metadata(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            opened.dev() == current.dev() && opened.ino() == current.ino(),
            "report_cache_changed"
        );
    }
    Ok(file)
}
fn read_cache(config: &Config, epoch: u64) -> Result<Option<Cache>> {
    if !directory(config).try_exists()? {
        return Ok(None);
    }
    private_metadata(&config.state_dir, true)?;
    private_metadata(&directory(config), true)?;
    if !path(config, epoch).try_exists()? {
        return Ok(None);
    }
    let file = open_private(&path(config, epoch), false)?;
    ensure!(
        file.metadata()?.len() <= CACHE_BYTES as u64,
        "report_cache_limit"
    );
    let mut bytes = Vec::new();
    file.take((CACHE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= CACHE_BYTES, "report_cache_limit");
    let cache: Cache = serde_json::from_slice(&bytes)?;
    ensure!(
        cache.matches(config, epoch),
        "foreign_or_invalid_report_cache"
    );
    Ok(Some(cache))
}
fn interest(config: &Config) -> Result<ReportInterest> {
    match Store::read_only(config)? {
        Some(store) => store.epoch_interest(&config.network.address),
        None => Ok(ReportInterest::new(config.network.address.clone())),
    }
}
/// Pure local view: missing/corrupt/foreign report cache is unavailable, never an account error.
pub fn view(config: &Config, query: EpochQuery) -> Result<Value> {
    ensure!(
        query.work_epoch.is_some() || query.close_epoch.is_some(),
        "an epoch selector is required"
    );
    ensure!(
        (1..=100).contains(&query.limit) && query.before.is_none_or(|n| n > 0),
        "epoch pagination requires limit 1..100 and positive before"
    );
    let (cache, cache_status) = match query.close_epoch {
        Some(epoch) => match read_cache(config, epoch) {
            Ok(Some(c)) => (Some(c), "available"),
            Ok(None) => (None, "missing"),
            Err(_) => (None, "unavailable"),
        },
        None => (None, "not_selected"),
    };
    render(config, query, cache, cache_status)
}
fn render(
    config: &Config,
    query: EpochQuery,
    cache: Option<Cache>,
    cache_status: &str,
) -> Result<Value> {
    let settled = cache
        .as_ref()
        .and_then(|c| c.components.get("settled"))
        .and_then(|c| c.last_good.as_ref());
    let raw = cache
        .as_ref()
        .and_then(|c| c.components.get("raw"))
        .and_then(|c| c.last_good.as_ref());
    let mut matched = Vec::new();
    if let Some(rows) = settled.and_then(|v| v["rows"].as_array()) {
        for row in rows {
            if let Some(tx) = row["tx"].as_str() {
                matched.push(tx.to_owned());
            }
        }
    }
    if let Some(pending) = raw.and_then(|v| v["pending_matches"].as_object()) {
        matched.extend(pending.keys().cloned());
    }
    let work = query
        .work_epoch
        .or(query.close_epoch)
        .context("epoch selector")?;
    let mut page = match Store::read_only(config)? {
        Some(store) => store.epoch_page(
            work,
            query.work_epoch.is_some(),
            &matched,
            query.before,
            query.limit,
            query.private,
        )?,
        None => json!({"rows":[],"truncated":false,"next_before":null}),
    };
    let mut sourced = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut expired = 0;
    let mut answer_rows = 0;
    let mut pending = 0;
    let mut jury = 0;
    if let Some(rows) = page["rows"].as_array_mut() {
        for row in rows {
            let tx = row["_tx"].as_str().map(str::to_owned);
            let candidate = row["_candidate"].as_str().map(str::to_owned);
            if row["kind"] == "answer" {
                answer_rows += 1;
            }
            if let Some(evidence) = settled.and_then(|v| v["rows"].as_array()) {
                for source in evidence {
                    if row["kind"] == "answer"
                        && source["own_answer"] == true
                        && tx.as_deref() == source["tx"].as_str()
                        && !source["outcome"].is_null()
                    {
                        row["settlement"] = json!({"status":source["outcome"],"graded":source["outcome"]!="expired","close_epoch":query.close_epoch,"source":"settled","checked_at":settled.map(|v|&v["checked_at"])});
                        sourced += 1;
                        match source["outcome"].as_str() {
                            Some("passed") => passed += 1,
                            Some("failed") => failed += 1,
                            Some("expired") => expired += 1,
                            _ => {}
                        }
                        row["jury"] = json!({"members":source["jury_size"],"aligned_count":source["jury_aligned"],"close_epoch":query.close_epoch,"scope":"answer_outcome_jury"});
                    }
                    if row["kind"] == "judge"
                        && candidate.as_deref() == source["tx"].as_str()
                        && source["jury_alignment"].is_boolean()
                    {
                        row["jury"] = json!({"aligned":source["jury_alignment"],"close_epoch":query.close_epoch,"scope":"candidate_jury_participation_not_grade_transaction_settlement"});
                        jury += 1;
                    }
                }
            }
            if row["kind"] == "answer"
                && row["settlement"]["status"] == "unknown"
                && tx
                    .as_ref()
                    .is_some_and(|tx| raw.is_some_and(|r| r["pending_matches"].get(tx).is_some()))
            {
                row["settlement"] = json!({"status":"pending_as_of_close","close_epoch":query.close_epoch,"source":"index_hash_verified_raw_basis","checked_at":raw.map(|v|&v["checked_at"])});
                pending += 1;
            }
            if let Some(object) = row.as_object_mut() {
                object.remove("_tx");
                object.remove("_candidate");
            }
        }
    }
    let mut sources = serde_json::Map::new();
    if let Some(cache) = &cache {
        for (name, component) in &cache.components {
            let good = component.last_good.as_ref();
            let mut source = json!({"last_attempt":component.last_attempt,"checked_at":good.map(|v|&v["checked_at"]),
            "age_seconds":good.and_then(|v|v["checked_at"].as_i64()).and_then(|at|reports::now().checked_sub(at)).filter(|n|*n>=0),
            "coverage":good.map(|v|&v["coverage"]),"last_good_available":good.is_some()});
            if name == "settled" {
                source["matched"] = good
                    .and_then(|v| v["matched"].as_u64())
                    .map_or(Value::Null, |n| json!(n));
                source["unlinked_account_rows"] = good
                    .and_then(|v| v["unlinked_account_rows"].as_u64())
                    .map_or(Value::Null, |n| json!(n));
                source["unlinked_account_outcomes"] = good
                    .filter(|v| v["unlinked_account_outcomes"].is_object())
                    .map(|v| {
                        json!({"scope":"account_source_rows_without_local_binding",
                "passed":v["unlinked_account_outcomes"]["passed"].as_u64().unwrap_or(0),
                "failed":v["unlinked_account_outcomes"]["failed"].as_u64().unwrap_or(0),
                "expired":v["unlinked_account_outcomes"]["expired"].as_u64().unwrap_or(0),
                "coverage":v["coverage"]})
                    })
                    .unwrap_or(Value::Null);
            }
            if name == "close-report" {
                source["aggregate"]=good.map(|v|json!({"close_epoch":v["report"]["close_epoch"],"close_ts":v["report"]["close_ts"],"settled_count":v["report"]["settled_count"]})).unwrap_or(Value::Null);
            }
            if name == "expiry-schedule" {
                source["aggregate"]=good.map(|v|json!({"as_of_close":v["report"]["as_of_close"],"pending_ttl_epochs":v["report"]["pending_ttl_epochs"],"total_pending":v["report"]["total_pending"],
            "schedule_count":v["report"]["schedule"].as_array().map_or(0,Vec::len),
            "schedule_truncated":v["report"]["schedule"].as_array().is_some_and(|rows|rows.len()>32),
            "schedule":v["report"]["schedule"].as_array().map(|rows|rows.iter().take(32).map(|r|json!({"expires_at_close":r["expires_at_close"],"total":r["total"]})).collect::<Vec<_>>())})).unwrap_or(Value::Null);
            }
            sources.insert(name.clone(), source);
        }
    }
    let reward=raw.map(|v|{let r=&v["account_reward"];json!({"status":r["status"],"amount":r["amount"],"close_epoch":query.close_epoch,
        "source":"indexed_raw_close","body_hash":v["body_hash"],"checked_at":v["checked_at"],"integrity":"index_hash_verified",
        "independent_ledger_verification":false,"allocation":"account_close_only"})}).unwrap_or_else(||json!({"status":"not_verified","amount":null,"independent_ledger_verification":false}));
    let mut output = json!({"work_epoch":query.work_epoch,"close_epoch":query.close_epoch,"private":query.private,
        "cache":cache_status,"rows":page["rows"],"next_before":page["next_before"],"truncated":page["truncated"],
        "summary":{"scope":"selected_local_operation_page","local_rows":page["rows"].as_array().map_or(0,Vec::len),
            "answer_rows":answer_rows,"sourced_outcomes":sourced,"graded":passed+failed,"passed":passed,"failed":failed,"expired":expired,
            "pending_as_of_close":pending,"unknown_answer_outcomes":answer_rows-sourced-pending,"jury_facts":jury,
            "page_truncated":page["truncated"],"settlement_source_coverage":settled.map(|v|&v["coverage"]).unwrap_or(&Value::Null)},
        "sources":sources,"account_close_reward":reward,"authority":"report_evidence_only","absence_means":"unknown",
        "settlement_source":if query.close_epoch.is_some(){"selected_close"}else{"not_selected"}});
    if query.private
        && let Some(cache) = cache
    {
        output["private_provenance"] =
            json!({"origin":cache.origin,"chain":cache.chain,"account":cache.account});
    }
    Ok(output)
}
/// Explicit refresh only. Failures preserve every component's original last-good observation.
/// Callers must return nonzero when refresh_ok is false, even with retained positive evidence.
pub async fn refresh(config: &Config, query: EpochQuery, raw: bool) -> Result<Value> {
    let source = ReportSource::new(config)?;
    refresh_with_source(config, query, raw, source).await
}
async fn refresh_with_source(
    config: &Config,
    query: EpochQuery,
    raw: bool,
    source: ReportSource,
) -> Result<Value> {
    let close_epoch = query.close_epoch.context("refresh requires close epoch")?;
    ensure!(
        (1..=100).contains(&query.limit) && query.before.is_none_or(|n| n > 0),
        "epoch pagination requires limit 1..100 and positive before"
    );
    let interest = interest(config)?; // Drop the read-only connection before HTTP.
    if !config.state_dir.try_exists()? {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.recursive(true).create(&config.state_dir)?;
    }
    private_metadata(&config.state_dir, true)?;
    let directory = directory(config);
    if !directory.try_exists()? {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory)?;
    }
    let initial_directory = private_metadata(&directory, true)?;
    let lease = open_private(&directory.join("refresh.lock"), true)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "report_refresh_in_progress"
        );
    }
    let (mut cache, cache_error) = match read_cache(config, close_epoch) {
        Ok(Some(cache)) => (cache, false),
        Ok(None) => (Cache::new(config, close_epoch), false),
        Err(_) => (Cache::new(config, close_epoch), true),
    };
    let mut errors = Vec::new();
    if cache_error {
        errors.push(json!({"component":"cache","reason":"prior_cache_unavailable"}));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    for name in COMPONENTS {
        let component = cache.components.entry(name.into()).or_default();
        let attempt = if component
            .last_attempt
            .as_ref()
            .and_then(|a| a.retry_not_before)
            .is_some_and(|at| at > reports::now())
        {
            Err(reports::Failure {
                reason: "retry_after".into(),
                retry_not_before: component
                    .last_attempt
                    .as_ref()
                    .and_then(|a| a.retry_not_before),
            })
        } else {
            reports::fetch_compact(&source, name, close_epoch, &interest, deadline).await
        };
        apply(component, name, attempt, &mut errors);
    }
    if raw {
        let component = cache.components.entry("raw".into()).or_default();
        let attempt = if component
            .last_attempt
            .as_ref()
            .and_then(|a| a.retry_not_before)
            .is_some_and(|at| at > reports::now())
        {
            Err(reports::Failure {
                reason: "retry_after".into(),
                retry_not_before: component
                    .last_attempt
                    .as_ref()
                    .and_then(|a| a.retry_not_before),
            })
        } else {
            reports::fetch_raw(
                &source,
                close_epoch,
                &interest,
                Instant::now() + Duration::from_secs(60),
                &directory,
            )
            .await
        };
        apply(component, "raw", attempt, &mut errors);
    }
    // Bounded retention preserves positives, explicitly marks partial coverage, and never asserts absence.
    let mut bytes = serde_json::to_vec(&cache)?;
    while bytes.len() > CACHE_BYTES {
        let settled = cache
            .components
            .get_mut("settled")
            .and_then(|c| c.last_good.as_mut());
        if let Some(good) = settled
            && let Some(rows) = good["rows"].as_array_mut()
            && !rows.is_empty()
        {
            rows.truncate(rows.len() / 2);
            good["truncated"] = json!(true);
            good["coverage"] = json!("partial");
            good["retained"] = json!(good["rows"].as_array().map_or(0, Vec::len));
            bytes = serde_json::to_vec(&cache)?;
            continue;
        }
        errors.push(json!({"component":"cache","reason":"cache_byte_limit"}));
        break;
    }
    if bytes.len() <= CACHE_BYTES {
        let persisted = (|| -> Result<()> {
            private_metadata(&config.state_dir, true)?;
            let current = private_metadata(&directory, true)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    initial_directory.dev() == current.dev()
                        && initial_directory.ino() == current.ino(),
                    "report_directory_changed"
                );
            }
            crate::admin::persist(&path(config, close_epoch), &bytes)
        })();
        if persisted.is_err() {
            errors.push(json!({"component":"cache","reason":"cache_write_failed"}));
        }
    }
    let mut output = render(config, query, Some(cache), "refreshed_in_memory")?;
    output["refresh_ok"] = json!(errors.is_empty());
    output["errors"] = json!(errors);
    drop(lease);
    Ok(output)
}
fn apply(
    component: &mut Component,
    name: &str,
    result: Result<Value, reports::Failure>,
    errors: &mut Vec<Value>,
) {
    match result {
        Ok(good) if good["validation_complete"] == false => {
            errors.push(json!({"component":name,"reason":"incomplete_validation"}));
            component.last_attempt = Some(Attempt {
                at: reports::now(),
                outcome: "failed".into(),
                reason: Some("incomplete_validation".into()),
                retry_not_before: None,
            });
            // An incomplete attempt cannot renew the last-good component's stamp.
            // First-ever partial evidence can still retain independently validated positives.
            if component.last_good.is_none() {
                component.last_good = Some(good);
            }
        }
        Ok(good) => {
            component.last_attempt = Some(Attempt {
                at: reports::now(),
                outcome: "success".into(),
                reason: None,
                retry_not_before: None,
            });
            component.last_good = Some(good);
        }
        Err(failure) => {
            errors.push(json!({"component":name,"reason":failure.reason,"retry_not_before":failure.retry_not_before}));
            component.last_attempt = Some(Attempt {
                at: reports::now(),
                outcome: "failed".into(),
                reason: Some(failure.reason.code().to_owned()),
                retry_not_before: failure.retry_not_before,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            state_dir: dir.path().join("state"),
            ..Config::default()
        };
        let identity = crate::store::digest(dir.path().as_os_str().as_encoded_bytes());
        config.network.address = format!("poa12{}", &identity[..43].replace('0', "1"));
        assert!(crate::config::valid_address(&config.network.address));
        fs::create_dir(&config.state_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        (dir, config)
    }
    fn compact_replies() -> Vec<(u16, String, Vec<u8>)> {
        vec![
            (
                200,
                String::new(),
                br#"{"epoch":9,"count":0,"rows":[]}"#.to_vec(),
            ),
            (
                200,
                String::new(),
                br#"{"close_epoch":9,"close_ts":100,"settled_count":0}"#.to_vec(),
            ),
            (
                200,
                String::new(),
                br#"{"as_of_close":8,"pending_ttl_epochs":16,"total_pending":0,"schedule":[]}"#
                    .to_vec(),
            ),
        ]
    }
    fn query() -> EpochQuery {
        EpochQuery {
            work_epoch: Some(4),
            close_epoch: Some(9),
            private: true,
            limit: 1,
            ..EpochQuery::default()
        }
    }
    #[tokio::test]
    async fn refresh_failure_retains_last_good_stamps_and_obeys_source_floor() {
        let (_dir, config) = fixture();
        let (source, task) = reports::fixture_server(compact_replies()).await;
        let first = refresh_with_source(&config, query(), false, source)
            .await
            .unwrap();
        assert_eq!(first["refresh_ok"], true);
        task.await.unwrap();
        let mut cache = read_cache(&config, 9).unwrap().unwrap();
        cache
            .components
            .get_mut("settled")
            .unwrap()
            .last_good
            .as_mut()
            .unwrap()["checked_at"] = json!(10);
        crate::admin::persist(&path(&config, 9), &serde_json::to_vec(&cache).unwrap()).unwrap();
        let mut replies = compact_replies();
        replies[0] = (503, "Retry-After: 120\r\n".into(), Vec::new());
        let (source, task) = reports::fixture_server(replies).await;
        let failed = refresh_with_source(&config, query(), false, source)
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(failed["refresh_ok"], false);
        assert_eq!(failed["sources"]["settled"]["checked_at"], 10);
        assert_eq!(
            failed["sources"]["settled"]["last_attempt"]["outcome"],
            "failed"
        );
        assert_eq!(failed["work_epoch"], 4);
        assert_eq!(failed["private"], true);
        let mut replies = compact_replies();
        replies.remove(0);
        let (source, task) = reports::fixture_server(replies).await;
        let blocked = refresh_with_source(&config, query(), false, source)
            .await
            .unwrap();
        assert_eq!(blocked["refresh_ok"], false);
        assert_eq!(blocked["errors"][0]["reason"], "retry_after");
        assert_eq!(task.await.unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(directory(&config)).unwrap().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(path(&config, 9)).unwrap().mode() & 0o777,
                0o600
            );
        }
    }
    #[tokio::test]
    async fn cache_write_failure_still_returns_new_verified_account_reward() {
        use sha2::{Digest, Sha256};
        let (_dir, config) = fixture();
        fs::create_dir(directory(&config)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory(&config), fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::create_dir(path(&config, 9)).unwrap(); // An unreplaceable cache target.
        let raw=serde_json::to_vec(&json!({"epoch":9,"rewards":{config.network.address.clone():"12.000001"},"basis":{"pending":{}}})).unwrap();
        let digest = format!("{:x}", Sha256::digest(&raw));
        let index=serde_json::to_vec(&json!({"chain_id":"poa-mainnet-1","v":1,"count":1,"epochs":[{"n":9,"sha256":digest,"bytes":raw.len(),"key":"epochs/poa-mainnet-1/9.json"}]})).unwrap();
        let mut replies = compact_replies();
        replies.push((200, String::new(), index));
        replies.push((200, String::new(), raw));
        let (source, task) = reports::fixture_server(replies).await;
        let result = refresh_with_source(&config, query(), true, source)
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(result["refresh_ok"], false);
        assert_eq!(result["account_close_reward"]["status"], "node_reported");
        assert_eq!(result["account_close_reward"]["amount"], "12.000001");
        assert!(
            result["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["reason"] == "cache_write_failed")
        );
    }
    #[test]
    fn foreign_and_corrupt_cache_are_unavailable_without_mutation() {
        let (_dir, config) = fixture();
        fs::create_dir(directory(&config)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory(&config), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut cache = Cache::new(&config, 9);
        cache.account = "foreign".into();
        crate::admin::persist(&path(&config, 9), &serde_json::to_vec(&cache).unwrap()).unwrap();
        let value = view(&config, query()).unwrap();
        assert_eq!(value["cache"], "unavailable");
        let before = fs::read(path(&config, 9)).unwrap();
        assert_eq!(before, serde_json::to_vec(&cache).unwrap());
        crate::admin::persist(&path(&config, 9), b"not json").unwrap();
        assert_eq!(view(&config, query()).unwrap()["cache"], "unavailable");
        assert_eq!(fs::read(path(&config, 9)).unwrap(), b"not json");
    }
}

#[cfg(test)]
mod summary_tests {
    use super::*;
    #[test]
    fn grading_counts_are_sourced_page_facts_and_jury_does_not_settle_judge() {
        let (_dir, config) = super::tests::fixture();
        let store = Store::open(&config).unwrap();
        drop(store);
        let db = rusqlite::Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
        let mut interest = ReportInterest::new(config.network.address.clone());
        for (id, letter) in [(1, "a"), (2, "b"), (3, "c"), (4, "d")] {
            let tx = letter.repeat(64);
            interest.add_answer(&tx);
            db.execute("INSERT INTO operations(id,kind,work_key,state,request,txid,generation,revision,created_at,updated_at)
                VALUES (?1,'answer',?2,'final',?3,?4,0,'test',0,0)",
                rusqlite::params![id,format!("unrelated-{id}"),json!({"solver":{"epoch":4,"kind":"answer"}}).to_string(),tx]).unwrap();
        }
        interest.add_candidate(&"a".repeat(64));
        db.execute("INSERT INTO operations(id,kind,work_key,state,request,generation,revision,created_at,updated_at)
            VALUES (5,'judge','candidate','final',?1,0,'test',0,0)",
            [json!({"solver":{"epoch":4,"kind":"judge","assignment":"a".repeat(64)}}).to_string()]).unwrap();
        drop(db);
        let rows = vec![
            json!({"answer":"a".repeat(64),"from":config.network.address,"outcome":"passed","jury":[{"grader":config.network.address,"aligned":true}]}),
            json!({"answer":"b".repeat(64),"from":config.network.address,"outcome":"failed","jury":[]}),
            json!({"answer":"c".repeat(64),"from":config.network.address,"outcome":"expired","jury":[]}),
        ];
        let mut settled = reports::parse_compact(
            "settled",
            9,
            &interest,
            &serde_json::to_vec(&json!({"epoch":9,"count":3,"rows":rows})).unwrap(),
        )
        .unwrap();
        settled["checked_at"] = json!(10);
        settled["content_hash"] = json!("0".repeat(64));
        let raw = json!({"close_epoch":9,"checked_at":10,"body_hash":"0".repeat(64),"index_hash":"1".repeat(64),"bytes":100,
            "coverage":"known_bindings_only","pending_matches":{"d".repeat(64):3},
            "account_reward":{"status":"not_listed","amount":null,"integrity":"index_hash_verified","independent_ledger_verification":false}});
        let mut cache = Cache::new(&config, 9);
        cache.components.insert(
            "settled".into(),
            Component {
                last_attempt: None,
                last_good: Some(settled),
            },
        );
        cache.components.insert(
            "raw".into(),
            Component {
                last_attempt: None,
                last_good: Some(raw),
            },
        );
        let query = EpochQuery {
            work_epoch: Some(4),
            close_epoch: Some(9),
            ..EpochQuery::default()
        };
        let value = render(&config, query, Some(cache), "available").unwrap();
        assert_eq!(value["summary"]["passed"], 1);
        assert_eq!(value["summary"]["failed"], 1);
        assert_eq!(value["summary"]["expired"], 1);
        assert_eq!(value["summary"]["graded"], 2);
        assert_eq!(value["summary"]["sourced_outcomes"], 3);
        assert_eq!(value["summary"]["pending_as_of_close"], 1);
        assert_eq!(value["summary"]["unknown_answer_outcomes"], 0);
        assert_eq!(value["summary"]["scope"], "selected_local_operation_page");
        assert_eq!(value["rows"][0]["kind"], "judge");
        assert_eq!(value["rows"][0]["settlement"]["status"], "unknown");
        assert_eq!(value["rows"][0]["jury"]["aligned"], true);
        assert_eq!(
            value["rows"][1]["settlement"]["status"],
            "pending_as_of_close"
        );
        assert_eq!(value["rows"][1]["local_effect"], "final");
    }
}
