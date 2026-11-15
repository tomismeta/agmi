//! Keyless, fixed-authority report evidence. Never a participation client.
use super::{canonical_txid, valid_txid};
use crate::config::Config;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ORIGIN: &str = "https://minepoa.com";
pub const MAX_MATCHES: usize = 4096;
#[derive(Clone)]
pub struct ReportSource {
    client: reqwest::Client,
    #[cfg(test)]
    test_origin: Option<String>,
}
impl ReportSource {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.network.chain == "poa-mainnet-1"
                && config.network.base_url.trim_end_matches('/') == ORIGIN
                && config.network.api == crate::config::NetworkConfig::default().api
                && crate::config::valid_address(&config.network.address),
            FailureReason::UnsupportedSource
        );
        Ok(Self {
            client: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .connect_timeout(Duration::from_secs(5))
                .build()?,
            #[cfg(test)]
            test_origin: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture(origin: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .build()
                .unwrap(),
            test_origin: Some(origin),
        }
    }
    fn origin(&self) -> &str {
        #[cfg(test)]
        if let Some(origin) = &self.test_origin {
            return origin;
        }
        ORIGIN
    }
}
#[derive(Clone, Default)]
pub struct ReportInterest {
    pub account: String,
    pub answers: BTreeSet<String>,
    pub candidates: BTreeSet<String>,
    pub truncated: bool,
}
impl ReportInterest {
    pub fn new(account: String) -> Self {
        Self {
            account,
            ..Self::default()
        }
    }
    pub fn add_answer(&mut self, tx: &str) {
        if self.answers.len() < MAX_MATCHES {
            if let Ok(tx) = canonical_txid(tx) {
                self.answers.insert(tx);
            }
        } else {
            self.truncated = true;
        }
    }
    pub fn add_candidate(&mut self, tx: &str) {
        if self.candidates.len() < MAX_MATCHES {
            if let Ok(tx) = canonical_txid(tx) {
                self.candidates.insert(tx);
            }
        } else {
            self.truncated = true;
        }
    }
    fn known(&self, tx: &str) -> bool {
        self.answers.contains(tx) || self.candidates.contains(tx)
    }
}
macro_rules! failure_reasons {
    ($($variant:ident => $code:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub enum FailureReason { $(#[serde(rename=$code)] $variant),+ }
        impl FailureReason { pub fn code(self)->&'static str { match self { $(Self::$variant=>$code),+ } } }
        impl From<&str> for FailureReason { fn from(code:&str)->Self {match code {$($code=>Self::$variant),+, _=>Self::MalformedReport}} }
    }
}
failure_reasons! {
    Deadline=>"deadline", Transport=>"transport", HttpStatus=>"http_status", BodyLimit=>"body_limit",
    BodyRead=>"body_read", MalformedReport=>"malformed_report", EpochOrCount=>"epoch_or_count",
    EpochMismatch=>"epoch_mismatch", InvalidExpiryAggregate=>"invalid_expiry_aggregate",
    UnsupportedComponent=>"unsupported_component", InvalidIndex=>"invalid_index", IndexBinding=>"index_binding",
    DuplicateIndexEpoch=>"duplicate_index_epoch", CloseNotIndexed=>"close_not_indexed", InvalidIndexEntry=>"invalid_index_entry",
    LengthMismatch=>"length_mismatch", TemporaryFile=>"temporary_file", TemporaryWrite=>"temporary_write",
    HashOrLengthMismatch=>"hash_or_length_mismatch", TemporaryRead=>"temporary_read", InvalidRawReport=>"invalid_raw_report",
    TrailingRawData=>"trailing_raw_data", RawBindingOrSchema=>"raw_binding_or_schema", RetryAfter=>"retry_after",
    UnsupportedSource=>"unsupported_report_source"
}
impl std::fmt::Display for FailureReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for FailureReason {}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Failure {
    pub reason: FailureReason,
    pub retry_not_before: Option<i64>,
}
impl Failure {
    fn new(reason: &str) -> Self {
        Self {
            reason: reason.into(),
            retry_not_before: None,
        }
    }
}
pub type CompactAttempt = Result<Value, Failure>;
pub type RawAttempt = Result<Value, Failure>;
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
async fn response(
    source: &ReportSource,
    path: &str,
    deadline: Instant,
    seconds: u64,
) -> Result<reqwest::Response, Failure> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(seconds));
    if remaining.is_zero() {
        return Err(Failure::new("deadline"));
    }
    let response = source
        .client
        .get(format!("{}{path}", source.origin()))
        .timeout(remaining)
        .send()
        .await
        .map_err(|_| Failure::new("transport"))?;
    if !response.status().is_success() {
        let mut failure = Failure::new("http_status");
        if matches!(response.status().as_u16(), 429 | 503) {
            failure.retry_not_before = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| {
                    s.parse::<u64>()
                        .ok()
                        .and_then(|s| i64::try_from(s).ok())
                        .map(|s| now().saturating_add(s))
                        .or_else(|| {
                            httpdate::parse_http_date(s)
                                .ok()
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .and_then(|d| i64::try_from(d.as_secs()).ok())
                        })
                });
        }
        return Err(failure);
    }
    Ok(response)
}
async fn body(
    source: &ReportSource,
    path: &str,
    cap: usize,
    deadline: Instant,
) -> Result<Vec<u8>, Failure> {
    let mut response = response(source, path, deadline, 5).await?;
    if response.content_length().is_some_and(|n| n > cap as u64) {
        return Err(Failure::new("body_limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Failure::new("body_read"))?
    {
        if Instant::now() >= deadline {
            return Err(Failure::new("deadline"));
        }
        if bytes.len().saturating_add(chunk.len()) > cap {
            return Err(Failure::new("body_limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[derive(Deserialize)]
struct Settled {
    epoch: u64,
    count: usize,
    rows: Vec<SettledEntry>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum SettledEntry {
    Known(SettledRow),
    Unsupported(IgnoredAny),
}
#[derive(Deserialize)]
struct SettledRow {
    answer: String,
    from: String,
    outcome: String,
    jury: Vec<Jury>,
}
#[derive(Deserialize)]
struct Jury {
    grader: String,
    aligned: bool,
}
#[derive(Deserialize, Serialize)]
struct Close {
    close_epoch: u64,
    close_ts: u64,
    settled_count: u64,
}
#[derive(Deserialize, Serialize)]
struct Expiry {
    as_of_close: u64,
    pending_ttl_epochs: u64,
    total_pending: u64,
    schedule: Vec<ExpiryRow>,
}
#[derive(Deserialize, Serialize)]
struct ExpiryRow {
    expires_at_close: u64,
    total: u64,
}
/// Each requested compact component has its own attempt and last-good timestamp.
pub async fn fetch_compact(
    source: &ReportSource,
    component: &str,
    epoch: u64,
    interest: &ReportInterest,
    deadline: Instant,
) -> CompactAttempt {
    if !matches!(component, "settled" | "close-report" | "expiry-schedule") {
        return Err(Failure::new("unsupported_component"));
    }
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    let bytes = body(
        source,
        &format!("/api/{component}?epoch={epoch}"),
        8 * 1024 * 1024,
        deadline,
    )
    .await?;
    let mut value = parse_compact_until(component, epoch, interest, &bytes, deadline)?;
    if Instant::now() >= deadline {
        return Err(Failure::new("deadline"));
    }
    value["content_hash"] = json!(hash(&bytes));
    value["checked_at"] = json!(now());
    Ok(value)
}
pub fn parse_compact(
    component: &str,
    epoch: u64,
    interest: &ReportInterest,
    bytes: &[u8],
) -> CompactAttempt {
    parse_compact_until(
        component,
        epoch,
        interest,
        bytes,
        Instant::now() + Duration::from_secs(5),
    )
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], deadline: Instant) -> Result<T, Failure> {
    serde_json::from_reader(std::io::BufReader::new(DeadlineReader {
        inner: bytes,
        deadline,
    }))
    .map_err(|_| Failure::new("malformed_report"))
}
fn parse_compact_until(
    component: &str,
    epoch: u64,
    interest: &ReportInterest,
    bytes: &[u8],
    deadline: Instant,
) -> CompactAttempt {
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Failure::new("body_limit"));
    }
    match component {
        "settled" => {
            let report: Settled = decode(bytes, deadline)?;
            if report.epoch != epoch || report.count != report.rows.len() {
                return Err(Failure::new("epoch_or_count"));
            }
            let mut seen = BTreeSet::new();
            let mut rows: Vec<Value> = Vec::new();
            let mut matched_tx = BTreeSet::new();
            let mut unlinked_by_tx = BTreeMap::<String, String>::new();
            let mut complete = true;
            for entry in report.rows {
                if Instant::now() >= deadline {
                    return Err(Failure::new("deadline"));
                }
                let SettledEntry::Known(row) = entry else {
                    complete = false;
                    continue;
                };
                let Ok(tx) = canonical_txid(&row.answer) else {
                    complete = false;
                    continue;
                };
                if !seen.insert(tx.clone()) {
                    rows.retain(|r| r["tx"] != tx);
                    unlinked_by_tx.remove(&tx);
                    matched_tx.remove(&tx);
                    complete = false;
                    continue;
                }
                if !crate::config::valid_address(&row.from)
                    || !matches!(row.outcome.as_str(), "passed" | "failed" | "expired")
                    || row.jury.len() > 1024
                {
                    complete = false;
                    continue;
                }
                let mut graders = BTreeSet::new();
                let mut own_jury = None;
                let mut valid = true;
                let jury_size = row.jury.len();
                let mut jury_aligned = 0usize;
                for juror in row.jury {
                    if !crate::config::valid_address(&juror.grader)
                        || !graders.insert(juror.grader.clone())
                    {
                        valid = false;
                        break;
                    }
                    if juror.grader == interest.account {
                        own_jury = Some(juror.aligned);
                    }
                    if juror.aligned {
                        jury_aligned += 1;
                    }
                }
                if !valid {
                    complete = false;
                    continue;
                }
                let own = row.from == interest.account;
                let own_binding = own && interest.answers.contains(&tx);
                if own && !own_binding {
                    unlinked_by_tx.insert(tx.clone(), row.outcome.clone());
                }
                if own_binding || (own_jury.is_some() && interest.candidates.contains(&tx)) {
                    matched_tx.insert(tx.clone());
                    if rows.len() < MAX_MATCHES {
                        rows.push(json!({"tx":tx,"outcome":if own_binding{Some(row.outcome)}else{None},"jury_alignment":own_jury,"own_answer":own_binding,"jury_size":jury_size,"jury_aligned":jury_aligned}));
                    }
                }
            }
            let matched = matched_tx.len();
            let unlinked = unlinked_by_tx.len();
            let mut unlinked_outcomes = BTreeMap::<String, usize>::new();
            for outcome in unlinked_by_tx.into_values() {
                *unlinked_outcomes.entry(outcome).or_default() += 1;
            }
            Ok(
                json!({"close_epoch":epoch,"rows":rows,"matched":matched,"retained":rows.len(),"unlinked_account_rows":unlinked,"unlinked_account_outcomes":unlinked_outcomes,
                "validation_complete":complete,"coverage":if !complete || matched>rows.len() || interest.truncated{"partial"}else{"complete_source"},"truncated":matched>rows.len()}),
            )
        }
        "close-report" => {
            let report: Close = decode(bytes, deadline)?;
            if report.close_epoch != epoch {
                return Err(Failure::new("epoch_mismatch"));
            }
            Ok(
                json!({"report":report,"coverage":"aggregate_only","account_earnings":"not_established"}),
            )
        }
        "expiry-schedule" => {
            let report: Expiry = decode(bytes, deadline)?;
            if report.as_of_close > epoch
                || report.schedule.len() > 4096
                || report
                    .schedule
                    .iter()
                    .try_fold(0u64, |n, r| n.checked_add(r.total))
                    != Some(report.total_pending)
            {
                return Err(Failure::new("invalid_expiry_aggregate"));
            }
            Ok(
                json!({"report":report,"coverage":"aggregate_only","per_answer_expiry":"not_established"}),
            )
        }
        _ => Err(Failure::new("unsupported_component")),
    }
}
#[derive(Deserialize)]
struct Index {
    chain_id: String,
    v: u64,
    count: usize,
    epochs: Vec<IndexEntry>,
}
#[derive(Deserialize)]
struct IndexEntry {
    n: u64,
    sha256: String,
    bytes: u64,
    key: String,
}
pub async fn fetch_raw(
    source: &ReportSource,
    epoch: u64,
    interest: &ReportInterest,
    deadline: Instant,
    directory: &std::path::Path,
) -> RawAttempt {
    let index_bytes = body(source, "/api/epochs", 1024 * 1024, deadline).await?;
    let index: Index =
        serde_json::from_slice(&index_bytes).map_err(|_| Failure::new("invalid_index"))?;
    if index.chain_id != "poa-mainnet-1" || index.v != 1 || index.count != index.epochs.len() {
        return Err(Failure::new("index_binding"));
    }
    let mut seen = BTreeSet::new();
    let mut entry = None;
    for item in index.epochs {
        if !seen.insert(item.n) {
            return Err(Failure::new("duplicate_index_epoch"));
        }
        if item.n == epoch {
            entry = Some(item);
        }
    }
    let entry = entry.ok_or_else(|| Failure::new("close_not_indexed"))?;
    if entry.key != format!("epochs/poa-mainnet-1/{epoch}.json")
        || !valid_txid(&entry.sha256)
        || entry.bytes == 0
        || entry.bytes > 64 * 1024 * 1024
    {
        return Err(Failure::new("invalid_index_entry"));
    }
    let mut response = response(source, &format!("/api/epochs/{epoch}"), deadline, 60).await?;
    if response.content_length().is_some_and(|n| n != entry.bytes) {
        return Err(Failure::new("length_mismatch"));
    }
    let mut temp = tempfile::tempfile_in(directory).map_err(|_| Failure::new("temporary_file"))?;
    let mut digest = Sha256::new();
    let mut length = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Failure::new("body_read"))?
    {
        if Instant::now() >= deadline {
            return Err(Failure::new("deadline"));
        }
        length = length.saturating_add(chunk.len() as u64);
        if length > entry.bytes {
            return Err(Failure::new("length_mismatch"));
        }
        digest.update(&chunk);
        temp.write_all(&chunk)
            .map_err(|_| Failure::new("temporary_write"))?;
    }
    let body_hash = format!("{:x}", digest.finalize());
    if length != entry.bytes || body_hash != entry.sha256.to_ascii_lowercase() {
        return Err(Failure::new("hash_or_length_mismatch"));
    }
    temp.rewind().map_err(|_| Failure::new("temporary_read"))?;
    let mut value = parse_raw(temp, epoch, interest, deadline)?;
    value["index_hash"] = json!(hash(&index_bytes));
    value["body_hash"] = json!(body_hash);
    value["bytes"] = json!(length);
    value["checked_at"] = json!(now());
    value["account_reward"]["source"] = json!("indexed_raw_close");
    value["account_reward"]["body_hash"] = value["body_hash"].clone();
    value["account_reward"]["checked_at"] = value["checked_at"].clone();
    value["account_reward"]["integrity"] = json!("index_hash_verified");
    Ok(value)
}
/// Exact fixed-six decimal scaled units; never floating point.
pub fn reward_units(value: &str) -> Option<u128> {
    let (whole, fraction) = value.split_once('.')?;
    if whole.is_empty()
        || (whole.len() > 1 && whole.starts_with('0'))
        || fraction.len() != 6
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    whole
        .parse::<u128>()
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(fraction.parse::<u128>().ok()?)
}
struct DeadlineReader<R> {
    inner: R,
    deadline: Instant,
}
impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "report deadline",
            ));
        }
        self.inner.read(buffer)
    }
}
#[derive(Default)]
struct RawData {
    epoch: Option<u64>,
    rewards: bool,
    basis: bool,
    pending_seen: bool,
    reward: Option<String>,
    pending: BTreeMap<String, Option<u64>>,
}
#[derive(Clone, Copy)]
enum Scope {
    Root,
    Rewards,
    Basis,
    Pending,
}
struct Filter<'a> {
    scope: Scope,
    interest: &'a ReportInterest,
    data: &'a mut RawData,
    deadline: Instant,
}
impl<'de> DeserializeSeed<'de> for Filter<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for Filter<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("report object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let mut seen = BTreeSet::new();
        while let Some(mut key) = map.next_key::<String>()? {
            if matches!(self.scope, Scope::Pending) && valid_txid(&key) {
                key.make_ascii_lowercase();
            }
            if Instant::now() >= self.deadline {
                return Err(de::Error::custom("deadline"));
            }
            // Track only relevant keys: unrelated maps can contain millions of keys.
            let relevant = match self.scope {
                Scope::Root => matches!(key.as_str(), "epoch" | "rewards" | "basis"),
                Scope::Basis => key == "pending",
                Scope::Rewards => key == self.interest.account,
                Scope::Pending => self.interest.known(&key),
            };
            if relevant && !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate report field"));
            }
            match (self.scope, key.as_str()) {
                (Scope::Root, "epoch") => self.data.epoch = Some(map.next_value()?),
                (Scope::Root, "rewards") => {
                    self.data.rewards = true;
                    map.next_value_seed(Filter {
                        scope: Scope::Rewards,
                        interest: self.interest,
                        data: &mut *self.data,
                        deadline: self.deadline,
                    })?;
                }
                (Scope::Root, "basis") => {
                    self.data.basis = true;
                    map.next_value_seed(Filter {
                        scope: Scope::Basis,
                        interest: self.interest,
                        data: &mut *self.data,
                        deadline: self.deadline,
                    })?;
                }
                (Scope::Basis, "pending") => {
                    self.data.pending_seen = true;
                    map.next_value_seed(Filter {
                        scope: Scope::Pending,
                        interest: self.interest,
                        data: &mut *self.data,
                        deadline: self.deadline,
                    })?;
                }
                (Scope::Rewards, _) if relevant => {
                    let amount: String = map.next_value()?;
                    if reward_units(&amount).is_none() {
                        return Err(de::Error::custom("invalid reward"));
                    }
                    self.data.reward = Some(amount);
                }
                (Scope::Pending, _) if relevant => {
                    #[derive(Deserialize)]
                    struct Pending {
                        since: u64,
                    }
                    let value: Pending = map.next_value()?;
                    if self.data.pending.len() < MAX_MATCHES {
                        self.data.pending.insert(key, Some(value.since));
                    } else {
                        return Err(de::Error::custom("pending retention limit"));
                    }
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}
pub fn parse_raw<R: Read>(
    reader: R,
    epoch: u64,
    interest: &ReportInterest,
    deadline: Instant,
) -> RawAttempt {
    let mut data = RawData::default();
    let mut deserializer =
        serde_json::Deserializer::from_reader(std::io::BufReader::new(DeadlineReader {
            inner: reader,
            deadline,
        }));
    Filter {
        scope: Scope::Root,
        interest,
        data: &mut data,
        deadline,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| Failure::new("invalid_raw_report"))?;
    deserializer
        .end()
        .map_err(|_| Failure::new("trailing_raw_data"))?;
    if data.epoch != Some(epoch)
        || !data.rewards
        || !data.basis
        || !data.pending_seen
        || data
            .pending
            .values()
            .any(|since| since.is_some_and(|n| n > epoch))
    {
        return Err(Failure::new("raw_binding_or_schema"));
    }
    Ok(
        json!({"close_epoch":epoch,"pending_matches":data.pending,"coverage":if interest.truncated{"partial"}else{"known_bindings_only"},
        "account_reward":{"status":if data.reward.is_some(){"node_reported"}else{"not_listed"},"amount":data.reward,"close_epoch":epoch,
        "integrity":"not_verified","independent_ledger_verification":false,"allocation":"account_close_only"}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) async fn server(
        replies: Vec<(u16, String, Vec<u8>)>,
    ) -> (ReportSource, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = ReportSource::fixture(format!("http://{}", listener.local_addr().unwrap()));
        let task = tokio::spawn(async move {
            let mut paths = Vec::new();
            for (status, extra, body) in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(3), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|b| b == b"\r\n\r\n") {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                    assert!(request.len() < 16384);
                }
                paths.push(
                    String::from_utf8(request)
                        .unwrap()
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                let headers = format!(
                    "HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
            paths
        });
        (source, task)
    }
    fn raw_fixture() -> (ReportInterest, Vec<u8>) {
        let account = format!("poa1{}", "1".repeat(32));
        let mut interest = ReportInterest::new(account.clone());
        interest.add_answer(&"a".repeat(64));
        let body=serde_json::to_vec(&json!({"epoch":9,"rewards":{account:"0.000000"},"basis":{"pending":{"a".repeat(64):{"since":4,"grades":{"ignored":"large"}}}}})).unwrap();
        (interest, body)
    }
    fn index(body: &[u8], digest: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"chain_id":"poa-mainnet-1","v":1,"count":1,"epochs":[{"n":9,"sha256":digest,"bytes":body.len(),"key":"epochs/poa-mainnet-1/9.json"}]})).unwrap()
    }
    #[tokio::test]
    async fn verified_raw_close_hashes_streamed_bytes_and_deletes_tempfile() {
        let (interest, body) = raw_fixture();
        let digest = hash(&body);
        let (source, task) = server(vec![
            (200, String::new(), index(&body, &digest)),
            (200, String::new(), body),
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let result = fetch_raw(
            &source,
            9,
            &interest,
            Instant::now() + Duration::from_secs(5),
            dir.path(),
        )
        .await
        .unwrap();
        assert_eq!(result["body_hash"], digest);
        assert_eq!(result["account_reward"]["amount"], "0.000000");
        assert_eq!(result["account_reward"]["integrity"], "index_hash_verified");
        assert_eq!(result["pending_matches"]["a".repeat(64)], 4);
        assert_eq!(fs_count(dir.path()), 0);
        assert_eq!(
            task.await.unwrap(),
            vec!["GET /api/epochs HTTP/1.1", "GET /api/epochs/9 HTTP/1.1"]
        );
    }
    fn fs_count(path: &std::path::Path) -> usize {
        std::fs::read_dir(path).unwrap().count()
    }
    #[tokio::test]
    async fn wrong_raw_hash_never_produces_reward_or_leaves_body() {
        let (interest, body) = raw_fixture();
        let (source, task) = server(vec![
            (200, String::new(), index(&body, &"0".repeat(64))),
            (200, String::new(), body),
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let error = fetch_raw(
            &source,
            9,
            &interest,
            Instant::now() + Duration::from_secs(5),
            dir.path(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason, FailureReason::HashOrLengthMismatch);
        assert_eq!(fs_count(dir.path()), 0);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn invalid_index_path_prevents_body_request() {
        let (interest, body) = raw_fixture();
        let mut value: Value = serde_json::from_slice(&index(&body, &hash(&body))).unwrap();
        value["epochs"][0]["key"] = json!("https://foreign.invalid/report");
        let (source, task) = server(vec![(
            200,
            String::new(),
            serde_json::to_vec(&value).unwrap(),
        )])
        .await;
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            fetch_raw(
                &source,
                9,
                &interest,
                Instant::now() + Duration::from_secs(5),
                dir.path()
            )
            .await
            .unwrap_err()
            .reason,
            FailureReason::InvalidIndexEntry
        );
        assert_eq!(task.await.unwrap().len(), 1);
        assert_eq!(fs_count(dir.path()), 0);
    }
    #[tokio::test]
    async fn retry_after_is_source_evidence_and_redirect_is_not_followed() {
        let (source, task) = server(vec![
            (503, "Retry-After: 120\r\n".into(), Vec::new()),
            (
                302,
                "Location: https://foreign.invalid/\r\n".into(),
                Vec::new(),
            ),
        ])
        .await;
        let before = now();
        let first = fetch_compact(
            &source,
            "settled",
            9,
            &ReportInterest::default(),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(first.retry_not_before.unwrap() >= before + 120);
        let second = fetch_compact(
            &source,
            "settled",
            9,
            &ReportInterest::default(),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert_eq!(second.reason, FailureReason::HttpStatus);
        assert_eq!(task.await.unwrap().len(), 2);
    }
}

#[cfg(test)]
pub(crate) use tests::server as fixture_server;

#[cfg(test)]
mod index_bounds_tests {
    use super::*;
    #[tokio::test]
    async fn foreign_duplicate_and_oversized_index_entries_never_fetch_a_body() {
        let entry =
            json!({"n":9,"sha256":"a".repeat(64),"bytes":1,"key":"epochs/poa-mainnet-1/9.json"});
        let normal = json!({"chain_id":"poa-mainnet-1","v":1,"count":1,"epochs":[entry.clone()]});
        let mut foreign = normal.clone();
        foreign["chain_id"] = json!("foreign");
        let mut duplicate = normal.clone();
        duplicate["epochs"] = json!([entry.clone(), entry]);
        duplicate["count"] = json!(2);
        let mut oversized = normal;
        oversized["epochs"][0]["bytes"] = json!(64 * 1024 * 1024 + 1);
        for (index, reason) in [
            (foreign, FailureReason::IndexBinding),
            (duplicate, FailureReason::DuplicateIndexEpoch),
            (oversized, FailureReason::InvalidIndexEntry),
        ] {
            let (source, task) = tests::server(vec![(
                200,
                String::new(),
                serde_json::to_vec(&index).unwrap(),
            )])
            .await;
            let dir = tempfile::tempdir().unwrap();
            let failure = fetch_raw(
                &source,
                9,
                &ReportInterest::default(),
                Instant::now() + Duration::from_secs(5),
                dir.path(),
            )
            .await
            .unwrap_err();
            assert_eq!(failure.reason, reason);
            assert_eq!(task.await.unwrap().len(), 1);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }
}
