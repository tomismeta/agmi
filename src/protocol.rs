//! Hosted API compatibility is based on https://minepoa.com/go.md,
//! https://minepoa.com/openapi.yaml and https://minepoa.com/client/poa.mjs.
//! HTTP success is not ledger finality. Unknown write outcomes never authorize replay.
use crate::config::{Config, Mode, WorkKind, safe_segment, validate_origin};
use anyhow::{Result, ensure};
use reqwest::{
    Client, Method, Url,
    header::{HeaderValue, RETRY_AFTER},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime},
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_CHARS: usize = 16384;

/// Bounded diagnostics only; these categories never establish a write outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadFailure {
    Timeout,
    Connect,
    Request,
    BodyInterrupted,
    ResponseTooLarge,
    InvalidJson,
    CredentialEchoRedacted,
}

impl ReadFailure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Request => "request",
            Self::BodyInterrupted => "body_interrupted",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidJson => "invalid_json",
            Self::CredentialEchoRedacted => "credential_echo_redacted",
        }
    }
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ReadFailure {}

pub fn transport_failure(error: &anyhow::Error) -> ReadFailure {
    error
        .downcast_ref::<ReadFailure>()
        .copied()
        .unwrap_or(ReadFailure::Request)
}

fn request_failure(error: &reqwest::Error) -> ReadFailure {
    if error.is_timeout() {
        ReadFailure::Timeout
    } else if error.is_connect() {
        ReadFailure::Connect
    } else {
        ReadFailure::Request
    }
}

// Deliberately no Debug: authentication and queued-job identifiers must not enter logs.
pub struct Protocol {
    client: Client,
    read_timeout: Duration,
    origin: Url,
    chain: String,
    address: String,
    key: Option<HeaderValue>,
    modes: [Mode; 3],
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    pub body: Value,
    pub retry_after_seconds: Option<u64>,
    #[serde(default)]
    pub read_failure: Option<ReadFailure>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Queued {
        job_id: String,
    },
    Included {
        txid: String,
    },
    Rejected {
        code: String,
    },
    /// Terminal processed rejection is not proof of unchanged nonce.
    ProcessedRejected {
        code: String,
        next_nonce: Option<u64>,
    },
    Retry {
        after_seconds: u64,
    },
    Expired,
    Unknown {
        reason: String,
    },
    Completed,
}

/// BoundJob is valid only when the identifier was durably learned from this
/// operation's submit response. An operator-supplied capability is not binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseSource {
    Submit,
    BoundJob,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticEvidence {
    pub stage: ResponseSource,
    pub route: WorkKind,
    pub status: Option<u16>,
    pub reason: String,
    pub retry_after_seconds: Option<u64>,
    pub shape: String,
    /// Diagnostic vocabulary only; it never grants retry or recovery authority.
    #[serde(default)]
    pub error_category: Option<String>,
}

/// Private, untrusted leads only. Deliberately no Debug: job IDs are bearer
/// capabilities. This type must not enter public events/health or authorize
/// reconciliation. Keep it separate from the dispatch's proven identifiers.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ResponseCandidates {
    pub job_id: Option<String>,
    pub transaction_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    #[default]
    Missing,
    /// Supplied by the selected row; not a claim of exhaustive author history.
    Supplied,
    Truncated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorPrior {
    pub epoch: u64,
    pub answer_txid: String,
    pub answer_text: String,
    pub seed_words: Vec<String>,
    pub text_truncated: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorHistory {
    pub entries: Vec<AuthorPrior>,
    pub coverage: EvidenceCoverage,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub epoch: u64,
    pub words: Vec<String>,
    pub answered: bool,
    pub min_chars: usize,
    pub max_chars: usize,
    pub fingerprint: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub epoch: u64,
    pub answer: String,
    /// Empty means the provider did not expose the answer's original words.
    pub words: Vec<String>,
    #[serde(default)]
    pub expires_at_epoch: Option<u64>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub author_prior: AuthorHistory,
}
impl Protocol {
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;
        let key = if config.network.credential_file.as_os_str().is_empty() {
            None
        } else {
            Some(read_credential(&config.network.credential_file)?)
        };
        Self::with_key(config, key)
    }

    /// Read-only administration can validate a replacement without persisting it.
    pub(crate) fn with_credential(config: &Config, bytes: &[u8]) -> Result<Self> {
        config.validate()?;
        Self::with_key(config, Some(parse_credential(bytes)?))
    }

    fn with_key(config: &Config, key: Option<HeaderValue>) -> Result<Self> {
        let timeout = Duration::from_secs(config.timeouts.http_seconds);
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(timeout)
            .connect_timeout(timeout.max(Duration::from_secs(
                config.timeouts.effective_read_http_seconds(),
            )))
            .user_agent(concat!("agmi/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| anyhow::anyhow!("HTTP client initialization failed"))?;
        Ok(Self {
            client,
            read_timeout: Duration::from_secs(config.timeouts.effective_read_http_seconds()),
            origin: validate_origin(&config.network.base_url)?,
            chain: config.network.chain.clone(),
            address: config.network.address.clone(),
            key,
            modes: [
                config.capabilities.answer,
                config.capabilities.judge,
                config.capabilities.mine,
            ],
        })
    }
    pub async fn get(&self, path: &str) -> Result<Response> {
        ensure!(self.allowed_read(path), "read endpoint is not allowlisted");
        self.request(Method::GET, path, None).await
    }
    /// Query values never enter the path allowlist. Offset inventories are
    /// moving views, not snapshots; aggregation and coverage belong to the owner.
    pub async fn assignment_page(&self, offset: u64, limit: u64) -> Result<Response> {
        ensure!(
            offset <= 10_000 && (1..=100).contains(&limit),
            "invalid inventory page bounds"
        );
        self.request_query(
            Method::GET,
            "/api/hosted/assignments",
            None,
            Some((offset, limit)),
        )
        .await
    }
    /// Validate synchronously before the caller journals a possible network effect.
    pub fn prepare_submission<'a>(
        &'a self,
        kind: WorkKind,
        payload: &'a Value,
    ) -> Result<impl Future<Output = Result<Response>> + 'a> {
        let index = match kind {
            WorkKind::Answer => 0,
            WorkKind::Judge => 1,
            WorkKind::Mine => 2,
        };
        ensure!(
            self.modes[index] == Mode::Active,
            "capability is not active"
        );
        ensure!(
            self.key.is_some() && !self.address.is_empty(),
            "submission requires configured identity"
        );
        validate_payload(kind, payload)?;
        Ok(async move {
            match kind {
                WorkKind::Answer => {
                    self.request(Method::POST, "/api/hosted/answer", Some(payload))
                        .await
                }
                WorkKind::Judge => {
                    self.request(Method::POST, "/api/hosted/grade", Some(payload))
                        .await
                }
                // GET here is an effect, never a read permission.
                WorkKind::Mine => self.request(Method::GET, "/api/hosted/mine", None).await,
            }
        })
    }
    fn allowed_read(&self, path: &str) -> bool {
        if matches!(
            path,
            "/api/status"
                | "/api/networks"
                | "/api/network-facts"
                | "/api/epochs"
                | "/api/hosted/me"
                | "/api/hosted/challenge"
                | "/api/hosted/assignments"
        ) {
            return true;
        }
        if let Some(id) = path.strip_prefix("/api/job/") {
            return safe_segment(id, 128);
        }
        for prefix in ["/api/receipt/", "/api/explorer/tx/"] {
            if let Some(id) = path.strip_prefix(prefix) {
                return valid_txid(id);
            }
        }
        if !self.address.is_empty() {
            for prefix in [
                "/api/assignments/",
                "/api/explorer/address/",
                "/api/established/",
            ] {
                if path.strip_prefix(prefix) == Some(self.address.as_str()) {
                    return true;
                }
            }
        }
        false
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<Response> {
        self.request_query(method, path, payload, None).await
    }
    async fn request_query(
        &self,
        method: Method,
        path: &str,
        payload: Option<&Value>,
        page: Option<(u64, u64)>,
    ) -> Result<Response> {
        let mut url = self.origin.clone();
        url.set_path(&format!("/chain/{}{}", self.chain, path));
        if let Some((offset, limit)) = page {
            url.query_pairs_mut()
                .append_pair("offset", &offset.to_string())
                .append_pair("limit", &limit.to_string());
        }
        // Hosted mining is effectful despite using GET; it retains the write timeout.
        let is_read = method == Method::GET && path != "/api/hosted/mine";
        let mut request = self.client.request(method, url);
        if is_read {
            request = request.timeout(self.read_timeout);
        }
        if path.starts_with("/api/hosted/") {
            let key = self
                .key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("hosted read requires a credential file"))?;
            request = request.header("X-Api-Key", key);
        }
        if let Some(payload) = payload {
            request = request.json(payload);
        }
        // Never propagate reqwest errors: they can contain a bearer job URL.
        let mut response = request
            .send()
            .await
            .map_err(|error| anyhow::Error::new(request_failure(&error)))?;
        let status = response.status().as_u16();
        let header_delay = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after);
        // Retain status/backoff even when an upstream error page is empty, broken,
        // oversized or interrupted. A null body cannot establish a write outcome.
        let unavailable = |failure| Response {
            status,
            body: Value::Null,
            retry_after_seconds: header_delay,
            read_failure: Some(failure),
        };
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Ok(unavailable(ReadFailure::ResponseTooLarge));
        }
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if chunk.len() <= MAX_RESPONSE_BYTES - bytes.len() => {
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Ok(Some(_)) => return Ok(unavailable(ReadFailure::ResponseTooLarge)),
                Err(error) => {
                    return Ok(unavailable(if error.is_timeout() {
                        ReadFailure::Timeout
                    } else {
                        ReadFailure::BodyInterrupted
                    }));
                }
            }
        }
        let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(unavailable(ReadFailure::InvalidJson));
        };
        if let Some(key) = &self.key {
            let secret = key
                .to_str()
                .map_err(|_| anyhow::anyhow!("invalid internal credential encoding"))?;
            if contains_credential(&body, secret) {
                return Ok(unavailable(ReadFailure::CredentialEchoRedacted));
            }
        }
        let body_delay = body.get("retry_after_seconds").and_then(Value::as_u64);
        Ok(Response {
            status,
            body,
            retry_after_seconds: max_delay(header_delay, body_delay),
            read_failure: None,
        })
    }
}

fn selected_assignment_row<'a>(response: &'a Response, id: &str) -> Result<&'a Value> {
    ensure!(valid_txid(id), "invalid selected assignment identifier");
    let rows = assignment_rows(response)?;
    let mut selected = rows.iter().filter(|row| {
        row.get("answer_txid")
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(id))
    });
    let row = selected
        .next()
        .ok_or_else(|| anyhow::anyhow!("selected assignment is not on this page"))?;
    ensure!(
        selected.next().is_none(),
        "duplicate selected assignment identifier"
    );
    Ok(row)
}

/// Present-but-malformed epochs are never repaired using explorer evidence.
/// The runtime owns all HTTP reads, including their durable read-failure gates.
pub fn assignment_needs_hydration(response: &Response, id: &str) -> Result<bool> {
    Ok(selected_assignment_row(response, id)?
        .get("answer_epoch")
        .is_none())
}

/// Decode only the selected assignment, binding optional explorer evidence to
/// the exact transaction and answer without assuming a complete inventory page.
pub fn parse_selected_assignment(
    response: &Response,
    id: &str,
    transaction: Option<&Response>,
) -> Result<Assignment> {
    let row = selected_assignment_row(response, id)?;
    if row.get("answer_epoch").is_some() {
        return parse_assignment(row);
    }
    let tx =
        transaction.ok_or_else(|| anyhow::anyhow!("assignment transaction lookup unavailable"))?;
    ensure!(
        tx.status == 200 && !failed(&tx.body),
        "assignment transaction lookup unavailable"
    );
    ensure!(
        tx.body
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(id)),
        "assignment transaction ID mismatch"
    );
    let body = tx
        .body
        .get("body")
        .ok_or_else(|| anyhow::anyhow!("assignment transaction has no body"))?;
    ensure!(
        body.get("type").and_then(Value::as_str) == Some("challenge"),
        "assignment is not a challenge transaction"
    );
    let answer = row
        .get("answer")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("assignment answer missing"))?;
    ensure!(
        body.get("answer").and_then(Value::as_str) == Some(answer),
        "assignment answer does not match transaction"
    );
    if let Some(author) = row.get("from") {
        ensure!(
            body.get("from") == Some(author),
            "assignment author does not match transaction"
        );
    }
    let mut bound = row.clone();
    bound["answer_epoch"] = body
        .get("epoch")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("assignment transaction epoch missing"))?;
    if let Some(words) = body.get("words") {
        if let Some(supplied) = row.get("words") {
            ensure!(
                supplied == words,
                "assignment words do not match transaction"
            );
        }
        bound["words"] = words.clone();
    }
    parse_assignment(&bound)
}
fn contains_credential(value: &Value, secret: &str) -> bool {
    match value {
        Value::String(value) => value.contains(secret),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_credential(value, secret)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.contains(secret) || contains_credential(value, secret)),
        _ => false,
    }
}
fn read_credential(path: &Path) -> Result<HeaderValue> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("cannot open credential file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("cannot inspect credential file"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4096,
        "credential must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.mode() & 0o077 == 0,
            "credential file must not be accessible to group or others"
        );
        ensure!(
            metadata.nlink() == 1,
            "credential file must not have multiple hard links"
        );
        // SAFETY: geteuid has no preconditions and only reads process identity.
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "credential file must be owned by the current user"
        );
    }
    #[cfg(not(unix))]
    anyhow::bail!("private credential permission checks require a Unix platform");
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("cannot read credential file"))?;
    parse_credential(&bytes)
}

fn parse_credential(bytes: &[u8]) -> Result<HeaderValue> {
    ensure!(bytes.len() <= 4096, "credential file exceeds size limit");
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("invalid credential encoding"))?
        .trim_end_matches(['\r', '\n']);
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Credential {
        api_key: String,
    }
    let parsed;
    let token = if text.trim_start().starts_with('{') {
        parsed = serde_json::from_str::<Credential>(text)
            .map_err(|_| anyhow::anyhow!("credential JSON must contain only one api_key string"))?;
        parsed.api_key.as_str()
    } else {
        text
    };
    ensure!(
        token.starts_with("pk_") && token.len() >= 4 && safe_segment(token, 4096),
        "credential file must contain one API key"
    );
    let mut key =
        HeaderValue::from_str(token).map_err(|_| anyhow::anyhow!("invalid credential format"))?;
    key.set_sensitive(true);
    Ok(key)
}
pub(crate) fn valid_grade_reasoning(reasoning: &str) -> bool {
    (10..=500).contains(&reasoning.trim().chars().count())
}

pub(crate) fn has_required_words(answer: &str, words: &[String]) -> bool {
    let lower = answer.to_lowercase();
    words
        .iter()
        .all(|word| lower.contains(&word.to_lowercase()))
}

fn validate_payload(kind: WorkKind, payload: &Value) -> Result<()> {
    let object = payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("submission payload must be an object"))?;
    match kind {
        WorkKind::Answer => {
            ensure!(object.len() == 1, "answer payload permits only answer");
            let answer = object
                .get("answer")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("answer text missing"))?;
            // Actual dynamic minimum/maximum and words are checked against the fresh challenge by runtime.
            ensure!(
                !answer.trim().is_empty() && answer.chars().count() <= MAX_TEXT_CHARS,
                "answer is empty or exceeds safety bound"
            );
        }
        WorkKind::Judge => {
            ensure!(
                object.len() == 3,
                "grade payload permits only assignment, score and reasoning"
            );
            ensure!(
                object
                    .get("assignment")
                    .and_then(Value::as_str)
                    .is_some_and(valid_txid),
                "invalid grade assignment"
            );
            ensure!(
                object
                    .get("score")
                    .and_then(Value::as_u64)
                    .is_some_and(|score| score <= 3),
                "grade score must be an integer 0..3"
            );
            let reasoning = object
                .get("reasoning")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("grade reasoning missing"))?;
            ensure!(
                valid_grade_reasoning(reasoning),
                "grade reasoning must contain 10..500 characters"
            );
        }
        WorkKind::Mine => ensure!(object.is_empty(), "mine takes no payload fields"),
    }
    Ok(())
}
fn parse_retry_after(value: &str) -> Option<u64> {
    let value = value.trim();
    value.parse().ok().or_else(|| {
        httpdate::parse_http_date(value).ok().map(|time| {
            let delay = time.duration_since(SystemTime::now()).unwrap_or_default();
            delay
                .as_secs()
                .saturating_add(u64::from(delay.subsec_nanos() != 0))
        })
    })
}
fn max_delay(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}
pub(crate) fn valid_txid(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}
/// Only typed transaction identifiers are canonicalized. Addresses and job
/// capabilities remain case-sensitive.
pub fn canonical_txid(id: &str) -> Result<String> {
    ensure!(valid_txid(id), "invalid transaction identifier");
    Ok(id.to_ascii_lowercase())
}

#[derive(Clone, Copy)]
pub enum RecoveryIdentifier {
    Job,
    Transaction,
}

/// A matching payload on an unrelated transaction is not request attribution.
/// Only a capability/txid already durably bound to the dispatch can be used here.
pub fn verify_recovery_identifier(
    recorded: Option<&str>,
    candidate: &str,
    source: RecoveryIdentifier,
) -> Result<String> {
    let recorded = recorded.ok_or_else(|| anyhow::anyhow!("request attribution unavailable"))?;
    match source {
        RecoveryIdentifier::Job => {
            ensure!(
                safe_segment(candidate, 128) && recorded == candidate,
                "job request binding mismatch"
            );
            Ok(candidate.to_owned())
        }
        RecoveryIdentifier::Transaction => {
            let id = canonical_txid(candidate)?;
            ensure!(
                canonical_txid(recorded)? == id,
                "transaction request binding mismatch"
            );
            Ok(id)
        }
    }
}
fn failed(body: &Value) -> bool {
    body.get("ok") == Some(&Value::Bool(false))
        || body.get("success") == Some(&Value::Bool(false))
        || body.get("halted") == Some(&Value::Bool(true))
        || matches!(
            body.get("status").and_then(Value::as_str),
            Some("halted" | "paused")
        )
        || body
            .get("error")
            .is_some_and(|error| !error.is_null() && error != false && error != "")
}
fn error_code(body: &Value) -> Option<&str> {
    body.get("code")
        .and_then(Value::as_str)
        .or_else(|| body.get("error").and_then(Value::as_str))
}
fn unknown(reason: &str) -> Outcome {
    Outcome::Unknown {
        reason: reason.into(),
    }
}

pub fn classify_source(kind: WorkKind, response: &Response, source: ResponseSource) -> Outcome {
    let body = &response.body;
    if !body.is_object() {
        return unknown("response_shape_unknown");
    }
    let code = error_code(body);
    if let (Some(code), Some(error)) = (
        body.get("code").and_then(Value::as_str),
        body.get("error").and_then(Value::as_str),
    ) && code != error
    {
        return unknown("conflicting_error_codes");
    }
    if body.get("state").is_some_and(|state| !state.is_string()) {
        return unknown("job_state_unknown");
    }
    let state = body.get("state").and_then(Value::as_str);
    let has_tx = ["id", "challenge_txid", "txid"]
        .iter()
        .any(|field| body.get(field).is_some());
    let has_job = body.get("job_id").is_some();
    let accepting = ["queued", "accepted"]
        .iter()
        .any(|field| body.get(field).is_some_and(|value| value != false))
        || matches!(state, Some("queued" | "running" | "processing"));
    // Acceptance evidence wins over refusal hints. Contradictory evidence must
    // never authorize a new write, even for an otherwise known refusal code.
    if response.status == 202 || code == Some("duplicate_in_flight") {
        if has_tx || (failed(body) && code != Some("duplicate_in_flight")) {
            return unknown("contradictory_acceptance");
        }
        return body
            .get("job_id")
            .and_then(Value::as_str)
            .filter(|id| safe_segment(id, 128))
            .map(|id| Outcome::Queued { job_id: id.into() })
            .unwrap_or_else(|| {
                unknown(if source == ResponseSource::BoundJob {
                    "bound_job_pending"
                } else {
                    "queued_identifier_missing"
                })
            });
    }
    if source == ResponseSource::BoundJob && state != Some("done") && state != Some("expired") {
        return unknown("bound_job_state_unknown");
    }
    if has_job || accepting {
        return unknown("contradictory_acceptance");
    }
    if code.is_some()
        && (body.get("ok") == Some(&Value::Bool(true))
            || body.get("success") == Some(&Value::Bool(true)))
    {
        return unknown("contradictory_acceptance");
    }
    if kind != WorkKind::Mine && !has_tx {
        if source == ResponseSource::Submit
            && ((response.status == 429 && code == Some("accept queue full"))
                || (response.status == 503 && code == Some("epoch_closing")))
            && state.is_none()
        {
            return Outcome::Retry {
                after_seconds: response
                    .retry_after_seconds
                    .unwrap_or(if response.status == 429 { 5 } else { 30 })
                    .max(1),
            };
        }
        if source == ResponseSource::BoundJob
            && response.status == 408
            && code == Some("job_expired")
            && state == Some("expired")
        {
            return Outcome::Expired;
        }
        let rejected = match kind {
            WorkKind::Answer => {
                response.status == 409
                    && matches!(code, Some("already_answered" | "duplicate_answer"))
            }
            WorkKind::Judge => {
                matches!(response.status, 400 | 403 | 409)
                    && matches!(code, Some("off_panel" | "duplicate_grade"))
            }
            WorkKind::Mine => false,
        };
        if rejected
            && (state.is_none() || (source == ResponseSource::BoundJob && state == Some("done")))
        {
            return Outcome::Rejected {
                code: code.unwrap().into(),
            };
        }
        // go.md binds a done job to the actual endpoint rejection. These exact
        // engine reasons establish terminal processing, NOT unchanged nonce.
        // Direct-submit vocabulary alone does not establish these semantics.
        if source == ResponseSource::BoundJob
            && state == Some("done")
            && matches!(response.status, 200 | 400)
        {
            let terminal = match (kind, code) {
                (WorkKind::Answer, Some("stale_seed")) => Some("stale_seed"),
                (WorkKind::Answer, Some("challenge answer length out of bounds")) => {
                    Some("answer_length")
                }
                (WorkKind::Judge, Some("duplicate sealed grade")) => Some("duplicate_sealed_grade"),
                _ => None,
            };
            if let Some(code) = terminal {
                return Outcome::ProcessedRejected {
                    code: code.into(),
                    next_nonce: body
                        .get("next_nonce")
                        .and_then(Value::as_u64)
                        .filter(|nonce| *nonce > 0),
                };
            }
        }
    }
    if response.status != 200 || failed(body) {
        return unknown("route_result_unknown");
    }
    if state.is_some_and(|state| state != "done") {
        return unknown("job_state_unknown");
    }
    if body.get("ok") != Some(&Value::Bool(true)) && body.get("success") != Some(&Value::Bool(true))
    {
        return unknown("route_success_missing");
    }
    if kind == WorkKind::Mine {
        return if !has_tx
            && body.get("ok") == Some(&Value::Bool(true))
            && body.get("attested").and_then(Value::as_u64).is_some()
        {
            Outcome::Completed
        } else {
            unknown("mine_attestation_count_missing")
        };
    }
    let field = if kind == WorkKind::Answer {
        "challenge_txid"
    } else {
        "id"
    };
    if ["id", "challenge_txid", "txid"]
        .iter()
        .any(|other| *other != field && body.get(other).is_some())
    {
        return unknown("conflicting_transaction_identifiers");
    }
    body.get(field)
        .and_then(Value::as_str)
        .and_then(|id| canonical_txid(id).ok())
        .map(|txid| Outcome::Included { txid })
        .unwrap_or_else(|| unknown("route_transaction_missing"))
}

fn response_error_category(kind: WorkKind, response: &Response) -> Option<&'static str> {
    let code = error_code(&response.body)?;
    match (kind, code) {
        (WorkKind::Answer, "stale_seed") => Some("stale_seed"),
        (WorkKind::Answer, "challenge answer length out of bounds") => Some("answer_length"),
        (WorkKind::Judge, "duplicate sealed grade") => Some("duplicate_sealed_grade"),
        (WorkKind::Judge, "grade queue is full") => Some("grade_queue_full"),
        (_, "accept queue full") => Some("accept_queue_full"),
        (_, "epoch_closing") => Some("epoch_closing"),
        (_, "job_expired") => Some("job_expired"),
        (_, "endpoint temporarily halted — API hardening in progress") => Some("endpoint_halted"),
        (WorkKind::Answer, value) => {
            let limit = value.strip_prefix("answer surface is at its global ceiling (")?;
            let limit = limit.strip_suffix(" — retry shortly").unwrap_or(limit);
            let number = limit.strip_suffix("/min)")?;
            (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
                .then_some("answer_global_ceiling")
        }
        _ => None,
    }
}

/// Static bounded labels only: never copy arbitrary errors, text or identifiers.
pub fn response_evidence(
    kind: WorkKind,
    source: ResponseSource,
    response: Option<&Response>,
) -> DiagnosticEvidence {
    let (reason, shape) = match response {
        None => ("transport_unknown".to_owned(), "unavailable"),
        Some(response) => {
            let reason = match classify_source(kind, response, source) {
                Outcome::Queued { .. } => "queued".into(),
                Outcome::Included { .. } => "included".into(),
                Outcome::Rejected { code } | Outcome::ProcessedRejected { code, .. } => code,
                Outcome::Retry { .. } => "proven_not_accepted".into(),
                Outcome::Expired => "bound_job_expired".into(),
                Outcome::Unknown { reason } => reason,
                Outcome::Completed => "completed".into(),
            };
            (
                reason,
                if response.body.is_object() {
                    "object"
                } else {
                    "unavailable"
                },
            )
        }
    };
    DiagnosticEvidence {
        stage: source,
        route: kind,
        status: response.map(|r| r.status),
        reason,
        retry_after_seconds: response.and_then(|r| r.retry_after_seconds),
        shape: shape.into(),
        error_category: response
            .and_then(|value| response_error_category(kind, value))
            .map(str::to_owned),
    }
}

/// Retain bounded syntactically usable leads even when the response is
/// contradictory. This performs no attribution or outcome classification.
pub fn response_candidates(response: &Response) -> ResponseCandidates {
    let job_id = response
        .body
        .get("job_id")
        .and_then(Value::as_str)
        .filter(|id| safe_segment(id, 128))
        .map(str::to_owned);
    let mut transaction_ids = Vec::new();
    for field in ["id", "challenge_txid", "txid"] {
        if let Some(id) = response
            .body
            .get(field)
            .and_then(Value::as_str)
            .and_then(|id| canonical_txid(id).ok())
            && !transaction_ids.contains(&id)
        {
            transaction_ids.push(id);
        }
    }
    ResponseCandidates {
        job_id,
        transaction_ids,
    }
}

pub fn parse_challenge(response: &Response) -> Result<Challenge> {
    ensure!(
        response.status == 200 && !failed(&response.body),
        "challenge request unsuccessful"
    );
    let body = &response.body;
    let epoch = body
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("challenge epoch missing or invalid"))?;
    let words = parse_words(
        body.get("words")
            .ok_or_else(|| anyhow::anyhow!("challenge words missing"))?,
    )?;
    ensure!(!words.is_empty(), "challenge words empty");
    let answered = body
        .get("answered")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow::anyhow!("challenge answered flag missing or invalid"))?;
    // Published hosted protocol currently specifies 120..600. Optional explicit
    // limits override this fallback; malformed or contradictory limits fail closed.
    let min_chars = challenge_limit(body, "min_chars", 120)?;
    let max_chars = challenge_limit(body, "max_chars", 600)?;
    ensure!(
        min_chars > 0 && min_chars <= max_chars && max_chars <= MAX_TEXT_CHARS,
        "invalid challenge length limits"
    );
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(epoch, &words, min_chars, max_chars,))?)
    );
    Ok(Challenge {
        epoch,
        words,
        answered,
        min_chars,
        max_chars,
        fingerprint,
    })
}
fn challenge_limit(body: &Value, name: &str, fallback: usize) -> Result<usize> {
    let outer = body.get(name);
    let inner = if let Some(constraints) = body.get("constraints") {
        ensure!(constraints.is_object(), "invalid challenge constraints");
        constraints.get(name)
    } else {
        None
    };
    if let (Some(outer), Some(inner)) = (outer, inner) {
        ensure!(outer == inner, "conflicting challenge constraints");
    }
    match outer.or(inner) {
        Some(value) => value
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| anyhow::anyhow!("invalid challenge length limit")),
        None => Ok(fallback),
    }
}
fn parse_words(value: &Value) -> Result<Vec<String>> {
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("words must be an array"))?;
    ensure!(values.len() <= 32, "too many required words");
    let mut words = Vec::with_capacity(values.len());
    for value in values {
        let word = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("word must be a string"))?;
        ensure!(
            !word.trim().is_empty()
                && word.chars().count() <= 128
                && !word.chars().any(char::is_control),
            "invalid required word"
        );
        ensure!(
            !words
                .iter()
                .any(|prior: &String| prior.eq_ignore_ascii_case(word)),
            "duplicate required word"
        );
        words.push(word.to_owned());
    }
    Ok(words)
}
fn assignment_rows(response: &Response) -> Result<&Vec<Value>> {
    ensure!(
        response.status == 200 && !failed(&response.body),
        "assignment request unsuccessful"
    );
    // A page is usable work, not a claim of complete inventory. Disappearance is
    // never evidence that a previously dispatched grade succeeded.
    ensure!(
        response.body.get("has_more").is_none_or(Value::is_boolean),
        "invalid assignment pagination flag"
    );
    let rows = response
        .body
        .get("assignments")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("assignment array missing"))?;
    Ok(rows)
}
fn assignment_id(row: &Value) -> Result<&str> {
    // answer_txid is the field emitted by the public reference client's assignments command.
    row.get("answer_txid")
        .and_then(Value::as_str)
        .filter(|id| valid_txid(id))
        .ok_or_else(|| anyhow::anyhow!("assignment answer_txid missing or invalid"))
}
/// Bounded row-local evidence only. `Supplied` means this provided list, never
/// exhaustive lifetime history; an explicit [] differs from a missing field.
fn parse_author_history(row: &Value) -> Result<AuthorHistory> {
    let Some(value) = row.get("author_prior") else {
        return Ok(AuthorHistory::default());
    };
    let Some(values) = value.as_array().filter(|_| {
        row.get("from")
            .and_then(Value::as_str)
            .is_some_and(|author| safe_segment(author, 128))
    }) else {
        return Ok(AuthorHistory {
            entries: vec![],
            coverage: EvidenceCoverage::Truncated,
        });
    };
    let candidate = assignment_id(row)?;
    let target_epoch = row
        .get("answer_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("author history has no target epoch"))?;
    let mut history = AuthorHistory {
        entries: Vec::with_capacity(values.len().min(16)),
        coverage: if values.len() > 16 {
            EvidenceCoverage::Truncated
        } else {
            EvidenceCoverage::Supplied
        },
    };
    let mut seen = std::collections::HashSet::new();
    for value in values.iter().take(16) {
        let parsed = (|| -> Result<AuthorPrior> {
            let epoch = value
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow::anyhow!("invalid prior epoch"))?;
            ensure!(epoch < target_epoch, "prior epoch is not prior");
            let answer_txid = canonical_txid(assignment_id(value)?)?;
            ensure!(
                !answer_txid.eq_ignore_ascii_case(candidate),
                "candidate in prior history"
            );
            if let Some(author) = value.get("from") {
                ensure!(Some(author) == row.get("from"), "prior author mismatch");
            }
            let text = value
                .get("answer_text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("invalid prior answer"))?;
            // Observed provider excerpts stop at 400 UTF-16 units without a
            // marker. Treat that boundary conservatively, not as full text.
            let text_truncated = text.encode_utf16().count() >= 400
                || text.ends_with('…')
                || text.ends_with("...")
                || value.get("truncated") == Some(&Value::Bool(true));
            let answer_text: String = text.chars().take(2048).collect();
            let seed_words = value
                .get("seed_words")
                .map(parse_words)
                .transpose()?
                .unwrap_or_default();
            Ok(AuthorPrior {
                epoch,
                answer_txid,
                answer_text,
                seed_words,
                text_truncated,
            })
        })();
        match parsed {
            Ok(entry) if seen.insert(entry.answer_txid.clone()) => {
                if entry.text_truncated {
                    history.coverage = EvidenceCoverage::Truncated;
                }
                history.entries.push(entry);
            }
            // Optional malformed history must not fabricate evidence or stop
            // all judging. Explicit coverage records the discarded evidence.
            _ => history.coverage = EvidenceCoverage::Truncated,
        }
    }
    Ok(history)
}
fn parse_assignment(row: &Value) -> Result<Assignment> {
    let id = assignment_id(row)?;
    let epoch = row
        .get("answer_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            anyhow::anyhow!("assignment target epoch unavailable; transaction hydration required")
        })?;
    let answer = row
        .get("answer")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("assignment answer missing"))?;
    ensure!(
        !answer.trim().is_empty() && answer.chars().count() <= MAX_TEXT_CHARS,
        "assignment answer empty or too long"
    );
    let words = row
        .get("words")
        .map(parse_words)
        .transpose()?
        .unwrap_or_default();
    Ok(Assignment {
        id: canonical_txid(id)?,
        epoch,
        answer: answer.into(),
        words,
        expires_at_epoch: row
            .pointer("/pending_meta/expires_at_epoch")
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| anyhow::anyhow!("invalid assignment expiry"))
            })
            .transpose()?,
        author: row
            .get("from")
            .map(|v| {
                v.as_str()
                    .filter(|author| safe_segment(author, 128))
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("invalid candidate author"))
            })
            .transpose()?,
        author_prior: parse_author_history(row)?,
    })
}
fn ensure_unique_assignments(rows: &[Assignment]) -> Result<()> {
    let mut ids = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        ensure!(ids.insert(&row.id), "duplicate assignment identifier");
    }
    Ok(())
}
/// IDs on the current page, without requiring target epochs or explorer reads.
/// `has_more` may be true: callers must not interpret omission as completion.
pub fn assignment_ids(response: &Response) -> Result<Vec<String>> {
    let rows = assignment_rows(response)?;
    let mut seen = std::collections::HashSet::with_capacity(rows.len());
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let id = canonical_txid(assignment_id(row)?)?;
        ensure!(seen.insert(id.clone()), "duplicate assignment identifier");
        ids.push(id);
    }
    Ok(ids)
}
pub fn parse_assignments(response: &Response) -> Result<Vec<Assignment>> {
    let rows = assignment_rows(response)?
        .iter()
        .map(parse_assignment)
        .collect::<Result<Vec<_>>>()?;
    ensure_unique_assignments(&rows)?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn response(status: u16, body: Value) -> Response {
        Response {
            status,
            body,
            retry_after_seconds: None,
            read_failure: None,
        }
    }
    fn txid() -> String {
        "a".repeat(64)
    }
    #[test]
    fn success_is_route_specific_not_just_http_status() {
        let answer = response(200, json!({"ok":true,"challenge_txid":txid()}));
        assert!(matches!(
            classify_source(WorkKind::Answer, &answer, ResponseSource::Submit),
            Outcome::Included { .. }
        ));
        assert!(matches!(
            classify_source(WorkKind::Judge, &answer, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
        assert!(matches!(
            classify_source(WorkKind::Mine, &answer, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
        let grade = response(200, json!({"ok":true,"id":txid()}));
        assert!(matches!(
            classify_source(WorkKind::Judge, &grade, ResponseSource::Submit),
            Outcome::Included { .. }
        ));
        assert!(matches!(
            classify_source(WorkKind::Answer, &grade, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
        assert!(matches!(
            classify_source(
                WorkKind::Judge,
                &response(
                    200,
                    json!({"ok":true,"id":"0123456789abcdef0123456789abcdef"})
                ),
                ResponseSource::Submit
            ),
            Outcome::Unknown { .. }
        ));
        for body in [
            json!({}),
            json!({"ok":true}),
            json!({"ok":false,"challenge_txid":txid()}),
            json!({"ok":true,"challenge_txid":"short"}),
            json!({"ok":true,"challenge_txid":txid(),"error":"bad_nonce"}),
        ] {
            assert!(matches!(
                classify_source(
                    WorkKind::Answer,
                    &response(200, body),
                    ResponseSource::Submit
                ),
                Outcome::Unknown { .. }
            ));
        }
    }
    #[test]
    fn queued_terminal_results_use_original_route() {
        assert_eq!(
            classify_source(
                WorkKind::Answer,
                &response(202, json!({"job_id":"safe-id_1"})),
                ResponseSource::Submit
            ),
            Outcome::Queued {
                job_id: "safe-id_1".into()
            }
        );
        assert_eq!(
            classify_source(
                WorkKind::Answer,
                &response(409, json!({"error":"duplicate_in_flight","job_id":"safe"})),
                ResponseSource::Submit
            ),
            Outcome::Queued {
                job_id: "safe".into()
            }
        );
        for body in [json!({}), json!({"job_id":"../unsafe"})] {
            assert!(matches!(
                classify_source(
                    WorkKind::Answer,
                    &response(202, body),
                    ResponseSource::Submit
                ),
                Outcome::Unknown { .. }
            ));
        }
        assert!(matches!(
            classify_source(
                WorkKind::Answer,
                &response(
                    200,
                    json!({"state":"done","ok":true,"challenge_txid":txid()})
                ),
                ResponseSource::BoundJob
            ),
            Outcome::Included { .. }
        ));
        assert_eq!(
            classify_source(
                WorkKind::Judge,
                &response(200, json!({"state":"done","ok":true,"id":txid()})),
                ResponseSource::BoundJob
            ),
            Outcome::Included { txid: txid() }
        );
        assert!(matches!(
            classify_source(
                WorkKind::Judge,
                &response(409, json!({"state":"done","error":"off_panel"})),
                ResponseSource::BoundJob
            ),
            Outcome::Rejected { .. }
        ));
        assert!(matches!(
            classify_source(
                WorkKind::Answer,
                &response(404, json!({"error":"unknown or expired job id"})),
                ResponseSource::BoundJob
            ),
            Outcome::Unknown { .. }
        ));
        assert!(matches!(
            classify_source(
                WorkKind::Answer,
                &response(408, json!({"state":"expired","error":"job_expired"})),
                ResponseSource::BoundJob
            ),
            Outcome::Expired
        ));
    }
    #[test]
    fn only_documented_nonacceptance_can_retry() {
        for (status, code) in [(429, "accept queue full"), (503, "epoch_closing")] {
            let mut result = response(status, json!({"error":code}));
            result.retry_after_seconds = Some(123);
            assert_eq!(
                classify_source(WorkKind::Answer, &result, ResponseSource::Submit),
                Outcome::Retry { after_seconds: 123 }
            );
            assert!(matches!(
                classify_source(WorkKind::Mine, &result, ResponseSource::Submit),
                Outcome::Unknown { .. }
            ));
        }
        for (status, code) in [
            (503, "overloaded"),
            (500, "epoch_closing"),
            (429, "rate_limited"),
        ] {
            assert!(matches!(
                classify_source(
                    WorkKind::Answer,
                    &response(status, json!({"error":code})),
                    ResponseSource::Submit
                ),
                Outcome::Unknown { .. }
            ));
        }
    }
    #[test]
    fn mine_completion_requires_explicit_nonnegative_attestation_count() {
        for count in [0, 7] {
            assert_eq!(
                classify_source(
                    WorkKind::Mine,
                    &response(200, json!({"ok":true,"attested":count})),
                    ResponseSource::Submit
                ),
                Outcome::Completed
            );
        }
        for body in [
            json!({"ok":true}),
            json!({"attested":3}),
            json!({"ok":true,"attested":true}),
            json!({"ok":true,"attested":-1}),
            json!({"ok":true,"attested":1,"error":"failed"}),
        ] {
            assert!(matches!(
                classify_source(WorkKind::Mine, &response(200, body), ResponseSource::Submit),
                Outcome::Unknown { .. }
            ));
        }
    }
    #[test]
    fn challenge_constraints_and_rotation_change_binding() {
        let mut result = response(
            200,
            json!({"epoch":10,"words":["one","two","three"],"answered":false}),
        );
        let original = parse_challenge(&result).unwrap();
        assert_eq!((original.min_chars, original.max_chars), (120, 600));
        result.body["constraints"] = json!({"min_chars":150,"max_chars":700});
        let changed = parse_challenge(&result).unwrap();
        assert_eq!((changed.min_chars, changed.max_chars), (150, 700));
        assert_ne!(original.fingerprint, changed.fingerprint);
        result.body["words"][0] = json!("rotated");
        assert_ne!(
            changed.fingerprint,
            parse_challenge(&result).unwrap().fingerprint
        );
        result.body["min_chars"] = json!(120);
        assert!(parse_challenge(&result).is_err());
    }
    #[test]
    fn challenge_rejects_partial_or_malformed_observations() {
        for body in [
            json!({"epoch":false,"words":["x"],"answered":false}),
            json!({"epoch":1,"words":[],"answered":false}),
            json!({"epoch":1,"words":["x"]}),
            json!({"epoch":1,"words":["x"],"answered":false,"max_chars":0}),
        ] {
            assert!(parse_challenge(&response(200, body)).is_err());
        }
    }
    #[test]
    fn assignment_epoch_is_never_current_page_epoch() {
        let mut result = response(
            200,
            json!({"epoch":100,"has_more":false,"assignments":[{"answer_txid":txid(),"answer":"candidate"}]}),
        );
        assert!(parse_assignments(&result).is_err());
        result.body["assignments"][0]["answer_epoch"] = json!(42);
        let assignments = parse_assignments(&result).unwrap();
        assert_eq!(assignments[0].epoch, 42);
        assert!(assignments[0].words.is_empty());
        result.body["has_more"] = json!(true);
        assert!(parse_assignments(&result).is_ok());
        result.body["has_more"] = json!(false);
        let duplicate = result.body["assignments"][0].clone();
        result.body["assignments"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(parse_assignments(&result).is_err());
        assert!(assignment_ids(&result).is_err());
    }
    #[test]
    fn supplied_answer_epoch_does_not_require_explorer_availability() {
        let page = response(
            200,
            json!({"epoch":100,"has_more":true,"assignments":[
                {"answer_txid":txid(),"answer_epoch":42,"answer":"candidate","words":["mechanism"]}
            ]}),
        );
        assert!(!assignment_needs_hydration(&page, &txid()).unwrap());
        let assignment = parse_selected_assignment(&page, &txid(), None).unwrap();
        assert_eq!(assignment.epoch, 42);
        assert_eq!(assignment.answer, "candidate");
        assert_eq!(assignment.words, vec!["mechanism"]);
    }
    #[test]
    fn malformed_supplied_epoch_cannot_be_repaired_by_explorer() {
        let tx = response(
            200,
            json!({
                "id":txid(),"body":{"type":"challenge","epoch":42,"answer":"candidate"}
            }),
        );
        for invalid_epoch in [Value::Null, json!(-1), json!("42"), json!(true)] {
            let page = response(
                200,
                json!({"epoch":100,"assignments":[
                    {"answer_txid":txid(),"answer_epoch":invalid_epoch,"answer":"candidate"}
                ]}),
            );
            assert!(!assignment_needs_hydration(&page, &txid()).unwrap());
            assert!(parse_selected_assignment(&page, &txid(), Some(&tx)).is_err());
        }
    }
    #[tokio::test]
    async fn selected_hydration_does_not_fetch_other_assignments() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.timeouts.http_seconds = 2;
        let selected = txid();
        let unavailable = "b".repeat(64);
        let page = response(
            200,
            json!({"epoch":100,"has_more":true,"assignments":[
                {"answer_txid":unavailable,"answer":"unavailable candidate"},
                {"answer_txid":selected,"answer":"selected candidate"}
            ]}),
        );
        assert_eq!(
            assignment_ids(&page).unwrap(),
            vec![unavailable, selected.clone()]
        );
        let expected_path = format!("GET /chain/poa-mainnet-1/api/explorer/tx/{selected} HTTP/1.1");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0 && request.len() + count <= 4096);
                request.extend_from_slice(&buffer[..count]);
            }
            assert!(
                std::str::from_utf8(&request)
                    .unwrap()
                    .starts_with(&expected_path)
            );
            let body = json!({"id":selected,"body":{"type":"challenge","epoch":42,"answer":"selected candidate"}}).to_string();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
            // Only this selected lookup is served. A bulk traversal would fail.
        });
        let protocol = Protocol::new(&config).unwrap();
        assert!(assignment_needs_hydration(&page, &txid()).unwrap());
        let tx = protocol
            .get(&format!("/api/explorer/tx/{}", txid()))
            .await
            .unwrap();
        let assignment = parse_selected_assignment(&page, &txid(), Some(&tx)).unwrap();
        assert_eq!(assignment.epoch, 42);
        assert_eq!(assignment.answer, "selected candidate");
        assert!(assignment.words.is_empty());
        server.await.unwrap();
    }
    #[test]
    fn read_allowlist_excludes_effects_and_url_injection() {
        let protocol = Protocol::new(&Config::default()).unwrap();
        for path in [
            "/api/hosted/mine",
            "/api/hosted/answer",
            "/api/hosted/register",
            "/api/hosted/send",
            "/api/hosted/export",
            "/api/hosted/me?key=x",
            "https://other.example/api/hosted/me",
            "/api/job/../hosted/mine",
            "/api/job/a%2fb",
            "/chain/other/api/status",
        ] {
            assert!(!protocol.allowed_read(path), "{path}");
        }
        for path in [
            "/api/status",
            "/api/hosted/me",
            "/api/job/safe-id",
            &format!("/api/receipt/{}", txid()),
        ] {
            assert!(protocol.allowed_read(path), "{path}");
        }
    }
    #[test]
    fn payload_allowlist_excludes_secret_and_extra_fields() {
        assert!(
            validate_payload(WorkKind::Answer, &json!({"answer":"text","key":"secret"})).is_err()
        );
        assert!(
            validate_payload(
                WorkKind::Judge,
                &json!({"assignment":txid(),"score":3,"reasoning":"Substantive mechanism."})
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                WorkKind::Judge,
                &json!({"assignment":txid(),"score":4,"reasoning":"Substantive mechanism."})
            )
            .is_err()
        );
        assert!(validate_payload(WorkKind::Mine, &json!({})).is_ok());
        assert!(validate_payload(WorkKind::Mine, &json!({"to":"elsewhere"})).is_err());
    }

    #[test]
    fn grade_bounds_are_rejected_before_a_network_future_exists() {
        let mut protocol = Protocol::new(&Config::default()).unwrap();
        protocol.modes = [Mode::Active; 3];
        protocol.key = Some(HeaderValue::from_static("pk_fixture"));
        protocol.address = "configured-account".into();
        for (length, accepted) in [(9, false), (10, true), (500, true), (501, false)] {
            let payload = json!({"assignment":txid(),"score":2,"reasoning":"a".repeat(length)});
            assert_eq!(
                protocol
                    .prepare_submission(WorkKind::Judge, &payload)
                    .is_ok(),
                accepted
            );
        }
    }

    #[tokio::test]
    async fn unavailable_bodies_retain_safe_categories_status_and_retry_after() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, body, length, failure) in [
            (429, "", 0, ReadFailure::InvalidJson),
            (
                503,
                "<html>unavailable</html>",
                24,
                ReadFailure::InvalidJson,
            ),
            (503, "{", 100, ReadFailure::BodyInterrupted),
            (
                503,
                "",
                MAX_RESPONSE_BYTES + 1,
                ReadFailure::ResponseTooLarge,
            ),
            (
                200,
                "\"private-test-credential\"",
                25,
                ReadFailure::CredentialEchoRedacted,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = Config::default();
            config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let mut received = 0;
                while !request[..received]
                    .windows(4)
                    .any(|bytes| bytes == b"\r\n\r\n")
                {
                    let count = stream.read(&mut request[received..]).await.unwrap();
                    assert!(count > 0);
                    received += count;
                }
                let reply = format!(
                    "HTTP/1.1 {status} Unavailable\r\nRetry-After: 300\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    length,
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            });
            let mut protocol = Protocol::new(&config).unwrap();
            protocol.key = Some(HeaderValue::from_static("private-test-credential"));
            let response = protocol.get("/api/status").await.unwrap();
            assert_eq!(response.status, status);
            assert_eq!(response.retry_after_seconds, Some(300));
            assert_eq!(response.read_failure, Some(failure));
            assert!(response.body.is_null());
            let public = serde_json::to_string(&response).unwrap();
            assert!(!public.contains("private-test-credential"));
            assert!(!public.contains("127.0.0.1"));
            assert!(matches!(
                classify_source(WorkKind::Answer, &response, ResponseSource::Submit),
                Outcome::Unknown { .. }
            ));
            server.await.unwrap();
        }
    }

    #[test]
    fn read_failure_vocabulary_and_transport_errors_are_sanitized() {
        for failure in [
            ReadFailure::Timeout,
            ReadFailure::Connect,
            ReadFailure::Request,
            ReadFailure::BodyInterrupted,
            ReadFailure::ResponseTooLarge,
            ReadFailure::InvalidJson,
            ReadFailure::CredentialEchoRedacted,
        ] {
            let error = anyhow::Error::new(failure).context("safe context");
            assert_eq!(transport_failure(&error), failure);
        }
        let unknown = anyhow::anyhow!("https://private.example/bearer-secret");
        assert_eq!(transport_failure(&unknown), ReadFailure::Request);
        let legacy: Response = serde_json::from_value(json!({
            "status": 200, "body": {}, "retry_after_seconds": null
        }))
        .unwrap();
        assert_eq!(legacy.read_failure, None);
    }
    #[cfg(unix)]
    #[test]
    fn credential_file_rejects_symlinks_and_public_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "pk_test_local_only\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_credential(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_credential(&path).unwrap().is_sensitive());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_credential(&link).is_err());
        let hardlink = dir.path().join("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(read_credential(&path).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn strict_json_credentials_reject_ambiguity_without_echoing_values() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, r#"{"api_key":"pk_local_fixture_only"}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_credential(&path).is_ok());
        for text in [
            r#"{"api_token":"pk_local_fixture_only"}"#,
            r#"{"api_key":"pk_local_fixture_only","api_key":"pk_other_fixture"}"#,
            r#"{"api_key":"pk_local_fixture_only","unexpected":"field"}"#,
            r#"{"api_key":12}"#,
            r#"{"api_key":"pk_local_fixture_only"#,
            "pk_local_fixture_only\npk_second_key",
        ] {
            std::fs::write(&path, text).unwrap();
            let error = read_credential(&path).unwrap_err().to_string();
            assert!(!error.contains("pk_local_fixture_only"));
        }
    }
    #[test]
    fn echoed_credentials_are_detected_even_when_json_escaped() {
        let body: Value =
            serde_json::from_str(r#"{"nested":["value with p\u006b_fixture"]}"#).unwrap();
        assert!(contains_credential(&body, "pk_fixture"));
        assert!(contains_credential(
            &json!({"pk_fixture":"value"}),
            "pk_fixture"
        ));
        assert!(!contains_credential(
            &json!({"ordinary":"value"}),
            "pk_fixture"
        ));
    }
    #[test]
    fn acceptance_evidence_prevents_refusal_retries() {
        for body in [
            json!({"error":"accept queue full","job_id":"capability"}),
            json!({"error":"accept queue full","id":txid()}),
            json!({"error":"accept queue full","accepted":true}),
            json!({"error":"accept queue full","ok":true}),
        ] {
            assert!(matches!(
                classify_source(
                    WorkKind::Answer,
                    &response(429, body),
                    ResponseSource::Submit
                ),
                Outcome::Unknown { .. }
            ));
        }
        for (status, body) in [
            (429, json!({"error":"answer ceiling"})),
            (429, json!({"error":"grade queue full"})),
            (503, json!({"halted":true})),
            (200, json!({"state":"done","error":"unspecified failure"})),
        ] {
            for source in [ResponseSource::Submit, ResponseSource::BoundJob] {
                assert!(matches!(
                    classify_source(WorkKind::Judge, &response(status, body.clone()), source),
                    Outcome::Unknown { .. }
                ));
            }
        }
    }

    #[test]
    fn known_engine_rejections_require_bound_terminal_source() {
        for (kind, error, code) in [
            (WorkKind::Answer, "stale_seed", "stale_seed"),
            (
                WorkKind::Answer,
                "challenge answer length out of bounds",
                "answer_length",
            ),
            (
                WorkKind::Judge,
                "duplicate sealed grade",
                "duplicate_sealed_grade",
            ),
        ] {
            let mut result = response(400, json!({"state":"done","error":error}));
            assert!(matches!(
                classify_source(kind, &result, ResponseSource::Submit),
                Outcome::Unknown { .. }
            ));
            assert_eq!(
                classify_source(kind, &result, ResponseSource::BoundJob),
                Outcome::ProcessedRejected {
                    code: code.into(),
                    next_nonce: None
                }
            );
            result.body["next_nonce"] = json!(7);
            assert_eq!(
                classify_source(kind, &result, ResponseSource::BoundJob),
                Outcome::ProcessedRejected {
                    code: code.into(),
                    next_nonce: Some(7)
                }
            );
            result.body["id"] = json!(txid());
            assert!(matches!(
                classify_source(kind, &result, ResponseSource::BoundJob),
                Outcome::Unknown { .. }
            ));
        }
        let expired = response(408, json!({"state":"expired","error":"job_expired"}));
        assert!(matches!(
            classify_source(WorkKind::Answer, &expired, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
        assert_eq!(
            classify_source(WorkKind::Answer, &expired, ResponseSource::BoundJob),
            Outcome::Expired
        );
    }

    #[test]
    fn diagnostics_never_echo_untrusted_values() {
        let result = response(
            500,
            json!({"error":"secret-canary","job_id":"secret-capability",
            "answer":"private answer","reasoning":"private reasoning"}),
        );
        let evidence = serde_json::to_string(&response_evidence(
            WorkKind::Judge,
            ResponseSource::Submit,
            Some(&result),
        ))
        .unwrap();
        for secret in [
            "secret-canary",
            "secret-capability",
            "private answer",
            "private reasoning",
        ] {
            assert!(!evidence.contains(secret));
        }
        assert!(evidence.contains("contradictory_acceptance"));
        assert_eq!(
            response_evidence(WorkKind::Answer, ResponseSource::Submit, None).reason,
            "transport_unknown"
        );
    }

    #[test]
    fn recognized_rate_limit_diagnostic_never_authorizes_unknown_replay() {
        let limited = response(
            429,
            json!({
                "error":"answer surface is at its global ceiling (20/min) — retry shortly",
                "retry_after_seconds":60
            }),
        );
        let diagnostic =
            response_evidence(WorkKind::Answer, ResponseSource::Submit, Some(&limited));
        assert_eq!(
            diagnostic.error_category.as_deref(),
            Some("answer_global_ceiling")
        );
        assert!(matches!(
            classify_source(WorkKind::Answer, &limited, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
        let injected = response(
            429,
            json!({
                "error":"answer surface is at its global ceiling (private-canary/min)"
            }),
        );
        let diagnostic =
            response_evidence(WorkKind::Answer, ResponseSource::Submit, Some(&injected));
        assert!(diagnostic.error_category.is_none());
        assert!(
            !serde_json::to_string(&diagnostic)
                .unwrap()
                .contains("private-canary")
        );
    }

    #[test]
    fn recovery_requires_prior_request_attribution() {
        assert!(
            verify_recovery_identifier(None, "plausible-job", RecoveryIdentifier::Job).is_err()
        );
        assert!(verify_recovery_identifier(Some("Job"), "job", RecoveryIdentifier::Job).is_err());
        assert!(verify_recovery_identifier(Some("Job"), "Job", RecoveryIdentifier::Job).is_ok());
        assert_eq!(
            verify_recovery_identifier(
                Some(&txid()),
                &txid().to_uppercase(),
                RecoveryIdentifier::Transaction
            )
            .unwrap(),
            txid()
        );
        assert!(
            verify_recovery_identifier(
                Some(&txid()),
                &"b".repeat(64),
                RecoveryIdentifier::Transaction
            )
            .is_err()
        );
    }

    #[test]
    fn assignment_ids_and_history_are_candidate_bound() {
        let prior = json!({"epoch":41,"answer_txid":"B".repeat(64),
            "answer_text":"Earlier mechanism","seed_words":["clock"]});
        let mut page = response(
            200,
            json!({"assignments":[
                {"answer_txid":txid().to_uppercase(),"answer_epoch":42,"answer":"Candidate",
                 "words":["clock"],"from":"CaseSensitiveAuthor",
                 "pending_meta":{"expires_at_epoch":58},"author_prior":[prior]},
                {"answer_txid":"c".repeat(64),"answer_epoch":43,"answer":"Other candidate",
                 "words":["clock"],"from":"OtherAuthor","author_prior":[]}
            ]}),
        );
        let first = parse_selected_assignment(&page, &txid(), None).unwrap();
        assert_eq!(first.id, txid());
        assert_eq!(first.author.as_deref(), Some("CaseSensitiveAuthor"));
        assert_eq!(first.expires_at_epoch, Some(58));
        assert_eq!(first.author_prior.coverage, EvidenceCoverage::Supplied);
        assert_eq!(first.author_prior.entries[0].answer_txid, "b".repeat(64));
        let other = parse_selected_assignment(&page, &"C".repeat(64), None).unwrap();
        assert!(other.author_prior.entries.is_empty());
        assert_eq!(other.author_prior.coverage, EvidenceCoverage::Supplied);
        page.body["assignments"][0]
            .as_object_mut()
            .unwrap()
            .remove("author_prior");
        assert_eq!(
            parse_selected_assignment(&page, &txid(), None)
                .unwrap()
                .author_prior
                .coverage,
            EvidenceCoverage::Missing
        );
        page.body["assignments"][0]["author_prior"] = json!([
            {"epoch":41,"answer_txid":"b".repeat(64),"answer_text":"x".repeat(400)},
            {"epoch":42,"answer_txid":txid(),"answer_text":"not prior"},
            {"epoch":40,"answer_txid":"d".repeat(64),"answer_text":"wrong author","from":"OtherAuthor"}
        ]);
        let history = parse_selected_assignment(&page, &txid(), None)
            .unwrap()
            .author_prior;
        assert_eq!(history.coverage, EvidenceCoverage::Truncated);
        assert_eq!(history.entries.len(), 1);
        assert!(history.entries[0].text_truncated);
        page.body["assignments"][1]["answer_txid"] = json!(txid());
        assert!(assignment_ids(&page).is_err());
    }

    #[tokio::test]
    async fn hosted_page_query_is_structured_and_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.timeouts.http_seconds = 2;
        let mut protocol = Protocol::new(&config).unwrap();
        protocol.key = Some(HeaderValue::from_static("pk_fixture"));
        assert!(protocol.assignment_page(10_001, 1).await.is_err());
        assert!(protocol.assignment_page(0, 101).await.is_err());
        assert!(protocol.assignment_page(0, 0).await.is_err());
        assert!(
            protocol
                .get("/api/hosted/assignments?offset=10&limit=10")
                .await
                .is_err()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let mut used = 0;
            while !bytes[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                let count = stream.read(&mut bytes[used..]).await.unwrap();
                assert!(count > 0);
                used += count;
            }
            let request = std::str::from_utf8(&bytes[..used]).unwrap();
            assert!(request.starts_with(
                "GET /chain/poa-mainnet-1/api/hosted/assignments?offset=10&limit=10 HTTP/1.1\r\n"
            ));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("x-api-key: pk_fixture\r\n")
            );
            let body = r#"{"assignments":[],"offset":10,"limit":10,"has_more":false}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        });
        let page = protocol.assignment_page(10, 10).await.unwrap();
        assert_eq!(page.body["offset"], 10);
        server.await.unwrap();
    }

    #[test]
    fn optional_history_stays_bounded_and_discloses_discarded_evidence() {
        let prior: Vec<Value> = (0..17)
            .map(|index| {
                json!({
                    "epoch":index,"answer_txid":format!("{index:064x}"),
                    "answer_text":"A prior mechanism","seed_words":[]
                })
            })
            .collect();
        let mut page = response(
            200,
            json!({"assignments":[{
                "answer_txid":txid(),"answer_epoch":100,"answer":"Candidate",
                "words":["clock"],"from":"Author","author_prior":prior
            }]}),
        );
        let history = parse_selected_assignment(&page, &txid(), None)
            .unwrap()
            .author_prior;
        assert_eq!(history.entries.len(), 16);
        assert_eq!(history.coverage, EvidenceCoverage::Truncated);
        page.body["assignments"][0]["author_prior"] = json!({"unrecognized":"shape"});
        let assignment = parse_selected_assignment(&page, &txid(), None).unwrap();
        assert_eq!(
            assignment.author_prior.coverage,
            EvidenceCoverage::Truncated
        );
        assert!(assignment.author_prior.entries.is_empty());
        assert_eq!(assignment.words, vec!["clock"]);
    }

    #[test]
    fn hydration_rejects_conflicting_author_and_word_evidence() {
        let page = response(
            200,
            json!({"assignments":[{
                "answer_txid":txid(),"answer":"Candidate","from":"Author","words":["clock"]
            }]}),
        );
        let mut transaction = response(
            200,
            json!({
                "id":txid().to_uppercase(),
                "body":{"type":"challenge","epoch":42,"answer":"Candidate",
                    "from":"OtherAuthor","words":["clock"]}
            }),
        );
        assert!(parse_selected_assignment(&page, &txid(), Some(&transaction)).is_err());
        transaction.body["body"]["from"] = json!("Author");
        transaction.body["body"]["words"] = json!(["other"]);
        assert!(parse_selected_assignment(&page, &txid(), Some(&transaction)).is_err());
        transaction.body["body"]["words"] = json!(["clock"]);
        assert!(parse_selected_assignment(&page, &txid(), Some(&transaction)).is_ok());
    }

    #[test]
    fn contradictory_identifiers_remain_private_untrusted_leads() {
        let result = response(
            429,
            json!({
                "error":"accept queue full","job_id":"private-bearer",
                "id":txid().to_uppercase(),"challenge_txid":txid(),"txid":"b".repeat(64)
            }),
        );
        let candidates = response_candidates(&result);
        assert_eq!(candidates.job_id.as_deref(), Some("private-bearer"));
        assert_eq!(candidates.transaction_ids, vec![txid(), "b".repeat(64)]);
        assert!(matches!(
            classify_source(WorkKind::Answer, &result, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
        assert!(
            verify_recovery_identifier(
                None,
                candidates.job_id.as_deref().unwrap(),
                RecoveryIdentifier::Job
            )
            .is_err()
        );
        let public = serde_json::to_string(&response_evidence(
            WorkKind::Answer,
            ResponseSource::Submit,
            Some(&result),
        ))
        .unwrap();
        assert!(!public.contains("private-bearer") && !public.contains(&txid()));
        let malformed = response_candidates(&response(
            500,
            json!({
                "job_id":"../unsafe","id":"bad","txid":"c".repeat(65)
            }),
        ));
        assert!(malformed.job_id.is_none() && malformed.transaction_ids.is_empty());
    }
}
