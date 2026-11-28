//! Hosted API compatibility is based on <https://minepoa.com/go.md>,
//! <https://minepoa.com/openapi.yaml> and <https://minepoa.com/client/poa.mjs>.
//! HTTP success is not ledger finality. Unknown write outcomes never authorize replay.
use crate::capability::LaneId;
use crate::config::{Config, safe_segment};
use crate::endpoints::{ApiEndpoints, Endpoint};
use anyhow::{Result, ensure};
use reqwest::{
    Client, Url,
    header::{HeaderValue, RETRY_AFTER},
};
use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime},
};

pub mod reports;
mod transport;
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use transport::HostedIdentityBody;
pub use transport::{
    EffectDeadline, HostedResponse, ReadDeadline, RequestContext, RequestMeta, RestrictionBasis,
    RestrictionEvidence, RestrictionScope,
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_CHARS: usize = 16384;

/// Role-specific validation tokens; canonical payload ownership remains in the journal.
pub(crate) struct AnswerIntent(());
pub(crate) struct GradeIntent(());
pub(crate) struct MineIntent;
impl AnswerIntent {
    pub(crate) fn new(payload: &Value) -> Result<Self> {
        validate_payload(LaneId::Answer, payload)?;
        Ok(Self(()))
    }
}
impl GradeIntent {
    pub(crate) fn new(payload: &Value) -> Result<Self> {
        validate_payload(LaneId::Judge, payload)?;
        Ok(Self(()))
    }
}
pub(crate) enum EffectIntent {
    Answer(AnswerIntent),
    Grade(GradeIntent),
    Mine(MineIntent),
}
impl EffectIntent {
    pub(crate) fn lane(&self) -> LaneId {
        match self {
            Self::Answer(_) => LaneId::Answer,
            Self::Grade(_) => LaneId::Judge,
            Self::Mine(_) => LaneId::Mine,
        }
    }
    pub(crate) fn endpoint(&self) -> Endpoint {
        match self {
            Self::Answer(_) => Endpoint::Answer,
            Self::Grade(_) => Endpoint::Grade,
            Self::Mine(_) => Endpoint::Mine,
        }
    }
    pub(crate) fn prepare(
        &self,
        protocol: &Protocol,
        payload: &Value,
        deadline: EffectDeadline,
        meta: RequestMeta,
    ) -> Result<impl Future<Output = Result<HostedResponse>> + Send + 'static + use<>> {
        protocol.prepare_submission(self.lane(), payload, deadline, meta)
    }
}
const HALT_MIDDLEWARE_ERROR: &str = "endpoint temporarily halted — API hardening in progress";
pub(crate) const BOUND_JOB_EXPIRY_CONFLICT: &str = "bound_job_expiry_conflict";

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
    BoundJobExpiryConflict,
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
            Self::BoundJobExpiryConflict => BOUND_JOB_EXPIRY_CONFLICT,
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

/// Shared transport policy for hosted and explicitly unauthenticated onboarding.
/// Callers must still validate and pin the origin and endpoint before use.
pub(crate) fn private_http_client(timeout: Duration, connect_timeout: Duration) -> Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .user_agent(concat!("agmi/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| anyhow::anyhow!("HTTP client initialization failed"))
}

// Never Debug or serialize this into public diagnostics: registration contains a key.
pub(crate) struct RawResponse {
    pub status: u16,
    pub retry_after_seconds: Option<u64>,
    pub retry_after_invalid: bool,
    pub bytes: Vec<u8>,
}

/// Consume a complete bounded body without interpreting it. Registration persists
/// these bytes privately before JSON parsing; interrupted bodies establish nothing.
pub(crate) async fn complete_raw_response(request: reqwest::RequestBuilder) -> Result<RawResponse> {
    let mut response = request
        .send()
        .await
        .map_err(|error| anyhow::Error::new(request_failure(&error)))?;
    let status = response.status().as_u16();
    let mut retry_after_seconds = None;
    let mut retry_after_invalid = false;
    for value in response.headers().get_all(RETRY_AFTER) {
        if let Some(delay) = value.to_str().ok().and_then(parse_retry_after) {
            retry_after_seconds = max_delay(retry_after_seconds, Some(delay));
        } else {
            retry_after_invalid = true;
        }
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ReadFailure::ResponseTooLarge.into());
    }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if chunk.len() <= MAX_RESPONSE_BYTES - bytes.len() => {
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Ok(Some(_)) => return Err(ReadFailure::ResponseTooLarge.into()),
            Err(error) => {
                return Err(if error.is_timeout() {
                    ReadFailure::Timeout
                } else {
                    ReadFailure::BodyInterrupted
                }
                .into());
            }
        }
    }
    Ok(RawResponse {
        status,
        retry_after_seconds,
        retry_after_invalid,
        bytes,
    })
}

// Deliberately no Debug: authentication and queued-job identifiers must not enter logs.
pub struct Protocol {
    client: Client,
    credential_reference: String,
    credential_instance: u64,
    origin: Url,
    api: ApiEndpoints,
    chain: String,
    address: String,
    key: Option<HeaderValue>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiningEvidence {
    pub ok: bool,
    pub attested: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticEvidence {
    pub stage: ResponseSource,
    pub route: LaneId,
    pub status: Option<u16>,
    pub reason: String,
    pub retry_after_seconds: Option<u64>,
    pub shape: String,
    /// Diagnostic vocabulary only; it never grants retry or recovery authority.
    #[serde(default)]
    pub error_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mining: Option<MiningEvidence>,
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
#[derive(Debug)]
pub(crate) struct CredentialFormatError;

impl CredentialFormatError {
    pub(crate) const MESSAGE: &str = "Hosted API key format is invalid. Paste only pk_ followed by letters, digits, '-' or '_', without quotes, spaces, extra lines or terminal control characters.";
}

impl std::fmt::Display for CredentialFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::MESSAGE)
    }
}

impl std::error::Error for CredentialFormatError {}

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

    /// Reloading an unchanged credential retains its opaque authority instance
    /// and reuses the existing HTTP client / TLS root store.
    pub fn reload(config: &Config, previous: &Self) -> Result<Self> {
        config.validate()?;
        let key = if config.network.credential_file.as_os_str().is_empty() {
            None
        } else {
            Some(read_credential(&config.network.credential_file)?)
        };
        let mut protocol = Self::with_key_and_client(config, key, Some(previous.client.clone()))?;
        if protocol.key == previous.key {
            protocol.credential_instance = previous.credential_instance;
        }
        Ok(protocol)
    }

    pub fn credential_instance(&self) -> u64 {
        self.credential_instance
    }

    fn with_key(config: &Config, key: Option<HeaderValue>) -> Result<Self> {
        Self::with_key_and_client(config, key, None)
    }

    fn with_key_and_client(
        config: &Config,
        key: Option<HeaderValue>,
        existing_client: Option<Client>,
    ) -> Result<Self> {
        static NEXT_CREDENTIAL_INSTANCE: AtomicU64 = AtomicU64::new(1);
        // No client total/connect caps: the owning request bounds all phases.
        let client = match existing_client {
            Some(client) => client,
            None => Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .user_agent(concat!("agmi/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|_| anyhow::anyhow!("HTTP client initialization failed"))?,
        };
        Ok(Self {
            client,
            credential_reference: config
                .network
                .credential_file
                .to_string_lossy()
                .into_owned(),
            credential_instance: NEXT_CREDENTIAL_INSTANCE.fetch_add(1, Ordering::Relaxed),
            origin: config.network.origin()?,
            api: config.network.api.clone(),
            chain: config.network.chain.clone(),
            address: config.network.address.clone(),
            key,
        })
    }
    pub async fn get(
        &self,
        endpoint: Endpoint,
        parameter: Option<&str>,
        deadline: ReadDeadline,
        meta: RequestMeta,
    ) -> Result<HostedResponse> {
        ensure!(
            !endpoint.is_effect(),
            "effect endpoint is not a read permission"
        );
        if matches!(
            endpoint,
            Endpoint::AddressAssignments | Endpoint::ExplorerAddress | Endpoint::Established
        ) {
            ensure!(
                !self.address.is_empty() && parameter == Some(self.address.as_str()),
                "read endpoint belongs to a different account"
            );
        }
        self.request_query(endpoint, parameter, None, None, deadline.0, meta)?
            .await
    }
    /// Pagination is a typed read permission, independent of configured paths.
    /// moving views, not snapshots; aggregation and coverage belong to the owner.
    pub async fn assignment_page(
        &self,
        offset: u64,
        limit: u64,
        deadline: ReadDeadline,
        meta: RequestMeta,
    ) -> Result<HostedResponse> {
        ensure!((1..=100).contains(&limit), "invalid inventory page bounds");
        self.request_query(
            Endpoint::Assignments,
            None,
            None,
            Some((offset, limit)),
            deadline.0,
            meta,
        )?
        .await
    }
    /// Validate synchronously before the caller journals a possible network effect.
    fn prepare_submission(
        &self,
        kind: LaneId,
        payload: &Value,
        deadline: EffectDeadline,
        meta: RequestMeta,
    ) -> Result<impl Future<Output = Result<HostedResponse>> + Send + 'static + use<>> {
        ensure!(
            self.key.is_some() && !self.address.is_empty(),
            "submission requires configured identity"
        );
        validate_payload(kind, payload)?;
        ensure!(
            meta.owner == Some(kind),
            "effect request owner does not match its route"
        );
        let endpoint = match kind {
            LaneId::Answer => Endpoint::Answer,
            LaneId::Judge => Endpoint::Grade,
            LaneId::Mine => Endpoint::Mine,
        };
        let body = if kind == LaneId::Mine {
            None
        } else {
            Some(payload)
        };
        self.request_query(endpoint, None, body, None, deadline.0, meta)
    }
    fn request_query(
        &self,
        endpoint: Endpoint,
        parameter: Option<&str>,
        payload: Option<&Value>,
        page: Option<(u64, u64)>,
        deadline: Duration,
        meta: RequestMeta,
    ) -> Result<impl Future<Output = Result<HostedResponse>> + Send + 'static + use<>> {
        let mut url = self
            .api
            .url(&self.origin, &self.chain, endpoint, parameter)?;
        if let Some((offset, limit)) = page {
            url.query_pairs_mut()
                .append_pair("offset", &offset.to_string())
                .append_pair("limit", &limit.to_string());
        }
        let context = RequestContext::capture(self, endpoint, parameter, meta);
        // The complete request timeout also bounds connect and effectful GET mine.
        let mut request = self
            .client
            .request(endpoint.method(), url)
            .timeout(deadline);
        if endpoint.authenticated() {
            let key = self
                .key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("hosted read requires a credential file"))?;
            request = request.header("X-Api-Key", key);
        }
        if let Some(payload) = payload {
            request = request.json(payload);
        }
        let request = request
            .build()
            .map_err(|_| anyhow::anyhow!("invalid hosted request"))?;
        Ok(Self::complete_request(
            self.client.clone(),
            request,
            self.key.clone(),
            context,
        ))
    }

    async fn complete_request(
        client: Client,
        request: reqwest::Request,
        key: Option<HeaderValue>,
        context: RequestContext,
    ) -> Result<HostedResponse> {
        // Never propagate reqwest errors: they can contain a bearer job URL.
        let mut response = client
            .execute(request)
            .await
            .map_err(|error| anyhow::Error::new(request_failure(&error)))?;
        let status = response.status().as_u16();
        let observed_at = context.monotonic_observed_at();
        let header_delay = response
            .headers()
            .get_all(RETRY_AFTER)
            .iter()
            .filter_map(|value| value.to_str().ok().and_then(parse_retry_after))
            .max();
        // Retain status/backoff even when an upstream error page is empty, broken,
        // oversized or interrupted. A null body cannot establish a write outcome.
        let assembled = |response| {
            let completed_at = context.monotonic_completed_at();
            HostedResponse {
                context: context.clone(),
                response,
                observed_at,
                completed_at,
            }
        };
        let unavailable = |failure| {
            assembled(Response {
                status,
                body: Value::Null,
                retry_after_seconds: header_delay,
                read_failure: Some(failure),
            })
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
        let credential = key
            .as_ref()
            .map(HeaderValue::to_str)
            .transpose()
            .map_err(|_| anyhow::anyhow!("invalid internal credential encoding"))?;
        let (body, body_delay) = match decode_hosted_body(
            &bytes,
            context.endpoint,
            context.meta.owner,
            status,
            credential,
        ) {
            Ok(decoded) => decoded,
            Err(failure) => return Ok(unavailable(failure)),
        };
        Ok(assembled(body.into_response(
            status,
            max_delay(header_delay, body_delay),
        )))
    }
}

#[derive(Debug, PartialEq)]
enum DecodedBody {
    Value(Value),
    Discarded(ReadFailure),
}

impl DecodedBody {
    fn into_response(self, status: u16, retry_after_seconds: Option<u64>) -> Response {
        let (body, read_failure) = match self {
            Self::Value(body) => (body, None),
            Self::Discarded(reason) => (Value::Null, Some(reason)),
        };
        Response {
            status,
            body,
            retry_after_seconds,
            read_failure,
        }
    }
}

fn decode_hosted_body(
    bytes: &[u8],
    endpoint: Endpoint,
    owner: Option<LaneId>,
    status: u16,
    credential: Option<&str>,
) -> Result<(DecodedBody, Option<u64>), ReadFailure> {
    let mut json = serde_json::Deserializer::from_slice(bytes);
    let bound_job_expiry = endpoint == Endpoint::Job
        && status == 408
        && matches!(owner, Some(LaneId::Answer | LaneId::Judge));
    let decoder = HostedBodyDecoder {
        credential,
        bound_job_expiry,
    };
    let decoded = de::DeserializeSeed::deserialize(decoder, &mut json)
        .map_err(|_| ReadFailure::InvalidJson)?;
    json.end().map_err(|_| ReadFailure::InvalidJson)?;
    if decoded.credential_echo {
        return Err(ReadFailure::CredentialEchoRedacted);
    }
    let body = if decoded.expiry.disputed() {
        DecodedBody::Discarded(ReadFailure::BoundJobExpiryConflict)
    } else if decoded.duplicate_key {
        // Duplicate delay hints may supply a maximum, but never outcome authority.
        DecodedBody::Discarded(ReadFailure::InvalidJson)
    } else {
        DecodedBody::Value(decoded.body)
    };
    // Top-level retry minima are independent of outcome authority.
    Ok((body, decoded.retry_after_seconds))
}

struct HostedBody {
    body: Value,
    duplicate_key: bool,
    expiry: ExpiryEvidence,
    credential_echo: bool,
    retry_after_seconds: Option<u64>,
}

impl HostedBody {
    fn plain(body: Value) -> Self {
        Self {
            body,
            duplicate_key: false,
            expiry: ExpiryEvidence::default(),
            credential_echo: false,
            retry_after_seconds: None,
        }
    }
}

#[derive(Clone, Copy)]
struct HostedBodyDecoder<'a> {
    credential: Option<&'a str>,
    bound_job_expiry: bool,
}

impl HostedBodyDecoder<'_> {
    fn echoes(self, value: &str) -> bool {
        self.credential.is_some_and(|secret| value.contains(secret))
    }
}

impl<'de> de::DeserializeSeed<'de> for HostedBodyDecoder<'_> {
    type Value = HostedBody;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<HostedBody, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> de::Visitor<'de> for HostedBodyDecoder<'_> {
    type Value = HostedBody;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<HostedBody, M::Error> {
        let mut body = serde_json::Map::new();
        let mut duplicate_key = false;
        let mut expiry = ExpiryEvidence::default();
        let mut credential_echo = false;
        let mut retry_after_seconds = None;
        while let Some(key) = map.next_key::<String>()? {
            let member = map.next_value_seed(self)?;
            // Check decoded occurrences before overwriting or normalizing them.
            credential_echo |= self.echoes(&key) || member.credential_echo;
            if self.bound_job_expiry {
                expiry.observe(&key, &member.body, member.expiry);
            }
            if key == "retry_after_seconds" {
                retry_after_seconds = max_delay(retry_after_seconds, member.body.as_u64());
            }
            duplicate_key |= member.duplicate_key | body.insert(key, member.body).is_some();
        }
        Ok(HostedBody {
            body: Value::Object(body),
            duplicate_key,
            expiry,
            credential_echo,
            retry_after_seconds,
        })
    }

    fn visit_seq<S: de::SeqAccess<'de>>(self, mut seq: S) -> Result<HostedBody, S::Error> {
        let mut body = Vec::new();
        let mut duplicate_key = false;
        let mut credential_echo = false;
        while let Some(member) = seq.next_element_seed(self)? {
            duplicate_key |= member.duplicate_key;
            credential_echo |= member.credential_echo;
            body.push(member.body);
        }
        Ok(HostedBody {
            duplicate_key,
            credential_echo,
            ..HostedBody::plain(Value::Array(body))
        })
    }

    fn visit_unit<E: de::Error>(self) -> Result<HostedBody, E> {
        Ok(HostedBody::plain(Value::Null))
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<HostedBody, E> {
        Ok(HostedBody::plain(value.into()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<HostedBody, E> {
        Ok(HostedBody::plain(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<HostedBody, E> {
        Ok(HostedBody::plain(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<HostedBody, E> {
        Ok(HostedBody::plain(value.into()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<HostedBody, E> {
        Ok(HostedBody {
            credential_echo: self.echoes(value),
            ..HostedBody::plain(value.into())
        })
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<HostedBody, E> {
        Ok(HostedBody {
            credential_echo: self.echoes(&value),
            ..HostedBody::plain(value.into())
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
    let parsed = parse_credential(&bytes);
    crate::fs_util::wipe_bytes(&mut bytes);
    Ok(parsed?)
}

fn parse_credential(bytes: &[u8]) -> std::result::Result<HeaderValue, CredentialFormatError> {
    if bytes.len() > 4096 {
        return Err(CredentialFormatError);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CredentialFormatError)?
        .trim_end_matches(['\r', '\n']);
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Credential {
        api_key: String,
    }
    let parsed;
    let token = if text.trim_start().starts_with('{') {
        parsed = serde_json::from_str::<Credential>(text).map_err(|_| CredentialFormatError)?;
        parsed.api_key.as_str()
    } else {
        text
    };
    if !token.starts_with("pk_") || token.len() < 4 || !safe_segment(token, 4096) {
        return Err(CredentialFormatError);
    }
    let mut key = HeaderValue::from_str(token).map_err(|_| CredentialFormatError)?;
    key.set_sensitive(true);
    Ok(key)
}

pub(crate) const GRADE_REASONING_LENGTH: std::ops::RangeInclusive<usize> = 10..=500;

pub(crate) fn grade_reasoning_length(reasoning: &str) -> usize {
    reasoning
        .trim()
        .chars()
        .take(GRADE_REASONING_LENGTH.end() + 1)
        .count()
}

pub(crate) fn valid_grade_reasoning(reasoning: &str) -> bool {
    GRADE_REASONING_LENGTH.contains(&grade_reasoning_length(reasoning))
}

pub(crate) fn has_required_words(answer: &str, words: &[String]) -> bool {
    let lower = answer.to_lowercase();
    words
        .iter()
        .all(|word| lower.contains(&word.to_lowercase()))
}

fn validate_payload(kind: LaneId, payload: &Value) -> Result<()> {
    let object = payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("submission payload must be an object"))?;
    match kind {
        LaneId::Answer => {
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
        LaneId::Judge => {
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
        LaneId::Mine => ensure!(object.is_empty(), "mine takes no payload fields"),
    }
    Ok(())
}
fn parse_retry_after(value: &str) -> Option<u64> {
    let value = value.trim();
    if !value.is_empty()
        && let Some(seconds) = value.bytes().try_fold(0_u64, |seconds, byte| {
            byte.is_ascii_digit().then(|| {
                seconds
                    .saturating_mul(10)
                    .saturating_add(u64::from(byte - b'0'))
            })
        })
    {
        return Some(seconds);
    }
    httpdate::parse_http_date(value).ok().map(|time| {
        let delay = time.duration_since(SystemTime::now()).unwrap_or_default();
        delay
            .as_secs()
            .saturating_add(u64::from(delay.subsec_nanos() != 0))
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

fn processing_evidence(body: &Value) -> bool {
    body.get("ok") == Some(&Value::Bool(true))
        || body.get("success") == Some(&Value::Bool(true))
        || body.get("next_nonce").is_some()
        || body.get("attested").is_some()
        || body.get("processed").is_some_and(|value| value != false)
        || matches!(
            body.get("status").and_then(Value::as_str),
            Some(
                "accepted"
                    | "queued"
                    | "running"
                    | "processing"
                    | "processed"
                    | "done"
                    | "included"
                    | "confirmed"
                    | "final"
                    | "completed"
            )
        )
}

#[derive(Clone, Copy, Default)]
struct ExpiryEvidence {
    code: bool,
    expired_state: bool,
    other_code: bool,
    opposition: bool,
}

impl ExpiryEvidence {
    fn observe(&mut self, key: &str, value: &Value, nested: Self) {
        match key {
            "error" if value.is_object() => {
                self.code |= nested.code;
                self.expired_state |= nested.expired_state;
                self.other_code |= nested.other_code;
                self.opposition |= nested.opposition;
            }
            "code" | "error" => {
                self.code |= value == "job_expired";
                self.other_code |= value != "job_expired";
                self.opposition |= value == "duplicate_in_flight";
            }
            "job_id" | "id" | "challenge_txid" | "txid" | "next_nonce" | "attested" => {
                self.opposition = true;
            }
            "state" => {
                self.expired_state |= value == "expired";
                self.opposition |= value != "expired";
            }
            "status" => self.opposition |= value != "expired",
            "queued" | "accepted" | "ok" | "success" | "processed" => {
                self.opposition |= value != false;
            }
            _ => {}
        }
    }

    fn from_body(body: &Value) -> Self {
        let mut evidence = Self::default();
        if let Some(fields) = body.as_object() {
            for (key, value) in fields {
                let nested = if key == "error" && value.is_object() {
                    Self::from_body(value)
                } else {
                    Self::default()
                };
                evidence.observe(key, value, nested);
            }
        }
        evidence
    }

    fn disputed(self) -> bool {
        (self.code || self.expired_state) && (self.opposition || (self.code && self.other_code))
    }
}

fn bound_expiry(body: &Value) -> Option<Outcome> {
    let evidence = ExpiryEvidence::from_body(body);
    if !evidence.code && !evidence.expired_state {
        return None;
    }
    if evidence.disputed() {
        return Some(unknown(BOUND_JOB_EXPIRY_CONFLICT));
    }
    // Missing facts are not contradictions, and a noncanonical shape does not
    // establish that the engine never processed the operation.
    let flat = body.get("error").is_none_or(|value| value == "job_expired");
    let state_expired = body.get("state").is_some_and(|value| value == "expired");
    Some(if state_expired && evidence.code && flat {
        Outcome::Expired
    } else {
        unknown("bound_job_expiry_incomplete")
    })
}

pub fn classify_source(kind: LaneId, response: &Response, source: ResponseSource) -> Outcome {
    let body = &response.body;
    let bound_job_expiry =
        kind != LaneId::Mine && source == ResponseSource::BoundJob && response.status == 408;
    if bound_job_expiry && response.read_failure == Some(ReadFailure::BoundJobExpiryConflict) {
        return unknown(BOUND_JOB_EXPIRY_CONFLICT);
    }
    if response.read_failure.is_some() || !body.is_object() {
        return unknown("response_shape_unknown");
    }
    if bound_job_expiry && let Some(outcome) = bound_expiry(body) {
        return outcome;
    }
    let explicit_code = body.get("code").and_then(Value::as_str);
    let explicit_error = body.get("error").and_then(Value::as_str);
    let code = explicit_code.or(explicit_error);
    let conflicting_codes = explicit_code
        .zip(explicit_error)
        .is_some_and(|(code, error)| code != error);
    let refused_submit = source == ResponseSource::Submit
        && (response.status == 429
            || (kind != LaneId::Mine
                && response.status == 503
                && matches!(code, Some("epoch_closing" | HALT_MIDDLEWARE_ERROR))));
    let state = body.get("state").and_then(Value::as_str);
    let has_tx = ["id", "challenge_txid", "txid"]
        .iter()
        .any(|field| body.get(field).is_some());
    let has_job = body.get("job_id").is_some();
    let accepting = ["queued", "accepted"]
        .iter()
        .any(|field| body.get(field).is_some_and(|value| value != false))
        || matches!(state, Some("queued" | "running" | "processing"));
    if conflicting_codes {
        return unknown("conflicting_error_codes");
    }
    if body.get("state").is_some_and(|state| !state.is_string()) {
        return unknown(if refused_submit {
            "contradictory_acceptance"
        } else {
            "job_state_unknown"
        });
    }
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
    if refused_submit {
        // Every 429 rejects before enqueue/write, including hosted mining.
        // The identified halt middleware covers answer/judge routes only;
        // diagnostic halt flags alone do not identify that middleware.
        if has_tx || state.is_some() || processing_evidence(body) {
            return unknown("contradictory_acceptance");
        }
        return Outcome::Retry {
            after_seconds: max_delay(
                response.retry_after_seconds,
                body.get("retry_after_seconds").and_then(Value::as_u64),
            )
            .unwrap_or(if response.status == 429 { 5 } else { 30 })
            .max(1),
        };
    }
    if kind != LaneId::Mine && !has_tx {
        let rejected = match kind {
            LaneId::Answer => {
                response.status == 409
                    && matches!(code, Some("already_answered" | "duplicate_answer"))
            }
            LaneId::Judge => {
                matches!(response.status, 400 | 403 | 409)
                    && matches!(code, Some("off_panel" | "duplicate_grade"))
            }
            LaneId::Mine => false,
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
                (LaneId::Answer, Some("stale_seed")) => Some("stale_seed"),
                (LaneId::Answer, Some("challenge answer length out of bounds")) => {
                    Some("answer_length")
                }
                (LaneId::Judge, Some("duplicate sealed grade")) => Some("duplicate_sealed_grade"),
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
    if kind == LaneId::Mine {
        return if !has_tx
            && body.get("ok") == Some(&Value::Bool(true))
            && body.get("attested").and_then(Value::as_u64).is_some()
        {
            Outcome::Completed
        } else {
            unknown("mine_attestation_count_missing")
        };
    }
    let field = if kind == LaneId::Answer {
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

/// Sanitized diagnostics, not retry authority or a promise of recovery.
pub(crate) fn failure_category(response: &Response) -> Option<&'static str> {
    if let Some(failure) = response.read_failure {
        return Some(failure.as_str());
    }
    match response.status {
        401 => return Some("authentication_rejected"),
        403 => return Some("permission_denied"),
        _ => {}
    }
    let code = error_code(&response.body);
    if response.body.get("halted").and_then(Value::as_bool) == Some(true)
        || matches!(
            response.body.get("status").and_then(Value::as_str),
            Some("halted" | "paused")
        )
        || code.is_some_and(|value| {
            value == "halted"
                || value.starts_with("endpoint temporarily halted — API hardening in progress")
        })
    {
        return Some("endpoint_halted");
    }
    match response.status {
        300..=399 => Some("redirect_refused"),
        404 => Some("not_found"),
        408 => Some("request_timeout"),
        410 => Some("gone"),
        429 => Some("rate_limited"),
        400..=499 => Some("request_rejected"),
        502 => Some("bad_gateway"),
        503 => Some("service_unavailable"),
        504 => Some("gateway_timeout"),
        500..=599 => Some("upstream_error"),
        _ if failed(&response.body) => Some("upstream_rejected"),
        _ => None,
    }
}

fn response_error_category(kind: LaneId, response: &Response) -> Option<&'static str> {
    let code = error_code(&response.body)?;
    match (kind, code) {
        (LaneId::Answer, "stale_seed") => Some("stale_seed"),
        (LaneId::Answer, "challenge answer length out of bounds") => Some("answer_length"),
        (LaneId::Judge, "duplicate sealed grade") => Some("duplicate_sealed_grade"),
        (LaneId::Judge, "grade queue is full") => Some("grade_queue_full"),
        (_, "accept queue full") => Some("accept_queue_full"),
        (_, "epoch_closing") => Some("epoch_closing"),
        (_, "job_expired") => Some("job_expired"),
        (_, HALT_MIDDLEWARE_ERROR) if kind != LaneId::Mine && response.status == 503 => {
            Some("halt_middleware")
        }
        (LaneId::Answer, value) => {
            let limit = value.strip_prefix("answer surface is at its global ceiling (")?;
            let limit = limit.strip_suffix(" — retry shortly").unwrap_or(limit);
            let number = limit.strip_suffix("/min)")?;
            (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
                .then_some("answer_global_ceiling")
        }
        _ => None,
    }
}

/// Bounded labels and validated facts only: never copy arbitrary text or identifiers.
pub fn response_evidence(
    kind: LaneId,
    source: ResponseSource,
    response: Option<&Response>,
) -> DiagnosticEvidence {
    let (reason, shape, mining) = match response {
        None => ("transport_unknown".to_owned(), "unavailable", None),
        Some(response) => {
            let outcome = classify_source(kind, response, source);
            let mining = if kind == LaneId::Mine && matches!(&outcome, Outcome::Completed) {
                response
                    .body
                    .get("attested")
                    .and_then(Value::as_u64)
                    .map(|attested| MiningEvidence { ok: true, attested })
            } else {
                None
            };
            let reason = match outcome {
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
                mining,
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
            .and_then(|value| {
                response_error_category(kind, value).or_else(|| failure_category(value))
            })
            .map(str::to_owned),
        mining,
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
        .filter(|epoch| *epoch <= i64::MAX as u64)
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
        .filter(|epoch| *epoch <= i64::MAX as u64)
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
        .filter(|epoch| *epoch <= i64::MAX as u64)
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
                    .filter(|epoch| *epoch <= i64::MAX as u64)
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
mod tests;
