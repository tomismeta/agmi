use super::{Outcome, Protocol, Response, ResponseSource, classify_source};
use crate::{capability::LaneId, endpoints::Endpoint};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
pub struct ReadDeadline(pub(super) Duration);
#[derive(Clone, Copy)]
pub struct EffectDeadline(pub(super) Duration);
fn duration(seconds: u64) -> Result<Duration> {
    let value = Duration::from_secs(seconds);
    ensure!(
        seconds > 0
            && std::time::Instant::now().checked_add(value).is_some()
            && i64::try_from(seconds).is_ok(),
        "invalid HTTP deadline"
    );
    Ok(value)
}
impl ReadDeadline {
    pub fn seconds(seconds: u64) -> Result<Self> {
        Ok(Self(duration(seconds)?))
    }
}
impl EffectDeadline {
    pub fn seconds(seconds: u64) -> Result<Self> {
        Ok(Self(duration(seconds)?))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RequestMeta {
    pub request_id: String,
    pub database_id: String,
    pub authority_epoch: u64,
    pub owner: Option<LaneId>,
    pub operation_id: Option<String>,
    pub read_key: Option<String>,
    pub binding_revision: Option<u64>,
    pub dispatch_sequence: Option<u64>,
}

// Private request/resource identifiers: deliberately not Debug or Deserialize.
#[derive(Clone, Serialize)]
#[non_exhaustive]
pub struct RequestContext {
    pub meta: RequestMeta,
    pub origin: String,
    pub chain: String,
    pub address: String,
    pub credential_reference: String,
    pub credential_instance: u64,
    pub endpoint: Endpoint,
    pub method: String,
    pub resource: Option<String>,
    pub authenticated: bool,
    pub started_at: i64,
}
impl RequestContext {
    pub(super) fn capture(
        protocol: &Protocol,
        endpoint: Endpoint,
        parameter: Option<&str>,
        meta: RequestMeta,
    ) -> Self {
        Self {
            meta,
            origin: protocol.origin.origin().ascii_serialization(),
            chain: protocol.chain.clone(),
            address: protocol.address.clone(),
            credential_reference: protocol.credential_reference.clone(),
            credential_instance: protocol.credential_instance,
            endpoint,
            method: endpoint.method().as_str().to_owned(),
            resource: parameter.map(str::to_owned),
            // Job capabilities and bound receipts are account recovery, even
            // where their route does not carry an X-Api-Key header.
            authenticated: endpoint.authenticated()
                || matches!(endpoint, Endpoint::Job | Endpoint::Receipt),
            started_at: observed_now(),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct HostedResponse {
    pub context: RequestContext,
    pub response: Response,
    pub observed_at: i64,
    pub completed_at: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum RestrictionScope {
    AccountAuthenticated,
    Resource {
        endpoint: Endpoint,
        resource: String,
    },
    AnswerJudgeEffects,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestrictionBasis {
    ServerRetryAfter,
    LocalUnscoped429Cooldown,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum RestrictionProvenance {
    Request,
    QueuedSubmission,
}

#[derive(Clone, Serialize)]
pub struct RestrictionEvidence {
    context: RequestContext,
    scope: RestrictionScope,
    basis: RestrictionBasis,
    observed_at: i64,
    not_before: i64,
    server_minimum_seconds: Option<u64>,
    policy: Option<String>,
    provenance: RestrictionProvenance,
}

impl RestrictionEvidence {
    pub fn context(&self) -> &RequestContext {
        &self.context
    }
    pub fn scope(&self) -> &RestrictionScope {
        &self.scope
    }
    pub fn basis(&self) -> RestrictionBasis {
        self.basis
    }
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
    pub fn not_before(&self) -> i64 {
        self.not_before
    }
    pub fn server_minimum_seconds(&self) -> Option<u64> {
        self.server_minimum_seconds
    }
    pub fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }

    pub(crate) fn resource_matches_context(&self) -> bool {
        let RestrictionScope::Resource { endpoint, resource } = &self.scope else {
            return false;
        };
        match self.provenance {
            RestrictionProvenance::Request => {
                *endpoint == self.context.endpoint
                    && self.context.resource.as_deref() == Some(resource.as_str())
            }
            // The transport alone captures this target from a validated queued
            // response. Callers cannot retarget the scope or dispatch context.
            RestrictionProvenance::QueuedSubmission => {
                *endpoint == Endpoint::Job
                    && matches!(
                        (self.context.meta.owner, self.context.endpoint),
                        (Some(LaneId::Answer), Endpoint::Answer)
                            | (Some(LaneId::Judge), Endpoint::Grade)
                            | (Some(LaneId::Mine), Endpoint::Mine)
                    )
                    && self
                        .context
                        .meta
                        .operation_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    && self
                        .context
                        .meta
                        .dispatch_sequence
                        .is_some_and(|value| value > 0)
            }
        }
    }
}

impl HostedResponse {
    /// Only assembled bodies establish the queued-response exception. Invalid
    /// or interrupted bodies retain headers but never invent narrower scope.
    pub fn restrictions(&self) -> Vec<RestrictionEvidence> {
        let response = &self.response;
        let (delay, basis, policy) = match response.retry_after_seconds {
            Some(delay) => (delay, RestrictionBasis::ServerRetryAfter, None),
            None if response.status == 429 && self.context.authenticated => (
                30,
                RestrictionBasis::LocalUnscoped429Cooldown,
                Some("agmi.local_bare_429_cooldown.v1".to_owned()),
            ),
            None => return Vec::new(),
        };
        // No source-backed origin-wide minima for anonymous public routes.
        if !self.context.authenticated {
            return Vec::new();
        }
        let queued_resource = self.queued_resource();
        let provenance = if queued_resource.is_some() && self.context.endpoint.is_effect() {
            RestrictionProvenance::QueuedSubmission
        } else {
            RestrictionProvenance::Request
        };
        let scope = queued_resource.map_or_else(
            || {
                let kind = self.context.meta.owner;
                if response.status == 503
                    && matches!(self.context.endpoint, Endpoint::Answer | Endpoint::Grade)
                    && matches!(kind, Some(LaneId::Answer | LaneId::Judge))
                    && super::error_code(&response.body) == Some(super::HALT_MIDDLEWARE_ERROR)
                    && matches!(
                        classify_source(kind.unwrap(), response, ResponseSource::Submit),
                        Outcome::Retry { .. }
                    )
                {
                    RestrictionScope::AnswerJudgeEffects
                } else {
                    RestrictionScope::AccountAuthenticated
                }
            },
            |resource| RestrictionScope::Resource {
                endpoint: Endpoint::Job,
                resource,
            },
        );
        vec![RestrictionEvidence {
            context: self.context.clone(),
            scope,
            basis,
            observed_at: self.observed_at,
            not_before: self
                .observed_at
                .saturating_add(i64::try_from(delay).unwrap_or(i64::MAX)),
            server_minimum_seconds: response.retry_after_seconds,
            policy,
            provenance,
        }]
    }

    fn queued_resource(&self) -> Option<String> {
        let response = &self.response;
        if response.status != 202 || response.read_failure.is_some() || !response.body.is_object() {
            return None;
        }
        if response.body.get("state").is_some_and(|state| {
            !matches!(state.as_str(), Some("queued" | "running" | "processing"))
        }) {
            return None;
        }
        let source = if self.context.endpoint == Endpoint::Job {
            ResponseSource::BoundJob
        } else if self.context.endpoint.is_effect() {
            ResponseSource::Submit
        } else {
            return None;
        };
        let kind = self.context.meta.owner?;
        match classify_source(kind, response, source) {
            Outcome::Queued { job_id } => {
                if source == ResponseSource::BoundJob
                    && self.context.resource.as_deref() != Some(&job_id)
                {
                    None
                } else {
                    Some(job_id)
                }
            }
            // A bound queued response may omit its redundant capability, but
            // must explicitly establish a pending state without failure/tx hints.
            Outcome::Unknown { .. } if source == ResponseSource::BoundJob => {
                let body = &response.body;
                let pending = matches!(
                    body.get("state").and_then(serde_json::Value::as_str),
                    Some("queued" | "running" | "processing")
                );
                if pending
                    && !super::failed(body)
                    && ["id", "txid", "challenge_txid", "job_id", "code", "error"]
                        .iter()
                        .all(|key| body.get(key).is_none())
                {
                    self.context.resource.clone()
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

pub(super) fn observed_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}

// Backoff origins round up so a whole-second deadline never retries early.
// Observation timestamps round down; they must not appear to come from the future.
pub(super) fn retry_observed_now() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_secs())
        .unwrap_or(i64::MAX)
        .saturating_add(i64::from(elapsed.subsec_nanos() != 0))
}

#[cfg(test)]
async fn receive_headers(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;
    let mut request = [0; 4096];
    let mut used: usize = 0;
    loop {
        let received = stream.read(&mut request[used..]).await.unwrap();
        assert!(received > 0, "fixture request closed before its headers");
        let start = used.saturating_sub(3);
        used += received;
        if request[start..used]
            .windows(4)
            .any(|bytes| bytes == b"\r\n\r\n")
        {
            return;
        }
        assert!(
            used < request.len(),
            "fixture request headers exceeded buffer"
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, protocol::ReadFailure};
    use serde_json::{Value, json};

    fn meta() -> RequestMeta {
        RequestMeta {
            request_id: "captured-request".into(),
            database_id: "journal".into(),
            authority_epoch: 7,
            owner: Some(LaneId::Answer),
            operation_id: Some("operation".into()),
            read_key: Some("job:1".into()),
            binding_revision: Some(1),
            dispatch_sequence: None,
        }
    }
    fn observed(
        endpoint: Endpoint,
        body: Value,
        status: u16,
        delay: Option<u64>,
    ) -> HostedResponse {
        let protocol = Protocol::new(&Config::default()).unwrap();
        HostedResponse {
            context: RequestContext::capture(&protocol, endpoint, Some("old-job"), meta()),
            response: Response {
                status,
                body,
                retry_after_seconds: delay,
                read_failure: None,
            },
            observed_at: 100,
            completed_at: 120,
        }
    }

    #[test]
    fn bare_429_uses_original_observation_and_versioned_local_basis() {
        let mut response = observed(Endpoint::Job, Value::Null, 429, None);
        response.response.read_failure = Some(ReadFailure::BodyInterrupted);
        let evidence = response.restrictions().pop().unwrap();
        assert_eq!(evidence.not_before, 130);
        assert_eq!(evidence.observed_at, 100);
        assert_eq!(evidence.basis, RestrictionBasis::LocalUnscoped429Cooldown);
        assert_eq!(evidence.server_minimum_seconds, None);
        assert_eq!(
            evidence.policy.as_deref(),
            Some("agmi.local_bare_429_cooldown.v1")
        );
        response.completed_at = 999;
        assert_eq!(response.restrictions()[0].not_before, 130);
        assert!(
            observed(Endpoint::ExplorerTx, Value::Null, 429, None)
                .restrictions()
                .is_empty()
        );
    }

    #[test]
    fn queued_minimum_is_actual_resource_only_after_body_validation() {
        let mut response = observed(
            Endpoint::Job,
            json!({"job_id":"old-job","state":"queued"}),
            202,
            Some(90),
        );
        let evidence = response.restrictions().pop().unwrap();
        assert_eq!(
            evidence.scope,
            RestrictionScope::Resource {
                endpoint: Endpoint::Job,
                resource: "old-job".into()
            }
        );
        assert_eq!(evidence.context.meta.binding_revision, Some(1));
        assert_eq!(evidence.not_before, 190);
        for body in [
            Value::Null,
            json!({"job_id":"replacement-job"}),
            json!({"job_id":"old-job","state":"done"}),
            json!({"job_id":"old-job","txid":"a".repeat(64)}),
            json!({"error":"unavailable","job_id":"old-job"}),
        ] {
            response.response.body = body;
            assert_eq!(
                response.restrictions()[0].scope,
                RestrictionScope::AccountAuthenticated
            );
        }
        response.response.body = json!({"state":"running"});
        assert!(matches!(
            response.restrictions()[0].scope,
            RestrictionScope::Resource { .. }
        ));
        response.response.read_failure = Some(ReadFailure::BodyInterrupted);
        assert_eq!(
            response.restrictions()[0].scope,
            RestrictionScope::AccountAuthenticated
        );
    }

    #[test]
    fn exact_halt_minimum_does_not_expand_to_mine_or_reads() {
        let mut response = observed(
            Endpoint::Answer,
            json!({"error":super::super::HALT_MIDDLEWARE_ERROR}),
            503,
            Some(60),
        );
        assert_eq!(
            response.restrictions()[0].scope,
            RestrictionScope::AnswerJudgeEffects
        );
        response.context.endpoint = Endpoint::Mine;
        response.context.meta.owner = Some(LaneId::Mine);
        assert_eq!(
            response.restrictions()[0].scope,
            RestrictionScope::AccountAuthenticated
        );
    }

    #[tokio::test]
    async fn assembled_body_minimum_suppresses_headerless_429_fallback() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let protocol = Protocol::new(&config).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            receive_headers(&mut stream).await;
            let body = r#"{"retry_after_seconds":7,"error":"limited"}"#;
            stream.write_all(format!("HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.write_all(body.as_bytes()).await.unwrap();
        });
        let result = protocol
            .get(
                Endpoint::Job,
                Some("old-job"),
                ReadDeadline::seconds(2).unwrap(),
                meta(),
            )
            .await
            .unwrap();
        let observed_through = observed_now();
        assert!(result.context.started_at <= observed_through);
        assert!(result.completed_at <= observed_through);
        let restriction = result.restrictions().pop().unwrap();
        assert_eq!(restriction.server_minimum_seconds, Some(7));
        assert_eq!(restriction.basis, RestrictionBasis::ServerRetryAfter);
        assert_eq!(restriction.not_before, result.observed_at + 7);
        assert_eq!(restriction.policy, None);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn independent_owner_deadlines_bound_complete_bodies_including_mine() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let mut protocol = Protocol::new(&config).unwrap();
        protocol.key = Some(reqwest::header::HeaderValue::from_static("pk_fixture"));
        protocol.address = "configured-account".into();
        let server = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    receive_headers(&mut stream).await;
                    stream.write_all(b"HTTP/1.1 202 Accepted\r\nRetry-After: 9\r\nContent-Length: 20\r\nConnection: close\r\n\r\n").await.unwrap();
                    tokio::time::sleep(Duration::from_millis(1300)).await;
                    let _ = stream.write_all(b"{\"job_id\":\"old-job\"}").await;
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });
        let mut mine_meta = meta();
        mine_meta.owner = Some(LaneId::Mine);
        let payload = json!({});
        let mine = protocol
            .prepare_submission(
                LaneId::Mine,
                &payload,
                EffectDeadline::seconds(1).unwrap(),
                mine_meta,
            )
            .unwrap();
        let (short, long, mine) = tokio::join!(
            protocol.get(
                Endpoint::Job,
                Some("old-job"),
                ReadDeadline::seconds(1).unwrap(),
                meta()
            ),
            protocol.get(
                Endpoint::Job,
                Some("old-job"),
                ReadDeadline::seconds(3).unwrap(),
                meta()
            ),
            mine,
        );
        let short = short.unwrap();
        let long = long.unwrap();
        let mine = mine.unwrap();
        assert_eq!(short.response.read_failure, Some(ReadFailure::Timeout));
        assert_eq!(mine.response.read_failure, Some(ReadFailure::Timeout));
        assert_eq!(mine.context.method, "GET");
        assert_eq!(long.response.read_failure, None);
        assert_eq!(short.response.retry_after_seconds, Some(9));
        assert_eq!(
            short.restrictions()[0].scope,
            RestrictionScope::AccountAuthenticated
        );
        assert!(matches!(
            long.restrictions()[0].scope,
            RestrictionScope::Resource { .. }
        ));
        server.await.unwrap();
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::config::Config;

    #[cfg(unix)]
    #[test]
    fn credential_instance_survives_lane_reload_but_not_material_rotation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("credential");
        std::fs::write(&key, "pk_original_fixture").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut config = Config::default();
        config.network.credential_file = key.clone();
        let first = Protocol::new(&config).unwrap();
        config.capabilities.judge.timeouts.read_http_seconds += 1;
        let unchanged = Protocol::reload(&config, &first).unwrap();
        assert_eq!(first.credential_instance(), unchanged.credential_instance());
        std::fs::write(&key, "pk_rotated_fixture").unwrap();
        let rotated = Protocol::reload(&config, &unchanged).unwrap();
        assert_ne!(
            unchanged.credential_instance(),
            rotated.credential_instance()
        );
    }

    #[tokio::test]
    async fn prepared_effect_owns_request_without_polling_network() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let mut protocol = Protocol::new(&config).unwrap();
        protocol.key = Some(reqwest::header::HeaderValue::from_static("pk_fixture"));
        protocol.address = "configured-account".into();
        let meta = RequestMeta {
            request_id: "effect".into(),
            database_id: "journal".into(),
            authority_epoch: 1,
            owner: Some(LaneId::Mine),
            operation_id: Some("mine".into()),
            read_key: None,
            binding_revision: None,
            dispatch_sequence: Some(1),
        };
        let payload = serde_json::json!({});
        let future = protocol
            .prepare_submission(
                LaneId::Mine,
                &payload,
                EffectDeadline::seconds(2).unwrap(),
                meta,
            )
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        drop(payload);
        drop(protocol);
        let task = tokio::spawn(future);
        let (mut stream, _) = listener.accept().await.unwrap();
        receive_headers(&mut stream).await;
        let body = r#"{"ok":true,"attested":0}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.context.endpoint, Endpoint::Mine);
        assert_eq!(response.context.meta.dispatch_sequence, Some(1));
        assert_eq!(
            classify_source(LaneId::Mine, &response.response, ResponseSource::Submit),
            Outcome::Completed
        );
    }
}
