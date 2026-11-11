use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn response(body: Value) -> Response {
    Response {
        status: 200,
        body,
        retry_after_seconds: None,
        read_failure: None,
    }
}
pub(super) fn fixture_with(
    mut config: Config,
) -> (tempfile::TempDir, HostAccess, watch::Sender<bool>) {
    let temp = tempfile::tempdir().unwrap();
    config.state_dir = temp.path().join("state");
    config.network.chain = format!(
        "test{}",
        temp.path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .replace('.', "")
    );
    config.network.address = format!("poa1{}", "1".repeat(32));
    config.network.credential_file = temp.path().join("key");
    std::fs::write(&config.network.credential_file, "pk_test_fixture").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &config.network.credential_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let core = temp.path().join("guidance.txt");
    std::fs::write(
        &core,
        "Evaluate the supplied task against protocol requirements.",
    )
    .unwrap();
    config.capabilities.answer.model.core_guidance_file = Some(core.clone());
    config.capabilities.judge.model.core_guidance_file = Some(core);
    config.capabilities.answer.schedule.jitter_seconds = 0;
    config.capabilities.judge.schedule.jitter_seconds = 0;
    config.capabilities.mine.schedule.jitter_seconds = 0;
    config.identity.jitter_seconds = 0;
    let path = temp.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let config = Config::load(&path).unwrap();
    let protocol = Arc::new(Protocol::new(&config).unwrap());
    let (_writer, mut store) = crate::store::AccountLock::acquire(&config).unwrap();
    store
        .set_paused(false, &AccountAdmissionGuard::acquire(&config).unwrap())
        .unwrap();
    store.runtime_state(&config, false).unwrap();
    let (sender, stop) = watch::channel(false);
    let runtime = HostAccess::new(path, config, protocol, store, stop, true).unwrap();
    (temp, runtime, sender)
}
pub(super) fn fixture() -> (tempfile::TempDir, HostAccess, watch::Sender<bool>) {
    fixture_with(Config::default())
}
fn persist(runtime: &HostAccess) {
    std::fs::write(
        &runtime.config_path,
        toml::to_string(&runtime.config).unwrap(),
    )
    .unwrap();
}
fn no_discovery(runtime: &HostAccess) {
    for kind in LaneId::ALL {
        runtime.store.defer(kind, 3600).unwrap();
    }
}
fn seed_bound(runtime: &mut HostAccess, kind: LaneId, key: &str, job: &str) -> Operation {
    let input = Input {
        solver: request(kind),
        challenge_fingerprint: Some("fixture".into()),
    };
    let op = runtime
        .store
        .seed_operation_for_test(
            kind,
            key,
            "prepared",
            &serde_json::to_value(input).unwrap(),
            runtime.store.control().unwrap(),
            &runtime.config.lane_revision(kind).unwrap(),
        )
        .unwrap();
    let db = rusqlite::Connection::open(runtime.config.state_dir.join("state.sqlite3")).unwrap();
    db.execute(
        "UPDATE operations SET state='unknown',job_id=?1,binding_revision=1,next_at=0 WHERE id=?2",
        rusqlite::params![job, op.id],
    )
    .unwrap();
    runtime.store.operation(op.id).unwrap().unwrap()
}
async fn accept(listener: &tokio::net::TcpListener) -> (tokio::net::TcpStream, String) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(n > 0 && bytes.len() < 8192);
        bytes.extend_from_slice(&buffer[..n]);
    }
    let line = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    (stream, line)
}
async fn reply(mut stream: tokio::net::TcpStream, status: u16, minimum: Option<u64>, body: Value) {
    let body = body.to_string();
    let retry = minimum
        .map(|seconds| format!("Retry-After: {seconds}\r\n"))
        .unwrap_or_default();
    stream.write_all(format!("HTTP/1.1 {status} Fixture\r\n{retry}Content-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
}
async fn collect_until(runtime: &mut HostAccess, predicate: impl Fn(&HostAccess) -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            runtime.collect().await.unwrap();
            if predicate(runtime) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("bounded fixture completion");
}
async fn read_result(runtime: &mut HostAccess, flight: &mut ReadFlight) -> Result<HostedResponse> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(result) = flight.take() {
                break result;
            }
            runtime.wake.notified().await;
        }
    })
    .await
    .unwrap()
}

#[test]
fn identity_classification_requires_valid_matching_evidence() {
    use crate::protocol::ReadFailure;
    use HostedIdentityOutcome::*;
    let mut config = Config::default();
    config.network.address = format!("poa1{}", "1".repeat(32));
    config.network.chain = "expected-chain".into();
    let address = &config.network.address;
    let other = format!("poa1{}2", "1".repeat(31));
    for (status, body, failure, expected) in [
        (200, json!({"address":address}), None, Verified),
        (
            200,
            json!({"address":address,"chain_id":"expected-chain","ok":true}),
            None,
            Verified,
        ),
        (
            401,
            Value::Null,
            Some(ReadFailure::InvalidJson),
            AuthenticationFailed,
        ),
        (
            403,
            Value::Null,
            Some(ReadFailure::Timeout),
            AuthenticationFailed,
        ),
        (429, json!({"address":"other"}), None, Unavailable),
        (503, json!({"address":"other"}), None, Unavailable),
        (408, Value::Null, None, Unavailable),
        (200, Value::Null, Some(ReadFailure::Timeout), Unavailable),
        (
            200,
            Value::Null,
            Some(ReadFailure::BodyInterrupted),
            Unavailable,
        ),
        (
            200,
            Value::Null,
            Some(ReadFailure::InvalidJson),
            InvalidResponse,
        ),
        (
            200,
            Value::Null,
            Some(ReadFailure::ResponseTooLarge),
            InvalidResponse,
        ),
        (200, Value::Null, None, InvalidResponse),
        (200, json!({}), None, InvalidResponse),
        (200, json!({"address":17}), None, InvalidResponse),
        (200, json!({"address":""}), None, InvalidResponse),
        (
            200,
            json!({"address":"other","ok":false}),
            None,
            InvalidResponse,
        ),
        (
            200,
            json!({"address":address,"success":false}),
            None,
            InvalidResponse,
        ),
        (
            200,
            json!({"address":address,"chain_id":null}),
            None,
            InvalidResponse,
        ),
        (
            200,
            json!({"address":address,"chain_id":17}),
            None,
            InvalidResponse,
        ),
        (
            200,
            json!({"address":address,"chain_id":""}),
            None,
            InvalidResponse,
        ),
        (
            200,
            json!({"address":address,"chain_id":"wrong chain"}),
            None,
            InvalidResponse,
        ),
        (200, json!({"address":"other"}), None, InvalidResponse),
        (200, json!({"address":other}), None, IdentityMismatch),
        (
            200,
            json!({"address":address,"chain_id":"other"}),
            None,
            IdentityMismatch,
        ),
        (400, json!({"error":"unauthorized"}), None, InvalidResponse),
    ] {
        let response = Response {
            status,
            body,
            read_failure: failure,
            retry_after_seconds: None,
        };
        assert_eq!(classify_hosted_identity(&config, &response), expected);
    }
}
pub(super) fn request(kind: LaneId) -> SolverRequest {
    SolverRequest {
        id: "request-test".into(),
        kind,
        epoch: 8,
        words: vec!["burn".into()],
        min_chars: 4,
        max_chars: 100,
        assignment: (kind == LaneId::Judge).then(|| "assignment-test".into()),
        candidate: (kind == LaneId::Judge).then(|| "candidate-test".into()),
        history: Vec::new(),
        guidance: String::new(),
        core_guidance: "Evaluate the supplied task against its protocol requirements.".into(),
        author_history: (kind == LaneId::Judge).then(Default::default),
        candidate_author: None,
    }
}
pub(super) fn result() -> SolverResult {
    SolverResult {
        answer: Some("burning".into()),
        score: Some(2),
        reasoning: Some("Grounded judgment.".into()),
        provider: "test".into(),
        model: "test".into(),
        run_id: "test".into(),
    }
}
#[test]
fn receipt_needs_positive_inclusion_and_nonce_evidence() {
    assert_eq!(
        receipt(&response(json!({"status":"included"})), "tx", "account"),
        Receipt::Unresolved
    );
    assert_eq!(
        receipt(
            &response(json!({"status":"included","valid_in_open_window":true})),
            "tx",
            "account"
        ),
        Receipt::Unresolved
    );
    assert_eq!(
        receipt(
            &response(json!({"status":"included","valid_in_open_window":true,"next_nonce":4})),
            "tx",
            "account"
        ),
        Receipt::Included
    );
    assert_eq!(
        receipt(
            &response(json!({"status":"included","checkpoint_covered":true,"next_nonce":4})),
            "tx",
            "account"
        ),
        Receipt::Final
    );
}

#[test]
fn receipt_cannot_cross_known_transaction_or_case_sensitive_account() {
    let body =
        json!({"status":"included","valid_in_open_window":true,"next_nonce":4,"txid":"other"});
    assert_eq!(
        receipt(&response(body), "known", "Account"),
        Receipt::Unresolved
    );
    let body =
        json!({"status":"included","valid_in_open_window":true,"next_nonce":4,"address":"account"});
    assert_eq!(
        receipt(&response(body), "known", "Account"),
        Receipt::Unresolved
    );
    let missing = Response {
        status: 404,
        body: json!({"status":"rejected"}),
        retry_after_seconds: None,
        read_failure: None,
    };
    assert_eq!(receipt(&missing, "known", "Account"), Receipt::Unresolved);
    for field in ["txid", "address", "sender"] {
        let mut malformed = json!({
            "status":"included","valid_in_open_window":true,"next_nonce":4
        });
        malformed[field] = json!(17);
        assert_eq!(
            receipt(&response(malformed), "known", "Account"),
            Receipt::Unresolved
        );
    }
}

#[test]
fn contradictory_receipts_cannot_release_the_effect_slot() {
    for status in ["included", "rejected"] {
        for field in ["ok", "success"] {
            for value in [json!(false), Value::Null, json!("true")] {
                let mut body = json!({
                    "status":status,"checkpoint_covered":true,"next_nonce":4
                });
                body[field] = value;
                assert_eq!(
                    receipt(&response(body), "known", "Account"),
                    Receipt::Unresolved
                );
            }
        }
    }
}

#[test]
fn generic_success_and_answered_flags_do_not_resolve_a_receipt() {
    assert_eq!(
        receipt(
            &response(json!({"ok":true,"answered":true})),
            "known",
            "account"
        ),
        Receipt::Unresolved
    );
    assert_eq!(
        receipt(&response(json!({"status":"rejected"})), "known", "account"),
        Receipt::Unresolved
    );
    assert_eq!(
        receipt(
            &response(json!({"status":"rejected","next_nonce":4})),
            "known",
            "account"
        ),
        Receipt::Rejected
    );
}

#[test]
fn answer_constraints_use_protocol_utf16_and_substrings() {
    let mut request = request(LaneId::Answer);
    assert!(payload(&request, &result()).is_ok());
    request.words.clear();
    request.min_chars = 2;
    request.max_chars = 2;
    let mut output = result();
    output.answer = Some("\u{1f600}".into());
    assert!(payload(&request, &output).is_ok());
    request.max_chars = 1;
    assert!(payload(&request, &output).is_err());
}

#[test]
fn judgment_never_fabricates_score_or_reasoning() {
    let request = request(LaneId::Judge);
    let mut output = result();
    assert_eq!(
        payload(&request, &output).unwrap()["assignment"],
        "assignment-test"
    );
    output.score = None;
    assert!(payload(&request, &output).is_err());
    output.score = Some(4);
    assert!(payload(&request, &output).is_err());
    output.score = Some(2);
    output.reasoning = Some(" ".into());
    assert!(payload(&request, &output).is_err());
}

#[test]
fn grading_refresh_binds_exact_candidate_assignment_and_answer_epoch() {
    let request = request(LaneId::Judge);
    let mut assignment = Assignment {
        id: "assignment-test".into(),
        epoch: 8,
        answer: "candidate-test".into(),
        words: vec!["burn".into()],
        expires_at_epoch: None,
        author: None,
        author_prior: Default::default(),
    };
    assert!(assignment_matches(&assignment, &request));
    assignment.epoch = 9;
    assert!(!assignment_matches(&assignment, &request));
    assignment.epoch = 8;
    assignment.answer.push('x');
    assert!(!assignment_matches(&assignment, &request));
}

#[test]
fn queued_polling_growth_has_exact_boundaries_and_saturates() {
    for (elapsed, expected) in [(0, 2), (1, 2), (2, 4), (5, 4), (6, 8), (13, 8), (14, 10)] {
        assert_eq!(queued_poll_interval(2, 10, elapsed), expected);
    }
    assert_eq!(queued_poll_interval(2, 10, u64::MAX), 10);
    assert_eq!(queued_poll_interval(1, 1, u64::MAX), 1);
    assert_eq!(
        queued_poll_interval(u64::MAX / 2 + 1, u64::MAX, u64::MAX),
        u64::MAX
    );
}

#[path = "coordination_tests.rs"]
mod coordination_tests;
#[path = "regressions.rs"]
mod regressions;

pub(super) fn observation(runtime: &HostAccess, lane: LaneId) -> Observation {
    let completed = Instant::now();
    let completed_at = now();
    let seconds = runtime.config.timeouts(lane).read_http_seconds;
    Observation {
        stamp: runtime.admission_stamp(lane).unwrap(),
        admit_before: completed + Duration::from_secs(seconds),
        admit_before_unix: completed_at + seconds as i64,
    }
}
fn offer_mine(runtime: &mut HostAccess, op: Operation) {
    let ready = runtime
        .mine_ready(
            crate::protocol::MineIntent,
            runtime.store.operation_binding(&op).unwrap(),
            observation(runtime, LaneId::Mine),
        )
        .unwrap();
    let NativeLane::Mine(lane) =
        &mut runtime.lanes[crate::runtime::registry::lane_index(LaneId::Mine)]
    else {
        unreachable!()
    };
    lane.ready = Some(ready);
}

pub(super) async fn identity_fixture(runtime: &mut HostAccess, listener: &tokio::net::TcpListener) {
    runtime.start_identity(LaneId::Answer).unwrap();
    let (stream, _) = accept(listener).await;
    reply(
        stream,
        200,
        None,
        json!({"address":runtime.config.network.address,"chain_id":runtime.config.network.chain}),
    )
    .await;
    collect_until(runtime, |runtime| runtime.permit_current().unwrap()).await;
}

pub(super) fn task_request(runtime: &HostAccess, kind: LaneId) -> SolverRequest {
    let mut request = request(kind);
    let model = runtime.config.model(kind).unwrap();
    request.guidance = model.guidance.to_string();
    request.core_guidance = model.core_guidance.to_string();
    if kind == LaneId::Judge {
        request.min_chars = 0;
        request.max_chars = 0;
    }
    request
}
