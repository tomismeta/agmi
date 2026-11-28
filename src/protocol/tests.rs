use super::*;
use serde_json::json;
fn meta() -> RequestMeta {
    RequestMeta {
        request_id: "request-1".into(),
        database_id: "journal-1".into(),
        authority_epoch: 1,
        owner: Some(LaneId::Answer),
        operation_id: None,
        read_key: None,
        binding_revision: None,
        dispatch_sequence: None,
    }
}
fn read_deadline() -> ReadDeadline {
    ReadDeadline::seconds(2).unwrap()
}
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
        classify_source(LaneId::Answer, &answer, ResponseSource::Submit),
        Outcome::Included { .. }
    ));
    assert!(matches!(
        classify_source(LaneId::Judge, &answer, ResponseSource::Submit),
        Outcome::Unknown { .. }
    ));
    assert!(matches!(
        classify_source(LaneId::Mine, &answer, ResponseSource::Submit),
        Outcome::Unknown { .. }
    ));
    let grade = response(200, json!({"ok":true,"id":txid()}));
    assert!(matches!(
        classify_source(LaneId::Judge, &grade, ResponseSource::Submit),
        Outcome::Included { .. }
    ));
    assert!(matches!(
        classify_source(LaneId::Answer, &grade, ResponseSource::Submit),
        Outcome::Unknown { .. }
    ));
    assert!(matches!(
        classify_source(
            LaneId::Judge,
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
            classify_source(LaneId::Answer, &response(200, body), ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
    }
}
#[test]
fn queued_terminal_results_use_original_route() {
    assert_eq!(
        classify_source(
            LaneId::Answer,
            &response(202, json!({"job_id":"safe-id_1"})),
            ResponseSource::Submit
        ),
        Outcome::Queued {
            job_id: "safe-id_1".into()
        }
    );
    assert_eq!(
        classify_source(
            LaneId::Answer,
            &response(409, json!({"error":"duplicate_in_flight","job_id":"safe"})),
            ResponseSource::Submit
        ),
        Outcome::Queued {
            job_id: "safe".into()
        }
    );
    for body in [json!({}), json!({"job_id":"../unsafe"})] {
        assert!(matches!(
            classify_source(LaneId::Answer, &response(202, body), ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
    }
    assert!(matches!(
        classify_source(
            LaneId::Answer,
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
            LaneId::Judge,
            &response(200, json!({"state":"done","ok":true,"id":txid()})),
            ResponseSource::BoundJob
        ),
        Outcome::Included { txid: txid() }
    );
    assert!(matches!(
        classify_source(
            LaneId::Judge,
            &response(409, json!({"state":"done","error":"off_panel"})),
            ResponseSource::BoundJob
        ),
        Outcome::Rejected { .. }
    ));
    assert!(matches!(
        classify_source(
            LaneId::Answer,
            &response(404, json!({"error":"unknown or expired job id"})),
            ResponseSource::BoundJob
        ),
        Outcome::Unknown { .. }
    ));
    assert!(matches!(
        classify_source(
            LaneId::Answer,
            &response(408, json!({"state":"expired","error":"job_expired"})),
            ResponseSource::BoundJob
        ),
        Outcome::Expired
    ));
}
#[test]
fn only_documented_nonacceptance_can_retry() {
    for (status, body, fallback) in [
        (429, json!({"error":"accept queue full"}), 5),
        (429, json!({"error":"rate_limited"}), 5),
        (429, json!({"error":"grade queue is full"}), 5),
        (429, json!({}), 5),
        (503, json!({"error":"epoch_closing"}), 30),
        (503, json!({"error":HALT_MIDDLEWARE_ERROR}), 30),
    ] {
        let mut result = response(status, body);
        for kind in [LaneId::Answer, LaneId::Judge] {
            assert_eq!(
                classify_source(kind, &result, ResponseSource::Submit),
                Outcome::Retry {
                    after_seconds: fallback
                }
            );
            assert!(matches!(
                classify_source(kind, &result, ResponseSource::BoundJob),
                Outcome::Unknown { .. }
            ));
        }
        result.retry_after_seconds = Some(3600);
        assert_eq!(
            classify_source(LaneId::Answer, &result, ResponseSource::Submit),
            Outcome::Retry {
                after_seconds: 3600
            }
        );
        if status == 429 {
            assert_eq!(
                classify_source(LaneId::Mine, &result, ResponseSource::Submit),
                Outcome::Retry {
                    after_seconds: 3600
                }
            );
        } else {
            assert!(matches!(
                classify_source(LaneId::Mine, &result, ResponseSource::Submit),
                Outcome::Unknown { .. }
            ));
        }
    }
    for (status, code) in [
        (503, "overloaded"),
        (500, "epoch_closing"),
        (400, "rate_limited"),
        (403, HALT_MIDDLEWARE_ERROR),
        (502, HALT_MIDDLEWARE_ERROR),
        (504, "rate_limited"),
    ] {
        assert!(matches!(
            classify_source(
                LaneId::Answer,
                &response(status, json!({"error":code})),
                ResponseSource::Submit
            ),
            Outcome::Unknown { .. }
        ));
    }
}

#[test]
fn only_exact_halt_middleware_has_authoritative_diagnostic_category() {
    let halted = response(503, json!({"error":HALT_MIDDLEWARE_ERROR}));
    let evidence = response_evidence(LaneId::Judge, ResponseSource::Submit, Some(&halted));
    assert_eq!(evidence.error_category.as_deref(), Some("halt_middleware"));
    assert_eq!(failure_category(&halted), Some("endpoint_halted"));
    assert_eq!(
        response_evidence(
            LaneId::Judge,
            ResponseSource::Submit,
            Some(&response(503, json!({"halted":true}))),
        )
        .error_category
        .as_deref(),
        Some("endpoint_halted")
    );
}

#[test]
fn refusal_retry_delay_preserves_valid_server_minima() {
    for (header, body, expected) in [
        (Some(300), json!(3600), 3600),
        (Some(3600), json!(300), 3600),
        (None, json!(3600), 3600),
        (None, json!(0), 1),
        (Some(3600), json!(-1), 3600),
        (Some(3600), json!("7200"), 3600),
        (None, json!(1.5), 5),
        (None, json!(u64::MAX), u64::MAX),
    ] {
        let mut result = response(429, json!({"retry_after_seconds":body}));
        result.retry_after_seconds = header;
        assert_eq!(
            classify_source(LaneId::Judge, &result, ResponseSource::Submit),
            Outcome::Retry {
                after_seconds: expected
            }
        );
    }
    assert_eq!(parse_retry_after("3600"), Some(3600));
    assert_eq!(parse_retry_after("-1"), None);
    assert_eq!(parse_retry_after("18446744073709551616"), Some(u64::MAX));
    assert_eq!(parse_retry_after("18446744073709551616x"), None);
}

#[test]
fn incomplete_refusal_responses_remain_unknown() {
    for status in [429, 503, 502, 504] {
        for body in [Value::Null, json!({"error":HALT_MIDDLEWARE_ERROR})] {
            let mut result = response(status, body);
            result.read_failure = Some(ReadFailure::Timeout);
            assert!(matches!(
                classify_source(LaneId::Judge, &result, ResponseSource::Submit),
                Outcome::Unknown { .. }
            ));
        }
    }
}
#[test]
fn mine_completion_requires_explicit_nonnegative_attestation_count() {
    for count in [0, 7] {
        assert_eq!(
            classify_source(
                LaneId::Mine,
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
            classify_source(LaneId::Mine, &response(200, body), ResponseSource::Submit),
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
        .get(Endpoint::ExplorerTx, Some(&txid()), read_deadline(), meta())
        .await
        .unwrap();
    let assignment = parse_selected_assignment(&page, &txid(), Some(&tx.response)).unwrap();
    assert_eq!(assignment.epoch, 42);
    assert_eq!(assignment.answer, "selected candidate");
    assert!(assignment.words.is_empty());
    server.await.unwrap();
}
#[tokio::test]
async fn typed_reads_exclude_effects_and_identifier_injection() {
    let protocol = Protocol::new(&Config::default()).unwrap();
    for endpoint in [
        Endpoint::Mine,
        Endpoint::Answer,
        Endpoint::Grade,
        Endpoint::Register,
    ] {
        assert!(
            protocol
                .get(endpoint, None, read_deadline(), meta())
                .await
                .is_err()
        );
    }
    for id in ["../mine", "a%2fb", "safe?key=x", "https://other.example/x"] {
        assert!(
            protocol
                .get(Endpoint::Job, Some(id), read_deadline(), meta())
                .await
                .is_err()
        );
    }
    assert!(
        protocol
            .get(
                Endpoint::ExplorerAddress,
                Some("another-account"),
                read_deadline(),
                meta()
            )
            .await
            .is_err()
    );
}
#[test]
fn payload_allowlist_excludes_secret_and_extra_fields() {
    assert!(validate_payload(LaneId::Answer, &json!({"answer":"text","key":"secret"})).is_err());
    assert!(
        validate_payload(
            LaneId::Judge,
            &json!({"assignment":txid(),"score":3,"reasoning":"Substantive mechanism."})
        )
        .is_ok()
    );
    assert!(
        validate_payload(
            LaneId::Judge,
            &json!({"assignment":txid(),"score":4,"reasoning":"Substantive mechanism."})
        )
        .is_err()
    );
    assert!(validate_payload(LaneId::Mine, &json!({})).is_ok());
    assert!(validate_payload(LaneId::Mine, &json!({"to":"elsewhere"})).is_err());
}

#[test]
fn grade_bounds_are_rejected_before_a_network_future_exists() {
    let mut protocol = Protocol::new(&Config::default()).unwrap();
    protocol.key = Some(HeaderValue::from_static("pk_fixture"));
    protocol.address = "configured-account".into();
    for (length, accepted) in [(9, false), (10, true), (500, true), (501, false)] {
        let payload = json!({"assignment":txid(),"score":2,"reasoning":"a".repeat(length)});
        assert_eq!(
            protocol
                .prepare_submission(
                    LaneId::Judge,
                    &payload,
                    EffectDeadline::seconds(2).unwrap(),
                    RequestMeta {
                        owner: Some(LaneId::Judge),
                        ..meta()
                    }
                )
                .is_ok(),
            accepted
        );
    }
}

#[tokio::test]
async fn unavailable_bodies_retain_safe_categories_status_and_retry_after() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let invalid_expiry = concat!(
        r#"{"state":"expired","error":"job_expired","processed":true,"processed":false,"#,
        r#""retry_after_seconds":900} trailing"#,
    );
    let echoed_expiry = r#"{"state":"expired","error":"job_expired","retry_after_seconds":900,"detail":"private-test-credential"}"#;
    let echoed_duplicate = r#"{"state":"expired","error":{"code":"job_expired"},"processed":true,"retry_after_seconds":900,"detail":["private-test-credenti\u0061l"],"detail":"ordinary"}"#;
    let echoed_throttle =
        r#"{"retry_after_seconds":0,"detail":"private-test-credential","detail":"ordinary"}"#;
    for (endpoint, status, body, length, failure) in [
        (Endpoint::Status, 429, "", 0, ReadFailure::InvalidJson),
        (
            Endpoint::Status,
            503,
            "<html>unavailable</html>",
            24,
            ReadFailure::InvalidJson,
        ),
        (
            Endpoint::Status,
            503,
            "{",
            100,
            ReadFailure::BodyInterrupted,
        ),
        (
            Endpoint::Status,
            503,
            "",
            MAX_RESPONSE_BYTES + 1,
            ReadFailure::ResponseTooLarge,
        ),
        (
            Endpoint::Status,
            200,
            "\"private-test-credential\"",
            25,
            ReadFailure::CredentialEchoRedacted,
        ),
        (
            Endpoint::Job,
            408,
            invalid_expiry,
            invalid_expiry.len(),
            ReadFailure::InvalidJson,
        ),
        (
            Endpoint::Job,
            408,
            echoed_expiry,
            echoed_expiry.len(),
            ReadFailure::CredentialEchoRedacted,
        ),
        (
            Endpoint::Job,
            408,
            echoed_duplicate,
            echoed_duplicate.len(),
            ReadFailure::CredentialEchoRedacted,
        ),
        (
            Endpoint::Identity,
            429,
            echoed_throttle,
            echoed_throttle.len(),
            ReadFailure::CredentialEchoRedacted,
        ),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        let retry_headers = if endpoint == Endpoint::Identity {
            ""
        } else {
            "Retry-After: 1\r\nRetry-After: 300\r\n"
        };
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
                "HTTP/1.1 {status} Unavailable\r\n{retry_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                length,
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        });
        let mut protocol = Protocol::new(&config).unwrap();
        protocol.key = Some(HeaderValue::from_static("private-test-credential"));
        let hosted = protocol
            .get(
                endpoint,
                (endpoint == Endpoint::Job).then_some("old-job"),
                read_deadline(),
                RequestMeta {
                    owner: Some(LaneId::Answer),
                    ..meta()
                },
            )
            .await
            .unwrap();
        if endpoint == Endpoint::Identity {
            assert_eq!(
                hosted.authenticated_retry_minimum(),
                Some((30, RestrictionBasis::LocalUnscoped429Cooldown))
            );
        }
        let response = hosted.response;
        assert_eq!(response.status, status);
        assert_eq!(
            response.retry_after_seconds,
            (endpoint != Endpoint::Identity).then_some(300)
        );
        assert_eq!(response.read_failure, Some(failure));
        assert!(response.body.is_null());
        let public = serde_json::to_string(&response).unwrap();
        assert!(!public.contains("private-test-credential"));
        assert!(!public.contains("127.0.0.1"));
        assert!(matches!(
            classify_source(LaneId::Answer, &response, ResponseSource::Submit),
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
    let decode =
        |body: &[u8]| decode_hosted_body(body, Endpoint::Status, None, 200, Some("pk_fixture"));
    for body in [
        &br#"{"nested":["value with p\u006b_fixture"]}"#[..],
        br#"{"p\u006b_fixture":"value","pk_fixture":"duplicate"}"#,
        br#"{"nested":{"old":"pk_fixture","old":"harmless"}}"#,
    ] {
        assert_eq!(decode(body), Err(ReadFailure::CredentialEchoRedacted));
    }
    assert_eq!(
        decode(br#"{"ordinary":"value"}"#),
        Ok((DecodedBody::Value(json!({"ordinary":"value"})), None))
    );
}
#[test]
fn acceptance_evidence_prevents_refusal_retries() {
    for (status, code) in [
        (429, "accept queue full"),
        (429, "rate_limited"),
        (503, HALT_MIDDLEWARE_ERROR),
        (503, "epoch_closing"),
    ] {
        for indicator in [
            json!({"job_id":"capability"}),
            json!({"job_id":null}),
            json!({"id":txid()}),
            json!({"challenge_txid":txid()}),
            json!({"txid":null}),
            json!({"accepted":true}),
            json!({"queued":true}),
            json!({"ok":true}),
            json!({"success":true}),
            json!({"state":"done"}),
            json!({"status":"processing"}),
            json!({"processed":true}),
            json!({"next_nonce":7}),
            json!({"attested":1}),
            json!({"code":"different_error"}),
        ] {
            let mut body = indicator;
            body["error"] = json!(code);
            for kind in [LaneId::Answer, LaneId::Judge, LaneId::Mine] {
                assert!(matches!(
                    classify_source(
                        kind,
                        &response(status, body.clone()),
                        ResponseSource::Submit
                    ),
                    Outcome::Unknown { .. }
                ));
            }
        }
    }
    for body in [json!({"ok":true}), json!({"success":true})] {
        assert!(matches!(
            classify_source(LaneId::Judge, &response(429, body), ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
    }
    let duplicate = response(429, json!({"error":"duplicate_in_flight","job_id":"bound"}));
    assert!(matches!(
        classify_source(LaneId::Judge, &duplicate, ResponseSource::Submit),
        Outcome::Queued { .. }
    ));
}

#[test]
fn refusal_contradictions_survive_in_recovery_diagnostics_without_candidates() {
    for (kind, status, code, category) in [
        (LaneId::Answer, 429, "rate_limited", "rate_limited"),
        (LaneId::Judge, 429, "rate_limited", "rate_limited"),
        (LaneId::Mine, 429, "rate_limited", "rate_limited"),
        (
            LaneId::Answer,
            503,
            HALT_MIDDLEWARE_ERROR,
            "halt_middleware",
        ),
        (LaneId::Judge, 503, HALT_MIDDLEWARE_ERROR, "halt_middleware"),
    ] {
        for indicator in [
            json!({"state":"done"}),
            json!({"state":"expired"}),
            json!({"state":"unrecognized"}),
            json!({"state":null}),
            json!({"id":null}),
            json!({"id":"invalid"}),
            json!({"challenge_txid":null}),
            json!({"txid":null}),
            json!({"job_id":null}),
            json!({"accepted":true}),
            json!({"queued":true}),
            json!({"ok":true}),
            json!({"success":true}),
            json!({"status":"processing"}),
            json!({"processed":true}),
            json!({"next_nonce":7}),
            json!({"attested":1}),
        ] {
            let mut body = indicator;
            body["error"] = json!(code);
            let result = response(status, body);
            let classified = classify_source(kind, &result, ResponseSource::Submit);
            assert_eq!(
                classified,
                Outcome::Unknown {
                    reason: "contradictory_acceptance".into()
                }
            );
            let candidates = response_candidates(&result);
            assert!(candidates.job_id.is_none());
            assert!(candidates.transaction_ids.is_empty());
            let evidence = response_evidence(kind, ResponseSource::Submit, Some(&result));
            assert_eq!(evidence.reason, "contradictory_acceptance");
            assert_eq!(evidence.error_category.as_deref(), Some(category));
            assert_eq!(evidence.stage, ResponseSource::Submit);
            assert_eq!(evidence.status, Some(status));
        }
    }
}

#[test]
fn known_engine_rejections_require_bound_terminal_source() {
    for (kind, error, code) in [
        (LaneId::Answer, "stale_seed", "stale_seed"),
        (
            LaneId::Answer,
            "challenge answer length out of bounds",
            "answer_length",
        ),
        (
            LaneId::Judge,
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
        classify_source(LaneId::Answer, &expired, ResponseSource::Submit),
        Outcome::Unknown { .. }
    ));
    assert_eq!(
        classify_source(LaneId::Answer, &expired, ResponseSource::BoundJob),
        Outcome::Expired
    );
    for kind in [LaneId::Answer, LaneId::Judge] {
        for indicator in [
            json!({"processed":true}),
            json!({"processed":"true"}),
            json!({"next_nonce":7}),
            json!({"code":"other_error","processed":true}),
            json!({"ok":"true"}),
            json!({"status":"completed"}),
            json!({"status":"success"}),
            json!({"code":true}),
            json!({"accepted":true}),
            json!({"success":true}),
            json!({"job_id":"bound"}),
            json!({"id":txid()}),
        ] {
            let mut body = indicator;
            body["state"] = json!("expired");
            body["error"] = json!("job_expired");
            assert_eq!(
                classify_source(kind, &response(408, body), ResponseSource::BoundJob),
                unknown(BOUND_JOB_EXPIRY_CONFLICT)
            );
        }
        let malformed = response(
            408,
            json!({"state":"expired","code":"job_expired","error":true}),
        );
        assert_eq!(
            classify_source(kind, &malformed, ResponseSource::BoundJob),
            unknown(BOUND_JOB_EXPIRY_CONFLICT)
        );
        let unprocessed = response(
            408,
            json!({"state":"expired","error":"job_expired","status":"expired","processed":false}),
        );
        assert_eq!(
            classify_source(kind, &unprocessed, ResponseSource::BoundJob),
            Outcome::Expired
        );
    }
}

#[test]
fn bound_expiry_rejects_duplicate_keys_in_raw_http_bodies() {
    for kind in [LaneId::Answer, LaneId::Judge] {
        for bytes in [
            &br#"{"state":"expired","error":"job_expired","processed":true,"processed":false}"#[..],
            br#"{"state":"expired","error":"job_expired","processed":true,"proces\u0073ed":false}"#,
            br#"{"state":"done","state":"expired","code":"job_expired"}"#,
            br#"{"state":"done","state":"expired"}"#,
            br#"{"state":"expired","processed":true,"processed":false}"#,
            br#"{"state":"expired","error":"other_error","error":"job_expired"}"#,
            br#"{"state":"expired","error":"job_expired","status":"processing","status":"expired"}"#,
            br#"{"code":"job_expired","code":"duplicate_in_flight","job_id":"other-job"}"#,
            br#"{"error":{"code":"job_expired","code":"other_error"}}"#,
            br#"{"code":"job_expired","error":{"processed":true,"processed":false}}"#,
            br#"{"error":{"state":"expired","processed":true,"processed":false}}"#,
        ] {
            let (body, delay) =
                decode_hosted_body(bytes, Endpoint::Job, Some(kind), 408, None).unwrap();
            assert_eq!(delay, None);
            let observed = body.into_response(408, delay);
            assert!(observed.body.is_null(), "conflicting wire data is discarded");
            assert_eq!(
                classify_source(kind, &observed, ResponseSource::BoundJob),
                unknown(BOUND_JOB_EXPIRY_CONFLICT),
                "{bytes:?}",
            );
            assert!(response_candidates(&observed).job_id.is_none());
        }
        for bytes in [
            &br#"{"state":"expired","error":"job_expired"}"#[..],
            br#"{"state":"expired","code":"job_expired","status":"expired","processed":false}"#,
        ] {
            let (body, _) =
                decode_hosted_body(bytes, Endpoint::Job, Some(kind), 408, None).unwrap();
            assert_eq!(
                classify_source(
                    kind,
                    &body.into_response(408, None),
                    ResponseSource::BoundJob
                ),
                Outcome::Expired,
            );
        }
    }

    let duplicate = br#"{"state":"expired","error":"job_expired","processed":true,"processed":false,"retry_after_seconds":20,"retry_after_seconds":5}"#;
    for (endpoint, kind, status) in [
        (Endpoint::Status, LaneId::Answer, 408),
        (Endpoint::Grade, LaneId::Judge, 408),
        (Endpoint::Job, LaneId::Answer, 200),
        (Endpoint::Job, LaneId::Mine, 408),
        (Endpoint::Answer, LaneId::Answer, 429),
        (Endpoint::Grade, LaneId::Judge, 503),
    ] {
        let (body, delay) =
            decode_hosted_body(duplicate, endpoint, Some(kind), status, None).unwrap();
        assert_eq!(delay, Some(20));
        assert_eq!(body, DecodedBody::Discarded(ReadFailure::InvalidJson));
    }
    let timeout = br#"{"error":"temporary","error":"request_timeout","retry_after_seconds":20,"retry_after_seconds":5}"#;
    let (body, delay) =
        decode_hosted_body(timeout, Endpoint::Job, Some(LaneId::Answer), 408, None).unwrap();
    assert_eq!(delay, Some(20));
    assert_eq!(body, DecodedBody::Discarded(ReadFailure::InvalidJson));
}

#[test]
fn bound_expiry_distinguishes_missing_facts_from_contradictions() {
    let classify = |body| {
        let (body, _) =
            decode_hosted_body(body, Endpoint::Job, Some(LaneId::Judge), 408, None).unwrap();
        classify_source(
            LaneId::Judge,
            &body.into_response(408, None),
            ResponseSource::BoundJob,
        )
    };
    for bytes in [
        &br#"{"state":"expired"}"#[..],
        br#"{"error":"job_expired"}"#,
        br#"{"state":"expired","error":{"code":"job_expired"}}"#,
        br#"{"error":{"state":"expired"}}"#,
        br#"{"state":"expired","code":"bound_job_expiry_conflict"}"#,
    ] {
        assert_eq!(classify(bytes), unknown("bound_job_expiry_incomplete"));
    }
    for bytes in [
        &br#"{"state":"expired","processed":true}"#[..],
        br#"{"error":{"state":"expired","processed":true}}"#,
        br#"{"state":"expired","error":"duplicate_in_flight"}"#,
        br#"{"state":"expired","error":{"code":"duplicate_in_flight"}}"#,
        br#"{"state":"expired","error":{"code":"job_expired","processed":true}}"#,
        br#"{"state":"expired","error":"job_expired","status":"running"}"#,
    ] {
        assert_eq!(classify(bytes), unknown(BOUND_JOB_EXPIRY_CONFLICT));
    }
    for bytes in [
        &br#"{"state":"expired","arbitrary":true,"arbitrary":false}"#[..],
        br#"{"code":"job_expired","arbitrary":true,"arbitrary":false}"#,
        br#"{"state":"expired","error":{"code":"job_expired"},"retry_after_seconds":20,"retry_after_seconds":5}"#,
        br#"{"state":"expired","error":"job_expired","metadata":[{"same":1,"same":1}]}"#,
    ] {
        assert_eq!(classify(bytes), unknown("response_shape_unknown"));
    }
    assert_ne!(
        classify(br#"{"code":"bound_job_expiry_conflict"}"#),
        unknown(BOUND_JOB_EXPIRY_CONFLICT)
    );
}

#[test]
fn outage_diagnostics_do_not_turn_unknown_writes_into_retries() {
    // Current journals retain 503 + 3600 seconds, but not the original body.
    // The other forms cover legacy halt fixtures and HTTP status fallbacks;
    // they are not claims that every synthetic body was captured on the wire.
    for (status, body, category) in [
        (503, json!({}), "service_unavailable"),
        (503, json!({"error":"halted"}), "endpoint_halted"),
        (503, json!({"halted":true}), "endpoint_halted"),
        (503, json!({"status":"paused"}), "endpoint_halted"),
        (
            503,
            json!({"error":"endpoint temporarily halted — API hardening in progress; check later"}),
            "endpoint_halted",
        ),
        (
            401,
            json!({"error":"private-canary"}),
            "authentication_rejected",
        ),
        (403, json!({}), "permission_denied"),
        (502, json!({}), "bad_gateway"),
        (504, json!({}), "gateway_timeout"),
        (500, json!({}), "upstream_error"),
    ] {
        let mut result = response(status, body);
        result.retry_after_seconds = Some(3600);
        let evidence = response_evidence(LaneId::Answer, ResponseSource::Submit, Some(&result));
        assert_eq!(evidence.error_category.as_deref(), Some(category));
        assert_eq!(evidence.retry_after_seconds, Some(3600));
        assert!(
            !serde_json::to_string(&evidence)
                .unwrap()
                .contains("private-canary")
        );
        assert!(matches!(
            classify_source(LaneId::Answer, &result, ResponseSource::Submit),
            Outcome::Unknown { .. }
        ));
    }
}

#[test]
fn diagnostics_never_echo_untrusted_values() {
    let result = response(
        500,
        json!({"error":"secret-canary","job_id":"secret-capability",
        "answer":"private answer","reasoning":"private reasoning"}),
    );
    let evidence = serde_json::to_string(&response_evidence(
        LaneId::Judge,
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
        response_evidence(LaneId::Answer, ResponseSource::Submit, None).reason,
        "transport_unknown"
    );
}

#[test]
fn rate_limit_refusal_keeps_bounded_diagnostics() {
    let limited = response(
        429,
        json!({
            "error":"answer surface is at its global ceiling (20/min) — retry shortly",
            "retry_after_seconds":60
        }),
    );
    let diagnostic = response_evidence(LaneId::Answer, ResponseSource::Submit, Some(&limited));
    assert_eq!(
        diagnostic.error_category.as_deref(),
        Some("answer_global_ceiling")
    );
    assert_eq!(
        classify_source(LaneId::Answer, &limited, ResponseSource::Submit),
        Outcome::Retry { after_seconds: 60 }
    );
    let injected = response(
        429,
        json!({
            "error":"answer surface is at its global ceiling (private-canary/min)"
        }),
    );
    let diagnostic = response_evidence(LaneId::Answer, ResponseSource::Submit, Some(&injected));
    assert_eq!(diagnostic.error_category.as_deref(), Some("rate_limited"));
    assert!(
        !serde_json::to_string(&diagnostic)
            .unwrap()
            .contains("private-canary")
    );
}

#[test]
fn recovery_requires_prior_request_attribution() {
    assert!(verify_recovery_identifier(None, "plausible-job", RecoveryIdentifier::Job).is_err());
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
    let mut protocol = Protocol::new(&config).unwrap();
    protocol.key = Some(HeaderValue::from_static("pk_fixture"));
    assert!(
        protocol
            .assignment_page(0, 101, read_deadline(), meta())
            .await
            .is_err()
    );
    assert!(
        protocol
            .assignment_page(0, 0, read_deadline(), meta())
            .await
            .is_err()
    );
    assert!(
        protocol
            .get(
                Endpoint::Job,
                Some("job?offset=10&limit=10"),
                read_deadline(),
                meta()
            )
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
    let page = protocol
        .assignment_page(10, 10, read_deadline(), meta())
        .await
        .unwrap();
    assert_eq!(page.response.body["offset"], 10);
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
        classify_source(LaneId::Answer, &result, ResponseSource::Submit),
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
        LaneId::Answer,
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
