use agmi::config::Config;
use agmi::epoch::{self, EpochQuery};
use agmi::protocol::reports::{self, ReportInterest};
use serde_json::{Value, json};
use std::io::Read;
use std::time::{Duration, Instant};

fn own() -> String {
    format!("poa1{}", "1".repeat(32))
}
fn other() -> String {
    "poa14jsSMPRfjSRcNKYZFf4XFs1gPUHXynC3NnM9bR9q1gue".into()
}
fn compact(interest: &ReportInterest, rows: Vec<Value>) -> Value {
    reports::parse_compact(
        "settled",
        9,
        interest,
        &serde_json::to_vec(&json!({"epoch":9,"count":rows.len(),"rows":rows})).unwrap(),
    )
    .unwrap()
}
fn row(tx: &str, account: &str, outcome: &str, jury: Vec<Value>) -> Value {
    json!({"answer":tx,"from":account,"outcome":outcome,"jury":jury})
}
fn raw(interest: &ReportInterest, value: Value) -> reports::RawAttempt {
    reports::parse_raw(
        serde_json::to_vec(&value).unwrap().as_slice(),
        9,
        interest,
        Instant::now() + Duration::from_secs(5),
    )
}
#[test]
fn source_outcome_requires_both_account_and_known_binding() {
    let tx = "a".repeat(64);
    let unknown = "b".repeat(64);
    let mut interest = ReportInterest::new(own());
    interest.add_answer(&tx);
    let wrong = compact(&interest, vec![row(&tx, &other(), "passed", vec![])]);
    assert!(wrong["rows"].as_array().unwrap().is_empty());
    let unlinked = compact(&interest, vec![row(&unknown, &own(), "passed", vec![])]);
    assert_eq!(unlinked["unlinked_account_rows"], 1);
    assert_eq!(unlinked["retained"], 0);
    let matched = compact(
        &interest,
        vec![row(&tx.to_uppercase(), &own(), "passed", vec![])],
    );
    assert_eq!(matched["rows"][0]["tx"], tx);
    assert_eq!(matched["rows"][0]["outcome"], "passed");
}
#[test]
fn jury_alignment_is_not_a_judge_transaction_outcome() {
    let tx = "a".repeat(64);
    let mut interest = ReportInterest::new(own());
    interest.add_candidate(&tx);
    let evidence = compact(
        &interest,
        vec![row(
            &tx,
            &other(),
            "failed",
            vec![json!({"grader":own(),"aligned":false})],
        )],
    );
    assert_eq!(evidence["rows"][0]["jury_alignment"], false);
    assert!(evidence["rows"][0]["outcome"].is_null());
    assert_eq!(evidence["rows"][0]["own_answer"], false);
}
#[test]
fn absence_never_means_pending_or_expired_and_expiry_keeps_source_epoch() {
    let mut interest = ReportInterest::new(own());
    interest.add_answer(&"a".repeat(64));
    let empty = compact(&interest, vec![]);
    assert_eq!(empty["retained"], 0);
    let expiry=reports::parse_compact("expiry-schedule",9,&interest,br#"{"as_of_close":8,"pending_ttl_epochs":16,"total_pending":2,"schedule":[{"expires_at_close":10,"total":2}]}"#).unwrap();
    assert_eq!(expiry["report"]["as_of_close"], 8);
    assert_eq!(expiry["per_answer_expiry"], "not_established");
}
#[test]
fn malformed_and_contradictory_rows_cannot_become_positive_outcomes() {
    let tx = "a".repeat(64);
    let good = "b".repeat(64);
    let mut interest = ReportInterest::new(own());
    interest.add_answer(&tx);
    interest.add_answer(&good);
    let evidence = compact(
        &interest,
        vec![
            row(&tx, &own(), "passed", vec![]),
            row(&tx, &own(), "failed", vec![]),
            row(&good, &own(), "expired", vec![]),
            json!({"future_schema":true}),
        ],
    );
    assert_eq!(evidence["validation_complete"], false);
    assert_eq!(evidence["coverage"], "partial");
    assert_eq!(evidence["rows"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["rows"][0]["outcome"], "expired");
    let future = compact(&interest, vec![row(&tx, &own(), "future_outcome", vec![])]);
    assert_eq!(future["validation_complete"], false);
    assert_eq!(future["retained"], 0);
}
#[test]
fn decimal_rewards_are_exact_canonical_checked_and_never_floats() {
    assert_eq!(reports::reward_units("0.000000"), Some(0));
    assert_eq!(
        reports::reward_units("12345678901234567890.123456"),
        Some(12345678901234567890123456)
    );
    let max = u128::MAX;
    let text = format!("{}.{:06}", max / 1_000_000, max % 1_000_000);
    assert_eq!(reports::reward_units(&text), Some(max));
    for invalid in [
        "0",
        "0.0",
        "00.000000",
        "+1.000000",
        "-0.000000",
        "1e6",
        "1.0000000",
        " 1.000000",
        "340282366920938463463374607431768211455.000000",
    ] {
        assert_eq!(reports::reward_units(invalid), None, "{invalid}");
    }
}
#[test]
fn zero_is_present_and_absence_is_not_listed_not_zero() {
    let interest = ReportInterest::new(own());
    let present = raw(
        &interest,
        json!({"epoch":9,"rewards":{own():"0.000000"},"basis":{"pending":{}}}),
    )
    .unwrap();
    assert_eq!(present["account_reward"]["status"], "node_reported");
    assert_eq!(present["account_reward"]["amount"], "0.000000");
    assert_eq!(
        present["account_reward"]["independent_ledger_verification"],
        false
    );
    let absent = raw(
        &interest,
        json!({"epoch":9,"rewards":{},"basis":{"pending":{}}}),
    )
    .unwrap();
    assert_eq!(absent["account_reward"]["status"], "not_listed");
    assert!(absent["account_reward"]["amount"].is_null());
    assert!(raw(&interest, json!({"epoch":9,"basis":{"pending":{}}})).is_err());
    assert!(
        raw(
            &interest,
            json!({"epoch":9,"rewards":{own():1.5},"basis":{"pending":{}}})
        )
        .is_err()
    );
}
#[test]
fn pending_requires_exact_raw_basis_and_matching_epoch() {
    let tx = "a".repeat(64);
    let foreign = "b".repeat(64);
    let mut interest = ReportInterest::new(own());
    interest.add_answer(&tx);
    let value = json!({"epoch":9,"rewards":{},"basis":{"pending":{tx.clone():{"since":4},foreign:{"since":1}}}});
    let parsed = raw(&interest, value.clone()).unwrap();
    assert_eq!(parsed["pending_matches"][&tx], 4);
    assert_eq!(parsed["pending_matches"].as_object().unwrap().len(), 1);
    let mut wrong = value.clone();
    wrong["epoch"] = json!(8);
    assert!(raw(&interest, wrong).is_err());
    let mut future = value;
    future["basis"]["pending"][&tx]["since"] = json!(10);
    assert!(raw(&interest, future).is_err());
    assert!(raw(&interest, json!({"epoch":9,"rewards":{},"basis":{}})).is_err());
}
#[test]
fn duplicate_rewards_and_trailing_bytes_are_rejected() {
    let account = own();
    let interest = ReportInterest::new(account.clone());
    let body = format!(
        r#"{{"epoch":9,"rewards":{{"{account}":"0.000000","{account}":"1.000000"}},"basis":{{"pending":{{}}}}}}"#
    );
    assert!(
        reports::parse_raw(
            body.as_bytes(),
            9,
            &interest,
            Instant::now() + Duration::from_secs(5)
        )
        .is_err()
    );
    assert!(
        reports::parse_raw(
            br#"{"epoch":9,"rewards":{},"basis":{"pending":{}}} {}"#.as_slice(),
            9,
            &interest,
            Instant::now() + Duration::from_secs(5)
        )
        .is_err()
    );
}
#[test]
fn irrelevant_raw_maps_are_streamed_and_skipped_without_dom() {
    let prefix = std::io::Cursor::new(br#"{"epoch":9,"unrelated":{"huge":""#.to_vec());
    let middle = std::io::repeat(b'x').take(2 * 1024 * 1024);
    let suffix = std::io::Cursor::new(br#""},"rewards":{},"basis":{"pending":{}}}"#.to_vec());
    let reader = prefix.chain(middle).chain(suffix);
    let parsed = reports::parse_raw(
        reader,
        9,
        &ReportInterest::new(own()),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(parsed["account_reward"]["status"], "not_listed");
    assert!(parsed.get("unrelated").is_none());
}
#[test]
fn local_unknown_view_is_keyless_nonmutating_and_validates_page_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.state_dir = dir.path().join("never-created");
    config.network.chain = format!(
        "epoch-local-{}",
        dir.path().file_name().unwrap().to_string_lossy()
    );
    config.network.address = own();
    config.network.credential_file = dir.path().join("missing-secret");
    config.capabilities.answer.model.guidance_file = Some(dir.path().join("missing-guidance"));
    let value = epoch::view(
        &config,
        EpochQuery {
            work_epoch: Some(9),
            ..EpochQuery::default()
        },
    )
    .unwrap();
    assert_eq!(value["cache"], "not_selected");
    assert!(value["rows"].as_array().unwrap().is_empty());
    assert!(!config.state_dir.exists());
    assert!(
        epoch::view(
            &config,
            EpochQuery {
                work_epoch: Some(9),
                before: Some(0),
                ..EpochQuery::default()
            }
        )
        .is_err()
    );
    for limit in [0, 101] {
        assert!(
            epoch::view(
                &config,
                EpochQuery {
                    work_epoch: Some(9),
                    limit,
                    ..EpochQuery::default()
                }
            )
            .is_err()
        );
    }
}
#[test]
fn unsupported_authorities_never_construct_report_transport() {
    let mut config = Config::default();
    config.network.address = own();
    config.network.base_url = "https://foreign.invalid".into();
    assert!(reports::ReportSource::new(&config).is_err());
    config.network.base_url = reports::ORIGIN.into();
    config.network.chain = "other-chain".into();
    assert!(reports::ReportSource::new(&config).is_err());
}

#[test]
fn interest_and_compact_body_bounds_are_explicit_not_complete_absence() {
    let mut interest = ReportInterest::new(own());
    for n in 0..=reports::MAX_MATCHES {
        interest.add_answer(&format!("{n:064x}"));
    }
    assert_eq!(interest.answers.len(), reports::MAX_MATCHES);
    assert!(interest.truncated);
    let empty = compact(&interest, vec![]);
    assert_eq!(empty["coverage"], "partial");
    let bytes = vec![b' '; 8 * 1024 * 1024 + 1];
    let failure = reports::parse_compact("settled", 9, &interest, &bytes).unwrap_err();
    assert_eq!(failure.reason, reports::FailureReason::BodyLimit);
}

#[test]
fn expired_raw_parse_deadline_cannot_manufacture_empty_account_reward() {
    let result = reports::parse_raw(
        br#"{"epoch":9,"rewards":{},"basis":{"pending":{}}}"#.as_slice(),
        9,
        &ReportInterest::new(own()),
        Instant::now() - Duration::from_secs(1),
    );
    assert!(result.is_err());
}
