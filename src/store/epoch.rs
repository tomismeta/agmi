use super::*;
use crate::protocol::reports::ReportInterest;

impl Store {
    /// Bounded transaction interest; no account lock or transaction survives this call.
    pub(crate) fn epoch_interest(&self, account: &str) -> Result<ReportInterest> {
        let mut query = self.db.prepare("SELECT kind,txid,json_extract(request,'$.solver.assignment') FROM operations WHERE txid IS NOT NULL OR kind='judge' ORDER BY id DESC LIMIT 4097")?;
        let mut interest = ReportInterest::new(account.to_owned());
        let mut rows = query.query([])?;
        let mut count = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            if count > 4096 {
                interest.truncated = true;
                break;
            }
            let kind: String = row.get(0)?;
            let tx: Option<String> = row.get(1)?;
            let candidate: Option<String> = row.get(2)?;
            if kind == "answer"
                && let Some(tx) = tx
            {
                interest.add_answer(&tx);
            }
            if kind == "judge"
                && let Some(tx) = candidate
            {
                interest.add_candidate(&tx);
            }
        }
        Ok(interest)
    }

    pub(crate) fn epoch_page(
        &self,
        work: u64,
        exact_work: bool,
        matches: &[String],
        before: Option<i64>,
        limit: usize,
        private: bool,
    ) -> Result<Value> {
        let matches = serde_json::to_string(matches)?;
        let mut statement = self.db.prepare("SELECT o.id,o.kind,o.state,o.txid,o.job_id,
            CASE WHEN json_type(o.request,'$.solver.epoch')='integer' AND json_extract(o.request,'$.solver.epoch')>=0
            THEN json_extract(o.request,'$.solver.epoch') ELSE NULL END,json_extract(o.request,'$.solver.kind'),
            json_extract(o.request,'$.solver.assignment'),e.evidence,
            CASE WHEN ?6 THEN json_object('answer',json_extract(o.payload,'$.answer'),
            'history',json_extract(o.request,'$.solver.history'),'author_history',json_extract(o.request,'$.solver.author_history'),
            'provider',json_extract(o.result,'$.provider'),'model',json_extract(o.result,'$.model')) ELSE NULL END
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
            WHERE (?1 IS NULL OR o.id<?1) AND ((json_type(o.request,'$.solver.epoch')='integer'
              AND json_extract(o.request,'$.solver.epoch')=?2 AND json_extract(o.request,'$.solver.kind')=o.kind)
              OR (?3=0 AND (lower(o.txid) IN (SELECT value FROM json_each(?4))
                OR lower(json_extract(o.request,'$.solver.assignment')) IN (SELECT value FROM json_each(?4)))))
            ORDER BY o.id DESC LIMIT ?5")?;
        let mut rows = statement.query(params![
            before,
            i64::try_from(work).ok(),
            exact_work,
            matches,
            (limit + 1) as i64,
            private
        ])?;
        let mut output = Vec::new();
        let mut bytes = 0usize;
        let mut truncated = false;
        let mut next = None;
        while let Some(row) = rows.next()? {
            if output.len() == limit {
                truncated = true;
                break;
            }
            let id: i64 = row.get(0)?;
            let kind: String = row.get(1)?;
            let state: String = row.get(2)?;
            let tx: Option<String> = row.get(3)?;
            let job: Option<String> = row.get(4)?;
            let epoch: Option<u64> = row.get(5)?;
            let captured_kind: Option<String> = row.get(6)?;
            let candidate: Option<String> = row.get(7)?;
            let evidence: Option<String> = row.get(8)?;
            let mining = evidence
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .filter(|e| {
                    kind == "mine"
                        && e["route"] == "mine"
                        && e["status"] == 200
                        && e["mining"]["ok"] == true
                        && e["reason"] == "completed"
                        && matches!(e["stage"].as_str(), Some("submit" | "bound_job"))
                })
                .and_then(|e| e["mining"]["attested"].as_u64());
            let mut value = json!({"operation_id":id,"kind":kind,"work_epoch":epoch.filter(|_|captured_kind.as_deref()==Some(kind.as_str())),
                "local_effect":state,"inclusion":if matches!(state.as_str(),"included_pending"|"confirmed"|"final") {"observed"}else{"not_recorded"},
                "checkpoint_coverage":if state=="final"{"covered"}else{"not_recorded"},
                "mining":{"status":if mining.is_some(){"recorded"}else{"not_recorded"},"attested":mining},
                "settlement":{"status":"unknown"},"jury":null,
                "_tx":tx.as_deref().and_then(|s|crate::protocol::canonical_txid(s).ok()),
                "_candidate":candidate.as_deref().and_then(|s|crate::protocol::canonical_txid(s).ok())});
            if private {
                let material: Option<String> = row.get(9)?;
                let mut history = material
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .unwrap_or(Value::Null);
                if let Some(object) = history.as_object_mut() {
                    let available = object.values().any(|v| !v.is_null());
                    object.insert(
                        "status".into(),
                        json!(if available { "captured" } else { "unavailable" }),
                    );
                    object.insert(
                        "capture_source".into(),
                        json!("persisted_operation_payload_and_solver_context"),
                    );
                }
                value["private"] = json!({"txid":tx,"job_id":job,"candidate":candidate,"mechanism_history":history,
                    "coverage":"captured_context_not_exhaustive","automatic_answer_context_limit":8});
                let size = serde_json::to_vec(&value)?.len();
                if bytes.saturating_add(size) > 750 * 1024 {
                    value["private"] =
                        json!({"status":"unavailable","reason":"page_byte_limit","truncated":true});
                    truncated = true;
                } else {
                    bytes += size;
                }
            }
            next = Some(id);
            output.push(value);
        }
        Ok(json!({"rows":output,"next_before":if truncated{next}else{None},"truncated":truncated}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: dir.path().join("state"),
            ..Config::default()
        };
        let store = Store::open(&config).unwrap();
        (dir, store)
    }
    fn seed(
        store: &Store,
        id: i64,
        work_key: &str,
        epoch: Value,
        kind: &str,
        tx: Option<&str>,
        answer: Option<&str>,
    ) {
        let request = json!({"solver":{"epoch":epoch,"kind":kind,"history":["captured prior"],"author_history":null}});
        store.db.execute("INSERT INTO operations(id,kind,work_key,state,request,payload,txid,generation,revision,created_at,updated_at)
            VALUES (?1,?2,?3,'unknown',?4,?5,?6,0,'test',999,999)",
            params![id,kind,work_key,request.to_string(),answer.map(|a|json!({"answer":a}).to_string()),tx]).unwrap();
    }
    #[test]
    fn actual_captured_epoch_not_work_key_or_creation_time_controls_selection() {
        let (_dir, store) = fixture();
        seed(
            &store,
            1,
            "9:looks-like-epoch",
            json!(4),
            "answer",
            None,
            None,
        );
        seed(
            &store,
            2,
            "4:looks-like-epoch",
            json!(9),
            "answer",
            None,
            None,
        );
        let page = store.epoch_page(4, true, &[], None, 50, false).unwrap();
        assert_eq!(page["rows"].as_array().unwrap().len(), 1);
        assert_eq!(page["rows"][0]["operation_id"], 1);
        assert_eq!(page["rows"][0]["work_epoch"], 4);
        assert_eq!(page["rows"][0]["settlement"]["status"], "unknown");
        assert_eq!(page["rows"][0]["checkpoint_coverage"], "not_recorded");
    }
    #[test]
    fn close_selector_can_include_matched_older_work_but_both_selectors_filter_it() {
        let (_dir, store) = fixture();
        let tx = "a".repeat(64);
        seed(&store, 1, "historical", json!(4), "answer", Some(&tx), None);
        seed(&store, 2, "selected", json!(9), "answer", None, None);
        let close = store
            .epoch_page(9, false, std::slice::from_ref(&tx), None, 50, false)
            .unwrap();
        assert_eq!(close["rows"].as_array().unwrap().len(), 2);
        let both = store.epoch_page(9, true, &[tx], None, 50, false).unwrap();
        assert_eq!(both["rows"].as_array().unwrap().len(), 1);
        assert_eq!(both["rows"][0]["operation_id"], 2);
    }
    #[test]
    fn cursor_is_descending_base_id_and_private_context_is_explicit() {
        let (_dir, store) = fixture();
        for id in 1..=3 {
            seed(
                &store,
                id,
                "private-work-key",
                json!(4),
                "answer",
                None,
                Some("private answer"),
            );
        }
        let public = store.epoch_page(4, true, &[], None, 2, false).unwrap();
        assert_eq!(public["next_before"], 2);
        assert_eq!(public["rows"][0]["operation_id"], 3);
        let encoded = public.to_string();
        assert!(!encoded.contains("private answer"));
        assert!(!encoded.contains("captured prior"));
        assert!(!encoded.contains("private-work-key"));
        let private = store.epoch_page(4, true, &[], Some(2), 2, true).unwrap();
        assert_eq!(private["rows"][0]["operation_id"], 1);
        assert_eq!(
            private["rows"][0]["private"]["mechanism_history"]["answer"],
            "private answer"
        );
        assert_eq!(
            private["rows"][0]["private"]["mechanism_history"]["history"][0],
            "captured prior"
        );
        assert_eq!(
            private["rows"][0]["private"]["coverage"],
            "captured_context_not_exhaustive"
        );
        assert_eq!(private["next_before"], Value::Null);
    }
    #[test]
    fn private_page_cap_keeps_rows_and_marks_material_unavailable() {
        let (_dir, store) = fixture();
        seed(
            &store,
            1,
            "key",
            json!(4),
            "answer",
            None,
            Some(&"x".repeat(800 * 1024)),
        );
        let page = store.epoch_page(4, true, &[], None, 50, true).unwrap();
        assert_eq!(page["rows"].as_array().unwrap().len(), 1);
        assert_eq!(page["truncated"], true);
        assert_eq!(page["rows"][0]["private"]["reason"], "page_byte_limit");
        assert!(serde_json::to_vec(&page).unwrap().len() < 1024 * 1024);
    }
    #[test]
    fn mining_zero_requires_classified_completion_not_legacy_absence() {
        let (_dir, store) = fixture();
        seed(&store, 1, "mine", json!(4), "mine", None, None);
        seed(&store, 2, "mine-legacy", json!(4), "mine", None, None);
        let evidence = json!({"stage":"bound_job","route":"mine","status":200,"reason":"completed","mining":{"ok":true,"attested":0}});
        store
            .db
            .execute(
                "INSERT INTO operation_evidence(operation_id,evidence) VALUES (1,?1)",
                [evidence.to_string()],
            )
            .unwrap();
        let page = store.epoch_page(4, true, &[], None, 50, false).unwrap();
        assert_eq!(page["rows"][0]["mining"]["status"], "not_recorded");
        assert!(page["rows"][0]["mining"]["attested"].is_null());
        assert_eq!(page["rows"][1]["mining"]["status"], "recorded");
        assert_eq!(page["rows"][1]["mining"]["attested"], 0);
        let mut bad = evidence;
        bad["stage"] = json!("receipt");
        store
            .db
            .execute(
                "UPDATE operation_evidence SET evidence=?1 WHERE operation_id=1",
                [bad.to_string()],
            )
            .unwrap();
        assert_eq!(
            store.epoch_page(4, true, &[], None, 50, false).unwrap()["rows"][1]["mining"]["status"],
            "not_recorded"
        );
    }
}
