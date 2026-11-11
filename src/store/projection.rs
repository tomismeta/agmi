use super::*;
use crate::endpoints::Endpoint;

impl Store {
    fn lane_participation_projection(
        &self,
        stopped: bool,
        operation_counts: &[Value],
        policy: Option<&Value>,
    ) -> Result<Value> {
        let stored: Option<String> = self
            .db
            .query_row(
                "SELECT lane_participation FROM runtime_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let assessments: Value = stored
            .map(|value| serde_json::from_str(&value))
            .transpose()?
            .unwrap_or(Value::Null);
        let mut result = json!({});
        for lane in LaneId::ALL {
            let entry = &assessments[lane.as_str()];
            let assessment = &entry["assessment"];
            let stamp = &entry["stamp"];
            let (generation, revision, authority): (i64, i64, Option<u64>) = self.db.query_row(
                "SELECT c.generation,l.control_revision,(SELECT authority_epoch FROM runtime_authority WHERE singleton=1)
                 FROM control c JOIN lane_control l ON l.lane=?1 WHERE c.singleton=1",
                [lane.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            let current_stamp = stamp["account_generation"].as_i64() == Some(generation)
                && stamp["lane_control_revision"].as_i64() == Some(revision)
                && authority.is_some()
                && stamp["authority_epoch"].as_u64() == authority
                && stamp["lane_config_revision"]
                    .as_str()
                    .is_some_and(|revision| {
                        policy.and_then(|p| p["lane_revisions"][lane.as_str()].as_str())
                            == Some(revision)
                    });
            let current = now();
            let freshness = if stopped {
                "stopped"
            } else if assessment.is_null() {
                "unobserved"
            } else if current_stamp
                && assessment["source"].is_string()
                && assessment["observed_at"]
                    .as_i64()
                    .is_some_and(|at| at >= 0 && at <= current)
                && assessment["valid_until"]
                    .as_i64()
                    .is_some_and(|until| until > current)
            {
                "current_observation"
            } else {
                "stale"
            };
            let outcomes: Vec<_> = operation_counts
                .iter()
                .filter(|row| row["kind"] == lane.as_str())
                .map(|row| json!({"state":row["state"],"count":row["count"]}))
                .collect();
            result[lane.as_str()] = json!({"assessment":assessment,"stamp":stamp,"freshness":freshness,
                "source":"journal_and_runtime_snapshot","model_attempts":0,"model_outcomes":[],
                "operation_outcomes":outcomes,"correctness":"not_verified","payment":"not_verified","finality":"not_verified"});
        }
        let mut statement = self.db.prepare(
            "SELECT o.kind,json_extract(e.model_attempt,'$.completion.outcome'),COUNT(*)
             FROM operation_evidence e JOIN operations o ON o.id=e.operation_id
             WHERE e.model_attempt IS NOT NULL GROUP BY o.kind,json_extract(e.model_attempt,'$.completion.outcome')")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let lane: String = row.get(0)?;
            let count: u64 = row.get(2)?;
            let entry = result
                .get_mut(&lane)
                .context("invalid model-attempt lane")?;
            entry["model_attempts"] = json!(entry["model_attempts"].as_u64().unwrap_or(0) + count);
            entry["model_outcomes"]
                .as_array_mut()
                .context("model outcomes missing")?
                .push(json!({"outcome":row.get::<_,Option<String>>(1)?,"count":count}));
        }
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn admission_projection(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
        op: Option<&Operation>,
    ) -> Result<Value> {
        let snapshot = accounting::AccountingReadSnapshot::load(&self.db, config)?;
        self.admission_projection_with(config, kind, epoch, op, &snapshot)
            .map(|projection| projection.value)
    }

    fn admission_projection_with(
        &self,
        config: &Config,
        kind: LaneId,
        epoch: Option<u64>,
        op: Option<&Operation>,
        snapshot: &accounting::AccountingReadSnapshot,
    ) -> Result<accounting::AdmissionProjection> {
        let cache_epoch = (config.participation(kind).mode == ParticipationMode::Manual)
            .then_some(epoch)
            .flatten();
        if op.is_none()
            && let Some(value) = snapshot.admissions.borrow().get(&(kind, cache_epoch))
        {
            return Ok(value.clone());
        }
        let cutoff = snapshot.cutoff;
        let retry_of = op
            .map(|op| {
                self.db
                    .query_row(
                        "SELECT retry_of FROM operation_links WHERE operation_id=?1",
                        [op.id],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()
            })
            .transpose()?
            .flatten();
        let accounting = snapshot.accounting(&self.db, config, kind, op.map(|o| o.id), retry_of)?;
        let policy = config.participation(kind);
        let control = self.control()?;
        let mut blocker =
            self.uncertainty_blocker_with_at(config, kind, epoch, &accounting, cutoff)?;
        if let Some(op) = op {
            let own_floor:i64=self.db.query_row("SELECT COALESCE((SELECT retry_not_before FROM operation_timing WHERE operation_id=?1),0)",[op.id],|r|r.get(0))?;
            if own_floor > cutoff.at {
                blocker = Some(("operation_retry_minimum", Some(own_floor)));
            } else if op.next_at > cutoff.at {
                blocker = Some(("operation_backoff", Some(op.next_at)));
            } else if blocker.is_none()
                && accounting::risk_decision_with(&self.db, config, op, cutoff, Some(snapshot))?
                    .is_none()
            {
                blocker = Some(("request_eligibility", None));
            }
            if op.generation != control.generation {
                blocker = Some(("generation_changed", None));
            }
        }
        let reload: bool = self.db.query_row(
            "SELECT COALESCE((SELECT reload_blocked FROM runtime_state WHERE singleton=1),0)",
            [],
            |r| r.get(0),
        )?;
        let identity_rejected: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosted_identity_evidence WHERE rejection IS NOT NULL)",
            [],
            |r| r.get(0),
        )?;
        if identity_rejected {
            blocker = Some(("identity_rejected", None));
        }
        // Preserve eligibility before control/mode/reload intent overlays. This
        // remains diagnostic evidence, never an independent admission permit.
        let pre_intent_blocker = blocker;
        if reload {
            blocker = Some(("config_reload_rejected", None));
        }
        if config.mode(kind) != Mode::Active {
            blocker = Some(("capability_not_active", None));
        }
        let lane_paused: bool = self.db.query_row(
            "SELECT paused FROM lane_control WHERE lane=?1",
            [kind.as_str()],
            |r| r.get(0),
        )?;
        if lane_paused {
            blocker = Some(("lane_paused", None));
        }
        if control.paused {
            blocker = Some(("admission_paused", None));
        }
        let reason = blocker.map(|b| b.0);
        let lane = reason == Some("lane_unresolved_capacity");
        let required_release = match reason {
            Some("lane_unresolved_capacity") => accounting
                .active()
                .saturating_add(1)
                .saturating_sub(u64::from(policy.max_unresolved_operations)),
            Some("account_uncertainty" | "manual_authorization_required") => accounting.total,
            Some("effect_in_flight") => 1,
            _ => 0,
        };
        let blockers = if lane {
            &accounting.own_blockers
        } else {
            &accounting.blockers
        };
        let value = json!({"allowed":blocker.is_none(),"reason":reason,
            "scope":match reason {
                Some("lane_unresolved_capacity"|"capability_not_active"|"lane_paused")=>"lane",
                Some("operation_retry_minimum"|"operation_backoff"|"generation_changed"|"request_eligibility")=>"operation",
                Some("shared_server_restriction"|"retained_legacy_floor")=>accounting.restriction_scope.as_deref().unwrap_or("account"),
                _=>"account"},
            "blocker_ids":blockers,"required_release":required_release,"not_before":blocker.and_then(|b|b.1),
            "blocker_ids_truncated":(if lane{accounting.active()}else{accounting.total})>blockers.len() as u64,
            "next_at":blocker.and_then(|b|b.1),"own_count":accounting.active(),"own_limit":policy.max_unresolved_operations,
            "own_remaining":u64::from(policy.max_unresolved_operations).saturating_sub(accounting.active()),
            "account_unresolved":accounting.total,"historical_eligible_count":accounting.eligible,
            "capacity_exempt_count":accounting.exempt,"historical_unknown_answers":accounting.historical,
            "historical_unknown_answers_truncated":accounting.exempt>accounting.historical.len() as u64});
        let projection = accounting::AdmissionProjection {
            value,
            pre_intent_blocker,
        };
        if op.is_none() {
            snapshot
                .admissions
                .borrow_mut()
                .insert((kind, cache_epoch), projection.clone());
        }
        Ok(projection)
    }

    fn current_read_projection(&self) -> Result<(Value, bool)> {
        let identity: String =
            self.db
                .query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let identity: Value = serde_json::from_str(&identity)?;
        let authority = format!(
            "{}\n{}",
            identity["chain"]
                .as_str()
                .context("journal chain missing")?,
            identity["address"]
                .as_str()
                .context("journal address missing")?
        );
        let origin = reqwest::Url::parse(
            identity["base_url"]
                .as_str()
                .context("journal origin missing")?,
        )?
        .origin()
        .ascii_serialization();
        let shared: i64 = self.db.query_row(
            "SELECT COALESCE(MAX(not_before),0) FROM request_restrictions
            WHERE authority=?1 AND origin=?2 AND scope='account_authenticated' AND read_class=1",
            params![authority, origin],
            |r| r.get(0),
        )?;
        let mut stmt=self.db.prepare("SELECT owner,purpose,resource,operation_id,binding_revision,remote_resource,retired,
            failures,in_flight,started_at,finished_at,last_http_success_at,last_success_at,last_failure_at,failure_category,status,
            local_next_at,server_not_before,retained_conservative_floor FROM read_state r WHERE retired=0
            AND (operation_id IS NULL OR EXISTS(SELECT 1 FROM operations o WHERE o.id=r.operation_id
                AND o.binding_revision=r.binding_revision AND o.state IN ('queued','unknown','included_pending','confirmed')))
            AND (purpose!='assignment' OR in_flight=1 OR EXISTS(SELECT 1 FROM operations o
                WHERE o.kind='judge' AND o.work_key=r.resource AND o.state IN ('generating','generated','prepared','retry','dispatching','queued','unknown','included_pending','confirmed')))
            ORDER BY CASE WHEN purpose='identity' THEN 0 WHEN purpose='discovery' THEN 1 ELSE 2 END,
                in_flight DESC,CASE WHEN operation_id IS NOT NULL THEN 0 ELSE 1 END,owner,purpose,resource LIMIT 257")?;
        let mut rows=stmt.query_map([],|r|{
            let local:i64=r.get(16)?;let server:i64=r.get(17)?;let legacy:i64=r.get(18)?;
            let next=local.max(server).max(legacy).max(shared);
            let category:Option<String>=r.get(14)?;
            Ok(json!({"owner":r.get::<_,String>(0)?,"purpose":r.get::<_,String>(1)?,"resource":r.get::<_,String>(2)?,
                "operation_id":r.get::<_,Option<i64>>(3)?,"binding_revision":r.get::<_,Option<i64>>(4)?,
                "remote_resource_digest":r.get::<_,Option<String>>(5)?.map(digest),"retired":r.get::<_,bool>(6)?,
                "failures":r.get::<_,u32>(7)?,"state":if r.get::<_,bool>(8)?{"in_flight"}else{"idle"},
                "started_at":r.get::<_,Option<i64>>(9)?,"finished_at":r.get::<_,Option<i64>>(10)?,
                "last_http_success_at":r.get::<_,Option<i64>>(11)?,"last_success_at":r.get::<_,Option<i64>>(12)?,
                "last_failure_at":r.get::<_,Option<i64>>(13)?,"failure_category":category.as_deref().map(safe_read_category),
                "status":r.get::<_,Option<u16>>(15)?,"local_next_at":local,"server_not_before":server,
                "retained_conservative_floor":legacy,"shared_not_before":shared,
                "next_at":next,"due_in_seconds":next.saturating_sub(now()).max(0)}))
        })?.collect::<std::result::Result<Vec<_>,_>>()?;
        let truncated = rows.len() > 256;
        rows.truncate(256);
        Ok((json!(rows), truncated))
    }

    pub(crate) fn reads_projection(&self) -> Result<Value> {
        let (reads, reads_truncated) = self.current_read_projection()?;
        Ok(json!({"reads":reads,"reads_truncated":reads_truncated}))
    }

    fn work_projection(
        &self,
        config: &Config,
        lane_revisions: &Value,
        stopped: bool,
        reload: bool,
        accounting: &accounting::AccountingReadSnapshot,
    ) -> Result<Value> {
        let control = self.control()?;
        let waits = self.wait_evidence()?;
        let mut work = json!({});
        for kind in LaneId::ALL {
            let observation = self.lane_observation(kind)?;
            let epoch = observation.as_ref().and_then(|o| o["epoch"].as_u64());
            let id:Option<i64>=self.db.query_row("SELECT id FROM operations WHERE kind=?1
                AND state IN ('generating','generated','prepared','retry','dispatching','queued','unknown','included_pending','confirmed','model_unknown')
                ORDER BY CASE WHEN state IN ('generating','generated','prepared','retry') THEN 0 ELSE 1 END,id DESC LIMIT 1",
                [kind.as_str()],|r|r.get(0)).optional()?;
            let op = id.map(|id| self.operation(id)).transpose()?.flatten();
            let admission = self
                .admission_projection_with(
                    config,
                    kind,
                    epoch,
                    op.as_ref()
                        .filter(|o| matches!(o.state.as_str(), "prepared" | "generated" | "retry")),
                    accounting,
                )?
                .value;
            let key =
                op.as_ref()
                    .and_then(Self::operation_read_key)
                    .unwrap_or(ReadKey::Discovery {
                        lane: kind,
                        source: if kind == LaneId::Judge {
                            DiscoverySource::Assignments
                        } else {
                            DiscoverySource::Challenge
                        },
                    });
            let backoff = self.read_backoff(&key)?;
            let discovery_at = if matches!(key, ReadKey::Discovery { .. }) {
                self.discovery_next_at(config, kind, &backoff)?
            } else {
                backoff.next_at
            };
            let mut next = Some(discovery_at.max(now()));
            let (mut phase, mut reason, mut action) =
                ("observing", "observation_due", "observe_challenge");
            if kind == LaneId::Judge {
                action = "observe_assignments";
            }
            let read_key = self.read_key_projection(&key)?;
            let in_flight: bool = self.db.query_row(
                "SELECT COALESCE((SELECT in_flight FROM read_state
                WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0),0)",
                params![
                    read_key["owner"].as_str(),
                    read_key["purpose"].as_str(),
                    read_key["resource"].as_str()
                ],
                |r| r.get(0),
            )?;
            if in_flight {
                reason = "read_in_flight";
                next = None;
            } else if backoff.next_at > now() || (backoff.failures > 0 && discovery_at > now()) {
                reason = "read_backoff";
            } else if discovery_at > now() {
                reason = "cadence";
            }
            if let Some(op) = &op {
                next = Some(op.next_at.max(backoff.next_at).max(now()));
                match op.state.as_str() {
                    "generating" => {
                        let pending:bool=self.db.query_row("SELECT COALESCE(json_extract(evidence,'$.state')='awaiting_admission',0)
                            FROM operation_evidence WHERE operation_id=?1",[op.id],|r|r.get(0)).optional()?.unwrap_or(false);
                        phase = if pending {
                            "awaiting_admission"
                        } else {
                            "preparing"
                        };
                        reason = if pending {
                            "awaiting_admission"
                        } else {
                            "model_running"
                        };
                        action = if pending {
                            "revalidate_launch_gate"
                        } else {
                            "await_model"
                        };
                        next = None;
                    }
                    "generated" | "prepared" | "retry" => {
                        phase = "prepared";
                        reason = "fresh_evidence_required";
                        action = "revalidate_request";
                        // Targeted revalidation bypasses ordinary discovery cadence,
                        // but not the canonical read retry or API restriction.
                        let endpoint = if kind == LaneId::Judge {
                            Endpoint::Assignments
                        } else {
                            Endpoint::Challenge
                        };
                        next = (!in_flight).then_some(
                            op.next_at
                                .max(backoff.next_at)
                                .max(self.request_not_before(config, endpoint, None)?)
                                .max(now()),
                        );
                        if admission["allowed"] == false {
                            phase = "blocked";
                            reason = admission["reason"]
                                .as_str()
                                .unwrap_or("request_eligibility");
                            action = if reason == "manual_authorization_required" {
                                "authorize"
                            } else {
                                "await_reconciliation"
                            };
                            next = next.and_then(|read_at| {
                                admission["not_before"].as_i64().map(|at| at.max(read_at))
                            });
                        }
                    }
                    "dispatching" => {
                        phase = "dispatching";
                        reason = "effect_in_flight";
                        action = "await_effect";
                        next = None;
                    }
                    "queued" | "unknown" | "included_pending" | "confirmed" => {
                        phase = if op.state == "confirmed" {
                            "included"
                        } else {
                            op.state.as_str()
                        };
                        reason = "authoritative_evidence_required";
                        action = if op.txid.is_some() {
                            "read_receipt"
                        } else if op.job_id.is_some() {
                            "read_job"
                        } else {
                            "authoritative_recovery"
                        };
                        if op.txid.is_none() && op.job_id.is_none() {
                            next = None;
                        }
                    }
                    "model_unknown" => {
                        phase = "blocked";
                        reason = "model_uncertain";
                        action = "recover_model";
                        next = None;
                    }
                    _ => {}
                }
            } else if admission["allowed"] == false
                && config.preparation(kind).is_none_or(|p| !p.while_blocked)
            {
                phase = "blocked";
                reason = admission["reason"]
                    .as_str()
                    .unwrap_or("request_eligibility");
                action = "await_reconciliation";
                next = admission["not_before"].as_i64();
            }
            if observation.as_ref().is_some_and(|o| o["answered"] == true)
                && kind == LaneId::Answer
                && op.is_none()
            {
                phase = "answered";
                reason = "hosted_answer_observed";
            }
            if config.mode(kind) == Mode::ReadOnly {
                phase = "read_only";
                reason = "capability_read_only";
            }
            if stopped {
                phase = "stopped";
                reason = "controller_stopped";
                action = "start_controller";
                next = None;
            }
            if reload {
                phase = "blocked";
                reason = "config_reload_rejected";
                action = "repair_config";
                next = None;
            }
            let lane_paused: bool = self.db.query_row(
                "SELECT paused FROM lane_control WHERE lane=?1",
                [kind.as_str()],
                |r| r.get(0),
            )?;
            if lane_paused {
                phase = "paused";
                reason = "lane_paused";
                action = "resume_lane";
                next = None;
            }
            if control.paused {
                phase = "paused";
                reason = "admission_paused";
                action = "resume";
                next = None;
            }
            if config.mode(kind) == Mode::Off {
                phase = "off";
                reason = "capability_off";
                action = "enable_capability";
                next = None;
            }
            let mut lane = json!({"phase":phase,"reason":reason,"next_action":action,"next_at":next,"epoch":epoch,
                "operation_id":id,"operation_epoch":op.as_ref().and_then(|o|o.request["solver"]["epoch"].as_u64()),
                "binding_revision":op.as_ref().map(|o|o.binding_revision),"read_key":self.read_key_projection(&key)?,
                "admission":admission,"manual_authorized":self.manual_authorized(kind,epoch)?});
            let effect_since = id
                .map(|id| {
                    self.db
                        .query_row(
                            "SELECT blocked_since FROM operation_evidence WHERE operation_id=?1",
                            [id],
                            |r| r.get::<_, Option<i64>>(0),
                        )
                        .optional()
                })
                .transpose()?
                .flatten()
                .flatten();
            lane["wait"] = waits
                .get(&id.unwrap_or(-1))
                .unwrap_or(&WaitEvidence::default())
                .projection(
                    op.as_ref().map_or("", |o| o.state.as_str()),
                    effect_since,
                    now(),
                );
            if let Some(preparation) = config.preparation(kind) {
                let latest:Option<(i64,String,String,Option<String>,String)>=self.db.query_row(
                    "SELECT o.id,o.work_key,o.state,e.evidence,o.revision FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
                     WHERE o.kind=?1 AND o.generation=?2 AND o.payload IS NULL AND o.job_id IS NULL AND o.txid IS NULL
                     AND o.state IN ('model_unknown','superseded_model_unknown','rejected','retry_model','prelaunch_failed') ORDER BY o.id DESC LIMIT 1",
                    params![kind.as_str(),control.generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
                if let Some((id, key, state, evidence, revision)) = latest {
                    let used = self.model_budget_used(kind, &key)?;
                    let evidence = evidence.and_then(|e| serde_json::from_str::<Value>(&e).ok());
                    lane["model"] = json!({"operation_id":id,"state":state,"budget_used":used,"budget_limit":preparation.max_attempts_per_work,
                        "retry_eligible":used<preparation.max_attempts_per_work&&(state!="model_unknown"||preparation.retry_uncertain),
                        "failure_category":evidence.as_ref().and_then(|e|e["reason"].as_str()).map(|reason|
                            match reason {"model_unknown"|"model_spawn_failed"|"model_rejected"|"model_timeout"|"invalid_model_output"|"cancelled"=>reason,_=>"model_failure"}),
                        "current_route":lane_revisions[kind.as_str()].as_str().map(|current| revision==current),
                        "scope":if kind==LaneId::Answer{"current_work"}else{"historical_assignment"}});
                }
            }
            if kind == LaneId::Answer {
                let original = epoch
                    .map(|epoch| self.uncertain_answer(epoch))
                    .transpose()?
                    .flatten();
                if let Some(original) = original {
                    let retry_epoch = original.request["solver"]["epoch"]
                        .as_u64()
                        .context("answer epoch missing")?;
                    let blocker = if let Some(reason) =
                        Self::answer_retry_policy_blocker(&self.db, config, retry_epoch, None)?
                    {
                        Some((reason, None))
                    } else {
                        let totals = accounting.accounting(
                            &self.db,
                            config,
                            kind,
                            None,
                            Some(original.id),
                        )?;
                        self.uncertainty_blocker_with(config, kind, Some(retry_epoch), &totals)?
                    };
                    let discovery = ReadKey::Discovery {
                        lane: kind,
                        source: DiscoverySource::Challenge,
                    };
                    let discovery_backoff = if matches!(key, ReadKey::Discovery { .. }) {
                        backoff
                    } else {
                        self.read_backoff(&discovery)?
                    };
                    let discovery_at = self.discovery_next_at(config, kind, &discovery_backoff)?;
                    let discovery_flight: bool = self.db.query_row(
                        "SELECT COALESCE((SELECT in_flight FROM read_state
                        WHERE owner='answer' AND purpose='discovery' AND resource='challenge'),0)",
                        [],
                        |r| r.get(0),
                    )?;
                    let (mut retry_reason, mut retry_at) = blocker
                        .unwrap_or(("fresh_evidence_required", Some(now().max(discovery_at))));
                    if blocker.is_none() {
                        if observation.as_ref().is_some_and(|o| o["answered"] == true) {
                            retry_reason = "hosted_answer_observed";
                        } else if discovery_flight {
                            retry_reason = "freshness_in_flight";
                            retry_at = None;
                        } else if discovery_backoff.next_at > now()
                            || (discovery_backoff.failures > 0 && discovery_at > now())
                        {
                            retry_reason = "read_backoff";
                            retry_at = Some(discovery_at);
                        }
                    }
                    if stopped
                        || reload
                        || control.paused
                        || lane_paused
                        || config.mode(kind) != Mode::Active
                    {
                        retry_reason = reason;
                        retry_at = next;
                    }
                    lane["retry"] = json!({"original_operation_id":original.id,"policy_eligible":blocker.is_none(),
                        "reason":retry_reason,"next_at":retry_at,
                        "next_action":if blocker.is_none(){"revalidate_challenge"}else{"await_retry_eligibility"},
                        "requires_fresh_eligibility":true,"manual_authorized":self.manual_authorized(kind,epoch)?});
                }
            }
            if kind == LaneId::Judge {
                let raw: Option<String> = self.db.query_row(
                    "SELECT json_extract(lane_participation,'$.judge') FROM runtime_state WHERE singleton=1",
                    [], |r| r.get(0)).optional()?.flatten();
                let record = raw
                    .map(|raw| serde_json::from_str::<Value>(&raw))
                    .transpose()?;
                lane["assessment"] = Value::Null;
                if let Some(record) = record {
                    let stamp: AdmissionStampSnapshot =
                        serde_json::from_value(record["stamp"].clone())?;
                    if Self::observation_stamp_matches(&self.db, kind, &stamp)? {
                        lane["assessment"] = record["assessment"].clone();
                    }
                }
                if op.is_none()
                    && lane["assessment"]["locally_judgeable"] == false
                    && !in_flight
                    && backoff.next_at <= now()
                    && lane["phase"] == "observing"
                {
                    lane["reason"] = json!("no_eligible_in_observed_inventory");
                }
            }
            work[kind.as_str()] = lane;
        }
        Ok(work)
    }

    pub(crate) fn status(&self, config: &Config) -> Result<Value> {
        let snapshot = self.db.unchecked_transaction()?;
        let control = self.control()?;
        let stored_identity: String =
            self.db
                .query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let stored: Value = serde_json::from_str(&stored_identity)?;
        let mut stmt = self.db.prepare(
            "SELECT kind,state,COUNT(*) FROM operations GROUP BY kind,state ORDER BY kind,state",
        )?;
        let counts=stmt.query_map([],|r|Ok(json!({"kind":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"count":r.get::<_,u64>(2)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let runtime:Option<(String,bool,String,i64)>=self.db.query_row("SELECT effective_revision,reload_blocked,capabilities,observed_at FROM runtime_state WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let policy: Option<String> = self
            .db
            .query_row(
                "SELECT policy FROM runtime_policy WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let policy = policy
            .map(|p| serde_json::from_str::<Value>(&p))
            .transpose()?;
        let mut effective_config = None;
        let effective=runtime.as_ref().map(|(revision,reload,capabilities,at)| -> Result<Value>{
            if let Some(policy)=&policy
                && policy["schema_version"]==2 {
                let mut captured=config.clone();
                captured.network.chain=stored["chain"].as_str().context("journal chain missing")?.to_owned();
                captured.network.address=stored["address"].as_str().context("journal address missing")?.to_owned();
                captured.network.base_url=stored["base_url"].as_str().context("journal origin missing")?.to_owned();
                captured.capabilities=serde_json::from_value(policy["capabilities"].clone())?;
                captured.identity=serde_json::from_value(policy["identity"].clone())?;
                captured.runtime=serde_json::from_value(policy["runtime"].clone())?;
                effective_config=Some(captured);
            }
            Ok(json!({"revision":revision,"reload_blocked":reload,"capabilities":serde_json::from_str::<Value>(capabilities)?,"observed_at":at,"policy":policy}))
        }).transpose()?;
        let stopped: bool = self.db.query_row(
            "SELECT COALESCE((SELECT controller_stopped FROM runtime_state WHERE singleton=1),0)",
            [],
            |r| r.get(0),
        )?;
        let reload = runtime.as_ref().is_some_and(|r| r.1);
        let mut observations = json!({});
        for kind in [LaneId::Answer, LaneId::Mine] {
            let mut observation = self.lane_observation(kind)?.unwrap_or(Value::Null);
            if let Some(object) = observation.as_object_mut() {
                object.remove("challenge");
            }
            observations[kind.as_str()] = observation;
        }
        let observed = [&observations["answer"], &observations["mine"]]
            .into_iter()
            .filter(|v| v["epoch"].is_u64())
            .max_by_key(|v| v["epoch"].as_u64())
            .cloned();
        let answer = &observations["answer"];
        let hosted_identity = Self::hosted_identity(&self.db)?;
        let identity_verified = if !hosted_identity["rejection"].is_null() {
            Some(false)
        } else if hosted_identity["status"] == "verified" {
            Some(true)
        } else {
            None
        };
        let accounting = effective_config
            .as_ref()
            .map(|config| accounting::AccountingReadSnapshot::load(&self.db, config))
            .transpose()?;
        let mut work = if let Some(captured) = &effective_config {
            self.work_projection(
                captured,
                policy
                    .as_ref()
                    .and_then(|value| value.get("lane_revisions"))
                    .unwrap_or(&Value::Null),
                stopped,
                reload,
                accounting
                    .as_ref()
                    .context("effective accounting missing")?,
            )?
        } else {
            json!({})
        };
        let mut lanes = json!({});
        let mut affected = Vec::new();
        for kind in LaneId::ALL {
            if let Some(policy) = &effective_config {
                let epoch = observations[kind.as_str()]["epoch"].as_u64();
                let projection = self.admission_projection_with(
                    policy,
                    kind,
                    epoch,
                    None,
                    accounting
                        .as_ref()
                        .context("effective accounting missing")?,
                )?;
                let mut value = projection.value;
                value["pre_intent_blocker"] = projection
                    .pre_intent_blocker
                    .map(|(reason, not_before)| json!({"reason":reason,"not_before":not_before}))
                    .unwrap_or(Value::Null);
                if policy.mode(kind) == Mode::Active && value["allowed"] == false {
                    affected.push(kind.as_str());
                }
                lanes[kind.as_str()] = value;
            } else {
                work[kind.as_str()] = json!({"phase":"unknown","reason":"effective_policy_unavailable","admission":null});
                lanes[kind.as_str()] = Value::Null;
            }
        }
        let mut pending_work = Vec::new();
        let mut captured_work = Vec::new();
        let mut statement=self.db.prepare("SELECT o.id,o.kind,o.state,o.created_at,o.updated_at,o.next_at,o.revision,o.generation,o.binding_revision,
            e.model_deadline,e.http_deadline,e.blocked_since,e.evidence,e.policy,COALESCE(t.retry_not_before,0),
            e.model_attempt,o.job_id IS NOT NULL,o.txid IS NOT NULL,o.request -> '$.solver.epoch'
            FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id LEFT JOIN operation_timing t ON t.operation_id=o.id
            WHERE o.state IN ('generating','generated','prepared','retry','dispatching','queued','unknown','included_pending','confirmed') ORDER BY o.id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let kind = match row.get_ref(1)?.as_str()? {
                "answer" => LaneId::Answer,
                "judge" => LaneId::Judge,
                "mine" => LaneId::Mine,
                _ => bail!("invalid pending operation lane"),
            };
            let state: String = row.get(2)?;
            let candidate = if matches!(state.as_str(), "generated" | "prepared" | "retry") {
                Some(self.operation(id)?.context("pending operation missing")?)
            } else {
                None
            };
            let phase = if row.get::<_, bool>(17)? {
                Some("receipt")
            } else if row.get::<_, bool>(16)? {
                Some("job")
            } else {
                None
            };
            let binding_revision: i64 = row.get(8)?;
            let read_key = phase.map(|phase| {
                json!({"owner":kind.as_str(),"purpose":phase,
                "resource":format!("{id}:{binding_revision}")})
            });
            let captured_policy: Option<Value> = row
                .get::<_, Option<String>>(13)?
                .map(|policy| serde_json::from_str(&policy))
                .transpose()?;
            let mut entry = json!({"operation_id":id,"kind":kind,"state":state,"created_at":row.get::<_,i64>(3)?,"updated_at":row.get::<_,i64>(4)?,
                "next_at":row.get::<_,i64>(5)?,"captured_revision":row.get::<_,String>(6)?,"captured_generation":row.get::<_,i64>(7)?,
                "binding_revision":row.get::<_,i64>(8)?,"model_deadline":row.get::<_,Option<i64>>(9)?,"http_deadline":row.get::<_,Option<i64>>(10)?,
                "blocked_since":row.get::<_,Option<i64>>(11)?,"retry_not_before":row.get::<_,i64>(14)?,
                "read_key":read_key,"reconciliation_scope":phase,
                "model_attempt":row.get::<_,Option<String>>(15)?.map(|s|serde_json::from_str::<Value>(&s)).transpose()?});
            entry["pending_execution_deadline"] = captured_policy
                .as_ref()
                .and_then(|policy| policy["pending_execution_deadline"].as_i64())
                .map_or(Value::Null, Value::from);
            if let Some(evidence) = row.get::<_, Option<String>>(12)? {
                entry["diagnostic"] = serde_json::from_str(&evidence)?;
            }
            if let Some(policy) = &effective_config {
                let accounting = accounting
                    .as_ref()
                    .context("effective accounting missing")?;
                entry["capacity_counted"] = json!(accounting.capacity_counted(policy, kind, id));
                let epoch = row
                    .get::<_, Option<String>>(18)?
                    .map(|value| serde_json::from_str::<Value>(&value))
                    .transpose()?
                    .and_then(|value| value.as_u64());
                entry["admission"] = self
                    .admission_projection_with(policy, kind, epoch, candidate.as_ref(), accounting)?
                    .value;
            } else {
                entry["capacity_counted"] = Value::Null;
                entry["admission"] = Value::Null;
            }
            if matches!(
                state.as_str(),
                "generating" | "generated" | "prepared" | "retry"
            ) {
                let mut captured = entry.clone();
                if let Some(policy) = &captured_policy {
                    captured["captured_policy"] = json!({"model":policy["model"]["model"],"harness":policy["model"]["harness"],
                        "reasoning":policy["model"]["reasoning"],"model_seconds":policy["model_seconds"],"attempt":policy["attempt"]});
                }
                captured_work.push(captured);
            }
            pending_work.push(entry);
        }
        let pending = pending_work
            .iter()
            .find(|p| {
                matches!(
                    p["state"].as_str(),
                    Some("dispatching" | "queued" | "unknown" | "included_pending")
                )
            })
            .or(pending_work.first());
        let unresolved: u64 = counts
            .iter()
            .filter(|row| {
                matches!(
                    row["state"].as_str(),
                    Some("dispatching" | "queued" | "unknown" | "included_pending")
                )
            })
            .map(|row| row["count"].as_u64().expect("grouped operation count"))
            .sum();
        let risk_admissions: u64 =
            self.db
                .query_row("SELECT COUNT(*) FROM risk_admissions", [], |r| r.get(0))?;
        let oldest = self.effect()?;
        let oldest_since=oldest.as_ref().map(|op|self.db.query_row("SELECT COALESCE(e.blocked_since,o.created_at) FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id WHERE o.id=?1",[op.id],|r|r.get::<_,i64>(0))).transpose()?;
        let last_progress:Option<i64>=self.db.query_row("SELECT MAX(updated_at) FROM operations WHERE state IN ('confirmed','final','completed')",[],|r|r.get(0))?;
        let safety: Option<i64> = self.db.query_row(
            "SELECT MAX(safety_observed_at) FROM operation_evidence",
            [],
            |r| r.get(0),
        )?;
        let last_event: Option<String> = self
            .db
            .query_row(
                "SELECT code FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let migration = if self.has_table("capability_migration")? {
            self.db
                .query_row(
                    "SELECT phase FROM capability_migration WHERE singleton=1",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
                .map(|phase| json!({"pending":phase!="complete","phase":phase}))
                .unwrap_or(json!({"pending":false}))
        } else {
            json!({"pending":false})
        };
        let legacy = if self.has_table("legacy_observation")? {
            self.db.query_row("SELECT epoch,observed_at FROM legacy_observation WHERE singleton=1",[],|r|Ok(json!({"epoch":r.get::<_,u64>(0)?,"observed_at":r.get::<_,i64>(1)?,"basis":"unattributed_legacy"}))).optional()?
        } else {
            None
        };
        let mut restrictions=self.db.prepare("SELECT scope,basis,not_before,observed_at,source,server_minimum_seconds,policy FROM request_restrictions WHERE not_before>?1 ORDER BY not_before DESC")?;
        let restrictions=restrictions.query_map([now()],|r|Ok(json!({"scope":r.get::<_,String>(0)?,"basis":r.get::<_,String>(1)?,"not_before":r.get::<_,i64>(2)?,
            "observed_at":r.get::<_,i64>(3)?,"source":r.get::<_,String>(4)?,"server_minimum_seconds":r.get::<_,Option<u64>>(5)?,"policy":r.get::<_,Option<String>>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let (reads, reads_truncated) = self.current_read_projection()?;
        let mut lane_controls = json!({});
        for lane in LaneId::ALL {
            lane_controls[lane.as_str()] = Self::lane_control_projection(&self.db, lane)?;
        }
        let lane_participation =
            self.lane_participation_projection(stopped, &counts, policy.as_ref())?;
        let participation = json!({"policy_source":if effective_config.is_some(){"effective"}else{"unavailable"},
            "unresolved_count":unresolved,"risk_admissions":risk_admissions,"lanes":lanes});
        let epoch_evidence =
            json!({"first_observed_at":answer["first_observed_at"],"answered":answer["answered"]});
        let mut status = json!({"initialized":true,"paused":control.paused,"generation":control.generation,"journal_schema":self.schema_version()?,
            "identity_fingerprint":digest(format!("{}\n{}",stored["chain"].as_str().unwrap_or_default(),stored["address"].as_str().unwrap_or_default())),
            "chain":stored["chain"],"identity_matches_config":stored_identity==identity(config)?,"capabilities":config.capabilities,
            "configured_revision":config.optional_revision()?,"effective_runtime":effective,"network_routing":self.routing_status(config)?,
            "controller_stopped":stopped,"hosted_identity":hosted_identity,"hosted_identity_verified":identity_verified,
            "lane_controls":lane_controls,"lane_participation":lane_participation,
            "observation":observed,"observations":observations,"legacy_observation":legacy,
            "epoch_evidence":epoch_evidence,
            "reads":reads,"reads_truncated":reads_truncated,"request_restrictions":restrictions,"work":work,"pending":pending,"pending_work":pending_work});
        status["operations"] = json!(counts);
        status["writer_authority"] = self.writer_authority_status()?;
        status["captured_work"] = json!(captured_work);
        status["last_event"] = json!(last_event);
        status["migration"] = json!(migration);
        status["participation"] = participation;
        status["admission_blocked"] =
            json!(effective_config.as_ref().map(|_| !affected.is_empty()));
        status["affected_capabilities"] = json!(affected);
        status["oldest_unresolved_operation"] = json!(oldest.map(|op| op.id));
        status["oldest_unresolved_since"] = json!(oldest_since);
        status["last_progress_at"] = json!(last_progress);
        status["last_safety_observation_at"] = json!(safety);
        status["last_reported_build"] = json!(policy.as_ref().map(|p| &p["build"]));
        status["process_identity"] = json!("unverified");
        status["evidence"] = json!("authenticated_hosted_response");
        status["finality"] = json!("node_reported_only");
        status["paid"] = json!("not_verified");
        snapshot.commit()?;
        Ok(status)
    }
}
