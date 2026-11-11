use super::*;
use crate::endpoints::Endpoint;
use crate::protocol::{RestrictionBasis, RestrictionEvidence, RestrictionScope};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadPhase {
    Job,
    Receipt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiscoverySource {
    Challenge,
    Assignments,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ReadKey {
    Identity,
    Discovery {
        lane: LaneId,
        source: DiscoverySource,
    },
    Assignment {
        assignment_id: String,
    },
    Operation {
        operation_id: i64,
        binding_revision: i64,
        phase: ReadPhase,
    },
}

/// Captured request authority and timing used to fence a lane observation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaneObservationStamp {
    pub(crate) authority_epoch: u64,
    pub(crate) generation: i64,
    pub(crate) request_sequence: u64,
    pub(crate) started_at: i64,
    pub(crate) completed_at: i64,
}

pub(crate) struct LaneObservation<'a> {
    pub(crate) epoch: u64,
    pub(crate) answered: bool,
    pub(crate) fingerprint: &'a str,
    pub(crate) challenge: &'a Value,
}

pub(super) fn effect_endpoint(kind: LaneId) -> Endpoint {
    match kind {
        LaneId::Answer => Endpoint::Answer,
        LaneId::Judge => Endpoint::Grade,
        LaneId::Mine => Endpoint::Mine,
    }
}
fn endpoint_name(endpoint: Endpoint) -> Result<String> {
    serde_json::to_value(endpoint)?
        .as_str()
        .map(str::to_owned)
        .context("invalid endpoint name")
}
fn resource_target(endpoint: Endpoint, resource: &str) -> Result<String> {
    Ok(format!("{}:{resource}", endpoint_name(endpoint)?))
}

impl Store {
    pub(crate) fn operation_read_key(op: &Operation) -> Option<ReadKey> {
        let phase = if op.txid.is_some() {
            ReadPhase::Receipt
        } else if op.job_id.is_some() {
            ReadPhase::Job
        } else {
            return None;
        };
        Some(ReadKey::Operation {
            operation_id: op.id,
            binding_revision: op.persisted_binding_revision.get(),
            phase,
        })
    }

    fn read_parts(&self, key: &ReadKey) -> Result<(String, &'static str, String, Option<String>)> {
        Ok(match key {
            ReadKey::Identity => ("account".into(), "identity", "identity".into(), None),
            ReadKey::Discovery { lane, source } => (
                lane.as_str().into(),
                "discovery",
                match source {
                    DiscoverySource::Challenge => "challenge",
                    DiscoverySource::Assignments => "assignments",
                }
                .into(),
                None,
            ),
            ReadKey::Assignment { assignment_id } => (
                "judge".into(),
                "assignment",
                assignment_id.clone(),
                Some(assignment_id.clone()),
            ),
            ReadKey::Operation {
                operation_id,
                binding_revision,
                phase,
            } => {
                let (owner, remote): (String, Option<String>) = self.db.query_row(
                    "SELECT kind,CASE WHEN ?2='receipt' THEN txid ELSE job_id END FROM operations WHERE id=?1",
                    params![operation_id, if *phase == ReadPhase::Receipt { "receipt" } else { "job" }],
                    |row| Ok((row.get(0)?,row.get(1)?)))?;
                (
                    owner,
                    if *phase == ReadPhase::Receipt {
                        "receipt"
                    } else {
                        "job"
                    },
                    format!("{operation_id}:{binding_revision}"),
                    remote,
                )
            }
        })
    }

    pub(crate) fn read_key_projection(&self, key: &ReadKey) -> Result<Value> {
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        Ok(json!({"owner":owner,"purpose":purpose,"resource":resource}))
    }

    pub(crate) fn read_current(&self, key: &ReadKey) -> Result<bool> {
        let ReadKey::Operation {
            operation_id,
            binding_revision,
            phase,
        } = key
        else {
            return Ok(true);
        };
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 AND binding_revision=?2
             AND state IN ('queued','unknown','included_pending','confirmed')
             AND ((?3='receipt' AND txid IS NOT NULL) OR (?3='job' AND txid IS NULL AND job_id IS NOT NULL)))",
            params![operation_id,binding_revision,if *phase == ReadPhase::Receipt {"receipt"} else {"job"}], |r| r.get(0))?)
    }

    fn ensure_read_row(&self, key: &ReadKey) -> Result<bool> {
        if !self.read_current(key)? {
            return Ok(false);
        }
        let (owner, purpose, resource, remote) = self.read_parts(key)?;
        let (id, revision) = match key {
            ReadKey::Operation {
                operation_id,
                binding_revision,
                ..
            } => (Some(*operation_id), Some(*binding_revision)),
            _ => (None, None),
        };
        self.db.execute("INSERT OR IGNORE INTO read_state(owner,purpose,resource,operation_id,binding_revision,remote_resource)
            VALUES (?1,?2,?3,?4,?5,?6)",params![owner,purpose,resource,id,revision,remote])?;
        if let Some(remote) = &remote {
            let endpoint = if purpose == "receipt" {
                Endpoint::Receipt
            } else {
                Endpoint::Job
            };
            if matches!(key, ReadKey::Operation { .. }) {
                let identity: String = self.db.query_row(
                    "SELECT identity FROM control WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )?;
                let identity: Value = serde_json::from_str(&identity)?;
                let origin = reqwest::Url::parse(
                    identity["base_url"]
                        .as_str()
                        .context("journal origin missing")?,
                )?
                .origin()
                .ascii_serialization();
                self.db.execute("UPDATE read_state SET server_not_before=MAX(server_not_before,
                    COALESCE((SELECT MAX(not_before) FROM request_restrictions WHERE scope='resource'
                        AND target=?4 AND origin=?5 AND authority=(SELECT json_extract(identity,'$.chain')||char(10)||json_extract(identity,'$.address') FROM control)),0))
                    WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
                    params![owner,purpose,resource,resource_target(endpoint,remote)?,origin])?;
            }
        }
        Ok(true)
    }

    pub(crate) fn read_backoff(&self, key: &ReadKey) -> Result<ReadBackoff> {
        if !self.read_current(key)? {
            return Ok(ReadBackoff {
                failures: 0,
                next_at: i64::MAX,
            });
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        Ok(self
            .db
            .query_row(
                "SELECT failures,MAX(local_next_at,server_not_before,retained_conservative_floor)
            FROM read_state WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
                params![owner, purpose, resource],
                |r| {
                    Ok(ReadBackoff {
                        failures: r.get(0)?,
                        next_at: r.get(1)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }

    pub(crate) fn discovery_next_at(
        &self,
        config: &Config,
        lane: LaneId,
        backoff: &ReadBackoff,
    ) -> Result<i64> {
        // Failed discovery owns its retry clock. Older journals may also contain
        // a copy in the lane cadence; that copy must not survive a policy change.
        let local = if backoff.failures > 0 {
            backoff.next_at
        } else {
            self.next_at(lane)?.max(backoff.next_at)
        };
        let endpoint = if lane == LaneId::Judge {
            Endpoint::Assignments
        } else {
            Endpoint::Challenge
        };
        Ok(local.max(self.request_not_before(config, endpoint, None)?))
    }

    pub(crate) fn read_started(&self, key: &ReadKey) -> Result<bool> {
        self.continuity()?;
        let tx = self.db.unchecked_transaction()?;
        if !self.ensure_read_row(key)? || self.read_backoff(key)?.next_at > now() {
            return Ok(false);
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        let changed = tx.execute(
            "UPDATE read_state SET in_flight=1,started_at=?4
            WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0 AND in_flight=0",
            params![owner, purpose, resource, now()],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn cancel_read(&self, key: &ReadKey) -> Result<()> {
        self.continuity()?;
        if !self.read_current(key)? {
            return Ok(());
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        self.db.execute(
            "UPDATE read_state SET in_flight=0,finished_at=?4
            WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
            params![owner, purpose, resource, now()],
        )?;
        Ok(())
    }

    pub(crate) fn read_finished(
        &self,
        key: &ReadKey,
        status: Option<u16>,
        category: Option<&str>,
    ) -> Result<()> {
        self.continuity()?;
        if !self.ensure_read_row(key)? {
            return Ok(());
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        self.db.execute(
            "UPDATE read_state SET in_flight=0,finished_at=?4,status=?5,
            failure_category=CASE WHEN ?6 IS NOT NULL THEN ?6
                WHEN failures>0 THEN failure_category ELSE NULL END,
            last_http_success_at=CASE WHEN ?5>=200 AND ?5<300 THEN ?4 ELSE last_http_success_at END
            WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
            params![
                owner,
                purpose,
                resource,
                now(),
                status,
                category.map(safe_read_category)
            ],
        )?;
        Ok(())
    }

    pub(crate) fn fail_read(
        &self,
        key: &ReadKey,
        base: u64,
        cap: u64,
        jitter: u64,
        minimum: Option<u64>,
    ) -> Result<ReadBackoff> {
        self.continuity()?;
        let tx = self.db.unchecked_transaction()?;
        let result = self.fail_read_in(&tx, key, base, cap, jitter, minimum)?;
        tx.commit()?;
        Ok(result)
    }
    pub(super) fn fail_read_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key: &ReadKey,
        base: u64,
        cap: u64,
        jitter: u64,
        minimum: Option<u64>,
    ) -> Result<ReadBackoff> {
        if !self.ensure_read_row(key)? {
            return self.read_backoff(key);
        }
        let failures = self.read_backoff(key)?.failures.saturating_add(1);
        let local = not_before(read_delay(failures, base, cap, jitter));
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        if minimum.is_some() {
            bail!(
                "ingest request-bound restriction evidence before recording a local read failure"
            );
        }
        tx.execute(
            "UPDATE read_state SET failures=?4,last_failure_at=?5,local_next_at=?6,
            failure_category=COALESCE(failure_category,'unusable_response')
            WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
            params![owner, purpose, resource, failures, now(), local],
        )?;
        self.read_backoff(key)
    }

    pub(crate) fn reset_read(&self, key: &ReadKey) -> Result<()> {
        self.continuity()?;
        let tx = self.db.unchecked_transaction()?;
        self.reset_read_in(&tx, key)?;
        tx.commit()?;
        Ok(())
    }
    pub(super) fn reset_read_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key: &ReadKey,
    ) -> Result<()> {
        if !self.ensure_read_row(key)? {
            return Ok(());
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        tx.execute("UPDATE read_state SET failures=0,local_next_at=0,last_success_at=?4,failure_category=NULL
            WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",params![owner,purpose,resource,now()])?;
        Ok(())
    }

    pub(crate) fn reschedule_read(
        &self,
        key: &ReadKey,
        base: u64,
        cap: u64,
        jitter: u64,
    ) -> Result<()> {
        self.continuity()?;
        if !self.read_current(key)? {
            return Ok(());
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        let timing:Option<(u32,Option<i64>)>=self.db.query_row(
            "SELECT failures,last_failure_at FROM read_state WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
            params![owner,purpose,resource],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((failures, Some(failed_at))) = timing.filter(|(n, _)| *n > 0) {
            let deadline = failed_at
                .saturating_add(read_delay(failures, base, cap, jitter).min(i64::MAX as u64) as i64)
                .saturating_add(1);
            self.db.execute("UPDATE read_state SET local_next_at=?4 WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0",
                params![owner,purpose,resource,deadline])?;
        }
        Ok(())
    }

    pub(crate) fn reschedule_all_reads(&self, config: &Config) -> Result<()> {
        let mut statement=self.db.prepare("SELECT owner,purpose,resource,operation_id,binding_revision FROM read_state WHERE retired=0")?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<i64>>(4)?,
            ))
        })?;
        for row in rows {
            let (owner, purpose, resource, id, revision) = row?;
            if owner == "account" {
                self.reschedule_read(
                    &ReadKey::Identity,
                    config.identity.retry_seconds,
                    config.identity.backoff_max_seconds,
                    config.identity.jitter_seconds,
                )?;
                continue;
            }
            let lane = match owner.as_str() {
                "answer" => LaneId::Answer,
                "judge" => LaneId::Judge,
                "mine" => LaneId::Mine,
                _ => bail!("invalid read owner"),
            };
            let schedule = config.schedule(lane);
            let key = if let (Some(operation_id), Some(binding_revision)) = (id, revision) {
                ReadKey::Operation {
                    operation_id,
                    binding_revision,
                    phase: if purpose == "receipt" {
                        ReadPhase::Receipt
                    } else {
                        ReadPhase::Job
                    },
                }
            } else if purpose == "assignment" {
                ReadKey::Assignment {
                    assignment_id: resource,
                }
            } else {
                ReadKey::Discovery {
                    lane,
                    source: if resource == "assignments" {
                        DiscoverySource::Assignments
                    } else {
                        DiscoverySource::Challenge
                    },
                }
            };
            let discovery = purpose == "discovery";
            self.reschedule_read(
                &key,
                if discovery {
                    schedule
                        .discovery_retry_seconds
                        .unwrap_or(schedule.retry_seconds)
                } else {
                    schedule.retry_seconds
                },
                if discovery {
                    schedule
                        .discovery_backoff_max_seconds
                        .unwrap_or(schedule.backoff_max_seconds)
                } else {
                    schedule.backoff_max_seconds
                },
                schedule.jitter_seconds,
            )?;
        }
        Ok(())
    }

    /// Stage one of completion handling: independent of the local state CAS.
    pub(crate) fn ingest_restrictions(&self, evidence: &[RestrictionEvidence]) -> Result<()> {
        self.continuity()?;
        let (database_id, _) = self.database_identity()?;
        let identity: String =
            self.db
                .query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let identity: Value = serde_json::from_str(&identity)?;
        let current_authority = format!(
            "{}\n{}",
            identity["chain"]
                .as_str()
                .context("journal chain missing")?,
            identity["address"]
                .as_str()
                .context("journal address missing")?
        );
        let current_origin = reqwest::Url::parse(
            identity["base_url"]
                .as_str()
                .context("journal origin missing")?,
        )?
        .origin()
        .ascii_serialization();
        let tx = self.db.unchecked_transaction()?;
        for item in evidence {
            let context = item.context();
            if context.meta.database_id != database_id
                || context.meta.request_id.is_empty()
                || context.method != context.endpoint.method().as_str()
                || item.observed_at() < context.started_at
                || item.not_before() < item.observed_at()
            {
                bail!("invalid request-bound restriction evidence");
            }
            let origin = reqwest::Url::parse(&context.origin)?
                .origin()
                .ascii_serialization();
            if origin != context.origin {
                bail!("noncanonical restriction origin");
            }
            let authority = format!("{}\n{}", context.chain, context.address);
            let (scope, target, reads, effects) = match item.scope() {
                RestrictionScope::AccountAuthenticated if context.authenticated => {
                    ("account_authenticated", "*".into(), true, true)
                }
                RestrictionScope::Resource { endpoint, resource }
                    if item.resource_matches_context() =>
                {
                    (
                        "resource",
                        resource_target(*endpoint, resource)?,
                        !endpoint.is_effect(),
                        endpoint.is_effect(),
                    )
                }
                RestrictionScope::AnswerJudgeEffects
                    if matches!(context.endpoint, Endpoint::Answer | Endpoint::Grade) =>
                {
                    ("answer_judge_effects", "*".into(), false, true)
                }
                _ => bail!("restriction scope does not match actual request"),
            };
            let basis = match item.basis() {
                RestrictionBasis::ServerRetryAfter => "server_retry_after",
                RestrictionBasis::LocalUnscoped429Cooldown => "local_unscoped_429_cooldown",
            };
            tx.execute("INSERT INTO request_restrictions VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                ON CONFLICT(authority,origin,scope,target,basis) DO UPDATE SET
                not_before=MAX(not_before,excluded.not_before),
                observed_at=CASE WHEN excluded.not_before>not_before THEN excluded.observed_at ELSE observed_at END,
                request_id=CASE WHEN excluded.not_before>not_before THEN excluded.request_id ELSE request_id END,
                source=CASE WHEN excluded.not_before>not_before THEN excluded.source ELSE source END,
                server_minimum_seconds=CASE WHEN excluded.not_before>not_before THEN excluded.server_minimum_seconds ELSE server_minimum_seconds END,
                policy=CASE WHEN excluded.not_before>not_before THEN excluded.policy ELSE policy END",
                params![authority,origin,scope,target,basis,item.not_before(),item.observed_at(),context.meta.request_id,
                    endpoint_name(context.endpoint)?,reads,effects,item.server_minimum_seconds(),item.policy()])?;
            if scope == "resource"
                && authority == current_authority
                && origin == current_origin
                && let (Some(id), Some(revision)) =
                    (&context.meta.operation_id, context.meta.binding_revision)
                && let Ok(id) = id.parse::<i64>()
            {
                tx.execute("UPDATE read_state SET server_not_before=MAX(server_not_before,?1)
                    WHERE operation_id=?2 AND binding_revision=?3 AND remote_resource=?4 AND retired=0
                    AND EXISTS(SELECT 1 FROM operations WHERE id=?2 AND binding_revision=?3)",
                    params![item.not_before(),id,revision,context.resource])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(super) fn request_floor_in(
        db: &Connection,
        config: &Config,
        endpoint: Endpoint,
        resource: Option<&str>,
    ) -> Result<(i64, bool, Option<String>)> {
        let origin = reqwest::Url::parse(&config.network.base_url)?
            .origin()
            .ascii_serialization();
        let authority = format!("{}\n{}", config.network.chain, config.network.address);
        let target = resource
            .map(|r| resource_target(endpoint, r))
            .transpose()?
            .unwrap_or_default();
        let authenticated =
            endpoint.authenticated() || matches!(endpoint, Endpoint::Job | Endpoint::Receipt);
        Ok(db
            .query_row(
                "SELECT not_before,basis='retained_legacy_floor',scope FROM request_restrictions
            WHERE authority=?1 AND origin=?2 AND ((?3 AND effect_class) OR (NOT ?3 AND read_class))
            AND ((scope='account_authenticated' AND ?4) OR (scope='resource' AND target=?5)
                OR (scope='answer_judge_effects' AND ?6) OR (scope='legacy_account_effect' AND ?3))
            ORDER BY not_before DESC LIMIT 1",
                params![
                    authority,
                    origin,
                    endpoint.is_effect(),
                    authenticated,
                    target,
                    matches!(endpoint, Endpoint::Answer | Endpoint::Grade)
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .unwrap_or_default())
    }
    pub(crate) fn request_not_before(
        &self,
        config: &Config,
        endpoint: Endpoint,
        resource: Option<&str>,
    ) -> Result<i64> {
        Ok(Self::request_floor_in(&self.db, config, endpoint, resource)?.0)
    }

    pub(crate) fn reconciliation_batch(&self, lane: LaneId) -> Result<Vec<Operation>> {
        let cursor: i64 = self
            .db
            .query_row(
                "SELECT COALESCE(CAST(cursor AS INTEGER),0) FROM schedule WHERE kind=?1",
                [format!("reconciliation:{}", lane.as_str())],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let identity: String =
            self.db
                .query_row("SELECT identity FROM control WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let identity: Value = serde_json::from_str(&identity)?;
        let authority = format!(
            "{}\n{}",
            identity["chain"].as_str().unwrap_or_default(),
            identity["address"].as_str().unwrap_or_default()
        );
        let origin = reqwest::Url::parse(
            identity["base_url"]
                .as_str()
                .context("journal origin missing")?,
        )?
        .origin()
        .ascii_serialization();
        let mut stmt=self.db.prepare("SELECT o.id FROM operations o LEFT JOIN read_state r
            ON r.operation_id=o.id AND r.binding_revision=o.binding_revision AND r.retired=0
            AND r.purpose=CASE WHEN o.txid IS NOT NULL THEN 'receipt' ELSE 'job' END
            WHERE o.kind=?1 AND o.state IN ('queued','unknown','included_pending','confirmed')
            AND (o.job_id IS NOT NULL OR o.txid IS NOT NULL) AND o.next_at<=?2
            AND COALESCE(r.in_flight,0)=0 AND MAX(COALESCE(r.local_next_at,0),COALESCE(r.server_not_before,0),COALESCE(r.retained_conservative_floor,0))<=?2
            AND NOT EXISTS(SELECT 1 FROM request_restrictions rr WHERE rr.authority=?4 AND rr.origin=?5
                AND rr.read_class=1 AND rr.not_before>?2 AND (rr.scope='account_authenticated'
                    OR (rr.scope='resource' AND rr.target=CASE WHEN o.txid IS NOT NULL
                        THEN 'receipt:'||o.txid ELSE 'job:'||o.job_id END)))
            ORDER BY CASE WHEN o.id>?3 THEN 0 ELSE 1 END,o.id LIMIT 2")?;
        let ids = stmt
            .query_map(
                params![lane.as_str(), now(), cursor, authority, origin],
                |r| r.get::<_, i64>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                self.operation(id)?
                    .context("recovery operation disappeared")
            })
            .collect()
    }
    pub(crate) fn reconciliation_attempted(&self, lane: LaneId, operation: i64) -> Result<()> {
        self.continuity()?;
        self.db.execute("INSERT INTO schedule(kind,next_at,cursor) VALUES (?1,0,?2) ON CONFLICT(kind) DO UPDATE SET cursor=excluded.cursor",
            params![format!("reconciliation:{}",lane.as_str()),operation.to_string()])?;
        Ok(())
    }

    pub(crate) fn wake_delay(&self, config: &Config, fallback: u64) -> Result<u64> {
        let current = now();
        let mut deadline = current.saturating_add(fallback.min(i64::MAX as u64) as i64);
        for lane in [LaneId::Answer, LaneId::Judge, LaneId::Mine] {
            if config.mode(lane) != Mode::Off {
                let key = ReadKey::Discovery {
                    lane,
                    source: if lane == LaneId::Judge {
                        DiscoverySource::Assignments
                    } else {
                        DiscoverySource::Challenge
                    },
                };
                let next = self.discovery_next_at(config, lane, &self.read_backoff(&key)?)?;
                if next > current {
                    deadline = deadline.min(next);
                }
            }
        }
        let next:Option<i64>=self.db.query_row("SELECT MIN(MAX(o.next_at,COALESCE(r.local_next_at,0),COALESCE(r.server_not_before,0),COALESCE(r.retained_conservative_floor,0)))
            FROM operations o LEFT JOIN read_state r ON r.operation_id=o.id AND r.binding_revision=o.binding_revision AND r.retired=0
            WHERE o.state IN ('queued','unknown','included_pending','confirmed') AND (o.job_id IS NOT NULL OR o.txid IS NOT NULL) AND COALESCE(r.in_flight,0)=0",[],|r|r.get(0))?;
        if let Some(next) = next.filter(|next| *next > current) {
            deadline = deadline.min(next);
        }
        let restriction: Option<i64> = self.db.query_row(
            "SELECT MIN(not_before) FROM request_restrictions WHERE not_before>?1",
            [current],
            |r| r.get(0),
        )?;
        if let Some(next) = restriction {
            deadline = deadline.min(next);
        }
        Ok(deadline.saturating_sub(current).max(1) as u64)
    }

    pub(crate) fn set_authority_epoch(&self, authority_epoch: u64) -> Result<()> {
        self.continuity()?;
        self.db.execute(
            "INSERT INTO runtime_authority VALUES(1,?1)
            ON CONFLICT(singleton) DO UPDATE SET authority_epoch=excluded.authority_epoch",
            [authority_epoch],
        )?;
        Ok(())
    }

    pub(crate) fn observe_lane(
        &self,
        lane: LaneId,
        stamp: LaneObservationStamp,
        observation: LaneObservation<'_>,
        admission: &AdmissionStampSnapshot,
    ) -> Result<bool> {
        self.observe_lane_in(lane, stamp, observation, Some(admission))
    }

    #[cfg(test)]
    pub(crate) fn seed_lane_observation_for_test(
        &self,
        lane: LaneId,
        stamp: LaneObservationStamp,
        observation: LaneObservation<'_>,
    ) -> Result<bool> {
        self.observe_lane_in(lane, stamp, observation, None)
    }

    fn observe_lane_in(
        &self,
        lane: LaneId,
        stamp: LaneObservationStamp,
        observation: LaneObservation<'_>,
        admission: Option<&AdmissionStampSnapshot>,
    ) -> Result<bool> {
        let LaneObservation {
            epoch,
            answered,
            fingerprint,
            challenge,
        } = observation;
        let LaneObservationStamp {
            authority_epoch,
            generation,
            request_sequence,
            started_at,
            completed_at,
        } = stamp;
        self.continuity()?;
        if lane == LaneId::Judge {
            bail!("judge has no challenge snapshot");
        }
        if completed_at < started_at {
            bail!("snapshot completion precedes request start");
        }
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        if let Some(admission) = admission
            && (generation != admission.account_generation
                || authority_epoch != admission.authority_epoch
                || !Self::observation_stamp_matches(&tx, lane, admission)?)
        {
            return Ok(false);
        }
        let previous: Option<(u64, bool)> = tx
            .query_row(
                "SELECT epoch,answered FROM lane_observations WHERE lane=?1",
                [lane.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let changed=tx.execute("INSERT INTO lane_observations SELECT ?1,?2,?3,?4,?5,?6,?7,?6,?8,?9,?10
            WHERE EXISTS(SELECT 1 FROM control WHERE generation=?3)
              AND EXISTS(SELECT 1 FROM runtime_authority WHERE authority_epoch=?2)
            ON CONFLICT(lane) DO UPDATE SET authority_epoch=excluded.authority_epoch,generation=excluded.generation,
            request_sequence=excluded.request_sequence,started_at=excluded.started_at,observed_at=excluded.observed_at,
            epoch=excluded.epoch,first_observed_at=CASE WHEN epoch=excluded.epoch THEN first_observed_at ELSE excluded.first_observed_at END,
            answered=excluded.answered,fingerprint=excluded.fingerprint,challenge=excluded.challenge
            WHERE excluded.epoch>=epoch AND (excluded.authority_epoch!=authority_epoch OR
                (excluded.authority_epoch=authority_epoch AND excluded.generation>=generation AND excluded.request_sequence>request_sequence))",
            params![lane.as_str(),authority_epoch,generation,request_sequence,started_at,completed_at,epoch,answered,fingerprint,serde_json::to_string(challenge)?])?;
        tx.execute(
            "INSERT OR IGNORE INTO lane_observation_evidence VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                lane.as_str(),
                authority_epoch,
                generation,
                request_sequence,
                completed_at,
                epoch,
                fingerprint,
                changed == 1
            ],
        )?;
        if changed == 1 {
            if previous.map(|p| p.0) != Some(epoch) {
                tx.execute(
                    "INSERT INTO events(at,code,kind) VALUES(?1,'epoch_observed',?2)",
                    params![completed_at, lane.as_str()],
                )?;
            }
            if previous != Some((epoch, answered)) {
                tx.execute(
                    "INSERT INTO events(at,code,kind) VALUES(?1,?2,?3)",
                    params![
                        completed_at,
                        if answered {
                            "challenge_answered"
                        } else {
                            "challenge_unanswered"
                        },
                        lane.as_str()
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(changed == 1)
    }
    pub(crate) fn lane_observation(&self, lane: LaneId) -> Result<Option<Value>> {
        self.db.query_row("SELECT authority_epoch,generation,request_sequence,started_at,observed_at,epoch,first_observed_at,answered,fingerprint,challenge
            FROM lane_observations WHERE lane=?1",[lane.as_str()],|r|Ok((json!({"lane":lane,"authority_epoch":r.get::<_,u64>(0)?,"generation":r.get::<_,i64>(1)?,
                "request_sequence":r.get::<_,u64>(2)?,"started_at":r.get::<_,i64>(3)?,"observed_at":r.get::<_,i64>(4)?,"epoch":r.get::<_,u64>(5)?,
                "first_observed_at":r.get::<_,i64>(6)?,"answered":r.get::<_,bool>(7)?,"fingerprint":r.get::<_,String>(8)?,"basis":"lane_authenticated_observation"}),r.get::<_,String>(9)?)))
            .optional()?.map(|(mut value,challenge)| -> Result<Value>{value["challenge"]=serde_json::from_str(&challenge)?;Ok(value)}).transpose()
    }
}
