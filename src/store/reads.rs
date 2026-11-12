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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconciliationService {
    Recent,
    Fair,
    Missing,
}

const RECONCILIATION_PAGE_SIZE: usize = 64;
const RECONCILIATION_SELECT: &str = "WITH page AS MATERIALIZED (
    SELECT id,binding_revision,txid,job_id,next_at
    FROM operations INDEXED BY operations_reconciliation
    WHERE kind=?1 AND id<=?3
    AND state IN ('queued','unknown','included_pending','confirmed')
    AND (job_id IS NOT NULL OR txid IS NOT NULL)
    ORDER BY id DESC LIMIT ?6)
    SELECT o.id,COALESCE(o.txid IS NULL AND r.status=404 AND r.failures>=2,0),
        o.next_at<=?2 AND COALESCE(r.in_flight,0)=0
        AND MAX(COALESCE(r.local_next_at,0),COALESCE(r.server_not_before,0),
            COALESCE(r.retained_conservative_floor,0))<=?2
        AND NOT EXISTS(SELECT 1 FROM request_restrictions rr
            WHERE rr.authority=?4 AND rr.origin=?5
            AND rr.scope='account_authenticated'
            AND rr.read_class=1 AND rr.not_before>?2)
        AND NOT EXISTS(SELECT 1 FROM request_restrictions rr
            WHERE rr.authority=?4 AND rr.origin=?5 AND rr.scope='resource'
            AND rr.target=CASE WHEN o.txid IS NOT NULL
                THEN 'receipt:'||o.txid ELSE 'job:'||o.job_id END
            AND rr.read_class=1 AND rr.not_before>?2)
    FROM page o LEFT JOIN read_state r
    ON r.operation_id=o.id AND r.binding_revision=o.binding_revision AND r.retired=0
    AND r.purpose=CASE WHEN o.txid IS NOT NULL THEN 'receipt' ELSE 'job' END
    ORDER BY o.id DESC";

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
            let success: Option<i64> = self
                .db
                .query_row(
                    "SELECT last_success_at FROM read_state
                WHERE owner=?1 AND purpose='discovery' AND resource=?2 AND retired=0",
                    params![
                        lane.as_str(),
                        if lane == LaneId::Judge {
                            "assignments"
                        } else {
                            "challenge"
                        }
                    ],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            let cadence = self.next_at(lane)?;
            // Old persisted poll deadlines may exceed the observation's new
            // refresh budget. Clamp only successful cadence, never a read
            // backoff or server floor, and never rebase from the current time.
            let cadence = success.map_or(cadence, |at| {
                cadence.min(
                    at.saturating_add(
                        config
                            .discovery_poll_seconds(lane, config.schedule(lane).jitter_seconds)
                            .min(i64::MAX as u64) as i64,
                    )
                    .saturating_add(1),
                )
            });
            cadence.max(backoff.next_at)
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
        let started = self.start_read_in(key, now())?;
        tx.commit()?;
        Ok(started)
    }

    fn start_read_in(&self, key: &ReadKey, at: i64) -> Result<bool> {
        if !self.ensure_read_row(key)? || self.read_backoff(key)?.next_at > at {
            return Ok(false);
        }
        let (owner, purpose, resource, _) = self.read_parts(key)?;
        Ok(self.db.execute(
            "UPDATE read_state SET in_flight=1,started_at=?4
            WHERE owner=?1 AND purpose=?2 AND resource=?3 AND retired=0 AND in_flight=0",
            params![owner, purpose, resource, at],
        )? == 1)
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
                "SELECT not_before,basis='retained_legacy_floor',scope FROM (
                    SELECT not_before,basis,scope FROM request_restrictions
                    WHERE authority=?1 AND origin=?2 AND scope='account_authenticated'
                        AND ?4 AND ((?3 AND effect_class) OR (NOT ?3 AND read_class))
                    UNION ALL
                    SELECT not_before,basis,scope FROM request_restrictions
                    WHERE authority=?1 AND origin=?2 AND scope='resource' AND target=?5
                        AND ((?3 AND effect_class) OR (NOT ?3 AND read_class))
                    UNION ALL
                    SELECT not_before,basis,scope FROM request_restrictions
                    WHERE authority=?1 AND origin=?2 AND scope='answer_judge_effects'
                        AND ?6 AND ((?3 AND effect_class) OR (NOT ?3 AND read_class))
                    UNION ALL
                    SELECT not_before,basis,scope FROM request_restrictions
                    WHERE authority=?1 AND origin=?2 AND scope='legacy_account_effect'
                        AND ?3 AND effect_class)
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
        self.reconciliation_selection(lane, now())?
            .into_iter()
            .map(|(id, _)| {
                self.operation(id)?
                    .context("recovery operation disappeared")
            })
            .collect()
    }

    pub(crate) fn reconciliation_plan(
        &self,
        lane: LaneId,
    ) -> Result<Vec<(Operation, ReconciliationService)>> {
        self.reconciliation_selection(lane, now())?
            .into_iter()
            .map(|(id, service)| {
                Ok((
                    self.operation(id)?
                        .context("recovery operation disappeared")?,
                    service,
                ))
            })
            .collect()
    }

    #[cfg(test)]
    fn reconciliation_candidates(&self, lane: LaneId, at: i64) -> Result<Vec<i64>> {
        Ok(self
            .reconciliation_selection(lane, at)?
            .into_iter()
            .map(|(id, _)| id)
            .collect())
    }

    fn reconciliation_schedule(&self, name: &str) -> Result<(i64, i64, bool)> {
        Ok(self
            .db
            .query_row(
                "SELECT next_at,COALESCE(CAST(cursor AS INTEGER),0),served_in_round
                FROM schedule WHERE kind=?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .unwrap_or_default())
    }

    fn set_reconciliation_cursor(&self, name: &str, cursor: i64) -> Result<()> {
        self.db.execute(
            "INSERT INTO schedule(kind,next_at,cursor) VALUES (?1,0,?2)
            ON CONFLICT(kind) DO UPDATE SET cursor=excluded.cursor
            WHERE schedule.cursor IS NOT excluded.cursor",
            params![name, cursor.to_string()],
        )?;
        Ok(())
    }

    fn reconciliation_selection(
        &self,
        lane: LaneId,
        at: i64,
    ) -> Result<Vec<(i64, ReconciliationService)>> {
        // Selection may advance past ineligible rows, but only a successful
        // claim may consume an eligible fair or missing candidate.
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let recent_name = format!("reconciliation:{}", lane.as_str());
        let fair_name = format!("reconciliation:fair:{}", lane.as_str());
        let missing_name = format!("reconciliation:missing:{}", lane.as_str());
        let recent = self.reconciliation_schedule(&recent_name)?;
        let fair = self.reconciliation_schedule(&fair_name)?;
        if recent.0 > at && fair.0 > at {
            return Ok(Vec::new());
        }
        let missing = self.reconciliation_schedule(&missing_name)?;
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
        // LIMIT belongs to the base ID page, before any eligibility predicate.
        // Every walk advances past ineligible rows, independently of whether a
        // request starts. A page with no match must not turn into a history scan.
        let mut stmt = self.db.prepare(RECONCILIATION_SELECT)?;
        let mut select = |cursor: i64, exclude: i64, missing_only: bool| -> Result<_> {
            let mut page = |ceiling| -> Result<(Option<i64>, i64)> {
                let rows = stmt.query_map(
                    params![
                        lane.as_str(),
                        at,
                        ceiling,
                        authority,
                        origin,
                        RECONCILIATION_PAGE_SIZE as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, bool>(1)?,
                            row.get::<_, bool>(2)?,
                        ))
                    },
                )?;
                let mut candidate = None;
                let mut last = 0;
                for row in rows {
                    let (id, missing, eligible) = row?;
                    last = id;
                    if id != exclude && missing == missing_only && eligible {
                        candidate = Some(id);
                        break;
                    }
                }
                Ok((candidate, last))
            };
            let result = page(if cursor > 0 { cursor - 1 } else { i64::MAX })?;
            // An exhausted walk wraps at most once, never until a match.
            if result.1 == 0 && cursor > 0 {
                page(i64::MAX)
            } else {
                Ok(result)
            }
        };
        let mut candidates = Vec::with_capacity(2);
        if recent.0 <= at {
            let head_name = format!("reconciliation:head:{}", lane.as_str());
            let head = self.reconciliation_schedule(&head_name)?.1;
            let newest = self
                .db
                .query_row(
                    "SELECT id FROM operations INDEXED BY operations_reconciliation
                    WHERE kind=?1 AND state IN ('queued','unknown','included_pending','confirmed')
                    AND (job_id IS NOT NULL OR txid IS NOT NULL)
                    ORDER BY id DESC LIMIT 1",
                    [lane.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0);
            // New work jumps ahead immediately; otherwise continue the recent
            // walk rather than repeatedly classifying the newest missing page.
            let cursor = if newest > head { 0 } else { recent.1 };
            let (candidate, last) = select(cursor, 0, false)?;
            // Keep ready recent work on its reserved cadence. Only an empty
            // eligible page advances this walk; ordinary history has its own.
            self.set_reconciliation_cursor(
                &recent_name,
                candidate.map_or(last, |id| id.saturating_add(1)),
            )?;
            if newest > head {
                self.set_reconciliation_cursor(&head_name, newest)?;
            }
            if let Some(candidate) = candidate {
                candidates.push((candidate, ReconciliationService::Recent));
            }
        }
        if fair.0 <= at {
            let exclude = candidates.first().map_or(0, |(id, _)| *id);
            let (ordinary, ordinary_last) = select(fair.1, exclude, false)?;
            // Missing work owns a separate descending walk. Alternation and
            // its sparse service floor are independent of traversal progress.
            let historical = if missing.0 <= at && (!fair.2 || ordinary.is_none()) {
                let (candidate, last) = select(missing.1, exclude, true)?;
                self.set_reconciliation_cursor(
                    &missing_name,
                    candidate.map_or(last, |id| id.saturating_add(1)),
                )?;
                candidate
            } else {
                None
            };
            self.set_reconciliation_cursor(
                &fair_name,
                ordinary.map_or(ordinary_last, |id| id.saturating_add(1)),
            )?;
            if let Some(candidate) = historical.or(ordinary) {
                candidates.push((
                    candidate,
                    if historical.is_some() {
                        ReconciliationService::Missing
                    } else {
                        ReconciliationService::Fair
                    },
                ));
            }
        }
        // With one free flight, the older unserved cadence wins. Claiming it
        // moves its durable deadline behind the other cadence, including after
        // restart; fresh arrivals cannot permanently monopolize the free slot.
        if candidates.len() == 2 && fair.0 < recent.0 {
            candidates.swap(0, 1);
        }
        drop(stmt);
        tx.commit()?;
        Ok(candidates)
    }

    /// Reserve durable lane service before starting the request. Completion,
    /// cancellation, restart and policy reload do not refund an occupied slot.
    pub(crate) fn reconciliation_read_started(
        &self,
        config: &Config,
        lane: LaneId,
        key: &ReadKey,
    ) -> Result<bool> {
        self.reconciliation_read_started_at(config, lane, key, now())
    }

    pub(crate) fn reconciliation_read_claimed(
        &self,
        config: &Config,
        lane: LaneId,
        key: &ReadKey,
        service: ReconciliationService,
    ) -> Result<bool> {
        self.reconciliation_claim_at(config, lane, key, now(), Some(service))
    }

    fn reconciliation_read_started_at(
        &self,
        config: &Config,
        lane: LaneId,
        key: &ReadKey,
        at: i64,
    ) -> Result<bool> {
        self.reconciliation_claim_at(config, lane, key, at, None)
    }

    fn reconciliation_claim_at(
        &self,
        config: &Config,
        lane: LaneId,
        key: &ReadKey,
        at: i64,
        service: Option<ReconciliationService>,
    ) -> Result<bool> {
        self.continuity()?;
        let ReadKey::Operation { operation_id, .. } = key else {
            bail!("reconciliation requires an operation binding");
        };
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        if !self.read_current(key)? {
            return Ok(false);
        }
        let (next_at, missing): (i64, bool) = self.db.query_row(
            "SELECT o.next_at,COALESCE(o.txid IS NULL AND r.status=404 AND r.failures>=2,0)
            FROM operations o LEFT JOIN read_state r
                ON r.operation_id=o.id AND r.binding_revision=o.binding_revision AND r.retired=0
                AND r.purpose=CASE WHEN o.txid IS NOT NULL THEN 'receipt' ELSE 'job' END
            WHERE o.id=?1 AND o.kind=?2",
            params![operation_id, lane.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let recent_name = format!("reconciliation:{}", lane.as_str());
        let fair_name = format!("reconciliation:fair:{}", lane.as_str());
        let missing_name = format!("reconciliation:missing:{}", lane.as_str());
        let recent = self.reconciliation_schedule(&recent_name)?;
        let service = service.unwrap_or(if missing {
            ReconciliationService::Missing
        } else if recent.0 > at {
            ReconciliationService::Fair
        } else {
            ReconciliationService::Recent
        });
        let fair = service != ReconciliationService::Recent;
        if missing != (service == ReconciliationService::Missing)
            || next_at > at
            || (!fair && recent.0 > at)
            || (fair && self.reconciliation_schedule(&fair_name)?.0 > at)
            || (missing && self.reconciliation_schedule(&missing_name)?.0 > at)
        {
            return Ok(false);
        }
        let (_, purpose, _, remote) = self.read_parts(key)?;
        let endpoint = if purpose == "receipt" {
            Endpoint::Receipt
        } else {
            Endpoint::Job
        };
        if self.request_not_before(config, endpoint, remote.as_deref())? > at {
            return Ok(false);
        }
        if !self.start_read_in(key, at)? {
            return Ok(false);
        }
        let schedule = config.schedule(lane);
        let interval = schedule
            .queued_job_polling
            .map_or(schedule.retry_seconds, |policy| policy.initial_seconds)
            .max(1);
        let deadline = |seconds: u64| {
            at.saturating_add(seconds.min(i64::MAX as u64) as i64)
                .saturating_add(1)
        };
        let name = if fair { &fair_name } else { &recent_name };
        tx.execute(
            "INSERT INTO schedule(kind,next_at,served_in_round) VALUES (?1,?2,?3)
            ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at,
                served_in_round=excluded.served_in_round",
            params![name, deadline(interval), missing],
        )?;
        let cursor_name = match service {
            ReconciliationService::Recent => None,
            ReconciliationService::Fair => Some(&fair_name),
            ReconciliationService::Missing => Some(&missing_name),
        };
        if let Some(cursor_name) = cursor_name {
            // A captured run-once batch may outlive a later selection. Do not
            // rewind a different walk when claiming that older snapshot.
            tx.execute(
                "UPDATE schedule SET cursor=?2 WHERE kind=?1 AND CAST(cursor AS INTEGER)=?3",
                params![
                    cursor_name,
                    operation_id.to_string(),
                    operation_id.saturating_add(1)
                ],
            )?;
        }
        if missing {
            tx.execute(
                "INSERT INTO schedule(kind,next_at) VALUES (?1,?2)
                ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at",
                params![
                    missing_name,
                    deadline(schedule.backoff_max_seconds.max(interval))
                ],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn wake_delay(&self, config: &Config, fallback: u64) -> Result<u64> {
        self.wake_delay_at(config, fallback, now())
    }

    fn wake_delay_at(&self, config: &Config, fallback: u64, current: i64) -> Result<u64> {
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
            // Probe lane presence, not every retained resource floor. Selection
            // and claim still enforce those floors; the configured cadence is
            // a conservative wake bound while an unfinished walk has work.
            let pending: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM operations INDEXED BY operations_reconciliation
                WHERE kind=?1 AND state IN ('queued','unknown','included_pending','confirmed')
                AND (job_id IS NOT NULL OR txid IS NOT NULL))",
                [lane.as_str()],
                |row| row.get(0),
            )?;
            if pending {
                let schedule = config.schedule(lane);
                let interval = schedule
                    .queued_job_polling
                    .map_or(schedule.retry_seconds, |policy| policy.initial_seconds)
                    .max(1);
                deadline =
                    deadline.min(current.saturating_add(interval.min(i64::MAX as u64) as i64));
                for name in [
                    format!("reconciliation:{}", lane.as_str()),
                    format!("reconciliation:fair:{}", lane.as_str()),
                    format!("reconciliation:missing:{}", lane.as_str()),
                ] {
                    let next = self.reconciliation_schedule(&name)?.0;
                    if next > current {
                        deadline = deadline.min(next);
                    }
                }
            }
        }
        let restriction: Option<i64> = self
            .db
            .query_row(
                "SELECT not_before FROM request_restrictions WHERE not_before>?1
                ORDER BY not_before LIMIT 1",
                [current],
                |row| row.get(0),
            )
            .optional()?;
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

#[cfg(test)]
#[path = "reconciliation_tests.rs"]
mod tests;
