//! Durable inference accounting. Scheduling labels never refund possible execution.
use super::*;
use crate::config::{CountLimit, Preparation};
use serde::{Deserialize, Serialize};

const MODEL_RETRY_PAGE_SIZE: i64 = 32;

fn retry_schedule_in(db: &Connection, name: &str) -> Result<(i64, Option<String>)> {
    Ok(db
        .query_row(
            "SELECT next_at,cursor FROM schedule WHERE kind=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .unwrap_or_default())
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ModelRetryAssessment {
    pub total_attempts: u64,
    pub unresolved_attempts: u64,
    pub reserved_attempts: u64,
    pub attempt_limit: CountLimit,
    pub uncertain_replacement_limit: u32,
    pub retry_eligible: bool,
    pub next_at: Option<i64>,
    pub blocker: Option<&'static str>,
}

#[derive(Default)]
struct ModelRetryFacts {
    total: u64,
    unresolved: u64,
    reserved: u64,
    next_at: i64,
}

impl Store {
    fn model_retry_facts_in(
        db: &Connection,
        kind: LaneId,
        key: &str,
        excluding_reservation: Option<i64>,
    ) -> Result<ModelRetryFacts> {
        // The work-key index bounds this scan to one logical work item. Immutable
        // native completion is authoritative, not mutable diagnostic evidence or
        // scheduling state. Legacy incomplete attempts remain possibly running.
        Ok(db.query_row(
            "WITH attempts AS (
                SELECT o.id,o.state,o.next_at,o.payload,o.job_id,o.txid,
                    e.model_attempt,
                    json_extract(e.model_attempt,'$.completion.execution') AS execution,
                    json_extract(e.model_attempt,'$.launch') AS launch,
                    CASE WHEN e.model_attempt IS NULL THEN
                        CASE WHEN o.state='prelaunch_failed' THEN 'not_started'
                             WHEN o.payload IS NOT NULL THEN 'completed'
                             ELSE 'unknown' END
                    ELSE NULL END AS legacy_execution
                FROM operations o LEFT JOIN operation_evidence e ON e.operation_id=o.id
                WHERE o.kind=?1 AND o.work_key=?2 COLLATE NOCASE
                AND NOT EXISTS(SELECT 1 FROM operation_links l
                    WHERE l.operation_id=o.id AND l.payload_reused=1)
                AND NOT (e.model_attempt IS NULL AND
                    json_extract(o.request,'$.local_abstention') IS NOT NULL)
            ), classified AS (
                SELECT *,CASE WHEN execution IN ('not_started','completed') THEN execution
                    WHEN execution IS NOT NULL THEN 'unknown'
                    ELSE COALESCE(legacy_execution,
                        CASE WHEN launch IS NOT NULL THEN 'unknown' ELSE 'not_started' END) END AS certainty
                FROM attempts
            ) SELECT
                COALESCE(SUM(certainty!='not_started'),0),
                COALESCE(SUM(certainty='unknown'),0),
                COALESCE(SUM(model_attempt IS NOT NULL AND execution IS NULL AND launch IS NULL
                    AND state='generating' AND (?3 IS NULL OR id!=?3)),0),
                COALESCE(MAX(CASE WHEN payload IS NULL AND job_id IS NULL AND txid IS NULL
                    AND state IN ('rejected','model_unknown','superseded_model_unknown','retry_model',
                        'prelaunch_failed','discarded','abandoned_model') THEN next_at ELSE 0 END),0)
            FROM classified",
            params![kind.as_str(), key, excluding_reservation],
            |row| Ok(ModelRetryFacts {
                total: row.get(0)?,
                unresolved: row.get(1)?,
                reserved: row.get(2)?,
                next_at: row.get(3)?,
            }),
        )?)
    }

    fn assess_model_retry_in(
        db: &Connection,
        kind: LaneId,
        key: &str,
        preparation: Preparation,
        at: i64,
        excluding_reservation: Option<i64>,
    ) -> Result<ModelRetryAssessment> {
        let facts = Self::model_retry_facts_in(db, kind, key, excluding_reservation)?;
        let blocker = if !preparation
            .max_attempts_per_work
            .allows(facts.total.saturating_add(facts.reserved))
        {
            Some("model_budget_exhausted")
        } else if facts.unresolved > 0 && !preparation.retry_uncertain {
            Some("model_uncertain_retry_disabled")
        } else if facts.unresolved.saturating_add(facts.reserved)
            > u64::from(preparation.max_uncertain_replacements_per_work)
        {
            Some("model_uncertain_replacement_exhausted")
        } else if facts.reserved > 0 {
            Some("model_preparation_reserved")
        } else if facts.next_at > at {
            Some("model_retry_cooldown")
        } else {
            None
        };
        Ok(ModelRetryAssessment {
            total_attempts: facts.total,
            unresolved_attempts: facts.unresolved,
            reserved_attempts: facts.reserved,
            attempt_limit: preparation.max_attempts_per_work,
            uncertain_replacement_limit: preparation.max_uncertain_replacements_per_work,
            retry_eligible: blocker.is_none(),
            next_at: (blocker == Some("model_retry_cooldown")).then_some(facts.next_at),
            blocker,
        })
    }

    pub(crate) fn model_retry_assessment(
        &self,
        kind: LaneId,
        key: &str,
        config: &Config,
        at: i64,
    ) -> Result<ModelRetryAssessment> {
        Self::model_retry_assessment_in(&self.db, kind, key, config, at, None)
    }

    pub(super) fn model_retry_assessment_in(
        db: &Connection,
        kind: LaneId,
        key: &str,
        config: &Config,
        at: i64,
        excluding_reservation: Option<i64>,
    ) -> Result<ModelRetryAssessment> {
        Self::assess_model_retry_in(
            db,
            kind,
            key,
            config
                .preparation(kind)
                .context("model preparation policy missing")?,
            at,
            excluding_reservation,
        )
    }

    // Reservation and launch both intersect current policy with the immutable
    // entry policy. In particular, run --once cannot expand its entry allowance.
    pub(super) fn model_retry_admission_in(
        db: &Connection,
        kind: LaneId,
        key: &str,
        config: &Config,
        at: i64,
        excluding_reservation: Option<i64>,
        policy: &Value,
    ) -> Result<ModelRetryAssessment> {
        let mut preparation = config
            .preparation(kind)
            .context("model preparation policy missing")?;
        if let Some(limit) = policy.get("max_attempts_per_work") {
            preparation.max_attempts_per_work = preparation
                .max_attempts_per_work
                .intersect(CountLimit::deserialize(limit)?);
        }
        if let Some(retry) = policy.get("retry_uncertain").and_then(Value::as_bool) {
            preparation.retry_uncertain &= retry;
        }
        if let Some(limit) = policy
            .get("max_uncertain_replacements_per_work")
            .and_then(Value::as_u64)
        {
            preparation.max_uncertain_replacements_per_work = preparation
                .max_uncertain_replacements_per_work
                .min(u32::try_from(limit).context("invalid captured uncertain replacement limit")?);
        }
        Self::assess_model_retry_in(db, kind, key, preparation, at, excluding_reservation)
    }

    #[cfg(test)]
    pub(crate) fn model_budget_used(&self, kind: LaneId, key: &str) -> Result<u32> {
        let facts = Self::model_retry_facts_in(&self.db, kind, key, None)?;
        Ok(u32::try_from(facts.total.saturating_add(facts.reserved)).unwrap_or(u32::MAX))
    }

    #[cfg(test)]
    pub(crate) fn model_retry_not_before(&self, kind: LaneId, key: &str) -> Result<i64> {
        Ok(Self::model_retry_facts_in(&self.db, kind, key, None)?.next_at)
    }

    pub(crate) fn retry_models(&mut self, config: &Config) -> Result<()> {
        self.retry_models_at(config, now())
    }

    pub(super) fn retry_models_at(&mut self, config: &Config, at: i64) -> Result<()> {
        self.continuity()?;
        let mut lanes = [None, None];
        for (slot, (kind, recent_name, fair_name)) in lanes.iter_mut().zip([
            (
                LaneId::Answer,
                "model_retry:answer",
                "model_retry:fair:answer",
            ),
            (LaneId::Judge, "model_retry:judge", "model_retry:fair:judge"),
        ]) {
            let schedule = config.schedule(kind);
            let policy = serde_json::to_string(&(
                config.preparation(kind),
                schedule.retry_seconds,
                schedule.backoff_max_seconds,
            ))?;
            let recent = retry_schedule_in(&self.db, recent_name)?;
            let fair = retry_schedule_in(&self.db, fair_name)?;
            if recent.0 <= at || fair.0 <= at || recent.1.as_deref() != Some(policy.as_str()) {
                *slot = Some((kind, recent_name, fair_name, policy));
            }
        }
        // The ordinary driver advance only reads the durable service clocks.
        // Restart does not refund maintenance service or any model retry anchor.
        if lanes.iter().all(Option::is_none) {
            return Ok(());
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (kind, recent_name, fair_name, policy) in lanes.into_iter().flatten() {
            let recent = retry_schedule_in(&tx, recent_name)?;
            let fair = retry_schedule_in(&tx, fair_name)?;
            let policy_changed = recent.1.as_deref() != Some(policy.as_str());
            let mut candidates = Vec::with_capacity(2 * MODEL_RETRY_PAGE_SIZE as usize);
            let schedule = config.schedule(kind);
            let next_service =
                |seconds: u64| at.saturating_add(seconds.max(1).min(i64::MAX as u64) as i64);
            if recent.0 <= at || policy_changed {
                // Limit the indexed page BEFORE cooldown, key deduplication or
                // canonical assessment. A recent completion of an old ID also
                // receives prompt service, independently of the historical walk.
                let mut statement = tx.prepare(
                    "SELECT id,work_key,next_at FROM operations
                     INDEXED BY operations_model_retry_recent
                     WHERE kind=?1 AND state IN ('rejected','model_unknown')
                     AND payload IS NULL AND job_id IS NULL AND txid IS NULL
                     ORDER BY updated_at DESC,id DESC LIMIT ?2",
                )?;
                let rows =
                    statement.query_map(params![kind.as_str(), MODEL_RETRY_PAGE_SIZE], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?;
                for row in rows {
                    candidates.push(row?);
                }
                tx.execute(
                    "INSERT INTO schedule(kind,next_at,cursor) VALUES(?1,?2,?3)
                     ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at,cursor=excluded.cursor",
                    params![recent_name, next_service(schedule.retry_seconds), policy],
                )?;
            }
            if fair.0 <= at || policy_changed {
                let cursor = fair
                    .1
                    .as_deref()
                    .map(str::parse::<i64>)
                    .transpose()?
                    .unwrap_or(0);
                let mut statement = tx.prepare(
                    "SELECT id,work_key,next_at FROM operations
                     INDEXED BY operations_model_retry_fair
                     WHERE kind=?1 AND id<=?2 AND state IN ('rejected','model_unknown')
                     AND payload IS NULL AND job_id IS NULL AND txid IS NULL
                     ORDER BY id DESC LIMIT ?3",
                )?;
                let mut page = |ceiling| -> Result<Vec<(i64, String, i64)>> {
                    Ok(statement
                        .query_map(
                            params![kind.as_str(), ceiling, MODEL_RETRY_PAGE_SIZE],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )?
                        .collect::<rusqlite::Result<Vec<_>>>()?)
                };
                let mut historical = page(if cursor > 0 { cursor - 1 } else { i64::MAX })?;
                if historical.is_empty() && cursor > 0 {
                    historical = page(i64::MAX)?;
                }
                // Advance over EVERY examined row, including cooldown/policy
                // blockers. Newer work and policy changes cannot reset this walk.
                let next_cursor = historical.last().map_or(0, |row| row.0);
                for candidate in historical {
                    if !candidates.iter().any(|row| row.0 == candidate.0) {
                        candidates.push(candidate);
                    }
                }
                tx.execute(
                    "INSERT INTO schedule(kind,next_at,cursor) VALUES(?1,?2,?3)
                     ON CONFLICT(kind) DO UPDATE SET next_at=excluded.next_at,cursor=excluded.cursor",
                    params![
                        fair_name,
                        next_service(schedule.backoff_max_seconds.max(schedule.retry_seconds)),
                        next_cursor.to_string()
                    ],
                )?;
            }
            let mut assessed = std::collections::HashMap::with_capacity(candidates.len());
            for (id, mut key, next_at) in candidates {
                if next_at > at {
                    continue;
                }
                // SQLite NOCASE folds ASCII only. Share one authoritative
                // assessment per work key across both bounded pages.
                key.make_ascii_lowercase();
                let eligible = match assessed.entry(key) {
                    std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let eligible = Self::model_retry_assessment_in(
                            &tx,
                            kind,
                            entry.key(),
                            config,
                            at,
                            None,
                        )?
                        .retry_eligible;
                        *entry.insert(eligible)
                    }
                };
                if eligible {
                    // Only scheduling labels on this page change. Do not turn a
                    // bounded selection into an unbounded same-key UPDATE.
                    tx.execute(
                        "UPDATE operations SET state=CASE WHEN state='model_unknown'
                            THEN 'superseded_model_unknown' ELSE 'retry_model' END,updated_at=?2
                         WHERE id=?1 AND state IN ('rejected','model_unknown') AND next_at<=?2
                         AND payload IS NULL AND job_id IS NULL AND txid IS NULL",
                        params![id, at],
                    )?;
                }
            }
        }
        Self::continuity_in(&tx, &self.binding, &self.writer_path, &self.database_file)?;
        tx.commit()?;
        Ok(())
    }
}
