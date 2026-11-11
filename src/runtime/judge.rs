use super::*;
use crate::solver::contract::GradeTask;

pub(super) struct GradeInputMatch {
    pending_key: PendingWorkKey,
    observation: Observation,
    matched_lane_config_revision: String,
}
impl GradeInputMatch {
    pub(super) fn into_parts(self) -> (PendingWorkKey, Observation, String) {
        (
            self.pending_key,
            self.observation,
            self.matched_lane_config_revision,
        )
    }
}
#[derive(Clone)]
enum Target {
    Prepared(Operation),
    Pending(PendingWorkKey, String),
}
impl Target {
    fn id(&self) -> &str {
        match self {
            Self::Prepared(op) => &op.key,
            Self::Pending(_, id) => id,
        }
    }
}
struct InventorySource {
    observation: Observation,
    completed_at: i64,
    rows: std::ops::Range<usize>,
}
struct Inventory {
    response: Response,
    ids: Vec<String>,
    // Each candidate retains the page's original authority and freshness deadline.
    sources: [Option<InventorySource>; 4],
    pages: usize,
    offset: u64,
    complete: bool,
    more: bool,
    usable: bool,
    eligible_candidates: usize,
    exclusions: std::collections::BTreeMap<&'static str, usize>,
    target: Option<Target>,
}
impl Inventory {
    fn source(&self, index: usize) -> &InventorySource {
        self.sources
            .iter()
            .flatten()
            .find(|source| source.rows.contains(&index))
            .expect("candidate page source")
    }

    fn candidate_source(&self, id: &str) -> Result<&InventorySource> {
        let index = self
            .ids
            .iter()
            .position(|candidate| candidate == id)
            .context("candidate source missing")?;
        Ok(self.source(index))
    }
}
enum JudgeReadKind {
    Page,
    Hydration { id: String },
}
struct JudgeRead {
    flight: ReadFlight,
    kind: JudgeReadKind,
    target: Option<Target>,
}
struct Selected {
    assignment: Assignment,
    observation: Observation,
}
#[derive(Default)]
pub(super) struct JudgeLane {
    read: Option<JudgeRead>,
    inventory: Option<Inventory>,
    selected: Option<Selected>,
    model: GradeModelSlot,
    pub(super) ready: Option<ReadyEffect>,
}
impl JudgeLane {
    pub(super) fn busy(&self) -> bool {
        self.read.is_some() || self.model.busy()
    }
    pub(super) fn collect(&mut self, services: &mut GradeServices<'_>) -> Result<()> {
        services.collect_reconciliation()?;
        services.collect_model(&mut self.model)?;
        let Some(read) = self.read.as_mut() else {
            return Ok(());
        };
        let Some(result) = read.flight.take() else {
            return Ok(());
        };
        let read = self.read.take().expect("judge read completion");
        let response = services.finish_read(&read.flight, result)?;
        let observation = services.observation(&read.flight)?;
        if !services.observation_current(&observation)? {
            self.inventory = None;
            return Ok(());
        }
        match read.kind {
            JudgeReadKind::Page => {
                let Some(mut response) = response else {
                    if let Some(inventory) = self.inventory.as_mut() {
                        inventory.more = false;
                        inventory.usable = false;
                    }
                    return Ok(());
                };
                let Ok(mut ids) = assignment_ids(&response) else {
                    services.evaluate_inventory(false)?;
                    if let Some(inventory) = self.inventory.as_mut() {
                        inventory.more = false;
                        inventory.usable = false;
                    }
                    return Ok(());
                };
                let has_more = response.body["has_more"].as_bool();
                let rows = response.body["assignments"]
                    .as_array_mut()
                    .context("assignment rows missing")?;
                let complete = has_more == Some(false);
                let more = has_more == Some(true) && !rows.is_empty();
                if let Some(inventory) = self.inventory.as_mut() {
                    let known: std::collections::HashSet<_> =
                        inventory.ids.iter().map(String::as_str).collect();
                    let mut added = 0;
                    for (id, row) in ids.iter().zip(rows.iter_mut()) {
                        if !known.contains(id.as_str()) {
                            inventory.response.body["assignments"]
                                .as_array_mut()
                                .context("inventory rows missing")?
                                .push(row.take());
                            added += 1;
                        }
                    }
                    ids.retain(|id| !known.contains(id.as_str()));
                    drop(known);
                    inventory.ids.append(&mut ids);
                    let end = inventory.response.body["assignments"]
                        .as_array()
                        .context("inventory rows missing")?
                        .len();
                    inventory.sources[inventory.pages] = Some(InventorySource {
                        observation,
                        completed_at: read.flight.completed_at,
                        rows: end - added..end,
                    });
                    inventory.pages += 1;
                    inventory.offset = inventory.offset.saturating_add(rows.len() as u64);
                    inventory.complete = complete;
                    inventory.more = more && added != 0 && inventory.pages < 4;
                    inventory.response.body["has_more"] = json!(!complete);
                } else {
                    let offset = rows.len() as u64;
                    self.inventory = Some(Inventory {
                        response,
                        ids,
                        sources: [
                            Some(InventorySource {
                                observation,
                                completed_at: read.flight.completed_at,
                                rows: 0..offset as usize,
                            }),
                            None,
                            None,
                            None,
                        ],
                        pages: 1,
                        offset,
                        complete,
                        more,
                        usable: true,
                        eligible_candidates: 0,
                        exclusions: Default::default(),
                        target: read.target,
                    });
                }
                if let Some(inventory) = self.inventory.as_mut()
                    && inventory
                        .target
                        .as_ref()
                        .is_some_and(|target| inventory.ids.iter().any(|id| id == target.id()))
                {
                    inventory.more = false;
                }
                // Bounded and targeted traversals are evidence, not whole-read recovery.
                if let Some(inventory) = self.inventory.as_ref() {
                    let mut recovered = inventory.complete && inventory.usable;
                    for source in inventory.sources.iter().flatten() {
                        recovered &= services.observation_current(&source.observation)?;
                    }
                    if recovered {
                        services.evaluate_inventory(true)?;
                    }
                }
                if let Some(selected) = self.selected.as_ref()
                    && services.observation_current(&selected.observation)?
                {
                    self.report(
                        services,
                        Some(!selected.assignment.words.is_empty()),
                        selected
                            .assignment
                            .words
                            .is_empty()
                            .then_some("required_words_absent"),
                        Some(&selected.assignment.id),
                    )?;
                }
            }
            JudgeReadKind::Hydration { id } => {
                if let Some(response) = response {
                    self.accept_assignment(services, &id, Some(&response))?;
                }
            }
        }
        Ok(())
    }
    fn inventory_current(&self, services: &GradeServices<'_>) -> Result<bool> {
        if let Some(inventory) = &self.inventory {
            for source in inventory.sources.iter().flatten() {
                if services.observation_current(&source.observation)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn start_inventory(
        &mut self,
        services: &mut GradeServices<'_>,
        target: Option<Target>,
    ) -> Result<bool> {
        if let Some(flight) = services.begin_discovery(None)? {
            self.inventory = None;
            self.selected = None;
            self.read = Some(JudgeRead {
                flight,
                kind: JudgeReadKind::Page,
                target,
            });
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(super) fn plan(&mut self, services: &mut GradeServices<'_>) -> Result<()> {
        services.poll_reconciliation()?;
        if let Some(ready) = self.ready.as_ref()
            && !services.ready_current(ready)?
        {
            self.ready = None;
        }
        if !self.inventory_current(services)? && self.read.is_none() {
            self.inventory = None;
            self.selected = None;
        }
        if services.active()?
            && let Some(selected) = self.selected.as_ref()
            && let Some(pending) = self.model.pending_work()
        {
            let key = pending.key.clone();
            let decision = match_pending(
                &selected.assignment,
                pending,
                selected.observation.clone(),
                &services.lane_revision()?,
                services.observation_current(&selected.observation)?,
            );
            match decision {
                PendingInputDecision::Unchanged(matched) => {
                    services.launch_pending(&mut self.model, matched)?
                }
                PendingInputDecision::Retire(reason) => {
                    services.retire_pending(&mut self.model, &key, reason.code())?
                }
                PendingInputDecision::Wait(_reason) => {}
            }
        }
        if let Some(pending) = self.model.pending_work() {
            let key = pending.key;
            let id = pending
                .task
                .request()
                .assignment
                .as_ref()
                .context("grade task assignment missing")?
                .clone();
            if services.config().mode == Mode::Off || services.assignment_excluded(&id) {
                services.retire_pending(&mut self.model, &key, "model_lane_closed")?;
            } else if services.active()?
                && self.read.is_none()
                && self.selected.is_none()
                && !self
                    .inventory
                    .as_ref()
                    .and_then(|i| i.target.as_ref())
                    .is_some_and(
                        |target| matches!(target,Target::Pending(existing,_) if existing == &key),
                    )
                && services.fresh_allowed(key.operation.operation_id)
            {
                self.start_inventory(services, Some(Target::Pending(key, id)))?;
                services.start_identity()?;
            }
        }
        if let Some(op) = services.preparation()?
            && self.read.is_none()
            && self.ready.is_none()
        {
            let targeted = self
                .inventory
                .as_ref()
                .and_then(|i| i.target.as_ref())
                .is_some_and(
                    |target| matches!(target,Target::Prepared(current) if current.id == op.id),
                );
            if !targeted
                && services.active()?
                && op.next_at <= services.deadline_now()
                && services.admission_allowed(&op)?
                && services.fresh_allowed(op.id)
                && self.start_inventory(services, Some(Target::Prepared(op)))?
            {
                services.start_identity()?;
            }
        }
        if let Some(selected) = self.selected.as_ref()
            && (!services.observation_current(&selected.observation)?
                || (!self.model.occupied()
                    && services
                        .assignment_blocker(&selected.assignment.id)?
                        .is_some()))
        {
            self.selected = None;
        }
        // Consume completed inventory before an overdue poll can replace it.
        // Assessment and bounded hydration are read-only in every non-off mode.
        if self.read.is_none()
            && self.selected.is_none()
            && services.config().mode != Mode::Off
            && (!self.model.occupied()
                || self.inventory.as_ref().is_some_and(|inventory| {
                    matches!(inventory.target.as_ref(), Some(Target::Pending(..)))
                }))
        {
            self.select(services)?;
        }
        self.prepare(services)?;
        if self.read.is_none() && self.inventory.as_ref().is_some_and(|i| i.more) {
            let offset = self.inventory.as_ref().expect("paged inventory").offset;
            if let Some(flight) = services.begin_discovery(Some(offset))? {
                self.read = Some(JudgeRead {
                    flight,
                    kind: JudgeReadKind::Page,
                    target: None,
                });
            }
        }
        if self.read.is_none()
            && services.discovery_allowed()?
            && self.inventory.as_ref().is_none_or(|i| i.target.is_none())
            && (!services.active()? || (self.selected.is_none() && !self.model.occupied()))
            && self.start_inventory(services, None)?
        {
            services.discovered()?;
        }
        Ok(())
    }
    fn candidates(
        &self,
        services: &GradeServices<'_>,
    ) -> Result<(Vec<String>, std::collections::BTreeMap<&'static str, usize>)> {
        let mut exclusions = std::collections::BTreeMap::new();
        let Some(inventory) = &self.inventory else {
            return Ok((Vec::new(), exclusions));
        };
        let rows = inventory.response.body["assignments"]
            .as_array()
            .context("assignment rows missing")?;
        let mut ranked = Vec::new();
        for (index, (id, row)) in inventory.ids.iter().zip(rows).enumerate() {
            if let Some(target) = &inventory.target
                && id != target.id()
            {
                continue;
            }
            let source = inventory.source(index);
            if !services.observation_current(&source.observation)? {
                *exclusions.entry("observation_stale").or_insert(0) += 1;
            } else if inventory.target.is_none()
                && let Some(reason) = services.assignment_blocker(id)?
            {
                *exclusions.entry(reason).or_insert(0) += 1;
            } else {
                ranked.push((
                    row["pending_meta"]["expires_at_epoch"]
                        .as_u64()
                        .unwrap_or(u64::MAX),
                    id,
                ));
            }
        }
        ranked.sort_unstable();
        Ok((
            ranked.into_iter().map(|(_, id)| id.clone()).collect(),
            exclusions,
        ))
    }
    fn report(
        &self,
        services: &GradeServices<'_>,
        selected: Option<bool>,
        reason: Option<&'static str>,
        candidate: Option<&str>,
    ) -> Result<()> {
        let Some(inventory) = &self.inventory else {
            return Ok(());
        };
        let count = inventory.response.body["assignments"]
            .as_array()
            .map_or(0, Vec::len);
        let source = match candidate {
            Some(id) => inventory.candidate_source(id)?,
            None => inventory.sources[inventory.pages - 1]
                .as_ref()
                .context("inventory source missing")?,
        };
        let mut complete = inventory.complete && inventory.usable;
        let mut valid_until = source.observation.admit_before_unix;
        for source in inventory.sources.iter().flatten() {
            complete &= services.observation_current(&source.observation)?;
            valid_until = valid_until.min(source.observation.admit_before_unix);
        }
        services.participation(&source.observation, &json!({"source":"validated_assignment_inventory","observed_at":source.completed_at,
            "valid_until":valid_until,
            "completeness":if complete {"complete"} else {"bounded_partial"},
            "observed_opportunities":count,"eligible_candidates":inventory.eligible_candidates,"exclusions":inventory.exclusions,"locally_judgeable":selected,
            "assessment_reason":reason,"assessment_creates_model_work":false,"outcome":"unobserved"}))
    }
    fn select(&mut self, services: &mut GradeServices<'_>) -> Result<()> {
        if !self.inventory_current(services)? {
            return Ok(());
        }
        let (candidates, exclusions) = self.candidates(services)?;
        let Some(inventory) = &mut self.inventory else {
            return Ok(());
        };
        inventory.eligible_candidates = candidates.len();
        inventory.exclusions = exclusions;
        if candidates.is_empty() {
            if let Some(target) = inventory.target.clone() {
                let mut complete = inventory.complete && inventory.usable;
                for source in inventory.sources.iter().flatten() {
                    complete &= services.observation_current(&source.observation)?;
                }
                if complete {
                    match target {
                        Target::Prepared(op) => services
                            .retire_unsent(&services.binding(&op)?, "request_no_longer_current")?,
                        Target::Pending(key, _) => services.retire_pending(
                            &mut self.model,
                            &key,
                            "request_no_longer_current",
                        )?,
                    }
                    self.inventory = None;
                } else if !inventory.more {
                    self.inventory = None;
                }
            } else if !inventory.more {
                self.report(services, Some(false), Some("excluded_or_unavailable"), None)?;
            }
            return Ok(());
        }
        self.report(services, None, Some("assessment_pending"), None)?;
        for id in candidates {
            let inventory = self.inventory.as_ref().expect("selection inventory");
            match assignment_needs_hydration(&inventory.response, &id) {
                Ok(true) => {
                    if let Some(flight) =
                        services.begin_hydration(&id, inventory.target.is_none())?
                    {
                        self.read = Some(JudgeRead {
                            flight,
                            kind: JudgeReadKind::Hydration { id },
                            target: None,
                        });
                        return Ok(());
                    }
                }
                Ok(false) => {
                    self.accept_assignment(services, &id, None)?;
                    if self.selected.is_some() || self.ready.is_some() || self.inventory.is_none() {
                        return Ok(());
                    }
                }
                Err(_) => {
                    services.evaluate_assignment(&id, false)?;
                    self.report(services, None, Some("assignment_unreadable"), Some(&id))?;
                }
            }
        }
        Ok(())
    }
    fn accept_assignment(
        &mut self,
        services: &mut GradeServices<'_>,
        id: &str,
        hydrated: Option<&Response>,
    ) -> Result<()> {
        if services.assignment_excluded(id) {
            return Ok(());
        }
        let inventory = self.inventory.as_ref().expect("assignment inventory");
        let source = inventory.candidate_source(id)?;
        if !services.observation_current(&source.observation)? {
            return Ok(());
        }
        let assignment = match parse_selected_assignment(&inventory.response, id, hydrated) {
            Ok(assignment) => assignment,
            Err(_) => {
                services.evaluate_assignment(id, false)?;
                self.report(services, None, Some("assignment_unreadable"), Some(id))?;
                return Ok(());
            }
        };
        services.evaluate_assignment(id, true)?;
        if let Some(target) = inventory.target.clone() {
            match target {
                Target::Prepared(op) => {
                    let binding = services.binding(&op)?;
                    if !services.draft_current(&binding)? {
                        self.inventory = None;
                        return Ok(());
                    }
                    let input: Input = serde::Deserialize::deserialize(&op.request)?;
                    if assignment_matches(&assignment, &input.solver) {
                        let intent = crate::protocol::GradeIntent::new(
                            op.payload.as_ref().context("grade payload missing")?,
                        )?;
                        self.ready = Some(services.emit_ready(
                            intent,
                            binding,
                            source.observation.clone(),
                        )?);
                    } else {
                        services.retire_unsent(&binding, "request_no_longer_current")?;
                    }
                }
                Target::Pending(key, _) => {
                    if let Some(pending) = self.model.pending_work()
                        && pending.key == key
                    {
                        let decision = match_pending(
                            &assignment,
                            pending,
                            source.observation.clone(),
                            &services.lane_revision()?,
                            true,
                        );
                        match decision {
                            PendingInputDecision::Unchanged(matched) => {
                                services.launch_pending(&mut self.model, matched)?
                            }
                            PendingInputDecision::Retire(reason) => {
                                services.retire_pending(&mut self.model, &key, reason.code())?
                            }
                            PendingInputDecision::Wait(_reason) => {}
                        }
                        if self.model.pending_work().is_some() {
                            self.selected = Some(Selected {
                                assignment,
                                observation: source.observation.clone(),
                            });
                            return Ok(());
                        }
                    }
                }
            }
            self.inventory = None;
        } else {
            let judgeable = !assignment.words.is_empty();
            self.report(
                services,
                Some(judgeable),
                (!judgeable).then_some("required_words_absent"),
                Some(id),
            )?;
            self.selected = Some(Selected {
                assignment,
                observation: source.observation.clone(),
            });
        }
        Ok(())
    }
    fn prepare(&mut self, services: &mut GradeServices<'_>) -> Result<()> {
        if self.model.occupied()
            || services.effect_busy()
            || !services.active()?
            || !services.effect_allowed()
            || services.has_preparation()?
        {
            return Ok(());
        }
        let Some(selected) = &self.selected else {
            return Ok(());
        };
        if !services.observation_current(&selected.observation)?
            || services
                .assignment_blocker(&selected.assignment.id)?
                .is_some()
        {
            self.selected = None;
            return Ok(());
        }
        // Missing rubric/input is sourced abstention evidence, never a model attempt or grant.
        if selected.assignment.words.is_empty() {
            if services.record_abstention(&selected.assignment, &selected.observation)? {
                self.selected = None;
            }
            return Ok(());
        }
        let task = services.task(&selected.assignment)?;
        // Retain the bound input through preflight and pending admission. The
        // generating operation belongs to this slot, not a competing attempt.
        services.begin_model(
            &mut self.model,
            task,
            &selected.assignment.id,
            &selected.observation,
        )?;
        Ok(())
    }
    pub(super) async fn cancel(
        &mut self,
        services: &mut GradeServices<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        if let Some(read) = self.read.as_mut() {
            read.flight.abort(deadline).await;
        }
        self.collect(services)?;
        if let Some(read) = self.read.take() {
            services.cancel_read(&read.flight)?;
        }
        services.cancel_reconciliation(deadline).await?;
        services.cancel_model(&mut self.model, deadline).await
    }
}
fn match_pending(
    assignment: &Assignment,
    pending: PendingWorkRef<'_, GradeTask>,
    observation: Observation,
    revision: &str,
    current: bool,
) -> PendingInputDecision<GradeInputMatch> {
    if revision != pending.producer.lane_config_revision {
        return PendingInputDecision::Retire(PendingRetirementReason::ConfigChanged);
    }
    if !current {
        return PendingInputDecision::Wait(PendingWaitReason::ObservationStale);
    }
    if !assignment_matches(assignment, pending.task.request()) {
        return PendingInputDecision::Retire(PendingRetirementReason::InputChanged);
    }
    PendingInputDecision::Unchanged(GradeInputMatch {
        pending_key: pending.key,
        observation,
        matched_lane_config_revision: revision.to_owned(),
    })
}
pub(super) fn assignment_matches(assignment: &Assignment, request: &SolverRequest) -> bool {
    request
        .assignment
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(&assignment.id))
        && request.epoch == assignment.epoch
        && request.candidate.as_deref() == Some(assignment.answer.as_str())
        && request.words == assignment.words
        && request.author_history.as_ref() == Some(&assignment.author_prior)
        && request.candidate_author == assignment.author
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::runtime::host::{HostAccess, tests};
    use crate::solver::contract::ModelSelection;
    use crate::store::now;

    fn paged_inventory(runtime: &HostAccess, count: usize) -> Inventory {
        let mut sources = [None, None, None, None];
        let mut rows = Vec::new();
        for (index, source) in sources.iter_mut().enumerate().take(count) {
            rows.push(json!({
                "answer_txid": format!("{:064x}", index + 1),
                "answer_epoch": 8,
                "answer": "burning candidate",
                "words": ["burn"],
                "pending_meta": {"expires_at_epoch": index + 10},
            }));
            *source = Some(InventorySource {
                observation: tests::observation(runtime, LaneId::Judge),
                completed_at: now(),
                rows: index..index + 1,
            });
        }
        Inventory {
            ids: rows
                .iter()
                .map(|row| row["answer_txid"].as_str().unwrap().to_owned())
                .collect(),
            response: Response {
                status: 200,
                body: json!({"assignments": rows, "has_more": true}),
                retry_after_seconds: None,
                read_failure: None,
            },
            sources,
            pages: count,
            offset: count as u64,
            complete: false,
            more: count < 4,
            usable: true,
            eligible_candidates: 0,
            exclusions: Default::default(),
            target: None,
        }
    }

    #[tokio::test]
    async fn partial_page_is_assessed_before_next_read_and_hydration_cannot_renew_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.judge.mode = Mode::ReadOnly;
        let (_temp, mut runtime, _stop) = tests::fixture_with(config);
        tests::store(&mut runtime)
            .defer(LaneId::Judge, 3600)
            .unwrap();
        let inventory = paged_inventory(&runtime, 1);
        let original_deadline = inventory.source(0).observation.admit_before;
        let mut lane = JudgeLane {
            inventory: Some(inventory),
            ..Default::default()
        };
        let mut services = GradeServices::new(&mut runtime);
        lane.plan(&mut services).unwrap();
        let selected = lane
            .selected
            .as_ref()
            .expect("first page assessed immediately");
        assert_eq!(selected.observation.admit_before, original_deadline);
        assert!(
            matches!(
                lane.read.as_ref().map(|read| &read.kind),
                Some(JudgeReadKind::Page)
            ),
            "assessment must precede the next page, not await the whole traversal"
        );
        lane.cancel(
            &mut services,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        lane.selected = None;
        lane.inventory.as_mut().unwrap().more = true;
        lane.inventory.as_mut().unwrap().response.body["assignments"][0]
            .as_object_mut()
            .unwrap()
            .remove("answer_epoch");
        lane.plan(&mut services).unwrap();
        assert!(matches!(
            lane.read.as_ref().map(|read| &read.kind),
            Some(JudgeReadKind::Hydration { .. })
        ));
        lane.cancel(
            &mut services,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let id = format!("{:064x}", 1);
        let hydration = Response {
            status: 200,
            body: json!({"id": id, "body": {
                "type": "challenge", "epoch": 8, "words": ["burn"],
                "answer": "burning candidate"
            }}),
            retry_after_seconds: None,
            read_failure: None,
        };
        lane.accept_assignment(&mut services, &id, Some(&hydration))
            .unwrap();
        assert_eq!(
            lane.selected.as_ref().unwrap().observation.admit_before,
            original_deadline,
            "successful hydration retains its page's deadline"
        );
        lane.selected = None;
        lane.inventory.as_mut().unwrap().sources[0]
            .as_mut()
            .unwrap()
            .observation
            .admit_before = Instant::now() - Duration::from_secs(1);
        lane.accept_assignment(&mut services, &id, Some(&hydration))
            .unwrap();
        assert!(
            lane.selected.is_none(),
            "hydration must not renew an expired page"
        );
    }

    #[tokio::test]
    async fn slow_pages_preserve_each_candidate_deadline_and_cannot_prove_stale_absence() {
        let mut config = Config::default();
        config.capabilities.judge.mode = Mode::ReadOnly;
        config.capabilities.judge.timeouts.read_http_seconds = 15;
        let (_temp, mut runtime, _stop) = tests::fixture_with(config);
        let mut inventory = paged_inventory(&runtime, 4);
        // Four six-second reads: at page four, page one is eighteen seconds old.
        let current = Instant::now();
        let wall = now();
        for (index, source) in inventory.sources.iter_mut().flatten().enumerate() {
            let age = (3 - index) as u64 * 6;
            source.completed_at = wall - age as i64;
            source.observation.admit_before =
                current - Duration::from_secs(age) + Duration::from_secs(15);
            source.observation.admit_before_unix = source.completed_at + 15;
        }
        inventory.complete = true;
        let second_deadline = inventory.source(1).observation.admit_before;
        let mut lane = JudgeLane {
            inventory: Some(inventory),
            ..Default::default()
        };
        {
            let mut services = GradeServices::new(&mut runtime);
            lane.select(&mut services).unwrap();
        }
        let selected = lane.selected.as_ref().unwrap();
        assert_eq!(selected.assignment.id, format!("{:064x}", 2));
        assert_eq!(selected.observation.admit_before, second_deadline);
        assert_eq!(
            lane.inventory
                .as_ref()
                .unwrap()
                .exclusions
                .get("observation_stale"),
            Some(&1)
        );
        let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
        let store = tests::store(&mut runtime);
        let op = store
            .seed_operation_for_test(
                LaneId::Judge,
                &"f".repeat(64),
                "prepared",
                &json!({}),
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        lane.selected = None;
        lane.inventory.as_mut().unwrap().target = Some(Target::Prepared(op.clone()));
        lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
        assert!(
            lane.inventory.is_none(),
            "stale absence requires rediscovery"
        );
        assert_eq!(
            tests::store(&mut runtime)
                .operation(op.id)
                .unwrap()
                .unwrap()
                .state,
            "prepared"
        );
    }

    #[tokio::test]
    async fn selected_candidate_entering_model_cooldown_is_replaced() {
        let mut config = Config::default();
        config.capabilities.judge.mode = Mode::ReadOnly;
        let (_temp, mut runtime, _stop) = tests::fixture_with(config);
        tests::store(&mut runtime)
            .defer(LaneId::Judge, 3600)
            .unwrap();
        let mut inventory = paged_inventory(&runtime, 2);
        inventory.more = false;
        inventory.complete = true;
        let mut lane = JudgeLane {
            inventory: Some(inventory),
            ..Default::default()
        };
        lane.select(&mut GradeServices::new(&mut runtime)).unwrap();
        let first = lane.selected.as_ref().unwrap().assignment.id.clone();
        let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
        let store = tests::store(&mut runtime);
        let mut op = store
            .seed_operation_for_test(
                LaneId::Judge,
                &first,
                "generating",
                &json!({}),
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        op.state = "prelaunch_failed".into();
        op.next_at = runtime.deadline_now() + 3600;
        tests::store(&mut runtime)
            .seed_transition_for_test(&op, "fixture_model_cooldown")
            .unwrap();
        lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
        assert_eq!(
            lane.selected.as_ref().unwrap().assignment.id,
            format!("{:064x}", 2)
        );
        assert_eq!(
            lane.inventory
                .as_ref()
                .unwrap()
                .exclusions
                .get("model_retry_cooldown"),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn partial_retries_preserve_inventory_failure_and_can_continue_paging() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.network.base_url = format!("http://{}", listener.local_addr().unwrap());
        config.capabilities.judge.mode = Mode::ReadOnly;
        let (temp, mut runtime, _stop) = tests::fixture_with(config);
        let config = Config::load(&temp.path().join("config.toml")).unwrap();
        let page = |index: usize, more: bool| {
            let inventory = paged_inventory(&runtime, index);
            json!({"assignments":[inventory.response.body["assignments"][index - 1].clone()],
                "has_more":more})
        };
        let bodies = vec![
            page(1, true),
            json!({"assignments":"malformed"}),
            page(1, true),
            page(2, true),
            page(3, true),
            page(4, true),
            page(1, true),
            page(1, false),
        ];
        let server = tokio::spawn(async move {
            for body in bodies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                let body = body.to_string();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        async fn collect_page(lane: &mut JudgeLane, runtime: &mut HostAccess) {
            tokio::time::timeout(
                Duration::from_secs(5),
                &mut lane.read.as_mut().expect("page admitted").flight.task,
            )
            .await
            .unwrap()
            .unwrap();
            lane.collect(&mut GradeServices::new(runtime)).unwrap();
        }
        let key = HostAccess::discovery_key(LaneId::Judge);
        let mut lane = JudgeLane::default();
        assert!(
            lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
                .unwrap()
        );
        collect_page(&mut lane, &mut runtime).await;
        lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
        collect_page(&mut lane, &mut runtime).await;
        assert!(!lane.inventory.as_ref().unwrap().usable);
        assert_eq!(
            tests::store(&mut runtime)
                .read_backoff(&key)
                .unwrap()
                .failures,
            1
        );
        // Move only the elapsed retry deadline; keep the failed traversal evidence.
        let db = rusqlite::Connection::open(config.state_dir.join("state.sqlite3")).unwrap();
        db.execute(
            "UPDATE read_state SET local_next_at=?1 WHERE owner='judge' AND purpose='discovery'",
            [now() - 1],
        )
        .unwrap();
        let failure = tests::store(&mut runtime).read_backoff(&key).unwrap();
        assert!(
            lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
                .unwrap()
        );
        for index in 0..4 {
            collect_page(&mut lane, &mut runtime).await;
            assert_eq!(
                tests::store(&mut runtime).read_backoff(&key).unwrap(),
                failure
            );
            if index < 3 {
                lane.plan(&mut GradeServices::new(&mut runtime)).unwrap();
                assert!(
                    lane.read.is_some(),
                    "retained failure must not deadlock pages"
                );
            }
        }
        assert!(!lane.inventory.as_ref().unwrap().more);
        assert!(!lane.inventory.as_ref().unwrap().complete);
        let revision = GradeServices::new(&mut runtime).lane_revision().unwrap();
        let store = tests::store(&mut runtime);
        let op = store
            .seed_operation_for_test(
                LaneId::Judge,
                &format!("{:064x}", 1),
                "prepared",
                &json!({}),
                store.control().unwrap(),
                &revision,
            )
            .unwrap();
        assert!(
            lane.start_inventory(
                &mut GradeServices::new(&mut runtime),
                Some(Target::Prepared(op))
            )
            .unwrap()
        );
        collect_page(&mut lane, &mut runtime).await;
        assert!(!lane.inventory.as_ref().unwrap().more);
        assert!(!lane.inventory.as_ref().unwrap().complete);
        assert_eq!(
            tests::store(&mut runtime).read_backoff(&key).unwrap(),
            failure
        );
        let status = tests::store(&mut runtime).status(&config).unwrap();
        let discovery = status["reads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|read| read["owner"] == "judge" && read["purpose"] == "discovery")
            .unwrap();
        assert_eq!(discovery["failure_category"], "unusable_response");
        assert!(discovery["last_success_at"].is_null());
        for (status, category) in [(None, Some("timeout")), (Some(200), None)] {
            tests::store(&mut runtime)
                .read_finished(&key, status, category)
                .unwrap();
            let category: String = db
                .query_row(
                    "SELECT failure_category FROM read_state WHERE owner='judge' AND purpose='discovery'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                category, "timeout",
                "new failure replaces retained evidence"
            );
        }
        assert!(
            lane.start_inventory(&mut GradeServices::new(&mut runtime), None)
                .unwrap()
        );
        collect_page(&mut lane, &mut runtime).await;
        assert!(lane.inventory.as_ref().unwrap().complete);
        assert_eq!(
            tests::store(&mut runtime)
                .read_backoff(&key)
                .unwrap()
                .failures,
            0
        );
        let recovered: (Option<String>, Option<i64>) = db
            .query_row(
                "SELECT failure_category,last_success_at FROM read_state WHERE owner='judge' AND purpose='discovery'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(recovered.0.is_none());
        assert!(recovered.1.is_some());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn aggregate_assessment_expires_with_earliest_page_not_selected_or_last_page() {
        let mut config = Config::default();
        config.capabilities.judge.mode = Mode::ReadOnly;
        let (temp, mut runtime, _stop) = tests::fixture_with(config);
        let config = Config::load(&temp.path().join("config.toml")).unwrap();
        runtime.heartbeat().unwrap();
        let mut inventory = paged_inventory(&runtime, 2);
        inventory.complete = true;
        inventory.more = false;
        let earliest = now() + 2;
        let first = inventory.sources[0].as_mut().unwrap();
        first.observation.admit_before = Instant::now() + Duration::from_secs(2);
        first.observation.admit_before_unix = earliest;
        let last = inventory.sources[1].as_mut().unwrap();
        last.observation.admit_before = Instant::now() + Duration::from_secs(60);
        last.observation.admit_before_unix = now() + 60;
        let candidate = inventory.ids[1].clone();
        let lane = JudgeLane {
            inventory: Some(inventory),
            ..Default::default()
        };
        for candidate in [Some(candidate.as_str()), None] {
            lane.report(
                &GradeServices::new(&mut runtime),
                Some(candidate.is_some()),
                None,
                candidate,
            )
            .unwrap();
            let status = tests::store(&mut runtime).status(&config).unwrap();
            let participation = &status["lane_participation"]["judge"];
            assert_eq!(participation["assessment"]["completeness"], "complete");
            assert_eq!(participation["assessment"]["valid_until"], earliest);
            assert_eq!(participation["freshness"], "current_observation");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let last = &lane.inventory.as_ref().unwrap().source(1).observation;
        assert!(
            GradeServices::new(&mut runtime)
                .observation_current(last)
                .unwrap()
        );
        let status = tests::store(&mut runtime).status(&config).unwrap();
        assert_eq!(status["lane_participation"]["judge"]["freshness"], "stale");
    }

    #[test]
    fn pending_grade_binds_candidate_history_and_waits_on_observation_expiry() {
        let mut assignment = Assignment {
            id: "a".repeat(64),
            epoch: 8,
            answer: "burning candidate".into(),
            words: vec!["burn".into()],
            expires_at_epoch: Some(12),
            author: Some("author".into()),
            author_prior: Default::default(),
        };
        let task = GradeTask::new(SolverRequest {
            id: "request".into(),
            kind: LaneId::Judge,
            epoch: 8,
            words: assignment.words.clone(),
            min_chars: 0,
            max_chars: 0,
            assignment: Some(assignment.id.clone()),
            candidate: Some(assignment.answer.clone()),
            history: Vec::new(),
            guidance: String::new(),
            core_guidance: "Evaluate protocol input.".into(),
            author_history: Some(assignment.author_prior.clone()),
            candidate_author: assignment.author.clone(),
        })
        .unwrap();
        let stamp = AdmissionStampSnapshot {
            account_generation: 1,
            lane_control_revision: 7,
            authority_epoch: 3,
            lane_config_revision: "config".into(),
        };
        let producer = ModelProducerProvenance {
            operation: OperationBinding {
                database_id: "db".into(),
                operation_id: 9,
                lane_id: LaneId::Judge,
                binding_revision: 0,
            },
            task_kind: "grade".into(),
            request_id: "request".into(),
            request_digest: "digest".into(),
            lane_config_revision: "config".into(),
            requested: ModelSelection::new(&crate::config::ModelConfig::default()).unwrap(),
            preflight_admission: stamp.clone(),
            created_at: 1,
        };
        let completed = Instant::now();
        let observation = Observation {
            stamp,
            admit_before: completed + Duration::from_secs(10),
            admit_before_unix: 11,
        };
        let descriptor = || PendingWorkRef {
            key: PendingWorkKey {
                operation: producer.operation.clone(),
                request_digest: producer.request_digest.clone(),
            },
            task: &task,
            producer: &producer,
        };
        assert!(matches!(
            match_pending(
                &assignment,
                descriptor(),
                observation.clone(),
                "config",
                true
            ),
            PendingInputDecision::Unchanged(_)
        ));
        assert!(matches!(
            match_pending(
                &assignment,
                descriptor(),
                observation.clone(),
                "config",
                false
            ),
            PendingInputDecision::Wait(PendingWaitReason::ObservationStale)
        ));
        assignment.author_prior.coverage = crate::protocol::EvidenceCoverage::Supplied;
        assert!(matches!(
            match_pending(
                &assignment,
                descriptor(),
                observation.clone(),
                "config",
                true
            ),
            PendingInputDecision::Retire(PendingRetirementReason::InputChanged)
        ));
        assignment.author_prior = Default::default();
        assignment.answer.push('!');
        assert!(matches!(
            match_pending(&assignment, descriptor(), observation, "config", true),
            PendingInputDecision::Retire(PendingRetirementReason::InputChanged)
        ));
    }
}
