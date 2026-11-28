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
#[derive(Default)]
struct CandidateSelection {
    candidates: Vec<String>,
    exclusions: std::collections::BTreeMap<&'static str, usize>,
    excluded_work: Vec<(usize, &'static str)>,
}

struct Inventory {
    response: Response,
    ids: Vec<String>,
    // Each candidate retains the page's original authority and freshness deadline.
    sources: [Option<InventorySource>; 4],
    pages: usize,
    start_offset: u64,
    offset: u64,
    complete: bool,
    overlapping_pages: bool,
    more: bool,
    usable: bool,
    eligible_candidates: usize,
    exclusions: std::collections::BTreeMap<&'static str, usize>,
    // Bounded diagnostic witnesses, indexed into the canonical inventory IDs.
    // These identify current dependencies; they never authorize another attempt.
    excluded_work: Vec<(usize, &'static str)>,
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
    Page { offset: u64 },
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
            JudgeReadKind::Page { offset } => {
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
                let page_complete = has_more == Some(false);
                let more = has_more == Some(true) && !rows.is_empty();
                let next_offset = offset.checked_add(rows.len() as u64).unwrap_or(0);
                // Moving pages can repeat IDs. Advance by the page's raw length,
                // not novel candidates, and wrap only at an explicit end, empty page,
                // or unpaginated response (omitted has_more).
                services.set_inventory_offset(
                    if page_complete || has_more.is_none() || rows.is_empty() {
                        0
                    } else {
                        next_offset
                    },
                )?;
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
                    inventory.overlapping_pages |= added != ids.len();
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
                    inventory.offset = next_offset;
                    inventory.complete = page_complete
                        && inventory.start_offset == 0
                        && !inventory.overlapping_pages;
                    inventory.more = more && inventory.pages < 4;
                    inventory.response.body["has_more"] = json!(!page_complete);
                } else {
                    let count = rows.len();
                    self.inventory = Some(Inventory {
                        response,
                        ids,
                        sources: [
                            Some(InventorySource {
                                observation,
                                completed_at: read.flight.completed_at,
                                rows: 0..count,
                            }),
                            None,
                            None,
                            None,
                        ],
                        pages: 1,
                        start_offset: offset,
                        offset: next_offset,
                        complete: page_complete && offset == 0,
                        overlapping_pages: false,
                        more,
                        usable: true,
                        eligible_candidates: 0,
                        exclusions: Default::default(),
                        excluded_work: Vec::new(),
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
        let offset = services.inventory_offset()?;
        if let Some(flight) = services.begin_discovery(Some(offset))? {
            if target.is_none() {
                services.discovered()?;
            }
            self.inventory = None;
            self.selected = None;
            self.read = Some(JudgeRead {
                flight,
                kind: JudgeReadKind::Page { offset },
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
        let retain_targeted_inventory = self.inventory.as_ref().is_some_and(|inventory| {
            inventory.more
                || inventory
                    .target
                    .as_ref()
                    .is_some_and(|target| inventory.ids.iter().any(|id| id == target.id()))
        }) || !services.discovery_allowed()?;
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
                    .is_some_and(|target| {
                        retain_targeted_inventory
                            && matches!(target,Target::Pending(existing,_) if existing == &key)
                    })
                && services.can_fresh(
                    key.operation.operation_id,
                    crate::runtime::host::FreshTarget::Pending,
                )
            {
                let op_id = key.operation.operation_id;
                if self.start_inventory(services, Some(Target::Pending(key, id)))? {
                    services.consume_fresh(op_id, crate::runtime::host::FreshTarget::Pending);
                    services.start_identity()?;
                }
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
                .is_some_and(|target| {
                    retain_targeted_inventory
                        && matches!(target,Target::Prepared(current) if current.id == op.id)
                });
            if !targeted
                && services.active()?
                && op.next_at <= services.deadline_now()
                && services.can_fresh(op.id, crate::runtime::host::FreshTarget::Prepared)
            {
                let op_id = op.id;
                if self.start_inventory(services, Some(Target::Prepared(op)))? {
                    services.consume_fresh(op_id, crate::runtime::host::FreshTarget::Prepared);
                    services.start_identity()?;
                }
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
                    kind: JudgeReadKind::Page { offset },
                    target: None,
                });
            }
        }
        if self.read.is_none()
            && services.discovery_allowed()?
            && self.inventory.as_ref().is_none_or(|i| i.target.is_none())
            && (!services.active()? || (self.selected.is_none() && !self.model.occupied()))
        {
            self.start_inventory(services, None)?;
        }
        Ok(())
    }
    fn candidates(&self, services: &GradeServices<'_>) -> Result<CandidateSelection> {
        let mut selection = CandidateSelection::default();
        let Some(inventory) = &self.inventory else {
            return Ok(selection);
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
                *selection.exclusions.entry("observation_stale").or_insert(0) += 1;
                if selection.excluded_work.len() < 32 {
                    selection.excluded_work.push((index, "observation_stale"));
                }
            } else if inventory.target.is_none()
                && let Some(reason) = services.assignment_blocker(id)?
            {
                *selection.exclusions.entry(reason).or_insert(0) += 1;
                if selection.excluded_work.len() < 32 {
                    selection.excluded_work.push((index, reason));
                }
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
        selection.candidates = ranked.into_iter().map(|(_, id)| id.clone()).collect();
        Ok(selection)
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
            "excluded_work":inventory.excluded_work.iter().map(|(index,reason)|json!({
                "work_key":inventory.ids[*index],"reason":reason
            })).collect::<Vec<_>>(),
            "excluded_work_truncated":inventory.exclusions.values().sum::<usize>()>inventory.excluded_work.len(),
            "assessment_reason":reason,"assessment_creates_model_work":false,"outcome":"unobserved"}))
    }
    fn select(&mut self, services: &mut GradeServices<'_>) -> Result<()> {
        if !self.inventory_current(services)? {
            return Ok(());
        }
        let CandidateSelection {
            candidates,
            exclusions,
            excluded_work,
        } = self.candidates(services)?;
        let Some(inventory) = &mut self.inventory else {
            return Ok(());
        };
        inventory.eligible_candidates = candidates.len();
        inventory.exclusions = exclusions;
        inventory.excluded_work = excluded_work;
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
        let mut first_error: Option<anyhow::Error> = None;
        let mut record = |res: Result<()>| {
            if let Err(error) = res
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        };
        if let Some(read) = self.read.as_mut() {
            read.flight.abort(deadline).await;
        }
        record(self.collect(services));
        if let Some(read) = self.read.take() {
            record(services.cancel_read(&read.flight));
        }
        record(services.cancel_reconciliation(deadline).await);
        record(services.cancel_model(&mut self.model, deadline).await);
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
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
#[path = "judge_tests.rs"]
mod tests;
