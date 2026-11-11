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
struct Inventory {
    response: Response,
    observation: Observation,
    completed_at: i64,
    pages: usize,
    offset: u64,
    complete: bool,
    more: bool,
    usable: bool,
    eligible_candidates: usize,
    exclusions: std::collections::BTreeMap<&'static str, usize>,
    target: Option<Target>,
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
                let Some(response) = response else {
                    if let Some(inventory) = self.inventory.as_mut() {
                        inventory.more = false;
                        inventory.usable = false;
                    }
                    return Ok(());
                };
                let Ok(ids) = assignment_ids(&response) else {
                    services.evaluate_inventory(false)?;
                    if let Some(inventory) = self.inventory.as_mut() {
                        inventory.more = false;
                        inventory.usable = false;
                    }
                    return Ok(());
                };
                services.evaluate_inventory(true)?;
                let rows = response.body["assignments"]
                    .as_array()
                    .context("assignment rows missing")?;
                let complete = response.body["has_more"].as_bool() == Some(false);
                let more = response.body["has_more"].as_bool() == Some(true) && !rows.is_empty();
                if let Some(inventory) = self.inventory.as_mut() {
                    let known: std::collections::HashSet<_> =
                        assignment_ids(&inventory.response)?.into_iter().collect();
                    let mut added = 0;
                    for (id, row) in ids.iter().zip(rows) {
                        if !known.contains(id) {
                            inventory.response.body["assignments"]
                                .as_array_mut()
                                .context("inventory rows missing")?
                                .push(row.clone());
                            added += 1;
                        }
                    }
                    inventory.pages += 1;
                    inventory.offset = inventory.offset.saturating_add(rows.len() as u64);
                    inventory.complete = complete;
                    inventory.more = more && added != 0 && inventory.pages < 4;
                    inventory.response.body["has_more"] = json!(!complete);
                } else {
                    let offset = rows.len() as u64;
                    self.inventory = Some(Inventory {
                        response,
                        observation,
                        completed_at: read.flight.completed_at,
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
                    && inventory.target.as_ref().is_some_and(|target| {
                        assignment_ids(&inventory.response)
                            .is_ok_and(|ids| ids.iter().any(|id| id == target.id()))
                    })
                {
                    inventory.more = false;
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
        match &self.inventory {
            Some(inventory) => services.observation_current(&inventory.observation),
            None => Ok(false),
        }
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
            && self.start_inventory(services, None)?
        {
            services.discovered()?;
        }
        // Assessment and bounded hydration are read-only in every non-off mode.
        if self.read.is_none() && self.selected.is_none() && services.config().mode != Mode::Off {
            self.select(services)?;
        }
        self.prepare(services)
    }
    fn candidates(
        &self,
        services: &GradeServices<'_>,
    ) -> Result<(Vec<String>, std::collections::BTreeMap<&'static str, usize>)> {
        let mut exclusions = std::collections::BTreeMap::new();
        let Some(inventory) = &self.inventory else {
            return Ok((Vec::new(), exclusions));
        };
        let ids = assignment_ids(&inventory.response)?;
        if let Some(target) = &inventory.target {
            return Ok((
                ids.into_iter().filter(|id| id == target.id()).collect(),
                exclusions,
            ));
        }
        let rows = inventory.response.body["assignments"]
            .as_array()
            .context("assignment rows missing")?;
        let mut ranked = Vec::new();
        for (id, row) in ids.into_iter().zip(rows) {
            if let Some(reason) = services.assignment_blocker(&id)? {
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
        Ok((ranked.into_iter().map(|(_, id)| id).collect(), exclusions))
    }
    fn report(
        &self,
        services: &GradeServices<'_>,
        selected: Option<bool>,
        reason: Option<&'static str>,
    ) -> Result<()> {
        let Some(inventory) = &self.inventory else {
            return Ok(());
        };
        let count = inventory.response.body["assignments"]
            .as_array()
            .map_or(0, Vec::len);
        services.participation(&inventory.observation, &json!({"source":"validated_assignment_inventory","observed_at":inventory.completed_at,
            "valid_until":inventory.completed_at.saturating_add(services.config().timeouts.read_http_seconds as i64),
            "completeness":if inventory.complete && inventory.usable {"complete"} else {"bounded_partial"},
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
        if inventory.more {
            return Ok(());
        }
        if candidates.is_empty() {
            if let Some(target) = inventory.target.clone() {
                if inventory.complete && inventory.usable {
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
            } else {
                self.report(services, Some(false), Some("excluded_or_unavailable"))?;
            }
            return Ok(());
        }
        self.report(services, None, Some("assessment_pending"))?;
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
                    self.report(services, None, Some("assignment_unreadable"))?;
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
        if !self.inventory_current(services)? || services.assignment_excluded(id) {
            return Ok(());
        }
        let inventory = self.inventory.as_ref().expect("assignment inventory");
        let assignment = match parse_selected_assignment(&inventory.response, id, hydrated) {
            Ok(assignment) => assignment,
            Err(_) => {
                services.evaluate_assignment(id, false)?;
                self.report(services, None, Some("assignment_unreadable"))?;
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
                            inventory.observation.clone(),
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
                            inventory.observation.clone(),
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
                                observation: inventory.observation.clone(),
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
            )?;
            self.selected = Some(Selected {
                assignment,
                observation: inventory.observation.clone(),
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
            || services.assignment_excluded(&selected.assignment.id)
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
        if services.begin_model(
            &mut self.model,
            task,
            &selected.assignment.id,
            &selected.observation,
        )? {
            self.selected = None;
        }
        Ok(())
    }
    pub(super) async fn cancel(&mut self, services: &mut GradeServices<'_>) -> Result<()> {
        if let Some(read) = self.read.as_mut() {
            read.flight.abort().await;
        }
        self.collect(services)?;
        if let Some(read) = self.read.take() {
            services.cancel_read(&read.flight)?;
        }
        services.cancel_reconciliation().await?;
        services.cancel_model(&mut self.model).await
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
    use crate::solver::contract::ModelSelection;
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
