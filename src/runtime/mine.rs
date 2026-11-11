use super::answer::challenge_matches;
use super::*;

struct ChallengeRead {
    flight: ReadFlight,
    target: Option<Operation>,
}
struct ObservedChallenge {
    challenge: Challenge,
    observation: Observation,
}
#[derive(Default)]
pub(super) struct MineLane {
    read: Option<ChallengeRead>,
    observed: Option<ObservedChallenge>,
    pub(super) ready: Option<ReadyEffect>,
}
impl MineLane {
    pub(super) fn busy(&self) -> bool {
        self.read.is_some()
    }
    pub(super) fn collect(&mut self, services: &mut MineServices<'_>) -> Result<()> {
        services.collect_reconciliation()?;
        let Some(read) = self.read.as_mut() else {
            return Ok(());
        };
        let Some(result) = read.flight.take() else {
            return Ok(());
        };
        let read = self.read.take().expect("mine read completion");
        let Some(response) = services.finish_read(&read.flight, result)? else {
            return Ok(());
        };
        let Some(challenge) = services.observe_challenge(&read.flight, &response)? else {
            return Ok(());
        };
        let observation = services.observation(&read.flight)?;
        if let Some(op) = read.target {
            let binding = services.binding(&op)?;
            if !services.draft_current(&binding)? {
                return Ok(());
            }
            let input: Input = serde::Deserialize::deserialize(&op.request)?;
            if challenge_matches(
                &challenge,
                &input.solver,
                input.challenge_fingerprint.as_deref(),
                false,
            ) {
                self.ready =
                    Some(services.emit_ready(crate::protocol::MineIntent, binding, observation)?);
            } else {
                services.retire_unsent(&binding, "request_no_longer_current")?;
            }
        } else {
            self.observed = Some(ObservedChallenge {
                challenge,
                observation,
            });
        }
        Ok(())
    }
    pub(super) fn plan(&mut self, services: &mut MineServices<'_>) -> Result<()> {
        services.poll_reconciliation()?;
        if let Some(ready) = self.ready.as_ref()
            && !services.ready_current(ready)?
        {
            self.ready = None;
        }
        if let Some(op) = services.preparation()?
            && self.read.is_none()
            && self.ready.is_none()
            && services.active()?
            && services.admission_allowed(&op)?
            && op.next_at <= services.deadline_now()
            && services.fresh_allowed(op.id)
            && let Some(flight) = services.begin_discovery()?
        {
            self.read = Some(ChallengeRead {
                flight,
                target: Some(op),
            });
            services.start_identity()?;
        }
        if self.read.is_none()
            && services.discovery_allowed()?
            && let Some(flight) = services.begin_discovery()?
        {
            services.discovered()?;
            self.read = Some(ChallengeRead {
                flight,
                target: None,
            });
        }
        if !services.active()? || !services.effect_allowed() || services.has_preparation()? {
            return Ok(());
        }
        let Some(observed) = &self.observed else {
            return Ok(());
        };
        if !services.observation_current(&observed.observation)? {
            self.observed = None;
            return Ok(());
        }
        if services.begin_preparation(&observed.challenge, &observed.observation)? {
            self.observed = None;
        }
        Ok(())
    }
    pub(super) async fn cancel(&mut self, services: &mut MineServices<'_>) -> Result<()> {
        if let Some(read) = self.read.as_mut() {
            read.flight.abort().await;
        }
        self.collect(services)?;
        if let Some(read) = self.read.take() {
            services.cancel_read(&read.flight)?;
        }
        services.cancel_reconciliation().await
    }
}
