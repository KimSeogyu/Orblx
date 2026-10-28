//! The harness state.
//!
//! The operator can select a level.
//! The operator can select a difficulty.
//! The operator can press a smash button.
//! Those actions run the level machine.
//! The machine updates the session panels.

use serde::Serialize;

use gyeol_identity::MockOidc;

use crate::difficulty::{Difficulty, DifficultyCard, FaultHook};
use crate::envelope::FeedLine;
use crate::event::{EventBus, EventKind, HarnessEvent, StackFeed};
use crate::feed::{DatapathFeed, EdgeNatFeed, IdentityFeed};
use crate::level::{LevelCard, LevelId};
use crate::session::SessionView;
use crate::sim::{AuditView, Engine};

/// A smash button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smash {
    /// Request an SVID revoke.
    Revoke,
    /// Request a UDP block.
    UdpBlock,
    /// Request an agent spawn.
    AgentSpawn,
}

impl Smash {
    /// Parse a smash id from the web API.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "revoke" => Ok(Self::Revoke),
            "udp_block" => Ok(Self::UdpBlock),
            "agent_spawn" => Ok(Self::AgentSpawn),
            other => Err(format!("The smash action {other} is not valid.")),
        }
    }
}

/// A JSON snapshot for the web UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// True while this build does not run a level machine.
    pub skeleton: bool,
    /// The page notice.
    pub notice: &'static str,
    /// The level cards.
    pub levels: Vec<LevelCard>,
    /// The difficulty cards.
    pub difficulties: Vec<DifficultyCard>,
    /// The stored fault hook.
    pub fault_hook: FaultHook,
    /// The fault-hook sentence.
    pub fault_detail: String,
    /// The session panels.
    pub session: SessionView,
    /// The event log.
    pub events: Vec<HarnessEvent>,
    /// The session audit chain for this run.
    pub audit: AuditView,
}

/// The sim harness.
pub struct Harness {
    engine: Engine,
    bus: EventBus,
    feeds: Vec<Box<dyn StackFeed + Send>>,
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    /// Create a harness with the three stack feeds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_feeds(vec![
            Box::new(IdentityFeed::default()),
            Box::new(EdgeNatFeed::default()),
            Box::new(DatapathFeed::default()),
        ])
    }

    /// Create a harness with caller-supplied feeds.
    ///
    /// A live Identity, EdgeNAT, or Datapath feed can replace a sim feed.
    #[must_use]
    pub fn with_feeds(feeds: Vec<Box<dyn StackFeed + Send>>) -> Self {
        Self {
            engine: Engine::new(),
            bus: EventBus::new(),
            feeds,
        }
    }

    /// The stored events.
    #[must_use]
    pub fn events(&self) -> &[HarnessEvent] {
        self.bus.events()
    }

    /// The session panels.
    #[must_use]
    pub fn session(&self) -> &SessionView {
        self.engine.session()
    }

    /// Select a level and run its script.
    pub fn select_level(&mut self, id: LevelId) {
        let lines = self.engine.select_level(id);
        self.stage(lines);
    }

    /// Select a difficulty and run the matching level.
    pub fn select_difficulty(&mut self, difficulty: Difficulty) {
        let lines = self.engine.select_difficulty(difficulty);
        self.stage(lines);
    }

    /// Finish City Breeze from the mock IdP callback.
    pub fn complete_oidc_city(&mut self, oidc: &MockOidc, subject: &str) {
        let lines = self.engine.complete_oidc_city(oidc, subject);
        self.stage(lines);
    }

    /// Run one smash action.
    pub fn smash(&mut self, action: Smash) {
        let lines = match action {
            Smash::Revoke => self.engine.revoke(),
            Smash::UdpBlock => self.engine.block_udp(),
            Smash::AgentSpawn => self.engine.spawn_agent(),
        };
        self.stage(lines);
    }

    fn stage(&mut self, lines: Vec<FeedLine>) {
        for line in lines {
            let mut queued = false;
            for feed in &mut self.feeds {
                if feed.source() == line.source {
                    feed.enqueue(line.body.clone());
                    queued = true;
                    break;
                }
            }
            if !queued {
                self.bus.push(line.source, bus_kind(&line.body), line.body);
            }
        }
        self.poll_feeds();
    }

    /// Drain the stack feeds into the event bus.
    ///
    /// Empty feeds add no events.
    /// Feed lines do not change the session panels.
    pub fn poll_feeds(&mut self) {
        for feed in &mut self.feeds {
            let source = feed.source();
            let details = feed.drain();
            for detail in details {
                let kind = bus_kind(&detail);
                self.bus.push(source, kind, detail);
            }
        }
    }

    /// Build the UI snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let levels = LevelId::all()
            .into_iter()
            .map(|id| {
                let selected = self.engine.selected() && self.engine.level() == id;
                let statuses = if selected {
                    self.engine.steps().to_vec()
                } else {
                    Vec::new()
                };
                id.card(selected, selected && self.engine.live(), &statuses)
            })
            .collect();
        let difficulties = Difficulty::all()
            .into_iter()
            .map(|difficulty| difficulty.card(difficulty == self.engine.difficulty()))
            .collect();
        let fault_hook = FaultHook {
            difficulty: self.engine.difficulty(),
            armed: self.engine.armed(),
        };
        Snapshot {
            skeleton: false,
            notice: "The harness runs the level machines. Smash buttons write live feed events.",
            levels,
            difficulties,
            fault_detail: fault_hook.detail(),
            fault_hook,
            session: self.engine.session().clone(),
            events: self.bus.events().to_vec(),
            audit: self.engine.audit_view(),
        }
    }
}

fn bus_kind(body: &str) -> EventKind {
    let kind = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(|item| item.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    match kind.as_str() {
        "level_selected" => EventKind::LevelSelected,
        "difficulty_selected" => EventKind::DifficultySelected,
        "smash_revoke" | "svid.revoked" | "session.dropped" => EventKind::SmashRevoke,
        "smash_udp_block" | "nat.inject" => EventKind::SmashUdpBlock,
        "smash_agent_spawn" | "agent.spawned" => EventKind::SmashAgentSpawn,
        _ => EventKind::Feed,
    }
}

#[cfg(test)]
mod tests {
    use super::{Harness, Smash};
    use crate::difficulty::Difficulty;
    use crate::event::{EventKind, EventSource, StackFeed};
    use crate::level::{LevelBody, LevelId, StepStatus};
    use crate::session::PanelState;

    struct NoteFeed;

    impl StackFeed for NoteFeed {
        fn source(&self) -> EventSource {
            EventSource::Datapath
        }

        fn drain(&mut self) -> Vec<String> {
            vec!["A later feed can write this line.".to_string()]
        }
    }

    #[test]
    fn smash_updates_the_session_panels() {
        let mut harness = Harness::new();
        harness.smash(Smash::AgentSpawn);
        assert_ne!(harness.session().svid.state, PanelState::None);
        assert!(!harness.session().peers.is_empty());
        let body = harness
            .events()
            .iter()
            .map(|event| event.detail.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("agent.spawned"));
        assert!(body.contains("jit.allow"));
        assert!(body.contains("jit.deny"));
        assert!(body.contains("svid.expired"));
        assert!(body.contains("\"v\":1"));
    }

    #[test]
    fn level_selection_runs_the_level() {
        let mut harness = Harness::new();
        harness.select_level(LevelId::CityBreeze);
        let snapshot = harness.snapshot();
        let selected = snapshot.levels.iter().find(|level| level.selected).unwrap();
        assert_eq!(selected.title, "City Breeze");
        assert_eq!(selected.body, LevelBody::Live);
        assert!(selected
            .steps
            .iter()
            .all(|step| step.status == StepStatus::Pass));
        assert!(harness.events()[0].detail.contains("City Breeze"));
        assert!(!harness.session().packets.is_empty());
        assert!(snapshot.audit.ok);
        assert!(!snapshot.skeleton);
    }

    #[test]
    fn difficulty_selection_arms_the_hook() {
        let mut harness = Harness::new();
        harness.select_difficulty(Difficulty::Hard);
        let snapshot = harness.snapshot();
        assert!(snapshot.fault_hook.armed);
        assert_eq!(snapshot.fault_hook.difficulty, Difficulty::Hard);
        assert!(snapshot.fault_detail.contains("armed"));
        assert!(harness.events()[0].detail.contains("Hard"));
        let body = harness
            .events()
            .iter()
            .map(|event| event.detail.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let direct = body.find("\"kind\":\"path.direct\"").unwrap();
        let switch = body.find("\"kind\":\"path.switch\"").unwrap();
        assert!(direct < switch);
        assert!(body.contains("\"ok\":false"));
        assert!(body.contains("session.dropped"));
        assert!(body.contains("\"within_s\""));
    }

    #[test]
    fn a_live_feed_does_not_fill_the_panels() {
        let mut harness = Harness::with_feeds(vec![Box::new(NoteFeed)]);
        let before = harness.session().clone();
        harness.poll_feeds();
        harness.poll_feeds();
        assert_eq!(harness.session(), &before);
        assert_eq!(harness.events().len(), 2);
        assert_eq!(harness.events()[0].source, EventSource::Datapath);
        assert_eq!(harness.events()[0].kind, EventKind::Feed);
    }

    #[test]
    fn the_default_feeds_add_no_events() {
        let mut harness = Harness::new();
        harness.poll_feeds();
        assert!(harness.events().is_empty());
        let snapshot = harness.snapshot();
        assert!(!snapshot.skeleton);
        assert_eq!(snapshot.levels.len(), 3);
        assert_eq!(snapshot.difficulties.len(), 3);
        assert!(snapshot.events.is_empty());
        assert!(!snapshot.fault_hook.armed);
    }
}
