//! The harness state.
//!
//! The operator can select a level.
//! The operator can select a difficulty.
//! The operator can press a smash button.
//! Those actions write stub events.
//! Those actions do not run the stack.

use serde::Serialize;

use crate::difficulty::{Difficulty, DifficultyCard, FaultHook};
use crate::event::{EventBus, EventKind, EventSource, HarnessEvent, StackFeed};
use crate::feed::{DatapathFeed, EdgeNatFeed, IdentityFeed};
use crate::level::{LevelCard, LevelId};
use crate::session::SessionView;

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
    /// True while this build is a skeleton.
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
}

/// The sim harness.
pub struct Harness {
    level: Option<LevelId>,
    difficulty: Difficulty,
    session: SessionView,
    bus: EventBus,
    feeds: Vec<Box<dyn StackFeed + Send>>,
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    /// Create a harness with the three empty stack feeds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_feeds(vec![
            Box::new(IdentityFeed),
            Box::new(EdgeNatFeed),
            Box::new(DatapathFeed),
        ])
    }

    /// Create a harness with caller-supplied feeds.
    ///
    /// A later week can pass a live Identity, EdgeNAT, or Datapath feed.
    #[must_use]
    pub fn with_feeds(feeds: Vec<Box<dyn StackFeed + Send>>) -> Self {
        Self {
            level: None,
            difficulty: Difficulty::Easy,
            session: SessionView::placeholder(),
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
        &self.session
    }

    /// Select a level.
    ///
    /// The level body stays empty.
    pub fn select_level(&mut self, id: LevelId) {
        self.level = Some(id);
        self.bus.push(
            EventSource::Harness,
            EventKind::LevelSelected,
            format!(
                "The operator selected {}. The level body is empty. The harness did not run the level.",
                id.title()
            ),
        );
    }

    /// Store a difficulty hook.
    ///
    /// The hook stays disarmed.
    pub fn select_difficulty(&mut self, difficulty: Difficulty) {
        self.difficulty = difficulty;
        let hook = difficulty.hook();
        self.bus.push(
            EventSource::Harness,
            EventKind::DifficultySelected,
            format!(
                "The operator selected {}. {}",
                difficulty.label(),
                hook.detail()
            ),
        );
    }

    /// Record a smash stub event.
    ///
    /// The session panels do not change.
    pub fn smash(&mut self, action: Smash) {
        let (kind, detail) = match action {
            Smash::Revoke => (
                EventKind::SmashRevoke,
                "The operator pressed revoke. The harness did not revoke an SVID. The harness did not drop packets.",
            ),
            Smash::UdpBlock => (
                EventKind::SmashUdpBlock,
                "The operator pressed UDP block. The harness did not block UDP. The harness did not change the path.",
            ),
            Smash::AgentSpawn => (
                EventKind::SmashAgentSpawn,
                "The operator pressed agent spawn. The harness did not spawn an agent. The harness did not write an allow or a deny.",
            ),
        };
        self.bus.push(EventSource::Harness, kind, detail);
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
                self.bus.push(source, EventKind::Feed, detail);
            }
        }
    }

    /// Build the UI snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let levels = LevelId::all()
            .into_iter()
            .map(|id| id.card(self.level == Some(id)))
            .collect();
        let difficulties = Difficulty::all()
            .into_iter()
            .map(|difficulty| difficulty.card(difficulty == self.difficulty))
            .collect();
        let fault_hook = self.difficulty.hook();
        Snapshot {
            skeleton: true,
            notice: "This page is a skeleton. The buttons write stub events. The buttons do not run the gyeol-quic stack.",
            levels,
            difficulties,
            fault_detail: fault_hook.detail(),
            fault_hook,
            session: self.session.clone(),
            events: self.bus.events().to_vec(),
        }
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
    fn smash_writes_stub_events_and_keeps_the_session_empty() {
        let mut harness = Harness::new();
        let before = harness.session().clone();
        harness.smash(Smash::Revoke);
        harness.smash(Smash::UdpBlock);
        harness.smash(Smash::AgentSpawn);
        assert_eq!(harness.session(), &before);
        assert_eq!(harness.session().quic.state, PanelState::None);
        assert_eq!(harness.session().svid.state, PanelState::None);
        assert_eq!(harness.session().ticket.state, PanelState::None);
        assert!(harness.session().peers.is_empty());
        assert!(harness.session().packets.is_empty());
        assert_eq!(harness.events().len(), 3);
        assert!(harness.events()[0].detail.contains("did not revoke"));
        assert!(harness.events()[1].detail.contains("did not block UDP"));
        assert!(harness.events()[2].detail.contains("did not spawn"));
        assert_eq!(harness.events()[0].kind, EventKind::SmashRevoke);
    }

    #[test]
    fn level_selection_does_not_run_the_level() {
        let mut harness = Harness::new();
        let before = harness.session().clone();
        harness.select_level(LevelId::RadioactiveNat);
        let snapshot = harness.snapshot();
        let selected = snapshot.levels.iter().find(|level| level.selected).unwrap();
        assert_eq!(selected.title, "Radioactive NAT");
        assert_eq!(selected.body, LevelBody::Empty);
        assert!(selected
            .steps
            .iter()
            .all(|step| step.status == StepStatus::NotRun));
        assert!(harness.events()[0].detail.contains("did not run the level"));
        assert_eq!(harness.session(), &before);
    }

    #[test]
    fn difficulty_selection_does_not_arm_the_hook() {
        let mut harness = Harness::new();
        harness.select_difficulty(Difficulty::Hard);
        let snapshot = harness.snapshot();
        assert!(!snapshot.fault_hook.armed);
        assert_eq!(snapshot.fault_hook.difficulty, Difficulty::Hard);
        assert!(snapshot.fault_detail.contains("not armed"));
        assert!(harness.events()[0].detail.contains("Hard"));
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
        assert!(snapshot.skeleton);
        assert_eq!(snapshot.levels.len(), 3);
        assert_eq!(snapshot.difficulties.len(), 3);
        assert!(snapshot.events.is_empty());
        assert!(!snapshot.fault_hook.armed);
    }
}
