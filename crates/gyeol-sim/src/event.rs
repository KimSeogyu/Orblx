//! Event bus for the sim harness.
//!
//! Smash buttons write stub events.
//! Identity, EdgeNAT, and Datapath can feed events later.
//! A feed event does not change the session panels.

use serde::Serialize;

/// The maximum number of stored events.
const EVENT_CAP: usize = 256;

/// The area that produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// The harness UI or a smash button.
    Harness,
    /// The identity stack. The stub feed is empty.
    Identity,
    /// The edge NAT stack. The stub feed is empty.
    EdgeNat,
    /// The data path stack. The stub feed is empty.
    Datapath,
}

impl EventSource {
    /// The display name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Harness => "Harness",
            Self::Identity => "Identity",
            Self::EdgeNat => "EdgeNAT",
            Self::Datapath => "Datapath",
        }
    }
}

/// The event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The operator selected a level.
    LevelSelected,
    /// The operator selected a difficulty.
    DifficultySelected,
    /// The operator pressed revoke.
    SmashRevoke,
    /// The operator pressed UDP block.
    SmashUdpBlock,
    /// The operator pressed agent spawn.
    SmashAgentSpawn,
    /// A stack feed produced a line.
    Feed,
}

impl EventKind {
    /// The log token.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LevelSelected => "level_selected",
            Self::DifficultySelected => "difficulty_selected",
            Self::SmashRevoke => "smash_revoke",
            Self::SmashUdpBlock => "smash_udp_block",
            Self::SmashAgentSpawn => "smash_agent_spawn",
            Self::Feed => "feed",
        }
    }
}

/// One stored harness event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HarnessEvent {
    /// The sequence number. The first event is 1.
    pub seq: u64,
    /// The producer.
    pub source: EventSource,
    /// The kind.
    pub kind: EventKind,
    /// One or two short sentences.
    pub detail: String,
}

impl HarnessEvent {
    /// One terminal log line.
    #[must_use]
    pub fn log_line(&self) -> String {
        format!(
            "event {} {} {} {}",
            self.seq,
            self.source.label(),
            self.kind.label(),
            self.detail
        )
    }
}

/// A producer of harness events.
///
/// Identity, EdgeNAT, and Datapath can implement this trait later.
/// A stub feed returns no lines.
pub trait StackFeed {
    /// The event source for drained lines.
    fn source(&self) -> EventSource;

    /// Take the lines that are ready.
    ///
    /// The skeleton feeds return an empty list.
    fn drain(&mut self) -> Vec<String>;
}

/// The in-memory event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBus {
    next_seq: u64,
    events: Vec<HarnessEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create an empty bus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            events: Vec::new(),
        }
    }

    /// The stored events in order.
    #[must_use]
    pub fn events(&self) -> &[HarnessEvent] {
        &self.events
    }

    /// Append one event.
    ///
    /// The bus drops the oldest event when the log is full.
    pub fn push(&mut self, source: EventSource, kind: EventKind, detail: impl Into<String>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.events.push(HarnessEvent {
            seq,
            source,
            kind,
            detail: detail.into(),
        });
        if self.events.len() > EVENT_CAP {
            let extra = self.events.len() - EVENT_CAP;
            self.events.drain(0..extra);
        }
    }

    /// Drain one feed into the bus.
    ///
    /// This method does not update session panels.
    pub fn ingest<F: StackFeed + ?Sized>(&mut self, feed: &mut F) {
        let source = feed.source();
        let details = feed.drain();
        for detail in details {
            self.push(source, EventKind::Feed, detail);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventBus, EventKind, EventSource, StackFeed, EVENT_CAP};

    struct OneLine;

    impl StackFeed for OneLine {
        fn source(&self) -> EventSource {
            EventSource::Identity
        }

        fn drain(&mut self) -> Vec<String> {
            vec!["An adapter sent one line.".to_string()]
        }
    }

    #[test]
    fn ingest_records_a_feed_line() {
        let mut bus = EventBus::new();
        bus.ingest(&mut OneLine);
        let event = &bus.events()[0];
        assert_eq!(event.seq, 1);
        assert_eq!(event.source, EventSource::Identity);
        assert_eq!(event.kind, EventKind::Feed);
        assert_eq!(event.detail, "An adapter sent one line.");
        assert!(event.log_line().contains("Identity"));
    }

    #[test]
    fn the_bus_drops_the_oldest_event() {
        let mut bus = EventBus::new();
        for index in 0..(EVENT_CAP + 5) {
            bus.push(
                EventSource::Harness,
                EventKind::Feed,
                format!("line {index}"),
            );
        }
        assert_eq!(bus.events().len(), EVENT_CAP);
        assert_eq!(bus.events()[0].seq, 6);
        assert_eq!(
            bus.events().last().unwrap().seq,
            u64::try_from(EVENT_CAP + 5).unwrap()
        );
    }
}
