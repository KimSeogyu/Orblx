//! Stack feeds for the sim harness.
//!
//! Each feed stores JSON lines.
//! `drain` returns those lines.
//! A new feed has no lines.

use crate::event::{EventSource, StackFeed};

/// The identity feed.
#[derive(Debug, Default)]
pub struct IdentityFeed {
    pending: Vec<String>,
}

impl StackFeed for IdentityFeed {
    fn source(&self) -> EventSource {
        EventSource::Identity
    }

    fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }

    fn enqueue(&mut self, line: String) {
        self.pending.push(line);
    }
}

/// The edge NAT feed.
#[derive(Debug, Default)]
pub struct EdgeNatFeed {
    pending: Vec<String>,
}

impl StackFeed for EdgeNatFeed {
    fn source(&self) -> EventSource {
        EventSource::EdgeNat
    }

    fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }

    fn enqueue(&mut self, line: String) {
        self.pending.push(line);
    }
}

/// The data path feed.
#[derive(Debug, Default)]
pub struct DatapathFeed {
    pending: Vec<String>,
}

impl StackFeed for DatapathFeed {
    fn source(&self) -> EventSource {
        EventSource::Datapath
    }

    fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }

    fn enqueue(&mut self, line: String) {
        self.pending.push(line);
    }
}

#[cfg(test)]
mod tests {
    use super::{DatapathFeed, EdgeNatFeed, IdentityFeed};
    use crate::event::{EventBus, EventSource, StackFeed};

    #[test]
    fn stub_feeds_are_empty() {
        let mut bus = EventBus::new();
        let mut identity = IdentityFeed::default();
        let mut edge = EdgeNatFeed::default();
        let mut data = DatapathFeed::default();
        bus.ingest(&mut identity);
        bus.ingest(&mut edge);
        bus.ingest(&mut data);
        assert!(bus.events().is_empty());
        assert_eq!(identity.source(), EventSource::Identity);
        assert_eq!(edge.source(), EventSource::EdgeNat);
        assert_eq!(data.source(), EventSource::Datapath);
        assert_eq!(EventSource::EdgeNat.label(), "EdgeNAT");
        assert_eq!(EventSource::Datapath.label(), "Datapath");
    }
}
