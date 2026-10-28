//! Empty stack feeds.
//!
//! The feeds exist so a later week can replace them.
//! Each feed returns no events.

use crate::event::{EventSource, StackFeed};

/// The identity feed stub.
///
/// The stub does not issue an SVID.
/// The stub does not read the identity crate.
#[derive(Debug, Default)]
pub struct IdentityFeed;

impl StackFeed for IdentityFeed {
    fn source(&self) -> EventSource {
        EventSource::Identity
    }

    fn drain(&mut self) -> Vec<String> {
        Vec::new()
    }
}

/// The edge NAT feed stub.
///
/// The stub does not allocate a path.
/// The stub does not punch a hole.
/// The stub does not open a relay socket.
#[derive(Debug, Default)]
pub struct EdgeNatFeed;

impl StackFeed for EdgeNatFeed {
    fn source(&self) -> EventSource {
        EventSource::EdgeNat
    }

    fn drain(&mut self) -> Vec<String> {
        Vec::new()
    }
}

/// The data path feed stub.
///
/// The stub does not open a QUIC socket.
/// The stub does not read a packet.
#[derive(Debug, Default)]
pub struct DatapathFeed;

impl StackFeed for DatapathFeed {
    fn source(&self) -> EventSource {
        EventSource::Datapath
    }

    fn drain(&mut self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{DatapathFeed, EdgeNatFeed, IdentityFeed};
    use crate::event::{EventBus, EventSource, StackFeed};

    #[test]
    fn stub_feeds_are_empty() {
        let mut bus = EventBus::new();
        bus.ingest(&mut IdentityFeed);
        bus.ingest(&mut EdgeNatFeed);
        bus.ingest(&mut DatapathFeed);
        assert!(bus.events().is_empty());
        assert_eq!(IdentityFeed.source(), EventSource::Identity);
        assert_eq!(EdgeNatFeed.source(), EventSource::EdgeNat);
        assert_eq!(DatapathFeed.source(), EventSource::Datapath);
        assert_eq!(EventSource::EdgeNat.label(), "EdgeNAT");
        assert_eq!(EventSource::Datapath.label(), "Datapath");
    }
}
