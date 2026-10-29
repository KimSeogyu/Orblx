use crate::EventKind;

/// Counters for session start, session end, and session deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub struct SessionMetrics {
    /// Session start events.
    pub start: u64,
    /// Session end events.
    pub end: u64,
    /// Session deny events.
    pub deny: u64,
}

impl SessionMetrics {
    pub(crate) fn observe(&mut self, kind: EventKind) {
        match kind {
            EventKind::Start => self.start = self.start.saturating_add(1),
            EventKind::End => self.end = self.end.saturating_add(1),
            EventKind::Deny => self.deny = self.deny.saturating_add(1),
        }
    }
}
