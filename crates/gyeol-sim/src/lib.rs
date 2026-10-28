//! Local sim harness skeleton.
//!
//! The harness serves a web UI.
//! The harness records stub events.
//! The harness does not run the gyeol-quic stack.
//! The harness does not animate a successful path.

mod difficulty;
mod event;
mod feed;
mod harness;
mod http;
mod level;
mod session;

pub use difficulty::{Difficulty, DifficultyCard, FaultHook};
pub use event::{EventBus, EventKind, EventSource, HarnessEvent, StackFeed};
pub use feed::{DatapathFeed, EdgeNatFeed, IdentityFeed};
pub use harness::{Harness, Smash, Snapshot};
pub use http::{default_listen, parse_listen, serve, serve_blocking, SimError, DEFAULT_PORT};
pub use level::{LevelBody, LevelCard, LevelId, LevelStep, StepStatus};
pub use session::{PacketRow, Panel, PanelState, PeerRow, SessionView};
