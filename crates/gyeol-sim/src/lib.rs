//! Local sim harness.
//!
//! The harness serves a web UI.
//! The harness runs three level state machines.
//! Feed lines are JSON version 1.
//! The HTTP server sends those lines on `/events`.

mod difficulty;
mod envelope;
mod event;
mod feed;
mod harness;
mod http;
mod level;
mod oidc_flow;
mod session;
mod sim;

pub use difficulty::{Difficulty, DifficultyCard, FaultHook};
pub use event::{EventBus, EventKind, EventSource, HarnessEvent, StackFeed};
pub use feed::{DatapathFeed, EdgeNatFeed, IdentityFeed};
pub use harness::{Harness, Smash, Snapshot};
pub use http::{default_listen, parse_listen, serve, serve_blocking, SimError, DEFAULT_PORT};
pub use level::{LevelBody, LevelCard, LevelId, LevelStep, StepStatus};
pub use session::{PacketRow, Panel, PanelState, PeerRow, SessionView};
pub use sim::AuditView;
