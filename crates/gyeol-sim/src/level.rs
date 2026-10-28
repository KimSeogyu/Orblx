//! Levels for the sim harness.
//!
//! Each level has a name and a script.
//! The harness runs the script.

use serde::Serialize;

use crate::difficulty::Difficulty;

/// The three harness levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LevelId {
    /// Human OIDC, SVID, overlay ping, and two HTTPS applications.
    CityBreeze,
    /// Agent spawn, allow A, deny B, and a visible ticket TTL.
    AgentJit,
    /// UDP block, symmetric NAT, Allocate, Direct, Relay, and revoke.
    RadioactiveNat,
}

impl LevelId {
    /// The levels in display order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::CityBreeze, Self::AgentJit, Self::RadioactiveNat]
    }

    /// The level name.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::CityBreeze => "City Breeze",
            Self::AgentJit => "Agent JIT",
            Self::RadioactiveNat => "Radioactive NAT",
        }
    }

    /// The level script in short sentences.
    #[must_use]
    pub const fn goal(self) -> &'static str {
        match self {
            Self::CityBreeze => {
                "A human uses OIDC to get an SVID. The human sends an overlay ping. The human opens two HTTPS applications."
            }
            Self::AgentJit => {
                "The operator spawns an agent. Application A allows the agent. Application B denies the agent. The ticket TTL expiry is visible."
            }
            Self::RadioactiveNat => {
                "The path can block UDP. The path can use symmetric NAT. The order is Allocate, then Direct, then Relay. An SVID revoke drops new packets within 60 seconds."
            }
        }
    }

    /// The script steps.
    #[must_use]
    pub const fn steps(self) -> &'static [&'static str] {
        match self {
            Self::CityBreeze => &[
                "A human uses OIDC.",
                "The human receives an SVID.",
                "The human sends an overlay ping.",
                "The human opens two HTTPS applications.",
            ],
            Self::AgentJit => &[
                "The operator spawns an agent.",
                "Application A allows the agent.",
                "Application B denies the agent.",
                "The ticket TTL expiry is visible.",
            ],
            Self::RadioactiveNat => &[
                "The operator can block UDP.",
                "The path can use symmetric NAT.",
                "The path uses Allocate.",
                "The path uses Direct.",
                "The path uses Relay.",
                "An SVID revoke drops new packets within 60 seconds.",
            ],
        }
    }

    /// Parse a level id from the web API.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "city_breeze" => Ok(Self::CityBreeze),
            "agent_jit" => Ok(Self::AgentJit),
            "radioactive_nat" => Ok(Self::RadioactiveNat),
            other => Err(format!("The level {other} is not valid.")),
        }
    }

    /// The difficulty that matches this level.
    #[must_use]
    pub const fn difficulty(self) -> Difficulty {
        match self {
            Self::CityBreeze => Difficulty::Easy,
            Self::AgentJit => Difficulty::Medium,
            Self::RadioactiveNat => Difficulty::Hard,
        }
    }
}

/// The level body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LevelBody {
    /// The level has not run.
    Empty,
    /// The level machine has run.
    Live,
}

/// The status of one script step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// The harness did not run the step.
    NotRun,
    /// The step passed.
    Pass,
    /// The step failed.
    Fail,
}

/// One level card in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LevelCard {
    /// API id.
    pub id: LevelId,
    /// Display name.
    pub title: &'static str,
    /// Script summary.
    pub goal: &'static str,
    /// Script steps.
    pub steps: Vec<LevelStep>,
    /// Body state.
    pub body: LevelBody,
    /// True when the operator selected this level.
    pub selected: bool,
}

/// One script step in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LevelStep {
    /// The step sentence.
    pub text: &'static str,
    /// The step status.
    pub status: StepStatus,
}

impl LevelId {
    /// Build the card for a snapshot.
    ///
    /// `statuses` aligns with `steps`.
    /// A missing status stays `not run`.
    #[must_use]
    pub fn card(self, selected: bool, live: bool, statuses: &[StepStatus]) -> LevelCard {
        let steps = self
            .steps()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, text)| LevelStep {
                text,
                status: statuses.get(index).copied().unwrap_or(StepStatus::NotRun),
            })
            .collect();
        LevelCard {
            id: self,
            title: self.title(),
            goal: self.goal(),
            steps,
            body: if live {
                LevelBody::Live
            } else {
                LevelBody::Empty
            },
            selected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LevelBody, LevelId, StepStatus};

    #[test]
    fn titles_are_exact() {
        assert_eq!(LevelId::CityBreeze.title(), "City Breeze");
        assert_eq!(LevelId::AgentJit.title(), "Agent JIT");
        assert_eq!(LevelId::RadioactiveNat.title(), "Radioactive NAT");
    }

    #[test]
    fn goals_keep_the_script() {
        let city = LevelId::CityBreeze.goal();
        assert!(city.contains("OIDC"));
        assert!(city.contains("SVID"));
        assert!(city.contains("overlay ping"));
        assert!(city.contains("two HTTPS applications"));

        let agent = LevelId::AgentJit.goal();
        assert!(agent.contains("spawns an agent"));
        assert!(agent.contains("Application A allows"));
        assert!(agent.contains("Application B denies"));
        assert!(agent.contains("TTL"));

        let nat = LevelId::RadioactiveNat.goal();
        assert!(nat.contains("block UDP"));
        assert!(nat.contains("symmetric NAT"));
        assert!(nat.contains("Allocate"));
        assert!(nat.contains("Direct"));
        assert!(nat.contains("Relay"));
        assert!(nat.contains("60 seconds"));
    }

    #[test]
    fn cards_are_empty() {
        for id in LevelId::all() {
            let card = id.card(false, false, &[]);
            assert_eq!(card.body, LevelBody::Empty);
            assert!(!card.steps.is_empty());
            assert!(card
                .steps
                .iter()
                .all(|step| step.status == StepStatus::NotRun));
        }
    }

    #[test]
    fn parse_accepts_the_api_ids() {
        assert_eq!(LevelId::parse("city_breeze").unwrap(), LevelId::CityBreeze);
        assert_eq!(LevelId::parse("agent_jit").unwrap(), LevelId::AgentJit);
        assert_eq!(
            LevelId::parse("radioactive_nat").unwrap(),
            LevelId::RadioactiveNat
        );
        assert!(LevelId::parse("city-breeze").is_err());
    }
}
