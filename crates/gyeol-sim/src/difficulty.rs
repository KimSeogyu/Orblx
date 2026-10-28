//! Fault-injection difficulty hooks.
//!
//! The harness stores Easy, Medium, or Hard.
//! The harness does not inject a fault.

use serde::Serialize;

/// The fault-injection difficulty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Difficulty {
    /// A light fault set for a later week.
    #[default]
    Easy,
    /// A mixed fault set for a later week.
    Medium,
    /// A heavy fault set for a later week.
    Hard,
}

impl Difficulty {
    /// The difficulties in display order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Easy, Self::Medium, Self::Hard]
    }

    /// The difficulty name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Easy => "Easy",
            Self::Medium => "Medium",
            Self::Hard => "Hard",
        }
    }

    /// A note for a later week.
    ///
    /// The note does not change harness behavior.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Easy => "Later weeks can attach a light fault set.",
            Self::Medium => "Later weeks can attach a mixed fault set.",
            Self::Hard => "Later weeks can attach a heavy fault set.",
        }
    }

    /// The stored hook for this difficulty.
    ///
    /// `armed` is false.
    /// The skeleton does not arm the hook.
    #[must_use]
    pub const fn hook(self) -> FaultHook {
        FaultHook {
            difficulty: self,
            armed: false,
        }
    }

    /// Parse a difficulty id from the web API.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "easy" => Ok(Self::Easy),
            "medium" => Ok(Self::Medium),
            "hard" => Ok(Self::Hard),
            other => Err(format!("The difficulty {other} is not valid.")),
        }
    }
}

/// A stored fault-injection hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FaultHook {
    /// The selected difficulty.
    pub difficulty: Difficulty,
    /// True when a later week arms the hook.
    ///
    /// The skeleton keeps this value false.
    pub armed: bool,
}

impl FaultHook {
    /// One status sentence for the UI.
    #[must_use]
    pub fn detail(self) -> String {
        let armed = if self.armed {
            "The fault hook is armed."
        } else {
            "The fault hook is not armed."
        };
        format!(
            "Difficulty {}. The fault hook is stored. {armed}",
            self.difficulty.label()
        )
    }
}

/// One difficulty button in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DifficultyCard {
    /// API id.
    pub id: Difficulty,
    /// Display name.
    pub label: &'static str,
    /// Later-week note.
    pub note: &'static str,
    /// True when this difficulty is stored.
    pub selected: bool,
}

impl Difficulty {
    /// Build the card for a snapshot.
    #[must_use]
    pub fn card(self, selected: bool) -> DifficultyCard {
        DifficultyCard {
            id: self,
            label: self.label(),
            note: self.note(),
            selected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Difficulty;

    #[test]
    fn hooks_are_not_armed() {
        for difficulty in Difficulty::all() {
            let hook = difficulty.hook();
            assert_eq!(hook.difficulty, difficulty);
            assert!(!hook.armed);
            assert!(hook.detail().contains("not armed"));
            assert!(hook.detail().contains(difficulty.label()));
        }
    }

    #[test]
    fn parse_accepts_the_api_ids() {
        assert_eq!(Difficulty::parse("easy").unwrap(), Difficulty::Easy);
        assert_eq!(Difficulty::parse("medium").unwrap(), Difficulty::Medium);
        assert_eq!(Difficulty::parse("hard").unwrap(), Difficulty::Hard);
        assert!(Difficulty::parse("Easy").is_err());
    }
}
