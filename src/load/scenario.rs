use super::LoadError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How a load sends its payments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ScenarioKind {
    /// One round of payments, then the load is done
    Once,
    /// A few payments every few seconds, until stopped
    Steady,
    /// Many payments at once, every few minutes, until stopped
    Burst,
}

impl std::fmt::Display for ScenarioKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ScenarioKind::Once => "once",
            ScenarioKind::Steady => "steady",
            ScenarioKind::Burst => "burst",
        })
    }
}

/// Rounds of payments: `per_round` payments, then a pause of `interval`,
/// until `rounds` rounds or `duration` (none: until stopped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    pub kind: ScenarioKind,
    pub per_round: u32,
    #[serde(with = "secs")]
    pub interval: Duration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rounds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_secs")]
    pub duration: Option<Duration>,
}

impl Scenario {
    /// The defaults of a kind.
    pub fn preset(kind: ScenarioKind) -> Self {
        let (per_round, interval, rounds) = match kind {
            ScenarioKind::Once => (1, 0, Some(1)),
            ScenarioKind::Steady => (1, 10, None),
            ScenarioKind::Burst => (10, 120, None),
        };
        Scenario {
            kind,
            per_round,
            interval: Duration::from_secs(interval),
            rounds,
            duration: None,
        }
    }

    /// The preset of `kind` with what was given instead.
    pub fn new(
        kind: ScenarioKind,
        per_round: Option<u32>,
        interval: Option<u64>,
        rounds: Option<u64>,
        duration: Option<u64>,
    ) -> Result<Self, LoadError> {
        let preset = Scenario::preset(kind);
        let scenario = Scenario {
            kind,
            per_round: per_round.unwrap_or(preset.per_round),
            interval: interval.map_or(preset.interval, Duration::from_secs),
            rounds: rounds.or(preset.rounds),
            duration: duration.map(Duration::from_secs),
        };
        if scenario.per_round == 0 {
            return Err(LoadError::Zero("--count"));
        }
        if scenario.rounds == Some(0) {
            return Err(LoadError::Zero("--rounds"));
        }
        Ok(scenario)
    }

    /// Whether a load that has run `rounds` rounds for `elapsed` is done.
    pub fn is_done(&self, rounds: u64, elapsed: Duration) -> bool {
        self.rounds.is_some_and(|max| rounds >= max)
            || self.duration.is_some_and(|max| elapsed >= max)
    }
}

mod secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

mod opt_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_u64(d.as_secs()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(d)?.map(Duration::from_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_and_limits() {
        let once = Scenario::preset(ScenarioKind::Once);
        assert!(!once.is_done(0, Duration::ZERO));
        assert!(once.is_done(1, Duration::ZERO));
        let steady = Scenario::preset(ScenarioKind::Steady);
        assert!(!steady.is_done(1_000, Duration::from_secs(86_400)));
        let timed = Scenario {
            duration: Some(Duration::from_secs(60)),
            ..Scenario::preset(ScenarioKind::Burst)
        };
        assert_eq!(timed.per_round, 10);
        assert!(!timed.is_done(3, Duration::from_secs(59)));
        assert!(timed.is_done(3, Duration::from_secs(60)));
        let json = serde_json::to_value(timed).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kind": "burst", "per_round": 10, "interval": 120, "duration": 60})
        );
        assert_eq!(serde_json::from_value::<Scenario>(json).unwrap(), timed);

        let given = Scenario::new(ScenarioKind::Burst, Some(3), None, Some(2), None).unwrap();
        assert_eq!(
            (given.per_round, given.interval.as_secs(), given.rounds),
            (3, 120, Some(2))
        );
        let err = Scenario::new(ScenarioKind::Once, Some(0), None, None, None).unwrap_err();
        assert_eq!(err.to_string(), "--count must be at least 1");
    }
}
