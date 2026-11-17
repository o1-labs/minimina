use serde::{Deserialize, Serialize};

/// A slot of a vesting schedule (`cliff_time`, `vesting_period`), in either
/// form a runtime config writes it, and written back in the form it was
/// read in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Slot {
    /// `"10"`, as minimina and most runtime configs write it.
    Plain(String),
    /// `["Since_genesis", "10"]` or `["Global_slot_span", "20"]`, as mina's
    /// own runtime configs write it.
    Tagged(SlotKind, String),
}

/// What a tagged slot counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotKind {
    /// A global slot since genesis (`cliff_time`).
    #[serde(rename = "Since_genesis")]
    SinceGenesis,
    /// A number of slots (`vesting_period`).
    #[serde(rename = "Global_slot_span")]
    GlobalSlotSpan,
}

impl Slot {
    /// The slot number, as written.
    pub fn value(&self) -> &str {
        match self {
            Slot::Plain(value) | Slot::Tagged(_, value) => value,
        }
    }
}

impl From<&str> for Slot {
    fn from(value: &str) -> Self {
        Slot::Plain(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_and_keeps_both_forms() {
        let plain: Slot = serde_json::from_value(json!("10")).unwrap();
        assert_eq!(plain, Slot::Plain("10".into()));
        assert_eq!(plain.value(), "10");
        assert_eq!(serde_json::to_value(&plain).unwrap(), json!("10"));

        let cliff: Slot = serde_json::from_value(json!(["Since_genesis", "10"])).unwrap();
        assert_eq!(cliff, Slot::Tagged(SlotKind::SinceGenesis, "10".into()));
        assert_eq!(cliff.value(), "10");
        assert_eq!(
            serde_json::to_value(&cliff).unwrap(),
            json!(["Since_genesis", "10"])
        );

        let period: Slot = serde_json::from_value(json!(["Global_slot_span", "20"])).unwrap();
        assert_eq!(period.value(), "20");

        assert!(serde_json::from_value::<Slot>(json!(["Since_fork", "10"])).is_err());
    }
}
