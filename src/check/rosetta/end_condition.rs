use serde::{Deserialize, Serialize};

/// The end condition a `rosetta-cli check:data` run met.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EndCondition {
    #[serde(rename = "type")]
    pub kind: String,
    pub detail: String,
}
