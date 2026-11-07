use serde::{Deserialize, Serialize};

/// A block: its height (`index`) and state hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIdentifier {
    pub index: u64,
    pub hash: String,
}
