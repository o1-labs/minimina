use serde::{Deserialize, Serialize};

/// A block of the archive database, as `fork-candidate last-filled-block`
/// prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveBlock {
    pub state_hash: String,
    pub height: u32,
    pub slot_since_genesis: u32,
}
