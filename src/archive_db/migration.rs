use serde::{Deserialize, Serialize};

/// The last row of the archive's `migration_history`: the schema migration
/// `upgrade.sql` made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Migration {
    pub protocol_version: String,
    pub migration_version: String,
    pub status: String,
}

impl Migration {
    /// `upgrade.sql` finished; it records `starting` first.
    pub fn is_applied(&self) -> bool {
        self.status == "applied"
    }
}

impl std::fmt::Display for Migration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "protocol {} migration {} {}",
            self.protocol_version, self.migration_version, self.status
        )
    }
}
