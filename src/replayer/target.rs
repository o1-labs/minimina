use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// The transaction protocol version of Mesa: the blocks of a Mesa chain
/// (4.x) have 4, Berkeley ones (3.x) 3.
const MESA_TRANSACTION_VERSION: u32 = 4;

/// `--hard-fork-target` of `mina-replayer`: what the prefork pass does to the
/// ledger it hands to the postfork pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HardForkTarget {
    /// Migrates a Berkeley ledger to Mesa: for a fork from Berkeley into Mesa.
    Mesa,
    /// No migration: the prefork ledger is a Mesa one already.
    Compatible,
}

impl HardForkTarget {
    /// The target of a prefork chain whose blocks have `transaction_version`:
    /// a Mesa ledger needs no migration, an older one the Mesa migration.
    pub fn for_prefork(transaction_version: u32) -> Self {
        match transaction_version >= MESA_TRANSACTION_VERSION {
            true => HardForkTarget::Compatible,
            false => HardForkTarget::Mesa,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            HardForkTarget::Mesa => "mesa",
            HardForkTarget::Compatible => "compatible",
        }
    }
}

impl std::fmt::Display for HardForkTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pre_mesa_chain_is_migrated() {
        assert_eq!(HardForkTarget::for_prefork(3), HardForkTarget::Mesa);
        assert_eq!(HardForkTarget::for_prefork(4), HardForkTarget::Compatible);
        assert_eq!(HardForkTarget::for_prefork(5), HardForkTarget::Compatible);
    }
}
