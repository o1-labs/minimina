use crate::hardfork::fork_config::ForkPoint;

/// What `hardfork prepare` made the postfork chain start from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFork {
    /// The fork block, and the slot of the postfork genesis.
    pub fork: ForkPoint,
    /// Hash of the postfork genesis ledger and of its staking ledger.
    pub ledger_hash: String,
    pub staking_ledger_hash: String,
}
