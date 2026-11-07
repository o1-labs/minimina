use serde::Deserialize;

/// Mina's metadata of a balance: the vesting split, in nanomina.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct BalanceMetadata {
    pub locked_balance: u64,
    pub liquid_balance: u64,
    pub total_balance: u64,
}
