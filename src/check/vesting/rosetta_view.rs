use mina_sdk::Currency;

/// A timed account as rosetta's `/account/balance` gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosettaView {
    /// Height of the block rosetta answered for.
    pub block_index: i64,
    pub block_hash: String,
    /// Global slot since genesis of that block; none when the daemon does
    /// not know the block.
    pub slot: Option<u64>,
    pub total: Currency,
    pub locked: Currency,
    pub liquid: Currency,
}
