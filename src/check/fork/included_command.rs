/// A user command in an archived block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludedCommand {
    pub hash: String,
    pub nonce: i64,
    pub fee_payer: String,
    pub block_state_hash: String,
    pub height: i64,
    /// applied or failed.
    pub status: String,
}
