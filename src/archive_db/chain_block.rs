/// A block of the archive's chain from its highest postfork block down
/// ([`super::ArchiveDb::chain_from_tip`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBlock {
    pub id: i32,
    pub parent_id: Option<i32>,
    pub height: i64,
    pub state_hash: String,
    pub parent_hash: String,
    /// canonical, pending or orphaned.
    pub chain_status: String,
    pub slot_since_genesis: i64,
    pub slot_since_hard_fork: i64,
}
