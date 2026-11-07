use std::path::PathBuf;

/// The hardfork of a network after `network hardfork apply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFork {
    /// The prefork runtime config `apply` kept, with `slot_chain_end` and
    /// `hard_fork_genesis_slot_delta`.
    pub prefork_config: PathBuf,
    pub fork_genesis_slot: u32,
}
