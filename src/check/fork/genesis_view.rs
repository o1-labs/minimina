use serde::Serialize;

/// The genesis block a daemon runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenesisView {
    pub state_hash: String,
    pub previous_state_hash: String,
    pub height: u64,
    pub slot: u64,
    pub ledger_hash: String,
    pub staking_ledger_hash: String,
}

impl From<mina_sdk::BlockInfo> for GenesisView {
    fn from(block: mina_sdk::BlockInfo) -> Self {
        GenesisView {
            state_hash: block.state_hash,
            previous_state_hash: block.previous_state_hash,
            height: block.height,
            slot: block.global_slot_since_genesis,
            ledger_hash: block.snarked_ledger_hash,
            staking_ledger_hash: block.staking_epoch.ledger_hash,
        }
    }
}
