use super::{api::GenesisData, ForkCheckError};
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

impl GenesisView {
    pub fn of_graphql(data: serde_json::Value) -> Result<Self, ForkCheckError> {
        let block = serde_json::from_value::<GenesisData>(data)
            .map_err(ForkCheckError::Graphql)?
            .genesis_block;
        let state = block.protocol_state;
        let consensus = state.consensus_state;
        let number = |field: &'static str, value: String| {
            value
                .parse()
                .map_err(|_| ForkCheckError::Field { field, value })
        };
        Ok(GenesisView {
            state_hash: block.state_hash,
            previous_state_hash: state.previous_state_hash,
            height: number("blockHeight", consensus.block_height)?,
            slot: number("slotSinceGenesis", consensus.slot_since_genesis)?,
            ledger_hash: state.blockchain_state.snarked_ledger_hash,
            staking_ledger_hash: consensus.staking_epoch_data.ledger.hash,
        })
    }
}
