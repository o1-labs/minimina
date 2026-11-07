use super::{BlockchainState, ConsensusState};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolState {
    pub previous_state_hash: String,
    pub blockchain_state: BlockchainState,
    pub consensus_state: ConsensusState,
}
