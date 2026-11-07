use super::EpochData;
use serde::Deserialize;

/// Lengths and slots are GraphQL strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusState {
    pub block_height: String,
    pub slot_since_genesis: String,
    pub staking_epoch_data: EpochData,
}
