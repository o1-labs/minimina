use super::ProtocolState;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisBlock {
    pub state_hash: String,
    pub protocol_state: ProtocolState,
}
