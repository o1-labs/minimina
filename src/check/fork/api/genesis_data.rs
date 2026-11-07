use super::GenesisBlock;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisData {
    pub genesis_block: GenesisBlock,
}
