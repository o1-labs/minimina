use super::BlockIdentifier;
use serde::Deserialize;

/// `/network/status`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NetworkStatus {
    pub current_block_identifier: BlockIdentifier,
    pub genesis_block_identifier: BlockIdentifier,
}
