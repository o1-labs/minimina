//! The daemon's GraphQL `genesisBlock`, as far as the fork check reads it.

mod blockchain_state;
mod consensus_state;
mod epoch_data;
mod epoch_ledger;
mod genesis_block;
mod genesis_data;
mod protocol_state;

pub use blockchain_state::BlockchainState;
pub use consensus_state::ConsensusState;
pub use epoch_data::EpochData;
pub use epoch_ledger::EpochLedger;
pub use genesis_block::GenesisBlock;
pub use genesis_data::GenesisData;
pub use protocol_state::ProtocolState;

pub const GENESIS_QUERY: &str = "{ genesisBlock { stateHash protocolState {
  previousStateHash
  blockchainState { snarkedLedgerHash }
  consensusState { blockHeight slotSinceGenesis stakingEpochData { ledger { hash } } }
} } }";
