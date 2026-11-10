/// What the load needs to know about the daemon's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainView {
    /// State hash of the genesis block: a new one means the hardfork happened.
    pub genesis: String,
    pub synced: bool,
}
