use serde::{Deserialize, Serialize};

/// The network a Rosetta request is about (`mina` and the network name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentifier {
    pub blockchain: String,
    pub network: String,
}
