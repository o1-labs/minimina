use super::NetworkIdentifier;
use serde::Deserialize;

/// `/network/list`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NetworkList {
    pub network_identifiers: Vec<NetworkIdentifier>,
}
