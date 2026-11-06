use super::{Balance, PublicKey, Timing};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// One account of the genesis ledger, as a runtime config writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerAccount {
    pub pk: PublicKey,
    pub balance: Balance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate: Option<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,
    /// Every other field (permissions, token, zkapp, ...), kept as it is.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl LedgerAccount {
    pub fn new(pk: PublicKey, balance: Balance) -> Self {
        LedgerAccount {
            pk,
            balance,
            sk: None,
            delegate: None,
            timing: None,
            other: Map::new(),
        }
    }
}
