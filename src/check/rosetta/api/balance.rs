use super::BalanceMetadata;
use serde::Deserialize;

/// One balance of `/account/balance` (mina has one, in MINA).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Balance {
    /// Nanomina.
    pub value: String,
    pub metadata: Option<BalanceMetadata>,
}
