use super::EpochLedger;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EpochData {
    pub ledger: EpochLedger,
}
