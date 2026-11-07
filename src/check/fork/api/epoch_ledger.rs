use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EpochLedger {
    pub hash: String,
}
