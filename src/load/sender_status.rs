use super::mina_amount;
use mina_sdk::Currency;
use serde::{Deserialize, Serialize};

/// The payments of one sender.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderStatus {
    pub public_key: String,
    pub accepted: u64,
    pub rejected: u64,
    /// Liquid balance at the daemon's best tip when last asked.
    #[serde(default, with = "mina_amount::option")]
    pub liquid: Option<Currency>,
    /// It could not pay amount + fee when last asked.
    pub drained: bool,
}
