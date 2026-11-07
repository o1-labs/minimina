use super::mina_amount;
use mina_sdk::Currency;
use serde::{Deserialize, Serialize};

/// One line of `payments.jsonl`: a payment the load sent and what the
/// daemon said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRecord {
    pub at: String,
    pub round: u64,
    /// State hash of the genesis of the chain it was sent on: the prefork
    /// or the postfork one.
    pub genesis: String,
    pub sender: String,
    pub receiver: String,
    #[serde(with = "mina_amount")]
    pub amount: Currency,
    #[serde(with = "mina_amount")]
    pub fee: Currency,
    pub memo: String,
    /// Transaction hash and nonce when the daemon took it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
