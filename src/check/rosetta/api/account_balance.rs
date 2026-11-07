use super::{Balance, BlockIdentifier};
use serde::Deserialize;

/// `/account/balance`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountBalance {
    pub block_identifier: BlockIdentifier,
    pub balances: Vec<Balance>,
}
