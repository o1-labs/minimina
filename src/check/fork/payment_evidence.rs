use super::{ChainBlock, IncludedCommand};
use crate::load::PaymentRecord;
use std::collections::BTreeMap;

/// What the payment checks hold the loads' payments against.
pub struct PaymentEvidence<'a> {
    /// The payments the daemons took, of every load.
    pub payments: &'a [PaymentRecord],
    pub postfork_genesis: &'a str,
    pub fork_height: i64,
    /// The archive's chain, highest block first.
    pub chain: &'a [ChainBlock],
    /// The archived blocks holding the payments.
    pub commands: &'a [IncludedCommand],
    /// Nonce of each account in the fork ledger.
    pub fork_nonces: &'a BTreeMap<String, u64>,
    /// Nonce of each postfork sender at the daemon's best tip now.
    pub daemon_nonces: &'a BTreeMap<String, u64>,
}
