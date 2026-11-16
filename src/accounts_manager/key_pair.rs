use crate::spec::ledger::PublicKey;
use serde::Serialize;

/// An account the accounts manager can hand out: its public key, and the
/// private key a test signs with.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: String,
}
