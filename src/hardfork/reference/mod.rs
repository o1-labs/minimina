//! Auto mode's legacy reference: the fork config a daemon gives over GraphQL
//! (`fork_config`), as in manual mode, with the ledgers the postfork
//! `runtime_genesis_ledger` makes from it. The daemons dump their own fork
//! config at `slot_chain_end` and exit; GraphQL serves the same fork block
//! from `slot_tx_end` on (the newest block before it), so `prepare` asks in
//! between. Each dumped config must name that fork block and those ledgers:
//! equal Merkle roots are equal ledgers. The checks take the fork ledger's
//! accounts from the reference, since a dumped config names its ledgers by
//! hash only.

use super::fork_config::{ForkPoint, LedgerHash, LedgerHashes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Under the network's hardfork directory: `fork_config.json`, `genesis/`
/// and `ledger_hashes.json` of the reference.
pub const REFERENCE_DIR: &str = "reference";

/// The legacy reference of an auto mode fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyReference {
    /// The daemon whose GraphQL fork config it is.
    pub source: String,
    pub fork: ForkPoint,
    /// The ledgers `runtime_genesis_ledger` made from it.
    pub hashes: LedgerHashes,
}

impl LegacyReference {
    /// How each daemon's dumped fork config differs from the reference: its
    /// fork point, and the hash (not the tarball checksum, which differs
    /// between equal ledgers) of the genesis, staking and next epoch ledgers.
    pub fn mismatches(&self, dumps: &BTreeMap<String, Result<Value, String>>) -> Vec<String> {
        let mut problems = Vec::new();
        for (name, dump) in dumps {
            let Ok(dump) = dump else {
                continue; // prepare reports an unreadable dump already
            };
            match ForkPoint::of(dump) {
                Ok(fork) if fork != self.fork => problems.push(format!(
                    "{name} dumped fork point {} (height {}), the legacy fork config has {} \
                     (height {})",
                    fork.state_hash,
                    fork.blockchain_length,
                    self.fork.state_hash,
                    self.fork.blockchain_length
                )),
                Ok(_) => {}
                Err(e) => problems.push(format!("{name}: {e}")),
            }
            let hashes = match LedgerHashes::deserialize(dump) {
                Ok(hashes) => hashes,
                Err(e) => {
                    problems.push(format!("{name}: the ledger hashes of its dump: {e}"));
                    continue;
                }
            };
            let pairs = [
                ("genesis", Some(&hashes.ledger), Some(&self.hashes.ledger)),
                (
                    "staking",
                    Some(&hashes.epoch_data.staking),
                    Some(&self.hashes.epoch_data.staking),
                ),
                (
                    "next epoch",
                    hashes.epoch_data.next.as_ref(),
                    self.hashes.epoch_data.next.as_ref(),
                ),
            ];
            for (ledger, dumped, legacy) in pairs {
                let hash =
                    |h: Option<&LedgerHash>| h.map_or("none".to_string(), |h| h.hash.clone());
                if hash(dumped) != hash(legacy) {
                    problems.push(format!(
                        "{name} dumped {ledger} ledger {}, the legacy fork config makes {}",
                        hash(dumped),
                        hash(legacy)
                    ));
                }
            }
        }
        problems
    }
}

#[cfg(test)]
mod tests;
