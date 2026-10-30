//! The fork config of a prefork daemon (GraphQL `fork_config`) and the
//! postfork runtime configs made from it, as mina's
//! `scripts/hardfork/create_runtime_config.sh` and `hardfork_test` make them.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The last block of the prefork chain, from `proof.fork` of a fork config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkPoint {
    pub state_hash: String,
    pub blockchain_length: u32,
    /// The first slot of the postfork chain.
    pub global_slot_since_genesis: u32,
}

impl ForkPoint {
    pub fn of(fork_config: &Value) -> Result<Self, String> {
        let fork = fork_config
            .pointer("/proof/fork")
            .ok_or("the fork config has no proof.fork")?;
        ForkPoint::deserialize(fork).map_err(|e| format!("proof.fork of the fork config: {e}"))
    }
}

/// A ledger in `ledger_hashes.json` of `runtime_genesis_ledger`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerHash {
    pub hash: String,
    pub s3_data_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochHashes {
    pub staking: LedgerHash,
    pub next: Option<LedgerHash>,
}

/// `ledger_hashes.json`: the hashes of the ledgers `runtime_genesis_ledger` made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerHashes {
    pub ledger: LedgerHash,
    pub epoch_data: EpochHashes,
}

/// The `daemon.json` of the postfork chain: the fork point and the seeds of
/// the fork config, the hashes of the postfork ledgers, and the genesis
/// timestamp of the postfork chain. The accounts are in the ledger files.
pub fn postfork_config(
    fork_config: &Value,
    hashes: &LedgerHashes,
    genesis_timestamp: &str,
) -> Value {
    let seed = |epoch: &str| {
        fork_config
            .pointer(&format!("/epoch_data/{epoch}/seed"))
            .cloned()
    };
    let mut epoch_data = json!({
        "staking": {
            "seed": seed("staking"),
            "hash": hashes.epoch_data.staking.hash,
            "s3_data_hash": hashes.epoch_data.staking.s3_data_hash,
        }
    });
    if let Some(next) = &hashes.epoch_data.next {
        epoch_data["next"] = json!({
            "seed": seed("next"),
            "hash": next.hash,
            "s3_data_hash": next.s3_data_hash,
        });
    }
    json!({
        "genesis": { "genesis_state_timestamp": genesis_timestamp },
        "proof": { "fork": fork_config.pointer("/proof/fork") },
        "ledger": {
            "add_genesis_winner": false,
            "hash": hashes.ledger.hash,
            "s3_data_hash": hashes.ledger.s3_data_hash,
        },
        "epoch_data": epoch_data,
    })
}

/// The network's shared runtime config for the postfork chain: the prefork
/// one without the ledger, the fork slots and the genesis timestamp, which
/// the postfork `daemon.json` of each node gives.
pub fn shared_postfork_config(prefork: &Value) -> Value {
    let mut config = prefork.clone();
    if let Some(map) = config.as_object_mut() {
        map.remove("ledger");
        map.remove("daemon");
    }
    if let Some(genesis) = config.get_mut("genesis").and_then(Value::as_object_mut) {
        genesis.remove("genesis_state_timestamp");
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fork_config() -> Value {
        json!({
            "genesis": {"genesis_state_timestamp": "2026-10-28T19:32:29.685000Z"},
            "proof": {"fork": {"state_hash": "3NL7", "blockchain_length": 5, "global_slot_since_genesis": 52}},
            "ledger": {"hash": "jwenn", "add_genesis_winner": false, "accounts": []},
            "epoch_data": {"staking": {"seed": "2va9", "accounts": []}, "next": {"seed": "2vby", "accounts": []}}
        })
    }

    fn hashes() -> LedgerHashes {
        serde_json::from_value(json!({
            "ledger": {"s3_data_hash": "4d5d", "hash": "jwenn"},
            "epoch_data": {
                "staking": {"s3_data_hash": "a5ba", "hash": "jxka"},
                "next": {"s3_data_hash": "a5bb", "hash": "jxkb"}
            }
        }))
        .unwrap()
    }

    #[test]
    fn fork_point_is_read_from_proof_fork() {
        assert_eq!(
            ForkPoint::of(&fork_config()).unwrap(),
            ForkPoint {
                state_hash: "3NL7".into(),
                blockchain_length: 5,
                global_slot_since_genesis: 52
            }
        );
        assert!(ForkPoint::of(&json!({}))
            .unwrap_err()
            .contains("no proof.fork"));
    }

    #[test]
    fn postfork_config_is_what_create_runtime_config_makes() {
        assert_eq!(
            postfork_config(&fork_config(), &hashes(), "2026-10-28T19:32:29Z"),
            json!({
                "genesis": {"genesis_state_timestamp": "2026-10-28T19:32:29Z"},
                "proof": {"fork": {"state_hash": "3NL7", "blockchain_length": 5, "global_slot_since_genesis": 52}},
                "ledger": {"add_genesis_winner": false, "hash": "jwenn", "s3_data_hash": "4d5d"},
                "epoch_data": {
                    "staking": {"seed": "2va9", "hash": "jxka", "s3_data_hash": "a5ba"},
                    "next": {"seed": "2vby", "hash": "jxkb", "s3_data_hash": "a5bb"}
                }
            })
        );
    }

    #[test]
    fn shared_config_loses_ledger_slots_and_timestamp() {
        let prefork = json!({
            "genesis": {"k": 10, "genesis_state_timestamp": "x"},
            "proof": {"block_window_duration_ms": 30000},
            "daemon": {"slot_chain_end": 42},
            "ledger": {"accounts": []}
        });
        assert_eq!(
            shared_postfork_config(&prefork),
            json!({"genesis": {"k": 10}, "proof": {"block_window_duration_ms": 30000}})
        );
    }
}
