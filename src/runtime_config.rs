//! Typed view of the parts of a genesis runtime config (`genesis_ledger.json`)
//! that minimina reads. Other keys are kept as they are in the file.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub genesis: Genesis,
    #[serde(default)]
    pub proof: Proof,
    #[serde(default)]
    pub daemon: Daemon,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct Genesis {
    /// Security parameter: blocks become final k blocks below the tip.
    pub k: Option<u32>,
    pub genesis_state_timestamp: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct Proof {
    /// Length of a slot.
    pub block_window_duration_ms: Option<u64>,
}

/// The `daemon` keys that place a hardfork.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Daemon {
    /// From this slot, blocks have no transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_tx_end: Option<u32>,
    /// From this slot, no blocks: the last slot of the prefork chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_chain_end: Option<u32>,
    /// The postfork chain begins at `slot_chain_end` + this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hard_fork_genesis_slot_delta: Option<u32>,
}

impl RuntimeConfig {
    pub fn from_json(config: &serde_json::Value) -> serde_json::Result<Self> {
        Self::deserialize(config)
    }
}

impl Daemon {
    /// The keys that are set, as they are in the runtime config.
    pub fn keys(&self) -> Vec<String> {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::Object(map)) => map.into_iter().map(|(k, _)| k).collect(),
            _ => Vec::new(),
        }
    }

    /// The `daemon` object to merge into a runtime config.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "daemon": self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_known_keys_and_ignores_the_others() {
        let config = RuntimeConfig::from_json(&serde_json::json!({
            "genesis": {"k": 10, "slots_per_epoch": 48},
            "proof": {"block_window_duration_ms": 30000},
            "daemon": {"slot_chain_end": 42, "peer_list_url": "x"},
            "ledger": {"accounts": []}
        }))
        .unwrap();
        assert_eq!(config.genesis.k, Some(10));
        assert_eq!(config.proof.block_window_duration_ms, Some(30000));
        assert_eq!(config.daemon.keys(), ["slot_chain_end"]);
        assert_eq!(
            config.daemon.to_json(),
            serde_json::json!({"daemon": {"slot_chain_end": 42}})
        );
        assert_eq!(
            RuntimeConfig::from_json(&serde_json::json!({})).unwrap(),
            RuntimeConfig::default()
        );
    }
}
