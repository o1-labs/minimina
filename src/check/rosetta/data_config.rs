use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::PathBuf;

/// The `data` section of a rosetta-cli config: the settings of
/// `check:data`. The fields minimina sets are typed; the others
/// (reconciliation concurrency, end conditions, ...) are kept as they are.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DataConfig {
    #[serde(default)]
    pub results_output_file: PathBuf,
    /// The first block to sync; none for rosetta's genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}
