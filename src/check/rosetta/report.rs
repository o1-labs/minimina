use super::{CheckDataResult, CheckDataStats, EndCondition};
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf};

/// `network check rosetta`: the result of `rosetta-cli check:data`.
#[derive(Debug, Clone, Serialize)]
pub struct RosettaReport {
    pub network_id: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The first block synced; none for rosetta's genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_condition: Option<EndCondition>,
    pub tests: BTreeMap<String, Option<bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<CheckDataStats>,
    /// The rosetta-cli config, data and results (`<network>/rosetta-cli`).
    pub dir: PathBuf,
}

impl RosettaReport {
    pub fn new(
        network_id: &str,
        result: CheckDataResult,
        start_index: Option<u64>,
        dir: PathBuf,
    ) -> Self {
        RosettaReport {
            network_id: network_id.to_string(),
            passed: result.passed(),
            error: result.error_line().map(str::to_string),
            start_index,
            end_condition: result.end_condition,
            tests: result.tests,
            stats: result.stats,
            dir,
        }
    }
}

impl std::fmt::Display for RosettaReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}
