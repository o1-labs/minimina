use super::LoadSummary;
use serde::Serialize;

/// `network load list` and `network load stop --all`.
#[derive(Debug, Clone, Serialize)]
pub struct LoadList {
    pub network_id: String,
    pub loads: Vec<LoadSummary>,
}

impl std::fmt::Display for LoadList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}
