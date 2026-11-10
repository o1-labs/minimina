use super::{mina_amount, LoadProcess, LoadSpec, LoadState, LoadStatus, Scenario, StopReason};
use mina_sdk::Currency;
use serde::Serialize;
use std::path::PathBuf;

/// `network load list` / `status`: what a load was asked to do and where it
/// is.
#[derive(Debug, Clone, Serialize)]
pub struct LoadSummary {
    pub id: String,
    pub scenario: Scenario,
    pub node: String,
    pub senders: Vec<String>,
    #[serde(with = "mina_amount")]
    pub amount: Currency,
    #[serde(with = "mina_amount")]
    pub fee: Currency,
    pub across_fork: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(flatten)]
    pub status: Option<LoadStatus>,
    pub dir: PathBuf,
}

impl LoadSummary {
    /// A load whose process is gone without a final state `Died`.
    pub fn new(
        spec: LoadSpec,
        process: Option<LoadProcess>,
        alive: bool,
        status: Option<LoadStatus>,
        dir: PathBuf,
    ) -> Self {
        let status = status.map(|mut s| {
            if !alive && !s.state.is_finished() {
                s.state = LoadState::Finished(StopReason::Died);
            }
            s
        });
        LoadSummary {
            id: spec.id,
            scenario: spec.scenario,
            node: spec.node,
            senders: spec.senders.into_iter().map(|s| s.name).collect(),
            amount: spec.amount,
            fee: spec.fee,
            across_fork: spec.across_fork,
            pid: process.as_ref().map(|p| p.pid),
            started_at: process.map(|p| p.started_at),
            status,
            dir,
        }
    }

    pub fn is_running(&self) -> bool {
        self.status.as_ref().is_some_and(|s| !s.state.is_finished())
    }
}

impl std::fmt::Display for LoadSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}
