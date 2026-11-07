use super::StopReason;
use serde::{Deserialize, Serialize};

/// Where a load is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LoadState {
    /// Waiting for the daemon to answer and report SYNCED.
    Starting,
    Running,
    /// `--across-fork` after `After_slot_tx_end`: waiting for a daemon with a
    /// new genesis.
    WaitingForFork,
    Finished(StopReason),
}

impl LoadState {
    pub fn is_finished(&self) -> bool {
        matches!(self, LoadState::Finished(_))
    }
}
