use serde::{Deserialize, Serialize};

/// Why a load stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum StopReason {
    /// `network load stop` (or `network stop`).
    Stopped,
    /// Its rounds or duration are over.
    Done,
    /// The daemon rejected a payment with `After_slot_tx_end`: the hardfork
    /// transaction window is closed.
    TxWindowClosed,
    /// No sender can pay amount + fee from its liquid balance.
    FundsDrained,
    /// Payments failed `max_failures` times in a row, or the daemon could not
    /// sign for a sender.
    Failed { error: String },
    /// The process is gone without a reason (killed, crashed): see `load.log`.
    Died,
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::Stopped => f.write_str("stopped"),
            StopReason::Done => f.write_str("done"),
            StopReason::TxWindowClosed => f.write_str("tx window closed"),
            StopReason::FundsDrained => f.write_str("funds drained"),
            StopReason::Failed { error } => write!(f, "failed: {error}"),
            StopReason::Died => f.write_str("died"),
        }
    }
}
