use super::{LoadState, SenderStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What the worker reports in `status.json` as it goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadStatus {
    #[serde(flatten)]
    pub state: LoadState,
    pub updated_at: String,
    pub rounds: u64,
    /// Payments the daemon took into its pool.
    pub accepted: u64,
    /// Payments it refused.
    pub rejected: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// By key name.
    pub by_sender: BTreeMap<String, SenderStatus>,
}

impl LoadStatus {
    pub fn new(senders: impl IntoIterator<Item = (String, String)>) -> Self {
        LoadStatus {
            state: LoadState::Starting,
            updated_at: chrono::Local::now().to_rfc3339(),
            rounds: 0,
            accepted: 0,
            rejected: 0,
            last_error: None,
            by_sender: senders
                .into_iter()
                .map(|(name, public_key)| {
                    (
                        name,
                        SenderStatus {
                            public_key,
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        }
    }
}
