use crate::native::process_tracker::proc_stat;
use serde::{Deserialize, Serialize};

/// The background process of a load (`process.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadProcess {
    pub pid: u32,
    /// Kernel start time of `pid`, to tell it from a later process with the
    /// same pid.
    pub start_time: Option<u64>,
    pub started_at: String,
}

impl LoadProcess {
    pub fn of(pid: u32) -> Self {
        LoadProcess {
            pid,
            start_time: proc_stat(pid).map(|s| s.start_time),
            started_at: chrono::Local::now().to_rfc3339(),
        }
    }

    pub fn is_alive(&self) -> bool {
        proc_stat(self.pid)
            .is_some_and(|s| !s.zombie && self.start_time.is_none_or(|t| t == s.start_time))
    }
}
