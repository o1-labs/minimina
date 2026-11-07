use super::VestingSchedule;
use mina_sdk::Currency;

/// A timed account as a daemon sees it at its best tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonView {
    /// Global slot since genesis of the best tip.
    pub slot: u64,
    pub schedule: Option<VestingSchedule>,
    pub total: Currency,
    pub locked: Option<Currency>,
}
