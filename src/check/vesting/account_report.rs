use super::VestingSchedule;
use crate::check::Check;
use serde::Serialize;

/// The checks of one timed account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountReport {
    pub public_key: String,
    pub schedule: String,
    pub passed: bool,
    pub checks: Vec<Check>,
}

impl AccountReport {
    pub fn new(public_key: &str, schedule: &VestingSchedule, checks: Vec<Check>) -> Self {
        AccountReport {
            public_key: public_key.to_string(),
            schedule: schedule.to_string(),
            passed: checks.iter().all(|c| c.passed),
            checks,
        }
    }
}
