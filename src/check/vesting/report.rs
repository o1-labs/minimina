use super::AccountReport;
use serde::Serialize;

/// `network check vesting`: the checks of every timed account.
#[derive(Debug, Clone, Serialize)]
pub struct VestingReport {
    pub network_id: String,
    /// The daemon the accounts were read from.
    pub daemon: String,
    pub passed: bool,
    pub accounts: Vec<AccountReport>,
}

impl VestingReport {
    pub fn new(network_id: &str, daemon: &str, accounts: Vec<AccountReport>) -> Self {
        VestingReport {
            network_id: network_id.to_string(),
            daemon: daemon.to_string(),
            passed: accounts.iter().all(|a| a.passed),
            accounts,
        }
    }
}

impl std::fmt::Display for VestingReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}
