use crate::check::Check;
use serde::Serialize;

/// `network check fork`: the postfork chain against what `hardfork prepare`
/// made, and the archive and the loads' payments across the fork.
#[derive(Debug, Clone, Serialize)]
pub struct ForkReport {
    pub network_id: String,
    pub passed: bool,
    pub chain: Vec<Check>,
    pub ledger: Vec<Check>,
    pub archive: Vec<Check>,
    pub payments: Vec<Check>,
    /// What could not be checked, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl ForkReport {
    pub fn new(
        network_id: &str,
        chain: Vec<Check>,
        ledger: Vec<Check>,
        archive: Vec<Check>,
        payments: Vec<Check>,
        notes: Vec<String>,
    ) -> Self {
        let passed = chain
            .iter()
            .chain(&ledger)
            .chain(&archive)
            .chain(&payments)
            .all(|c| c.passed);
        ForkReport {
            network_id: network_id.to_string(),
            passed,
            chain,
            ledger,
            archive,
            payments,
            notes,
        }
    }
}

impl std::fmt::Display for ForkReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}
