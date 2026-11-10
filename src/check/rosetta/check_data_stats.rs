use serde::{Deserialize, Serialize};

/// The counts of a `rosetta-cli check:data` run.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CheckDataStats {
    pub blocks: u64,
    pub orphans: u64,
    pub transactions: u64,
    pub operations: u64,
    pub accounts: u64,
    pub active_reconciliations: u64,
    pub inactive_reconciliations: u64,
    pub exempt_reconciliations: u64,
    pub failed_reconciliations: u64,
    pub skipped_reconciliations: u64,
    /// The share of seen accounts reconciled, from 0 to 1.
    pub reconciliation_coverage: f64,
}
