use super::{CheckDataStats, EndCondition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The results file of `rosetta-cli check:data` (`results_output_file`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CheckDataResult {
    /// Empty on success; else the error with a Go stack trace.
    #[serde(default)]
    pub error: String,
    pub end_condition: Option<EndCondition>,
    /// Each test: passed, failed, or not run (null).
    #[serde(default)]
    pub tests: BTreeMap<String, Option<bool>>,
    pub stats: Option<CheckDataStats>,
}

impl CheckDataResult {
    /// No error, no failed test, no failed reconciliation.
    pub fn passed(&self) -> bool {
        self.error.is_empty()
            && self.tests.values().all(|t| *t != Some(false))
            && self
                .stats
                .as_ref()
                .is_none_or(|s| s.failed_reconciliations == 0)
    }

    /// The error without its stack trace.
    pub fn error_line(&self) -> Option<&str> {
        self.error.lines().next().filter(|l| !l.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sync_error_fails_and_keeps_its_first_line() {
        let failed: CheckDataResult = serde_json::from_str(
            r#"{"error": "unable to sync to 25: cannot remove genesis block\ngithub.com/x\n\tdata.go:712",
                "end_condition": null,
                "tests": {"request_response": true, "block_syncing": false, "reconciliation": null},
                "stats": {"blocks": 0, "orphans": 0, "transactions": 0, "operations": 0, "accounts": 0,
                          "active_reconciliations": 0, "inactive_reconciliations": 0,
                          "exempt_reconciliations": 0, "failed_reconciliations": 0,
                          "skipped_reconciliations": 0, "reconciliation_coverage": 0}}"#,
        )
        .unwrap();
        assert!(!failed.passed());
        assert_eq!(
            failed.error_line(),
            Some("unable to sync to 25: cannot remove genesis block")
        );

        let passed: CheckDataResult = serde_json::from_str(
            r#"{"error": "", "end_condition": {"type": "Reconciliation Coverage", "detail": "Coverage: 100%"},
                "tests": {"request_response": true, "reconciliation": true},
                "stats": {"blocks": 37, "orphans": 0, "transactions": 46, "operations": 62, "accounts": 4,
                          "active_reconciliations": 40, "inactive_reconciliations": 0,
                          "exempt_reconciliations": 0, "failed_reconciliations": 0,
                          "skipped_reconciliations": 0, "reconciliation_coverage": 1}}"#,
        )
        .unwrap();
        assert!(passed.passed());
        assert_eq!(passed.error_line(), None);
        assert_eq!(passed.stats.unwrap().blocks, 37);
    }
}
