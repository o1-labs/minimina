use super::AccountState;
use crate::check::Check;
use std::collections::{BTreeMap, BTreeSet};

/// At most this many problems are named in the detail.
const SHOWN: usize = 10;

/// Every MINA account of the fork ledger is in the archive's postfork
/// genesis, the same, and the archive has no other.
pub fn ledger_check(fork: &[AccountState], archive: &[AccountState]) -> Check {
    let in_archive: BTreeMap<&str, &AccountState> =
        archive.iter().map(|a| (a.public_key.as_str(), a)).collect();
    let in_fork: BTreeSet<&str> = fork.iter().map(|a| a.public_key.as_str()).collect();
    let mut problems = Vec::new();
    for account in fork {
        match in_archive.get(account.public_key.as_str()) {
            None => problems.push(format!("{}: not in the archive", account.public_key)),
            Some(found) => {
                let differences = account.differences(found);
                if !differences.is_empty() {
                    problems.push(format!(
                        "{}: {}",
                        account.public_key,
                        differences.join(", ")
                    ));
                }
            }
        }
    }
    problems.extend(
        archive
            .iter()
            .filter(|a| !in_fork.contains(a.public_key.as_str()))
            .map(|a| format!("{}: not in the fork ledger", a.public_key)),
    );
    let passed = problems.is_empty();
    let detail = if passed {
        format!("{} accounts", fork.len())
    } else {
        let count = problems.len();
        let mut shown: Vec<String> = problems.into_iter().take(SHOWN).collect();
        if count > SHOWN {
            shown.push(format!("and {} more", count - SHOWN));
        }
        shown.join("; ")
    };
    Check::new(
        "the archive's postfork genesis accounts are the fork ledger",
        passed,
        detail,
    )
}
