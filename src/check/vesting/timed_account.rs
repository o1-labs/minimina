use super::{VestingError, VestingSchedule};
use crate::spec::ledger::LedgerAccount;

/// An account of the genesis ledger with a vesting schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedAccount {
    pub public_key: String,
    pub schedule: VestingSchedule,
}

impl TimedAccount {
    /// The timed accounts of a ledger, in its order.
    pub fn of_ledger(accounts: &[LedgerAccount]) -> Result<Vec<Self>, VestingError> {
        accounts
            .iter()
            .filter_map(|a| {
                let timing = a.timing.as_ref()?;
                Some(
                    VestingSchedule::from_timing(timing)
                        .map(|schedule| TimedAccount {
                            public_key: a.pk.to_string(),
                            schedule,
                        })
                        .map_err(|e| VestingError::Account {
                            public_key: a.pk.to_string(),
                            cause: Box::new(e),
                        }),
                )
            })
            .collect()
    }
}
