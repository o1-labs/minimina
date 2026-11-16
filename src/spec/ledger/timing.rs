use super::Slot;
use serde::{Deserialize, Serialize};

/// The vesting schedule of a time-locked account, as a runtime config writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    pub initial_minimum_balance: String,
    pub cliff_time: Slot,
    pub cliff_amount: String,
    pub vesting_period: Slot,
    pub vesting_increment: String,
}
