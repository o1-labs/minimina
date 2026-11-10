use super::VestingError;
use crate::spec::ledger::Timing;
use mina_sdk::{AccountTiming, Currency};

/// The vesting schedule of a timed account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VestingSchedule {
    pub initial_minimum_balance: Currency,
    pub cliff_time: u64,
    pub cliff_amount: Currency,
    pub vesting_period: u64,
    pub vesting_increment: Currency,
}

impl VestingSchedule {
    /// The schedule of a runtime config account: amounts in MINA, slots as
    /// numbers, all as strings.
    pub fn from_timing(timing: &Timing) -> Result<Self, VestingError> {
        let amount = |field: &'static str, value: &str| {
            Currency::from_mina(value).map_err(|_| VestingError::Field {
                field,
                value: value.to_string(),
            })
        };
        let slot = |field: &'static str, value: &str| {
            value.parse::<u64>().map_err(|_| VestingError::Field {
                field,
                value: value.to_string(),
            })
        };
        Ok(VestingSchedule {
            initial_minimum_balance: amount(
                "initial_minimum_balance",
                &timing.initial_minimum_balance,
            )?,
            cliff_time: slot("cliff_time", &timing.cliff_time)?,
            cliff_amount: amount("cliff_amount", &timing.cliff_amount)?,
            vesting_period: slot("vesting_period", &timing.vesting_period)?,
            vesting_increment: amount("vesting_increment", &timing.vesting_increment)?,
        })
    }

    /// The schedule a daemon reports; none when a field is missing.
    pub fn from_daemon(timing: &AccountTiming) -> Option<Self> {
        Some(VestingSchedule {
            initial_minimum_balance: timing.initial_minimum_balance?,
            cliff_time: timing.cliff_time?,
            cliff_amount: timing.cliff_amount?,
            vesting_period: timing.vesting_period?,
            vesting_increment: timing.vesting_increment?,
        })
    }

    /// The balance the account cannot spend at `slot` (mina's
    /// `Account.min_balance_at_slot`): the initial minimum balance before the
    /// cliff; from the cliff on, less the cliff amount and one increment per
    /// whole vesting period since the cliff, never below 0. With a vesting
    /// period of 0, all of it vests at the cliff.
    pub fn locked_at(&self, slot: u64) -> Currency {
        if slot < self.cliff_time {
            return self.initial_minimum_balance;
        }
        let Some(periods) = (slot - self.cliff_time).checked_div(self.vesting_period) else {
            return Currency::from_nanomina(0);
        };
        let vested = self
            .vesting_increment
            .nanomina()
            .saturating_mul(periods)
            .saturating_add(self.cliff_amount.nanomina());
        Currency::from_nanomina(
            self.initial_minimum_balance
                .nanomina()
                .saturating_sub(vested),
        )
    }
}

impl From<VestingSchedule> for AccountTiming {
    fn from(schedule: VestingSchedule) -> Self {
        AccountTiming {
            initial_minimum_balance: Some(schedule.initial_minimum_balance),
            cliff_time: Some(schedule.cliff_time),
            cliff_amount: Some(schedule.cliff_amount),
            vesting_period: Some(schedule.vesting_period),
            vesting_increment: Some(schedule.vesting_increment),
        }
    }
}

impl std::fmt::Display for VestingSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} MINA locked, cliff at slot {} unlocks {}, then {} every {} slots",
            self.initial_minimum_balance.mina(),
            self.cliff_time,
            self.cliff_amount.mina(),
            self.vesting_increment.mina(),
            self.vesting_period
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timing(imb: &str, cliff: &str, amount: &str, period: &str, inc: &str) -> Timing {
        Timing {
            initial_minimum_balance: imb.into(),
            cliff_time: cliff.into(),
            cliff_amount: amount.into(),
            vesting_period: period.into(),
            vesting_increment: inc.into(),
        }
    }

    fn mina(s: &str) -> Currency {
        Currency::from_mina(s).unwrap()
    }

    #[test]
    fn the_locked_balance_follows_the_schedule() {
        // the hardfork rehearsal's "cliff before the fork" account
        let s = VestingSchedule::from_timing(&timing("1000", "20", "100", "5", "50")).unwrap();
        assert_eq!(s.locked_at(19), mina("1000"));
        assert_eq!(s.locked_at(20), mina("900"));
        assert_eq!(s.locked_at(24), mina("900"));
        assert_eq!(s.locked_at(68), mina("450"));
        assert_eq!(s.locked_at(84), mina("300"));
        assert_eq!(s.locked_at(200), mina("0"));
        // all vested at the cliff
        let s = VestingSchedule::from_timing(&timing("100", "10", "100", "1", "1")).unwrap();
        assert_eq!(s.locked_at(10), mina("0"));
        // no vesting period: all of it at the cliff
        let s = VestingSchedule::from_timing(&timing("10", "5", "4", "0", "1")).unwrap();
        assert_eq!(s.locked_at(4), mina("10"));
        assert_eq!(s.locked_at(5), mina("0"));
    }

    #[test]
    fn a_bad_field_is_named() {
        let err = VestingSchedule::from_timing(&timing("x", "20", "100", "5", "50")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "timing.initial_minimum_balance 'x' is not valid"
        );
        let err = VestingSchedule::from_timing(&timing("1", "soon", "1", "5", "1")).unwrap_err();
        assert_eq!(err.to_string(), "timing.cliff_time 'soon' is not valid");
    }
}
