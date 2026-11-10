use super::VestingSchedule;

/// What the fork config (`hardfork/fork_config.json`) has for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkSchedule {
    /// The account is not in the fork ledger.
    Absent,
    /// The account is there without a schedule.
    Untimed,
    Timed(VestingSchedule),
    /// The schedule is there but not valid.
    Invalid,
}

impl std::fmt::Display for ForkSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForkSchedule::Absent => f.write_str("not in the fork ledger"),
            ForkSchedule::Untimed => f.write_str("no schedule in the fork ledger"),
            ForkSchedule::Timed(s) => s.fmt(f),
            ForkSchedule::Invalid => f.write_str("an invalid schedule in the fork ledger"),
        }
    }
}
