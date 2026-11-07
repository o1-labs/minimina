/// Why the vesting schedules cannot be checked.
#[derive(Debug, thiserror::Error)]
pub enum VestingError {
    #[error("timing.{field} '{value}' is not valid")]
    Field { field: &'static str, value: String },
    #[error("account {public_key}: {cause}")]
    Account {
        public_key: String,
        cause: Box<VestingError>,
    },
    #[error(
        "the genesis ledger of network '{0}' has no timed accounts: give accounts a `timing` in \
         the [ledger] file of the spec"
    )]
    NoTimedAccounts(String),
}
