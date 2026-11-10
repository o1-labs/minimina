//! Checks of a running network, mostly for after a hardfork:
//!
//! - [`vesting`]: the timed accounts of the genesis ledger keep their vesting
//!   schedule through the fork, and the daemon and rosetta lock the amount
//!   the schedule gives at the current slot;
//! - [`rosetta`]: `rosetta-cli check:data` reconciles every balance change of
//!   every block, across the fork, against `/account/balance`.

pub mod rosetta;
pub mod vesting;

mod outcome;

pub use outcome::Check;
