//! Checks of a running network, mostly for after a hardfork:
//!
//! - [`vesting`]: the timed accounts of the genesis ledger keep their vesting
//!   schedule through the fork, and the daemon and rosetta lock the amount
//!   the schedule gives at the current slot;
//! - [`rosetta`]: `rosetta-cli check:data` reconciles every balance change of
//!   every block, across the fork, against `/account/balance`;
//! - [`fork`]: the postfork chain, ledger, archive and payments against what
//!   `hardfork prepare` made.

pub mod fork;
pub mod rosetta;
pub mod vesting;

mod outcome;

pub use outcome::Check;
