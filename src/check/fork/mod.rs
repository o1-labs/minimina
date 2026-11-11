//! `network check fork`: after `hardfork apply`, the postfork chain against
//! what `hardfork prepare` made.
//!
//! - chain: every daemon runs the same postfork genesis; it follows the
//!   fork block, at the fork slot, with the ledger prepare made; the chain
//!   grows;
//! - ledger: the archive's postfork genesis accounts are the fork ledger;
//! - archive: the schema is migrated, and one chain runs from the highest
//!   block through the postfork genesis and the fork block down to the first
//!   block, canonical up to the postfork genesis, and no prefork block is
//!   left pending;
//! - payments: the payments of the network's loads (see [`crate::load`])
//!   sent before the fork are in blocks up to the fork block or dropped, the
//!   fork ledger nonces follow them, and those sent after the fork land.

mod archive_checks;
mod chain_checks;
mod error;
mod expected_fork;
mod fork_account;
mod genesis_view;
mod ledger_check;
mod payment_checks;
mod payment_evidence;
mod pending_check;
mod report;

pub use archive_checks::archive_checks;
pub use chain_checks::chain_checks;
pub use error::ForkCheckError;
pub use expected_fork::ExpectedFork;
pub use fork_account::ForkAccount;
pub use genesis_view::GenesisView;
pub use ledger_check::ledger_check;
pub use payment_checks::{payment_checks, PaymentChecks};
pub use payment_evidence::PaymentEvidence;
pub use pending_check::pending_check;
pub use report::ForkReport;

/// The token id of MINA.
pub const MINA_TOKEN: &str = "wSHV2S4qX9jFsLjQo8r1BsMLH2ZRKsZx6EJd1sbozGPieEC4Jf";

#[cfg(test)]
mod tests;
