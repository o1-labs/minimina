use super::{ChainView, DaemonError, Sender};
use mina_sdk::{Currency, Payment, SubmittedCommand};

/// The daemon a load sends through.
pub trait Gateway {
    fn chain(&self) -> Result<ChainView, DaemonError>;
    /// Imports the sender's key into the daemon's wallets and unlocks it, so
    /// that the daemon signs its payments.
    fn unlock(&self, sender: &Sender) -> Result<(), DaemonError>;
    /// The liquid balance (the total, for an untimed account) at the best tip.
    fn liquid(&self, public_key: &str) -> Result<Currency, DaemonError>;
    fn send(&self, payment: Payment) -> Result<SubmittedCommand, DaemonError>;
}
