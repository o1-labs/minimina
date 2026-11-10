/// What went wrong asking the daemon something, sorted by what the load
/// does about it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DaemonError {
    /// The pool refused the payment with `After_slot_tx_end`.
    #[error("After_slot_tx_end: the hardfork transaction window is closed")]
    TxWindowClosed,
    /// The pool refused the payment with `Insufficient_funds`: the sender's
    /// pending payments already spend its balance.
    #[error("{0}")]
    InsufficientFunds(String),
    /// The daemon has no unlocked key for the sender (it restarted, say).
    #[error("{0}")]
    Locked(String),
    /// No answer.
    #[error("{0}")]
    Unreachable(String),
    #[error("{0}")]
    Rejected(String),
}

impl DaemonError {
    /// Sorts a GraphQL error by its message (`Couldn't send user command:
    /// ["After_slot_tx_end"]`, ...).
    pub fn of_message(message: String) -> Self {
        if message.contains("After_slot_tx_end") {
            DaemonError::TxWindowClosed
        } else if message.contains("Insufficient_funds") {
            DaemonError::InsufficientFunds(message)
        } else if message.contains("Couldn't find an unlocked key") {
            DaemonError::Locked(message)
        } else {
            DaemonError::Rejected(message)
        }
    }
}

impl From<mina_sdk::Error> for DaemonError {
    fn from(e: mina_sdk::Error) -> Self {
        match e {
            mina_sdk::Error::Connection { .. } => DaemonError::Unreachable(e.to_string()),
            e => DaemonError::of_message(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_errors_are_told_apart() {
        let closed =
            r#"GraphQL error in send_payment: Couldn't send user command: ["After_slot_tx_end"]"#;
        assert_eq!(
            DaemonError::of_message(closed.into()),
            DaemonError::TxWindowClosed
        );
        let funds = r#"Couldn't send user command: (Insufficient_funds (Balance 1) 2)"#;
        assert!(matches!(
            DaemonError::of_message(funds.into()),
            DaemonError::InsufficientFunds(_)
        ));
        let locked = "Couldn't find an unlocked key for specified `sender`. Did you unlock the account you're making a transaction from?";
        assert!(matches!(
            DaemonError::of_message(locked.into()),
            DaemonError::Locked(_)
        ));
        assert!(matches!(
            DaemonError::of_message("Invalid_nonce".into()),
            DaemonError::Rejected(_)
        ));
    }
}
