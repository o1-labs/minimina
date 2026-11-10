#[derive(Debug, thiserror::Error)]
pub enum ForkCheckError {
    #[error("network '{0}' has no applied hardfork: run `network hardfork apply` first")]
    NotApplied(String),
    #[error("account {public_key} of the fork ledger has {field} {value}")]
    Account {
        public_key: String,
        field: &'static str,
        value: String,
    },
}
