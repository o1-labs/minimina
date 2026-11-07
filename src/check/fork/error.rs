#[derive(Debug, thiserror::Error)]
pub enum ForkCheckError {
    #[error("network '{0}' has no applied hardfork: run `network hardfork apply` first")]
    NotApplied(String),
    #[error("the genesis block of the daemon: {0}")]
    Graphql(serde_json::Error),
    #[error("the genesis block of the daemon has {field} = {value}")]
    Field { field: &'static str, value: String },
    #[error("account {public_key} of the fork ledger has {field} {value}")]
    Account {
        public_key: String,
        field: &'static str,
        value: String,
    },
    #[error("archive account {public_key}: {field} {value}")]
    ArchiveAccount {
        public_key: String,
        field: &'static str,
        value: String,
    },
    #[error("the archive database: {0}")]
    Archive(postgres::Error),
}
