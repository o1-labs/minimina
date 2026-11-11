#[derive(Debug, thiserror::Error)]
pub enum ArchiveDbError {
    #[error("connecting to the archive database: {0}")]
    Connect(#[source] postgres::Error),
    #[error("{what}: {source}")]
    Query {
        what: &'static str,
        source: postgres::Error,
    },
    #[error("{what}: {column} = {value} is out of range")]
    OutOfRange {
        what: &'static str,
        column: &'static str,
        value: i64,
    },
    #[error("archive account {public_key}: {field} {value}")]
    Account {
        public_key: String,
        field: &'static str,
        value: String,
    },
}
