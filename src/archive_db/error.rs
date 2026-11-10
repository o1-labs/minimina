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
}
