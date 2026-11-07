/// The last row of the archive's `migration_history`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMigration {
    pub protocol_version: String,
    pub migration_version: String,
    pub status: String,
}
