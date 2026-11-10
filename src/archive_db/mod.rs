//! The archive database, through a postgres client. The queries are in
//! `sql/`, with bound parameters; the rows come back as models.
//!
//! Applying a schema script (`upgrade.sql`) stays with `psql`: the scripts
//! use psql meta-commands (`\set ON_ERROR_STOP on`).

mod archive_block;
mod chain_block;
mod error;
mod included_command;
mod migration;
mod postgres;

#[cfg(test)]
pub mod fake;

pub use self::postgres::Postgres;
pub use archive_block::ArchiveBlock;
pub use chain_block::ChainBlock;
pub use error::ArchiveDbError;
pub use included_command::IncludedCommand;
pub use migration::Migration;

/// The queries minimina makes to an archive database.
pub trait ArchiveDb {
    /// The last row of `migration_history`: the last schema migration. None
    /// also for an archive no upgrade script has migrated (no such table).
    fn last_migration(&mut self) -> Result<Option<Migration>, ArchiveDbError>;

    /// The postfork genesis block: at `fork_genesis_slot` since genesis and
    /// slot 0 since the hardfork.
    fn postfork_genesis_block(
        &mut self,
        fork_genesis_slot: u32,
    ) -> Result<Option<ArchiveBlock>, ArchiveDbError>;

    /// The highest transaction protocol version of the blocks before
    /// `fork_genesis_slot`; `None` without such blocks.
    fn prefork_transaction_version(
        &mut self,
        fork_genesis_slot: u32,
    ) -> Result<Option<u32>, ArchiveDbError>;

    /// The chain from the highest block at or after `fork_genesis_slot` down
    /// to the first block, following `parent_id`, highest first.
    fn chain_from_tip(&mut self, fork_genesis_slot: u32)
        -> Result<Vec<ChainBlock>, ArchiveDbError>;

    /// The accounts of `token` the archive recorded for the block with
    /// `state_hash`.
    fn genesis_accounts(
        &mut self,
        state_hash: &str,
        token: &str,
    ) -> Result<Vec<mina_sdk::AccountData>, ArchiveDbError>;

    /// The archived blocks holding the user commands with `hashes`.
    fn commands(&mut self, hashes: &[String]) -> Result<Vec<IncludedCommand>, ArchiveDbError>;
}

/// Opens an archive database; tests give a fake.
pub trait Connector {
    fn connect(&self, uri: &str) -> Result<Box<dyn ArchiveDb + '_>, ArchiveDbError>;
}
