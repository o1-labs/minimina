//! An archive database for tests: set answers, recorded queries.

use super::{ArchiveBlock, ArchiveDb, ArchiveDbError, Connector, Migration};
use std::cell::RefCell;

#[derive(Debug, Default)]
pub struct FakeArchive {
    pub migration: RefCell<Option<Migration>>,
    pub postfork_genesis: RefCell<Option<ArchiveBlock>>,
    pub prefork_transaction_version: RefCell<Option<u32>>,
    /// The queries made, as `<method> <argument>`.
    pub calls: RefCell<Vec<String>>,
}

struct FakeDb<'a>(&'a FakeArchive);

impl Connector for FakeArchive {
    fn connect(&self, uri: &str) -> Result<Box<dyn ArchiveDb + '_>, ArchiveDbError> {
        self.calls.borrow_mut().push(format!("connect {uri}"));
        Ok(Box::new(FakeDb(self)))
    }
}

impl ArchiveDb for FakeDb<'_> {
    fn last_migration(&mut self) -> Result<Option<Migration>, ArchiveDbError> {
        self.0.calls.borrow_mut().push("last_migration".into());
        Ok(self.0.migration.borrow().clone())
    }

    fn postfork_genesis_block(
        &mut self,
        slot: u32,
    ) -> Result<Option<ArchiveBlock>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("postfork_genesis_block {slot}"));
        Ok(self.0.postfork_genesis.borrow().clone())
    }

    fn prefork_transaction_version(&mut self, slot: u32) -> Result<Option<u32>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("prefork_transaction_version {slot}"));
        Ok(*self.0.prefork_transaction_version.borrow())
    }
}
