//! An archive database for tests: set answers, recorded queries.

use super::{
    ArchiveBlock, ArchiveDb, ArchiveDbError, ChainBlock, Connector, IncludedCommand, Migration,
};
use mina_sdk::AccountData;
use std::cell::RefCell;

#[derive(Debug, Default)]
pub struct FakeArchive {
    pub migration: RefCell<Option<Migration>>,
    pub postfork_genesis: RefCell<Option<ArchiveBlock>>,
    pub prefork_transaction_version: RefCell<Option<u32>>,
    pub chain: RefCell<Vec<ChainBlock>>,
    pub genesis_accounts: RefCell<Vec<AccountData>>,
    pub genesis_ledger_accounts: RefCell<Vec<AccountData>>,
    pub pending: RefCell<Vec<ChainBlock>>,
    pub commands: RefCell<Vec<IncludedCommand>>,
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

    fn chain_from_tip(&mut self, slot: u32) -> Result<Vec<ChainBlock>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("chain_from_tip {slot}"));
        Ok(self.0.chain.borrow().clone())
    }

    fn genesis_accounts(
        &mut self,
        state_hash: &str,
        token: &str,
    ) -> Result<Vec<AccountData>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("genesis_accounts {state_hash} {token}"));
        Ok(self.0.genesis_accounts.borrow().clone())
    }

    fn genesis_ledger_accounts(
        &mut self,
        height: u32,
        token: &str,
    ) -> Result<Vec<AccountData>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("genesis_ledger_accounts {height} {token}"));
        Ok(self.0.genesis_ledger_accounts.borrow().clone())
    }

    fn pending_before(&mut self, slot: u32) -> Result<Vec<ChainBlock>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("pending_before {slot}"));
        Ok(self.0.pending.borrow().clone())
    }

    fn commands(&mut self, hashes: &[String]) -> Result<Vec<IncludedCommand>, ArchiveDbError> {
        self.0
            .calls
            .borrow_mut()
            .push(format!("commands {}", hashes.join(",")));
        Ok(self.0.commands.borrow().clone())
    }
}
