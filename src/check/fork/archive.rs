use super::{
    AccountState, ArchiveMigration, ChainBlock, ForkCheckError, IncludedCommand, MINA_TOKEN,
};
use crate::check::vesting::VestingSchedule;
use mina_sdk::Currency;
use postgres::{error::SqlState, Client, NoTls, Row};

const LAST_MIGRATION: &str = include_str!("sql/last_migration.sql");
const CHAIN_FROM_TIP: &str = include_str!("sql/chain_from_tip.sql");
const GENESIS_ACCOUNTS: &str = include_str!("sql/genesis_accounts.sql");
const COMMANDS: &str = include_str!("sql/commands.sql");

/// The archive database of a network.
pub struct ArchiveDb {
    client: Client,
}

impl ArchiveDb {
    pub fn connect(uri: &str) -> Result<Self, ForkCheckError> {
        let client = Client::connect(uri, NoTls).map_err(ForkCheckError::Archive)?;
        Ok(ArchiveDb { client })
    }

    /// None for an archive no upgrade script has migrated.
    pub fn last_migration(&mut self) -> Result<Option<ArchiveMigration>, ForkCheckError> {
        match self.client.query_opt(LAST_MIGRATION, &[]) {
            Ok(row) => Ok(row.map(|r| ArchiveMigration {
                protocol_version: r.get(0),
                migration_version: r.get(1),
                status: r.get(2),
            })),
            Err(e) if e.code() == Some(&SqlState::UNDEFINED_TABLE) => Ok(None),
            Err(e) => Err(ForkCheckError::Archive(e)),
        }
    }

    /// The chain from the highest block at or after `slot` down to the first
    /// block, highest first.
    pub fn chain_from_tip(&mut self, slot: i64) -> Result<Vec<ChainBlock>, ForkCheckError> {
        let rows = self
            .client
            .query(CHAIN_FROM_TIP, &[&slot])
            .map_err(ForkCheckError::Archive)?;
        Ok(rows
            .iter()
            .map(|r| ChainBlock {
                id: r.get(0),
                parent_id: r.get(1),
                height: r.get(2),
                state_hash: r.get(3),
                parent_hash: r.get(4),
                chain_status: r.get(5),
                slot_since_genesis: r.get(6),
                slot_since_hard_fork: r.get(7),
            })
            .collect())
    }

    /// The MINA accounts recorded for the block with `state_hash`.
    pub fn genesis_accounts(
        &mut self,
        state_hash: &str,
    ) -> Result<Vec<AccountState>, ForkCheckError> {
        self.client
            .query(GENESIS_ACCOUNTS, &[&state_hash, &MINA_TOKEN])
            .map_err(ForkCheckError::Archive)?
            .iter()
            .map(account)
            .collect()
    }

    /// The archived blocks holding the commands with `hashes`.
    pub fn commands(&mut self, hashes: &[String]) -> Result<Vec<IncludedCommand>, ForkCheckError> {
        let rows = self
            .client
            .query(COMMANDS, &[&hashes])
            .map_err(ForkCheckError::Archive)?;
        Ok(rows
            .iter()
            .map(|r| IncludedCommand {
                hash: r.get(0),
                nonce: r.get(1),
                fee_payer: r.get(2),
                block_state_hash: r.get(3),
                height: r.get(4),
                status: r.get(5),
            })
            .collect())
    }
}

/// An archive account row; amounts are nanomina text, and an untimed
/// account has a timing of zeros.
fn account(row: &Row) -> Result<AccountState, ForkCheckError> {
    let public_key: String = row.get(0);
    let nanomina =
        |field: &'static str, text: Option<String>| -> Result<Currency, ForkCheckError> {
            let text = text.unwrap_or_else(|| "0".to_string());
            text.parse()
                .map(Currency::from_nanomina)
                .map_err(|_| ForkCheckError::ArchiveAccount {
                    public_key: public_key.clone(),
                    field,
                    value: text,
                })
        };
    let slot = |n: Option<i64>| u64::try_from(n.unwrap_or(0)).unwrap_or(0);
    let initial_minimum_balance = nanomina("initial_minimum_balance", row.get(5))?;
    let timing = (initial_minimum_balance.nanomina() > 0)
        .then(|| -> Result<_, ForkCheckError> {
            Ok(VestingSchedule {
                initial_minimum_balance,
                cliff_time: slot(row.get(6)),
                cliff_amount: nanomina("cliff_amount", row.get(7))?,
                vesting_period: slot(row.get(8)),
                vesting_increment: nanomina("vesting_increment", row.get(9))?,
            })
        })
        .transpose()?;
    let nonce: i64 = row.get(2);
    Ok(AccountState {
        balance: nanomina("balance", row.get(1))?,
        nonce: u64::try_from(nonce).unwrap_or(0),
        receipt_chain_hash: row.get(3),
        delegate: row.get(4),
        timing,
        public_key,
    })
}
