use super::{
    ArchiveBlock, ArchiveDb, ArchiveDbError, ChainBlock, Connector, IncludedCommand, Migration,
};
use crate::check::{fork::ForkAccount, vesting::VestingSchedule};
use mina_sdk::{AccountData, Currency};
use postgres::{error::SqlState, types::ToSql, Client, NoTls, Row};

/// Connects with the `postgres` client, without TLS: the archive databases
/// are on the postgres server of the host.
#[derive(Debug, Default, Clone, Copy)]
pub struct Postgres;

impl Connector for Postgres {
    fn connect(&self, uri: &str) -> Result<Box<dyn ArchiveDb + '_>, ArchiveDbError> {
        let client = Client::connect(uri, NoTls).map_err(ArchiveDbError::Connect)?;
        Ok(Box::new(PostgresDb { client }))
    }
}

struct PostgresDb {
    client: Client,
}

impl PostgresDb {
    fn row(
        &mut self,
        what: &'static str,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, ArchiveDbError> {
        self.client
            .query_opt(query, params)
            .map_err(|source| ArchiveDbError::Query { what, source })
    }

    fn rows(
        &mut self,
        what: &'static str,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, ArchiveDbError> {
        self.client
            .query(query, params)
            .map_err(|source| ArchiveDbError::Query { what, source })
    }
}

fn get<'a, T: postgres::types::FromSql<'a>>(
    row: &'a Row,
    what: &'static str,
    column: &str,
) -> Result<T, ArchiveDbError> {
    row.try_get(column)
        .map_err(|source| ArchiveDbError::Query { what, source })
}

fn to_u32(what: &'static str, column: &'static str, value: i64) -> Result<u32, ArchiveDbError> {
    u32::try_from(value).map_err(|_| ArchiveDbError::OutOfRange {
        what,
        column,
        value,
    })
}

impl ArchiveDb for PostgresDb {
    fn last_migration(&mut self) -> Result<Option<Migration>, ArchiveDbError> {
        const WHAT: &str = "reading migration_history";
        let row = match self.row(WHAT, include_str!("sql/last_migration.sql"), &[]) {
            Err(ArchiveDbError::Query { source, .. })
                if source.code() == Some(&SqlState::UNDEFINED_TABLE) =>
            {
                return Ok(None)
            }
            result => result?,
        };
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(Migration {
            protocol_version: get(&row, WHAT, "protocol_version")?,
            migration_version: get(&row, WHAT, "migration_version")?,
            status: get(&row, WHAT, "status")?,
        }))
    }

    fn postfork_genesis_block(
        &mut self,
        fork_genesis_slot: u32,
    ) -> Result<Option<ArchiveBlock>, ArchiveDbError> {
        const WHAT: &str = "reading the postfork genesis block";
        let slot = i64::from(fork_genesis_slot);
        let Some(row) = self.row(
            WHAT,
            include_str!("sql/postfork_genesis_block.sql"),
            &[&slot],
        )?
        else {
            return Ok(None);
        };
        Ok(Some(ArchiveBlock {
            state_hash: get(&row, WHAT, "state_hash")?,
            height: to_u32(WHAT, "height", get(&row, WHAT, "height")?)?,
            slot_since_genesis: to_u32(
                WHAT,
                "global_slot_since_genesis",
                get(&row, WHAT, "global_slot_since_genesis")?,
            )?,
        }))
    }

    fn prefork_transaction_version(
        &mut self,
        fork_genesis_slot: u32,
    ) -> Result<Option<u32>, ArchiveDbError> {
        const WHAT: &str = "reading the prefork protocol version";
        let slot = i64::from(fork_genesis_slot);
        let row = self.row(
            WHAT,
            include_str!("sql/prefork_transaction_version.sql"),
            &[&slot],
        )?;
        // max() gives one row, NULL without blocks
        row.map(|row| get::<Option<i32>>(&row, WHAT, "transaction"))
            .transpose()?
            .flatten()
            .map(|version| to_u32(WHAT, "transaction", version.into()))
            .transpose()
    }

    fn chain_from_tip(
        &mut self,
        fork_genesis_slot: u32,
    ) -> Result<Vec<ChainBlock>, ArchiveDbError> {
        const WHAT: &str = "reading the chain from the archive's tip";
        let slot = i64::from(fork_genesis_slot);
        self.rows(WHAT, include_str!("sql/chain_from_tip.sql"), &[&slot])?
            .iter()
            .map(|row| {
                Ok(ChainBlock {
                    id: get(row, WHAT, "id")?,
                    parent_id: get(row, WHAT, "parent_id")?,
                    height: get(row, WHAT, "height")?,
                    state_hash: get(row, WHAT, "state_hash")?,
                    parent_hash: get(row, WHAT, "parent_hash")?,
                    chain_status: get(row, WHAT, "chain_status")?,
                    slot_since_genesis: get(row, WHAT, "global_slot_since_genesis")?,
                    slot_since_hard_fork: get(row, WHAT, "global_slot_since_hard_fork")?,
                })
            })
            .collect()
    }

    fn genesis_accounts(
        &mut self,
        state_hash: &str,
        token: &str,
    ) -> Result<Vec<AccountData>, ArchiveDbError> {
        const WHAT: &str = "reading the postfork genesis accounts";
        self.rows(
            WHAT,
            include_str!("sql/genesis_accounts.sql"),
            &[&state_hash, &token],
        )?
        .iter()
        .map(|row| account(row, WHAT))
        .collect()
    }

    fn commands(&mut self, hashes: &[String]) -> Result<Vec<IncludedCommand>, ArchiveDbError> {
        const WHAT: &str = "reading the archived user commands";
        self.rows(WHAT, include_str!("sql/commands.sql"), &[&hashes])?
            .iter()
            .map(|row| {
                Ok(IncludedCommand {
                    hash: get(row, WHAT, "hash")?,
                    nonce: get(row, WHAT, "nonce")?,
                    fee_payer: get(row, WHAT, "fee_payer")?,
                    block_state_hash: get(row, WHAT, "block_state_hash")?,
                    height: get(row, WHAT, "height")?,
                    status: get(row, WHAT, "status")?,
                })
            })
            .collect()
    }
}

/// An archive account row; amounts are nanomina text, and an untimed
/// account has a timing of zeros (or none).
fn account(row: &Row, what: &'static str) -> Result<AccountData, ArchiveDbError> {
    let public_key: String = get(row, what, "public_key")?;
    let nanomina = |column: &'static str| -> Result<Currency, ArchiveDbError> {
        let text = get::<Option<String>>(row, what, column)?.unwrap_or_else(|| "0".into());
        text.parse()
            .map(Currency::from_nanomina)
            .map_err(|_| ArchiveDbError::Account {
                public_key: public_key.clone(),
                field: column,
                value: text,
            })
    };
    let slot = |column: &'static str| -> Result<u64, ArchiveDbError> {
        let value = get::<Option<i64>>(row, what, column)?.unwrap_or(0);
        u64::try_from(value).map_err(|_| ArchiveDbError::OutOfRange {
            what,
            column,
            value,
        })
    };
    let initial_minimum_balance = nanomina("initial_minimum_balance")?;
    let timing = if initial_minimum_balance.nanomina() > 0 {
        Some(VestingSchedule {
            initial_minimum_balance,
            cliff_time: slot("cliff_time")?,
            cliff_amount: nanomina("cliff_amount")?,
            vesting_period: slot("vesting_period")?,
            vesting_increment: nanomina("vesting_increment")?,
        })
    } else {
        None
    };
    let nonce: i64 = get(row, what, "nonce")?;
    let nonce = u64::try_from(nonce).map_err(|_| ArchiveDbError::OutOfRange {
        what,
        column: "nonce",
        value: nonce,
    })?;
    let balance = nanomina("balance")?;
    Ok(AccountData {
        receipt_chain_hash: get(row, what, "receipt_chain_hash")?,
        delegate: get(row, what, "delegate")?,
        timing: timing.map(Into::into),
        ..AccountData::with_balance(public_key.clone(), balance, nonce)
    })
}

/// Against a real database: `MINIMINA_TEST_ARCHIVE_URI` names an archive
/// database with the postfork schema (`create_schema.sql`, then `upgrade.sql`).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "needs an archive database; set MINIMINA_TEST_ARCHIVE_URI"]
    fn the_queries_run_on_an_archive_database() {
        let uri = std::env::var("MINIMINA_TEST_ARCHIVE_URI").unwrap();
        let mut db = Postgres.connect(&uri).unwrap();
        let migration = db.last_migration().unwrap().unwrap();
        assert!(migration.is_applied(), "{migration}");
        assert_eq!(db.postfork_genesis_block(46).unwrap(), None);
        assert_eq!(db.prefork_transaction_version(46).unwrap(), None);
        assert!(db.chain_from_tip(46).unwrap().is_empty());
        assert!(db.genesis_accounts("3NLnone", "wnone").unwrap().is_empty());
        assert!(db.commands(&["5Jnone".to_string()]).unwrap().is_empty());
    }
}
