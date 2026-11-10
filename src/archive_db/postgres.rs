use super::{ArchiveBlock, ArchiveDb, ArchiveDbError, Connector, Migration};
use postgres::{types::ToSql, Client, NoTls, Row};

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
        let Some(row) = self.row(WHAT, include_str!("sql/last_migration.sql"), &[])? else {
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
    }
}
