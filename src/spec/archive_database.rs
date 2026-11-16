//! `database` of the archive node: the name of its database in native mode,
//! instead of `minimina_<network id>`.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// PostgreSQL keeps the first 63 bytes of a name.
const MAX_LEN: usize = 63;

/// Databases every PostgreSQL server has: `network create` drops and creates
/// the archive database, so it must never be one of them.
const RESERVED: [&str; 3] = ["postgres", "template0", "template1"];

/// A database name that minimina can write into SQL unquoted: lowercase
/// letters, digits and `_`, not starting with a digit, at most 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArchiveDatabase(String);

/// Why a name cannot be the archive database, or why `network create` does
/// not use it.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ArchiveDatabaseError {
    #[error("database name '{0}': use lowercase letters, digits and _, not starting with a digit")]
    Characters(String),
    #[error("database name '{0}' is longer than {MAX_LEN} bytes")]
    TooLong(String),
    #[error("database name '{0}' is a database of every PostgreSQL server")]
    Reserved(String),
    #[error(
        "`database` of the archive node is for native mode: a docker network's archive \
         database is always 'archive', in the network's own postgres container"
    )]
    DockerMode,
    #[error(
        "database '{database}' exists and minimina did not create it for network \
         '{network_id}'{}: drop it yourself, or choose another `database`",
        .comment.as_deref().map(|c| format!(" (its comment: '{c}')")).unwrap_or_default()
    )]
    NotThisNetwork {
        database: String,
        network_id: String,
        /// The database's comment, which names the network minimina created
        /// it for; `None` when it has none.
        comment: Option<String>,
    },
}

impl ArchiveDatabase {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The comment `network create` puts on the database it creates for
    /// `network_id`, and checks before it drops one.
    pub fn owner_comment(network_id: &str) -> String {
        format!("minimina network {network_id}")
    }

    /// Whether `network create` may drop the existing database whose comment
    /// is `comment` (empty: none), to create it again for `network_id`.
    pub fn check_owner(&self, network_id: &str, comment: &str) -> Result<(), ArchiveDatabaseError> {
        if comment == Self::owner_comment(network_id) {
            return Ok(());
        }
        Err(ArchiveDatabaseError::NotThisNetwork {
            database: self.0.clone(),
            network_id: network_id.to_string(),
            comment: (!comment.is_empty()).then(|| comment.to_string()),
        })
    }
}

impl FromStr for ArchiveDatabase {
    type Err = ArchiveDatabaseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let valid_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        let starts_with_digit = name.starts_with(|c: char| c.is_ascii_digit());
        if name.is_empty() || starts_with_digit || !name.chars().all(valid_char) {
            return Err(ArchiveDatabaseError::Characters(name.to_string()));
        }
        if name.len() > MAX_LEN {
            return Err(ArchiveDatabaseError::TooLong(name.to_string()));
        }
        if RESERVED.contains(&name) {
            return Err(ArchiveDatabaseError::Reserved(name.to_string()));
        }
        Ok(ArchiveDatabase(name.to_string()))
    }
}

impl TryFrom<String> for ArchiveDatabase {
    type Error = ArchiveDatabaseError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        name.parse()
    }
}

impl From<ArchiveDatabase> for String {
    fn from(database: ArchiveDatabase) -> Self {
        database.0
    }
}

impl fmt::Display for ArchiveDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_postgres_takes_unquoted() {
        assert_eq!(
            "archive".parse::<ArchiveDatabase>().unwrap().as_str(),
            "archive"
        );
        assert!("_lightnet_2".parse::<ArchiveDatabase>().is_ok());
        for bad in ["", "Archive", "2nd", "my-db", "a b", "x;drop"] {
            assert_eq!(
                bad.parse::<ArchiveDatabase>(),
                Err(ArchiveDatabaseError::Characters(bad.into())),
                "{bad}"
            );
        }
        let long = "a".repeat(64);
        assert_eq!(
            long.parse::<ArchiveDatabase>(),
            Err(ArchiveDatabaseError::TooLong(long.clone()))
        );
        assert!("a".repeat(63).parse::<ArchiveDatabase>().is_ok());
        assert_eq!(
            "postgres".parse::<ArchiveDatabase>(),
            Err(ArchiveDatabaseError::Reserved("postgres".into()))
        );
    }

    #[test]
    fn only_the_network_it_was_created_for_may_drop_it() {
        let db: ArchiveDatabase = "archive".parse().unwrap();
        assert_eq!(
            db.check_owner("lightnet", "minimina network lightnet"),
            Ok(())
        );
        let err = db.check_owner("lightnet", "").unwrap_err();
        assert_eq!(
            err.to_string(),
            "database 'archive' exists and minimina did not create it for network 'lightnet': \
             drop it yourself, or choose another `database`"
        );
        let err = db
            .check_owner("lightnet", "minimina network other")
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("(its comment: 'minimina network other')"));
    }
}
