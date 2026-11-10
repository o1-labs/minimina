use std::{io, path::PathBuf};

/// Why the rosetta check cannot run. The cause of an error is in its
/// message, not its `source`, so `{:#}` does not print it twice.
#[derive(Debug, thiserror::Error)]
pub enum RosettaError {
    #[error("network '{0}' has no rosetta")]
    NoRosetta(String),
    #[error("rosetta {cause}")]
    Api { cause: mina_rosetta_sdk::Error },
    #[error("starting the runtime for rosetta queries: {cause}")]
    Runtime { cause: io::Error },
    #[error(
        "{0} is not found: give the path of a rosetta-cli to --rosetta-cli, or leave it out to \
         download one"
    )]
    CliMissing(PathBuf),
    #[error("running {program}: {cause}")]
    Cli { program: PathBuf, cause: io::Error },
    #[error(
        "{0} is missing: the network's mina package has no rosetta-cli config \
         (etc/mina/rosetta/rosetta-cli-config/config.json)"
    )]
    NoTemplate(PathBuf),
    #[error("{path}: {cause}")]
    Io { path: PathBuf, cause: io::Error },
    #[error("{path}: {cause}")]
    Json {
        path: PathBuf,
        cause: serde_json::Error,
    },
    #[error(
        "rosetta's current block is {index} ({hash}), above the best tip at height {tip}: after a \
         hardfork it takes the highest block of the archive, an orphaned prefork one, until the \
         postfork chain is taller (MinaProtocol/mina#19984), and its /block then gives orphaned \
         blocks, so check:data fails. Run again when the best tip is above height {index}, or \
         add --wait"
    )]
    OrphanedTip { index: i64, hash: String, tip: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cause_is_printed_once() {
        let err = anyhow::Error::from(RosettaError::Io {
            path: "/n/config.json".into(),
            cause: io::Error::other("disk full"),
        });
        assert_eq!(format!("{err:#}"), "/n/config.json: disk full");
        let nested = anyhow::Error::from(crate::check::vesting::VestingError::Account {
            public_key: "B62q".into(),
            cause: Box::new(crate::check::vesting::VestingError::Field {
                field: "cliff_time",
                value: "x".into(),
            }),
        });
        assert_eq!(
            format!("{nested:#}"),
            "account B62q: timing.cliff_time 'x' is not valid"
        );
    }
}
