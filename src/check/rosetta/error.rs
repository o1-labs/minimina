use std::{io, path::PathBuf};

/// Why the rosetta check cannot run.
#[derive(Debug, thiserror::Error)]
pub enum RosettaError {
    #[error("network '{0}' has no rosetta")]
    NoRosetta(String),
    #[error("rosetta {path}: {source}")]
    Http {
        path: &'static str,
        source: reqwest::Error,
    },
    #[error("rosetta {path}: HTTP {status}: {body}")]
    Status {
        path: &'static str,
        status: u16,
        body: String,
    },
    #[error("rosetta serves no network (/network/list is empty)")]
    NoNetwork,
    #[error(
        "{0} is not installed: build it as mina CI does \
         (buildkite/scripts/tests/rosetta/install-cli.sh: mesh-cli v0.10.1 with \
         MinaProtocol/rosetta-sdk-go stake-delegation-v1) into \
         ~/.minimina/.tools/rosetta-cli/<version>/rosetta-cli, or give --rosetta-cli"
    )]
    CliMissing(PathBuf),
    #[error("running {program}: {source}")]
    Cli { program: PathBuf, source: io::Error },
    #[error(
        "{0} is missing: the network's mina package has no rosetta-cli config \
         (etc/mina/rosetta/rosetta-cli-config/config.json)"
    )]
    NoTemplate(PathBuf),
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error(
        "rosetta's current block is {index} ({hash}), above the best tip at height {tip}: after a \
         hardfork it takes the highest block of the archive, an orphaned prefork one, until the \
         postfork chain is taller (MinaProtocol/mina#19984), and its /block then gives orphaned \
         blocks, so check:data fails. Run again when the best tip is above height {index}, or \
         add --wait"
    )]
    OrphanedTip { index: u64, hash: String, tip: u64 },
}
