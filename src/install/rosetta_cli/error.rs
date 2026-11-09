use super::{PACKAGE, VERSION};
use crate::install::mina::Source;
use std::{io, path::PathBuf};

/// Why rosetta-cli cannot be installed. The cause of an error is in its
/// message, not its `source`, so `{:#}` does not print it twice.
#[derive(Debug, thiserror::Error)]
pub enum RosettaCliError {
    /// The codename or architecture of this host.
    #[error("{cause:#}: give the path of a rosetta-cli to --rosetta-cli")]
    Host { cause: anyhow::Error },
    #[error("{cause:#}")]
    Index { cause: anyhow::Error },
    #[error(
        "{PACKAGE} {VERSION} is not in the {} packages of {} for {} {}: give the path of a \
         rosetta-cli to --rosetta-cli",
        .from.channel, .from.repository, .from.codename, .from.arch
    )]
    NotPublished { from: Source },
    #[error("downloading {url}: {cause:#}")]
    Download { url: String, cause: anyhow::Error },
    #[error("{url}: SHA-256 {found}, the index has {expected}")]
    ChecksumMismatch {
        url: String,
        expected: String,
        found: String,
    },
    /// dpkg-deb is missing or failed.
    #[error("{cause:#}")]
    Unpack { cause: anyhow::Error },
    #[error("{deb} has no {path}")]
    NoBinary { deb: String, path: &'static str },
    #[error("{path}: {cause}")]
    Io { path: PathBuf, cause: io::Error },
}
