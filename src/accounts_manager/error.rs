use super::ACCOUNTS_KEPT;
use std::{io, path::PathBuf};

/// Why the accounts manager cannot be set up. The cause of an error is in its
/// message, not its `source`, so `{:#}` does not print it twice.
#[derive(Debug, thiserror::Error)]
pub enum AccountsManagerError {
    #[error(
        "the accounts manager needs more than {ACCOUNTS_KEPT} accounts with a private key, \
         as it keeps {ACCOUNTS_KEPT} of them unused; the network has {found}: give \
         accounts with their private key (`sk`) in [ledger] file, or test accounts \
         with `accounts`"
    )]
    TooFewAccounts { found: usize },
    #[error(
        "the accounts manager runs in native mode only: it asks its daemon's GraphQL API \
         on localhost"
    )]
    DockerMode,
    #[error("'{}' does not exist", .0.display())]
    NoOwnBuild(PathBuf),
    #[error("{cause:#}")]
    Host { cause: anyhow::Error },
    #[error("release v{version} of the accounts manager: {cause:#}")]
    Release {
        version: String,
        cause: anyhow::Error,
    },
    #[error("release v{version} of the accounts manager has no {asset}")]
    NoAsset { version: String, asset: String },
    #[error("downloading {url}: {cause:#}")]
    Download { url: String, cause: anyhow::Error },
    #[error("{url}: SHA-256 {found}, the release has {expected}")]
    ChecksumMismatch {
        url: String,
        expected: String,
        found: String,
    },
    #[error("the private key of '{account}': {cause:#}")]
    PrivateKey {
        account: String,
        cause: anyhow::Error,
    },
    #[error("{}: {cause}", .path.display())]
    Io { path: PathBuf, cause: io::Error },
}

impl AccountsManagerError {
    pub fn io(path: &std::path::Path) -> impl FnOnce(io::Error) -> Self + '_ {
        move |cause| AccountsManagerError::Io {
            path: path.to_path_buf(),
            cause,
        }
    }
}
