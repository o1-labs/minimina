use crate::cli::Profile;
use std::{io, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error(
        "the hardfork dispatcher runs devnet or mainnet daemons, not {profile}: it names the \
         daemon's fork directory after the profile"
    )]
    Profile { profile: Profile },
    #[error("{}: {cause}", .path.display())]
    Io { path: PathBuf, cause: io::Error },
}
