use super::PassKind;
use crate::archive_db::ArchiveDbError;
use std::{io, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ReplayerError {
    #[error("--hard-fork-target is for a network after `network hardfork apply`")]
    TargetWithoutFork,
    #[error(
        "the archive has no blocks before the fork genesis slot {0} to take the hard fork \
         target from: pass --hard-fork-target"
    )]
    NoPreforkBlocks(u32),
    #[error(transparent)]
    Archive(#[from] ArchiveDbError),
    #[error("creating {}: {source}", .path.display())]
    WorkDir { path: PathBuf, source: io::Error },
    #[error("the {pass} pass: {source}")]
    Pass { pass: PassKind, source: io::Error },
}
