use super::{AppliedFork, HardForkTarget, ReplayerError};
use crate::archive_db::{ArchiveDb, ArchiveDbError};
use std::path::PathBuf;

/// The replay of an applied hardfork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fork {
    /// Where the prefork pass stops: [`AppliedFork::prefork_config`].
    pub prefork_config: PathBuf,
    pub target: HardForkTarget,
}

impl Fork {
    /// The fork a replay crosses: none before `hardfork apply`, where a
    /// `given` target is an error. Without `given`, the target follows the
    /// protocol version of the archive's prefork blocks.
    pub fn resolve<'a>(
        applied: Option<AppliedFork>,
        given: Option<HardForkTarget>,
        archive: impl FnOnce() -> Result<Box<dyn ArchiveDb + 'a>, ArchiveDbError>,
    ) -> Result<Option<Self>, ReplayerError> {
        let Some(applied) = applied else {
            return match given {
                Some(_) => Err(ReplayerError::TargetWithoutFork),
                None => Ok(None),
            };
        };
        let target = match given {
            Some(target) => target,
            None => archive()?
                .prefork_transaction_version(applied.fork_genesis_slot)?
                .map(HardForkTarget::for_prefork)
                .ok_or(ReplayerError::NoPreforkBlocks(applied.fork_genesis_slot))?,
        };
        Ok(Some(Fork {
            prefork_config: applied.prefork_config,
            target,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_db::{fake::FakeArchive, Connector};

    fn applied() -> Option<AppliedFork> {
        Some(AppliedFork {
            prefork_config: "/net/genesis_ledger.prefork.json".into(),
            fork_genesis_slot: 46,
        })
    }

    #[test]
    fn the_target_comes_from_the_archive_unless_given() {
        let archive = FakeArchive::default();
        *archive.prefork_transaction_version.borrow_mut() = Some(4);
        let fork = Fork::resolve(applied(), None, || archive.connect("db")).unwrap();
        assert_eq!(fork.unwrap().target, HardForkTarget::Compatible);
        assert_eq!(
            *archive.calls.borrow(),
            ["connect db", "prefork_transaction_version 46"]
        );

        let archive = FakeArchive::default();
        let fork = Fork::resolve(applied(), Some(HardForkTarget::Mesa), || {
            archive.connect("db")
        })
        .unwrap();
        assert_eq!(fork.unwrap().target, HardForkTarget::Mesa);
        assert!(archive.calls.borrow().is_empty());

        let err = Fork::resolve(applied(), None, || archive.connect("db")).unwrap_err();
        assert!(matches!(err, ReplayerError::NoPreforkBlocks(46)), "{err}");
    }

    #[test]
    fn no_fork_takes_no_target() {
        let archive = FakeArchive::default();
        let connect = || archive.connect("db");
        assert_eq!(Fork::resolve(None, None, connect).unwrap(), None);
        let err = Fork::resolve(None, Some(HardForkTarget::Compatible), connect).unwrap_err();
        assert!(matches!(err, ReplayerError::TargetWithoutFork), "{err}");
        assert!(archive.calls.borrow().is_empty());
    }
}
