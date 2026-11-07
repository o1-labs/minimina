//! `rosetta-cli check:data` on a network's rosetta: every balance change of
//! every block is reconciled against `/account/balance`, until every account
//! seen is reconciled from the tip (the end condition of the config the mina
//! package ships, as mina CI runs it).
//!
//! After a hardfork, rosetta names the postfork genesis as its genesis, and
//! rosetta-cli refuses the prefork genesis (its parent hash is its own), so
//! the sync starts at block 2 to cross the fork. And until the postfork chain
//! is taller than the orphaned prefork tip, rosetta answers with orphaned
//! prefork blocks (MinaProtocol/mina#19984), so the check waits for that.

pub mod api;

mod check_data_config;
mod check_data_result;
mod check_data_run;
mod check_data_stats;
mod client;
mod end_condition;
mod error;
mod report;

pub use check_data_config::CheckDataConfig;
pub use check_data_result::CheckDataResult;
pub use check_data_run::CheckDataRun;
pub use check_data_stats::CheckDataStats;
pub use client::RosettaClient;
pub use end_condition::EndCondition;
pub use error::RosettaError;
pub use report::RosettaReport;

use api::NetworkStatus;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// rosetta-cli under the tools directory: `rosetta-cli/<version>/rosetta-cli`.
pub const TOOL: &str = "rosetta-cli";
/// The rosetta-cli config of a mina package, under its root.
pub const TEMPLATE: &str = "etc/mina/rosetta/rosetta-cli-config/config.json";

/// The rosetta-cli to run: `given`, else the last version under
/// `<tools>/rosetta-cli`, else `rosetta-cli` on the PATH.
pub fn find_cli(tools_root: &Path, given: Option<&Path>) -> PathBuf {
    if let Some(given) = given {
        return given.to_path_buf();
    }
    let mut installed: Vec<PathBuf> = fs::read_dir(tools_root.join(TOOL))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path().join(TOOL))
        .filter(|path| path.is_file())
        .collect();
    installed.sort();
    installed.pop().unwrap_or_else(|| PathBuf::from(TOOL))
}

/// After a hardfork, rosetta's current block is an orphaned prefork one
/// while it is above the best tip.
pub fn orphaned_tip(status: &NetworkStatus, best_tip_height: u64) -> Option<RosettaError> {
    let current = &status.current_block_identifier;
    (current.index > best_tip_height).then(|| RosettaError::OrphanedTip {
        index: current.index,
        hash: current.hash.clone(),
        tip: best_tip_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use api::BlockIdentifier;

    fn status(index: u64) -> NetworkStatus {
        let block = |index| BlockIdentifier {
            index,
            hash: format!("3N{index}"),
        };
        NetworkStatus {
            current_block_identifier: block(index),
            genesis_block_identifier: block(19),
        }
    }

    #[test]
    fn a_current_block_above_the_best_tip_is_the_orphaned_prefork_tip() {
        assert!(orphaned_tip(&status(25), 25).is_none());
        let err = orphaned_tip(&status(25), 22).unwrap().to_string();
        assert!(err.contains("current block is 25 (3N25), above the best tip at height 22"));
    }

    #[test]
    fn the_last_installed_rosetta_cli_is_found() {
        let tools = tempfile::tempdir().unwrap();
        assert_eq!(find_cli(tools.path(), None), PathBuf::from("rosetta-cli"));
        for v in ["v0.10.1-stake-delegation-v1", "v0.10.3"] {
            let dir = tools.path().join(TOOL).join(v);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(TOOL), "").unwrap();
        }
        assert_eq!(
            find_cli(tools.path(), None),
            tools.path().join("rosetta-cli/v0.10.3/rosetta-cli")
        );
        assert_eq!(
            find_cli(tools.path(), Some(Path::new("/opt/rc"))),
            PathBuf::from("/opt/rc")
        );
    }
}
