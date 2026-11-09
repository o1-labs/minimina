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

mod check_data_config;
mod check_data_result;
mod check_data_run;
mod check_data_stats;
mod client;
mod data_config;
mod end_condition;
mod error;
mod report;
mod rosetta_cli_config;

pub use check_data_config::CheckDataConfig;
pub use check_data_result::CheckDataResult;
pub use check_data_run::CheckDataRun;
pub use check_data_stats::CheckDataStats;
pub use client::RosettaClient;
pub use data_config::DataConfig;
pub use end_condition::EndCondition;
pub use error::RosettaError;
pub use report::RosettaReport;
pub use rosetta_cli_config::RosettaCliConfig;

use mina_rosetta_sdk::NetworkStatusResponse;

/// The rosetta-cli config of a mina package, under its root.
pub const TEMPLATE: &str = "etc/mina/rosetta/rosetta-cli-config/config.json";

/// After a hardfork, rosetta's current block is an orphaned prefork one
/// while it is above the best tip.
pub fn orphaned_tip(status: &NetworkStatusResponse, best_tip_height: u64) -> Option<RosettaError> {
    let current = &status.current_block_identifier;
    let above = u64::try_from(current.index).is_ok_and(|index| index > best_tip_height);
    above.then(|| RosettaError::OrphanedTip {
        index: current.index,
        hash: current.hash.clone(),
        tip: best_tip_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_rosetta_sdk::BlockIdentifier;

    fn status(index: i64) -> NetworkStatusResponse {
        let block = |index| BlockIdentifier {
            index,
            hash: format!("3N{index}"),
        };
        NetworkStatusResponse {
            current_block_identifier: block(index),
            genesis_block_identifier: block(19),
            ..Default::default()
        }
    }

    #[test]
    fn a_current_block_above_the_best_tip_is_the_orphaned_prefork_tip() {
        assert!(orphaned_tip(&status(25), 25).is_none());
        let err = orphaned_tip(&status(25), 22).unwrap().to_string();
        assert!(err.contains("current block is 25 (3N25), above the best tip at height 22"));
    }
}
