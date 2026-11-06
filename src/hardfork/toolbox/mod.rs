//! `mina-archive-hardfork-toolbox` of the postfork package: the checks and
//! repairs of the archive database across a hardfork.
//!
//! "Fork block" means two blocks in the toolbox (MinaProtocol/mina#19983):
//! the last prefork block in `fork-candidate *`, the postfork genesis block
//! in `validate-fork`. Here the first is the fork block and the second the
//! postfork genesis.

mod archive_block;
mod error;
mod migration;

pub use archive_block::ArchiveBlock;
pub use error::ToolboxError;
pub use migration::Migration;

use crate::{
    cli::Profile,
    native::{self, binary::Binary},
    runner::Runner,
};
use std::{
    io,
    path::{Path, PathBuf},
    process::Output,
};

/// The toolbox of a binary directory, on one archive database.
pub struct Toolbox<'a> {
    runner: &'a dyn Runner,
    program: PathBuf,
    postgres_uri: String,
    env: Vec<(&'static str, String)>,
}

impl<'a> Toolbox<'a> {
    pub fn new(
        runner: &'a dyn Runner,
        bin_path: &Path,
        postgres_uri: &str,
        profile: Profile,
    ) -> Self {
        Toolbox {
            runner,
            program: Binary::ArchiveHardforkToolbox.path(bin_path),
            postgres_uri: postgres_uri.to_string(),
            env: native::mina_env(bin_path, profile),
        }
    }

    /// The last block with commands: the fork block of the daemons' fork config.
    pub fn last_filled_block(&self) -> Result<ArchiveBlock, ToolboxError> {
        const CHECK: &str = "fork-candidate last-filled-block";
        let out = self.run(CHECK, &["fork-candidate", "last-filled-block"])?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        // the block is the last line; log lines may come before it
        stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line.trim()).ok())
            .ok_or_else(|| ToolboxError::NoBlock {
                check: CHECK,
                output: stdout.trim().to_string(),
            })
    }

    /// The fork block is on the best chain of the archive.
    pub fn is_in_best_chain(&self, fork_block: &ArchiveBlock) -> Result<(), ToolboxError> {
        let height = fork_block.height.to_string();
        let slot = fork_block.slot_since_genesis.to_string();
        self.run(
            "fork-candidate is-in-best-chain",
            &[
                "fork-candidate",
                "is-in-best-chain",
                "--fork-state-hash",
                &fork_block.state_hash,
                "--fork-height",
                &height,
                "--fork-slot",
                &slot,
            ],
        )
        .map(drop)
    }

    /// The chain from the fork block to `tip` has `required` blocks after the fork block.
    pub fn confirmations(
        &self,
        fork_block: &ArchiveBlock,
        tip: &str,
        required: u32,
    ) -> Result<(), ToolboxError> {
        let slot = fork_block.slot_since_genesis.to_string();
        let required = required.to_string();
        self.run(
            "fork-candidate confirmations",
            &[
                "fork-candidate",
                "confirmations",
                "--latest-state-hash",
                tip,
                "--fork-slot",
                &slot,
                "--required-confirmations",
                &required,
            ],
        )
        .map(drop)
    }

    /// The schema is the one of `migration`.
    pub fn verify_upgrade(&self, migration: &Migration) -> Result<(), ToolboxError> {
        self.run(
            "verify-upgrade",
            &[
                "verify-upgrade",
                "--migration-version",
                &migration.migration_version,
                "--protocol-version",
                &migration.protocol_version,
            ],
        )
        .map(drop)
    }

    /// The postfork genesis block and its prefork ancestors are in the archive.
    pub fn validate_fork(&self, postfork_genesis: &ArchiveBlock) -> Result<(), ToolboxError> {
        let slot = postfork_genesis.slot_since_genesis.to_string();
        self.run(
            "validate-fork",
            &[
                "validate-fork",
                "--fork-state-hash",
                &postfork_genesis.state_hash,
                "--fork-slot",
                &slot,
            ],
        )
        .map(drop)
    }

    /// Marks the prefork chain up to the fork block canonical and its other
    /// blocks orphaned. It finds the fork from the latest postfork genesis block.
    pub fn convert_chain_to_canonical(&self) -> Result<(), ToolboxError> {
        self.run(
            "convert-chain-to-canonical",
            &["convert-chain-to-canonical"],
        )
        .map(drop)
    }

    fn run(&self, check: &'static str, args: &[&str]) -> Result<Output, ToolboxError> {
        let args: Vec<&str> = args
            .iter()
            .copied()
            .chain(["--postgres-uri", &self.postgres_uri])
            .collect();
        let out = self
            .runner
            .run(
                self.program.as_os_str(),
                &args,
                &native::env_refs(&[], &self.env),
            )
            .map_err(|cause| match cause.kind() {
                io::ErrorKind::NotFound => ToolboxError::Missing(self.program.clone()),
                _ => ToolboxError::Run { check, cause },
            })?;
        match out.status.success() {
            true => Ok(out),
            false => Err(ToolboxError::Failed {
                check,
                detail: failure_detail(&out),
            }),
        }
    }
}

/// The failed checks of a toolbox report (its `❌` lines), else the last line
/// of stderr or stdout.
fn failure_detail(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let failed: Vec<&str> = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .filter(|line| line.starts_with('❌'))
        .map(|line| line.trim_start_matches('❌').trim())
        .collect();
    if !failed.is_empty() {
        return failed.join("; ");
    }
    let last_line = |text: &str| {
        text.lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_string)
    };
    last_line(&stderr)
        .or_else(|| last_line(&stdout))
        .unwrap_or_else(|| "no output".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    const URI: &str = "postgres://postgres:postgres@localhost:5432/minimina_hf";

    fn toolbox(fake: &FakeRunner) -> Toolbox<'_> {
        Toolbox::new(fake, Path::new("/post/bin"), URI, Profile::Devnet)
    }

    fn fork_block() -> ArchiveBlock {
        ArchiveBlock {
            state_hash: "3NLPHX".into(),
            height: 12,
            slot_since_genesis: 23,
        }
    }

    #[test]
    fn last_filled_block_is_the_json_line() {
        let fake = FakeRunner::default();
        fake.reply(
            0,
            "{\"level\":\"Info\"}\n{\"state_hash\":\"3NLPHX\",\"slot_since_genesis\":23,\"height\":12}\n",
            "",
        );
        assert_eq!(toolbox(&fake).last_filled_block().unwrap(), fork_block());
        assert_eq!(
            fake.lines(),
            [format!(
                "/post/bin/mina-archive-hardfork-toolbox fork-candidate last-filled-block \
                 --postgres-uri {URI}"
            )]
        );
        assert_eq!(
            fake.calls.borrow()[0].envs[0],
            ("MINA_PROFILE".to_string(), "devnet".to_string())
        );

        fake.reply(0, "nothing here\n", "");
        let err = toolbox(&fake).last_filled_block().unwrap_err().to_string();
        assert!(err.contains("printed no block: nothing here"), "{err}");
    }

    #[test]
    fn checks_pass_their_blocks() {
        let fake = FakeRunner::default();
        for _ in 0..5 {
            fake.reply(0, "🎉 All checks passed!\n", "");
        }
        let t = toolbox(&fake);
        let postfork_genesis = ArchiveBlock {
            state_hash: "3NLVD6".into(),
            height: 13,
            slot_since_genesis: 46,
        };
        t.is_in_best_chain(&fork_block()).unwrap();
        t.confirmations(&fork_block(), "3NLVYR", 10).unwrap();
        t.verify_upgrade(&Migration {
            protocol_version: "5.0.0".into(),
            migration_version: "0.0.3".into(),
            status: "applied".into(),
        })
        .unwrap();
        t.validate_fork(&postfork_genesis).unwrap();
        t.convert_chain_to_canonical().unwrap();
        let args: Vec<String> = fake
            .lines()
            .iter()
            .map(|l| {
                l.trim_start_matches("/post/bin/mina-archive-hardfork-toolbox ")
                    .trim_end_matches(&format!(" --postgres-uri {URI}"))
                    .to_string()
            })
            .collect();
        assert_eq!(
            args,
            [
                "fork-candidate is-in-best-chain --fork-state-hash 3NLPHX --fork-height 12 --fork-slot 23",
                "fork-candidate confirmations --latest-state-hash 3NLVYR --fork-slot 23 --required-confirmations 10",
                "verify-upgrade --migration-version 0.0.3 --protocol-version 5.0.0",
                "validate-fork --fork-state-hash 3NLVD6 --fork-slot 46",
                "convert-chain-to-canonical",
            ]
        );
    }

    #[test]
    fn a_failed_check_reports_its_failures() {
        let fake = FakeRunner::default();
        fake.reply(
            1,
            "=== DETAILED RESULTS ===\n\
             ❌ [8.F] Fork validation: FAILED - Expected last fork block to be 3NLVD6 at slot 46\n\
             \n💥 Failed checks:\n  - [8.F] Fork validation\n",
            "",
        )
        .reply(2, "", "uncaught exception\nconnection refused\n")
        .reply_err(io::ErrorKind::NotFound);
        let t = toolbox(&fake);
        let err = t.validate_fork(&fork_block()).unwrap_err().to_string();
        assert_eq!(
            err,
            "validate-fork failed: [8.F] Fork validation: FAILED - Expected last fork block to be 3NLVD6 at slot 46"
        );
        let err = t.convert_chain_to_canonical().unwrap_err().to_string();
        assert_eq!(err, "convert-chain-to-canonical failed: connection refused");
        let err = t.is_in_best_chain(&fork_block()).unwrap_err().to_string();
        assert_eq!(
            err,
            "/post/bin/mina-archive-hardfork-toolbox is not installed"
        );
    }
}
