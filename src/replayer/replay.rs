use super::{Fork, PassKind, ReplayPass, POSTFORK_INPUT_JSON};
use std::path::{Path, PathBuf};

/// The replay of an archive database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// The replayer input of the genesis ledger.
    pub input_file: PathBuf,
    pub archive_uri: String,
    /// [`REPLAYER_DIR`] of the network.
    pub work_dir: PathBuf,
    pub fork: Option<Fork>,
}

impl Replay {
    pub fn passes(&self) -> Vec<ReplayPass> {
        let Some(fork) = &self.fork else {
            return vec![self.pass(PassKind::Chain, &self.input_file, &[])];
        };
        let postfork_input = self.work_dir.join(POSTFORK_INPUT_JSON);
        vec![
            self.pass(
                PassKind::Prefork,
                &self.input_file,
                &[
                    ("--stop-slot-config-file", path(&fork.prefork_config)),
                    ("--hard-fork-output-file", path(&postfork_input)),
                    ("--hard-fork-target", fork.target.as_str().to_string()),
                ],
            ),
            self.pass(PassKind::Postfork, &postfork_input, &[]),
        ]
    }

    fn pass(&self, kind: PassKind, input: &Path, extra: &[(&str, String)]) -> ReplayPass {
        let work_dir = path(&self.work_dir);
        let flags = [
            ("--input-file", path(input)),
            ("--archive-uri", self.archive_uri.clone()),
            ("--genesis-ledger-dir", work_dir.clone()),
            ("--checkpoint-output-folder", work_dir),
        ];
        ReplayPass {
            kind,
            args: flags
                .into_iter()
                .chain(extra.iter().cloned())
                .flat_map(|(flag, value)| [flag.to_string(), value])
                .collect(),
        }
    }
}

fn path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replayer::HardForkTarget;

    fn replay(fork: Option<Fork>) -> Replay {
        Replay {
            input_file: "/net/replayer_input.json".into(),
            archive_uri: "postgres://db".into(),
            work_dir: "/net/replayer".into(),
            fork,
        }
    }

    const COMMON: &str = "--archive-uri postgres://db --genesis-ledger-dir /net/replayer \
                          --checkpoint-output-folder /net/replayer";

    #[test]
    fn a_network_without_a_fork_takes_one_pass() {
        let passes = replay(None).passes();
        assert_eq!(passes.len(), 1);
        assert_eq!(passes[0].kind, PassKind::Chain);
        assert_eq!(
            passes[0].args.join(" "),
            format!("--input-file /net/replayer_input.json {COMMON}")
        );
    }

    #[test]
    fn a_fork_takes_a_prefork_and_a_postfork_pass() {
        let passes = replay(Some(Fork {
            prefork_config: "/net/genesis_ledger.prefork.json".into(),
            target: HardForkTarget::Compatible,
        }))
        .passes();
        let lines: Vec<(PassKind, String)> =
            passes.iter().map(|p| (p.kind, p.args.join(" "))).collect();
        assert_eq!(
            lines,
            [
                (
                    PassKind::Prefork,
                    format!(
                        "--input-file /net/replayer_input.json {COMMON} \
                         --stop-slot-config-file /net/genesis_ledger.prefork.json \
                         --hard-fork-output-file /net/replayer/postfork_input.json \
                         --hard-fork-target compatible"
                    )
                ),
                (
                    PassKind::Postfork,
                    format!("--input-file /net/replayer/postfork_input.json {COMMON}")
                ),
            ]
        );
    }
}
