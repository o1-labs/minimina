use super::{PassLog, Replay, ReplayerError};
use crate::{
    cli::Profile,
    native::{self, binary::Binary},
    runner::{check, Runner},
};
use log::info;
use std::path::{Path, PathBuf};

/// `mina-replayer` of a binary directory.
pub struct Replayer<'a> {
    runner: &'a dyn Runner,
    program: PathBuf,
    env: Vec<(&'static str, String)>,
}

impl<'a> Replayer<'a> {
    pub fn new(runner: &'a dyn Runner, bin_path: &Path, profile: Profile) -> Self {
        Replayer {
            runner,
            program: Binary::Replayer.path(bin_path),
            env: native::mina_env(bin_path, profile),
        }
    }

    /// Runs the passes of `replay` in order; the first that fails stops it.
    pub fn run(&self, replay: &Replay) -> Result<Vec<PassLog>, ReplayerError> {
        std::fs::create_dir_all(&replay.work_dir).map_err(|source| ReplayerError::WorkDir {
            path: replay.work_dir.clone(),
            source,
        })?;
        replay
            .passes()
            .into_iter()
            .map(|pass| {
                info!("Running the {} pass of {}", pass.kind, Binary::Replayer);
                let args: Vec<&str> = pass.args.iter().map(String::as_str).collect();
                let output = self
                    .runner
                    .run(
                        self.program.as_os_str(),
                        &args,
                        &native::env_refs(&[], &self.env),
                    )
                    .and_then(|output| check(output, &Binary::Replayer.to_string()))
                    .map_err(|source| ReplayerError::Pass {
                        pass: pass.kind,
                        source,
                    })?;
                Ok(PassLog {
                    pass: pass.kind,
                    logs: String::from_utf8_lossy(&output.stdout).into(),
                })
            })
            .collect()
    }
}
