//! Command handlers behind the CLI.
//!
//! Handlers return errors instead of exiting; `main` turns an error into the
//! JSON `{"error_message": ...}` object and a non-zero exit code.

mod env;
mod network;
mod node;
mod setup;

use crate::{
    cli::{Cli, Command, ExecutionMode},
    directory_manager::DirectoryManager,
    docker::manager::DockerManager,
    native::manager::NativeManager,
    runner::{Runner, SystemRunner},
};
use anyhow::{bail, Context as _, Result};
use std::{
    path::{Path, PathBuf},
    rc::Rc,
};

// Hardcoded daemon image for default network
// TODO: This image is very old (berkeley-rc1). Update to a more current image in a separate PR.
const DEFAULT_DAEMON_DOCKER_IMAGE: &str =
    "gcr.io/o1labs-192920/mina-daemon:2.0.0berkeley-rc1-1551e2f-bullseye-berkeley";

// Hardcoded archive image for default network
const DEFAULT_ARCHIVE_DOCKER_IMAGE: &str =
    "gcr.io/o1labs-192920/mina-archive:2.0.0berkeley-rc1-1551e2f-bullseye";

const IMAGE_COMMIT_HASH: &str = "1551e2f";

/// Everything a command handler needs from its environment.
pub struct Context {
    pub dirs: DirectoryManager,
    pub mode: ExecutionMode,
    bin_path: Option<PathBuf>,
    pub runner: Rc<dyn Runner>,
}

impl Context {
    pub fn new(
        dirs: DirectoryManager,
        mode: ExecutionMode,
        bin_path: Option<PathBuf>,
        runner: Rc<dyn Runner>,
    ) -> Self {
        Context {
            dirs,
            mode,
            bin_path,
            runner,
        }
    }

    /// Directory holding the `mina` binary; resolved for native mode only.
    pub fn bin_path(&self) -> Result<&Path> {
        self.bin_path
            .as_deref()
            .context("mina binary directory is only resolved in native mode")
    }

    pub fn docker(&self, network_id: &str) -> DockerManager {
        DockerManager::new(&self.dirs.network_path(network_id), self.runner.clone())
    }

    pub fn native(&self, network_id: &str) -> Result<NativeManager> {
        Ok(NativeManager::new(
            &self.dirs.network_path(network_id),
            self.bin_path()?,
        ))
    }

    pub fn ensure_network_exists(&self, network_id: &str) -> Result<()> {
        if self.dirs.network_path_exists(network_id) {
            Ok(())
        } else {
            bail!(
                "Network directory '{}' does not exist, therefore network '{network_id}' does not exist too.",
                self.dirs.network_path(network_id).display()
            )
        }
    }
}

/// Runs `cli` against the host: `~/.minimina` (or `$MINIMINA_HOME`) and real processes.
pub fn run(cli: Cli) -> Result<()> {
    run_with(cli, DirectoryManager::new()?, Rc::new(SystemRunner))
}

pub fn run_with(cli: Cli, dirs: DirectoryManager, runner: Rc<dyn Runner>) -> Result<()> {
    let bin_path = env::resolve_bin_path(&cli.mode, cli.bin_path)?;
    env::check_execution_environment(&cli.mode, runner.as_ref())?;
    let ctx = Context::new(dirs, cli.mode, bin_path, runner);

    match cli.command {
        Command::Network(cmd) => network::run(&ctx, cmd),
        Command::Node(cmd) => node::run(&ctx, cmd),
    }
}

#[cfg(test)]
mod tests;
