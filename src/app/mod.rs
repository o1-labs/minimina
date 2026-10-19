//! Command handlers behind the CLI.
//!
//! Handlers return errors instead of exiting; `main` turns an error into the
//! JSON `{"error_message": ...}` object and a non-zero exit code.

mod env;
mod network;
mod node;
mod setup;

use crate::{
    cli::{Cli, Command, ExecutionMode, NetworkCommand, ShutdownTimeout},
    directory_manager::DirectoryManager,
    docker::manager::DockerManager,
    native::manager::{NativeManager, DEFAULT_POSTGRES_URI, DEFAULT_SHUTDOWN_TIMEOUT},
    network_meta::NetworkMeta,
    runner::{Runner, SystemRunner},
};
use anyhow::{bail, Context as _, Result};
use std::{
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

/// Overrides the postgres server used by native archive nodes at `network create`.
const POSTGRES_URI_ENV: &str = "MINIMINA_POSTGRES_URI";

// Images and archive schema of the default network: Mina 4.0.1, devnet profile.
// The daemon must be a generic image: network images ship config_<commit>.json,
// which the daemon merges into every config, so a local network would inherit
// the public network's peer list and fork point. 4.0.1 is the newest release
// with generic images.
const DEFAULT_DAEMON_DOCKER_IMAGE: &str =
    "minaprotocol/mina-daemon:4.0.1-1e9d141-bookworm-devnet-generic";
const DEFAULT_ARCHIVE_DOCKER_IMAGE: &str =
    "minaprotocol/mina-archive:4.0.1-1e9d141-bookworm-devnet";
const IMAGE_COMMIT_HASH: &str = "1e9d141";

/// Everything a command handler needs from its environment.
pub struct Context {
    pub dirs: DirectoryManager,
    pub mode: ExecutionMode,
    bin_path: Option<PathBuf>,
    /// Postgres server URI (no database) for native archive nodes.
    pub postgres_uri: String,
    pub runner: Rc<dyn Runner>,
}

impl Context {
    /// What `network create` records for later commands.
    pub fn meta(&self) -> NetworkMeta {
        match self.mode {
            ExecutionMode::Docker => NetworkMeta {
                mode: self.mode,
                bin_path: None,
                postgres_uri: None,
            },
            ExecutionMode::Native => NetworkMeta {
                mode: self.mode,
                bin_path: self.bin_path.clone(),
                postgres_uri: Some(self.postgres_uri.clone()),
            },
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
            &self.postgres_uri,
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
    let is_create = matches!(cli.command, Command::Network(NetworkCommand::Create(_)));
    let stored = match cli.command.network_id() {
        // `create` replaces whatever was there
        Some(id) if !is_create => NetworkMeta::load(&dirs.network_path(id))?,
        _ => None,
    };

    let mode = match (&stored, cli.mode) {
        (Some(meta), Some(asked)) if asked != meta.mode => bail!(
            "network '{}' was created in {} mode; run without --mode or with --mode {}",
            cli.command.network_id().unwrap_or_default(),
            meta.mode,
            meta.mode
        ),
        (Some(meta), _) => meta.mode,
        // networks created before minimina.json existed default to docker, as before
        (None, asked) => asked.unwrap_or(ExecutionMode::Docker),
    };
    let stored_bin = stored.as_ref().and_then(|m| m.bin_path.clone());
    let bin_path = env::resolve_bin_path(&mode, cli.bin_path.or(stored_bin))?;
    let postgres_uri = stored
        .and_then(|m| m.postgres_uri)
        .or_else(|| std::env::var(POSTGRES_URI_ENV).ok())
        .unwrap_or_else(|| DEFAULT_POSTGRES_URI.to_string());

    // list and info only read ~/.minimina
    let reads_files_only = matches!(
        cli.command,
        Command::Network(NetworkCommand::List | NetworkCommand::Info(_))
    );
    if !reads_files_only {
        env::check_execution_environment(&mode, runner.as_ref())?;
    }

    let ctx = Context {
        dirs,
        mode,
        bin_path,
        postgres_uri,
        runner,
    };

    match cli.command {
        Command::Network(cmd) => network::run(&ctx, cmd),
        Command::Node(cmd) => node::run(&ctx, cmd),
    }
}

fn shutdown_timeout(timeout: &ShutdownTimeout) -> Duration {
    timeout
        .secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT)
}

#[cfg(test)]
mod tests;
