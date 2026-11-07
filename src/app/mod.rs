//! Command handlers behind the CLI.
//!
//! Handlers return errors instead of exiting; `main` turns an error into the
//! JSON `{"error_message": ...}` object and a non-zero exit code.

mod env;
mod hardfork;
mod inputs;
mod mina;
mod network;
mod node;
mod setup;
mod spec;

use crate::{
    archive_db::{Connector, Postgres},
    cli::{
        Cli, Command, ExecutionMode, HardforkCommand, NetworkCommand, NodeCommand, Profile,
        ShutdownTimeout,
    },
    daemon_args::DaemonFeatures,
    directory_manager::DirectoryManager,
    docker::manager::DockerManager,
    genesis_ledger::GENESIS_LEDGER_JSON,
    install,
    native::manager::{NativeManager, DEFAULT_POSTGRES_URI, DEFAULT_SHUTDOWN_TIMEOUT},
    network_meta::{HardforkState, NetworkMeta},
    runner::{Runner, SystemRunner},
    service::typed::{self, Mode, Service},
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
const DEFAULT_ROSETTA_DOCKER_IMAGE: &str =
    "minaprotocol/mina-rosetta:4.0.1-1e9d141-bookworm-devnet";
const IMAGE_COMMIT_HASH: &str = "1e9d141";

/// Everything a command handler needs from its environment.
pub struct Context {
    pub dirs: DirectoryManager,
    pub mode: ExecutionMode,
    bin_path: Option<PathBuf>,
    /// The installed mina version of `bin_path`, if it is one.
    pub mina_version: Option<String>,
    /// Postgres server URI (no database) for native archive nodes.
    pub postgres_uri: String,
    /// Build profile exported as `MINA_PROFILE` to every mina process.
    pub profile: Profile,
    /// Version-dependent daemon flags recorded at create (probed again by create).
    pub features: DaemonFeatures,
    /// The runtime config native `mina-archive` starts with; see [`archive_config`].
    pub archive_config: Option<PathBuf>,
    pub runner: Rc<dyn Runner>,
    /// Opens archive databases (native mode).
    pub archive_db: Rc<dyn Connector>,
}

impl Context {
    /// What `network create` records for later commands.
    pub fn meta(&self) -> NetworkMeta {
        match self.mode {
            ExecutionMode::Docker => NetworkMeta {
                mode: self.mode,
                bin_path: None,
                mina_version: None,
                postgres_uri: None,
                profile: self.profile,
                features: self.features,
                genesis_pending: false,
                hardfork: None,
            },
            ExecutionMode::Native => NetworkMeta {
                mode: self.mode,
                bin_path: self.bin_path.clone(),
                mina_version: self.mina_version.clone(),
                postgres_uri: Some(self.postgres_uri.clone()),
                profile: self.profile,
                features: self.features,
                genesis_pending: false,
                hardfork: None,
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
        DockerManager::new(
            &self.dirs.network_path(network_id),
            self.profile,
            self.runner.clone(),
        )
    }

    pub fn native(&self, network_id: &str) -> Result<NativeManager> {
        Ok(NativeManager::new(
            &self.dirs.network_path(network_id),
            self.bin_path()?,
            &self.postgres_uri,
            self.profile,
        )
        .with_features(self.features)
        .with_archive_config(self.archive_config.clone()))
    }

    /// The services of a network from its `services.json`, checked for mode `M`.
    pub fn services<M: Mode>(&self, network_id: &str) -> Result<Vec<Service<M>>> {
        let path = self.dirs.services_file_path(network_id);
        let configs = self
            .dirs
            .get_services_info(network_id)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        typed::check(&configs).with_context(|| format!("{} is not valid", path.display()))
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
    let dirs = DirectoryManager::new()?;
    match cli.command {
        Command::Mina(cmd) => mina::run(&dirs, &SystemRunner, &install::mina::Http, cmd),
        Command::Spec(cmd) => spec::run(cmd),
        _ => run_with(cli, dirs, Rc::new(SystemRunner), Rc::new(Postgres)),
    }
}

pub fn run_with(
    cli: Cli,
    dirs: DirectoryManager,
    runner: Rc<dyn Runner>,
    archive_db: Rc<dyn Connector>,
) -> Result<()> {
    // `create` takes the profile from --profile, else from the spec
    let created_profile = match &cli.command {
        Command::Network(NetworkCommand::Create(args)) => Some(match args.profile {
            Some(profile) => Some(profile),
            None => inputs::create_spec(args)?.profile,
        }),
        _ => None,
    };
    let is_create = created_profile.is_some();
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
        // an installed version runs natively
        (None, None) if cli.mina_version.is_some() => ExecutionMode::Native,
        // networks created before minimina.json existed default to docker, as before
        (None, asked) => asked.unwrap_or(ExecutionMode::Docker),
    };
    let asked_mina = match (&cli.mina_version, mode) {
        (None, _) => None,
        (Some(_), ExecutionMode::Docker) => bail!("--mina-version is only valid in native mode"),
        (Some(version), ExecutionMode::Native) => {
            Some(install::mina::resolve(&dirs.tools_root(), version)?)
        }
    };
    // a binary directory given now replaces the recorded one, and its version
    let mina_version = match (&asked_mina, &cli.bin_path) {
        (Some(installed), _) => Some(installed.version.clone()),
        (None, Some(_)) => None,
        (None, None) => stored.as_ref().and_then(|m| m.mina_version.clone()),
    };
    let stored_bin = stored.as_ref().and_then(|m| m.bin_path.clone());
    let asked_bin = cli
        .bin_path
        .or(asked_mina.as_ref().map(install::mina::Installed::bin_path));
    let bin_path = env::resolve_bin_path(&mode, asked_bin.or(stored_bin))?;
    let postfork_bin = stored
        .as_ref()
        .and_then(|m| m.hardfork.as_ref())
        .map(|h| h.postfork_bin_path.clone());
    let features = stored.as_ref().map(|m| m.features).unwrap_or_default();
    let archive_config = cli
        .command
        .network_id()
        .and_then(|id| archive_config(stored.as_ref(), &dirs.network_path(id)));
    let profile = created_profile
        .flatten()
        .or(stored.as_ref().map(|m| m.profile))
        .unwrap_or_default();
    let postgres_uri = stored
        .and_then(|m| m.postgres_uri)
        .or_else(|| std::env::var(POSTGRES_URI_ENV).ok())
        .unwrap_or_else(|| DEFAULT_POSTGRES_URI.to_string());

    // list, info and hardfork status only read ~/.minimina
    let reads_files_only = matches!(
        cli.command,
        Command::Network(
            NetworkCommand::List
                | NetworkCommand::Info(_)
                | NetworkCommand::Hardfork(HardforkCommand::Status(_))
        )
    );
    if !reads_files_only {
        env::check_execution_environment(&mode, runner.as_ref())?;
    }

    let ctx = Context {
        dirs,
        mode,
        bin_path,
        mina_version,
        postgres_uri,
        profile,
        features,
        archive_config,
        runner,
        archive_db,
    };

    check_runnable(&ctx, &cli.command, postfork_bin.as_deref())?;

    match cli.command {
        Command::Network(cmd) => network::run(&ctx, cmd),
        Command::Node(cmd) => node::run(&ctx, cmd),
        Command::Mina(cmd) => mina::run(&ctx.dirs, ctx.runner.as_ref(), &install::mina::Http, cmd),
        Command::Spec(cmd) => spec::run(cmd),
    }
}

/// The runtime config of a network's `mina-archive`: the network's genesis
/// config, from which it inserts the genesis block (as canonical) and records
/// the genesis accounts. After a hardfork, the postfork config `apply`
/// recorded; none for a network forked before minimina wrote one, since its
/// genesis config then has no ledger.
fn archive_config(stored: Option<&NetworkMeta>, network_path: &Path) -> Option<PathBuf> {
    match stored.and_then(|m| m.hardfork.as_ref()) {
        Some(h) if h.state == HardforkState::Applied => h.archive_config.clone(),
        _ => Some(network_path.join(GENESIS_LEDGER_JSON)),
    }
}

/// Before a command starts mina binaries: fails when they cannot load their
/// libraries, which would otherwise show only as a loader error in a log.
fn check_runnable(ctx: &Context, command: &Command, postfork_bin: Option<&Path>) -> Result<()> {
    if ctx.mode != ExecutionMode::Native {
        return Ok(());
    }
    let runner = ctx.runner.as_ref();
    match command {
        Command::Network(NetworkCommand::Create(_) | NetworkCommand::Start(_))
        | Command::Node(NodeCommand::Start(_)) => match &ctx.bin_path {
            Some(bin) => install::mina::require_runnable(runner, bin, ctx.mina_version.as_deref()),
            None => Ok(()),
        },
        // apply starts the postfork binaries
        Command::Network(NetworkCommand::Hardfork(HardforkCommand::Apply(_))) => match postfork_bin
        {
            Some(bin) => install::mina::require_runnable(runner, bin, None),
            None => Ok(()),
        },
        _ => Ok(()),
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

#[cfg(test)]
mod archive_config_tests {
    use super::*;
    use crate::{
        hardfork::HardforkMode,
        network_meta::{HardforkMeta, HardforkState},
    };

    fn plain() -> NetworkMeta {
        NetworkMeta {
            mode: ExecutionMode::Native,
            bin_path: None,
            mina_version: None,
            postgres_uri: None,
            profile: Profile::Devnet,
            features: DaemonFeatures::default(),
            genesis_pending: false,
            hardfork: None,
        }
    }

    fn meta(state: HardforkState, archive_config: Option<&str>) -> NetworkMeta {
        NetworkMeta {
            hardfork: Some(HardforkMeta {
                mode: HardforkMode::Manual,
                method: None,
                postfork_bin_path: "/post".into(),
                archive_upgrade: None,
                state,
                prefork_bin_path: None,
                archive_config: archive_config.map(PathBuf::from),
            }),
            ..plain()
        }
    }

    #[test]
    fn the_archive_reads_the_genesis_config_until_a_fork_is_applied() {
        let net = Path::new("/n");
        let genesis = Some(PathBuf::from("/n/genesis_ledger.json"));
        // a new network, a plain one, a fork not applied yet
        assert_eq!(archive_config(None, net), genesis);
        assert_eq!(archive_config(Some(&plain()), net), genesis);
        let prepared = meta(HardforkState::Prepared, None);
        assert_eq!(archive_config(Some(&prepared), net), genesis);
        // applied: the recorded postfork config, or none (forked before it existed)
        let applied = meta(
            HardforkState::Applied,
            Some("/n/hardfork/archive_config.json"),
        );
        assert_eq!(
            archive_config(Some(&applied), net),
            Some(PathBuf::from("/n/hardfork/archive_config.json"))
        );
        let old = meta(HardforkState::Applied, None);
        assert_eq!(archive_config(Some(&old), net), None);
    }
}
