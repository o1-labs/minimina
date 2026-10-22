//! # `minimina` Command-Line Interface (CLI)

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    Docker,
    Native,
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ExecutionMode::Docker => "docker",
            ExecutionMode::Native => "native",
        })
    }
}

/// Build profile of the mina binaries (`Node_config` constants and signature kind).
///
/// Since 4.0 the daemon, archive and rosetta binaries are generic: they read the
/// profile at runtime from `MINA_PROFILE`, else from `/etc/coda/build_config/PROFILE`,
/// which only the `mina-<net>-profile` package installs. Older binaries ignore it.
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Dev,
    #[default]
    Devnet,
    Lightnet,
    Mainnet,
}

impl Profile {
    /// Environment variable the mina binaries read the profile from.
    pub const ENV: &'static str = "MINA_PROFILE";

    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Dev => "dev",
            Profile::Devnet => "devnet",
            Profile::Lightnet => "lightnet",
            Profile::Mainnet => "mainnet",
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "MiniMina - A Command-line Tool for Spinning up Local Mina Networks"
)]
#[command(propagate_version = true)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,

    /// Execution mode: docker or native. `network create` defaults to docker;
    /// other commands use the mode the network was created with.
    #[clap(long, global = true)]
    pub mode: Option<ExecutionMode>,

    /// Path to mina binaries directory (native mode only).
    /// If omitted, minimina searches /usr/local/bin, /usr/bin, and PATH.
    #[clap(long, global = true)]
    pub bin_path: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage local network
    #[clap(subcommand)]
    Network(NetworkCommand),

    /// Manage a single node
    #[clap(subcommand)]
    Node(NodeCommand),
}

#[derive(Subcommand)]
pub enum NetworkCommand {
    /// Create a local network
    Create(CreateNetworkArgs),
    /// Delete a local network
    Delete(NetworkId),
    /// List local networks
    List,
    /// Get status of a local network
    Status(NetworkId),
    /// Get details of a local network
    Info(NetworkId),
    /// Start a local network
    Start(StartNetworkArgs),
    /// Stop a local network
    Stop(StopNetworkArgs),
}

#[derive(Args, Debug, Clone)]
pub struct NetworkId {
    /// Network identifier
    #[clap(short, long, default_value = "default", value_parser = crate::network_id::parse)]
    pub network_id: String,
}

/// Seconds to wait after SIGTERM before SIGKILL (native) or `docker compose stop -t` (docker).
#[derive(Args, Debug, Clone, Default)]
pub struct ShutdownTimeout {
    /// Seconds to wait for a graceful shutdown before killing
    /// [default: 60 in native mode, docker compose default in docker mode]
    #[clap(long = "timeout")]
    pub secs: Option<u64>,
}

#[derive(Args, Debug, Clone)]
pub struct StopNetworkArgs {
    #[clap(flatten)]
    pub network_id: NetworkId,

    #[clap(flatten)]
    pub timeout: ShutdownTimeout,
}

#[derive(Args, Clone)]
pub struct CreateNetworkArgs {
    /// Path to a (TOML) network spec: roles and counts of the nodes; minimina
    /// generates keys, ports, peers and the genesis ledger
    #[clap(short = 's', long, conflicts_with_all = ["topology", "genesis_ledger"])]
    pub spec: Option<std::path::PathBuf>,

    /// Path to the (JSON) topology file
    #[clap(short = 't', long)]
    pub topology: Option<std::path::PathBuf>,

    /// Path to the (JSON) genesis ledger/runtime config
    #[clap(short = 'g', long)]
    pub genesis_ledger: Option<std::path::PathBuf>,

    /// Network identifier
    #[clap(flatten)]
    pub network_id: NetworkId,

    /// Specify log level
    #[clap(short = 'l', long, default_value = "warn")]
    pub log_level: String,

    /// Build profile the mina processes run with (exported as MINA_PROFILE)
    /// [default: the spec's profile, else devnet]. Recorded at create; later
    /// commands use the recorded profile
    #[clap(long, value_enum)]
    pub profile: Option<Profile>,
}

#[derive(Args, Clone)]
pub struct StartNetworkArgs {
    /// Network identifier
    #[clap(flatten)]
    pub network_id: NetworkId,

    /// Network identifier
    #[clap(short = 'v', long, default_value_t = false)]
    pub verbose: bool,

    /// Specify log level
    #[clap(short = 'l', long, default_value = "warn")]
    pub log_level: String,

    /// Native mode: seconds to wait for the seeds' libp2p ports before starting
    /// the other nodes (non-seed daemons exit if they find no peer at boot)
    #[clap(long, default_value_t = 900)]
    pub seed_timeout: u64,
}

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Start a node
    Start(StartNodeCommandArgs),
    /// Stop a node
    Stop(StopNodeArgs),
    /// Dump the node's logs to stdout
    Logs(NodeCommandArgs),
    /// Dump the node's precomputed blocks to stdout
    DumpPrecomputedBlocks(NodeCommandArgs),
    /// Dump an archive node's data
    DumpArchiveData(NodeCommandArgs),
    /// Run the replayer on an archive node's db
    RunReplayer(ReplayerArgs),
}

#[derive(Args, Debug)]
pub struct NodeId {
    /// Node identifier
    #[clap(short = 'i', long)]
    pub node_id: String,
}

#[derive(Args, Debug)]
pub struct NodeCommandArgs {
    /// Network identifier
    #[clap(flatten)]
    pub network_id: NetworkId,

    /// Node identifier
    #[clap(flatten)]
    pub node_id: NodeId,

    /// Log level filter
    #[clap(short = 'l', long, default_value = "warn")]
    pub log_level: String,

    /// Raw output (not wrapped in JSON)
    #[clap(short = 'r', long, default_value_t = false)]
    pub raw_output: bool,
}

#[derive(Args, Debug)]
pub struct StartNodeCommandArgs {
    /// Start node with fresh state
    #[clap(short = 'f', long, default_value_t = false)]
    pub fresh_state: bool,

    /// Import genesis accounts from network-keypairs
    #[clap(short = 'a', long, default_value_t = false)]
    pub import_accounts: bool,

    /// Start node with GraphQL filtered logs enabled
    #[clap(short = 'g', long, default_value_t = false)]
    pub graphql_filtered_logs: bool,

    #[clap(flatten)]
    pub node_args: NodeCommandArgs,
}

#[derive(Args, Debug)]
pub struct StopNodeArgs {
    #[clap(flatten)]
    pub node_args: NodeCommandArgs,

    #[clap(flatten)]
    pub timeout: ShutdownTimeout,
}

#[derive(Args, Debug)]
pub struct ReplayerArgs {
    /// Global slot since genesis
    #[clap(short = 's', long)]
    pub start_slot_since_genesis: u64,

    #[clap(flatten)]
    pub node_args: NodeCommandArgs,
}

pub trait DefaultLogLevel {
    fn log_level(&self) -> &str;
}

trait LogLevel {
    fn log_level(&self) -> &str;
}

pub trait CommandWithNetworkId {
    fn network_id(&self) -> &str;
}

pub trait CommandWithNodeId {
    fn node_id(&self) -> &str;
}

macro_rules! log_level {
    ($name:path) => {
        impl LogLevel for $name {
            fn log_level(&self) -> &str {
                &self.log_level
            }
        }
    };
}

macro_rules! network_id {
    ($name:path) => {
        impl CommandWithNetworkId for $name {
            fn network_id(&self) -> &str {
                &self.network_id.network_id
            }
        }
    };
}

macro_rules! node_id {
    ($name:path) => {
        impl CommandWithNodeId for $name {
            fn node_id(&self) -> &str {
                &self.node_id.node_id
            }
        }
    };
}

log_level!(StartNetworkArgs);
log_level!(CreateNetworkArgs);
log_level!(NodeCommandArgs);

network_id!(StartNetworkArgs);
network_id!(CreateNetworkArgs);
network_id!(NodeCommandArgs);
network_id!(StopNetworkArgs);

node_id!(NodeCommandArgs);

impl DefaultLogLevel for Command {
    fn log_level(&self) -> &str {
        match self {
            Command::Network(cmd) => match cmd {
                NetworkCommand::Create(args) => args.log_level(),
                NetworkCommand::Start(args) => args.log_level(),
                _ => "warn",
            },
            Command::Node(cmd) => match cmd {
                NodeCommand::DumpArchiveData(args)
                | NodeCommand::DumpPrecomputedBlocks(args)
                | NodeCommand::Logs(args)
                | NodeCommand::Stop(StopNodeArgs {
                    node_args: args, ..
                }) => args.log_level(),
                NodeCommand::Start(args) => args.node_args.log_level(),
                NodeCommand::RunReplayer(args) => args.node_args.log_level(),
            },
        }
    }
}

impl Command {
    /// Network the command operates on; `None` for `network list`.
    pub fn network_id(&self) -> Option<&str> {
        match self {
            Command::Network(cmd) => match cmd {
                NetworkCommand::Create(args) => Some(args.network_id()),
                NetworkCommand::Start(args) => Some(args.network_id()),
                NetworkCommand::Stop(args) => Some(args.network_id()),
                NetworkCommand::Delete(args)
                | NetworkCommand::Status(args)
                | NetworkCommand::Info(args) => Some(&args.network_id),
                NetworkCommand::List => None,
            },
            Command::Node(cmd) => Some(match cmd {
                NodeCommand::Start(args) => args.node_args.network_id(),
                NodeCommand::Stop(args) => args.node_args.network_id(),
                NodeCommand::RunReplayer(args) => args.node_args.network_id(),
                NodeCommand::Logs(args)
                | NodeCommand::DumpPrecomputedBlocks(args)
                | NodeCommand::DumpArchiveData(args) => args.network_id(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_is_checked_by_every_command() {
        let err = Cli::try_parse_from(["minimina", "network", "status", "-n", "../etc"])
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("invalid network id '../etc'"),
            "{err}"
        );
    }

    #[test]
    fn spec_excludes_topology_and_ledger() {
        for other in [["-t", "t.json"], ["-g", "g.json"]] {
            let mut args = vec!["minimina", "network", "create", "--spec", "n.toml"];
            args.extend(other);
            let err = Cli::try_parse_from(args).err().unwrap();
            assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
        let cli = Cli::try_parse_from(["minimina", "network", "create", "-s", "n.toml"]).unwrap();
        match cli.command {
            Command::Network(NetworkCommand::Create(args)) => {
                assert_eq!(args.spec.as_deref(), Some(std::path::Path::new("n.toml")));
                assert_eq!(args.profile, None);
            }
            _ => panic!("not a create"),
        }
    }

    #[test]
    fn test_network_create_command() {
        let args = vec![
            "minimina",
            "network",
            "create",
            "--topology",
            "/path/to/file",
            "--genesis-ledger",
            "/path/to/dir",
            "--network-id",
            "test",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Network(NetworkCommand::Create(args)) => {
                assert_eq!(
                    args.topology,
                    Some(std::path::PathBuf::from("/path/to/file"))
                );
                assert_eq!(
                    args.genesis_ledger,
                    Some(std::path::PathBuf::from("/path/to/dir"))
                );
                assert_eq!(args.network_id(), "test");
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_network_delete_command() {
        let args = vec!["minimina", "network", "delete", "--network-id", "test"];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Network(NetworkCommand::Delete(args)) => {
                assert_eq!(args.network_id, "test");
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_network_list_command() {
        let args = vec!["minimina", "network", "list"];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Network(NetworkCommand::List) => {}
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_network_start_command() {
        let args = vec!["minimina", "network", "start", "--network-id", "test"];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Network(NetworkCommand::Start(args)) => {
                assert_eq!(args.network_id(), "test");
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_network_stop_command() {
        let args = vec!["minimina", "network", "stop", "--network-id", "test"];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Network(NetworkCommand::Stop(args)) => {
                assert_eq!(args.network_id(), "test");
                assert_eq!(args.timeout.secs, None);
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_node_start_command() {
        let args = vec!["minimina", "node", "start", "--node-id", "test"];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Node(NodeCommand::Start(args)) => {
                assert_eq!(args.node_args.node_id(), "test");
                assert_eq!(args.node_args.network_id(), "default");
                assert!(!args.fresh_state);
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_node_start_fresh_state() {
        let args = vec![
            "minimina",
            "node",
            "start",
            "--node-id",
            "test",
            "--fresh-state",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Node(NodeCommand::Start(args)) => {
                assert_eq!(args.node_args.node_id(), "test");
                assert_eq!(args.node_args.network_id(), "default");
                assert!(args.fresh_state);
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_node_stop_command() {
        let args = vec![
            "minimina",
            "node",
            "stop",
            "--node-id",
            "test",
            "--network-id",
            "banana",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Node(NodeCommand::Stop(args)) => {
                assert_eq!(args.node_args.node_id(), "test");
                assert_eq!(args.node_args.network_id(), "banana");
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_node_logs_command() {
        let args = vec!["minimina", "node", "logs", "--node-id", "test"];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Node(NodeCommand::Logs(args)) => {
                assert_eq!(args.node_id(), "test");
                assert_eq!(args.network_id(), "default");
            }
            _ => panic!("Unexpected command parsed"),
        }
    }

    #[test]
    fn test_node_dump_precomputed_blocks() {
        let args = vec![
            "minimina",
            "node",
            "dump-precomputed-blocks",
            "--node-id",
            "test_node",
            "--network-id",
            "test_network",
        ];

        let cli = Cli::parse_from(args);

        match cli.command {
            Command::Node(NodeCommand::DumpPrecomputedBlocks(args)) => {
                assert_eq!(args.node_id(), "test_node");
                assert_eq!(args.network_id(), "test_network");
            }
            _ => panic!("Unexpected command parsed"),
        }
    }
}
