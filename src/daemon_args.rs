//! `mina` arguments of the daemon services and snark workers.
//!
//! One builder for both execution modes: they differ only in where files are
//! (`/local-network` in a container, the network directory on the host) and in
//! how a process reaches another service (compose DNS name or localhost).

use crate::cli::ExecutionMode;
use crate::directory_manager::{LIBP2P_KEYPAIRS, NETWORK_KEYPAIRS};
use crate::genesis_ledger::GENESIS_LEDGER_JSON;
use crate::service::typed::{
    BlockProducerKey, Daemon, Libp2pKeypair, Mode, Peers, Role, Rosetta, SnarkWorker,
};
use log::warn;
use serde::{Deserialize, Serialize};

/// Precomputed blocks directory inside a daemon's config directory.
pub const PRECOMPUTED_BLOCKS_DIR: &str = "precomputed_blocks";
/// Precomputed blocks file of daemons without `-precomputed-blocks-dir`.
pub const PRECOMPUTED_BLOCKS_FILE: &str = "precomputed_blocks.log";

/// Daemon flags that only some mina versions have, probed at `network create`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonFeatures {
    /// `-precomputed-blocks-dir` (4.0.2+): one file per block. Older daemons
    /// only have `-precomputed-blocks-file`, which appends to one file.
    #[serde(default)]
    pub precomputed_blocks_dir: bool,
}

impl DaemonFeatures {
    /// Reads the features from the output of `mina daemon -help`.
    pub fn from_daemon_help(help: &str) -> Self {
        DaemonFeatures {
            precomputed_blocks_dir: help.contains("-precomputed-blocks-dir"),
        }
    }
}

fn arg(args: &mut Vec<String>, flag: &str, value: impl Into<String>) {
    args.push(flag.to_string());
    args.push(value.into());
}

/// Where a mina process finds its files and the other services.
pub struct Layout<'a> {
    pub mode: ExecutionMode,
    /// Network name; docker service names end with `-<network>`.
    pub network: &'a str,
    /// Directory with the genesis ledger, key directories and peer list, as the process sees it.
    pub network_dir: &'a str,
    /// The process's `-config-directory`.
    pub config_dir: &'a str,
    /// Compose service name of the uptime service backend (docker mode only).
    pub uptime_service: Option<&'a str>,
    pub features: DaemonFeatures,
}

impl Layout<'_> {
    /// Host under which other processes reach the service `name`.
    fn host(&self, name: &str) -> String {
        match self.mode {
            ExecutionMode::Docker => format!("{name}-{}", self.network),
            ExecutionMode::Native => "127.0.0.1".to_string(),
        }
    }

    fn add_peers(&self, name: &str, peers: &Peers, args: &mut Vec<String>) {
        match peers {
            Peers::ListFile => arg(
                args,
                "-peer-list-file",
                format!("{}/peer_list_file.txt", self.network_dir),
            ),
            Peers::List(peers) => {
                for peer in peers {
                    arg(args, "-peer", peer.clone());
                }
            }
            Peers::None => warn!("No peers for node '{name}'."),
        }
    }

    fn add_libp2p_keypair<M: Mode>(&self, name: &str, daemon: &Daemon<M>, args: &mut Vec<String>) {
        match &daemon.libp2p_keypair {
            Some(Libp2pKeypair::File) => arg(
                args,
                "-libp2p-keypair",
                format!("{}/{LIBP2P_KEYPAIRS}/{name}.json", self.network_dir),
            ),
            Some(Libp2pKeypair::Path(path)) => arg(args, "-libp2p-keypair", path.clone()),
            None => warn!("No libp2p keypair for node '{name}'."),
        }
    }

    fn block_producer_key(&self, name: &str, key: &BlockProducerKey) -> String {
        match key {
            BlockProducerKey::File => {
                format!("{}/{NETWORK_KEYPAIRS}/{name}.json", self.network_dir)
            }
            BlockProducerKey::Path(path) => path.clone(),
        }
    }

    /// Arguments of `mina` for the daemon `name`.
    pub fn daemon<M: Mode>(&self, name: &str, daemon: &Daemon<M>) -> Vec<String> {
        let client_port = daemon.client_port;
        let mut args = vec!["daemon".to_string()];
        arg(&mut args, "-client-port", client_port.to_string());
        arg(&mut args, "-rest-port", (client_port + 1).to_string());
        args.push("-insecure-rest-server".to_string());
        arg(&mut args, "-external-port", (client_port + 2).to_string());
        arg(&mut args, "-metrics-port", (client_port + 3).to_string());
        arg(
            &mut args,
            "-libp2p-metrics-port",
            (client_port + 4).to_string(),
        );
        if self.mode == ExecutionMode::Native {
            // without it the daemon looks up and advertises the host's public IP
            arg(&mut args, "-external-ip", "127.0.0.1");
        }
        arg(
            &mut args,
            "-config-file",
            format!("{}/{GENESIS_LEDGER_JSON}", self.network_dir),
        );
        args.push("-log-json".to_string());
        // stdout goes to the service log; the config directory's mina.log rotates
        arg(&mut args, "-log-level", "Info");
        arg(&mut args, "-file-log-level", "Trace");
        arg(&mut args, "-config-directory", self.config_dir);
        if self.features.precomputed_blocks_dir {
            arg(
                &mut args,
                "-precomputed-blocks-dir",
                format!("{}/{PRECOMPUTED_BLOCKS_DIR}", self.config_dir),
            );
        } else {
            arg(
                &mut args,
                "-precomputed-blocks-file",
                format!("{}/{PRECOMPUTED_BLOCKS_FILE}", self.config_dir),
            );
        }
        arg(&mut args, "-log-txn-pool-gossip", "true");
        arg(&mut args, "-log-snark-work-gossip", "true");
        // no -proof-level: the profile's compiled level (or `proof.level` in the
        // runtime config) applies; `full` is fatal for binaries compiled for less

        match &daemon.role {
            Role::Seed => args.push("-seed".to_string()),
            Role::BlockProducer { key } => {
                self.add_peers(name, &daemon.peers, &mut args);
                let uptime_url = self
                    .uptime_service
                    .map(|host| format!("http://{host}:8080/v1/submit"));
                if let Some(url) = &uptime_url {
                    arg(&mut args, "-uptime-url", url.clone());
                }
                match key {
                    Some(key) => {
                        let key = self.block_producer_key(name, key);
                        if uptime_url.is_some() {
                            arg(&mut args, "-uptime-submitter-key", key.clone());
                        }
                        arg(&mut args, "-block-producer-key", key);
                    }
                    None => {
                        warn!("Block producer '{name}' has no key: it will not produce blocks.")
                    }
                }
            }
            Role::Plain => self.add_peers(name, &daemon.peers, &mut args),
            Role::SnarkCoordinator { fee, public_key } => {
                arg(&mut args, "-work-selection", "seq");
                self.add_peers(name, &daemon.peers, &mut args);
                arg(&mut args, "-snark-worker-fee", fee.clone());
                arg(&mut args, "-run-snark-coordinator", public_key.clone());
            }
            Role::Archive { port, .. } => {
                self.add_peers(name, &daemon.peers, &mut args);
                arg(
                    &mut args,
                    "-archive-address",
                    format!("{}:{port}", self.host(&format!("{name}-service"))),
                );
            }
        }
        self.add_libp2p_keypair(name, daemon, &mut args);
        args
    }

    /// Arguments of `mina` for a snark worker.
    pub fn snark_worker<M: Mode>(&self, worker: &SnarkWorker<M>) -> Vec<String> {
        let mut args = vec!["internal".to_string(), "snark-worker".to_string()];
        arg(&mut args, "-shutdown-on-disconnect", "false");
        arg(&mut args, "-config-directory", self.config_dir);
        arg(
            &mut args,
            "-daemon-address",
            format!(
                "{}:{}",
                self.host(&worker.coordinator),
                worker.coordinator_port
            ),
        );
        if let Some(proof_level) = &worker.proof_level {
            arg(&mut args, "-proof-level", proof_level.clone());
        }
        args
    }
}

/// Environment `mina-rosetta` needs: it refuses to start without a database
/// pool size, and has no default for it. A local postgres allows 100
/// connections, shared with the archive.
pub const ROSETTA_ENV: &[(&str, &str)] = &[("MINA_ROSETTA_MAX_DB_POOL_SIZE", "16")];

/// Arguments of `mina-rosetta`: the API on its port, data from the archive
/// database `archive_uri` and from the GraphQL API of its daemon.
pub fn rosetta_args<M: Mode>(
    rosetta: &Rosetta<M>,
    layout: &Layout,
    archive_uri: &str,
) -> Vec<String> {
    let mut args = Vec::new();
    arg(&mut args, "--port", rosetta.port.to_string());
    arg(&mut args, "--archive-uri", archive_uri);
    arg(
        &mut args,
        "--graphql-uri",
        format!(
            "http://{}:{}/graphql",
            layout.host(&rosetta.graphql_node),
            rosetta.graphql_port
        ),
    );
    args.push("--log-json".to_string());
    arg(&mut args, "--log-level", "Info");
    args
}

/// Orders precomputed block file names (`<network>-<height>-<state_hash>.json`)
/// by height; names that do not parse go last.
pub fn sort_precomputed_block_files(names: &mut [String]) {
    let height = |name: &str| -> Option<u64> { name.rsplit('-').nth(1)?.parse().ok() };
    names.sort_by_key(|name| (height(name).unwrap_or(u64::MAX), name.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::typed::{Kind, Native, Service};

    fn layout(mode: ExecutionMode) -> Layout<'static> {
        Layout {
            mode,
            network: "net",
            network_dir: "/n",
            config_dir: "/c",
            uptime_service: None,
            features: DaemonFeatures::default(),
        }
    }

    fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        let i = args.iter().position(|a| a == flag)?;
        args.get(i + 1).map(String::as_str)
    }

    fn daemon(role: Role<Native>) -> Daemon<Native> {
        Daemon {
            image: (),
            client_port: 4000,
            published: true,
            peers: Peers::List(vec!["/ip4/127.0.0.1/tcp/3102/p2p/x".into()]),
            libp2p_keypair: Some(Libp2pKeypair::Path("kp".into())),
            role,
        }
    }

    fn service(name: &str, kind: Kind<Native>) -> Service<Native> {
        Service {
            name: name.into(),
            kind,
        }
    }

    fn node(name: &str, role: Role<Native>) -> Service<Native> {
        service(name, Kind::Daemon(daemon(role)))
    }

    fn args_in(service: &Service<Native>, layout: &Layout) -> Vec<String> {
        match &service.kind {
            Kind::Daemon(daemon) => layout.daemon(&service.name, daemon),
            Kind::SnarkWorker(worker) => layout.snark_worker(worker),
            other => panic!("not run by mina: {other:?}"),
        }
    }

    fn args(service: &Service<Native>, mode: ExecutionMode) -> Vec<String> {
        args_in(service, &layout(mode))
    }

    #[test]
    fn ports_follow_the_client_port() {
        let args = args(&node("seed", Role::Seed), ExecutionMode::Docker);
        for (flag, port) in [
            ("-client-port", "4000"),
            ("-rest-port", "4001"),
            ("-external-port", "4002"),
            ("-metrics-port", "4003"),
            ("-libp2p-metrics-port", "4004"),
        ] {
            assert_eq!(value_of(&args, flag), Some(port), "{flag}");
        }
        assert!(args.contains(&"-seed".to_string()));
        assert_eq!(
            value_of(&args, "-config-file"),
            Some("/n/genesis_ledger.json")
        );
        assert_eq!(value_of(&args, "-proof-level"), None);
        // seeds take no peers
        assert_eq!(value_of(&args, "-peer"), None);
    }

    #[test]
    fn native_daemons_advertise_localhost() {
        let bp = node("bp", Role::BlockProducer { key: None });
        let native = args(&bp, ExecutionMode::Native);
        assert_eq!(value_of(&native, "-external-ip"), Some("127.0.0.1"));
        let docker = args(&bp, ExecutionMode::Docker);
        assert_eq!(value_of(&docker, "-external-ip"), None);
    }

    #[test]
    fn precomputed_blocks_go_to_a_directory_when_the_daemon_has_it() {
        let seed = node("seed", Role::Seed);
        let old = args(&seed, ExecutionMode::Native);
        assert_eq!(
            value_of(&old, "-precomputed-blocks-file"),
            Some("/c/precomputed_blocks.log")
        );
        let mut new_layout = layout(ExecutionMode::Native);
        new_layout.features.precomputed_blocks_dir = true;
        let new = args_in(&seed, &new_layout);
        assert_eq!(
            value_of(&new, "-precomputed-blocks-dir"),
            Some("/c/precomputed_blocks")
        );
        assert_eq!(value_of(&new, "-precomputed-blocks-file"), None);
        assert!(!new.contains(&"-log-precomputed-blocks".to_string()));
    }

    #[test]
    fn block_producer_keys() {
        let bp = |key| node("bp", Role::BlockProducer { key });
        let no_key = args(&bp(None), ExecutionMode::Native);
        assert_eq!(value_of(&no_key, "-block-producer-key"), None);

        let generated = args(
            &bp(Some(BlockProducerKey::Path(
                "/n/network-keypairs/bp".into(),
            ))),
            ExecutionMode::Native,
        );
        assert_eq!(
            value_of(&generated, "-block-producer-key"),
            Some("/n/network-keypairs/bp")
        );

        let mut with_uptime = layout(ExecutionMode::Docker);
        with_uptime.uptime_service = Some("uptime-net");
        let copied = args_in(&bp(Some(BlockProducerKey::File)), &with_uptime);
        assert_eq!(
            value_of(&copied, "-block-producer-key"),
            Some("/n/network-keypairs/bp.json")
        );
        assert_eq!(
            value_of(&copied, "-uptime-submitter-key"),
            Some("/n/network-keypairs/bp.json")
        );
        assert_eq!(
            value_of(&copied, "-uptime-url"),
            Some("http://uptime-net:8080/v1/submit")
        );
    }

    #[test]
    fn snark_coordinator_gets_its_fee_and_key() {
        let coordinator = node(
            "coord",
            Role::SnarkCoordinator {
                fee: "0.001".into(),
                public_key: "B62".into(),
            },
        );
        let args = args(&coordinator, ExecutionMode::Native);
        assert_eq!(value_of(&args, "-snark-worker-fee"), Some("0.001"));
        assert_eq!(value_of(&args, "-run-snark-coordinator"), Some("B62"));
        assert_eq!(value_of(&args, "-work-selection"), Some("seq"));
    }

    #[test]
    fn services_are_reached_by_compose_name_or_localhost() {
        let archive = node(
            "archive",
            Role::Archive {
                port: 3086,
                image: (),
            },
        );
        assert_eq!(
            value_of(&args(&archive, ExecutionMode::Docker), "-archive-address"),
            Some("archive-service-net:3086")
        );
        assert_eq!(
            value_of(&args(&archive, ExecutionMode::Native), "-archive-address"),
            Some("127.0.0.1:3086")
        );

        let worker = service(
            "w",
            Kind::SnarkWorker(SnarkWorker {
                image: (),
                coordinator: "coord".into(),
                coordinator_port: 7000,
                proof_level: Some("none".into()),
            }),
        );
        let docker = args(&worker, ExecutionMode::Docker);
        assert_eq!(docker[..2], ["internal", "snark-worker"]);
        assert_eq!(value_of(&docker, "-daemon-address"), Some("coord-net:7000"));
        assert_eq!(value_of(&docker, "-proof-level"), Some("none"));
        let native = args(&worker, ExecutionMode::Native);
        assert_eq!(value_of(&native, "-daemon-address"), Some("127.0.0.1:7000"));
    }

    #[test]
    fn rosetta_reads_the_archive_and_a_daemon() {
        let rosetta = Rosetta::<Native> {
            image: (),
            port: 3087,
            graphql_node: "archive".into(),
            graphql_port: 3141,
        };
        let native = rosetta_args(&rosetta, &layout(ExecutionMode::Native), "postgres://db/a");
        assert_eq!(value_of(&native, "--port"), Some("3087"));
        assert_eq!(value_of(&native, "--archive-uri"), Some("postgres://db/a"));
        assert_eq!(
            value_of(&native, "--graphql-uri"),
            Some("http://127.0.0.1:3141/graphql")
        );
        let docker = rosetta_args(&rosetta, &layout(ExecutionMode::Docker), "pg");
        assert_eq!(
            value_of(&docker, "--graphql-uri"),
            Some("http://archive-net:3141/graphql")
        );
    }

    #[test]
    fn precomputed_block_files_sort_by_height() {
        let mut names = vec![
            "testnet-10-3NLb.json".to_string(),
            "my-net-2-3NLa.json".to_string(),
            "testnet-9-3NLc.json".to_string(),
            "README".to_string(),
        ];
        sort_precomputed_block_files(&mut names);
        assert_eq!(
            names,
            [
                "my-net-2-3NLa.json",
                "testnet-9-3NLc.json",
                "testnet-10-3NLb.json",
                "README"
            ]
        );
    }

    #[test]
    fn features_from_help() {
        assert!(
            DaemonFeatures::from_daemon_help("  [--precomputed-blocks-dir DIR] ...")
                .precomputed_blocks_dir
        );
        assert!(
            !DaemonFeatures::from_daemon_help("  [--precomputed-blocks-file PATH]")
                .precomputed_blocks_dir
        );
    }
}
