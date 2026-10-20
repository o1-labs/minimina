//! `mina` arguments of the daemon services and snark workers.
//!
//! One builder for both execution modes: they differ only in where files are
//! (`/local-network` in a container, the network directory on the host) and in
//! how a process reaches another service (compose DNS name or localhost).

use crate::cli::ExecutionMode;
use crate::directory_manager::{LIBP2P_KEYPAIRS, NETWORK_KEYPAIRS};
use crate::genesis_ledger::GENESIS_LEDGER_JSON;
use crate::service::{ServiceConfig, ServiceType};
use log::warn;
use serde::{Deserialize, Serialize};
use std::io;

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

    fn add_peers(&self, service: &ServiceConfig, args: &mut Vec<String>) {
        if service.peer_list_file.is_some() {
            arg(
                args,
                "-peer-list-file",
                format!("{}/peer_list_file.txt", self.network_dir),
            );
        } else if let Some(peers) = &service.peers {
            for peer in peers {
                arg(args, "-peer", peer.clone());
            }
        } else {
            warn!("No peers for node '{}'.", service.service_name);
        }
    }

    fn add_libp2p_keypair(&self, service: &ServiceConfig, args: &mut Vec<String>) {
        if service.libp2p_keypair_path.is_some() {
            arg(
                args,
                "-libp2p-keypair",
                format!(
                    "{}/{LIBP2P_KEYPAIRS}/{}.json",
                    self.network_dir, service.service_name
                ),
            );
        } else if let Some(keypair) = &service.libp2p_keypair {
            arg(args, "-libp2p-keypair", keypair.clone());
        } else {
            warn!("No libp2p keypair for node '{}'.", service.service_name);
        }
    }

    /// Block producer key: topology keys are copied to `<name>.json`; generated
    /// keys of the default network stay where key generation put them.
    fn block_producer_key(&self, service: &ServiceConfig) -> Option<String> {
        if service.private_key_path.is_some() {
            Some(format!(
                "{}/{NETWORK_KEYPAIRS}/{}.json",
                self.network_dir, service.service_name
            ))
        } else {
            service.public_key_path.clone()
        }
    }

    fn daemon(&self, service: &ServiceConfig) -> io::Result<Vec<String>> {
        let client_port = match (service.client_port, self.mode) {
            (Some(port), _) => port,
            // every container has its own ports
            (None, ExecutionMode::Docker) => 3100,
            (None, ExecutionMode::Native) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("daemon '{}' has no client_port", service.service_name),
                ))
            }
        };
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

        match service.service_type {
            ServiceType::Seed => args.push("-seed".to_string()),
            ServiceType::BlockProducer => {
                self.add_peers(service, &mut args);
                let uptime_url = self
                    .uptime_service
                    .map(|host| format!("http://{host}:8080/v1/submit"));
                if let Some(url) = &uptime_url {
                    arg(&mut args, "-uptime-url", url.clone());
                }
                match self.block_producer_key(service) {
                    Some(key) => {
                        if uptime_url.is_some() {
                            arg(&mut args, "-uptime-submitter-key", key.clone());
                        }
                        arg(&mut args, "-block-producer-key", key);
                    }
                    None => warn!(
                        "Block producer '{}' has no key: it will not produce blocks.",
                        service.service_name
                    ),
                }
            }
            ServiceType::PlainNode => self.add_peers(service, &mut args),
            ServiceType::SnarkCoordinator => {
                arg(&mut args, "-work-selection", "seq");
                self.add_peers(service, &mut args);
                match &service.snark_coordinator_fees {
                    Some(fee) => arg(&mut args, "-snark-worker-fee", fee.clone()),
                    None => warn!(
                        "No snark worker fee for snark coordinator '{}'.",
                        service.service_name
                    ),
                }
                match &service.public_key {
                    Some(pk) => arg(&mut args, "-run-snark-coordinator", pk.clone()),
                    None => warn!(
                        "No public key for snark coordinator '{}'.",
                        service.service_name
                    ),
                }
            }
            ServiceType::ArchiveNode => {
                self.add_peers(service, &mut args);
                match service.archive_port {
                    Some(port) => arg(
                        &mut args,
                        "-archive-address",
                        format!(
                            "{}:{port}",
                            self.host(&format!("{}-service", service.service_name))
                        ),
                    ),
                    None => warn!(
                        "No archive port for archive node '{}'.",
                        service.service_name
                    ),
                }
            }
            ServiceType::SnarkWorker
            | ServiceType::UptimeServiceBackend
            | ServiceType::Rosetta
            | ServiceType::ArchiveNodeApi => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("'{}' is not a daemon", service.service_name),
                ))
            }
        }
        self.add_libp2p_keypair(service, &mut args);
        Ok(args)
    }

    fn snark_worker(&self, service: &ServiceConfig) -> Vec<String> {
        let mut args = vec!["internal".to_string(), "snark-worker".to_string()];
        arg(&mut args, "-shutdown-on-disconnect", "false");
        arg(&mut args, "-config-directory", self.config_dir);
        match (
            &service.snark_coordinator_host,
            service.snark_coordinator_port,
        ) {
            (Some(host), Some(port)) => arg(
                &mut args,
                "-daemon-address",
                format!("{}:{port}", self.host(host)),
            ),
            _ => warn!(
                "No snark coordinator for snark worker '{}'.",
                service.service_name
            ),
        }
        if let Some(proof_level) = &service.snark_worker_proof_level {
            arg(&mut args, "-proof-level", proof_level.clone());
        }
        args
    }
}

/// Environment `mina-rosetta` needs: it refuses to start without a database
/// pool size, and has no default for it. A local postgres allows 100
/// connections, shared with the archive.
pub const ROSETTA_ENV: &[(&str, &str)] = &[("MINA_ROSETTA_MAX_DB_POOL_SIZE", "16")];

/// Arguments of `mina-rosetta`: the API on `client_port`, data from the archive
/// database `archive_uri` and from the GraphQL API of `rosetta_graphql_node`.
pub fn rosetta_args(
    service: &ServiceConfig,
    layout: &Layout,
    archive_uri: &str,
) -> io::Result<Vec<String>> {
    let missing = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("rosetta '{}' has no {what}", service.service_name),
        )
    };
    let port = service.client_port.ok_or_else(|| missing("client_port"))?;
    let node = service
        .rosetta_graphql_node
        .as_deref()
        .ok_or_else(|| missing("rosetta_graphql_node"))?;
    let graphql_port = service
        .rosetta_graphql_port
        .ok_or_else(|| missing("rosetta_graphql_port"))?;
    let mut args = Vec::new();
    arg(&mut args, "--port", port.to_string());
    arg(&mut args, "--archive-uri", archive_uri);
    arg(
        &mut args,
        "--graphql-uri",
        format!("http://{}:{graphql_port}/graphql", layout.host(node)),
    );
    args.push("--log-json".to_string());
    arg(&mut args, "--log-level", "Info");
    Ok(args)
}

/// Arguments of `mina` for a daemon service or snark worker.
pub fn mina_args(service: &ServiceConfig, layout: &Layout) -> io::Result<Vec<String>> {
    match service.service_type {
        ServiceType::SnarkWorker => Ok(layout.snark_worker(service)),
        _ => layout.daemon(service),
    }
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

    fn service(service_type: ServiceType, name: &str) -> ServiceConfig {
        ServiceConfig {
            service_type,
            service_name: name.into(),
            client_port: Some(4000),
            libp2p_keypair: Some("kp".into()),
            peers: Some(vec!["/ip4/127.0.0.1/tcp/3102/p2p/x".into()]),
            ..Default::default()
        }
    }

    #[test]
    fn ports_follow_the_client_port() {
        let args = mina_args(
            &service(ServiceType::Seed, "seed"),
            &layout(ExecutionMode::Docker),
        )
        .unwrap();
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
        let bp = service(ServiceType::BlockProducer, "bp");
        let native = mina_args(&bp, &layout(ExecutionMode::Native)).unwrap();
        assert_eq!(value_of(&native, "-external-ip"), Some("127.0.0.1"));
        let docker = mina_args(&bp, &layout(ExecutionMode::Docker)).unwrap();
        assert_eq!(value_of(&docker, "-external-ip"), None);
    }

    #[test]
    fn precomputed_blocks_go_to_a_directory_when_the_daemon_has_it() {
        let seed = service(ServiceType::Seed, "seed");
        let old = mina_args(&seed, &layout(ExecutionMode::Native)).unwrap();
        assert_eq!(
            value_of(&old, "-precomputed-blocks-file"),
            Some("/c/precomputed_blocks.log")
        );
        let mut new_layout = layout(ExecutionMode::Native);
        new_layout.features.precomputed_blocks_dir = true;
        let new = mina_args(&seed, &new_layout).unwrap();
        assert_eq!(
            value_of(&new, "-precomputed-blocks-dir"),
            Some("/c/precomputed_blocks")
        );
        assert_eq!(value_of(&new, "-precomputed-blocks-file"), None);
        assert!(!new.contains(&"-log-precomputed-blocks".to_string()));
    }

    #[test]
    fn block_producer_keys() {
        let mut bp = service(ServiceType::BlockProducer, "bp");
        let args = mina_args(&bp, &layout(ExecutionMode::Native)).unwrap();
        assert_eq!(value_of(&args, "-block-producer-key"), None);

        bp.public_key_path = Some("/n/network-keypairs/bp".into());
        let args = mina_args(&bp, &layout(ExecutionMode::Native)).unwrap();
        assert_eq!(
            value_of(&args, "-block-producer-key"),
            Some("/n/network-keypairs/bp")
        );

        bp.private_key_path = Some("topology/bp.json".into());
        let mut with_uptime = layout(ExecutionMode::Docker);
        with_uptime.uptime_service = Some("uptime-net");
        let args = mina_args(&bp, &with_uptime).unwrap();
        assert_eq!(
            value_of(&args, "-block-producer-key"),
            Some("/n/network-keypairs/bp.json")
        );
        assert_eq!(
            value_of(&args, "-uptime-submitter-key"),
            Some("/n/network-keypairs/bp.json")
        );
        assert_eq!(
            value_of(&args, "-uptime-url"),
            Some("http://uptime-net:8080/v1/submit")
        );
    }

    #[test]
    fn services_are_reached_by_compose_name_or_localhost() {
        let mut archive = service(ServiceType::ArchiveNode, "archive");
        archive.archive_port = Some(3086);
        let docker = mina_args(&archive, &layout(ExecutionMode::Docker)).unwrap();
        assert_eq!(
            value_of(&docker, "-archive-address"),
            Some("archive-service-net:3086")
        );
        let native = mina_args(&archive, &layout(ExecutionMode::Native)).unwrap();
        assert_eq!(
            value_of(&native, "-archive-address"),
            Some("127.0.0.1:3086")
        );

        let mut worker = service(ServiceType::SnarkWorker, "w");
        worker.snark_coordinator_host = Some("coord".into());
        worker.snark_coordinator_port = Some(7000);
        worker.snark_worker_proof_level = Some("none".into());
        let docker = mina_args(&worker, &layout(ExecutionMode::Docker)).unwrap();
        assert_eq!(docker[..2], ["internal", "snark-worker"]);
        assert_eq!(value_of(&docker, "-daemon-address"), Some("coord-net:7000"));
        assert_eq!(value_of(&docker, "-proof-level"), Some("none"));
        let native = mina_args(&worker, &layout(ExecutionMode::Native)).unwrap();
        assert_eq!(value_of(&native, "-daemon-address"), Some("127.0.0.1:7000"));
    }

    #[test]
    fn rosetta_reads_the_archive_and_a_daemon() {
        let rosetta = ServiceConfig {
            service_type: ServiceType::Rosetta,
            service_name: "rosetta".into(),
            client_port: Some(3087),
            rosetta_graphql_node: Some("archive".into()),
            rosetta_graphql_port: Some(3141),
            ..Default::default()
        };
        let native =
            rosetta_args(&rosetta, &layout(ExecutionMode::Native), "postgres://db/a").unwrap();
        assert_eq!(value_of(&native, "--port"), Some("3087"));
        assert_eq!(value_of(&native, "--archive-uri"), Some("postgres://db/a"));
        assert_eq!(
            value_of(&native, "--graphql-uri"),
            Some("http://127.0.0.1:3141/graphql")
        );
        let docker = rosetta_args(&rosetta, &layout(ExecutionMode::Docker), "pg").unwrap();
        assert_eq!(
            value_of(&docker, "--graphql-uri"),
            Some("http://archive-net:3141/graphql")
        );
        // not a daemon
        assert!(mina_args(&rosetta, &layout(ExecutionMode::Native)).is_err());

        let mut lost = rosetta.clone();
        lost.rosetta_graphql_node = None;
        let err = rosetta_args(&lost, &layout(ExecutionMode::Native), "pg").unwrap_err();
        assert!(err.to_string().contains("no rosetta_graphql_node"));
    }

    #[test]
    fn daemon_needs_a_client_port() {
        let mut seed = service(ServiceType::Seed, "seed");
        seed.client_port = None;
        let err = mina_args(&seed, &layout(ExecutionMode::Native)).unwrap_err();
        assert!(err.to_string().contains("'seed' has no client_port"));
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
