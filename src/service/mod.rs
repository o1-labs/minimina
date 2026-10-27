//! # Service Module
//!
//! This module provides structures and methods to hold and manage configurations for different Mina daemons.
//! With these configurations, docker-compose files can be dynamically generated to deploy and manage nodes in the network.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::cli::ExecutionMode;
use crate::topology::GitBuild;

pub mod typed;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Default)]
pub enum ServiceType {
    #[serde(rename = "Seed_node")]
    Seed,
    #[default]
    #[serde(rename = "Block_producer")]
    BlockProducer,
    /// A daemon that follows the chain without producing blocks.
    #[serde(rename = "Plain_node")]
    PlainNode,
    #[serde(rename = "Snark_worker")]
    SnarkWorker,
    #[serde(rename = "Snark_coordinator")]
    SnarkCoordinator,
    #[serde(rename = "Archive_node")]
    ArchiveNode,
    #[serde(rename = "Uptime_service_backend")]
    UptimeServiceBackend,
    /// `mina-rosetta`: the Rosetta API on top of a daemon and the archive database.
    #[serde(rename = "Rosetta")]
    Rosetta,
    /// Archive Node API: GraphQL over the archive database (events, actions).
    #[serde(rename = "Archive_node_api")]
    ArchiveNodeApi,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub service_type: ServiceType,
    pub service_name: String,
    pub docker_image: Option<String>,
    pub git_build: Option<GitBuild>,
    pub client_port: Option<u16>,
    pub public_key: Option<String>,
    pub public_key_path: Option<String>,
    pub private_key: Option<String>,
    /// Path to the privkey file used by `mina daemon --block-producer-key KEYFILE ...`
    pub private_key_path: Option<PathBuf>,
    pub libp2p_keypair: Option<String>,
    /// Path to the libp2p keyfile used by `mina daemon --libp2p-keypair KEYFILE ...`
    pub libp2p_keypair_path: Option<PathBuf>,
    pub libp2p_peerid: Option<String>,
    pub peers: Option<Vec<String>>,
    /// Path to the file used by `mina daemon --peer-list-file PATH ...`
    pub peer_list_file: Option<PathBuf>,

    //snark coordinator specific
    pub snark_coordinator_fees: Option<String>,
    pub worker_nodes: Option<u16>,

    //snark worker specific
    pub snark_worker_proof_level: Option<String>,
    // on snark_worker -daemon-address <snark_coordinator_host>:<snark_coordinator_port>
    pub snark_coordinator_host: Option<String>,
    pub snark_coordinator_port: Option<u16>,

    //archive node specific
    pub archive_docker_image: Option<String>,
    pub archive_schema_files: Option<Vec<String>>,
    pub archive_port: Option<u16>,

    //rosetta specific: --port is client_port
    /// Daemon whose GraphQL API rosetta reads (`--graphql-uri`).
    pub rosetta_graphql_node: Option<String>,
    /// GraphQL (REST) port of that daemon.
    pub rosetta_graphql_port: Option<u16>,

    //archive node api specific: PORT is client_port
    pub archive_node_api_version: Option<String>,
    /// Native mode: the server's executable, resolved (and installed) at create.
    pub archive_node_api_bin: Option<PathBuf>,

    //uptime service backend specific
    pub uptime_service_backend_app_config: Option<PathBuf>,
    pub uptime_service_backend_minasheets: Option<PathBuf>,
    pub uptime_service_other_config_files: Option<Vec<PathBuf>>,
}

/// A problem of one service of a network, found by [`typed::check`].
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("'{service}' has no {field}")]
    MissingField {
        service: String,
        field: &'static str,
    },
    #[error("'{service}': client_port {port} leaves no room for its 5 ports")]
    PortRange { service: String, port: u16 },
    #[error("two services are called '{service}'")]
    Duplicate { service: String },
    #[error("{} {kind}s: {}; a network has one at most", services.len(), services.join(", "))]
    TooMany {
        kind: &'static str,
        services: Vec<String>,
    },
    #[error("'{service}': {field} '{target}' is not a {what} of the network")]
    NotFound {
        service: String,
        field: &'static str,
        target: String,
        what: &'static str,
    },
    #[error("'{service}' needs an archive node")]
    NeedsArchive { service: String },
}

impl ServiceConfig {
    /// libp2p address of a seed: its compose service name in docker mode,
    /// localhost in native mode (every node shares the host).
    pub fn generate_peer(
        seed_name: &str,
        network_name: &str,
        libp2p_peerid: &str,
        external_port: u16,
        mode: ExecutionMode,
    ) -> String {
        let host = match mode {
            ExecutionMode::Docker => format!("dns4/{seed_name}-{network_name}"),
            ExecutionMode::Native => "ip4/127.0.0.1".to_string(),
        };
        format!("/{host}/tcp/{external_port}/p2p/{libp2p_peerid}")
    }

    pub fn get_seeds(services: &[Self]) -> Vec<&Self> {
        services
            .iter()
            .filter(|service| ServiceType::Seed == service.service_type)
            .collect()
    }

    /// The first archive node; [`typed::check`] reports a second one.
    pub fn get_archive_node(services: &[Self]) -> Option<&Self> {
        services
            .iter()
            .find(|s| s.service_type == ServiceType::ArchiveNode)
    }

    /// The first uptime service backend; [`typed::check`] reports a second one.
    pub fn get_uptime_service_backend(services: &[Self]) -> Option<&Self> {
        services
            .iter()
            .find(|s| s.service_type == ServiceType::UptimeServiceBackend)
    }
}
