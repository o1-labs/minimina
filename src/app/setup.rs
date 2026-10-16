//! Genesis ledger, keys and service configs for `network create`.

use super::{
    Context, DEFAULT_ARCHIVE_DOCKER_IMAGE, DEFAULT_DAEMON_DOCKER_IMAGE, IMAGE_COMMIT_HASH,
};
use crate::{
    cli::{CreateNetworkArgs, ExecutionMode},
    genesis_ledger::default,
    keys::{KeysManager, NodeKey},
    native::keys::NativeKeysManager,
    service::{ServiceConfig, ServiceType},
    topology::Topology,
};
use anyhow::{bail, Context as _, Result};
use log::info;
use std::{collections::HashMap, path::Path};

/// Keys generated for the default network; `None` when a topology brings its own.
pub struct DefaultKeys {
    pub bp: HashMap<String, NodeKey>,
    pub libp2p: HashMap<String, NodeKey>,
}

/// Handles `network_id`'s genesis ledger
///
/// If no genesis ledger is provided, a default ledger will be generated
pub fn handle_genesis_ledger(
    ctx: &Context,
    cmd: &CreateNetworkArgs,
    network_id: &str,
) -> Result<Option<DefaultKeys>> {
    let dirs = &ctx.dirs;
    match &cmd.genesis_ledger {
        Some(genesis_ledger_path) => {
            info!(
                "Copying genesis ledger from '{}' to network directory.",
                genesis_ledger_path.display()
            );
            dirs.copy_genesis_ledger(network_id, genesis_ledger_path)?;
            dirs.overwrite_genesis_timestamp(network_id, genesis_ledger_path)?;
            Ok(None)
        }
        None => generate_default_genesis_ledger(ctx, &dirs.network_path(network_id)).map(Some),
    }
}

/// Generates a genesis ledger for the default network:
/// 1 seed, 2 bps, and a snark coordinator with one woker
fn generate_default_genesis_ledger(ctx: &Context, network_path: &Path) -> Result<DefaultKeys> {
    info!("Genesis ledger not provided. Generating default genesis ledger.");
    let all_services = [
        "mina-seed-1",
        "mina-bp-1",
        "mina-bp-2",
        "mina-snark-coordinator",
        "mina-snark-worker-1",
        "mina-archive",
    ];

    let (bp, libp2p) = match ctx.mode {
        ExecutionMode::Docker => {
            let keys = KeysManager::new(
                network_path,
                DEFAULT_DAEMON_DOCKER_IMAGE,
                ctx.runner.clone(),
            );
            (
                keys.generate_bp_key_pairs(&all_services),
                keys.generate_libp2p_key_pairs(&all_services),
            )
        }
        ExecutionMode::Native => {
            let keys = NativeKeysManager::new(network_path, ctx.bin_path()?, ctx.runner.clone());
            (
                keys.generate_bp_key_pairs(&all_services),
                keys.generate_libp2p_key_pairs(&all_services),
            )
        }
    };
    let keys = DefaultKeys {
        bp: bp.context("Failed to generate key pairs for mina services")?,
        libp2p: libp2p.context("Failed to generate libp2p key pairs for mina services")?,
    };

    default::LedgerGenerator::generate(network_path, &keys.bp)
        .context("Error generating default ledger")?;
    Ok(keys)
}

/// Creates service configs for the nodes specified in the topology file of the given `cmd`
pub fn handle_topology(
    ctx: &Context,
    cmd: &CreateNetworkArgs,
    network_id: &str,
    keys: Option<DefaultKeys>,
) -> Result<Vec<ServiceConfig>> {
    match &cmd.topology {
        Some(topology_path) => {
            info!(
                "Generating docker-compose based on provided topology '{}'.",
                topology_path.display()
            );

            std::fs::copy(topology_path, ctx.dirs.topology_file_path(network_id))?;
            create_services(ctx, topology_path, network_id)
        }
        None => {
            info!("Topology not provided. Generating docker-compose based on default topology.");
            let keys =
                keys.context("Failed to generate docker-compose.yaml. Keys not generated.")?;
            generate_default_topology(
                &keys,
                DEFAULT_DAEMON_DOCKER_IMAGE,
                DEFAULT_ARCHIVE_DOCKER_IMAGE,
                network_id,
                ctx.mode,
            )
        }
    }
}

/// Creates the list of docker service configs from the topology file at `topology_path`
/// using the seed nodes as the list of network peers (at least 1 seed node must be declared)
fn create_services(
    ctx: &Context,
    topology_path: &Path,
    network_id: &str,
) -> Result<Vec<ServiceConfig>> {
    let topology = Topology::new(topology_path).with_context(|| {
        format!(
            "Error occured while parsing the topology file:\npath: {}",
            topology_path.display()
        )
    })?;
    let dirs = &ctx.dirs;
    let services = topology.services(&dirs.peer_list_file(network_id));
    let peers: Vec<&ServiceConfig> = ServiceConfig::get_seeds(&services);
    dirs.create_peer_list_file(network_id, &peers, ctx.mode)?;
    if let Some(uptime_service_backend) = ServiceConfig::get_uptime_service_backend(&services) {
        dirs.copy_uptime_service_config(network_id, uptime_service_backend)
            .context("Failed to copy uptime service config")?;
        info!("Successfully copied uptime service config.");
    }
    if peers.is_empty() {
        bail!("There are no seed nodes declared in this network. You must include seed nodes.");
    }
    Ok(services)
}

/// Generates a topology file for the default network:
/// 1 seed, 2 bps, and a snark coordinator with one woker
fn generate_default_topology(
    keys: &DefaultKeys,
    docker_image: &str,
    docker_image_archive: &str,
    network_id: &str,
    mode: ExecutionMode,
) -> Result<Vec<ServiceConfig>> {
    let bp = |name: &str| {
        keys.bp
            .get(name)
            .with_context(|| format!("no block producer key generated for '{name}'"))
    };
    let libp2p = |name: &str| {
        keys.libp2p
            .get(name)
            .with_context(|| format!("no libp2p key generated for '{name}'"))
    };

    let seed_name = "mina-seed-1";
    let seed_keypair = &libp2p(seed_name)?.key_string;
    let libp2p_peerid = seed_keypair
        .split(',')
        .next_back()
        .filter(|id| !id.is_empty())
        .with_context(|| format!("malformed libp2p keypair for '{seed_name}'"))?;
    let peer = ServiceConfig::generate_peer(
        seed_name,
        network_id,
        libp2p_peerid,
        3102, //external port on my mina_seed_1 will be 3102
        mode,
    );

    let seed = ServiceConfig {
        service_type: ServiceType::Seed,
        service_name: seed_name.to_string(),
        docker_image: Some(docker_image.into()),
        client_port: Some(3100),
        libp2p_keypair: Some(seed_keypair.clone()),
        libp2p_peerid: Some(libp2p_peerid.to_string()),
        ..Default::default()
    };

    let block_producer = |name: &str, client_port: u16| -> Result<ServiceConfig> {
        Ok(ServiceConfig {
            service_type: ServiceType::BlockProducer,
            service_name: name.to_string(),
            docker_image: Some(docker_image.into()),
            client_port: Some(client_port),
            public_key: Some(bp(name)?.key_string.clone()),
            public_key_path: Some(bp(name)?.key_path.clone()),
            libp2p_keypair: Some(libp2p(name)?.key_string.clone()),
            peers: Some(vec![peer.clone()]),
            ..Default::default()
        })
    };
    let bp_1 = block_producer("mina-bp-1", 4000)?;
    let bp_2 = block_producer("mina-bp-2", 4005)?;

    let snark_coordinator_name = "mina-snark-coordinator";
    let snark_coordinator = ServiceConfig {
        service_type: ServiceType::SnarkCoordinator,
        service_name: snark_coordinator_name.to_string(),
        docker_image: Some(docker_image.into()),
        client_port: Some(7000),
        public_key: Some(bp(snark_coordinator_name)?.key_string.clone()),
        libp2p_keypair: Some(libp2p(snark_coordinator_name)?.key_string.clone()),
        peers: Some(vec![peer.clone()]),
        snark_coordinator_fees: Some("0.001".into()),
        worker_nodes: Some(1),
        ..Default::default()
    };

    let snark_worker_1 = ServiceConfig {
        service_type: ServiceType::SnarkWorker,
        service_name: "mina-snark-worker-1".to_string(),
        docker_image: Some(docker_image.into()),
        snark_coordinator_port: Some(7000),
        snark_worker_proof_level: Some("full".into()),
        snark_coordinator_host: Some(snark_coordinator.service_name.clone()),
        ..Default::default()
    };

    let archive_node_name = "mina-archive";
    let archive_node = ServiceConfig {
        service_type: ServiceType::ArchiveNode,
        service_name: archive_node_name.to_string(),
        docker_image: Some(docker_image.into()),
        client_port: Some(5005),
        public_key: Some(bp(archive_node_name)?.key_string.clone()),
        public_key_path: Some(bp(archive_node_name)?.key_path.clone()),
        libp2p_keypair: Some(libp2p(archive_node_name)?.key_string.clone()),
        peers: Some(vec![peer]),
        archive_docker_image: Some(docker_image_archive.into()),
        archive_schema_files: Some(vec![
            format!("https://raw.githubusercontent.com/MinaProtocol/mina/{IMAGE_COMMIT_HASH}/src/app/archive/zkapp_tables.sql"),
            format!("https://raw.githubusercontent.com/MinaProtocol/mina/{IMAGE_COMMIT_HASH}/src/app/archive/create_schema.sql"),
        ]),
        archive_port: Some(3086),
        ..Default::default()
    };

    Ok(vec![
        seed,
        bp_1,
        bp_2,
        snark_coordinator,
        snark_worker_1,
        archive_node,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> NodeKey {
        NodeKey {
            key_string: s.to_string(),
            key_path: format!("/keys/{s}"),
        }
    }

    fn default_keys() -> DefaultKeys {
        let names = [
            "mina-seed-1",
            "mina-bp-1",
            "mina-bp-2",
            "mina-snark-coordinator",
            "mina-snark-worker-1",
            "mina-archive",
        ];
        DefaultKeys {
            bp: names
                .iter()
                .map(|n| (n.to_string(), key(&format!("B62{n}"))))
                .collect(),
            libp2p: names
                .iter()
                .map(|n| (n.to_string(), key(&format!("enc,pub,peer-{n}"))))
                .collect(),
        }
    }

    #[test]
    fn default_topology_wires_seed_peer_into_every_daemon() {
        let services = generate_default_topology(
            &default_keys(),
            "daemon",
            "archive",
            "net",
            ExecutionMode::Docker,
        )
        .unwrap();
        let names: Vec<_> = services.iter().map(|s| s.service_name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "mina-seed-1",
                "mina-bp-1",
                "mina-bp-2",
                "mina-snark-coordinator",
                "mina-snark-worker-1",
                "mina-archive"
            ]
        );
        assert_eq!(
            services[0].libp2p_peerid.as_deref(),
            Some("peer-mina-seed-1")
        );
        let peer = ServiceConfig::generate_peer(
            "mina-seed-1",
            "net",
            "peer-mina-seed-1",
            3102,
            ExecutionMode::Docker,
        );
        for s in [&services[1], &services[2], &services[3], &services[5]] {
            assert_eq!(s.peers.as_deref(), Some(std::slice::from_ref(&peer)));
        }
        assert_eq!(services[1].public_key.as_deref(), Some("B62mina-bp-1"));
        assert_eq!(services[5].archive_docker_image.as_deref(), Some("archive"));
    }

    #[test]
    fn native_default_topology_dials_the_seed_on_localhost() {
        let services =
            generate_default_topology(&default_keys(), "d", "a", "net", ExecutionMode::Native)
                .unwrap();
        assert_eq!(
            services[1].peers.as_deref(),
            Some(&["/ip4/127.0.0.1/tcp/3102/p2p/peer-mina-seed-1".to_string()][..])
        );
    }

    #[test]
    fn default_topology_reports_missing_key() {
        let mut keys = default_keys();
        keys.bp.remove("mina-bp-2");
        let err =
            generate_default_topology(&keys, "d", "a", "net", ExecutionMode::Docker).unwrap_err();
        assert_eq!(
            err.to_string(),
            "no block producer key generated for 'mina-bp-2'"
        );
    }

    #[test]
    fn default_topology_rejects_malformed_seed_keypair() {
        let mut keys = default_keys();
        keys.libp2p.insert("mina-seed-1".into(), key("enc,pub,"));
        let err =
            generate_default_topology(&keys, "d", "a", "net", ExecutionMode::Docker).unwrap_err();
        assert!(err.to_string().contains("malformed libp2p keypair"));
    }
}
