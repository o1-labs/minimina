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
    spec::{NetworkSpec, PlannedNode, Role},
    topology::Topology,
};
use anyhow::{bail, Context as _, Result};
use log::info;
use std::{collections::HashMap, path::Path};

/// Balance of the funded test accounts of a spec that sets none.
const DEFAULT_ACCOUNT_BALANCE: &str = "1000";

/// A network generated from a spec: its nodes and the keys made for them.
pub struct SpecNetwork {
    pub spec: NetworkSpec,
    pub nodes: Vec<PlannedNode>,
    /// Block producer key pairs, by node or account name.
    pub bp: HashMap<String, NodeKey>,
    /// libp2p key pairs, by node name.
    pub libp2p: HashMap<String, NodeKey>,
}

/// The spec of `network create`: `--spec`, else the default network.
pub fn create_spec(cmd: &CreateNetworkArgs) -> Result<NetworkSpec> {
    cmd.spec
        .as_deref()
        .map(NetworkSpec::load)
        .unwrap_or_else(|| Ok(NetworkSpec::default_network()))
}

/// Handles `network_id`'s genesis ledger: copies the given one, or generates
/// keys and a ledger from the spec. `None` when a topology brings its own keys.
pub fn handle_genesis_ledger(
    ctx: &Context,
    cmd: &CreateNetworkArgs,
    network_id: &str,
) -> Result<Option<SpecNetwork>> {
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
        None => {
            let network_path = dirs.network_path(network_id);
            if let Some(spec_path) = &cmd.spec {
                std::fs::copy(spec_path, network_path.join("network.toml"))
                    .with_context(|| format!("copying {}", spec_path.display()))?;
            }
            generate_from_spec(ctx, &network_path, create_spec(cmd)?).map(Some)
        }
    }
}

/// Generates the keys of every node and the genesis ledger of a spec network.
fn generate_from_spec(
    ctx: &Context,
    network_path: &Path,
    spec: NetworkSpec,
) -> Result<SpecNetwork> {
    let nodes = spec.plan()?;
    let daemons: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
    let accounts = spec.ledger_accounts();
    let with_keys: Vec<&str> = nodes
        .iter()
        .filter(|n| n.needs_key())
        .map(|n| n.name.as_str())
        .chain(accounts.iter().map(String::as_str))
        .collect();
    info!(
        "Generating keys for {} nodes and {} accounts.",
        daemons.len(),
        accounts.len()
    );

    let (bp, libp2p) = match ctx.mode {
        ExecutionMode::Docker => {
            let image = spec
                .docker
                .daemon_image
                .as_deref()
                .unwrap_or(DEFAULT_DAEMON_DOCKER_IMAGE);
            let keys = KeysManager::new(network_path, image, ctx.profile, ctx.runner.clone());
            (
                keys.generate_bp_key_pairs(&with_keys),
                keys.generate_libp2p_key_pairs(&daemons),
            )
        }
        ExecutionMode::Native => {
            let keys = NativeKeysManager::new(
                network_path,
                ctx.bin_path()?,
                ctx.profile,
                ctx.runner.clone(),
            );
            (
                keys.generate_bp_key_pairs(&with_keys),
                keys.generate_libp2p_key_pairs(&daemons),
            )
        }
    };
    let bp = bp.context("Failed to generate key pairs for mina services")?;
    let libp2p = libp2p.context("Failed to generate libp2p key pairs for mina services")?;

    let pk = |name: &str| {
        bp.get(name)
            .map(|k| k.key_string.clone())
            .with_context(|| format!("no key generated for '{name}'"))
    };
    let account_balance = spec
        .ledger
        .balance
        .as_deref()
        .unwrap_or(DEFAULT_ACCOUNT_BALANCE);
    let mut ledger = Vec::new();
    for node in &nodes {
        if let Some(balance) = &node.balance {
            ledger.push((pk(&node.name)?, balance.clone()));
        }
    }
    for account in &accounts {
        ledger.push((pk(account)?, account_balance.to_string()));
    }
    default::LedgerGenerator::generate(network_path, &ledger, spec.runtime_config_json()?.as_ref())
        .context("Error generating genesis ledger")?;

    Ok(SpecNetwork {
        spec,
        nodes,
        bp,
        libp2p,
    })
}

/// Creates service configs for the nodes specified in the topology file of the given `cmd`
pub fn handle_topology(
    ctx: &Context,
    cmd: &CreateNetworkArgs,
    network_id: &str,
    generated: Option<SpecNetwork>,
) -> Result<Vec<ServiceConfig>> {
    match &cmd.topology {
        Some(topology_path) => {
            info!(
                "Generating services from the topology '{}'.",
                topology_path.display()
            );

            std::fs::copy(topology_path, ctx.dirs.topology_file_path(network_id))?;
            create_services(ctx, topology_path, network_id)
        }
        None => {
            let generated = generated.context("Keys of the network spec were not generated.")?;
            spec_services(&generated, network_id, ctx.mode)
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

/// Service configs of a spec network; every non-seed daemon dials every seed.
fn spec_services(
    net: &SpecNetwork,
    network_id: &str,
    mode: ExecutionMode,
) -> Result<Vec<ServiceConfig>> {
    let docker_image = net
        .spec
        .docker
        .daemon_image
        .as_deref()
        .unwrap_or(DEFAULT_DAEMON_DOCKER_IMAGE);
    let archive_image = net
        .spec
        .docker
        .archive_image
        .as_deref()
        .unwrap_or(DEFAULT_ARCHIVE_DOCKER_IMAGE);
    let libp2p = |name: &str| {
        net.libp2p
            .get(name)
            .with_context(|| format!("no libp2p key generated for '{name}'"))
    };
    let peer_id = |name: &str| -> Result<String> {
        libp2p(name)?
            .key_string
            .split(',')
            .next_back()
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .with_context(|| format!("malformed libp2p keypair for '{name}'"))
    };

    let mut peers = Vec::new();
    for seed in net.nodes.iter().filter(|n| n.role == Role::Seed) {
        peers.push(ServiceConfig::generate_peer(
            &seed.name,
            network_id,
            &peer_id(&seed.name)?,
            seed.client_port + 2, // external port
            mode,
        ));
    }

    let mut services = Vec::new();
    for node in &net.nodes {
        let key = net.bp.get(&node.name);
        let mut service = ServiceConfig {
            service_name: node.name.clone(),
            docker_image: Some(docker_image.into()),
            client_port: Some(node.client_port),
            public_key: key.map(|k| k.key_string.clone()),
            libp2p_keypair: Some(libp2p(&node.name)?.key_string.clone()),
            ..Default::default()
        };
        match node.role {
            Role::Seed => {
                service.service_type = ServiceType::Seed;
                service.libp2p_peerid = Some(peer_id(&node.name)?);
            }
            Role::BlockProducer => {
                service.service_type = ServiceType::BlockProducer;
                service.public_key_path = key.map(|k| k.key_path.clone());
                service.peers = Some(peers.clone());
            }
            Role::Plain => {
                service.service_type = ServiceType::PlainNode;
                service.peers = Some(peers.clone());
            }
            Role::SnarkCoordinator => {
                service.service_type = ServiceType::SnarkCoordinator;
                service.peers = Some(peers.clone());
                service.snark_coordinator_fees = node.fee.clone().or(Some("0.001".into()));
                service.worker_nodes = Some(node.workers.len() as u16);
            }
            Role::Archive => {
                service.service_type = ServiceType::ArchiveNode;
                service.peers = Some(peers.clone());
                service.archive_docker_image = Some(archive_image.into());
                // replaced by the archive package's own copy when it has one
                service.archive_schema_files = Some(vec![format!(
                    "https://raw.githubusercontent.com/MinaProtocol/mina/{IMAGE_COMMIT_HASH}/src/app/archive/create_schema.sql"
                )]);
                service.archive_port = node.archive_port;
            }
        }
        services.push(service);
        for worker in &node.workers {
            services.push(ServiceConfig {
                service_type: ServiceType::SnarkWorker,
                service_name: worker.clone(),
                docker_image: Some(docker_image.into()),
                snark_coordinator_host: Some(node.name.clone()),
                snark_coordinator_port: Some(node.client_port),
                ..Default::default()
            });
        }
    }
    Ok(services)
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

    fn generated(spec: NetworkSpec) -> SpecNetwork {
        let nodes = spec.plan().unwrap();
        let names: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        SpecNetwork {
            bp: nodes
                .iter()
                .filter(|n| n.needs_key())
                .map(|n| (n.name.clone(), key(&format!("B62{}", n.name))))
                .collect(),
            libp2p: names
                .iter()
                .map(|n| (n.clone(), key(&format!("enc,pub,peer-{n}"))))
                .collect(),
            spec,
            nodes,
        }
    }

    #[test]
    fn default_network_wires_seed_peer_into_every_daemon() {
        let services = spec_services(
            &generated(NetworkSpec::default_network()),
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
        assert_eq!(
            services[1].public_key_path.as_deref(),
            Some("/keys/B62mina-bp-1")
        );
        assert_eq!(
            services[4].snark_coordinator_host.as_deref(),
            Some("mina-snark-coordinator")
        );
        assert_eq!(services[4].snark_coordinator_port, Some(7000));
        // the worker uses the profile's compiled proof level
        assert_eq!(services[4].snark_worker_proof_level, None);
        assert_eq!(
            services[5].archive_docker_image.as_deref(),
            Some(DEFAULT_ARCHIVE_DOCKER_IMAGE)
        );
        assert_eq!(services[5].archive_port, Some(3086));
    }

    #[test]
    fn native_spec_network_dials_the_seed_on_localhost() {
        let spec: NetworkSpec = toml::from_str(
            "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"plain\"\n[docker]\ndaemon_image = \"img\"",
        )
        .unwrap();
        let services = spec_services(&generated(spec), "net", ExecutionMode::Native).unwrap();
        assert_eq!(services[1].service_type, ServiceType::PlainNode);
        assert_eq!(
            services[1].peers.as_deref(),
            Some(&["/ip4/127.0.0.1/tcp/3102/p2p/peer-seed-1".to_string()][..])
        );
        assert_eq!(services[1].public_key, None);
        assert_eq!(services[1].docker_image.as_deref(), Some("img"));
    }

    #[test]
    fn spec_network_reports_malformed_seed_keypair() {
        let mut net = generated(NetworkSpec::default_network());
        net.libp2p.insert("mina-seed-1".into(), key("enc,pub,"));
        let err = spec_services(&net, "net", ExecutionMode::Docker).unwrap_err();
        assert!(err.to_string().contains("malformed libp2p keypair"));
    }
}
