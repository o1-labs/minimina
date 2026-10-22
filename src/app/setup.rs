//! Genesis ledger, keys and service configs for `network create`.

use super::{
    Context, DEFAULT_ARCHIVE_DOCKER_IMAGE, DEFAULT_DAEMON_DOCKER_IMAGE,
    DEFAULT_ROSETTA_DOCKER_IMAGE, IMAGE_COMMIT_HASH,
};
use crate::{
    archive_node_api,
    cli::{CreateNetworkArgs, ExecutionMode},
    genesis_ledger::default,
    install::Installer,
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
    let daemons: Vec<&str> = nodes
        .iter()
        .filter(|n| n.is_daemon())
        .map(|n| n.name.as_str())
        .collect();
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

/// Installs what the archive node api needs to run.
///
/// Both modes run it. Docker mode runs its image
/// (`ghcr.io/o1-labs/archive-node-api:<version>`, see `docker/compose.rs`) and
/// needs nothing here. Native mode runs the npm package: this checks Node.js,
/// installs the package once per version into `~/.minimina/.tools`, and records
/// the executable in the service.
pub fn install_archive_node_api(ctx: &Context, services: &mut [ServiceConfig]) -> Result<()> {
    if ctx.mode == ExecutionMode::Docker {
        // the compose service runs the image
        return Ok(());
    }
    let installer = Installer::new(ctx.dirs.tools_root(), ctx.runner.as_ref());
    for service in services
        .iter_mut()
        .filter(|s| s.service_type == ServiceType::ArchiveNodeApi)
    {
        let version = service
            .archive_node_api_version
            .clone()
            .unwrap_or_else(|| archive_node_api::DEFAULT_VERSION.to_string());
        let bin = installer
            .npm_app(
                &archive_node_api::APP,
                &version,
                service.archive_node_api_bin.as_deref(),
            )
            .with_context(|| format!("preparing '{}'", service.service_name))?;
        service.archive_node_api_bin = Some(bin);
    }
    Ok(())
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

    let rosetta_image = net
        .spec
        .docker
        .rosetta_image
        .as_deref()
        .unwrap_or(DEFAULT_ROSETTA_DOCKER_IMAGE);

    let mut services = Vec::new();
    for node in &net.nodes {
        let key = net.bp.get(&node.name);
        let daemon = |service_type| -> Result<ServiceConfig> {
            Ok(ServiceConfig {
                service_type,
                service_name: node.name.clone(),
                docker_image: Some(docker_image.into()),
                client_port: Some(node.client_port),
                public_key: key.map(|k| k.key_string.clone()),
                libp2p_keypair: Some(libp2p(&node.name)?.key_string.clone()),
                peers: (service_type != ServiceType::Seed).then(|| peers.clone()),
                ..Default::default()
            })
        };
        let service = match node.role {
            Role::Seed => ServiceConfig {
                libp2p_peerid: Some(peer_id(&node.name)?),
                ..daemon(ServiceType::Seed)?
            },
            Role::BlockProducer => ServiceConfig {
                public_key_path: key.map(|k| k.key_path.clone()),
                ..daemon(ServiceType::BlockProducer)?
            },
            Role::Plain => daemon(ServiceType::PlainNode)?,
            Role::SnarkCoordinator => ServiceConfig {
                snark_coordinator_fees: node.fee.clone().or(Some("0.001".into())),
                worker_nodes: Some(node.workers.len() as u16),
                ..daemon(ServiceType::SnarkCoordinator)?
            },
            Role::Archive => ServiceConfig {
                archive_docker_image: Some(archive_image.into()),
                // replaced by the archive package's own copy when it has one
                archive_schema_files: Some(vec![format!(
                    "https://raw.githubusercontent.com/MinaProtocol/mina/{IMAGE_COMMIT_HASH}/src/app/archive/create_schema.sql"
                )]),
                archive_port: node.archive_port,
                ..daemon(ServiceType::ArchiveNode)?
            },
            Role::ArchiveNodeApi => {
                let version = node
                    .version
                    .clone()
                    .unwrap_or_else(|| archive_node_api::DEFAULT_VERSION.to_string());
                let image = net
                    .spec
                    .docker
                    .archive_node_api_image
                    .clone()
                    .unwrap_or_else(|| archive_node_api::docker_image(&version));
                ServiceConfig {
                    service_type: ServiceType::ArchiveNodeApi,
                    service_name: node.name.clone(),
                    docker_image: Some(image),
                    client_port: Some(node.client_port),
                    archive_node_api_version: Some(version),
                    archive_node_api_bin: node.bin.clone(),
                    ..Default::default()
                }
            }
            Role::Rosetta => {
                let (graphql_node, client_port) = node
                    .graphql_node
                    .clone()
                    .with_context(|| format!("rosetta '{}' has no daemon to read", node.name))?;
                ServiceConfig {
                    service_type: ServiceType::Rosetta,
                    service_name: node.name.clone(),
                    docker_image: Some(rosetta_image.into()),
                    client_port: Some(node.client_port),
                    rosetta_graphql_node: Some(graphql_node),
                    rosetta_graphql_port: Some(client_port + 1),
                    ..Default::default()
                }
            }
        };
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
        let names: Vec<String> = nodes
            .iter()
            .filter(|n| n.is_daemon())
            .map(|n| n.name.clone())
            .collect();
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
    fn rosetta_service_points_at_the_daemon_graphql_port() {
        let spec: NetworkSpec = toml::from_str(
            "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"archive\"\n[[nodes]]\nrole = \"rosetta\"",
        )
        .unwrap();
        let net = generated(spec);
        assert!(!net.libp2p.contains_key("rosetta-1"));
        let services = spec_services(&net, "net", ExecutionMode::Native).unwrap();
        let rosetta = &services[2];
        assert_eq!(rosetta.service_type, ServiceType::Rosetta);
        assert_eq!(rosetta.client_port, Some(3120));
        assert_eq!(rosetta.rosetta_graphql_node.as_deref(), Some("archive"));
        assert_eq!(rosetta.rosetta_graphql_port, Some(3111));
        assert_eq!(
            rosetta.docker_image.as_deref(),
            Some(DEFAULT_ROSETTA_DOCKER_IMAGE)
        );
        assert_eq!(rosetta.libp2p_keypair, None);
        assert_eq!(rosetta.peers, None);
    }

    #[test]
    fn archive_node_api_service_carries_version_and_image() {
        let spec: NetworkSpec = toml::from_str(
            "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"archive\"\n[[nodes]]\nrole = \"archive-node-api\"",
        )
        .unwrap();
        let services = spec_services(&generated(spec), "net", ExecutionMode::Docker).unwrap();
        let api = &services[2];
        assert_eq!(api.service_type, ServiceType::ArchiveNodeApi);
        assert_eq!(api.client_port, Some(3120));
        assert_eq!(api.archive_node_api_version.as_deref(), Some("2.0.0"));
        assert_eq!(
            api.docker_image.as_deref(),
            Some("ghcr.io/o1-labs/archive-node-api:2.0.0")
        );
        assert_eq!(api.libp2p_keypair, None);
    }

    #[test]
    fn spec_network_reports_malformed_seed_keypair() {
        let mut net = generated(NetworkSpec::default_network());
        net.libp2p.insert("mina-seed-1".into(), key("enc,pub,"));
        let err = spec_services(&net, "net", ExecutionMode::Docker).unwrap_err();
        assert!(err.to_string().contains("malformed libp2p keypair"));
    }
}
