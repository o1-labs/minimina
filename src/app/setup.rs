//! Genesis ledger, keys and service configs for `network create`.

use super::{
    inputs::CreateInputs, Context, DEFAULT_ARCHIVE_DOCKER_IMAGE, DEFAULT_DAEMON_DOCKER_IMAGE,
    DEFAULT_ROSETTA_DOCKER_IMAGE, IMAGE_COMMIT_HASH,
};
use crate::{
    accounts_manager::{self, AccountsManagerError, GeneratedAccount, KeyPair},
    archive_node_api,
    cli::ExecutionMode,
    genesis_ledger::default,
    install::{mina::Fetch, Installer},
    keys::{KeysManager, NodeKey},
    native::keys::NativeKeysManager,
    service::{ServiceConfig, ServiceType},
    spec::{
        ledger::{Balance, LedgerAccount, PublicKey},
        NetworkSpec, PlannedNode, Role, DEFAULT_ACCOUNT_BALANCE, DEFAULT_SNARK_WORK_FEE,
    },
};
use anyhow::{Context as _, Result};
use log::info;
use std::{collections::HashMap, path::Path};

/// A network generated from a spec: its nodes and the keys made for them.
pub struct SpecNetwork {
    pub spec: NetworkSpec,
    pub nodes: Vec<PlannedNode>,
    /// Block producer key pairs, by node or account name.
    pub bp: HashMap<String, NodeKey>,
    /// libp2p key pairs, by node name.
    pub libp2p: HashMap<String, NodeKey>,
}

/// Services of a spec network: its keys and genesis ledger are generated, and
/// the spec as resolved is kept to create the network again with --spec.
pub fn spec_network(
    ctx: &Context,
    inputs: CreateInputs,
    network_id: &str,
) -> Result<Vec<ServiceConfig>> {
    std::fs::write(ctx.dirs.spec_path(network_id), inputs.spec.to_toml()?)
        .context("writing the network spec")?;
    let network = generate_from_spec(ctx, &ctx.dirs.network_path(network_id), inputs)?;
    let services = spec_services(&network, network_id, ctx.mode)?;
    if let Some(backend) = ServiceConfig::get_uptime_service_backend(&services) {
        ctx.dirs
            .copy_uptime_service_config(network_id, backend)
            .context("Failed to copy uptime service config")?;
    }
    Ok(services)
}

/// Generates the keys of every node and the genesis ledger of a spec network.
fn generate_from_spec(
    ctx: &Context,
    network_path: &Path,
    inputs: CreateInputs,
) -> Result<SpecNetwork> {
    let CreateInputs { spec, nodes, given } = inputs;
    let accounts_manager = nodes.iter().find(|n| n.role == Role::AccountsManager);
    if accounts_manager.is_some() && ctx.mode == ExecutionMode::Docker {
        return Err(AccountsManagerError::DockerMode.into());
    }
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

    let pk = |name: &str| -> Result<PublicKey> {
        let key = bp
            .get(name)
            .with_context(|| format!("no key generated for '{name}'"))?;
        key.key_string
            .parse()
            .with_context(|| format!("the key generated for '{name}'"))
    };
    let account_balance = spec
        .ledger
        .balance
        .clone()
        .unwrap_or(Balance::mina(DEFAULT_ACCOUNT_BALANCE));
    // the accounts of the ledger file first, then the generated ones
    if let Some(manager) = accounts_manager {
        let keys = NativeKeysManager::new(
            network_path,
            ctx.bin_path()?,
            ctx.profile,
            ctx.runner.clone(),
        );
        let generated = accounts
            .iter()
            .map(|name| -> Result<GeneratedAccount> {
                let key = bp
                    .get(name)
                    .with_context(|| format!("no key generated for '{name}'"))?;
                let sk =
                    keys.private_key(name)
                        .map_err(|cause| AccountsManagerError::PrivateKey {
                            account: name.clone(),
                            cause: cause.into(),
                        })?;
                Ok(GeneratedAccount {
                    pair: KeyPair { pk: pk(name)?, sk },
                    key_file: key.key_path.clone().into(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let ledger =
            accounts_manager::prepare(network_path, &given, &generated, manager.keys.as_deref())?;
        info!(
            "The accounts manager has {} accounts; it keeps {} of them unused.",
            ledger.served(),
            accounts_manager::ACCOUNTS_KEPT
        );
    }
    let mut ledger = given;
    for node in &nodes {
        if let Some(balance) = &node.balance {
            ledger.push(LedgerAccount::new(pk(&node.name)?, balance.clone()));
        }
    }
    for account in &accounts {
        ledger.push(LedgerAccount::new(pk(account)?, account_balance.clone()));
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

/// Installs the accounts manager (native mode; docker mode refuses it at
/// create): its release binary once into `~/.minimina/.tools`, or the
/// executable the spec names, recorded in the service.
pub fn install_accounts_manager(
    ctx: &Context,
    services: &mut [ServiceConfig],
    fetch: &dyn Fetch,
) -> Result<()> {
    for service in services
        .iter_mut()
        .filter(|s| s.service_type == ServiceType::AccountsManager)
    {
        let version = service
            .accounts_manager_version
            .clone()
            .unwrap_or_else(|| accounts_manager::DEFAULT_VERSION.to_string());
        let bin = accounts_manager::install::resolve(
            &ctx.dirs.tools_root(),
            &version,
            service.accounts_manager_bin.as_deref(),
            fetch,
        )
        .with_context(|| format!("preparing '{}'", service.service_name))?;
        service.accounts_manager_bin = Some(bin);
    }
    Ok(())
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
    for seed in net.nodes.iter().filter(|n| n.role.is_seed()) {
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
                peers: (!node.role.is_seed()).then(|| peers.clone()),
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
            Role::Standalone => ServiceConfig {
                libp2p_peerid: Some(peer_id(&node.name)?),
                public_key_path: key.map(|k| k.key_path.clone()),
                snark_worker_fee: node.fee.clone().or(Some(DEFAULT_SNARK_WORK_FEE.into())),
                ..with_archive(daemon(ServiceType::Standalone)?, node, archive_image)
            },
            Role::SnarkCoordinator => ServiceConfig {
                snark_coordinator_fees: node.fee.clone().or(Some(DEFAULT_SNARK_WORK_FEE.into())),
                worker_nodes: Some(node.workers.len() as u16),
                ..daemon(ServiceType::SnarkCoordinator)?
            },
            Role::Archive => with_archive(daemon(ServiceType::ArchiveNode)?, node, archive_image),
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
            Role::AccountsManager => {
                let (daemon, daemon_port) = node.graphql_node.clone().with_context(|| {
                    format!("accounts manager '{}' has no daemon to ask", node.name)
                })?;
                ServiceConfig {
                    service_type: ServiceType::AccountsManager,
                    service_name: node.name.clone(),
                    client_port: Some(node.client_port),
                    accounts_manager_version: Some(
                        node.version
                            .clone()
                            .unwrap_or_else(|| accounts_manager::DEFAULT_VERSION.to_string()),
                    ),
                    accounts_manager_bin: node.bin.clone(),
                    accounts_manager_node: Some(daemon),
                    accounts_manager_graphql_port: Some(daemon_port + 1),
                    ..Default::default()
                }
            }
            Role::UptimeServiceBackend => {
                let files = node
                    .uptime
                    .as_ref()
                    .with_context(|| format!("'{}' has no uptime files", node.name))?;
                ServiceConfig {
                    service_type: ServiceType::UptimeServiceBackend,
                    service_name: node.name.clone(),
                    docker_image: net.spec.docker.uptime_service_backend_image.clone(),
                    uptime_service_backend_app_config: Some(files.app_config.clone()),
                    uptime_service_backend_minasheets: Some(files.minasheets.clone()),
                    uptime_service_other_config_files: Some(files.config_files.clone()),
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

/// `daemon` with the `mina-archive` of `node`, when it runs one: its port,
/// image and schema.
fn with_archive(daemon: ServiceConfig, node: &PlannedNode, archive_image: &str) -> ServiceConfig {
    if !node.runs_archive() {
        return daemon;
    }
    ServiceConfig {
        archive_docker_image: Some(archive_image.into()),
        // replaced by the archive package's own copy when it has one
        archive_schema_files: Some(vec![format!(
            "https://raw.githubusercontent.com/MinaProtocol/mina/{IMAGE_COMMIT_HASH}/src/app/archive/create_schema.sql"
        )]),
        archive_port: node.archive_port,
        ..daemon
    }
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
    fn archive_node_attaches_to_the_standalone_daemon() {
        let spec: NetworkSpec = toml::from_str(
            r#"
            [[nodes]]
            role = "standalone"
            client_port = 3084

            [[nodes]]
            role = "archive"

            [[nodes]]
            role = "rosetta"
            "#,
        )
        .unwrap();
        let services = spec_services(&generated(spec), "net", ExecutionMode::Native).unwrap();
        // the archive node is no service of its own: the standalone daemon runs it
        let (solo, rosetta) = (&services[0], &services[1]);
        assert_eq!(services.len(), 2);
        assert_eq!(solo.service_type, ServiceType::Standalone);
        assert_eq!(solo.libp2p_peerid.as_deref(), Some("peer-standalone-1"));
        assert_eq!(solo.peers, None);
        assert_eq!(solo.public_key.as_deref(), Some("B62standalone-1"));
        assert_eq!(
            solo.public_key_path.as_deref(),
            Some("/keys/B62standalone-1")
        );
        assert_eq!(
            solo.snark_worker_fee.as_deref(),
            Some(DEFAULT_SNARK_WORK_FEE)
        );
        // mina-archive on client port + 5, with the schema the archive node gets
        assert_eq!(solo.archive_port, Some(3089));
        assert!(solo.archive_schema_files.is_some());
        assert_eq!(
            ServiceConfig::get_archive_node(&services).map(|s| s.service_name.as_str()),
            Some("standalone-1")
        );
        // rosetta reads the daemon that runs the archive
        assert_eq!(
            rosetta.rosetta_graphql_node.as_deref(),
            Some("standalone-1")
        );
        assert_eq!(rosetta.rosetta_graphql_port, Some(3085));
        crate::service::typed::check::<crate::service::typed::Native>(&services).unwrap();
    }

    #[test]
    fn standalone_without_archive_runs_none() {
        let spec: NetworkSpec = toml::from_str(
            r#"
            [[nodes]]
            role = "standalone"
            "#,
        )
        .unwrap();
        let services = spec_services(&generated(spec), "net", ExecutionMode::Native).unwrap();
        assert_eq!(services[0].archive_port, None);
        assert_eq!(services[0].archive_schema_files, None);
        assert!(ServiceConfig::get_archive_node(&services).is_none());
    }

    #[test]
    fn accounts_manager_service_asks_its_daemon() {
        let spec: NetworkSpec = toml::from_str(
            r#"
            [[nodes]]
            role = "seed"

            [[nodes]]
            role = "accounts-manager"
            client_port = 8181
            "#,
        )
        .unwrap();
        let services = spec_services(&generated(spec), "net", ExecutionMode::Native).unwrap();
        let manager = &services[1];
        assert_eq!(manager.service_type, ServiceType::AccountsManager);
        assert_eq!(manager.client_port, Some(8181));
        assert_eq!(manager.accounts_manager_node.as_deref(), Some("seed-1"));
        assert_eq!(manager.accounts_manager_graphql_port, Some(3101));
        assert_eq!(
            manager.accounts_manager_version.as_deref(),
            Some(accounts_manager::DEFAULT_VERSION)
        );
        assert_eq!(manager.libp2p_keypair, None);
        assert_eq!(
            manager.to_node_info().accounts_manager_uri.as_deref(),
            Some("http://localhost:8181")
        );
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
