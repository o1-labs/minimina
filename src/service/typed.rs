//! Services with exactly the fields their kind needs, checked once.
//!
//! [`ServiceConfig`] is the format of `services.json` and of Lucy topologies:
//! one flat record in which every field is optional. [`check`] turns the
//! records of a network into [`Service`]s and reports every missing or
//! inconsistent field of every service at once. It runs at `network create`
//! and when a command loads `services.json`, so a broken network fails before
//! a process starts, and the code that starts processes cannot ask for a
//! field that is not there.
//!
//! What a service needs depends on the execution mode: docker mode runs
//! images, native mode runs the host's binaries. [`Mode`] puts that difference
//! in the types: a `Service<Docker>` has its images, a `Service<Native>` has
//! none.

use super::{ServiceConfig, ServiceError, ServiceType};
use crate::cli::ExecutionMode;
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;

/// What a service needs in one execution mode.
pub trait Mode: Sized + Debug + Clone + PartialEq {
    const MODE: ExecutionMode;
    /// The image a service runs: `String` in docker mode, nothing in native mode.
    type Image: Clone + Debug + PartialEq;
    /// How the archive node api runs: its image, or its npm executable.
    type ApiServer: Clone + Debug + PartialEq;

    fn image(check: &mut Check, value: &Option<String>, field: &'static str)
        -> Option<Self::Image>;
    fn api_server(check: &mut Check, config: &ServiceConfig) -> Option<Self::ApiServer>;
    /// Client port of a daemon whose config has none.
    fn default_client_port() -> Option<u16>;
    /// Server port of `mina-archive` when the config has none.
    fn default_archive_port() -> Option<u16>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Docker;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Native;

impl Mode for Docker {
    const MODE: ExecutionMode = ExecutionMode::Docker;
    type Image = String;
    type ApiServer = String;

    fn image(check: &mut Check, value: &Option<String>, field: &'static str) -> Option<String> {
        check.need(value, field)
    }
    fn api_server(check: &mut Check, config: &ServiceConfig) -> Option<String> {
        check.need(&config.docker_image, "docker_image")
    }
    // every container has its own ports
    fn default_client_port() -> Option<u16> {
        Some(3100)
    }
    fn default_archive_port() -> Option<u16> {
        Some(3086)
    }
}

impl Mode for Native {
    const MODE: ExecutionMode = ExecutionMode::Native;
    type Image = ();
    type ApiServer = PathBuf;

    fn image(_: &mut Check, _: &Option<String>, _: &'static str) -> Option<()> {
        Some(())
    }
    /// Set by `network create`, which installs the server.
    fn api_server(check: &mut Check, config: &ServiceConfig) -> Option<PathBuf> {
        check.need(&config.archive_node_api_bin, "archive_node_api_bin")
    }
    // every node shares the host's ports
    fn default_client_port() -> Option<u16> {
        None
    }
    fn default_archive_port() -> Option<u16> {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Service<M: Mode> {
    pub name: String,
    pub kind: Kind<M>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind<M: Mode> {
    Daemon(Daemon<M>),
    SnarkWorker(SnarkWorker<M>),
    Rosetta(Rosetta<M>),
    ArchiveNodeApi(ArchiveNodeApi<M>),
    UptimeServiceBackend(UptimeServiceBackend<M>),
}

/// A `mina daemon` process.
#[derive(Debug, Clone, PartialEq)]
pub struct Daemon<M: Mode> {
    pub image: M::Image,
    /// First of five ports: client, REST (+1), external (+2), metrics (+3),
    /// libp2p metrics (+4).
    pub client_port: u16,
    /// Docker mode: the client, REST and external ports are published on the
    /// host. A daemon without a client port in its config is not published.
    pub published: bool,
    pub peers: Peers,
    pub libp2p_keypair: Option<Libp2pKeypair>,
    pub role: Role<M>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Role<M: Mode> {
    Seed,
    /// Without a key the daemon does not produce blocks.
    BlockProducer {
        key: Option<BlockProducerKey>,
    },
    Plain,
    SnarkCoordinator {
        fee: String,
        /// Receives the snark fees.
        public_key: String,
    },
    /// A daemon that sends its blocks to `mina-archive`.
    Archive {
        /// Server port of `mina-archive`.
        port: u16,
        /// Image of `mina-archive`.
        image: M::Image,
    },
}

/// Where a daemon finds the seeds.
#[derive(Debug, Clone, PartialEq)]
pub enum Peers {
    /// `peer_list_file.txt` in the network directory.
    ListFile,
    List(Vec<String>),
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Libp2pKeypair {
    /// Copied to `libp2p_keypairs/<name>.json` in the network directory.
    File,
    /// A key file path as the daemon sees it.
    Path(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockProducerKey {
    /// A topology key, copied to `network_keypairs/<name>.json`.
    File,
    /// A key that key generation left at this path.
    Path(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnarkWorker<M: Mode> {
    pub image: M::Image,
    /// Service name of the snark coordinator.
    pub coordinator: String,
    pub coordinator_port: u16,
    /// Unset: the profile's compiled proof level applies.
    pub proof_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rosetta<M: Mode> {
    pub image: M::Image,
    /// Port of the Rosetta API.
    pub port: u16,
    /// Daemon whose GraphQL API rosetta reads.
    pub graphql_node: String,
    /// REST (GraphQL) port of that daemon.
    pub graphql_port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveNodeApi<M: Mode> {
    pub server: M::ApiServer,
    pub port: u16,
}

/// Docker mode only: native mode skips it.
#[derive(Debug, Clone, PartialEq)]
pub struct UptimeServiceBackend<M: Mode> {
    pub image: M::Image,
    pub app_config: PathBuf,
    pub minasheets: PathBuf,
}

impl<M: Mode> Service<M> {
    pub fn daemon(&self) -> Option<&Daemon<M>> {
        match &self.kind {
            Kind::Daemon(daemon) => Some(daemon),
            _ => None,
        }
    }

    pub fn is_seed(&self) -> bool {
        self.daemon().is_some_and(|d| matches!(d.role, Role::Seed))
    }

    pub fn is_archive(&self) -> bool {
        self.daemon()
            .is_some_and(|d| matches!(d.role, Role::Archive { .. }))
    }
}

/// The archive node of `services`, if the network has one ([`check`] allows
/// one at most).
pub fn archive_node<M: Mode>(services: &[Service<M>]) -> Option<&Service<M>> {
    services.iter().find(|s| s.is_archive())
}

/// The uptime service backend of `services`, if the network has one.
pub fn uptime_service_backend<M: Mode>(
    services: &[Service<M>],
) -> Option<(&Service<M>, &UptimeServiceBackend<M>)> {
    services.iter().find_map(|s| match &s.kind {
        Kind::UptimeServiceBackend(backend) => Some((s, backend)),
        _ => None,
    })
}

/// Every problem [`check`] found.
#[derive(Debug, thiserror::Error)]
pub struct InvalidServices(pub Vec<ServiceError>);

impl std::fmt::Display for InvalidServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.len() {
            1 => write!(f, "1 problem:")?,
            n => write!(f, "{n} problems:")?,
        }
        for problem in &self.0 {
            write!(f, "\n  - {problem}")?;
        }
        Ok(())
    }
}

impl From<InvalidServices> for std::io::Error {
    fn from(e: InvalidServices) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

/// Problems found so far, for one service at a time.
pub struct Check {
    service: String,
    problems: Vec<ServiceError>,
}

impl Check {
    /// `value`, or `None` and a [`ServiceError::MissingField`].
    pub fn need<T: Clone>(&mut self, value: &Option<T>, field: &'static str) -> Option<T> {
        if value.is_none() {
            self.problems.push(ServiceError::MissingField {
                service: self.service.clone(),
                field,
            });
        }
        value.clone()
    }

    fn need_or<T: Clone>(
        &mut self,
        value: &Option<T>,
        default: Option<T>,
        field: &'static str,
    ) -> Option<T> {
        match value {
            Some(_) => value.clone(),
            None => self.need(&default, field),
        }
    }
}

/// The services of a network, typed for mode `M`, or every problem of every
/// service: missing fields, two services with one name, references to
/// services that do not exist.
pub fn check<M: Mode>(configs: &[ServiceConfig]) -> Result<Vec<Service<M>>, InvalidServices> {
    let mut check = Check {
        service: String::new(),
        problems: Vec::new(),
    };
    let mut names = HashMap::new();
    for config in configs {
        if names
            .insert(&config.service_name, config.service_type)
            .is_some()
        {
            check.problems.push(ServiceError::Duplicate {
                service: config.service_name.clone(),
            });
        }
    }
    for (kind, service_type) in [
        ("archive node", ServiceType::ArchiveNode),
        ("uptime service backend", ServiceType::UptimeServiceBackend),
    ] {
        let of_type: Vec<String> = configs
            .iter()
            .filter(|c| c.service_type == service_type)
            .map(|c| c.service_name.clone())
            .collect();
        if of_type.len() > 1 {
            check.problems.push(ServiceError::TooMany {
                kind,
                services: of_type,
            });
        }
    }

    // daemons first: snark workers take the port of their coordinator
    let mut services: Vec<Service<M>> = Vec::new();
    for config in configs.iter().filter(|c| is_daemon(c.service_type)) {
        check.service = config.service_name.clone();
        if let Some(daemon) = daemon::<M>(&mut check, config) {
            services.push(Service {
                name: config.service_name.clone(),
                kind: Kind::Daemon(daemon),
            });
        }
    }
    let daemon_port = |name: &str| {
        services
            .iter()
            .find(|s| s.name == name)
            .and_then(Service::daemon)
            .map(|d| d.client_port)
    };
    let has_archive = configs
        .iter()
        .any(|c| c.service_type == ServiceType::ArchiveNode);

    let mut others = Vec::new();
    for config in configs.iter().filter(|c| !is_daemon(c.service_type)) {
        check.service = config.service_name.clone();
        // a reference to a service of the wrong kind, and the client port of
        // the daemon it names (none if that daemon has problems of its own)
        let refers = |check: &mut Check,
                      field: &'static str,
                      target: &Option<String>,
                      what: &'static str,
                      kind: fn(ServiceType) -> bool| {
            let target = target.as_ref()?;
            if !names.get(target).is_some_and(|t| kind(*t)) {
                check.problems.push(ServiceError::NotFound {
                    service: check.service.clone(),
                    field,
                    target: target.clone(),
                    what,
                });
                return None;
            }
            daemon_port(target)
        };
        let needs_archive = |check: &mut Check| {
            if !has_archive {
                check.problems.push(ServiceError::NeedsArchive {
                    service: check.service.clone(),
                });
            }
        };
        let kind = match config.service_type {
            ServiceType::SnarkWorker => {
                let image = M::image(&mut check, &config.docker_image, "docker_image");
                let coordinator =
                    check.need(&config.snark_coordinator_host, "snark_coordinator_host");
                let port = refers(
                    &mut check,
                    "snark_coordinator_host",
                    &config.snark_coordinator_host,
                    "snark coordinator",
                    |t| t == ServiceType::SnarkCoordinator,
                );
                let coordinator_port = check.need_or(
                    &config.snark_coordinator_port,
                    port,
                    "snark_coordinator_port",
                );
                (|| {
                    Some(Kind::SnarkWorker(SnarkWorker {
                        image: image?,
                        coordinator: coordinator?,
                        coordinator_port: coordinator_port?,
                        proof_level: config.snark_worker_proof_level.clone(),
                    }))
                })()
            }
            ServiceType::Rosetta => {
                needs_archive(&mut check);
                let image = M::image(&mut check, &config.docker_image, "docker_image");
                let port = check.need(&config.client_port, "client_port");
                let graphql_node = check.need(&config.rosetta_graphql_node, "rosetta_graphql_node");
                refers(
                    &mut check,
                    "rosetta_graphql_node",
                    &config.rosetta_graphql_node,
                    "daemon",
                    is_daemon,
                );
                let graphql_port = check.need(&config.rosetta_graphql_port, "rosetta_graphql_port");
                (|| {
                    Some(Kind::Rosetta(Rosetta {
                        image: image?,
                        port: port?,
                        graphql_node: graphql_node?,
                        graphql_port: graphql_port?,
                    }))
                })()
            }
            ServiceType::ArchiveNodeApi => {
                needs_archive(&mut check);
                let server = M::api_server(&mut check, config);
                let port = check.need(&config.client_port, "client_port");
                (|| {
                    Some(Kind::ArchiveNodeApi(ArchiveNodeApi {
                        server: server?,
                        port: port?,
                    }))
                })()
            }
            ServiceType::UptimeServiceBackend => {
                let image = M::image(&mut check, &config.docker_image, "docker_image");
                let app_config = check.need(
                    &config.uptime_service_backend_app_config,
                    "uptime_service_backend_app_config",
                );
                let minasheets = check.need(
                    &config.uptime_service_backend_minasheets,
                    "uptime_service_backend_minasheets",
                );
                (|| {
                    Some(Kind::UptimeServiceBackend(UptimeServiceBackend {
                        image: image?,
                        app_config: app_config?,
                        minasheets: minasheets?,
                    }))
                })()
            }
            // daemons are typed above
            _ => None,
        };
        if let Some(kind) = kind {
            others.push(Service {
                name: config.service_name.clone(),
                kind,
            });
        }
    }

    if !check.problems.is_empty() {
        return Err(InvalidServices(check.problems));
    }
    // the order of the configs
    let mut by_name: HashMap<String, Service<M>> = services
        .into_iter()
        .chain(others)
        .map(|s| (s.name.clone(), s))
        .collect();
    Ok(configs
        .iter()
        .filter_map(|c| by_name.remove(&c.service_name))
        .collect())
}

fn is_daemon(service_type: ServiceType) -> bool {
    matches!(
        service_type,
        ServiceType::Seed
            | ServiceType::BlockProducer
            | ServiceType::PlainNode
            | ServiceType::SnarkCoordinator
            | ServiceType::ArchiveNode
    )
}

fn daemon<M: Mode>(check: &mut Check, config: &ServiceConfig) -> Option<Daemon<M>> {
    let image = M::image(check, &config.docker_image, "docker_image");
    let client_port = check.need_or(&config.client_port, M::default_client_port(), "client_port");
    if let Some(port) = client_port.filter(|p| p.checked_add(4).is_none()) {
        check.problems.push(ServiceError::PortRange {
            service: check.service.clone(),
            port,
        });
    }
    let role = match config.service_type {
        ServiceType::Seed => Some(Role::Seed),
        ServiceType::BlockProducer => Some(Role::BlockProducer {
            key: match (&config.private_key_path, &config.public_key_path) {
                (Some(_), _) => Some(BlockProducerKey::File),
                (None, Some(path)) => Some(BlockProducerKey::Path(path.clone())),
                (None, None) => None,
            },
        }),
        ServiceType::PlainNode => Some(Role::Plain),
        ServiceType::SnarkCoordinator => {
            let fee = check.need(&config.snark_coordinator_fees, "snark_coordinator_fees");
            let public_key = check.need(&config.public_key, "public_key");
            (|| {
                Some(Role::SnarkCoordinator {
                    fee: fee?,
                    public_key: public_key?,
                })
            })()
        }
        ServiceType::ArchiveNode => {
            let port = check.need_or(
                &config.archive_port,
                M::default_archive_port(),
                "archive_port",
            );
            let image = M::image(check, &config.archive_docker_image, "archive_docker_image");
            (|| {
                Some(Role::Archive {
                    port: port?,
                    image: image?,
                })
            })()
        }
        _ => None,
    };
    let peers = match (&config.peer_list_file, &config.peers) {
        (Some(_), _) => Peers::ListFile,
        (None, Some(peers)) => Peers::List(peers.clone()),
        (None, None) => Peers::None,
    };
    let libp2p_keypair = match (&config.libp2p_keypair_path, &config.libp2p_keypair) {
        (Some(_), _) => Some(Libp2pKeypair::File),
        (None, Some(path)) => Some(Libp2pKeypair::Path(path.clone())),
        (None, None) => None,
    };
    Some(Daemon {
        image: image?,
        client_port: client_port?,
        published: config.client_port.is_some(),
        peers,
        libp2p_keypair,
        role: role?,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn config(service_type: ServiceType, name: &str) -> ServiceConfig {
        ServiceConfig {
            service_type,
            service_name: name.into(),
            ..Default::default()
        }
    }

    fn problems<M: Mode>(configs: &[ServiceConfig]) -> Vec<String> {
        check::<M>(configs)
            .unwrap_err()
            .0
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn every_problem_of_every_service_is_reported() {
        let rosetta = config(ServiceType::Rosetta, "rosetta");
        let mut worker = config(ServiceType::SnarkWorker, "w");
        worker.snark_coordinator_host = Some("nobody".into());
        let configs = [
            config(ServiceType::Seed, "seed"),
            config(ServiceType::Seed, "seed"),
            rosetta,
            worker,
        ];
        assert_eq!(
            problems::<Native>(&configs),
            [
                "two services are called 'seed'",
                "'seed' has no client_port",
                "'seed' has no client_port",
                "'rosetta' needs an archive node",
                "'rosetta' has no client_port",
                "'rosetta' has no rosetta_graphql_node",
                "'rosetta' has no rosetta_graphql_port",
                "'w': snark_coordinator_host 'nobody' is not a snark coordinator of the network",
                "'w' has no snark_coordinator_port",
            ]
        );
        let err = check::<Native>(&configs[..1]).unwrap_err().to_string();
        assert_eq!(err, "1 problem:\n  - 'seed' has no client_port");
    }

    #[test]
    fn docker_needs_images_and_has_default_ports() {
        let mut archive = config(ServiceType::ArchiveNode, "archive");
        assert_eq!(
            problems::<Docker>(std::slice::from_ref(&archive)),
            [
                "'archive' has no docker_image",
                "'archive' has no archive_docker_image"
            ]
        );
        archive.docker_image = Some("daemon".into());
        archive.archive_docker_image = Some("archive".into());
        let services = check::<Docker>(&[archive.clone()]).unwrap();
        let daemon = services[0].daemon().unwrap();
        assert_eq!((daemon.client_port, daemon.published), (3100, false));
        assert_eq!(
            daemon.role,
            Role::Archive {
                port: 3086,
                image: "archive".into()
            }
        );
        // native mode runs no image, but needs the ports
        assert_eq!(
            problems::<Native>(&[archive]),
            [
                "'archive' has no client_port",
                "'archive' has no archive_port"
            ]
        );
    }

    #[test]
    fn snark_workers_take_the_port_of_their_coordinator() {
        let mut coordinator = config(ServiceType::SnarkCoordinator, "coord");
        coordinator.client_port = Some(7000);
        coordinator.snark_coordinator_fees = Some("0.001".into());
        coordinator.public_key = Some("B62".into());
        let mut worker = config(ServiceType::SnarkWorker, "w");
        worker.snark_coordinator_host = Some("coord".into());
        let services = check::<Native>(&[worker, coordinator]).unwrap();
        // in the order of the configs
        assert_eq!(services[1].name, "coord");
        match &services[0].kind {
            Kind::SnarkWorker(w) => assert_eq!(
                (w.coordinator.as_str(), w.coordinator_port),
                ("coord", 7000)
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn daemon_ports_fit_below_65536() {
        let mut bp = config(ServiceType::BlockProducer, "bp");
        bp.client_port = Some(65534);
        assert_eq!(
            problems::<Native>(&[bp]),
            ["'bp': client_port 65534 leaves no room for its 5 ports"]
        );
    }

    #[test]
    fn one_archive_node_at_most() {
        let mut archive = config(ServiceType::ArchiveNode, "a1");
        archive.client_port = Some(3100);
        archive.archive_port = Some(3086);
        let mut second = archive.clone();
        second.service_name = "a2".into();
        assert_eq!(
            problems::<Native>(&[archive, second]),
            ["2 archive nodes: a1, a2; a network has one at most"]
        );
    }

    #[test]
    fn native_archive_node_api_needs_its_server() {
        let mut archive = config(ServiceType::ArchiveNode, "archive");
        archive.client_port = Some(3100);
        archive.archive_port = Some(3086);
        let mut api = config(ServiceType::ArchiveNodeApi, "api");
        api.client_port = Some(8080);
        assert_eq!(
            problems::<Native>(&[archive.clone(), api.clone()]),
            ["'api' has no archive_node_api_bin"]
        );
        api.archive_node_api_bin = Some("/bin/api".into());
        let services = check::<Native>(&[archive, api]).unwrap();
        assert_eq!(
            services[1].kind,
            Kind::ArchiveNodeApi(ArchiveNodeApi {
                server: "/bin/api".into(),
                port: 8080
            })
        );
    }
}
