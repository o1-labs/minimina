//! # Docker Compose Module
//!
//! This module facilitates the generation contents of `docker-compose.yaml` for
//! deploying various Mina services in a Docker environment.

use crate::archive_node_api;
use crate::cli::{ExecutionMode, Profile};
use crate::daemon_args::{
    rosetta_args, DaemonFeatures, Layout, PRECOMPUTED_BLOCKS_DIR, ROSETTA_ENV,
};
use crate::native::binary::Binary;
use crate::service::typed::{self, Daemon, Docker, Kind, Role};
use log::debug;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::path::Path;

#[derive(Serialize)]
pub(crate) struct DockerCompose {
    version: String,
    #[serde(
        rename = "x-defaults",
        serialize_with = "serialize_defaults_with_anchor"
    )]
    x_defaults: Defaults,
    volumes: HashMap<String, Option<String>>,
    services: HashMap<String, ComposeService>,
}

fn serialize_defaults_with_anchor<S>(defaults: &Defaults, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("Defaults", 1)?;
    state.serialize_field("&default-attributes", defaults)?;
    state.end()
}

#[derive(Serialize)]
struct Defaults {
    environment: Environment,
    /// A non-seed daemon exits when it finds no peers at boot, which happens when it
    /// is up before the seed; restarting retries until the seed accepts connections.
    /// `docker compose stop` is not overridden by this.
    restart: &'static str,
}

#[derive(Serialize)]
struct Environment {
    mina_privkey_pass: String,
    mina_libp2p_pass: String,
    mina_client_trustlist: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_privkey_pass: Option<String>,
    rayon_num_threads: u32,
    mina_profile: Profile,
}

#[derive(Default, Serialize)]
struct ComposeService {
    #[serde(rename = "<<", skip_serializing_if = "Option::is_none")]
    merge: Option<&'static str>,
    container_name: String,
    image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    volumes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ports: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<Vec<String>>,
}

pub const CONFIG_DIRECTORY: &str = "config-directory";
const POSTGRES_DATA: &str = "postgres-data";
// postgres:18+ refuses the /var/lib/postgresql/data mount, so the major version is pinned
const POSTGRES_IMAGE: &str = "postgres:17";
const RAYON_NUM_THREADS: u32 = 2;

impl DockerCompose {
    pub fn generate(
        services: &[typed::Service<Docker>],
        network_path: &Path,
        profile: Profile,
        features: DaemonFeatures,
    ) -> io::Result<String> {
        let network_path_string = path_str(network_path)?;
        let network_name = network_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                invalid(format!(
                    "network path '{}' has no UTF-8 file name",
                    network_path.display()
                ))
            })?;

        // the daemon refuses a missing -precomputed-blocks-dir, and a fresh config
        // volume has none: a volume of its own makes docker create the mount point
        let blocks_volume = |service_name: &str| {
            features
                .precomputed_blocks_dir
                .then(|| format!("{service_name}-blocks"))
        };
        let daemon_volumes = |service_name: &str| {
            let mut volumes = vec![
                format!("{network_path_string}:/local-network"),
                format!("{service_name}:/{CONFIG_DIRECTORY}"),
            ];
            if let Some(volume) = blocks_volume(service_name) {
                volumes.push(format!(
                    "{volume}:/{CONFIG_DIRECTORY}/{PRECOMPUTED_BLOCKS_DIR}"
                ));
            }
            volumes
        };
        let config_dir = format!("/{CONFIG_DIRECTORY}");
        let full_name = |name: &str| format!("{name}-{network_name}");
        let uptime_service =
            typed::uptime_service_backend(services).map(|(s, _)| full_name(&s.name));
        let layout = |uptime_service| Layout {
            mode: ExecutionMode::Docker,
            network: network_name,
            network_dir: "/local-network",
            config_dir: &config_dir,
            uptime_service,
            features,
        };
        // client (GraphQL is client + 1) and external ports, when published
        let daemon_ports = |daemon: &Daemon<Docker>| {
            daemon.published.then(|| {
                let port = daemon.client_port;
                vec![
                    format!("{}:{}", port + 1, port + 1),
                    port.to_string(),
                    (port + 2).to_string(),
                ]
            })
        };
        let mina_service = |name: &str, image: &str, args: Vec<String>| ComposeService {
            merge: Some("*default-attributes"),
            container_name: name.to_string(),
            entrypoint: Some(vec!["mina".to_string()]),
            volumes: Some(daemon_volumes(name)),
            image: image.to_string(),
            command: Some(args.join(" ")),
            ..Default::default()
        };
        let archive = typed::archive_node(services);
        let postgres_name = format!("postgres-{network_name}");
        let archive_uri = format!("postgres://postgres:postgres@{postgres_name}:5432/archive");

        let mut volumes = HashMap::new();
        let mut compose_services = HashMap::new();
        for service in services {
            let name = full_name(&service.name);
            if !matches!(service.kind, Kind::Rosetta(_) | Kind::ArchiveNodeApi(_)) {
                if let Some(volume) = blocks_volume(&name) {
                    volumes.insert(volume, None);
                }
                volumes.insert(name.clone(), None);
            }
            match &service.kind {
                Kind::Daemon(daemon) => {
                    let args = layout(uptime_service.as_deref()).daemon(&service.name, daemon);
                    let mut node = ComposeService {
                        ports: daemon_ports(daemon),
                        ..mina_service(&name, &daemon.image, args)
                    };
                    if let Role::Archive { port, image } = &daemon.role {
                        // the daemon pushes blocks to mina-archive, which writes to postgres
                        volumes.insert(POSTGRES_DATA.to_string(), None);
                        compose_services.insert(
                            postgres_name.clone(),
                            ComposeService {
                                container_name: postgres_name.clone(),
                                image: POSTGRES_IMAGE.to_string(),
                                environment: Some(HashMap::from([(
                                    "POSTGRES_PASSWORD".to_string(),
                                    "postgres".to_string(),
                                )])),
                                volumes: Some(vec![format!(
                                    "{POSTGRES_DATA}:/var/lib/postgresql/data"
                                )]),
                                ports: Some(vec!["5432".to_string()]),
                                ..Default::default()
                            },
                        );
                        let archive_service = full_name(&format!("{}-service", service.name));
                        compose_services.insert(
                            archive_service.clone(),
                            ComposeService {
                                container_name: archive_service.clone(),
                                image: image.clone(),
                                command: Some(format!(
                                    "mina-archive run --postgres-uri {archive_uri} --server-port {port}"
                                )),
                                volumes: Some(vec![
                                    format!("{name}:/data"),
                                    format!("{network_path_string}:/local-network"),
                                ]),
                                ports: Some(vec![port.to_string()]),
                                depends_on: Some(vec![postgres_name.clone()]),
                                ..Default::default()
                            },
                        );
                        // the archive daemon has no uptime service
                        node.command = Some(layout(None).daemon(&service.name, daemon).join(" "));
                        node.depends_on = Some(vec![archive_service]);
                    }
                    compose_services.insert(name, node);
                }
                Kind::SnarkWorker(worker) => {
                    let args = layout(uptime_service.as_deref()).snark_worker(worker);
                    compose_services.insert(name.clone(), mina_service(&name, &worker.image, args));
                }
                Kind::UptimeServiceBackend(backend) => {
                    let config_file = |path: &Path| -> io::Result<String> {
                        Ok(format!(
                            "/local-network/uptime_service_config/{}",
                            Self::get_filename(path)?
                        ))
                    };
                    compose_services.insert(
                        name.clone(),
                        ComposeService {
                            container_name: name,
                            volumes: Some(vec![
                                format!("{network_path_string}:/local-network"),
                                format!("{network_path_string}/uptime-storage:/uptime-storage"),
                            ]),
                            environment: Some(HashMap::from([
                                ("CONFIG_FILE".to_string(), config_file(&backend.app_config)?),
                                (
                                    "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                                    config_file(&backend.minasheets)?,
                                ),
                            ])),
                            image: backend.image.clone(),
                            ports: Some(vec!["8080:8080".to_string()]),
                            ..Default::default()
                        },
                    );
                }
                Kind::Rosetta(rosetta) => {
                    let args = rosetta_args(rosetta, &layout(None), &archive_uri);
                    let mut depends_on: Vec<String> =
                        archive.map(|a| full_name(&a.name)).into_iter().collect();
                    depends_on.push(full_name(&rosetta.graphql_node));
                    depends_on.dedup();
                    // a service's own `environment` replaces the merged default one
                    let environment = ROSETTA_ENV
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .chain([(Profile::ENV.to_string(), profile.to_string())])
                        .collect();
                    let port = rosetta.port;
                    compose_services.insert(
                        name.clone(),
                        ComposeService {
                            // MINA_PROFILE and the restart policy of the daemons
                            merge: Some("*default-attributes"),
                            container_name: name,
                            image: rosetta.image.clone(),
                            // the image's own entrypoint starts a whole stack (daemon, postgres)
                            entrypoint: Some(vec![Binary::Rosetta.to_string()]),
                            command: Some(args.join(" ")),
                            environment: Some(environment),
                            ports: Some(vec![format!("{port}:{port}")]),
                            depends_on: Some(depends_on),
                            ..Default::default()
                        },
                    );
                }
                Kind::ArchiveNodeApi(api) => {
                    let port = api.port;
                    let mut depends_on = vec![postgres_name.clone()];
                    depends_on.extend(archive.map(|a| full_name(&a.name)));
                    compose_services.insert(
                        name.clone(),
                        ComposeService {
                            container_name: name,
                            image: api.server.clone(),
                            environment: Some(
                                archive_node_api::env(&archive_uri, port)
                                    .into_iter()
                                    .map(|(k, v)| (k.to_string(), v))
                                    .collect(),
                            ),
                            ports: Some(vec![format!("{port}:{port}")]),
                            depends_on: Some(depends_on),
                            ..Default::default()
                        },
                    );
                }
            }
        }

        let compose = DockerCompose {
            version: "3.8".to_string(),
            x_defaults: Defaults {
                restart: "on-failure",
                environment: Environment {
                    mina_privkey_pass: "naughty blue worm".to_string(),
                    mina_libp2p_pass: "naughty blue worm".to_string(),
                    uptime_privkey_pass: uptime_service
                        .is_some()
                        .then(|| "naughty blue worm".to_string()),
                    mina_client_trustlist: "0.0.0.0/0".to_string(),
                    rayon_num_threads: RAYON_NUM_THREADS,
                    mina_profile: profile,
                },
            },
            volumes,
            services: compose_services,
        };

        let yaml_output = serde_norway::to_string(&compose).map_err(Error::other)?;
        let generated_file = Self::post_process_yaml(yaml_output);
        debug!("Generated docker-compose.yaml: {}", generated_file);
        Ok(generated_file)
    }

    // fix the format of the yaml output
    fn post_process_yaml(yaml: String) -> String {
        yaml.replace(
            "x-defaults:\n  '&default-attributes':",
            "x-defaults: &default-attributes",
        )
        .replace("<<: '*default-attributes'", "<<: *default-attributes")
        .replace("mina_privkey_pass", "MINA_PRIVKEY_PASS")
        .replace("mina_libp2p_pass", "MINA_LIBP2P_PASS")
        .replace("uptime_privkey_pass", "UPTIME_PRIVKEY_PASS")
        .replace("mina_client_trustlist", "MINA_CLIENT_TRUSTLIST")
        .replace("rayon_num_threads", "RAYON_NUM_THREADS")
        .replace("mina_profile", "MINA_PROFILE")
        .replace("null", "")
    }

    fn get_filename(path: &Path) -> io::Result<String> {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .ok_or_else(|| invalid(format!("'{}' has no UTF-8 file name", path.display())))
    }
}

fn invalid(msg: String) -> Error {
    Error::new(ErrorKind::InvalidData, msg)
}

fn path_str(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| invalid(format!("path '{}' is not valid UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceConfig, ServiceType};

    /// The compose file of `configs`, checked as `network create` does.
    fn generate(
        configs: &[ServiceConfig],
        network_path: &Path,
        profile: Profile,
        features: DaemonFeatures,
    ) -> io::Result<String> {
        let services = typed::check::<Docker>(configs)?;
        DockerCompose::generate(&services, network_path, profile, features)
    }

    #[test]
    fn test_generate() {
        let configs = vec![
            ServiceConfig {
                service_name: "seed".to_string(),
                service_type: ServiceType::Seed,
                docker_image: Some("seed-image".into()),
                client_port: Some(8300),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "block-producer".to_string(),
                service_type: ServiceType::BlockProducer,
                docker_image: Some("bp-image".into()),
                client_port: Some(8301),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "snark-coordinator".to_string(),
                service_type: ServiceType::SnarkCoordinator,
                docker_image: Some("snark-image".into()),
                client_port: Some(8302),
                snark_coordinator_fees: Some("0.001".into()),
                public_key: Some("B62".into()),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "snark-worker".to_string(),
                service_type: ServiceType::SnarkWorker,
                docker_image: Some("worker-image".into()),
                snark_coordinator_host: Some("snark-coordinator".into()),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "mina-archive555".to_string(),
                service_type: ServiceType::ArchiveNode,
                docker_image: Some("archive-node-image".into()),
                archive_docker_image: Some("archive-service-image".into()),
                archive_port: Some(8304),
                ..Default::default()
            },
        ];
        let network_path = Path::new("/not-a-real-path");
        let docker_compose = generate(
            &configs,
            network_path,
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap();
        println!("{:?}", docker_compose);
        assert!(docker_compose.contains("seed"));
        assert!(docker_compose.contains("block-producer"));
        assert!(docker_compose.contains("snark-coordinator"));
        assert!(docker_compose.contains("snark-worker"));
        assert!(docker_compose.contains("mina-archive555"));
        assert!(docker_compose.contains("image: postgres:17"));
        assert!(docker_compose.contains("restart: on-failure"));
        assert!(docker_compose.contains("postgres-data"));
        assert!(docker_compose.contains("-archive-address"));
        assert!(docker_compose.contains("archive-node-image"));
        assert!(docker_compose.contains("archive-service-image"));
        assert!(docker_compose.contains("worker-image"));
        assert!(docker_compose.contains("snark-image"));
        assert!(docker_compose.contains("bp-image"));
        assert!(docker_compose.contains("seed-image"));
    }

    #[test]
    fn test_generate_without_archive_node() {
        let configs = vec![
            ServiceConfig {
                service_name: "seed".to_string(),
                service_type: ServiceType::Seed,
                docker_image: Some("seed-image".into()),
                client_port: Some(8300),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "block-producer".to_string(),
                service_type: ServiceType::BlockProducer,
                docker_image: Some("bp-image".into()),
                client_port: Some(8301),
                ..Default::default()
            },
        ];
        let network_path = Path::new("/not-a-real-path");
        let docker_compose = generate(
            &configs,
            network_path,
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap();
        println!("{}", docker_compose);
        assert!(docker_compose.contains("seed"));
        assert!(docker_compose.contains("block-producer"));
        assert!(!docker_compose.contains("mina-archive"));
        assert!(!docker_compose.contains("postgres"));
        assert!(!docker_compose.contains("postgres-data"));
        assert!(!docker_compose.contains("archive-data"));
        assert!(!docker_compose.contains("-archive-address"));
    }

    #[test]
    fn rosetta_runs_mina_rosetta_against_the_archive() {
        let configs = vec![
            ServiceConfig {
                service_name: "seed".to_string(),
                service_type: ServiceType::Seed,
                docker_image: Some("daemon".into()),
                client_port: Some(3100),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "archive".to_string(),
                service_type: ServiceType::ArchiveNode,
                docker_image: Some("daemon".into()),
                archive_docker_image: Some("archive".into()),
                client_port: Some(3110),
                archive_port: Some(3115),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "rosetta".to_string(),
                service_type: ServiceType::Rosetta,
                docker_image: Some("rosetta-image".into()),
                client_port: Some(3120),
                rosetta_graphql_node: Some("archive".into()),
                rosetta_graphql_port: Some(3111),
                ..Default::default()
            },
        ];
        let yaml = generate(
            &configs,
            Path::new("/net/hf"),
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap();
        let compose: serde_json::Value = serde_norway::from_str(
            &yaml
                .replace("<<: *default-attributes", "")
                .replace("&default-attributes", ""),
        )
        .unwrap();
        let rosetta = &compose["services"]["rosetta-hf"];
        assert_eq!(rosetta["image"], "rosetta-image");
        assert_eq!(rosetta["entrypoint"][0], "mina-rosetta");
        let command = rosetta["command"].as_str().unwrap();
        assert!(command.contains("--port 3120"), "{command}");
        assert!(
            command.contains("--archive-uri postgres://postgres:postgres@postgres-hf:5432/archive")
        );
        assert!(command.contains("--graphql-uri http://archive-hf:3111/graphql"));
        assert_eq!(rosetta["depends_on"][0], "archive-hf");
        assert_eq!(rosetta["ports"][0], "3120:3120");
        assert_eq!(
            rosetta["environment"]["MINA_ROSETTA_MAX_DB_POOL_SIZE"],
            "16"
        );
        assert_eq!(rosetta["environment"]["MINA_PROFILE"], "devnet");
        // no config volume for rosetta
        assert!(compose["volumes"].get("rosetta-hf").is_none());

        let without_archive = generate(
            &[configs[0].clone(), configs[2].clone()],
            Path::new("/net/hf"),
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap_err();
        assert!(without_archive
            .to_string()
            .contains("needs an archive node"));
    }

    #[test]
    fn archive_node_api_reads_the_archive_database() {
        let configs = vec![
            ServiceConfig {
                service_name: "seed".to_string(),
                service_type: ServiceType::Seed,
                docker_image: Some("daemon".into()),
                client_port: Some(3100),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "archive".to_string(),
                service_type: ServiceType::ArchiveNode,
                docker_image: Some("daemon".into()),
                archive_docker_image: Some("archive".into()),
                client_port: Some(3110),
                archive_port: Some(3115),
                ..Default::default()
            },
            ServiceConfig {
                service_name: "ana".to_string(),
                service_type: ServiceType::ArchiveNodeApi,
                docker_image: Some("ghcr.io/o1-labs/archive-node-api:2.0.0".into()),
                client_port: Some(3120),
                ..Default::default()
            },
        ];
        let yaml = generate(
            &configs,
            Path::new("/net/hf"),
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap();
        let compose: serde_json::Value = serde_norway::from_str(
            &yaml
                .replace("<<: *default-attributes", "")
                .replace("&default-attributes", ""),
        )
        .unwrap();
        let api = &compose["services"]["ana-hf"];
        assert_eq!(api["image"], "ghcr.io/o1-labs/archive-node-api:2.0.0");
        assert_eq!(
            api["environment"]["PG_CONN"],
            "postgres://postgres:postgres@postgres-hf:5432/archive"
        );
        assert_eq!(api["environment"]["PORT"], "3120");
        assert_eq!(api["ports"][0], "3120:3120");
        assert_eq!(api["depends_on"][1], "archive-hf");
        assert!(compose["volumes"].get("ana-hf").is_none());
    }

    #[test]
    fn test_generate_compose_from_topology() -> std::io::Result<()> {
        use crate::{directory_manager::DirectoryManager, topology::Topology};
        let tempdir = tempfile::Builder::new()
            .prefix("test_generate_compose_from_topology")
            .tempdir()
            .expect("Cannot create temporary directory");
        let tmp_network_path = tempdir.path();
        let dir_manager = DirectoryManager::with_base_path(tmp_network_path.to_path_buf());
        let network_id = "test_network";
        let network_path = dir_manager.network_path(network_id);
        dir_manager.generate_dir_structure(network_id)?;

        let file = std::path::PathBuf::from("./tests/data/large_network/topology.json");
        let contents = std::fs::read_to_string(file)?;
        let topology: Topology = serde_json::from_str(&contents)?;
        let peers_file = dir_manager.peer_list_file(network_id);
        let services = topology.services(&peers_file);
        let compose_contents = generate(
            &services,
            &network_path,
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap();

        assert!(compose_contents.contains("snark-node"));
        assert!(compose_contents.contains("archive-node"));
        assert!(compose_contents.contains("archive-node-service"));
        assert!(compose_contents.contains("receiver"));
        assert!(compose_contents.contains("empty_node-1"));
        assert!(compose_contents.contains("empty_node-2"));
        assert!(compose_contents.contains("observer"));
        assert!(compose_contents.contains("seed-0"));
        assert!(compose_contents.contains("seed-1"));
        assert!(compose_contents.contains("-archive-address"));

        dir_manager.delete_network_directory(network_id)?;

        Ok(())
    }

    #[test]
    fn test_generate_only_archive() {
        let configs = vec![ServiceConfig {
            service_name: "mina-archive777".to_string(),
            service_type: ServiceType::ArchiveNode,
            client_port: Some(8000),
            docker_image: Some("archive-image".into()),
            archive_docker_image: Some("archive-service-image".into()),
            archive_port: Some(8304),
            ..Default::default()
        }];
        let network_path = Path::new("/not-a-real-path/network-id");
        let docker_compose = generate(
            &configs,
            network_path,
            Profile::Devnet,
            DaemonFeatures::default(),
        )
        .unwrap();
        println!("{}", docker_compose);
        assert!(docker_compose.contains("mina-archive777-network-id"));
        assert!(docker_compose.contains("mina-archive777-service-network-id"));
        assert!(docker_compose.contains("postgres-network-id"));
        assert!(docker_compose.contains("postgres-data"));
        assert!(docker_compose.contains("/data"));
        assert!(docker_compose.contains("-archive-address mina-archive777-service-network-id:8304"));
    }
}
