//! # Docker Compose Module
//!
//! This module facilitates the generation contents of `docker-compose.yaml` for
//! deploying various Mina services in a Docker environment.

use crate::cli::{ExecutionMode, Profile};
use crate::daemon_args::{mina_args, DaemonFeatures, Layout, PRECOMPUTED_BLOCKS_DIR};
use crate::service::{ServiceConfig, ServiceType};
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
    services: HashMap<String, Service>,
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
struct Service {
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
        configs: &[ServiceConfig],
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
        let command = |config: &ServiceConfig, uptime_service: Option<&str>| {
            let layout = Layout {
                mode: ExecutionMode::Docker,
                network: network_name,
                network_dir: "/local-network",
                config_dir: &config_dir,
                uptime_service,
                features,
            };
            mina_args(config, &layout).map(|args| args.join(" "))
        };

        //insert volumes for each service
        let mut volumes = configs.iter().fold(HashMap::new(), |mut acc, config| {
            let service_name = format!("{}-{network_name}", config.service_name.clone());
            if let Some(volume) = blocks_volume(&service_name) {
                acc.insert(volume, None);
            }
            acc.insert(service_name, None);
            acc
        });

        let uptime_service_hostname = if let Some(uptime_service_backend) =
            ServiceConfig::get_uptime_service_backend(configs)
        {
            let uptime_service_name = format!(
                "{}-{network_name}",
                uptime_service_backend.service_name.clone()
            );
            Some(uptime_service_name)
        } else {
            None
        };

        let mut services: HashMap<String, Service> = configs
            .iter()
            .filter_map(|config| {
                match config.service_type {
                    // We'll handle ArchiveNode outside of this map operation
                    // because it requires adding additional services: postgres, mina-archive-service
                    ServiceType::ArchiveNode => None,
                    // We'll handle UptimeServiceBackend outside of this map operation
                    // because it has different shape than other daemon services
                    ServiceType::UptimeServiceBackend => None,
                    _ => {
                        let service_name =
                            format!("{}-{network_name}", config.service_name.clone());
                        let service = Service {
                            merge: Some("*default-attributes"),
                            container_name: service_name.clone(),
                            entrypoint: Some(vec!["mina".to_string()]),
                            volumes: Some(daemon_volumes(&service_name)),
                            image: match required(&config.docker_image, "docker_image", config) {
                                Ok(image) => image,
                                Err(e) => return Some(Err(e)),
                            },
                            command: Some(
                                match command(config, uptime_service_hostname.as_deref()) {
                                    Ok(command) => command,
                                    Err(e) => return Some(Err(e)),
                                },
                            ),
                            ports: match config.client_port {
                                Some(port) => {
                                    let gql_port = port + 1;
                                    let external_port = port + 2;
                                    Some(vec![
                                        format!("{}:{}", gql_port, gql_port),
                                        port.to_string(),
                                        external_port.to_string(),
                                    ])
                                }
                                None => None,
                            },
                            ..Default::default()
                        };
                        Some(Ok((
                            format!("{}-{network_name}", config.service_name.clone()),
                            service,
                        )))
                    }
                }
            })
            .collect::<io::Result<_>>()?;

        // Add ArchiveNode service bits
        if let Some(archive_config) = ServiceConfig::get_archive_node(configs) {
            // Add postgres service
            volumes.insert(POSTGRES_DATA.to_string(), None);
            let mut postgres_environment = HashMap::new();
            postgres_environment.insert("POSTGRES_PASSWORD".to_string(), "postgres".to_string());
            let postgres_name = format!("postgres-{network_name}");
            services.insert(
                postgres_name.clone(),
                Service {
                    container_name: postgres_name.clone(),
                    image: POSTGRES_IMAGE.to_string(),
                    environment: Some(postgres_environment),
                    volumes: Some(vec![format!("{}:/var/lib/postgresql/data", POSTGRES_DATA)]),
                    ports: Some(vec!["5432".to_string()]),
                    ..Default::default()
                },
            );

            // Add archive service
            let archive_node_name =
                format!("{}-{network_name}", archive_config.service_name.clone());
            let archive_service_name = format!(
                "{}-service-{network_name}",
                archive_config.service_name.clone()
            );
            let archive_port = archive_config.archive_port.unwrap_or(3086);
            let archive_command = format!(
                "mina-archive run --postgres-uri postgres://postgres:postgres@{}:5432/archive \
                --server-port {}",
                postgres_name, archive_port
            );
            services.insert(
                archive_service_name.clone(),
                Service {
                    container_name: archive_service_name.clone(),
                    image: required(
                        &archive_config.archive_docker_image,
                        "archive_docker_image",
                        archive_config,
                    )?,
                    command: Some(archive_command),
                    volumes: Some(vec![
                        format!("{}:/data", archive_node_name),
                        format!("{}:/local-network", network_path_string),
                    ]),
                    ports: Some(vec![archive_port.to_string()]),
                    depends_on: Some(vec![postgres_name]),
                    ..Default::default()
                },
            );

            // Add archive node
            let archive_command = command(archive_config, None)?;
            services.insert(
                archive_node_name.clone(),
                Service {
                    merge: Some("*default-attributes"),
                    container_name: archive_node_name.clone(),
                    entrypoint: Some(vec!["mina".to_string()]),
                    volumes: Some(daemon_volumes(&archive_node_name)),
                    image: required(&archive_config.docker_image, "docker_image", archive_config)?,
                    command: Some(archive_command),
                    ports: match archive_config.client_port {
                        Some(port) => {
                            let gql_port = port + 1;
                            let external_port = port + 2;
                            Some(vec![
                                format!("{}:{}", gql_port, gql_port),
                                port.to_string(),
                                external_port.to_string(),
                            ])
                        }
                        None => None,
                    },
                    depends_on: Some(vec![archive_service_name]),
                    ..Default::default()
                },
            );
        }

        // Add UptimeServiceBackend service
        if let Some(uptime_service_backend) = ServiceConfig::get_uptime_service_backend(configs) {
            let uptime_service_name = format!(
                "{}-{network_name}",
                uptime_service_backend.service_name.clone()
            );
            let mut uptime_service_env = HashMap::new();
            let app_config = Self::get_filename(
                required(
                    &uptime_service_backend.uptime_service_backend_app_config,
                    "uptime_service_backend_app_config",
                    uptime_service_backend,
                )?
                .as_path(),
            )?;
            let minasheets_config = Self::get_filename(
                required(
                    &uptime_service_backend.uptime_service_backend_minasheets,
                    "uptime_service_backend_minasheets",
                    uptime_service_backend,
                )?
                .as_path(),
            )?;
            uptime_service_env.insert(
                "CONFIG_FILE".to_string(),
                format!("/local-network/uptime_service_config/{app_config}"),
            );
            uptime_service_env.insert(
                "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                format!("/local-network/uptime_service_config/{minasheets_config}"),
            );

            services.insert(
                uptime_service_name.clone(),
                Service {
                    container_name: uptime_service_name.clone(),
                    volumes: Some(vec![
                        format!("{network_path_string}:/local-network"),
                        format!("{network_path_string}/uptime-storage:/uptime-storage"),
                    ]),
                    environment: Some(uptime_service_env),
                    image: required(
                        &uptime_service_backend.docker_image,
                        "docker_image",
                        uptime_service_backend,
                    )?,
                    ports: Some(vec!["8080:8080".to_string()]),
                    ..Default::default()
                },
            );
        }

        let compose = DockerCompose {
            version: "3.8".to_string(),
            x_defaults: Defaults {
                restart: "on-failure",
                environment: Environment {
                    mina_privkey_pass: "naughty blue worm".to_string(),
                    mina_libp2p_pass: "naughty blue worm".to_string(),
                    uptime_privkey_pass: if ServiceConfig::get_uptime_service_backend(configs)
                        .is_some()
                    {
                        Some("naughty blue worm".to_string())
                    } else {
                        None
                    },
                    mina_client_trustlist: "0.0.0.0/0".to_string(),
                    rayon_num_threads: RAYON_NUM_THREADS,
                    mina_profile: profile,
                },
            },
            volumes,
            services,
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

/// Returns a clone of a topology field that the compose file needs.
fn required<T: Clone>(field: &Option<T>, name: &str, config: &ServiceConfig) -> io::Result<T> {
    field.clone().ok_or_else(|| {
        invalid(format!(
            "service '{}' has no '{name}' in its topology",
            config.service_name
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceType;

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
                ..Default::default()
            },
            ServiceConfig {
                service_name: "snark-worker".to_string(),
                service_type: ServiceType::SnarkWorker,
                docker_image: Some("worker-image".into()),
                client_port: Some(8303),
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
        let docker_compose = DockerCompose::generate(
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
        let docker_compose = DockerCompose::generate(
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
        let compose_contents = DockerCompose::generate(
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
        let docker_compose = DockerCompose::generate(
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
