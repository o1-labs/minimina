//! # Docker Manager Module
//!
//! Provides an interface for managing Docker operations within the application.
//! Specifically, it offers functionalities to:
//! - Generate a `docker-compose.yaml` file from provided service configurations.
//! - Start up services using the generated Docker Compose file.
//! - Shut down active services.
//! - Handle interactions with the Docker CLI.

use crate::directory_manager::NETWORK_KEYPAIRS;
use crate::genesis_ledger::REPLAYER_INPUT_JSON;
use crate::{
    cli::Profile, docker::compose::DockerCompose, docker::compose::CONFIG_DIRECTORY,
    runner::Runner, service::ServiceConfig,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use std::rc::Rc;
use std::{
    io::Result,
    path::{Path, PathBuf},
    process::Output,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerInfo {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "Command")]
    pub command: String,
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "State")]
    pub state: ContainerState,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Health")]
    pub health: String,
    #[serde(rename = "ExitCode")]
    pub exit_code: i32,
    #[serde(rename = "Labels")]
    pub labels: String,
    #[serde(rename = "Service")]
    pub service: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ContainerState {
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "exited")]
    Exited,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "paused")]
    Paused,
    #[serde(rename = "restarting")]
    Restarting,
    #[serde(rename = "removing")]
    Removing,
    #[serde(rename = "dead")]
    Dead,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComposeInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "ConfigFiles")]
    pub config_files: String,
}

#[derive(Clone)]
pub struct DockerManager {
    pub network_path: PathBuf,
    pub compose_path: PathBuf,
    profile: Profile,
    runner: Rc<dyn Runner>,
}

impl DockerManager {
    pub fn new(network_path: &Path, profile: Profile, runner: Rc<dyn Runner>) -> Self {
        let compose_path = network_path.join("docker-compose.yaml");
        DockerManager {
            network_path: network_path.to_path_buf(),
            compose_path,
            profile,
            runner,
        }
    }

    fn docker(&self, args: &[&str]) -> Result<Output> {
        self.runner.run("docker".as_ref(), args, &[])
    }

    pub fn compose_generate_file(&self, configs: &[ServiceConfig]) -> Result<()> {
        let mut file = File::create(&self.compose_path)?;
        let contents = DockerCompose::generate(configs, &self.network_path, self.profile)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }

    pub fn exec(&self, service: &str, cmd: &[&str]) -> Result<Output> {
        let mut args = vec!["exec", "-i", service];
        args.extend_from_slice(cmd);
        self.docker(&args)
    }

    pub fn cp(&self, service: &str, src: &Path, dest: &Path) -> Result<Output> {
        let destination = format!("{}:{}", service, utf8(dest)?);
        self.docker(&["cp", utf8(src)?, destination.as_str()])
    }

    /// Removes containers (and volumes); images are kept, since other networks share them.
    pub fn compose_down(
        &self,
        specific_service: Option<String>,
        remove_volumes: bool,
    ) -> Result<Output> {
        let mut args = vec!["down"];
        let specific_service = specific_service.as_deref();
        if let Some(service) = specific_service {
            args.push(service);
        }

        if remove_volumes {
            args.push("--volumes");
        }

        args.push("--remove-orphans");
        self.run_docker_compose(&args)
    }

    /// Create the network
    pub fn compose_create(&self, specific_service: Option<String>) -> Result<Output> {
        let mut args = vec!["create"];
        let specific_service = specific_service.as_deref();
        if let Some(service) = specific_service {
            args.push(service);
        }
        self.run_docker_compose(&args)
    }

    /// Start all services in the network
    pub fn compose_start_all(&self) -> Result<Output> {
        self.run_docker_compose(&["start"])
    }

    /// Stop all services in the network
    pub fn compose_stop_all(&self, timeout_secs: Option<u64>) -> Result<Output> {
        self.compose_stop(vec![], timeout_secs)
    }

    /// Start a subset of services in the network
    pub fn compose_start(&self, services: Vec<&str>) -> Result<Output> {
        let mut cmd = vec!["start"];
        cmd.extend(services);
        self.run_docker_compose(&cmd)
    }

    /// Stop a subset of services in the network
    /// Stop a subset of services (all when empty), waiting `timeout_secs` before killing
    pub fn compose_stop(&self, services: Vec<&str>, timeout_secs: Option<u64>) -> Result<Output> {
        let timeout = timeout_secs.map(|t| t.to_string());
        let mut cmd = vec!["stop"];
        if let Some(t) = &timeout {
            cmd.extend(["-t", t.as_str()]);
        }
        cmd.extend(services);
        self.run_docker_compose(&cmd)
    }

    pub fn compose_ls(&self) -> Result<Vec<ComposeInfo>> {
        let output = self.run_docker_compose(&["ls", "--format", "json"])?;
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let compose_info = serde_json::from_str(&stdout_str)?;
        Ok(compose_info)
    }

    /// Get docker info of all services in the network
    pub fn compose_ps(&self, filter: Option<ContainerState>) -> Result<Vec<ContainerInfo>> {
        let mut cmd: Vec<String> = vec![
            "ps".to_string(),
            "-a".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        if let Some(state) = filter {
            cmd.push("--filter".to_string());
            cmd.push(format!("status={}", state));
        }

        // Convert Vec<String> to Vec<&str> for compatibility with run_docker_compose
        let cmd_str_slices: Vec<&str> = cmd.iter().map(AsRef::as_ref).collect();

        let output = self.run_docker_compose(&cmd_str_slices)?;
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout_str.trim().split('\n').collect();

        let containers: Vec<ContainerInfo> = lines
            .iter()
            .filter_map(|&line| serde_json::from_str::<ContainerInfo>(line).ok())
            .collect();

        Ok(containers)
    }

    /// Execute a command in a compose service
    pub fn compose_dump_precomputed_blocks(
        &self,
        node_id: &str,
        network_id: &str,
    ) -> Result<Output> {
        let service = format!("{node_id}-{network_id}");
        let cmd = &[
            "exec",
            &service,
            "cat",
            &format!("/{CONFIG_DIRECTORY}/precomputed_blocks.log"),
        ];
        self.run_docker_compose(cmd)
    }

    /// Execute `pg_dump` on the postgres db
    pub fn compose_dump_archive_data(&self, network_id: &str) -> Result<Output> {
        let service = format!("postgres-{network_id}");
        let cmd = &[
            "exec", &service, "pg_dump", "--insert", "-U", "postgres", "archive",
        ];
        self.run_docker_compose(cmd)
    }

    /// Execute archive service replayer
    pub fn compose_run_replayer(&self, node_id: &str, network_id: &str) -> Result<Output> {
        // -input-file PATH (genesis ledger)
        // -output-file PATH (output ledger)
        let service = format!("{node_id}-{network_id}");
        let pg_archive_uri =
            format!("postgres://postgres:postgres@postgres-{network_id}:5432/archive");
        let cmd = &[
            "exec",
            &service,
            "mina-replayer",
            "--continue-on-error",
            "--input-file",
            &format!("/local-network/{}", REPLAYER_INPUT_JSON),
            "--archive-uri",
            &pg_archive_uri,
            "--output-file",
            "/dev/null",
        ];
        self.run_docker_compose(cmd)
    }

    pub fn compose_import_account(
        &self,
        node_id: &str,
        network_id: &str,
        account_file: &str,
    ) -> Result<Output> {
        let service = format!("{node_id}-{network_id}");
        let privkey_path = format!("/local-network/{NETWORK_KEYPAIRS}/{account_file}");
        let cmd = &[
            "run",
            "--rm",
            "--entrypoint",
            "mina",
            &service,
            "accounts",
            "import",
            "--privkey-path",
            privkey_path.as_str(),
            "--config-directory",
            &format!("/{CONFIG_DIRECTORY}"),
        ];
        self.run_docker_compose(cmd)
    }

    /// Filter container by service name
    /// returns Option<ContainerInfo>
    pub fn filter_container_by_name(
        &self,
        containers: Vec<ContainerInfo>,
        service_name: &str,
    ) -> Result<Option<ContainerInfo>> {
        let mut matching = containers
            .into_iter()
            .filter(|container| container.service == service_name);
        let first = matching.next();
        let extra = matching.count();
        if extra > 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Expected 1 container for '{service_name}', found {}",
                    extra + 1
                ),
            ));
        }
        Ok(first)
    }

    fn run_docker_compose(&self, subcommands: &[&str]) -> Result<Output> {
        let network_id = self
            .network_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "network path '{}' has no UTF-8 file name",
                        self.network_path.display()
                    ),
                )
            })?;

        let mut args = vec!["compose", "-f", utf8(&self.compose_path)?, "-p", network_id];
        args.extend_from_slice(subcommands);
        self.docker(&args)
    }

    pub fn run_docker_logs(&self, node_id: &str, network_id: &str) -> Result<Output> {
        let container = format!("{node_id}-{network_id}");
        self.docker(&["logs", &container])
    }
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("path '{}' is not valid UTF-8", path.display()),
        )
    })
}

impl fmt::Display for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_str = match self {
            ContainerState::Created => "created",
            ContainerState::Exited => "exited",
            ContainerState::Running => "running",
            ContainerState::Paused => "paused",
            ContainerState::Restarting => "restarting",
            ContainerState::Removing => "removing",
            ContainerState::Dead => "dead",
            ContainerState::Unknown => "unknown",
        };
        write!(f, "{}", state_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    fn ps_line(service: &str, state: &str) -> String {
        format!(
            r#"{{"ID":"1","Name":"{service}","Image":"i","Command":"c","CreatedAt":"t","State":"{state}","Status":"s","Health":"","ExitCode":0,"Labels":"","Service":"{service}"}}"#
        )
    }

    fn manager(fake: &Rc<FakeRunner>) -> DockerManager {
        DockerManager::new(
            Path::new("/home/u/.minimina/net"),
            Profile::Devnet,
            fake.clone(),
        )
    }

    #[test]
    fn compose_commands_use_network_project() {
        let fake = Rc::new(FakeRunner::default());
        let docker = manager(&fake);
        docker
            .compose_stop(vec!["a-net", "b-net"], Some(30))
            .unwrap();
        docker.compose_down(Some("a-net".into()), true).unwrap();
        assert_eq!(
            fake.lines(),
            vec![
                "docker compose -f /home/u/.minimina/net/docker-compose.yaml -p net stop -t 30 a-net b-net",
                "docker compose -f /home/u/.minimina/net/docker-compose.yaml -p net down a-net --volumes --remove-orphans",
            ]
        );
    }

    #[test]
    fn compose_ps_parses_json_lines_and_filters() {
        let fake = Rc::new(FakeRunner::default());
        let stdout = format!(
            "{}\nnot json\n{}\n",
            ps_line("seed-net", "running"),
            ps_line("bp-net", "exited")
        );
        fake.reply(0, &stdout, "");
        let docker = manager(&fake);
        let containers = docker.compose_ps(Some(ContainerState::Running)).unwrap();
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[1].state, ContainerState::Exited);
        assert!(fake.lines()[0].ends_with("ps -a --format json --filter status=running"));

        let seed = docker
            .filter_container_by_name(containers, "seed-net")
            .unwrap()
            .unwrap();
        assert_eq!(seed.state, ContainerState::Running);
    }

    #[test]
    fn filter_container_rejects_duplicates() {
        let fake = Rc::new(FakeRunner::default());
        let docker = manager(&fake);
        let dup = |s| serde_json::from_str::<ContainerInfo>(&ps_line(s, "running")).unwrap();
        assert!(docker
            .filter_container_by_name(vec![dup("x")], "y")
            .unwrap()
            .is_none());
        let err = docker
            .filter_container_by_name(vec![dup("x"), dup("x")], "x")
            .unwrap_err();
        assert_eq!(err.to_string(), "Expected 1 container for 'x', found 2");
    }

    #[test]
    fn compose_ls_parses_projects() {
        let fake = Rc::new(FakeRunner::default());
        fake.reply(
            0,
            r#"[{"Name":"net","Status":"running(2)","ConfigFiles":"/c.yaml"}]"#,
            "",
        );
        let ls = manager(&fake).compose_ls().unwrap();
        assert_eq!(ls[0].name, "net");
        assert_eq!(ls[0].config_files, "/c.yaml");
    }

    #[test]
    fn archive_helpers_target_network_services() {
        let fake = Rc::new(FakeRunner::default());
        let docker = manager(&fake);
        docker.compose_dump_archive_data("net").unwrap();
        docker.compose_run_replayer("arch-service", "net").unwrap();
        docker
            .compose_import_account("bp", "net", "bp.json")
            .unwrap();
        docker
            .cp("pg", Path::new("/tmp/a.sql"), Path::new("/tmp/b.sql"))
            .unwrap();
        let lines = fake.lines();
        assert!(lines[0].ends_with("exec postgres-net pg_dump --insert -U postgres archive"));
        assert!(lines[1].contains(
            "exec arch-service-net mina-replayer --continue-on-error --input-file /local-network/replayer_input.json"
        ));
        assert!(lines[1].contains("postgres://postgres:postgres@postgres-net:5432/archive"));
        assert!(lines[2].ends_with(
            "run --rm --entrypoint mina bp-net accounts import --privkey-path /local-network/network-keypairs/bp.json --config-directory /config-directory"
        ));
        assert_eq!(lines[3], "docker cp /tmp/a.sql pg:/tmp/b.sql");
    }
}
