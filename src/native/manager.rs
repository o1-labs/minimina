//! Native execution: every node is a local `mina` process.
//!
//! Each process runs in its own process group so that signals reach helper
//! children (libp2p_helper) and a Ctrl-C in the shell that ran
//! `minimina network start` does not stop the network.

use crate::docker::compose::CONFIG_DIRECTORY;
use crate::native::port_manager;
use crate::native::process_tracker::{proc_stat, ProcessRecord, ProcessTracker, Records};
use crate::service::{ServiceConfig, ServiceType};
use chrono::Local;
use log::{info, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs::{self, OpenOptions};
use std::io::{self, Result};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Default wait between SIGTERM and SIGKILL.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// Base URI (no database) of the postgres server used by native archive nodes.
pub const DEFAULT_POSTGRES_URI: &str = "postgres://postgres:postgres@localhost:5432";

const ARCHIVE_SUFFIX: &str = "-archive";

pub struct NativeManager {
    pub network_path: PathBuf,
    pub bin_path: PathBuf,
    pub postgres_uri: String,
}

/// A tracked process and whether it is still running.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessStatus {
    pub name: String,
    pub pid: u32,
    pub alive: bool,
}

impl NativeManager {
    pub fn new(network_path: &Path, bin_path: &Path, postgres_uri: &str) -> Self {
        NativeManager {
            network_path: network_path.to_path_buf(),
            bin_path: bin_path.to_path_buf(),
            postgres_uri: postgres_uri.trim_end_matches('/').to_string(),
        }
    }

    /// Archive database of this network: `minimina_<network_id>`, one per network
    /// so that networks sharing a postgres server do not mix chains.
    pub fn archive_db_name(&self) -> String {
        let network_id = self
            .network_path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let sanitized: String = network_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("minimina_{sanitized}")
    }

    /// URI of the archive database.
    pub fn archive_db_uri(&self) -> String {
        format!("{}/{}", self.postgres_uri, self.archive_db_name())
    }

    /// URI of the server's maintenance database, for CREATE/DROP DATABASE.
    pub fn maintenance_db_uri(&self) -> String {
        format!("{}/postgres", self.postgres_uri)
    }

    fn tracker(&self) -> ProcessTracker {
        ProcessTracker::new(&self.network_path)
    }

    fn logs_dir(&self) -> PathBuf {
        self.network_path.join("logs")
    }

    pub fn config_dir_for_service(&self, service_name: &str) -> PathBuf {
        self.network_path.join(CONFIG_DIRECTORY).join(service_name)
    }

    /// Empties the node's config directory (its chain state); the node must be stopped.
    pub fn reset_state(&self, service_name: &str) -> Result<()> {
        if let Some(p) = self
            .status()?
            .into_iter()
            .find(|p| p.alive && p.name == service_name)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("'{}' is running (pid {}); stop it first", p.name, p.pid),
            ));
        }
        let dir = self.config_dir_for_service(service_name);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)
    }

    /// Generate native config (stores services.json, creates dirs)
    pub fn generate_config(&self, configs: &[ServiceConfig]) -> Result<()> {
        fs::create_dir_all(self.logs_dir())?;
        for config in configs {
            fs::create_dir_all(self.config_dir_for_service(&config.service_name))?;
        }
        Ok(())
    }

    /// Starts every service; fails without starting anything if one is already running
    /// or a port is taken, and stops what it started if a later service fails.
    ///
    /// Seeds go first: a non-seed daemon exits ("crashing because this is not a seed
    /// node") when it finds no peer during its initialization, so the others start
    /// only once every seed accepts libp2p connections, or `seed_timeout` passes.
    pub fn start_all(
        &self,
        services: &[ServiceConfig],
        network_id: &str,
        seed_timeout: Duration,
    ) -> Result<()> {
        let running: Vec<String> = self
            .status()?
            .into_iter()
            .filter(|p| p.alive)
            .map(|p| p.name)
            .collect();
        if !running.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("already running: {}", running.join(", ")),
            ));
        }
        port_manager::check_ports_available(&port_manager::collect_all_ports(services)?)?;

        let (seeds, others): (Vec<&ServiceConfig>, Vec<&ServiceConfig>) = services
            .iter()
            .filter(|s| {
                let skip = s.service_type == ServiceType::UptimeServiceBackend;
                if skip {
                    warn!(
                        "Skipping uptime service backend '{}' in native mode",
                        s.service_name
                    );
                }
                !skip
            })
            .partition(|s| s.service_type == ServiceType::Seed);

        let result = seeds
            .iter()
            .try_for_each(|s| self.spawn_service(s, network_id))
            .and_then(|()| match others.is_empty() {
                true => Ok(()),
                false => self.wait_for_seeds(&seeds, seed_timeout),
            })
            .and_then(|()| {
                others
                    .iter()
                    .try_for_each(|s| self.spawn_service(s, network_id))
            });
        if let Err(e) = result {
            warn!("Stopping the services already started after: {e}");
            self.stop_all(Duration::from_secs(10))?;
            return Err(e);
        }
        Ok(())
    }

    /// Waits until every seed accepts TCP connections on its libp2p (external) port.
    fn wait_for_seeds(&self, seeds: &[&ServiceConfig], timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        for seed in seeds {
            let port = seed.client_port.map(|p| p + 2).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("seed '{}' has no client_port", seed.service_name),
                )
            })?;
            info!(
                "Waiting for seed '{}' to accept connections on port {port}",
                seed.service_name
            );
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            while std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err() {
                let record = self.tracker().get(&seed.service_name)?;
                if !record.as_ref().is_some_and(ProcessRecord::is_alive) {
                    return Err(io::Error::other(format!(
                        "seed '{}' exited during startup; see {}",
                        seed.service_name,
                        self.logs_dir()
                            .join(format!("{}.log", seed.service_name))
                            .display()
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "seed '{}' did not accept connections on port {port} within {}s",
                            seed.service_name,
                            timeout.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        Ok(())
    }

    /// Starts one service; fails if it is running or one of its ports is taken.
    pub fn start_service(&self, service: &ServiceConfig, network_id: &str) -> Result<()> {
        if service.service_type == ServiceType::UptimeServiceBackend {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the uptime service backend is not supported in native mode",
            ));
        }
        let names = process_names(service);
        if let Some(p) = self
            .status()?
            .into_iter()
            .find(|p| p.alive && names.contains(&p.name))
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("'{}' is already running (pid {})", p.name, p.pid),
            ));
        }
        port_manager::check_ports_available(&port_manager::collect_all_ports(
            std::slice::from_ref(service),
        )?)?;
        self.spawn_service(service, network_id)
    }

    fn spawn_service(&self, service: &ServiceConfig, network_id: &str) -> Result<()> {
        // the archive daemon pushes blocks to mina-archive, so that comes up first
        if service.service_type == ServiceType::ArchiveNode {
            let name = format!("{}{ARCHIVE_SUFFIX}", service.service_name);
            let (binary, args) = self.archive_process_command(service)?;
            self.spawn(&name, &binary, &args)?;
        }

        let config_dir = self.config_dir_for_service(&service.service_name);
        fs::create_dir_all(&config_dir)?;
        let (binary, args) = self.build_command(
            service,
            network_id,
            utf8(&self.network_path)?,
            utf8(&config_dir)?,
        )?;
        self.spawn(&service.service_name, &binary, &args)
    }

    fn archive_process_command(&self, service: &ServiceConfig) -> Result<(PathBuf, Vec<String>)> {
        let port = service.archive_port.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "archive node '{}' has no archive_port",
                    service.service_name
                ),
            )
        })?;
        Ok((
            self.bin_path.join("mina-archive"),
            vec![
                "run".into(),
                "--postgres-uri".into(),
                self.archive_db_uri(),
                "--server-port".into(),
                port.to_string(),
            ],
        ))
    }

    fn spawn(&self, name: &str, binary: &Path, args: &[String]) -> Result<()> {
        fs::create_dir_all(self.logs_dir())?;
        let log_file_path = self.logs_dir().join(format!("{name}.log"));
        info!(
            "Starting service '{name}' with command: {} {}",
            binary.display(),
            args.join(" ")
        );

        // append: a restart keeps the previous run's log
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;
        let log_file_err = log_file.try_clone()?;

        let child = Command::new(binary)
            .args(args)
            .env("MINA_PRIVKEY_PASS", "naughty blue worm")
            .env("MINA_LIBP2P_PASS", "naughty blue worm")
            .env("MINA_CLIENT_TRUSTLIST", "0.0.0.0/0")
            .env("RAYON_NUM_THREADS", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .process_group(0)
            .spawn()
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("Failed to start {name} ({}): {e}", binary.display()),
                )
            })?;

        let pid = child.id();
        self.tracker().add(ProcessRecord {
            pid,
            service_name: name.to_string(),
            started_at: Local::now().to_rfc3339(),
            log_file: log_file_path,
            config_dir: self.config_dir_for_service(name),
            start_time: proc_stat(pid).map(|s| s.start_time),
        })?;
        info!("Service '{name}' started with PID {pid}");
        Ok(())
    }

    fn build_command(
        &self,
        service: &ServiceConfig,
        network_id: &str,
        network_path: &str,
        config_dir: &str,
    ) -> Result<(PathBuf, Vec<String>)> {
        let mina_bin = self.bin_path.join("mina");

        match service.service_type {
            ServiceType::SnarkWorker => {
                let mut args = vec![
                    "internal".to_string(),
                    "snark-worker".to_string(),
                    "-shutdown-on-disconnect".to_string(),
                    "false".to_string(),
                    "-config-directory".to_string(),
                    config_dir.to_string(),
                ];

                if let (Some(_host), Some(port)) = (
                    &service.snark_coordinator_host,
                    service.snark_coordinator_port,
                ) {
                    args.push("-daemon-address".to_string());
                    // In native mode, all services are on localhost
                    args.push(format!("127.0.0.1:{}", port));
                }

                if let Some(proof_level) = &service.snark_worker_proof_level {
                    args.push("-proof-level".to_string());
                    args.push(proof_level.clone());
                }

                Ok((mina_bin, args))
            }
            _ => Ok((
                mina_bin,
                self.build_daemon_args(service, network_id, network_path, config_dir)?,
            )),
        }
    }

    fn build_daemon_args(
        &self,
        service: &ServiceConfig,
        _network_id: &str,
        network_path: &str,
        config_dir: &str,
    ) -> Result<Vec<String>> {
        let client_port = service.client_port.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("daemon '{}' has no client_port", service.service_name),
            )
        })?;
        let rest_port = client_port + 1;
        let external_port = rest_port + 1;
        let metrics_port = external_port + 1;
        let libp2p_metrics_port = metrics_port + 1;

        let genesis_path = format!("{}/genesis_ledger.json", network_path);
        let precomputed_path = format!("{}/precomputed_blocks.log", config_dir);

        let mut args = vec![
            "daemon".to_string(),
            "-client-port".to_string(),
            client_port.to_string(),
            "-rest-port".to_string(),
            rest_port.to_string(),
            "-insecure-rest-server".to_string(),
            "-external-port".to_string(),
            external_port.to_string(),
            "-metrics-port".to_string(),
            metrics_port.to_string(),
            "-libp2p-metrics-port".to_string(),
            libp2p_metrics_port.to_string(),
            "-config-file".to_string(),
            genesis_path,
            "-log-json".to_string(),
            "-log-level".to_string(),
            "Trace".to_string(),
            "-file-log-level".to_string(),
            "Trace".to_string(),
            "-config-directory".to_string(),
            config_dir.to_string(),
            "-precomputed-blocks-file".to_string(),
            precomputed_path,
            "-log-txn-pool-gossip".to_string(),
            "true".to_string(),
            "-log-snark-work-gossip".to_string(),
            "true".to_string(),
            "-log-precomputed-blocks".to_string(),
            "true".to_string(),
            "-proof-level".to_string(),
            "full".to_string(),
        ];

        // Service-type-specific args
        match service.service_type {
            ServiceType::Seed => {
                args.push("-seed".to_string());
                self.add_libp2p_args(service, network_path, &mut args);
            }
            ServiceType::BlockProducer => {
                self.add_peers_args(service, network_path, &mut args);
                if service.private_key_path.is_some() {
                    args.push("-block-producer-key".to_string());
                    args.push(format!(
                        "{}/network-keypairs/{}.json",
                        network_path, service.service_name
                    ));
                }
                self.add_libp2p_args(service, network_path, &mut args);
            }
            ServiceType::SnarkCoordinator => {
                args.push("-work-selection".to_string());
                args.push("seq".to_string());
                self.add_peers_args(service, network_path, &mut args);
                if let Some(fees) = &service.snark_coordinator_fees {
                    args.push("-snark-worker-fee".to_string());
                    args.push(fees.clone());
                }
                if let Some(pk) = &service.public_key {
                    args.push("-run-snark-coordinator".to_string());
                    args.push(pk.clone());
                }
                self.add_libp2p_args(service, network_path, &mut args);
            }
            ServiceType::ArchiveNode => {
                self.add_peers_args(service, network_path, &mut args);
                if let Some(archive_port) = service.archive_port {
                    args.push("-archive-address".to_string());
                    args.push(format!("127.0.0.1:{}", archive_port));
                }
                self.add_libp2p_args(service, network_path, &mut args);
            }
            _ => {}
        }

        Ok(args)
    }

    fn add_peers_args(&self, service: &ServiceConfig, network_path: &str, args: &mut Vec<String>) {
        if service.peer_list_file.is_some() {
            args.push("-peer-list-file".to_string());
            args.push(format!("{}/peer_list_file.txt", network_path));
        } else if let Some(peers) = &service.peers {
            for peer in peers {
                args.push("-peer".to_string());
                args.push(peer.clone());
            }
        }
    }

    fn add_libp2p_args(&self, service: &ServiceConfig, network_path: &str, args: &mut Vec<String>) {
        if service.libp2p_keypair_path.is_some() {
            args.push("-libp2p-keypair".to_string());
            args.push(format!(
                "{}/libp2p-keypairs/{}.json",
                network_path, service.service_name
            ));
        } else if let Some(keypair) = &service.libp2p_keypair {
            args.push("-libp2p-keypair".to_string());
            args.push(keypair.clone());
        }
    }

    /// Stops every tracked process: SIGTERM to all groups, then SIGKILL after `timeout`.
    pub fn stop_all(&self, timeout: Duration) -> Result<()> {
        self.tracker().update(|records| {
            let all: Vec<String> = records.keys().cloned().collect();
            stop_records(records, &all, timeout);
            Ok(())
        })
    }

    /// Stops one service (and its mina-archive process for an archive node).
    pub fn stop_service(&self, service_name: &str, timeout: Duration) -> Result<()> {
        self.tracker().update(|records| {
            let archive = format!("{service_name}{ARCHIVE_SUFFIX}");
            if !records.contains_key(service_name) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Service '{service_name}' is not running"),
                ));
            }
            // the daemon goes first so it does not lose its archive mid-run
            stop_records(records, &[service_name.to_string()], timeout);
            stop_records(records, &[archive], timeout);
            Ok(())
        })
    }

    pub fn destroy(&self, timeout: Duration) -> Result<()> {
        self.stop_all(timeout)?;
        for dir in [self.logs_dir(), self.network_path.join(CONFIG_DIRECTORY)] {
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
        }
        Ok(())
    }

    pub fn service_logs(&self, service_name: &str) -> Result<String> {
        let log_file = self.logs_dir().join(format!("{service_name}.log"));
        fs::read_to_string(&log_file).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("no log for '{service_name}' at {}: {e}", log_file.display()),
            )
        })
    }

    pub fn precomputed_blocks(&self, service_name: &str) -> Result<String> {
        let file = self
            .config_dir_for_service(service_name)
            .join("precomputed_blocks.log");
        fs::read_to_string(&file).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "no precomputed blocks for '{service_name}' at {}: {e}",
                    file.display()
                ),
            )
        })
    }

    /// Tracked processes, sorted by name.
    pub fn status(&self) -> Result<Vec<ProcessStatus>> {
        let mut result: Vec<ProcessStatus> = self
            .tracker()
            .list()?
            .into_values()
            .map(|r| ProcessStatus {
                alive: r.is_alive(),
                name: r.service_name,
                pid: r.pid,
            })
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }
}

/// Process names minimina tracks for `service`.
fn process_names(service: &ServiceConfig) -> Vec<String> {
    let mut names = vec![service.service_name.clone()];
    if service.service_type == ServiceType::ArchiveNode {
        names.push(format!("{}{ARCHIVE_SUFFIX}", service.service_name));
    }
    names
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path '{}' is not valid UTF-8", path.display()),
        )
    })
}

/// Terminates the process groups of `names` in parallel and drops them from `records`.
fn stop_records(records: &mut Records, names: &[String], timeout: Duration) {
    let targets: Vec<ProcessRecord> = names
        .iter()
        .filter_map(|n| records.remove(n))
        .filter(ProcessRecord::is_alive)
        .collect();
    for record in &targets {
        info!("Stopping service '{}'", record.service_name);
        signal_group(record.pid, Signal::SIGTERM);
    }
    if wait_until_dead(&targets, timeout) {
        return;
    }
    for record in targets.iter().filter(|r| r.is_alive()) {
        warn!(
            "Service '{}' did not stop within {}s; killing it",
            record.service_name,
            timeout.as_secs()
        );
        signal_group(record.pid, Signal::SIGKILL);
    }
    wait_until_dead(&targets, Duration::from_secs(5));
}

fn signal_group(pid: u32, sig: Signal) {
    let pgid = Pid::from_raw(pid as i32);
    // processes started before process groups were used are not group leaders
    if signal::killpg(pgid, sig).is_err() {
        let _ = signal::kill(pgid, sig);
    }
}

fn wait_until_dead(records: &[ProcessRecord], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if records.iter().all(|r| !r.is_alive()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> NativeManager {
        NativeManager::new(
            Path::new("/net"),
            Path::new("/opt/mina"),
            DEFAULT_POSTGRES_URI,
        )
    }

    fn args_for(service: &ServiceConfig) -> (PathBuf, Vec<String>) {
        manager()
            .build_command(service, "net", "/net", "/net/config-directory/x")
            .unwrap()
    }

    fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    }

    #[test]
    fn daemon_ports_follow_client_port() {
        let seed = ServiceConfig {
            service_type: ServiceType::Seed,
            service_name: "seed".into(),
            client_port: Some(3100),
            libp2p_keypair_path: Some("k".into()),
            ..Default::default()
        };
        let (bin, args) = args_for(&seed);
        assert_eq!(bin, Path::new("/opt/mina/mina"));
        assert_eq!(args[0], "daemon");
        assert!(args.contains(&"-seed".to_string()));
        for (flag, port) in [
            ("-client-port", "3100"),
            ("-rest-port", "3101"),
            ("-external-port", "3102"),
            ("-metrics-port", "3103"),
            ("-libp2p-metrics-port", "3104"),
        ] {
            assert_eq!(value_of(&args, flag), Some(port), "{flag}");
        }
        assert_eq!(
            value_of(&args, "-config-file"),
            Some("/net/genesis_ledger.json")
        );
        assert_eq!(
            value_of(&args, "-libp2p-keypair"),
            Some("/net/libp2p-keypairs/seed.json")
        );
    }

    #[test]
    fn block_producer_uses_peer_list_and_key() {
        let bp = ServiceConfig {
            service_type: ServiceType::BlockProducer,
            service_name: "bp".into(),
            client_port: Some(4000),
            private_key_path: Some("k".into()),
            peer_list_file: Some("p".into()),
            libp2p_keypair: Some("inline".into()),
            ..Default::default()
        };
        let (_, args) = args_for(&bp);
        assert_eq!(
            value_of(&args, "-peer-list-file"),
            Some("/net/peer_list_file.txt")
        );
        assert_eq!(
            value_of(&args, "-block-producer-key"),
            Some("/net/network-keypairs/bp.json")
        );
        assert_eq!(value_of(&args, "-libp2p-keypair"), Some("inline"));
        assert!(!args.contains(&"-seed".to_string()));
    }

    #[test]
    fn snark_coordinator_and_worker() {
        let coordinator = ServiceConfig {
            service_type: ServiceType::SnarkCoordinator,
            service_name: "coord".into(),
            client_port: Some(7000),
            public_key: Some("B62q".into()),
            snark_coordinator_fees: Some("0.001".into()),
            peers: Some(vec!["/ip4/1/tcp/2/p2p/x".into()]),
            ..Default::default()
        };
        let (_, args) = args_for(&coordinator);
        assert_eq!(value_of(&args, "-run-snark-coordinator"), Some("B62q"));
        assert_eq!(value_of(&args, "-snark-worker-fee"), Some("0.001"));
        assert_eq!(value_of(&args, "-work-selection"), Some("seq"));
        assert_eq!(value_of(&args, "-peer"), Some("/ip4/1/tcp/2/p2p/x"));

        let worker = ServiceConfig {
            service_type: ServiceType::SnarkWorker,
            service_name: "w".into(),
            snark_coordinator_host: Some("coord".into()),
            snark_coordinator_port: Some(7000),
            snark_worker_proof_level: Some("none".into()),
            ..Default::default()
        };
        let (_, args) = args_for(&worker);
        assert_eq!(args[..2], ["internal", "snark-worker"]);
        assert_eq!(value_of(&args, "-daemon-address"), Some("127.0.0.1:7000"));
        assert_eq!(value_of(&args, "-proof-level"), Some("none"));
    }

    #[test]
    fn archive_node_points_at_archive_port() {
        let archive = ServiceConfig {
            service_type: ServiceType::ArchiveNode,
            service_name: "arch".into(),
            client_port: Some(5000),
            archive_port: Some(3086),
            ..Default::default()
        };
        let (_, args) = args_for(&archive);
        assert_eq!(value_of(&args, "-archive-address"), Some("127.0.0.1:3086"));
    }

    #[test]
    fn daemon_without_client_port_is_rejected() {
        let bp = ServiceConfig {
            service_type: ServiceType::BlockProducer,
            service_name: "bp".into(),
            ..Default::default()
        };
        let err = manager()
            .build_command(&bp, "net", "/net", "/c")
            .unwrap_err();
        assert!(err.to_string().contains("'bp' has no client_port"));
    }

    #[test]
    fn archive_db_is_per_network() {
        let native = NativeManager::new(
            Path::new("/home/u/.minimina/My-Net.1"),
            Path::new("/b"),
            "postgres://u:p@db:5432/",
        );
        assert_eq!(native.archive_db_name(), "minimina_my_net_1");
        assert_eq!(
            native.archive_db_uri(),
            "postgres://u:p@db:5432/minimina_my_net_1"
        );
        assert_eq!(
            native.maintenance_db_uri(),
            "postgres://u:p@db:5432/postgres"
        );
    }

    /// A network dir plus a bin dir whose `mina` and `mina-archive` run `script`.
    ///
    /// Holds a lock for the test's lifetime: a fork in one test thread inherits the
    /// port probe sockets of another until `exec`, so spawning tests run one at a time.
    struct Sandbox {
        net: tempfile::TempDir,
        bin: tempfile::TempDir,
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    static SPAWNING_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl Sandbox {
        fn new(script: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let sandbox = Sandbox {
                _serial: SPAWNING_TESTS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                net: tempfile::tempdir().unwrap(),
                bin: tempfile::tempdir().unwrap(),
            };
            for name in ["mina", "mina-archive"] {
                let path = sandbox.bin.path().join(name);
                fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            sandbox
        }

        fn manager(&self) -> NativeManager {
            NativeManager::new(self.net.path(), self.bin.path(), DEFAULT_POSTGRES_URI)
        }
    }

    /// Start of 10 ports nobody else in this test run uses: a per-process counter
    /// below the ephemeral range, skipping blocks something on the host holds.
    fn free_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(0);
        let base = 20000 + (std::process::id() % 500) as u16 * 20;
        loop {
            let port = base + NEXT.fetch_add(10, Ordering::SeqCst);
            assert!(port < 32000, "ran out of test ports");
            let block: Vec<_> = (0..10)
                .map(|o| port_manager::PortUse {
                    port: port + o,
                    service: "probe".into(),
                })
                .collect();
            if port_manager::check_ports_available(&block).is_ok() {
                return port;
            }
        }
    }

    /// Fake daemon body that listens on its `-external-port` (as a seed's libp2p
    /// does) after `delay` seconds, then idles.
    fn listening_daemon(delay: u32) -> String {
        format!(
            r#"port=""; prev=""
for a in "$@"; do [ "$prev" = "-external-port" ] && port=$a; prev=$a; done
sleep {delay}
[ -n "$port" ] && exec python3 -c "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', $port)); s.listen(); time.sleep(300)"
exec sleep 300"#
        )
    }

    const SEED_WAIT: Duration = Duration::from_secs(20);

    fn producer(name: &str) -> ServiceConfig {
        ServiceConfig {
            service_type: ServiceType::BlockProducer,
            ..seed(name)
        }
    }

    fn seed(name: &str) -> ServiceConfig {
        ServiceConfig {
            service_type: ServiceType::Seed,
            service_name: name.into(),
            client_port: Some(free_port()),
            ..Default::default()
        }
    }

    /// Waits until the service has logged `needle` `count` times.
    fn wait_for_log(native: &NativeManager, name: &str, needle: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while native
            .service_logs(name)
            .map_or(0, |log| log.matches(needle).count())
            < count
        {
            assert!(Instant::now() < deadline, "'{name}' never logged {needle}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn alive(native: &NativeManager) -> Vec<String> {
        native
            .status()
            .unwrap()
            .into_iter()
            .filter(|p| p.alive)
            .map(|p| p.name)
            .collect()
    }

    #[test]
    fn start_status_stop_lifecycle() {
        let sandbox = Sandbox::new("echo started; exec sleep 300");
        let native = sandbox.manager();
        let a = seed("a");

        native.start_service(&a, "net").unwrap();
        assert_eq!(alive(&native), vec!["a"]);
        let record = native.tracker().get("a").unwrap().unwrap();
        assert!(record.start_time.is_some());
        // own process group, so signals reach helper children
        assert_eq!(
            nix::unistd::getpgid(Some(Pid::from_raw(record.pid as i32))).unwrap(),
            Pid::from_raw(record.pid as i32)
        );

        let err = native.start_service(&a, "net").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        wait_for_log(&native, "a", "started", 1);
        native.stop_service("a", Duration::from_secs(5)).unwrap();
        assert!(alive(&native).is_empty());
        assert!(native.status().unwrap().is_empty());
        assert_eq!(
            native
                .stop_service("a", Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );

        // a restart appends to the log instead of truncating it
        native.start_service(&a, "net").unwrap();
        wait_for_log(&native, "a", "started", 2);
        native.stop_all(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn stop_escalates_to_sigkill_after_timeout() {
        let sandbox = Sandbox::new("trap '' TERM; while :; do sleep 1; done");
        let native = sandbox.manager();
        native.start_service(&seed("stubborn"), "net").unwrap();
        let started = Instant::now();
        native.stop_all(Duration::from_millis(500)).unwrap();
        assert!(alive(&native).is_empty());
        assert!(native.status().unwrap().is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn start_all_refuses_a_running_network() {
        let sandbox = Sandbox::new("exec sleep 300");
        let native = sandbox.manager();
        let services = vec![seed("a"), seed("b")];
        native.start_all(&services, "net", SEED_WAIT).unwrap();
        assert_eq!(alive(&native), vec!["a", "b"]);

        let err = native.start_all(&services, "net", SEED_WAIT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(err.to_string(), "already running: a, b");
        native.stop_all(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn start_all_rolls_back_when_a_service_fails() {
        let sandbox = Sandbox::new(&listening_daemon(0));
        fs::remove_file(sandbox.bin.path().join("mina-archive")).unwrap();
        let native = sandbox.manager();
        let mut archive = seed("arch");
        archive.service_type = ServiceType::ArchiveNode;
        archive.archive_port = Some(free_port());

        let err = native
            .start_all(&[seed("a"), archive], "net", SEED_WAIT)
            .unwrap_err();
        assert!(err.to_string().contains("mina-archive"), "{err}");
        assert!(alive(&native).is_empty(), "seed 'a' must be stopped again");
    }

    #[test]
    fn non_seeds_start_after_the_seed_accepts_connections() {
        let sandbox = Sandbox::new(&listening_daemon(1));
        let native = sandbox.manager();
        let started = Instant::now();
        native
            .start_all(&[producer("bp"), seed("s")], "net", SEED_WAIT)
            .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert_eq!(alive(&native), vec!["bp", "s"]);
        let record = |n: &str| native.tracker().get(n).unwrap().unwrap();
        assert!(record("s").started_at <= record("bp").started_at);
        native.stop_all(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn seed_exiting_during_startup_fails_fast_without_starting_others() {
        let sandbox = Sandbox::new("exit 3");
        let native = sandbox.manager();
        let started = Instant::now();
        let err = native
            .start_all(&[seed("s"), producer("bp")], "net", SEED_WAIT)
            .unwrap_err();
        assert!(
            err.to_string().contains("seed 's' exited during startup"),
            "{err}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(native.tracker().get("bp").unwrap().is_none());
    }

    #[test]
    fn seed_that_never_listens_times_out() {
        let sandbox = Sandbox::new("exec sleep 300");
        let native = sandbox.manager();
        let err = native
            .start_all(&[seed("s"), producer("bp")], "net", Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(alive(&native).is_empty(), "the seed is stopped again");
    }

    #[test]
    fn archive_node_runs_mina_archive_first() {
        let sandbox = Sandbox::new("echo \"$0 $*\"; exec sleep 300");
        let native = sandbox.manager();
        let mut archive = seed("arch");
        archive.service_type = ServiceType::ArchiveNode;
        let archive_port = free_port();
        archive.archive_port = Some(archive_port);

        native.start_service(&archive, "net").unwrap();
        assert_eq!(alive(&native), vec!["arch", "arch-archive"]);
        wait_for_log(&native, "arch-archive", "--server-port", 1);
        let log = native.service_logs("arch-archive").unwrap();
        assert!(log.contains(
            "mina-archive run --postgres-uri postgres://postgres:postgres@localhost:5432/minimina_"
        ));
        assert!(log.contains(&format!("--server-port {archive_port}")));

        native.stop_service("arch", Duration::from_secs(5)).unwrap();
        assert!(native.status().unwrap().is_empty());
    }

    #[test]
    fn reset_state_requires_stopped_node() {
        let sandbox = Sandbox::new("exec sleep 300");
        let native = sandbox.manager();
        let a = seed("a");
        native.start_service(&a, "net").unwrap();
        let state = native.config_dir_for_service("a").join("state");
        fs::write(&state, "x").unwrap();
        assert!(native.reset_state("a").is_err());
        native.stop_all(Duration::from_secs(5)).unwrap();
        native.reset_state("a").unwrap();
        assert!(!state.exists());
        assert!(native.config_dir_for_service("a").is_dir());
    }

    #[test]
    fn missing_logs_and_blocks_are_errors() {
        let sandbox = Sandbox::new("true");
        let native = sandbox.manager();
        assert!(native
            .service_logs("ghost")
            .unwrap_err()
            .to_string()
            .contains("no log for 'ghost'"));
        assert!(native.precomputed_blocks("ghost").is_err());
        fs::create_dir_all(native.config_dir_for_service("g")).unwrap();
        fs::write(
            native
                .config_dir_for_service("g")
                .join("precomputed_blocks.log"),
            "{}",
        )
        .unwrap();
        assert_eq!(native.precomputed_blocks("g").unwrap(), "{}");
    }
}
