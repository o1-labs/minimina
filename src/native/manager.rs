use crate::docker::compose::CONFIG_DIRECTORY;
use crate::native::port_manager;
use crate::native::process_tracker::{ProcessRecord, ProcessTracker};
use crate::service::{ServiceConfig, ServiceType};
use chrono::Local;
use log::{info, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct NativeManager {
    pub network_path: PathBuf,
    pub bin_path: PathBuf,
}

impl NativeManager {
    pub fn new(network_path: &Path, bin_path: &Path) -> Self {
        NativeManager {
            network_path: network_path.to_path_buf(),
            bin_path: bin_path.to_path_buf(),
        }
    }

    fn tracker(&self) -> ProcessTracker {
        ProcessTracker::new(&self.network_path)
    }

    fn logs_dir(&self) -> PathBuf {
        self.network_path.join("logs")
    }

    fn config_dir_for_service(&self, service_name: &str) -> PathBuf {
        self.network_path.join(CONFIG_DIRECTORY).join(service_name)
    }

    /// Generate native config (stores services.json, creates dirs)
    pub fn generate_config(&self, configs: &[ServiceConfig]) -> Result<()> {
        // Create logs directory
        fs::create_dir_all(self.logs_dir())?;
        // Create per-service config directories
        for config in configs {
            fs::create_dir_all(self.config_dir_for_service(&config.service_name))?;
        }
        Ok(())
    }

    pub fn start_all(&self, services: &[ServiceConfig], network_id: &str) -> Result<()> {
        let ports = port_manager::collect_all_ports(services);
        port_manager::check_ports_available(&ports)?;

        for service in services {
            // Skip uptime service backend for now
            if service.service_type == ServiceType::UptimeServiceBackend {
                warn!(
                    "Skipping uptime service backend '{}' in native mode",
                    service.service_name
                );
                continue;
            }
            self.start_service(service, network_id)?;
        }
        Ok(())
    }

    pub fn stop_all(&self) -> Result<()> {
        let tracker = self.tracker();
        let records = tracker.list()?;
        for (service_name, record) in &records {
            info!("Stopping service '{}'", service_name);
            Self::kill_process(record.pid);
        }
        // Clear tracker
        tracker.save(&HashMap::new())?;
        Ok(())
    }

    pub fn start_service(&self, service: &ServiceConfig, network_id: &str) -> Result<()> {
        let service_name = &service.service_name;
        let log_file_path = self.logs_dir().join(format!("{}.log", service_name));
        let config_dir = self.config_dir_for_service(service_name);
        fs::create_dir_all(&config_dir)?;

        let utf8 = |p: &Path| {
            p.to_str().map(str::to_string).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path '{}' is not valid UTF-8", p.display()),
                )
            })
        };
        let network_path_str = utf8(&self.network_path)?;
        let config_dir_str = utf8(&config_dir)?;

        // Build command based on service type
        let (binary, args) =
            self.build_command(service, network_id, &network_path_str, &config_dir_str)?;

        info!(
            "Starting service '{}' with command: {} {}",
            service_name,
            binary.display(),
            args.join(" ")
        );

        let log_file = fs::File::create(&log_file_path)?;
        let log_file_err = log_file.try_clone()?;

        let child = Command::new(&binary)
            .args(&args)
            .env("MINA_PRIVKEY_PASS", "naughty blue worm")
            .env("MINA_LIBP2P_PASS", "naughty blue worm")
            .env("MINA_CLIENT_TRUSTLIST", "0.0.0.0/0")
            .env("RAYON_NUM_THREADS", "2")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .map_err(|e| io::Error::other(format!("Failed to start {}: {}", service_name, e)))?;

        let record = ProcessRecord {
            pid: child.id(),
            service_name: service_name.clone(),
            started_at: Local::now().to_rfc3339(),
            log_file: log_file_path,
            config_dir,
        };

        self.tracker().add(record)?;
        info!("Service '{}' started with PID {}", service_name, child.id());
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
            ServiceType::ArchiveNode => {
                // The archive node daemon command
                // First we need the mina-archive service, but for native we combine them
                Ok((
                    mina_bin,
                    self.build_daemon_args(service, network_id, network_path, config_dir),
                ))
            }
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
                self.build_daemon_args(service, network_id, network_path, config_dir),
            )),
        }
    }

    fn build_daemon_args(
        &self,
        service: &ServiceConfig,
        _network_id: &str,
        network_path: &str,
        config_dir: &str,
    ) -> Vec<String> {
        let client_port = service.client_port.unwrap_or(3100);
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

        args
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

    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        let tracker = self.tracker();
        if let Some(record) = tracker.get(service_name)? {
            Self::kill_process(record.pid);
            tracker.remove(service_name)?;
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Service '{}' not found", service_name),
            ))
        }
    }

    pub fn destroy(&self) -> Result<()> {
        self.stop_all()?;
        // Clean up logs and config dirs
        let logs_dir = self.logs_dir();
        if logs_dir.exists() {
            fs::remove_dir_all(&logs_dir)?;
        }
        let config_base = self.network_path.join(CONFIG_DIRECTORY);
        if config_base.exists() {
            fs::remove_dir_all(&config_base)?;
        }
        Ok(())
    }

    pub fn service_logs(&self, service_name: &str) -> Result<String> {
        let log_file = self.logs_dir().join(format!("{}.log", service_name));
        if log_file.exists() {
            fs::read_to_string(&log_file)
        } else {
            Ok(String::new())
        }
    }

    pub fn list_services(&self) -> Result<Vec<(String, bool)>> {
        let tracker = self.tracker();
        let records = tracker.list()?;
        let mut result = Vec::new();
        for (name, record) in records {
            let alive = ProcessTracker::is_alive(record.pid);
            result.push((name, alive));
        }
        Ok(result)
    }

    fn kill_process(pid: u32) {
        let nix_pid = Pid::from_raw(pid as i32);
        // Try SIGTERM first
        if signal::kill(nix_pid, Signal::SIGTERM).is_ok() {
            // Wait briefly for graceful shutdown
            std::thread::sleep(std::time::Duration::from_secs(2));
            // Check if still alive, force kill if needed
            if ProcessTracker::is_alive(pid) {
                let _ = signal::kill(nix_pid, Signal::SIGKILL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> NativeManager {
        NativeManager::new(Path::new("/net"), Path::new("/opt/mina"))
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
    fn logs_of_unknown_service_are_empty_and_stop_reports_missing() {
        let net = tempfile::tempdir().unwrap();
        let native = NativeManager::new(net.path(), Path::new("/opt/mina"));
        assert_eq!(native.service_logs("ghost").unwrap(), "");
        let err = native.stop_service("ghost").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(native.list_services().unwrap().is_empty());
    }
}
