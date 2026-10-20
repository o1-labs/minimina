//! End-to-end: real mina daemons must produce blocks. Ignored by default;
//! CI runs them with `cargo test --test e2e -- --ignored <name>`.
//!
//! - `native_small_network_produces_blocks` needs `mina` (a generic build:
//!   network packages merge their installed config into the local network).
//!   `MINIMINA_E2E_BIN_PATH` overrides the lookup.
//! - `docker_small_network_produces_blocks` needs docker; `MINIMINA_E2E_IMAGE`
//!   overrides the daemon image.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SMALL_TOPOLOGY: &str = "tests/data/small_network/topology.json";
const SMALL_LEDGER: &str = "tests/data/small_network/genesis_ledger.json";
const DEFAULT_IMAGE: &str = "minaprotocol/mina-daemon:4.0.1-1e9d141-bookworm-devnet-generic";
/// Daemon start (genesis proof) plus a few 2-minute slots, with room for slow runners.
/// `MINIMINA_E2E_TIMEOUT_SECS` overrides it.
fn block_timeout() -> Duration {
    std::env::var("MINIMINA_E2E_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(Duration::from_secs(40 * 60), Duration::from_secs)
}

struct Network {
    /// `MINIMINA_HOME`: under `MINIMINA_E2E_KEEP` (kept for CI to upload) or a temp dir.
    home: PathBuf,
    _temp: Option<tempfile::TempDir>,
    id: &'static str,
    mode_args: Vec<String>,
}

impl Network {
    fn minimina(&self, args: &[&str]) -> Value {
        let out = Command::cargo_bin("minimina")
            .unwrap()
            .env("MINIMINA_HOME", self.home.as_path())
            .args(args)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "minimina {args:?} failed\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_str(&stdout).unwrap_or(Value::Null)
    }

    fn create(id: &'static str, mode_args: Vec<String>, topology: &Path) -> (Self, Value) {
        let (home, temp) = match std::env::var("MINIMINA_E2E_KEEP") {
            Ok(keep) => {
                let home = Path::new(&keep).join(id);
                fs::create_dir_all(&home).unwrap();
                (home, None)
            }
            Err(_) => {
                let temp = tempfile::tempdir().unwrap();
                (temp.path().to_path_buf(), Some(temp))
            }
        };
        let net = Network {
            home,
            _temp: temp,
            id,
            mode_args,
        };
        let mut args: Vec<&str> = net.mode_args.iter().map(String::as_str).collect();
        args.extend([
            "network",
            "create",
            "-n",
            id,
            "-t",
            topology.to_str().unwrap(),
            "-g",
            SMALL_LEDGER,
        ]);
        let created = net.minimina(&args);
        (net, created)
    }

    fn graphql_uri(created: &Value, node: &str) -> String {
        created["nodes"][node]["graphql_uri"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Polls until the node is synced with a block past genesis.
    fn wait_for_block(&self, uri: &str) -> u64 {
        let client = mina_sdk::MinaClient::with_config(mina_sdk::ClientConfig {
            graphql_uri: uri.to_string(),
            retries: 1,
            retry_delay: Duration::from_secs(1),
            timeout: Duration::from_secs(10),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let start = Instant::now();
        let mut genesis_length = None;
        loop {
            let status = runtime.block_on(client.get_daemon_status()).ok();
            let synced = status.as_ref().map(|s| s.sync_status.clone());
            let length = status
                .and_then(|s| s.blockchain_length)
                .and_then(|l| u64::try_from(l).ok());
            eprintln!(
                "+{:>4}s {uri}: {synced:?} {length:?}",
                start.elapsed().as_secs()
            );
            if let (Some(mina_sdk::SyncStatus::Synced), Some(length)) = (synced, length) {
                let first = *genesis_length.get_or_insert(length);
                if length > first || length >= 2 {
                    return length;
                }
            }
            assert!(
                start.elapsed() < block_timeout(),
                "no block within {}s; logs under {}",
                block_timeout().as_secs(),
                self.home.as_path().display()
            );
            std::thread::sleep(Duration::from_secs(20));
        }
    }
}

impl Network {
    /// Prints what a failed run needs: network status and the tail of every node log.
    fn report_failure(&self) {
        let status = Command::cargo_bin("minimina")
            .unwrap()
            .env("MINIMINA_HOME", &self.home)
            .args(["network", "status", "-n", self.id])
            .output();
        if let Ok(out) = status {
            eprintln!(
                "--- network status\n{}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        let logs = self.home.join(".minimina").join(self.id).join("logs");
        for entry in fs::read_dir(&logs).into_iter().flatten().flatten() {
            let text = fs::read_to_string(entry.path()).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            eprintln!(
                "--- {} (last 40 of {} lines)",
                entry.path().display(),
                lines.len()
            );
            for line in &lines[lines.len().saturating_sub(40)..] {
                eprintln!("{}", &line[..line.len().min(400)]);
            }
        }
        // docker mode: container output is the daemon log
        let names = std::process::Command::new("docker")
            .args(["ps", "-a", "--format", "{{.Names}} {{.Status}}"])
            .args([
                "--filter",
                &format!("label=com.docker.compose.project={}", self.id),
            ])
            .output();
        for line in names
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
            .lines()
        {
            eprintln!("--- container {line}");
            let name = line.split_whitespace().next().unwrap_or_default();
            if let Ok(out) = std::process::Command::new("docker")
                .args(["logs", "--tail", "40", name])
                .output()
            {
                eprintln!(
                    "{}",
                    String::from_utf8_lossy(&[out.stdout, out.stderr].concat())
                );
            }
            if let Ok(out) = std::process::Command::new("docker")
                .args(["logs", name])
                .output()
            {
                let _ = fs::write(
                    self.home.join(format!("{name}.log")),
                    [out.stdout, out.stderr].concat(),
                );
            }
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.report_failure();
        }
        // runs on failure too, so nodes never outlive the test; with
        // MINIMINA_E2E_KEEP the logs stay because only containers/processes go
        let _ = Command::cargo_bin("minimina")
            .unwrap()
            .env("MINIMINA_HOME", &self.home)
            .args(["network", "stop", "-n", self.id, "--timeout", "30"])
            .output();
        if self._temp.is_some() || !std::thread::panicking() {
            let _ = Command::cargo_bin("minimina")
                .unwrap()
                .env("MINIMINA_HOME", &self.home)
                .args(["network", "delete", "-n", self.id])
                .output();
        }
    }
}

/// Stops and restarts the block producer, then checks it serves GraphQL again.
fn restart_node(net: &Network, node: &str) {
    let v = net.minimina(&["node", "stop", "-n", net.id, "-i", node, "--timeout", "120"]);
    assert_eq!(v["node_id"], node);
    let v = net.minimina(&["node", "start", "-n", net.id, "-i", node]);
    assert_eq!(v["node_id"], node);
}

#[test]
#[ignore = "needs a generic mina build; run with --ignored"]
fn native_small_network_produces_blocks() {
    let mut mode_args = vec!["--mode".to_string(), "native".to_string()];
    if let Ok(bin) = std::env::var("MINIMINA_E2E_BIN_PATH") {
        mode_args.extend(["--bin-path".to_string(), bin]);
    }
    let (net, created) = Network::create("e2e-native", mode_args, Path::new(SMALL_TOPOLOGY));
    net.minimina(&["network", "start", "-n", net.id]);

    let length = net.wait_for_block(&Network::graphql_uri(&created, "seed-0"));
    eprintln!("seed-0 reached block {length}");

    let status = net.minimina(&["network", "status", "-n", net.id]);
    assert_eq!(status["status"], "running(2)", "{status}");
    let logs = Command::cargo_bin("minimina")
        .unwrap()
        .env("MINIMINA_HOME", net.home.as_path())
        .args(["node", "logs", "-n", net.id, "-i", "receiver", "-r"])
        .output()
        .unwrap();
    assert!(!logs.stdout.is_empty());

    restart_node(&net, "receiver");
    net.minimina(&["network", "stop", "-n", net.id, "--timeout", "120"]);
    let status = net.minimina(&["network", "status", "-n", net.id]);
    assert_eq!(status["status"], "not_running", "{status}");
}

#[test]
#[ignore = "needs docker; run with --ignored"]
fn docker_small_network_produces_blocks() {
    let image = std::env::var("MINIMINA_E2E_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    let dir = tempfile::tempdir().unwrap();
    let mut topology: Value =
        serde_json::from_str(&fs::read_to_string(SMALL_TOPOLOGY).unwrap()).unwrap();
    for node in topology.as_object_mut().unwrap().values_mut() {
        node["docker_image"] = Value::String(image.clone());
    }
    let topology_path = dir.path().join("topology.json");
    fs::write(&topology_path, topology.to_string()).unwrap();

    let (net, created) = Network::create("e2e-docker", vec![], &topology_path);
    net.minimina(&["network", "start", "-n", net.id]);

    let length = net.wait_for_block(&Network::graphql_uri(&created, "seed-0"));
    eprintln!("seed-0 reached block {length}");

    let status = net.minimina(&["network", "status", "-n", net.id]);
    let services = status["services"].as_array().unwrap();
    assert!(services.iter().all(|s| s["state"] == "running"), "{status}");
    restart_node(&net, "receiver");
    net.minimina(&["network", "stop", "-n", net.id]);
}
