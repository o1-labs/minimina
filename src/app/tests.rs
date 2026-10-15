//! Handler tests: real filesystem under a temp `MINIMINA_HOME`, fake `docker`/`mina`.

use super::run_with;
use crate::{cli::Cli, directory_manager::DirectoryManager, runner::fake::FakeRunner};
use clap::Parser;
use std::{path::Path, rc::Rc};

const SMALL_TOPOLOGY: &str = "tests/data/small_network/topology.json";
const SMALL_LEDGER: &str = "tests/data/small_network/genesis_ledger.json";

struct Harness {
    _home: tempfile::TempDir,
    dirs: DirectoryManager,
    fake: Rc<FakeRunner>,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let dirs = DirectoryManager::with_base_path(home.path().join(".minimina"));
        Harness {
            _home: home,
            dirs,
            fake: Rc::new(FakeRunner::default()),
        }
    }

    /// Queues the replies of the docker-mode environment check.
    fn docker_ok(&self) -> &FakeRunner {
        self.fake
            .reply(0, "Docker version 27", "")
            .reply(0, "2.29.1", "")
    }

    fn run(&self, args: &[&str]) -> anyhow::Result<()> {
        let cli =
            Cli::try_parse_from(std::iter::once("minimina").chain(args.iter().copied())).unwrap();
        run_with(cli, self.dirs.clone(), self.fake.clone())
    }

    fn compose(&self, network_id: &str, rest: &str) -> String {
        let compose = self
            .dirs
            .network_path(network_id)
            .join("docker-compose.yaml");
        format!(
            "docker compose -f {} -p {network_id} {rest}",
            compose.display()
        )
    }

    fn create_small(&self, network_id: &str) -> anyhow::Result<()> {
        self.run(&[
            "network",
            "create",
            "-n",
            network_id,
            "-t",
            SMALL_TOPOLOGY,
            "-g",
            SMALL_LEDGER,
        ])
    }
}

fn fake_mina_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("mina"), "").unwrap();
    dir
}

fn path_arg(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn list_without_networks_succeeds() {
    let h = Harness::new();
    h.docker_ok();
    h.run(&["network", "list"]).unwrap();
}

#[test]
fn info_on_missing_network_fails() {
    let h = Harness::new();
    h.docker_ok();
    let err = h.run(&["network", "info", "-n", "nope"]).unwrap_err();
    assert!(err.to_string().contains("network 'nope' does not exist"));
}

#[test]
fn docker_environment_failure_stops_before_any_command() {
    let h = Harness::new();
    h.fake.reply(127, "", "");
    let err = h.run(&["network", "list"]).unwrap_err();
    assert!(err.to_string().contains("Docker is not installed"));
    assert_eq!(h.fake.lines(), vec!["docker --version"]);
}

#[test]
fn docker_create_from_topology_writes_network_files() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();

    let net = h.dirs.network_path("small");
    for file in [
        "docker-compose.yaml",
        "network.json",
        "services.json",
        "genesis_ledger.json",
        "topology.json",
        "peer_list_file.txt",
        "network-keypairs/receiver.json",
        "libp2p-keypairs/seed-0.json",
    ] {
        assert!(net.join(file).exists(), "missing {file}");
    }
    assert_eq!(h.fake.lines()[2..], [h.compose("small", "create")]);
    assert!(h.dirs.get_network_info("small").unwrap().contains("seed-0"));
}

#[test]
fn docker_create_reports_compose_failure() {
    let h = Harness::new();
    h.docker_ok().reply(1, "", "no such image");
    let err = h.create_small("small").unwrap_err();
    assert!(err.to_string().contains("docker compose create"));
    assert!(err.to_string().contains("no such image"));
}

#[test]
fn create_over_existing_network_tears_it_down_first() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    h.docker_ok();
    h.create_small("small").unwrap();
    assert!(h
        .fake
        .lines()
        .contains(&h.compose("small", "down --remove-orphans")));
}

#[test]
fn genesis_ledger_without_topology_is_rejected() {
    let h = Harness::new();
    h.docker_ok();
    let err = h
        .run(&["network", "create", "-n", "x", "-g", SMALL_LEDGER])
        .unwrap_err();
    assert!(err.to_string().contains("Must provide a topology file"));
    assert!(!h.dirs.network_path_exists("x"));
}

#[test]
fn topology_without_genesis_ledger_is_rejected() {
    let h = Harness::new();
    h.docker_ok();
    let err = h
        .run(&["network", "create", "-n", "x", "-t", SMALL_TOPOLOGY])
        .unwrap_err();
    assert!(err.to_string().contains("Must provide a genesis ledger"));
    assert!(!h.dirs.network_path_exists("x"));
}

#[test]
fn docker_start_stop_delete_drive_compose() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();

    h.docker_ok();
    h.run(&["network", "start", "-n", "small"]).unwrap();
    h.docker_ok();
    h.run(&["network", "stop", "-n", "small"]).unwrap();
    h.docker_ok();
    h.run(&["network", "delete", "-n", "small"]).unwrap();

    let lines = h.fake.lines();
    for expected in [
        h.compose("small", "start"),
        h.compose("small", "stop"),
        h.compose("small", "down --volumes --rmi all --remove-orphans"),
    ] {
        assert!(
            lines.contains(&expected),
            "missing `{expected}` in {lines:#?}"
        );
    }
    assert!(!h.dirs.network_path_exists("small"));
}

#[test]
fn node_stop_reports_compose_stderr() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    h.docker_ok().reply(1, "", "no such service");
    let err = h
        .run(&["node", "stop", "-n", "small", "-i", "seed-0"])
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Failed to stop node 'seed-0': no such service"
    );
}

#[test]
fn node_start_fails_for_unknown_node() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    h.docker_ok().reply(0, "", "");
    let err = h
        .run(&["node", "start", "-n", "small", "-i", "ghost"])
        .unwrap_err();
    assert!(err.to_string().contains("Node 'ghost' does not exist"));
}

#[test]
fn node_logs_returns_docker_logs() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    h.docker_ok().reply(0, "log line", "");
    h.run(&["node", "logs", "-n", "small", "-i", "seed-0", "-r"])
        .unwrap();
    assert_eq!(h.fake.lines().last().unwrap(), "docker logs seed-0-small");

    h.docker_ok().reply(1, "", "gone");
    let err = h
        .run(&["node", "logs", "-n", "small", "-i", "seed-0"])
        .unwrap_err();
    assert!(err.to_string().contains("gone"));
}

#[test]
fn archive_commands_require_an_archive_node() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    for args in [
        &["node", "dump-archive-data", "-n", "small", "-i", "seed-0"][..],
        &[
            "node",
            "run-replayer",
            "-n",
            "small",
            "-i",
            "seed-0",
            "-s",
            "1",
        ][..],
    ] {
        h.docker_ok();
        let err = h.run(args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Node 'seed-0' is not an archive node in 'small' network."
        );
    }
}

#[test]
fn native_create_prepares_directories_without_running_anything() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    h.run(&[
        "--mode",
        "native",
        "--bin-path",
        path_arg(bin.path()),
        "network",
        "create",
        "-n",
        "nat",
        "-t",
        SMALL_TOPOLOGY,
        "-g",
        SMALL_LEDGER,
    ])
    .unwrap();

    let net = h.dirs.network_path("nat");
    assert!(net.join("logs").is_dir());
    assert!(net.join("config-directory/seed-0").is_dir());
    assert!(net.join("services.json").exists());
    assert!(h.fake.lines().is_empty());
}

#[test]
fn native_default_network_generates_keys_with_mina() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    for _ in 0..6 {
        h.fake.reply(0, "Public key: B62qtest\n", "");
    }
    for i in 0..6 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
    // stop at the archive database step so the test never fetches schemas over HTTP
    h.fake.reply_err(std::io::ErrorKind::NotFound);
    h.run(&[
        "--mode",
        "native",
        "--bin-path",
        path_arg(bin.path()),
        "network",
        "create",
        "-n",
        "def",
    ])
    .unwrap_err();

    let calls = h.fake.calls.borrow();
    assert_eq!(calls.len(), 13);
    assert!(calls[0]
        .line()
        .contains("advanced generate-keypair -privkey-path"));
    assert_eq!(
        calls[0].envs,
        vec![("MINA_PRIVKEY_PASS".into(), "naughty blue worm".into())]
    );
    assert!(calls[6].line().contains("libp2p generate-keypair"));
    assert_eq!(calls[12].line(), "createdb -U postgres archive");
    drop(calls);

    let net = h.dirs.network_path("def");
    let ledger = std::fs::read_to_string(net.join("genesis_ledger.json")).unwrap();
    assert!(ledger.contains("B62qtest"));
}

#[test]
fn native_mode_requires_mina_binary() {
    let h = Harness::new();
    let empty = tempfile::tempdir().unwrap();
    let err = h
        .run(&[
            "--mode",
            "native",
            "--bin-path",
            path_arg(empty.path()),
            "network",
            "list",
        ])
        .unwrap_err();
    assert!(err.to_string().contains("Mina binary not found"));
}
