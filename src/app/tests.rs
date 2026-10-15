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

/// Runner calls other than `mina version` (the installed-config probe).
fn non_probe_calls(fake: &FakeRunner) -> Vec<String> {
    fake.lines()
        .into_iter()
        .filter(|l| !l.ends_with("/mina version"))
        .collect()
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
fn list_without_networks_succeeds_without_docker() {
    let h = Harness::new();
    h.run(&["network", "list"]).unwrap();
    assert!(h.fake.lines().is_empty());
}

#[test]
fn info_on_missing_network_fails() {
    let h = Harness::new();
    let err = h.run(&["network", "info", "-n", "nope"]).unwrap_err();
    assert!(err.to_string().contains("network 'nope' does not exist"));
}

#[test]
fn docker_environment_failure_stops_before_any_command() {
    let h = Harness::new();
    h.fake.reply(127, "", "");
    let err = h.run(&["network", "start", "-n", "x"]).unwrap_err();
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
        .contains(&h.compose("small", "down --volumes --remove-orphans")));
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
        h.compose("small", "down --volumes --remove-orphans"),
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
    assert!(non_probe_calls(&h.fake).is_empty());
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
    h.fake.reply(1, "", ""); // mina version: no installed config
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
    assert_eq!(calls.len(), 14);
    assert!(calls[0]
        .line()
        .contains("advanced generate-keypair -privkey-path"));
    assert_eq!(
        calls[0].envs,
        vec![("MINA_PRIVKEY_PASS".into(), "naughty blue worm".into())]
    );
    assert!(calls[6].line().contains("libp2p generate-keypair"));
    assert!(calls[12].line().ends_with("/mina version"));
    assert_eq!(
        calls[13].line(),
        "psql postgres://postgres:postgres@localhost:5432/postgres -v ON_ERROR_STOP=1 -c DROP DATABASE IF EXISTS minimina_def"
    );
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

fn native_args<'a>(bin: &'a tempfile::TempDir, rest: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["--mode", "native", "--bin-path", path_arg(bin.path())];
    args.extend_from_slice(rest);
    args
}

#[test]
fn native_network_remembers_its_mode() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    h.run(&native_args(
        &bin,
        &[
            "network",
            "create",
            "-n",
            "nat",
            "-t",
            SMALL_TOPOLOGY,
            "-g",
            SMALL_LEDGER,
        ],
    ))
    .unwrap();
    let meta = crate::network_meta::NetworkMeta::load(&h.dirs.network_path("nat"))
        .unwrap()
        .unwrap();
    assert_eq!(meta.mode, crate::cli::ExecutionMode::Native);
    assert_eq!(meta.bin_path.as_deref(), Some(bin.path()));

    // no --mode / --bin-path: native is taken from minimina.json, docker is never called
    h.run(&["network", "status", "-n", "nat"]).unwrap();
    h.run(&["network", "stop", "-n", "nat"]).unwrap();
    h.run(&["node", "stop", "-n", "nat", "-i", "seed-0"])
        .unwrap_err();
    assert!(non_probe_calls(&h.fake).is_empty(), "{:?}", h.fake.lines());

    let err = h
        .run(&["--mode", "docker", "network", "stop", "-n", "nat"])
        .unwrap_err();
    assert!(err.to_string().contains("was created in native mode"));

    h.run(&["network", "delete", "-n", "nat"]).unwrap();
    assert!(!h.dirs.network_path_exists("nat"));
    assert!(non_probe_calls(&h.fake).is_empty());
}

#[test]
fn docker_network_records_docker_mode() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    let meta = crate::network_meta::NetworkMeta::load(&h.dirs.network_path("small"))
        .unwrap()
        .unwrap();
    assert_eq!(meta.mode, crate::cli::ExecutionMode::Docker);
    assert_eq!(meta.bin_path, None);
}

#[test]
fn network_without_metadata_defaults_to_docker() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("old").unwrap();
    std::fs::remove_file(h.dirs.network_path("old").join("minimina.json")).unwrap();
    h.docker_ok();
    h.run(&["network", "stop", "-n", "old"]).unwrap();
    assert_eq!(h.fake.lines().last().unwrap(), &h.compose("old", "stop"));
}

#[test]
fn recreating_a_native_network_does_not_call_docker() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let create = native_args(
        &bin,
        &[
            "network",
            "create",
            "-n",
            "nat",
            "-t",
            SMALL_TOPOLOGY,
            "-g",
            SMALL_LEDGER,
        ],
    );
    h.run(&create).unwrap();
    h.run(&create).unwrap();
    assert!(non_probe_calls(&h.fake).is_empty());
}

#[test]
fn docker_stop_passes_timeout() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    h.docker_ok();
    h.run(&["network", "stop", "-n", "small", "--timeout", "90"])
        .unwrap();
    assert_eq!(
        h.fake.lines().last().unwrap(),
        &h.compose("small", "stop -t 90")
    );
}

#[test]
fn native_node_start_rejects_unknown_node() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    h.run(&native_args(
        &bin,
        &[
            "network",
            "create",
            "-n",
            "nat",
            "-t",
            SMALL_TOPOLOGY,
            "-g",
            SMALL_LEDGER,
        ],
    ))
    .unwrap();
    let err = h
        .run(&["node", "start", "-n", "nat", "-i", "ghost"])
        .unwrap_err();
    assert!(format!("{err:#}").contains("Node 'ghost' does not exist in network 'nat'"));
}

const LARGE_TOPOLOGY: &str = "tests/data/large_network/topology.json";
const LARGE_LEDGER: &str = "tests/data/large_network/genesis_ledger.json";

/// The large network (with an archive node) whose schema is a local file.
fn archive_topology(dir: &Path) -> std::path::PathBuf {
    let schema = dir.join("create_schema.sql");
    std::fs::write(&schema, "CREATE TABLE blocks ();").unwrap();
    let mut topology: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(LARGE_TOPOLOGY).unwrap()).unwrap();
    topology["archive-node"]["schema_files"] = serde_json::json!([schema.to_str().unwrap()]);
    let path = dir.join("topology.json");
    std::fs::write(&path, topology.to_string()).unwrap();
    path
}

/// Replies for `network create` up to the schema step of the archive database.
fn queue_archive_create(h: &Harness, network_id: &str) {
    let postgres = format!("postgres-{network_id}");
    let ps = format!(
        r#"{{"ID":"1","Name":"{postgres}","Image":"postgres:17","Command":"","CreatedAt":"","State":"running","Status":"Up","Health":"","ExitCode":0,"Labels":"","Service":"{postgres}"}}"#
    );
    h.docker_ok()
        .reply(0, "", "") // compose create
        .reply(0, "", "") // compose start postgres
        .reply(0, &ps, "") // compose ps
        .reply(2, "", "no response") // pg_isready: still in init
        .reply(0, "", "") // pg_isready
        .reply(0, "", "") // createdb
        .reply(0, "", ""); // docker cp schema
}

#[test]
fn docker_archive_create_waits_for_postgres_and_applies_schema() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let topology = archive_topology(dir.path());
    queue_archive_create(&h, "arch");
    h.run(&[
        "network",
        "create",
        "-n",
        "arch",
        "-t",
        path_arg(&topology),
        "-g",
        LARGE_LEDGER,
    ])
    .unwrap();

    let lines = h.fake.lines();
    let pos = |needle: &str| {
        lines
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no `{needle}` in {lines:#?}"))
    };
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("pg_isready -h 127.0.0.1"))
            .count(),
        2
    );
    assert!(pos("pg_isready") < pos("createdb -U postgres archive"));
    assert!(lines[pos("docker cp")].ends_with("postgres-arch:/tmp/create_schema.sql"));
    assert!(lines[pos("psql")].ends_with(
        "exec -i postgres-arch psql -U postgres -d archive -v ON_ERROR_STOP=1 -f /tmp/create_schema.sql"
    ));
    assert!(lines.last().unwrap().ends_with("stop postgres-arch"));
}

#[test]
fn docker_archive_create_fails_on_schema_error() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let topology = archive_topology(dir.path());
    queue_archive_create(&h, "arch");
    h.fake.reply(3, "", "ERROR: syntax error");
    let err = h
        .run(&[
            "network",
            "create",
            "-n",
            "arch",
            "-t",
            path_arg(&topology),
            "-g",
            LARGE_LEDGER,
        ])
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "applying schema create_schema.sql failed (exit status: 3): ERROR: syntax error"
    );
}

#[test]
fn docker_archive_create_fails_when_createdb_fails() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let topology = archive_topology(dir.path());
    let postgres = "postgres-arch";
    let ps = format!(
        r#"{{"ID":"1","Name":"{postgres}","Image":"postgres:17","Command":"","CreatedAt":"","State":"running","Status":"Up","Health":"","ExitCode":0,"Labels":"","Service":"{postgres}"}}"#
    );
    h.docker_ok()
        .reply(0, "", "")
        .reply(0, "", "")
        .reply(0, &ps, "")
        .reply(0, "", "")
        .reply(1, "", "container is not running");
    let err = h
        .run(&[
            "network",
            "create",
            "-n",
            "arch",
            "-t",
            path_arg(&topology),
            "-g",
            LARGE_LEDGER,
        ])
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("creating the archive database failed"));
    assert!(err.to_string().contains("container is not running"));
}
