//! Handler tests: real filesystem under a temp `MINIMINA_HOME`, fake `docker`/`mina`.

use super::run_with;
use crate::{
    cli::{Cli, Profile},
    directory_manager::DirectoryManager,
    network_meta::NetworkMeta,
    runner::fake::FakeRunner,
};
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
        .filter(|l| !l.ends_with("/mina version") && !l.ends_with("mina daemon -help"))
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
    assert!(h.fake.lines()[2].ends_with("--entrypoint mina gcr.io/o1labs-192920/mina-daemon:2.0.0berkeley-rc1-1551e2f-bullseye-berkeley daemon -help"));
    assert_eq!(h.fake.lines()[3..], [h.compose("small", "create")]);
    // the berkeley image has no -precomputed-blocks-dir
    let compose = std::fs::read_to_string(net.join("docker-compose.yaml")).unwrap();
    assert!(compose.contains("-precomputed-blocks-file /config-directory/precomputed_blocks.log"));
    let peers = std::fs::read_to_string(net.join("peer_list_file.txt")).unwrap();
    assert!(peers.starts_with("/dns4/seed-0-small/tcp/"), "{peers}");
    assert!(h.dirs.get_network_info("small").unwrap().contains("seed-0"));
}

#[test]
fn docker_create_reports_compose_failure() {
    let h = Harness::new();
    h.docker_ok()
        .reply(0, "", "") // mina daemon -help
        .reply(1, "", "no such image");
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
    // native nodes share the host: the seed is dialled on localhost, not a compose DNS name
    let peers = std::fs::read_to_string(net.join("peer_list_file.txt")).unwrap();
    assert!(
        peers.starts_with("/ip4/127.0.0.1/tcp/") && peers.contains("/p2p/12D3KooW"),
        "{peers}"
    );
    assert!(net.join("logs").is_dir());
    assert!(net.join("config-directory/seed-0").is_dir());
    assert!(net.join("services.json").exists());
    assert!(non_probe_calls(&h.fake).is_empty());
}

#[test]
fn native_archive_uses_the_schema_of_its_package() {
    let h = Harness::new();
    // an unpacked archive deb: <root>/usr/local/bin and <root>/etc/mina/archive
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("usr/local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("mina"), "").unwrap();
    let schema_dir = root.path().join("etc/mina/archive");
    std::fs::create_dir_all(&schema_dir).unwrap();
    std::fs::write(schema_dir.join("create_schema.sql"), "-- packaged").unwrap();
    for _ in 0..3 {
        h.fake.reply(0, "Public key: B62qtest\n", "");
    }
    for i in 0..5 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
    h.run(&[
        "--mode",
        "native",
        "--bin-path",
        path_arg(&bin),
        "network",
        "create",
        "-n",
        "pkg",
    ])
    .unwrap();

    let net = h.dirs.network_path("pkg");
    let applied = std::fs::read_to_string(net.join("create_schema.sql")).unwrap();
    assert_eq!(applied, "-- packaged");
    let schema_call = h
        .fake
        .lines()
        .into_iter()
        .find(|l| l.contains(" -f "))
        .unwrap();
    assert!(schema_call.ends_with(&format!("-f {}", net.join("create_schema.sql").display())));
}

#[test]
fn native_default_network_generates_keys_with_mina() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    for _ in 0..3 {
        h.fake.reply(0, "Public key: B62qtest\n", "");
    }
    for i in 0..5 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
    h.fake.reply(0, "  [--precomputed-blocks-dir DIR]", ""); // mina daemon -help
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
        "--profile",
        "lightnet",
    ])
    .unwrap_err();

    let meta = NetworkMeta::load(&h.dirs.network_path("def"))
        .unwrap()
        .unwrap();
    assert_eq!(meta.profile, Profile::Lightnet);
    assert!(meta.features.precomputed_blocks_dir);
    let calls = h.fake.calls.borrow();
    assert_eq!(calls.len(), 11);
    assert!(calls[0]
        .line()
        .contains("advanced generate-keypair -privkey-path"));
    assert_eq!(
        calls[0].envs,
        vec![
            ("MINA_PRIVKEY_PASS".into(), "naughty blue worm".into()),
            ("MINA_PROFILE".into(), "lightnet".into())
        ]
    );
    assert!(calls[3].line().contains("libp2p generate-keypair"));
    assert!(calls[8].line().ends_with("/mina daemon -help"));
    assert!(calls[9].line().ends_with("/mina version"));
    // generic 4.x binaries refuse even `version` without a profile
    assert_eq!(
        calls[9].envs,
        vec![("MINA_PROFILE".into(), "lightnet".into())]
    );
    assert_eq!(
        calls[10].line(),
        "psql postgres://postgres:postgres@localhost:5432/postgres -v ON_ERROR_STOP=1 -c DROP DATABASE IF EXISTS minimina_def"
    );
    drop(calls);

    let net = h.dirs.network_path("def");
    let ledger = std::fs::read_to_string(net.join("genesis_ledger.json")).unwrap();
    assert!(ledger.contains("B62qtest"));
    // only the two block producers hold stake
    assert_eq!(ledger.matches("\"pk\"").count(), 2, "{ledger}");
}

#[test]
fn native_spec_network() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("net.toml");
    std::fs::write(
        &spec,
        r#"
        profile = "lightnet"
        [[nodes]]
        role = "seed"
        [[nodes]]
        role = "block-producer"
        count = 2
        balance = "500"
        [[nodes]]
        role = "plain"
        [ledger]
        accounts = 2
        [runtime_config.proof]
        block_window_duration_ms = 30000
        "#,
    )
    .unwrap();
    // keys: bp-1, bp-2, account-1, account-2; libp2p: seed-1, bp-1, bp-2, node-1
    for i in 0..4 {
        h.fake.reply(0, &format!("Public key: B62q{i}\n"), "");
    }
    for i in 0..4 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
    h.run(&[
        "--mode",
        "native",
        "--bin-path",
        path_arg(bin.path()),
        "network",
        "create",
        "-n",
        "spec",
        "--spec",
        path_arg(&spec),
    ])
    .unwrap();

    let net = h.dirs.network_path("spec");
    let meta = NetworkMeta::load(&net).unwrap().unwrap();
    assert_eq!(meta.profile, Profile::Lightnet);
    assert!(net.join("network.toml").exists());
    assert!(h.fake.calls.borrow()[0]
        .envs
        .contains(&("MINA_PROFILE".into(), "lightnet".into())));

    let ledger: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(net.join("genesis_ledger.json")).unwrap())
            .unwrap();
    let balances: Vec<_> = ledger["ledger"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["pk"].as_str().unwrap(), a["balance"].as_str().unwrap()))
        .collect();
    assert_eq!(
        balances,
        [
            ("B62q0", "500"),
            ("B62q1", "500"),
            ("B62q2", "1000"),
            ("B62q3", "1000")
        ]
    );
    assert_eq!(ledger["proof"]["block_window_duration_ms"], 30000);
    assert!(ledger["genesis"]["genesis_state_timestamp"].is_string());

    let services = std::fs::read_to_string(net.join("services.json")).unwrap();
    assert!(services.contains("\"Plain_node\""), "{services}");
    assert!(services.contains("\"node-1\""), "{services}");
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
        .reply(0, "", "") // mina daemon -help
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
        .reply(0, "", "") // mina daemon -help
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

/// A seed and an archive, with a fork at slot 42 to the binaries in `postfork`.
fn hardfork_spec(dir: &Path, postfork: &Path, hardfork: &str) -> std::path::PathBuf {
    let spec = dir.join("hf.toml");
    std::fs::write(
        &spec,
        format!(
            r#"
            [[nodes]]
            role = "seed"
            [[nodes]]
            role = "archive"
            [runtime_config]
            genesis = {{ k = 10 }}
            proof = {{ block_window_duration_ms = 30000 }}
            [hardfork]
            {hardfork}
            postfork = {{ bin_path = "{}" }}
            "#,
            postfork.display()
        ),
    )
    .unwrap();
    spec
}

/// Queues the replies of creating [`hardfork_spec`]: the postfork probe, then
/// the libp2p keys of the seed and the archive.
fn queue_hardfork_create(h: &Harness) {
    h.fake.reply(0, "Commit 33a46fb\n", "");
    for i in 0..2 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
}

fn postfork_dir(files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for file in files {
        std::fs::write(dir.path().join(file), "").unwrap();
    }
    dir
}

#[test]
fn hardfork_network_gets_its_schedule_and_status() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let post = postfork_dir(&["mina", "mina-archive", "mina-create-genesis"]);
    let dir = tempfile::tempdir().unwrap();
    let spec = hardfork_spec(
        dir.path(),
        post.path(),
        "mode = \"manual\"\nat = { slot = 42 }",
    );
    queue_hardfork_create(&h);
    h.run(&native_args(
        &bin,
        &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
    ))
    .unwrap();

    let post_mina = format!("{}/mina version", post.path().display());
    assert_eq!(h.fake.lines()[0], post_mina);
    let net = h.dirs.network_path("hf");
    let meta = NetworkMeta::load(&net).unwrap().unwrap();
    assert!(meta.genesis_pending);
    let hf = meta.hardfork.unwrap();
    assert_eq!(hf.postfork_bin_path, post.path());
    assert_eq!(hf.method, Some(crate::hardfork::ForkMethod::Legacy));
    let ledger = crate::genesis_ledger::read(&net).unwrap();
    assert_eq!(
        ledger["daemon"],
        serde_json::json!({"slot_tx_end": 30, "slot_chain_end": 42, "hard_fork_genesis_slot_delta": 10})
    );

    let ctx_status = |now| {
        let ctx = super::Context {
            dirs: h.dirs.clone(),
            mode: crate::cli::ExecutionMode::Native,
            bin_path: Some(bin.path().into()),
            postgres_uri: String::new(),
            profile: Profile::Devnet,
            features: Default::default(),
            runner: h.fake.clone(),
        };
        if let Some(now) = now {
            super::hardfork::set_genesis(&ctx, "hf").unwrap();
            return super::hardfork::status(&ctx, "hf", now).unwrap();
        }
        super::hardfork::status(&ctx, "hf", chrono::Utc::now()).unwrap()
    };
    let before = ctx_status(None);
    assert_eq!(before.phase, crate::hardfork::Phase::NotStarted);
    assert_eq!(before.slot_chain_end.slot, 42);
    assert_eq!(before.fork_genesis.slot, 52);
    assert!(before.slot_chain_end.time.is_none());

    // the first start sets the genesis; 16 min 15 s later it is past slot_tx_end
    let started = chrono::Utc::now() + chrono::Duration::seconds(16 * 60 + 15);
    let status = ctx_status(Some(started));
    assert_eq!(status.phase, crate::hardfork::Phase::TxEnd);
    assert_eq!(status.slot, Some(32));
    let next = status.next.unwrap();
    assert_eq!(next.phase, crate::hardfork::Phase::ChainEnd);
    assert!(
        (280..=285).contains(&next.in_seconds),
        "{}",
        next.in_seconds
    );
    assert!(!NetworkMeta::load(&net).unwrap().unwrap().genesis_pending);
}

#[test]
fn invalid_hardfork_is_refused_before_the_old_network_goes() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let dir = tempfile::tempdir().unwrap();
    let ok_post = postfork_dir(&["mina", "mina-archive", "mina-create-genesis"]);
    let spec = hardfork_spec(
        dir.path(),
        ok_post.path(),
        "mode = \"manual\"\nat = { slot = 42 }",
    );
    queue_hardfork_create(&h);
    h.run(&native_args(
        &bin,
        &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
    ))
    .unwrap();
    let calls = h.fake.lines().len();

    let post = postfork_dir(&["mina"]);
    let spec = hardfork_spec(
        dir.path(),
        post.path(),
        "mode = \"auto\"\nat = { slot = 20 }\nmethod = \"advanced\"",
    );
    h.fake
        .reply(1, "", "libssl.so.3: cannot open shared object file\n");
    let err = h
        .run(&native_args(
            &bin,
            &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
        ))
        .unwrap_err()
        .to_string();
    for part in [
        "method is for mode = \"manual\"",
        "slot_tx_end 8 is 240 s after the genesis",
        "has no mina-archive",
        "does not run: libssl.so.3",
        "needs a prefork daemon with --hardfork-handling",
    ] {
        assert!(err.contains(part), "no '{part}' in:\n{err}");
    }
    // only the two probes ran, and the old network is still there
    assert_eq!(h.fake.lines().len(), calls + 2, "{:?}", h.fake.lines());
    assert!(NetworkMeta::load(&h.dirs.network_path("hf"))
        .unwrap()
        .unwrap()
        .hardfork
        .is_some());
}

#[test]
fn hardfork_needs_postfork_binaries_and_native_mode() {
    let h = Harness::new();
    h.docker_ok();
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("hf.toml");
    std::fs::write(
        &spec,
        "[[nodes]]\nrole = \"seed\"\n[hardfork]\nmode = \"manual\"\nat = { slot = 42 }",
    )
    .unwrap();
    let err = h
        .run(&["network", "create", "-n", "hf", "--spec", path_arg(&spec)])
        .unwrap_err()
        .to_string();
    for part in [
        "runs in native mode only",
        "set [runtime_config] genesis.k",
        "[hardfork.postfork] bin_path is missing",
    ] {
        assert!(err.contains(part), "no '{part}' in:\n{err}");
    }
    assert!(!h.dirs.network_path_exists("hf"));
}
