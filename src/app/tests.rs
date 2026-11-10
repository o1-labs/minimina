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

/// The small network: a seed `seed-0` and a block producer `receiver`.
const SMALL_SPEC: &str = r#"
[[nodes]]
role = "seed"
name = "seed-0"
[[nodes]]
role = "block-producer"
name = "receiver"
"#;

struct Harness {
    home: tempfile::TempDir,
    dirs: DirectoryManager,
    fake: Rc<FakeRunner>,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let dirs = DirectoryManager::with_base_path(home.path().join(".minimina"));
        Harness {
            home,
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

    /// The small network's spec file.
    fn small_spec(&self) -> String {
        let path = self.home.path().join("small.toml");
        std::fs::write(&path, SMALL_SPEC).unwrap();
        path.display().to_string()
    }

    /// Queues the key generation of the small network: the key of
    /// `receiver`, then the libp2p keys of `seed-0` and `receiver`.
    fn small_keys(&self) -> &FakeRunner {
        self.fake
            .reply(0, &format!("Public key: {}\n", test_pk(0)), "")
            .reply(0, "libp2p keypair:\nenc,pub,peer0\n", "")
            .reply(0, "libp2p keypair:\nenc,pub,peer1\n", "")
    }

    /// `network create --spec <small>` with `extra` arguments before it.
    fn create_small_with(&self, extra: &[&str], network_id: &str) -> anyhow::Result<()> {
        let spec = self.small_spec();
        let mut args = extra.to_vec();
        args.extend(["network", "create", "-n", network_id, "--spec", &spec]);
        self.run(&args)
    }

    /// Creates the small network in docker mode, after [`Harness::docker_ok`].
    fn create_small(&self, network_id: &str) -> anyhow::Result<()> {
        self.small_keys();
        self.create_small_with(&[], network_id)
    }

    /// Creates the small network natively with the mina of `bin`.
    fn create_small_native(&self, bin: &tempfile::TempDir, network_id: &str) -> anyhow::Result<()> {
        self.small_keys();
        let bin = path_arg(bin.path());
        self.create_small_with(&["--mode", "native", "--bin-path", bin], network_id)
    }
}

/// Runner calls other than the probes of the mina binaries (`mina version`,
/// `mina daemon -help`) and key generation.
fn non_probe_calls(fake: &FakeRunner) -> Vec<String> {
    fake.lines()
        .into_iter()
        .filter(|l| {
            !l.ends_with("/mina version")
                && !l.ends_with("mina daemon -help")
                && !l.contains(" generate-keypair ")
        })
        .collect()
}

/// A public key the fake `generate-keypair` prints: `B62q`, `i`, and zeros
/// to the 55 characters of a real one.
fn test_pk(i: usize) -> String {
    format!("B62q{i:0<51}")
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
fn docker_create_from_a_spec_writes_network_files() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();

    let net = h.dirs.network_path("small");
    for file in [
        "docker-compose.yaml",
        "network.json",
        "network.toml",
        "services.json",
        "genesis_ledger.json",
    ] {
        assert!(net.join(file).exists(), "missing {file}");
    }
    let lines = h.fake.lines();
    // the keys are generated in the daemon image
    assert!(lines[2].contains(" advanced generate-keypair -privkey-path "));
    assert!(lines[5].ends_with(&format!(
        "--entrypoint mina {} daemon -help",
        super::DEFAULT_DAEMON_DOCKER_IMAGE
    )));
    assert_eq!(lines[6..], [h.compose("small", "create")]);
    // a daemon whose help has no -precomputed-blocks-dir
    let compose = std::fs::read_to_string(net.join("docker-compose.yaml")).unwrap();
    assert!(compose.contains("-precomputed-blocks-file /config-directory/precomputed_blocks.log"));
    assert!(
        compose.contains("-peer /dns4/seed-0-small/tcp/3102/p2p/peer0"),
        "{compose}"
    );
    assert!(h.dirs.get_network_info("small").unwrap().contains("seed-0"));
}

#[test]
fn docker_create_with_an_uptime_service_backend() {
    let h = Harness::new();
    let fixture = std::fs::canonicalize("tests/data/uptime").unwrap();
    let spec = h.home.path().join("uptime.toml");
    std::fs::write(
        &spec,
        format!(
            "{SMALL_SPEC}[[nodes]]\nrole = \"uptime-service-backend\"\n\
             app_config = \"{0}/app_config.json\"\nminasheets = \"{0}/minasheets.json\"\n\
             [docker]\nuptime_service_backend_image = \"uptime:1\"\n",
            fixture.display()
        ),
    )
    .unwrap();
    h.docker_ok();
    h.small_keys();
    h.run(&["network", "create", "-n", "up", "--spec", path_arg(&spec)])
        .unwrap();

    let net = h.dirs.network_path("up");
    for file in ["app_config.json", "minasheets.json"] {
        assert!(
            net.join("uptime_service_config").join(file).is_file(),
            "{file}"
        );
    }
    let compose = std::fs::read_to_string(net.join("docker-compose.yaml")).unwrap();
    assert!(compose.contains("image: uptime:1"), "{compose}");
    assert!(
        compose.contains("-uptime-url http://uptime-service-backend-up:8080/v1/submit"),
        "{compose}"
    );
}

#[test]
fn docker_create_reports_compose_failure() {
    let h = Harness::new();
    h.docker_ok();
    h.small_keys()
        .reply(0, "", "") // mina daemon -help
        .reply(1, "", "no such image");
    let err = h.create_small_with(&[], "small").unwrap_err();
    assert!(err.to_string().contains("docker compose create"));
    assert!(err.to_string().contains("no such image"));
}

#[test]
fn create_over_existing_network_tears_it_down_first() {
    let h = Harness::new();
    h.docker_ok();
    h.create_small("small").unwrap();
    h.docker_ok().reply(0, "", ""); // compose down, before the new keys
    h.create_small("small").unwrap();
    assert!(h
        .fake
        .lines()
        .contains(&h.compose("small", "down --volumes --remove-orphans")));
}

/// A mistake in what create is given is found before the old network of the
/// same name is stopped and deleted.
#[test]
fn bad_inputs_leave_the_old_network_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    };
    // a name for two nodes, found when the nodes are planned
    let named_pair = write(
        "pair.toml",
        "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"block-producer\"\ncount = 2\nname = \"bp\"\n",
    );
    // a ledger file with a bad key, found when it is read
    write("bad.csv", "public_key,balance\nB62qbad,10\n");
    let bad_ledger = write(
        "ledger.toml",
        "[[nodes]]\nrole = \"seed\"\n[ledger]\nfile = \"bad.csv\"\n",
    );
    // a balance that is not one, found when the spec is read
    let bad_balance = write(
        "balance.toml",
        "[[nodes]]\nrole = \"seed\"\n[ledger]\nbalance = \"1e9\"\n",
    );

    let cases = [
        (named_pair, "need count = 1"),
        (bad_ledger, "'B62qbad' is not a mina public key"),
        (bad_balance, "balance '1e9' is not an amount of MINA"),
    ];
    for (spec, problem) in cases {
        let h = Harness::new();
        let old = h.dirs.network_path("x");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("services.json"), "old").unwrap();
        h.docker_ok();

        let err = h
            .run(&["network", "create", "-n", "x", "--spec", &spec])
            .unwrap_err();
        assert!(format!("{err:#}").contains(problem), "{err:#}");
        // at most the environment check ran: no compose down
        let lines = h.fake.lines();
        assert!(
            lines
                .iter()
                .all(|l| l.starts_with("docker --version")
                    || l.starts_with("docker compose version")),
            "{lines:?}"
        );
        assert_eq!(
            std::fs::read_to_string(old.join("services.json")).unwrap(),
            "old"
        );
    }
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
    h.create_small_native(&bin, "nat").unwrap();

    let net = h.dirs.network_path("nat");
    // native nodes share the host: the seed is dialled on localhost, not a compose DNS name
    let services = std::fs::read_to_string(net.join("services.json")).unwrap();
    assert!(
        services.contains("/ip4/127.0.0.1/tcp/3102/p2p/peer0"),
        "{services}"
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
        h.fake
            .reply(0, &format!("Public key: {}\n", test_pk(0)), "");
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
        h.fake
            .reply(0, &format!("Public key: {}\n", test_pk(0)), "");
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
    assert!(ledger.contains(&test_pk(0)));
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
        h.fake
            .reply(0, &format!("Public key: {}\n", test_pk(i)), "");
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
    assert!(h.dirs.spec_path("spec").exists());
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
            (test_pk(0).as_str(), "500"),
            (test_pk(1).as_str(), "500"),
            (test_pk(2).as_str(), "1000"),
            (test_pk(3).as_str(), "1000")
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
    h.create_small_native(&bin, "nat").unwrap();
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
    h.create_small_native(&bin, "nat").unwrap();
    h.create_small_native(&bin, "nat").unwrap();
    assert!(non_probe_calls(&h.fake).is_empty(), "{:?}", h.fake.lines());
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
    h.create_small_native(&bin, "nat").unwrap();
    let err = h
        .run(&["node", "start", "-n", "nat", "-i", "ghost"])
        .unwrap_err();
    assert!(format!("{err:#}").contains("Node 'ghost' does not exist in network 'nat'"));
}

/// A seed and an archive node.
fn archive_spec(h: &Harness) -> String {
    let path = h.home.path().join("archive.toml");
    std::fs::write(
        &path,
        "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"archive\"\n",
    )
    .unwrap();
    path.display().to_string()
}

/// Replies for `network create` up to the schema step of the archive database.
fn queue_archive_create(h: &Harness, network_id: &str) {
    let postgres = format!("postgres-{network_id}");
    let ps = format!(
        r#"{{"ID":"1","Name":"{postgres}","Image":"postgres:17","Command":"","CreatedAt":"","State":"running","Status":"Up","Health":"","ExitCode":0,"Labels":"","Service":"{postgres}"}}"#
    );
    h.docker_ok()
        .reply(0, "libp2p keypair:\nenc,pub,peer0\n", "") // seed
        .reply(0, "libp2p keypair:\nenc,pub,peer1\n", "") // archive
        .reply(0, "", "") // mina daemon -help
        .reply(0, "", "") // compose create
        .reply(0, "", "") // compose start postgres
        .reply(0, &ps, "") // compose ps
        .reply(2, "", "no response") // pg_isready: still in init
        .reply(0, "", "") // pg_isready
        .reply(0, "", "") // createdb
        .reply(0, "CREATE TABLE blocks ();", "") // the schema of the archive image
        .reply(0, "", ""); // docker cp schema
}

#[test]
fn docker_archive_create_waits_for_postgres_and_applies_schema() {
    let h = Harness::new();
    let spec = archive_spec(&h);
    queue_archive_create(&h, "arch");
    h.run(&["network", "create", "-n", "arch", "--spec", &spec])
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
    let spec = archive_spec(&h);
    queue_archive_create(&h, "arch");
    h.fake.reply(3, "", "ERROR: syntax error");
    let err = h
        .run(&["network", "create", "-n", "arch", "--spec", &spec])
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "applying schema create_schema.sql failed (exit status: 3): ERROR: syntax error"
    );
}

#[test]
fn docker_archive_create_fails_when_createdb_fails() {
    let h = Harness::new();
    let spec = archive_spec(&h);
    let postgres = "postgres-arch";
    let ps = format!(
        r#"{{"ID":"1","Name":"{postgres}","Image":"postgres:17","Command":"","CreatedAt":"","State":"running","Status":"Up","Health":"","ExitCode":0,"Labels":"","Service":"{postgres}"}}"#
    );
    h.docker_ok()
        .reply(0, "libp2p keypair:\nenc,pub,peer0\n", "")
        .reply(0, "libp2p keypair:\nenc,pub,peer1\n", "")
        .reply(0, "", "") // mina daemon -help
        .reply(0, "", "")
        .reply(0, "", "")
        .reply(0, &ps, "")
        .reply(0, "", "")
        .reply(1, "", "container is not running");
    let err = h
        .run(&["network", "create", "-n", "arch", "--spec", &spec])
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

/// An unpacked postfork package: `files` in `usr/local/bin`, and the archive
/// upgrade script in `etc/mina/archive`.
struct PostforkPackage {
    _root: tempfile::TempDir,
    bin: std::path::PathBuf,
}

impl PostforkPackage {
    fn root(&self) -> &Path {
        self._root.path()
    }
}

fn postfork_dir(files: &[&str]) -> PostforkPackage {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("usr/local/bin");
    let sql = root.path().join(crate::utils::PACKAGED_SCHEMA_DIR);
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&sql).unwrap();
    std::fs::write(sql.join("upgrade.sql"), "").unwrap();
    for file in files {
        std::fs::write(bin.join(file), "").unwrap();
    }
    PostforkPackage { _root: root, bin }
}

#[test]
fn hardfork_network_gets_its_schedule_and_status() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let post = postfork_dir(&[
        "mina",
        "mina-archive",
        "mina-create-genesis",
        "mina-archive-hardfork-toolbox",
    ]);
    let dir = tempfile::tempdir().unwrap();
    let spec = hardfork_spec(
        dir.path(),
        &post.bin,
        "mode = \"manual\"\nat = { slot = 42 }",
    );
    queue_hardfork_create(&h);
    h.run(&native_args(
        &bin,
        &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
    ))
    .unwrap();

    let post_mina = format!("{}/mina version", post.bin.display());
    assert_eq!(h.fake.lines()[0], post_mina);
    let net = h.dirs.network_path("hf");
    let meta = NetworkMeta::load(&net).unwrap().unwrap();
    assert!(meta.genesis_pending);
    let hf = meta.hardfork.unwrap();
    assert_eq!(hf.postfork_bin_path, post.bin);
    assert_eq!(hf.method, Some(crate::hardfork::ForkMethod::Legacy));
    let ledger = crate::genesis_ledger::read(&net).unwrap();
    assert_eq!(
        ledger["daemon"],
        serde_json::json!({"slot_tx_end": 34, "slot_chain_end": 42, "hard_fork_genesis_slot_delta": 20})
    );

    let ctx_status = |now| {
        let ctx = super::Context {
            dirs: h.dirs.clone(),
            mode: crate::cli::ExecutionMode::Native,
            bin_path: Some(bin.path().into()),
            mina_version: None,
            postgres_uri: String::new(),
            profile: Profile::Devnet,
            features: Default::default(),
            archive_config: None,
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
    assert_eq!(before.fork_genesis.slot, 62);
    assert!(before.slot_chain_end.time.is_none());

    // the first start sets the genesis; 17 min 15 s later it is past slot_tx_end
    let started = chrono::Utc::now() + chrono::Duration::seconds(17 * 60 + 15);
    let status = ctx_status(Some(started));
    assert_eq!(status.phase, crate::hardfork::Phase::TxEnd);
    assert_eq!(status.slot, Some(34));
    let next = status.next.unwrap();
    assert_eq!(next.phase, crate::hardfork::Phase::ChainEnd);
    assert!(
        (220..=225).contains(&next.in_seconds),
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
    let ok_post = postfork_dir(&[
        "mina",
        "mina-archive",
        "mina-create-genesis",
        "mina-archive-hardfork-toolbox",
    ]);
    let spec = hardfork_spec(
        dir.path(),
        &ok_post.bin,
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
        &post.bin,
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
        "slot_tx_end 12 is 360 s after the genesis",
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
fn a_manual_fork_with_an_archive_needs_the_toolbox() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let dir = tempfile::tempdir().unwrap();
    let post = postfork_dir(&["mina", "mina-archive", "mina-create-genesis"]);
    let spec = hardfork_spec(
        dir.path(),
        &post.bin,
        "mode = \"manual\"\nat = { slot = 42 }",
    );
    queue_hardfork_create(&h);
    let err = h
        .run(&native_args(
            &bin,
            &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
        ))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!(
            "postfork bin_path {} has no mina-archive-hardfork-toolbox",
            post.bin.display()
        )),
        "{err}"
    );
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

#[test]
fn prepare_and_apply_refuse_out_of_order() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let post = postfork_dir(&[
        "mina",
        "mina-archive",
        "mina-create-genesis",
        "mina-archive-hardfork-toolbox",
    ]);
    let dir = tempfile::tempdir().unwrap();
    let spec = hardfork_spec(
        dir.path(),
        &post.bin,
        "mode = \"manual\"\nat = { slot = 42 }",
    );
    queue_hardfork_create(&h);
    h.run(&native_args(
        &bin,
        &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
    ))
    .unwrap();
    let meta = NetworkMeta::load(&h.dirs.network_path("hf"))
        .unwrap()
        .unwrap();
    assert_eq!(
        meta.hardfork.unwrap().archive_upgrade,
        Some(post.root().join("etc/mina/archive/upgrade.sql"))
    );

    let err = |args: &[&str]| h.run(args).unwrap_err().to_string();
    assert!(err(&["network", "hardfork", "apply", "-n", "hf"])
        .contains("run `network hardfork prepare -n hf`"));
    assert!(err(&["network", "hardfork", "prepare", "-n", "hf"]).contains("has not started"));
}

#[test]
fn hardfork_with_archive_needs_an_upgrade_script() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let post = tempfile::tempdir().unwrap();
    for file in [
        "mina",
        "mina-archive",
        "mina-create-genesis",
        "mina-archive-hardfork-toolbox",
    ] {
        std::fs::write(post.path().join(file), "").unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let spec = hardfork_spec(
        dir.path(),
        post.path(),
        "mode = \"manual\"\nat = { slot = 42 }",
    );
    let err = h
        .run(&native_args(
            &bin,
            &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
        ))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("set [hardfork.postfork] archive_upgrade"),
        "{err}"
    );
}

/// An install of mina `version` in the tools directory, as `mina install` leaves it.
fn installed_mina(h: &Harness, version: &str) -> std::path::PathBuf {
    let dir = crate::install::mina::root(&h.dirs.tools_root()).join(version);
    let bin = dir.join(crate::install::mina::BIN_DIR);
    std::fs::create_dir_all(&bin).unwrap();
    for file in [
        "mina",
        "mina-archive",
        "mina-create-genesis",
        "mina-archive-hardfork-toolbox",
    ] {
        std::fs::write(bin.join(file), "").unwrap();
    }
    // the archive scripts of the package
    let archive = dir.join("etc/mina/archive");
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::write(archive.join("upgrade.sql"), "").unwrap();
    std::fs::write(
        dir.join("install.json"),
        format!(r#"{{"version":"{version}","channel":"stable","codename":"noble","packages":[]}}"#),
    )
    .unwrap();
    bin
}

#[test]
fn mina_version_runs_an_installed_version_natively() {
    let h = Harness::new();
    let create = |extra: &[&str]| h.create_small_with(extra, "v");
    let err = create(&["--mina-version", "4.0.2"])
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "mina 4.0.2 is not installed; run `minimina mina install 4.0.2`"
    );
    let err = create(&["--mode", "docker", "--mina-version", "4.0.2"])
        .unwrap_err()
        .to_string();
    assert_eq!(err, "--mina-version is only valid in native mode");

    let bin = installed_mina(&h, "4.0.2-84b8d96");
    installed_mina(&h, "4.0.4-c9e2eac");
    // no --mode: an installed version runs natively
    h.small_keys();
    create(&["--mina-version", "4.0.2"]).unwrap();
    let meta = NetworkMeta::load(&h.dirs.network_path("v"))
        .unwrap()
        .unwrap();
    assert_eq!(meta.mode, crate::cli::ExecutionMode::Native);
    assert_eq!(meta.bin_path.as_deref(), Some(bin.as_path()));
    assert_eq!(meta.mina_version.as_deref(), Some("4.0.2-84b8d96"));
    // later commands run the recorded binaries
    h.run(&["network", "stop", "-n", "v"]).unwrap();
    assert!(non_probe_calls(&h.fake).is_empty(), "{:?}", h.fake.lines());

    // a binary directory replaces the version
    let own = fake_mina_dir();
    h.create_small_native(&own, "v").unwrap();
    let meta = NetworkMeta::load(&h.dirs.network_path("v"))
        .unwrap()
        .unwrap();
    assert_eq!(meta.mina_version, None);
}

#[test]
fn hardfork_postfork_can_be_an_installed_version() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("hf.toml");
    let write = |postfork: &str| {
        std::fs::write(
            &spec,
            format!(
                "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"archive\"\n\
                 [runtime_config]\ngenesis = {{ k = 10 }}\n\
                 proof = {{ block_window_duration_ms = 30000 }}\n\
                 [hardfork]\nmode = \"manual\"\nat = {{ slot = 42 }}\npostfork = {{ {postfork} }}\n"
            ),
        )
        .unwrap();
    };
    let create = || {
        h.run(&native_args(
            &bin,
            &["network", "create", "-n", "hf", "--spec", path_arg(&spec)],
        ))
    };

    write("mina_version = \"4.0.4\"");
    let err = create().unwrap_err().to_string();
    assert!(
        err.contains("[hardfork.postfork] mina 4.0.4 is not installed"),
        "{err}"
    );
    write("mina_version = \"4.0.4\", bin_path = \"/x\"");
    let err = create().unwrap_err().to_string();
    assert!(err.contains("has bin_path and mina_version"), "{err}");

    let post = installed_mina(&h, "4.0.4-c9e2eac");
    write("mina_version = \"4.0.4\"");
    queue_hardfork_create(&h);
    create().unwrap();
    let meta = NetworkMeta::load(&h.dirs.network_path("hf"))
        .unwrap()
        .unwrap();
    let hardfork = meta.hardfork.unwrap();
    assert_eq!(hardfork.postfork_bin_path, post);
    // the upgrade script comes from the installed version
    assert_eq!(
        hardfork.archive_upgrade,
        Some(
            crate::install::mina::root(&h.dirs.tools_root())
                .join("4.0.4-c9e2eac/etc/mina/archive/upgrade.sql")
        )
    );
}

#[test]
fn native_start_refuses_binaries_that_cannot_load() {
    let h = Harness::new();
    let bin = tempfile::tempdir().unwrap();
    // an executable ldd looks at
    std::fs::write(bin.path().join("mina"), b"\x7fELF").unwrap();
    h.fake.reply(0, "\tlibssl.so.3 => not found\n", "");
    let err = h
        .run(&native_args(&bin, &["network", "create", "-n", "x"]))
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        format!(
            "the mina binaries in {} cannot run here: missing libraries libssl.so.3; \
             install the packages that provide them",
            bin.path().display()
        )
    );
    // nothing ran but ldd
    assert_eq!(
        h.fake.lines(),
        [format!("ldd {}/mina", bin.path().display())]
    );
    assert!(!h.dirs.network_path("x").exists());
}

#[test]
fn flags_change_the_spec_and_the_resolved_spec_is_kept() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    let dir = tempfile::tempdir().unwrap();
    let pk = "B62qrPN5Y5yq8kGE3FbVKbGTdTAJNdtNtB5sNVpxyRwWGcDEhpMzc8g";
    std::fs::write(
        dir.path().join("given.csv"),
        format!("public_key,balance\n{pk},42.5\n"),
    )
    .unwrap();
    let spec = dir.path().join("net.toml");
    std::fs::write(
        &spec,
        "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"block-producer\"\nbalance = \"500\"\n\
         [ledger]\nfile = \"given.csv\"\n",
    )
    .unwrap();
    // --bps 2 replaces the spec's one block producer; --accounts 1 adds an account
    // keys: bp-1, bp-2, account-1; libp2p: seed-1, bp-1, bp-2
    for i in 0..3 {
        h.fake
            .reply(0, &format!("Public key: {}\n", test_pk(i)), "");
    }
    for i in 0..3 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
    h.run(&native_args(
        &bin,
        &[
            "network",
            "create",
            "-n",
            "f",
            "--spec",
            path_arg(&spec),
            "--block-producers",
            "2",
            "--accounts",
            "1",
        ],
    ))
    .unwrap();

    let net = h.dirs.network_path("f");
    let ledger: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(net.join("genesis_ledger.json")).unwrap())
            .unwrap();
    let balances: Vec<_> = ledger["ledger"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["pk"].as_str().unwrap(), a["balance"].as_str().unwrap()))
        .collect();
    // the given account first, then the generated ones
    assert_eq!(
        balances,
        [
            (pk, "42.5"),
            (test_pk(0).as_str(), "500"),
            (test_pk(1).as_str(), "500"),
            (test_pk(2).as_str(), "1000")
        ]
    );

    // network.toml is the spec as resolved, with the ledger file's absolute path
    let kept = crate::spec::NetworkSpec::load(&h.dirs.spec_path("f")).unwrap();
    assert_eq!(kept.nodes[1].count, 2);
    assert_eq!(kept.ledger.accounts, 1);
    assert_eq!(kept.ledger.file, Some(dir.path().join("given.csv")));
}

#[test]
fn flags_alone_make_a_network() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    // keys: bp-1; libp2p: seed-1, bp-1, node-1
    h.fake
        .reply(0, &format!("Public key: {}\n", test_pk(0)), "");
    for i in 0..3 {
        h.fake
            .reply(0, &format!("libp2p keypair:\nenc,pub,peer{i}\n"), "");
    }
    h.run(&native_args(
        &bin,
        &["network", "create", "-n", "f", "--plains", "1"],
    ))
    .unwrap();
    let kept = crate::spec::NetworkSpec::load(&h.dirs.spec_path("f")).unwrap();
    let roles: Vec<_> = kept.nodes.iter().map(|g| (g.role, g.count)).collect();
    use crate::spec::Role;
    assert_eq!(
        roles,
        [(Role::Seed, 1), (Role::BlockProducer, 1), (Role::Plain, 1)]
    );
}

#[test]
fn the_checks_say_what_the_network_lacks() {
    let h = Harness::new();
    let bin = fake_mina_dir();
    h.create_small_native(&bin, "nat").unwrap();
    let err = |args: &[&str]| h.run(args).unwrap_err().to_string();
    // the small network has neither rosetta nor timed accounts
    assert_eq!(
        err(&["network", "check", "rosetta", "-n", "nat"]),
        "network 'nat' has no rosetta"
    );
    assert!(err(&["network", "check", "vesting", "-n", "nat"])
        .starts_with("the genesis ledger of network 'nat' has no timed accounts"));
    assert!(err(&["network", "check", "vesting", "-n", "none"]).contains("none"));
}
