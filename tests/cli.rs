//! Black-box tests of the `minimina` binary: exit codes and the JSON on stdout
//! that callers (Lucy, CI scripts) parse. Native mode runs a fake `mina`, so no
//! docker or mina installation is needed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const SMALL_TOPOLOGY: &str = "tests/data/small_network/topology.json";
const SMALL_LEDGER: &str = "tests/data/small_network/genesis_ledger.json";

struct Env {
    home: tempfile::TempDir,
    bin: tempfile::TempDir,
}

impl Env {
    /// A temp `MINIMINA_HOME` and a bin dir whose `mina` sleeps until signalled.
    fn new() -> Self {
        let env = Env {
            home: tempfile::tempdir().unwrap(),
            bin: tempfile::tempdir().unwrap(),
        };
        let mina = env.bin.path().join("mina");
        fs::write(&mina, "#!/bin/sh\necho \"mina $*\"\nexec sleep 300\n").unwrap();
        fs::set_permissions(&mina, fs::Permissions::from_mode(0o755)).unwrap();
        env
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("minimina").unwrap();
        cmd.env("MINIMINA_HOME", self.home.path())
            .env_remove("RUST_LOG")
            .args(args);
        cmd
    }

    fn bin_path(&self) -> &str {
        self.bin.path().to_str().unwrap()
    }

    fn network_dir(&self, id: &str) -> PathBuf {
        self.home.path().join(".minimina").join(id)
    }

    /// Runs and parses stdout as JSON, asserting the exit status.
    fn json(&self, args: &[&str], success: bool) -> Value {
        let out = self.cmd(args).output().unwrap();
        assert_eq!(
            out.status.success(),
            success,
            "minimina {args:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout of {args:?} is not JSON ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    fn create_native(&self, id: &str) -> Value {
        self.json(
            &[
                "--mode",
                "native",
                "--bin-path",
                self.bin_path(),
                "network",
                "create",
                "-n",
                id,
                "-t",
                SMALL_TOPOLOGY,
                "-g",
                SMALL_LEDGER,
            ],
            true,
        )
    }
}

fn error_message(v: &Value) -> &str {
    v["error_message"]
        .as_str()
        .unwrap_or_else(|| panic!("no error_message in {v}"))
}

#[test]
fn version_and_help() {
    let env = Env::new();
    let out = env.cmd(&["--version"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("minimina "));
    env.cmd(&["network", "--help"]).assert().success();
    env.cmd(&["network", "frobnicate"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn list_on_a_fresh_home_is_empty() {
    let env = Env::new();
    assert_eq!(
        env.json(&["network", "list"], true),
        serde_json::json!({"networks": []})
    );
}

#[test]
fn errors_are_json_with_exit_code_1() {
    let env = Env::new();
    let v = env.json(&["network", "info", "-n", "ghost"], false);
    assert!(error_message(&v).contains("network 'ghost' does not exist"));

    let v = env.json(
        &[
            "--mode",
            "native",
            "--bin-path",
            "/nonexistent",
            "network",
            "list",
        ],
        false,
    );
    assert_eq!(
        error_message(&v),
        "Mina binary not found at '/nonexistent/mina'."
    );

    let v = env.json(&["network", "create", "-n", "x", "-g", SMALL_LEDGER], false);
    assert!(error_message(&v).contains("Must provide a topology file"));
}

#[test]
fn native_network_lifecycle() {
    let env = Env::new();
    let created = env.create_native("life");
    assert_eq!(created["network_id"], "life");
    let nodes = created["nodes"].as_object().unwrap();
    assert!(nodes.contains_key("seed-0") && nodes.contains_key("receiver"));
    assert_eq!(
        nodes["seed-0"]["graphql_uri"].as_str().unwrap(),
        "http://localhost:7081/graphql"
    );

    let listed = env.json(&["network", "list"], true);
    assert_eq!(listed["networks"][0]["network_id"], "life");
    assert_eq!(
        env.json(&["network", "info", "-n", "life"], true)["network_id"],
        "life"
    );

    // the mode is remembered: no --mode / --bin-path from here on
    assert_eq!(
        env.json(&["network", "start", "-n", "life"], true)["network_id"],
        "life"
    );
    let status = env.json(&["network", "status", "-n", "life"], true);
    assert_eq!(status["status"], "running(2)");
    let services = status["services"].as_array().unwrap();
    assert!(services.iter().all(|s| s["state"] == "running"), "{status}");

    let v = env.json(&["network", "start", "-n", "life"], false);
    assert!(error_message(&v).contains("already running: receiver, seed-0"));

    // logs hold the daemon arguments the fake mina echoed
    let out = env
        .cmd(&["node", "logs", "-n", "life", "-i", "seed-0", "-r"])
        .output()
        .unwrap();
    let logs = String::from_utf8_lossy(&out.stdout);
    assert!(logs.contains("mina daemon -client-port 7080"), "{logs}");
    assert!(logs.contains("-seed"), "{logs}");

    let v = env.json(
        &[
            "node",
            "stop",
            "-n",
            "life",
            "-i",
            "seed-0",
            "--timeout",
            "5",
        ],
        true,
    );
    assert_eq!(v["node_id"], "seed-0");
    let status = env.json(&["network", "status", "-n", "life"], true);
    assert_eq!(status["status"], "running(1)");

    let v = env.json(&["node", "start", "-n", "life", "-i", "seed-0"], true);
    assert_eq!(v["node_id"], "seed-0");

    env.json(&["network", "stop", "-n", "life", "--timeout", "5"], true);
    let status = env.json(&["network", "status", "-n", "life"], true);
    assert_eq!(status["status"], "not_running");

    let v = env.json(
        &["--mode", "docker", "network", "start", "-n", "life"],
        false,
    );
    assert!(error_message(&v).contains("was created in native mode"));

    env.json(&["network", "delete", "-n", "life"], true);
    assert!(!env.network_dir("life").exists());
    assert_eq!(
        env.json(&["network", "list"], true)["networks"],
        serde_json::json!([])
    );
}

#[test]
fn native_network_files_and_permissions() {
    let env = Env::new();
    env.create_native("files");
    let dir = env.network_dir("files");
    for file in [
        "minimina.json",
        "network.json",
        "services.json",
        "genesis_ledger.json",
        "topology.json",
        "peer_list_file.txt",
    ] {
        assert!(dir.join(file).is_file(), "missing {file}");
    }
    for sub in ["network-keypairs", "libp2p-keypairs"] {
        let mode = fs::metadata(dir.join(sub)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{sub}");
    }
    let key = dir.join("network-keypairs/receiver.json");
    assert_eq!(
        fs::metadata(key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(Path::new(&dir.join("logs")).is_dir());
    env.json(&["network", "delete", "-n", "files"], true);
}
