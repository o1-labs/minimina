//! `network hardfork prepare`: makes and checks the postfork config of every
//! daemon of a running network, after `slot_chain_end`.

use super::{status, Context};
use crate::{
    genesis_ledger,
    hardfork::{
        fork_config::{self, ForkPoint, LedgerHashes},
        ForkMethod, HardforkMode,
    },
    native::{self, binary::Binary},
    network_meta::{HardforkState, NetworkMeta},
    node_client,
    runner::check,
    service::ServiceConfig,
};
use anyhow::{bail, Context as _, Result};
use chrono::Utc;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// Directory of the postfork data in the network directory.
pub const HARDFORK_DIR: &str = "hardfork";
const PREPARED_JSON: &str = "prepared.json";
const FORK_CONFIG_JSON: &str = "fork_config.json";
const LEDGER_HASHES_JSON: &str = "ledger_hashes.json";
/// The postfork runtime config of a node, as the hardfork tools name it.
pub const DAEMON_JSON: &str = "daemon.json";
/// The postfork ledger files of a node.
pub const GENESIS_DIR: &str = "genesis";
/// The shared postfork runtime config, which `apply` makes the genesis ledger.
pub const SHARED_CONFIG_JSON: &str = "genesis_ledger.postfork.json";

/// What `prepare` made: the input of `apply`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Prepared {
    pub method: ForkMethod,
    /// The daemon whose fork config is used.
    pub source: String,
    /// Daemons that did not answer or have another fork point (with `--source`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub fork: ForkPoint,
    /// Hash of the postfork genesis ledger.
    pub ledger_hash: String,
    /// The chain id every node computes for the postfork chain.
    pub chain_id: String,
    /// The fork data of each daemon: a directory with `daemon.json` and `genesis/`.
    pub nodes: BTreeMap<String, PathBuf>,
}

impl Prepared {
    pub fn load(network_path: &Path) -> Result<Self> {
        let path = network_path.join(HARDFORK_DIR).join(PREPARED_JSON);
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "reading {}: run `network hardfork prepare` first",
                path.display()
            )
        })?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }
}

impl std::fmt::Display for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

/// Makes the postfork config of every daemon and checks that they agree:
/// one fork point, the ledger hash of the postfork tool, one chain id.
/// With `wait`, it waits for `slot_chain_end` first. With `source`, the fork
/// config of that daemon is used, and the others only give warnings.
pub fn prepare(
    ctx: &Context,
    network_id: &str,
    wait: bool,
    source: Option<&str>,
) -> Result<Prepared> {
    let network_path = ctx.dirs.network_path(network_id);
    let mut meta = NetworkMeta::load(&network_path)?
        .with_context(|| format!("network '{network_id}' has no minimina.json"))?;
    let h = meta
        .hardfork
        .clone()
        .with_context(|| format!("network '{network_id}' has no hardfork"))?;
    if h.mode == HardforkMode::Auto {
        bail!("network '{network_id}' forks in auto mode: the daemons write their fork config themselves");
    }
    if h.state == HardforkState::Applied {
        bail!("the hardfork of network '{network_id}' is applied already");
    }
    wait_for_chain_end(ctx, network_id, wait)?;
    let method = h.method.unwrap_or_default();
    let prefork_bin = meta
        .bin_path
        .clone()
        .context("the network has no prefork bin_path")?;
    let postfork_bin = &h.postfork_bin_path;

    let services = ctx.dirs.get_services_info(network_id)?;
    let daemons: Vec<&ServiceConfig> = services.iter().filter(|s| s.is_chain_daemon()).collect();
    let configs = node_client::fork_configs(&services)?;
    let (source, fork, warnings) = fork_point(&configs, source)?;
    let fork_config = configs[&source]
        .as_ref()
        .map_err(|e| anyhow::anyhow!(e.clone()))?;
    let mut problems = Vec::new();
    info!(
        "Fork point from '{source}': {} at height {}",
        fork.state_hash, fork.blockchain_length
    );

    let dir = network_path.join(HARDFORK_DIR);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    let fork_config_path = dir.join(FORK_CONFIG_JSON);
    fs::write(
        &fork_config_path,
        serde_json::to_string_pretty(fork_config)?,
    )?;

    let fork_genesis = status(ctx, network_id, Utc::now())?.fork_genesis;
    if fork.global_slot_since_genesis != fork_genesis.slot {
        bail!(
            "the fork config starts the postfork chain at slot {}, the schedule at slot {}",
            fork.global_slot_since_genesis,
            fork_genesis.slot
        );
    }
    let genesis_timestamp = fork_genesis
        .time
        .context("the network has no genesis timestamp")?;
    // the postfork tool makes the reference ledgers
    let hashes = create_genesis(ctx, postfork_bin, &fork_config_path, &dir)?;
    let postfork_config = fork_config::postfork_config(fork_config, &hashes, &genesis_timestamp);
    fs::write(
        dir.join(DAEMON_JSON),
        serde_json::to_string_pretty(&postfork_config)?,
    )?;
    let shared = dir.join(SHARED_CONFIG_JSON);
    let prefork_config = genesis_ledger::read(&network_path)?;
    fs::write(
        &shared,
        serde_json::to_string_pretty(&fork_config::shared_postfork_config(&prefork_config))?,
    )?;

    let mut nodes = BTreeMap::new();
    for daemon in &daemons {
        let data = match method {
            ForkMethod::Legacy => dir.clone(),
            ForkMethod::Advanced => {
                let data = dir.join("nodes").join(&daemon.service_name);
                match advanced_fork_data(ctx, &prefork_bin, daemon, &data, &hashes) {
                    Ok(()) => data,
                    Err(e) => {
                        problems.push(format!("{}: {e}", daemon.service_name));
                        continue;
                    }
                }
            }
        };
        nodes.insert(daemon.service_name.clone(), data);
    }

    // legacy: one fork data directory for all nodes, so one computation
    let mut by_data: BTreeMap<&Path, std::result::Result<String, String>> = BTreeMap::new();
    let mut chain_ids = BTreeMap::new();
    for (name, data) in &nodes {
        let id = by_data.entry(data).or_insert_with(|| {
            chain_id(ctx, postfork_bin, data, &shared).map_err(|e| format!("{e:#}"))
        });
        match id {
            Ok(id) => {
                chain_ids.insert(name.clone(), id.clone());
            }
            Err(e) => problems.push(format!("{name}: {e}")),
        }
    }
    let ids: BTreeSet<&String> = chain_ids.values().collect();
    if ids.len() > 1 {
        problems.push(format!(
            "the nodes compute different postfork chain ids: {}",
            chain_ids
                .iter()
                .map(|(n, id)| format!("{n} {id}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !problems.is_empty() {
        bail!(
            "The postfork config of network '{network_id}' is not valid:\n  - {}",
            problems.join("\n  - ")
        );
    }

    let prepared = Prepared {
        method,
        source,
        warnings,
        fork,
        ledger_hash: hashes.ledger.hash,
        chain_id: ids
            .first()
            .map(|id| id.to_string())
            .context("no chain id")?,
        nodes,
    };
    fs::write(
        dir.join(PREPARED_JSON),
        serde_json::to_string_pretty(&prepared)?,
    )?;
    if let Some(h) = meta.hardfork.as_mut() {
        h.state = HardforkState::Prepared;
    }
    meta.save(&network_path)
        .context("Failed to record the prepared hardfork")?;
    Ok(prepared)
}

/// The daemon whose fork config is used and its fork point. Without
/// `given`, every daemon must give the same one; with it, the daemons that
/// differ or do not answer are warnings.
fn fork_point(
    configs: &BTreeMap<String, std::result::Result<serde_json::Value, String>>,
    given: Option<&str>,
) -> Result<(String, ForkPoint, Vec<String>)> {
    let mut problems = Vec::new();
    let mut points = BTreeMap::new();
    for (name, config) in configs {
        match config
            .as_ref()
            .map_err(String::clone)
            .and_then(ForkPoint::of)
        {
            Ok(point) => {
                points.insert(name.as_str(), point);
            }
            Err(e) => problems.push(format!("{name}: {e}")),
        }
    }
    if let Some(name) = given.filter(|n| !configs.contains_key(*n)) {
        bail!(
            "--source {name}: no such daemon (daemons: {})",
            configs.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    let source = given.or_else(|| points.keys().next().copied());
    let Some((source, fork)) = source.and_then(|s| Some((s, points.get(s)?.clone()))) else {
        bail!(
            "No fork config from {}:\n  - {}",
            given.unwrap_or("any daemon"),
            problems.join("\n  - ")
        );
    };
    for (name, point) in &points {
        if *point != fork {
            problems.push(format!(
                "{name} has fork point {} (height {}), {source} has {} (height {})",
                point.state_hash, point.blockchain_length, fork.state_hash, fork.blockchain_length
            ));
        }
    }
    if given.is_none() && !problems.is_empty() {
        bail!(
            "The daemons do not give one fork config:\n  - {}\n\
             Use --source <daemon> to take the fork config of one daemon",
            problems.join("\n  - ")
        );
    }
    for warning in &problems {
        warn!("{warning}");
    }
    Ok((source.to_string(), fork, problems))
}

/// Fails before `slot_chain_end` and one slot more (the daemons need the
/// last block), or with `wait`, sleeps until then.
fn wait_for_chain_end(ctx: &Context, network_id: &str, wait: bool) -> Result<()> {
    let s = status(ctx, network_id, Utc::now())?;
    let chain_end = s
        .slot_chain_end
        .time
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()?
        .with_context(|| format!("network '{network_id}' has not started"))?;
    let ready =
        chain_end.with_timezone(&Utc) + chrono::Duration::milliseconds(s.slot_duration_ms as i64);
    loop {
        let seconds = (ready - Utc::now()).num_seconds();
        if seconds <= 0 {
            return Ok(());
        }
        if !wait {
            bail!(
                "the fork config is final after slot_chain_end {} ({chain_end}), in {seconds} s: \
                 run again then, or add --wait",
                s.slot_chain_end.slot
            );
        }
        info!(
            "Waiting {seconds} s for slot_chain_end {}",
            s.slot_chain_end.slot
        );
        std::thread::sleep(std::time::Duration::from_secs(seconds.clamp(1, 60) as u64));
    }
}

/// Runs the postfork `runtime_genesis_ledger` on the fork config: the ledger
/// files go to `<dir>/genesis`, their hashes to `<dir>/ledger_hashes.json`.
fn create_genesis(
    ctx: &Context,
    postfork_bin: &Path,
    fork_config: &Path,
    dir: &Path,
) -> Result<LedgerHashes> {
    let tool = Binary::CreateGenesis.path(postfork_bin);
    let mina_env = native::mina_env(postfork_bin, ctx.profile);
    let env = native::env_refs(&[], &mina_env);
    let help = ctx.runner.run(tool.as_os_str(), &["-help"], &env)?;
    let hashes_path = dir.join(LEDGER_HASHES_JSON);
    let mut args = vec![
        "--config-file".to_string(),
        utf8(fork_config)?.to_string(),
        "--genesis-dir".to_string(),
        utf8(&dir.join(GENESIS_DIR))?.to_string(),
        "--hash-output-file".to_string(),
        utf8(&hashes_path)?.to_string(),
    ];
    // a fork to Mesa widens the app state of zkApp accounts
    if String::from_utf8_lossy(&help.stdout).contains("-pad-app-state")
        || String::from_utf8_lossy(&help.stderr).contains("-pad-app-state")
    {
        args.push("--pad-app-state".to_string());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    info!("Making the postfork ledgers with {}", tool.display());
    check(
        ctx.runner.run(tool.as_os_str(), &args, &env)?,
        &format!("{} on the fork config", Binary::CreateGenesis),
    )?;
    let text = fs::read_to_string(&hashes_path)
        .with_context(|| format!("reading {}", hashes_path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", hashes_path.display()))
}

/// The advanced method: the prefork daemon writes its own fork data to
/// `data`. Its ledger must be the one the postfork tool made.
fn advanced_fork_data(
    ctx: &Context,
    prefork_bin: &Path,
    daemon: &ServiceConfig,
    data: &Path,
    hashes: &LedgerHashes,
) -> Result<()> {
    let port = daemon
        .client_port
        .context("the daemon has no client port")?
        .to_string();
    let mina_env = native::mina_env(prefork_bin, ctx.profile);
    let mina = Binary::Mina.path(prefork_bin);
    check(
        ctx.runner.run(
            mina.as_os_str(),
            &[
                "advanced",
                "generate-hardfork-config",
                "--daemon-port",
                &port,
                "--hardfork-config-dir",
                utf8(data)?,
                "--generate-fork-validation",
                "false",
            ],
            &native::env_refs(&[], &mina_env),
        )?,
        "mina advanced generate-hardfork-config",
    )?;
    let config = genesis_ledger::read_file(&data.join(DAEMON_JSON))?;
    let hash = config
        .pointer("/ledger/hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if hash != hashes.ledger.hash {
        bail!(
            "the prefork daemon made ledger {hash}, the postfork {} made {}: the two versions \
             do not agree on the hardfork ledger (for example on the hardfork txn version of \
             account permissions), so the postfork daemon cannot load this fork config",
            Binary::CreateGenesis,
            hashes.ledger.hash
        );
    }
    Ok(())
}

/// The chain id the postfork daemon computes from the fork data in `data`
/// and the shared config; it also checks that the ledger files are there.
fn chain_id(ctx: &Context, postfork_bin: &Path, data: &Path, shared: &Path) -> Result<String> {
    let mina_env = native::mina_env(postfork_bin, ctx.profile);
    let mina = Binary::Mina.path(postfork_bin);
    let out = check(
        ctx.runner.run(
            mina.as_os_str(),
            &[
                "internal",
                "chain-id",
                "--genesis-ledger-dir",
                utf8(&data.join(GENESIS_DIR))?,
                "--config-file",
                utf8(&data.join(DAEMON_JSON))?,
                "--config-file",
                utf8(shared)?,
            ],
            &native::env_refs(&[], &mina_env),
        )?,
        "mina internal chain-id",
    )?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .map(|l| l.trim().to_string())
        .filter(|id| !id.is_empty())
        .context("mina internal chain-id printed nothing")
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path '{}' is not valid UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(state_hash: &str) -> std::result::Result<serde_json::Value, String> {
        Ok(json!({"proof": {"fork": {
            "state_hash": state_hash, "blockchain_length": 8, "global_slot_since_genesis": 52
        }}}))
    }

    fn configs() -> BTreeMap<String, std::result::Result<serde_json::Value, String>> {
        BTreeMap::from([
            ("bp-2".to_string(), config("3NK5")),
            ("node-1".to_string(), Err("no answer".to_string())),
            ("seed-1".to_string(), config("3NLn")),
        ])
    }

    #[test]
    fn all_daemons_must_agree_without_a_source() {
        let err = fork_point(&configs(), None).unwrap_err().to_string();
        assert!(err.contains("node-1: no answer"), "{err}");
        assert!(
            err.contains("seed-1 has fork point 3NLn (height 8), bp-2 has 3NK5"),
            "{err}"
        );
        assert!(err.contains("Use --source <daemon>"), "{err}");

        let agree = BTreeMap::from([
            ("a".to_string(), config("3NLn")),
            ("b".to_string(), config("3NLn")),
        ]);
        let (source, fork, warnings) = fork_point(&agree, None).unwrap();
        assert_eq!((source.as_str(), fork.state_hash.as_str()), ("a", "3NLn"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_source_turns_the_others_into_warnings() {
        let (source, fork, warnings) = fork_point(&configs(), Some("seed-1")).unwrap();
        assert_eq!(
            (source.as_str(), fork.state_hash.as_str()),
            ("seed-1", "3NLn")
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");

        let err = |s| fork_point(&configs(), Some(s)).unwrap_err().to_string();
        assert!(err("nope").contains("no such daemon (daemons: bp-2, node-1, seed-1)"));
        assert!(err("node-1").contains("No fork config from node-1"));
    }
}
