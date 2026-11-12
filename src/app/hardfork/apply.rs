//! `network hardfork apply`: stops the network, installs the prepared postfork
//! config in every daemon, upgrades the archive database, and starts the
//! network with the postfork binaries. In auto mode the daemons have their
//! fork config already, and the dispatcher starts the postfork daemon.

use super::{
    daemon_help,
    prepare::{
        Prepared, DAEMON_JSON, FORK_CONFIG_JSON, GENESIS_DIR, HARDFORK_DIR, SHARED_CONFIG_JSON,
    },
    Context,
};
use crate::{
    archive_db::{ArchiveBlock, ArchiveDb, Migration},
    daemon_args::DaemonFeatures,
    genesis_ledger::{self, GENESIS_LEDGER_JSON, PREFORK_GENESIS_LEDGER_JSON},
    hardfork::{fork_config, toolbox::Toolbox, HardforkMode},
    native::manager::NativeManager,
    network_meta::{HardforkState, NetworkMeta},
    runner::check,
    runtime_config::RuntimeConfig,
    service::{typed::Native, ServiceConfig},
    utils,
};
use anyhow::{bail, Context as _, Result};
use chrono::{DateTime, FixedOffset, Utc};
use log::{info, warn};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// The postfork `mina-archive` config, in the hardfork directory.
pub const ARCHIVE_CONFIG_JSON: &str = "archive_config.json";
/// How long the restarted archive has to insert the postfork genesis block,
/// after the postfork genesis time.
const ARCHIVE_GENESIS_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Serialize)]
pub struct Applied {
    pub network_id: String,
    pub chain_id: String,
    pub bin_path: std::path::PathBuf,
    /// The last row of the archive's `migration_history` after the upgrade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_migration: Option<Migration>,
    /// The postfork genesis block the archive inserted, checked by `validate-fork`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_postfork_genesis: Option<ArchiveBlock>,
    /// What the archive left undone, for `network check fork` to report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl std::fmt::Display for Applied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

pub fn apply(
    ctx: &Context,
    network_id: &str,
    stop_timeout: Duration,
    seed_timeout: Duration,
) -> Result<Applied> {
    let network_path = ctx.dirs.network_path(network_id);
    let mut meta = NetworkMeta::load(&network_path)?
        .with_context(|| format!("network '{network_id}' has no minimina.json"))?;
    let h = meta
        .hardfork
        .clone()
        .with_context(|| format!("network '{network_id}' has no hardfork"))?;
    match h.state {
        HardforkState::Planned => {
            bail!("run `network hardfork prepare -n {network_id}` before `apply`")
        }
        HardforkState::Applied => {
            bail!("the hardfork of network '{network_id}' is applied already")
        }
        HardforkState::Prepared => {}
    }
    let prepared = Prepared::load(&network_path)?;
    let genesis_time = postfork_genesis_time(&network_path)?;
    let native = ctx.native(network_id)?;
    info!("Stopping network '{network_id}'");
    native.stop_all(stop_timeout)?;

    // the prefork config stays for `hardfork status` and for the record
    let genesis_ledger = network_path.join(GENESIS_LEDGER_JSON);
    let prefork = network_path.join(PREFORK_GENESIS_LEDGER_JSON);
    if !prefork.exists() {
        fs::copy(&genesis_ledger, &prefork)
            .with_context(|| format!("keeping {}", genesis_ledger.display()))?;
    }
    let shared = network_path.join(HARDFORK_DIR).join(SHARED_CONFIG_JSON);
    fs::copy(&shared, &genesis_ledger)
        .with_context(|| format!("installing {}", shared.display()))?;

    // auto mode: the dispatcher gives each daemon its own fork config
    let auto = h.mode == HardforkMode::Auto;
    if !auto {
        for (name, data) in &prepared.nodes {
            install_fork_data(&native, name, data, &prepared.chain_id)
                .with_context(|| format!("installing the fork data of '{name}'"))?;
        }
    }

    let services = ctx.dirs.get_services_info(network_id)?;
    let archive_uri = native.archive_db_uri();
    let toolbox = Toolbox::new(
        ctx.runner.as_ref(),
        &h.postfork_bin_path,
        &archive_uri,
        ctx.profile,
    );
    let mut archive = match ServiceConfig::get_archive_node(&services) {
        Some(_) => Some(ctx.archive_db.connect(&archive_uri)?),
        None => None,
    };
    let archive_migration = match (archive.as_deref_mut(), &h.archive_upgrade) {
        (Some(db), Some(script)) => {
            let migration = upgrade_archive(ctx, &archive_uri, db, script)?;
            toolbox
                .verify_upgrade(&migration)
                .context("the upgraded archive database")?;
            Some(migration)
        }
        (Some(_), None) => bail!("the network has an archive but no archive upgrade script"),
        (None, _) => None,
    };
    let archive_config = match ServiceConfig::get_archive_node(&services) {
        Some(_) => Some(write_archive_config(&network_path)?),
        None => None,
    };
    // an auto mode fork config names its ledgers by hash only
    let archive_ledgers = match (&archive_config, auto) {
        (Some(_), true) => prepared
            .nodes
            .get(&prepared.source)
            .map(|data| data.join(GENESIS_DIR)),
        _ => None,
    };

    let postfork = h.postfork_bin_path.clone();
    let features = DaemonFeatures::from_daemon_help(&daemon_help(ctx, &postfork));
    let prefork_bin = meta.bin_path.replace(postfork.clone());
    meta.features = features;
    if let Some(hf) = meta.hardfork.as_mut() {
        hf.prefork_bin_path = prefork_bin;
        hf.archive_config = archive_config.clone();
        hf.archive_ledgers = archive_ledgers.clone();
        hf.state = HardforkState::Applied;
    }
    meta.save(&network_path)
        .context("Failed to record the applied hardfork")?;

    info!(
        "Starting network '{network_id}' with {}",
        postfork.display()
    );
    let typed = ctx.services::<Native>(network_id)?;
    NativeManager::new(&network_path, &postfork, &ctx.postgres_uri, ctx.profile)
        .with_features(features)
        .with_archive_config(archive_config.clone())
        .with_archive_handover(h.archive_handover)
        .with_dispatch(ctx.dispatch.clone())
        .with_archive_ledgers(archive_ledgers)
        .start_all(&typed, network_id, seed_timeout)
        .with_context(|| format!("Failed to start network '{network_id}' after the fork"))?;
    let (archive_postfork_genesis, warnings) = match archive.as_deref_mut() {
        Some(db) => {
            let (genesis, warnings) = repair_archive(
                &toolbox,
                db,
                prepared.fork.global_slot_since_genesis,
                genesis_wait(Utc::now(), genesis_time),
                h.archive_handover,
            )
            .with_context(|| {
                format!(
                    "network '{network_id}' runs the postfork binaries, but its archive is not \
                     checked"
                )
            })?;
            (Some(genesis), warnings)
        }
        None => (None, Vec::new()),
    };
    Ok(Applied {
        network_id: network_id.to_string(),
        chain_id: prepared.chain_id,
        bin_path: postfork,
        archive_migration,
        archive_postfork_genesis,
        warnings,
    })
}

/// The postfork genesis time, from the fork config the daemons gave.
fn postfork_genesis_time(network_path: &Path) -> Result<Option<DateTime<FixedOffset>>> {
    let path = network_path.join(HARDFORK_DIR).join(FORK_CONFIG_JSON);
    let config = RuntimeConfig::from_json(&genesis_ledger::read_file(&path)?)
        .with_context(|| format!("parsing {}", path.display()))?;
    config
        .genesis
        .genesis_state_timestamp
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .with_context(|| {
            format!(
                "invalid genesis.genesis_state_timestamp in {}",
                path.display()
            )
        })
}

/// How long to wait for the postfork genesis block in the archive:
/// [`ARCHIVE_GENESIS_TIMEOUT`] after the postfork genesis time. With
/// `--hardfork-handover` the archive does not insert the block at its start;
/// the daemons send it at the genesis time.
fn genesis_wait(now: DateTime<Utc>, genesis: Option<DateTime<FixedOffset>>) -> Duration {
    let until_genesis = genesis
        .and_then(|g| (g.with_timezone(&Utc) - now).to_std().ok())
        .unwrap_or_default();
    until_genesis + ARCHIVE_GENESIS_TIMEOUT
}

/// After the restart: the archive inserts the postfork genesis block from
/// its `--config-file`, or with `handover`, gets it from the daemons at the
/// genesis time. `validate-fork` checks it and its prefork ancestors.
/// With `handover`, settling the prefork chain is the archive's own work,
/// and the prefork blocks it leaves pending are warnings; otherwise
/// `convert-chain-to-canonical` marks the chain canonical, which the archive
/// does not do with the k of its compiled profile (MinaProtocol/mina#19986).
fn repair_archive(
    toolbox: &Toolbox,
    archive: &mut dyn ArchiveDb,
    fork_genesis_slot: u32,
    wait: Duration,
    handover: bool,
) -> Result<(ArchiveBlock, Vec<String>)> {
    let genesis = wait_for_postfork_genesis(archive, fork_genesis_slot, wait)?;
    info!(
        "The archive has the postfork genesis block {} (height {})",
        genesis.state_hash, genesis.height
    );
    toolbox.validate_fork(&genesis)?;
    if !handover {
        toolbox.convert_chain_to_canonical()?;
        return Ok((genesis, Vec::new()));
    }
    let pending = archive.pending_before(fork_genesis_slot)?;
    if pending.is_empty() {
        info!("The archive settled the prefork chain itself (--hardfork-handover)");
        return Ok((genesis, Vec::new()));
    }
    let warning = format!(
        "the archive left {} prefork blocks pending (highest: height {}); it settles the fork \
         only at its start, so restarting it settles them",
        pending.len(),
        pending.iter().map(|b| b.height).max().unwrap_or_default()
    );
    warn!("{warning}");
    Ok((genesis, vec![warning]))
}

/// Waits up to `wait` for the postfork genesis block in the archive.
fn wait_for_postfork_genesis(
    archive: &mut dyn ArchiveDb,
    slot: u32,
    wait: Duration,
) -> Result<ArchiveBlock> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        if let Some(block) = archive.postfork_genesis_block(slot)? {
            return Ok(block);
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "the archive has no postfork genesis block (slot {slot}) after {} s",
                wait.as_secs()
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Writes the postfork `mina-archive` config ([`fork_config::archive_postfork_config`]):
/// the shared postfork config with the fork config on top.
fn write_archive_config(network_path: &Path) -> Result<PathBuf> {
    let dir = network_path.join(HARDFORK_DIR);
    let shared = genesis_ledger::read_file(&dir.join(SHARED_CONFIG_JSON))?;
    let fork = genesis_ledger::read_file(&dir.join(FORK_CONFIG_JSON))?;
    let path = dir.join(ARCHIVE_CONFIG_JSON);
    fs::write(
        &path,
        serde_json::to_string_pretty(&fork_config::archive_postfork_config(&shared, &fork))?,
    )
    .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Puts the fork data where the postfork daemon reads it: `daemon.json` in
/// the config directory, the ledgers in `<config dir>/<chain id>/genesis`.
fn install_fork_data(
    native: &NativeManager,
    name: &str,
    data: &Path,
    chain_id: &str,
) -> Result<()> {
    let config_dir = native.config_dir_for_service(name);
    fs::create_dir_all(config_dir.join(chain_id))?;
    fs::copy(data.join(DAEMON_JSON), config_dir.join(DAEMON_JSON))?;
    let genesis = config_dir.join(chain_id).join(GENESIS_DIR);
    if genesis.exists() {
        fs::remove_dir_all(&genesis)?;
    }
    utils::copy_dir(&data.join(GENESIS_DIR), &genesis)?;
    Ok(())
}

/// Applies the postfork `upgrade.sql` to the archive database and returns the
/// last `migration_history` row, which must say `applied`.
fn upgrade_archive(
    ctx: &Context,
    uri: &str,
    archive: &mut dyn ArchiveDb,
    script: &Path,
) -> Result<Migration> {
    let script = script
        .to_str()
        .with_context(|| format!("path '{}' is not valid UTF-8", script.display()))?;
    info!("Upgrading the archive database with {script}");
    check(
        ctx.runner.run(
            "psql".as_ref(),
            &[uri, "-v", "ON_ERROR_STOP=1", "-f", script],
            &[],
        )?,
        &format!("applying {script}"),
    )?;
    let migration = archive
        .last_migration()?
        .context("the archive upgrade left migration_history empty")?;
    if !migration.is_applied() {
        bail!("the archive upgrade did not finish: migration_history says {migration}");
    }
    Ok(migration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_archive_config_is_the_shared_config_with_the_fork_config() {
        let net = tempfile::tempdir().unwrap();
        let dir = net.path().join(HARDFORK_DIR);
        fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, value: serde_json::Value| {
            fs::write(dir.join(name), value.to_string()).unwrap();
        };
        write(SHARED_CONFIG_JSON, json!({"genesis": {"k": 10}}));
        write(
            FORK_CONFIG_JSON,
            json!({
                "genesis": {"genesis_state_timestamp": "2026-11-06T16:50:44.325000Z"},
                "proof": {"fork": {"global_slot_since_genesis": 46}},
                "ledger": {"hash": "jw", "accounts": [{"pk": "B62q", "balance": "1"}]}
            }),
        );

        let path = write_archive_config(net.path()).unwrap();
        assert_eq!(path, dir.join(ARCHIVE_CONFIG_JSON));
        let config = genesis_ledger::read_file(&path).unwrap();
        assert_eq!(config["genesis"]["k"], 10);
        assert_eq!(
            config["genesis"]["genesis_state_timestamp"],
            "2026-11-06T16:50:44.325000Z"
        );
        assert_eq!(config["ledger"]["accounts"][0]["pk"], "B62q");
        assert_eq!(config["proof"]["fork"]["global_slot_since_genesis"], 46);
    }

    #[test]
    fn the_archive_has_until_after_the_postfork_genesis_time() {
        let now = DateTime::parse_from_rfc3339("2026-11-12T00:41:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let genesis = DateTime::parse_from_rfc3339("2026-11-12T01:46:59+01:00").ok();
        assert_eq!(
            genesis_wait(now, genesis),
            Duration::from_secs(359) + ARCHIVE_GENESIS_TIMEOUT
        );
        let past = DateTime::parse_from_rfc3339("2026-11-12T00:30:00Z").ok();
        assert_eq!(genesis_wait(now, past), ARCHIVE_GENESIS_TIMEOUT);
        assert_eq!(genesis_wait(now, None), ARCHIVE_GENESIS_TIMEOUT);
    }

    #[test]
    fn the_genesis_time_is_the_fork_configs() {
        let net = tempfile::tempdir().unwrap();
        let dir = net.path().join(HARDFORK_DIR);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(FORK_CONFIG_JSON),
            json!({"genesis": {"genesis_state_timestamp": "2026-11-12T00:46:59.717000Z"}})
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            postfork_genesis_time(net.path()).unwrap(),
            DateTime::parse_from_rfc3339("2026-11-12T00:46:59.717Z").ok()
        );
    }
}
