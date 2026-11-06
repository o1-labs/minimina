//! `network hardfork apply`: stops the network, installs the prepared postfork
//! config in every daemon, upgrades the archive database, and starts the
//! network with the postfork binaries.

use super::{
    daemon_help,
    prepare::{
        Prepared, DAEMON_JSON, FORK_CONFIG_JSON, GENESIS_DIR, HARDFORK_DIR, SHARED_CONFIG_JSON,
    },
    Context,
};
use crate::{
    daemon_args::DaemonFeatures,
    genesis_ledger::{self, GENESIS_LEDGER_JSON, PREFORK_GENESIS_LEDGER_JSON},
    hardfork::fork_config,
    native::manager::NativeManager,
    network_meta::{HardforkState, NetworkMeta},
    runner::check,
    service::{typed::Native, ServiceConfig},
    utils,
};
use anyhow::{bail, Context as _, Result};
use log::info;
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// The postfork `mina-archive` config, in the hardfork directory.
pub const ARCHIVE_CONFIG_JSON: &str = "archive_config.json";

#[derive(Debug, Serialize)]
pub struct Applied {
    pub network_id: String,
    pub chain_id: String,
    pub bin_path: std::path::PathBuf,
    /// The last row of the archive's `migration_history` after the upgrade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_migration: Option<String>,
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

    for (name, data) in &prepared.nodes {
        install_fork_data(&native, name, data, &prepared.chain_id)
            .with_context(|| format!("installing the fork data of '{name}'"))?;
    }

    let services = ctx.dirs.get_services_info(network_id)?;
    let archive_migration = match (
        ServiceConfig::get_archive_node(&services),
        &h.archive_upgrade,
    ) {
        (Some(_), Some(script)) => Some(upgrade_archive(ctx, &native, script)?),
        (Some(_), None) => bail!("the network has an archive but no archive upgrade script"),
        (None, _) => None,
    };
    let archive_config = match ServiceConfig::get_archive_node(&services) {
        Some(_) => Some(write_archive_config(&network_path)?),
        None => None,
    };

    let postfork = h.postfork_bin_path.clone();
    let features = DaemonFeatures::from_daemon_help(&daemon_help(ctx, &postfork));
    let prefork_bin = meta.bin_path.replace(postfork.clone());
    meta.features = features;
    if let Some(hf) = meta.hardfork.as_mut() {
        hf.prefork_bin_path = prefork_bin;
        hf.archive_config = archive_config.clone();
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
        .with_archive_config(archive_config)
        .start_all(&typed, network_id, seed_timeout)
        .with_context(|| format!("Failed to start network '{network_id}' after the fork"))?;
    Ok(Applied {
        network_id: network_id.to_string(),
        chain_id: prepared.chain_id,
        bin_path: postfork,
        archive_migration,
    })
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
fn upgrade_archive(ctx: &Context, native: &NativeManager, script: &Path) -> Result<String> {
    let db = native.archive_db_uri();
    let script = script
        .to_str()
        .with_context(|| format!("path '{}' is not valid UTF-8", script.display()))?;
    info!("Upgrading the archive database with {script}");
    check(
        ctx.runner.run(
            "psql".as_ref(),
            &[&db, "-v", "ON_ERROR_STOP=1", "-f", script],
            &[],
        )?,
        &format!("applying {script}"),
    )?;
    let out = check(
        ctx.runner.run(
            "psql".as_ref(),
            &[
                &db,
                "-At",
                "-c",
                "SELECT protocol_version || ' ' || migration_version || ' ' || status \
                 FROM migration_history ORDER BY commit_start_at DESC LIMIT 1",
            ],
            &[],
        )?,
        "reading migration_history",
    )?;
    let row = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !row.ends_with(" applied") {
        bail!("the archive upgrade did not finish: migration_history says '{row}'");
    }
    Ok(row)
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
}
