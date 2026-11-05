//! The hardfork of a spec network: checks at `network create`, the genesis
//! timestamp at the first `network start`, and `network hardfork status`.

use super::Context;
use crate::{
    cli::{CreateNetworkArgs, ExecutionMode},
    daemon_args::DaemonFeatures,
    genesis_ledger,
    hardfork::{self, Constants, ForkAt, ForkMethod, HardforkMode, HardforkSpec, Schedule},
    native::{self, binary::Binary},
    network_meta::{HardforkMeta, HardforkState, NetworkMeta},
    runtime_config::{self, RuntimeConfig},
    spec::{NetworkSpec, Role},
    utils,
};
use anyhow::{bail, Context as _, Result};
use chrono::{DateTime, FixedOffset, Local, Utc};
use log::info;
use serde::Serialize;
use std::path::{Path, PathBuf};

mod apply;
mod prepare;

pub use apply::apply;
pub use prepare::prepare;

/// The archive schema migration of a mina package, in `etc/mina/archive`.
const ARCHIVE_UPGRADE_SQL: &str = "upgrade.sql";

/// Checks the `[hardfork]` of the spec of `create`, with every problem in one
/// error, before anything is changed. The schedule is placed from a genesis
/// of now; the first `network start` places a date again.
pub fn check_create(
    ctx: &Context,
    cmd: &CreateNetworkArgs,
) -> Result<Option<(HardforkMeta, Schedule)>> {
    let Some(spec_path) = &cmd.spec else {
        return Ok(None);
    };
    let spec = NetworkSpec::load(spec_path)?;
    let Some(h) = &spec.hardfork else {
        return Ok(None);
    };
    let mut problems = Vec::new();
    if ctx.mode != ExecutionMode::Native {
        problems
            .push("a network with [hardfork] runs in native mode only: add --mode native".into());
    }

    let runtime_config = spec
        .runtime_config_json()?
        .map(|json| RuntimeConfig::from_json(&json))
        .transpose()
        .context("[runtime_config] is not a valid runtime config")?
        .unwrap_or_default();
    let schedule = match Constants::from_runtime_config(&runtime_config) {
        Ok(c) => h
            .schedule(Local::now().fixed_offset(), c, &runtime_config.daemon)
            .map_err(|p| problems.extend(p))
            .ok(),
        Err(p) => {
            problems.extend(p);
            None
        }
    };

    let method = match h.mode {
        HardforkMode::Auto => None,
        HardforkMode::Manual => Some(h.method.unwrap_or_default()),
    };
    let postfork = h.postfork.as_ref().and_then(|p| p.bin_path.as_ref());
    let postfork = match postfork {
        None => {
            problems.push(
                "[hardfork.postfork] bin_path is missing: minimina must know the binaries \
                 that the network switches to"
                    .into(),
            );
            None
        }
        Some(path) => {
            let base = spec_path.parent().unwrap_or(Path::new("."));
            let dir = std::path::absolute(base.join(path))
                .with_context(|| format!("resolving {}", path.display()))?;
            problems.extend(check_postfork(ctx, &spec, method, &dir));
            Some(dir)
        }
    };
    let archive_upgrade = match (
        &postfork,
        spec.nodes.iter().any(|g| g.role == Role::Archive),
    ) {
        (Some(postfork), true) => archive_upgrade_script(spec_path, h, postfork)
            .map_err(|p| problems.push(p))
            .ok(),
        _ => None,
    };

    if ctx.mode == ExecutionMode::Native && h.mode == HardforkMode::Auto {
        let bin = ctx.bin_path()?;
        if !DaemonFeatures::from_daemon_help(&daemon_help(ctx, bin)).hardfork_handling {
            problems.push(format!(
                "mode = \"auto\" needs a prefork daemon with --hardfork-handling; {} has none",
                Binary::Mina.path(bin).display()
            ));
        }
    }

    match (schedule, postfork) {
        (Some(schedule), Some(postfork_bin_path)) if problems.is_empty() => Ok(Some((
            HardforkMeta {
                mode: h.mode,
                method,
                postfork_bin_path,
                archive_upgrade,
                state: HardforkState::Planned,
                prefork_bin_path: None,
            },
            schedule,
        ))),
        _ => bail!(
            "The [hardfork] of {} is not valid:\n  - {}",
            spec_path.display(),
            problems.join("\n  - ")
        ),
    }
}

/// The postfork `upgrade.sql` of the archive database: `archive_upgrade` of
/// the spec, else the one of the postfork package.
fn archive_upgrade_script(
    spec_path: &Path,
    h: &HardforkSpec,
    postfork: &Path,
) -> std::result::Result<PathBuf, String> {
    let given = h.postfork.as_ref().and_then(|p| p.archive_upgrade.as_ref());
    match given {
        Some(path) => {
            let base = spec_path.parent().unwrap_or(Path::new("."));
            let path = std::path::absolute(base.join(path)).map_err(|e| e.to_string())?;
            path.is_file().then_some(path.clone()).ok_or_else(|| {
                format!(
                    "[hardfork.postfork] archive_upgrade {} is not a file",
                    path.display()
                )
            })
        }
        None => utils::packaged_schema(postfork, ARCHIVE_UPGRADE_SQL).ok_or_else(|| {
            format!(
                "the archive needs the postfork {ARCHIVE_UPGRADE_SQL}, and {} is not in a package \
                 directory with {}: set [hardfork.postfork] archive_upgrade",
                postfork.display(),
                utils::PACKAGED_SCHEMA_DIR
            )
        }),
    }
}

/// Problems of the postfork binaries: missing files, or a `mina` that does not run.
fn check_postfork(
    ctx: &Context,
    spec: &NetworkSpec,
    method: Option<ForkMethod>,
    dir: &Path,
) -> Vec<String> {
    let has = |role| spec.nodes.iter().any(|g| g.role == role);
    let mut needed = vec![Binary::Mina];
    if has(Role::Archive) {
        needed.push(Binary::Archive);
    }
    if has(Role::Rosetta) {
        needed.push(Binary::Rosetta);
    }
    if method == Some(ForkMethod::Legacy) {
        // makes the postfork genesis ledgers from the fork config
        needed.push(Binary::CreateGenesis);
    }
    let missing: Vec<Binary> = needed
        .into_iter()
        .filter(|binary| !binary.path(dir).exists())
        .collect();
    if !dir.is_dir() {
        return vec![format!(
            "postfork bin_path {} is not a directory",
            dir.display()
        )];
    }
    let mut problems = Vec::new();
    if !missing.is_empty() {
        problems.push(format!(
            "postfork bin_path {} has no {}",
            dir.display(),
            missing
                .iter()
                .map(|b| b.file_name())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !missing.contains(&Binary::Mina) {
        let mina_env = native::mina_env(dir, ctx.profile);
        let mina = Binary::Mina.path(dir);
        match ctx.runner.run(
            mina.as_os_str(),
            &["version"],
            &native::env_refs(&[], &mina_env),
        ) {
            Ok(out) if out.status.success() => {}
            Ok(out) => problems.push(format!(
                "postfork {} does not run: {}",
                mina.display(),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("no output")
            )),
            Err(e) => problems.push(format!("postfork {} does not run: {e}", mina.display())),
        }
    }
    problems
}

/// `mina daemon -help` of the binaries in `bin`, for [`DaemonFeatures`].
fn daemon_help(ctx: &Context, bin: &Path) -> String {
    let mina_env = native::mina_env(bin, ctx.profile);
    ctx.runner
        .run(
            Binary::Mina.path(bin).as_os_str(),
            &["daemon", "-help"],
            &native::env_refs(&[], &mina_env),
        )
        .map(|out| {
            String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr)
        })
        .unwrap_or_default()
}

/// At the first `network start`: sets the genesis timestamp to now and, for a
/// fork at a date, places the fork slots from it again.
pub fn set_genesis(ctx: &Context, network_id: &str) -> Result<()> {
    let network_path = ctx.dirs.network_path(network_id);
    let Some(mut meta) = NetworkMeta::load(&network_path)? else {
        return Ok(());
    };
    if !meta.genesis_pending {
        return Ok(());
    }
    let now = Local::now().fixed_offset();
    let mut overrides = serde_json::json!({
        "genesis": { "genesis_state_timestamp": genesis_ledger::format_timestamp(now) }
    });
    if meta.hardfork.is_some() {
        let spec_path = ctx.dirs.spec_path(network_id);
        let spec = NetworkSpec::load(&spec_path)?;
        if let Some(h) = spec
            .hardfork
            .as_ref()
            .filter(|h| matches!(h.at, ForkAt::Date(_)))
        {
            let c = Constants::from_runtime_config(&read_runtime_config(&network_path)?)
                .map_err(|p| anyhow::anyhow!(p.join("; ")))?;
            // the fork keys in the genesis ledger are the ones placed at create
            let schedule = h.schedule(now, c, &Default::default()).map_err(|p| {
                anyhow::anyhow!(
                    "the fork date of network '{network_id}' does not fit a genesis of now:\n  - {}\n\
                     Change [hardfork] at in {} and create the network again",
                    p.join("\n  - "),
                    spec_path.display()
                )
            })?;
            info!(
                "Fork at slot_chain_end {} (slot_tx_end {}).",
                schedule.slot_chain_end, schedule.slot_tx_end
            );
            overrides["daemon"] = serde_json::to_value(runtime_config::Daemon::from(schedule))?;
        }
    }
    genesis_ledger::update(&network_path, &overrides)
        .with_context(|| format!("Failed to set the genesis timestamp of '{network_id}'"))?;
    info!("Genesis timestamp of '{network_id}': {now}");
    meta.genesis_pending = false;
    meta.save(&network_path)
        .context("Failed to record the genesis timestamp")?;
    Ok(())
}

/// Whether the network runs the postfork binaries after `hardfork apply`.
pub fn is_applied(ctx: &Context, network_id: &str) -> Result<bool> {
    Ok(NetworkMeta::load(&ctx.dirs.network_path(network_id))?
        .and_then(|m| m.hardfork)
        .is_some_and(|h| h.state == HardforkState::Applied))
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub network_id: String,
    pub mode: HardforkMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<ForkMethod>,
    pub state: HardforkState,
    pub phase: hardfork::Phase,
    /// Global slot now; none before the genesis.
    pub slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_timestamp: Option<String>,
    pub slot_duration_ms: u64,
    pub k: u32,
    pub slot_tx_end: Point,
    pub slot_chain_end: Point,
    pub fork_genesis: Point,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<Next>,
    pub prefork_bin_path: Option<PathBuf>,
    pub postfork_bin_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct Point {
    pub slot: u32,
    /// None until the first `network start` sets the genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Next {
    pub phase: hardfork::Phase,
    pub time: String,
    pub in_seconds: i64,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

/// `network hardfork status`: the fork schedule and the phase of the network now.
pub fn status(ctx: &Context, network_id: &str, now: DateTime<Utc>) -> Result<Status> {
    let network_path = ctx.dirs.network_path(network_id);
    let meta = NetworkMeta::load(&network_path)?
        .with_context(|| format!("network '{network_id}' has no minimina.json"))?;
    let h = meta.hardfork.with_context(|| {
        format!("network '{network_id}' has no hardfork: add [hardfork] to its spec and create it again")
    })?;
    let config = read_runtime_config(&network_path)?;
    let c = Constants::from_runtime_config(&config).map_err(|p| anyhow::anyhow!(p.join("; ")))?;
    let schedule = Schedule::from_daemon(&config.daemon).with_context(|| {
        format!("the genesis ledger of '{network_id}' has no complete fork schedule in `daemon`")
    })?;
    let genesis = (!meta.genesis_pending)
        .then_some(config.genesis.genesis_state_timestamp.as_deref())
        .flatten()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .context("invalid genesis.genesis_state_timestamp")?;

    let point = |slot: u32| Point {
        slot,
        time: genesis.map(|g| hardfork::slot_time(g, c, slot).to_rfc3339()),
    };
    let (phase, slot, next) = match genesis {
        None => (hardfork::Phase::NotStarted, None, None),
        Some(g) => hardfork::phase(g, c, schedule, now),
    };
    let next = next.map(|(phase, at): (_, DateTime<FixedOffset>)| Next {
        phase,
        time: at.to_rfc3339(),
        in_seconds: (at.with_timezone(&Utc) - now).num_seconds(),
    });
    Ok(Status {
        network_id: network_id.to_string(),
        mode: h.mode,
        state: h.state,
        method: h.method,
        phase,
        slot,
        genesis_timestamp: genesis.map(|g| g.to_rfc3339()),
        slot_duration_ms: c.slot_ms,
        k: c.k,
        slot_tx_end: point(schedule.slot_tx_end),
        slot_chain_end: point(schedule.slot_chain_end),
        fork_genesis: point(schedule.fork_genesis_slot()),
        next,
        prefork_bin_path: meta.bin_path,
        postfork_bin_path: h.postfork_bin_path,
    })
}

/// The prefork genesis runtime config: the one `hardfork apply` kept, else the current one.
fn read_runtime_config(network_path: &Path) -> Result<RuntimeConfig> {
    let prefork = network_path.join(genesis_ledger::PREFORK_GENESIS_LEDGER_JSON);
    let json = if prefork.exists() {
        genesis_ledger::read_file(&prefork)?
    } else {
        genesis_ledger::read(network_path)?
    };
    RuntimeConfig::from_json(&json).context("the genesis ledger is not a valid runtime config")
}
