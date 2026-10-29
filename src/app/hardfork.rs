//! The hardfork of a spec network: checks at `network create`, the genesis
//! timestamp at the first `network start`, and `network hardfork status`.

use super::Context;
use crate::{
    cli::{CreateNetworkArgs, ExecutionMode},
    genesis_ledger,
    hardfork::{self, Constants, ForkAt, ForkMethod, HardforkMode, Schedule},
    native,
    network_meta::{HardforkMeta, NetworkMeta},
    spec::{NetworkSpec, Role},
};
use anyhow::{bail, Context as _, Result};
use chrono::{DateTime, FixedOffset, Local, Utc};
use log::info;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// The spec copy in the network directory.
const SPEC_FILE: &str = "network.toml";

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

    let runtime_config = spec.runtime_config_json()?.unwrap_or_default();
    let schedule = match Constants::from_runtime_config(&runtime_config) {
        Ok(c) => h
            .schedule(Local::now().fixed_offset(), c, runtime_config.get("daemon"))
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

    if ctx.mode == ExecutionMode::Native && h.mode == HardforkMode::Auto {
        let bin = ctx.bin_path()?;
        if !daemon_help(ctx, bin).contains("-hardfork-handling") {
            problems.push(format!(
                "mode = \"auto\" needs a prefork daemon with --hardfork-handling; {} has none",
                bin.join("mina").display()
            ));
        }
    }

    match (schedule, postfork) {
        (Some(schedule), Some(postfork_bin_path)) if problems.is_empty() => Ok(Some((
            HardforkMeta {
                mode: h.mode,
                method,
                postfork_bin_path,
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

/// Problems of the postfork binaries: missing files, or a `mina` that does not run.
fn check_postfork(
    ctx: &Context,
    spec: &NetworkSpec,
    method: Option<ForkMethod>,
    dir: &Path,
) -> Vec<String> {
    let has = |role| spec.nodes.iter().any(|g| g.role == role);
    let mut needed = vec!["mina"];
    if has(Role::Archive) {
        needed.push("mina-archive");
    }
    if has(Role::Rosetta) {
        needed.push("mina-rosetta");
    }
    if method == Some(ForkMethod::Legacy) {
        // makes the postfork genesis ledgers from the fork config
        needed.push("mina-create-genesis");
    }
    let missing: Vec<_> = needed
        .iter()
        .filter(|name| !dir.join(name).exists())
        .copied()
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
            missing.join(", ")
        ));
    }
    if !missing.contains(&"mina") {
        let mina_env = native::mina_env(dir, ctx.profile);
        let mina = dir.join("mina");
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

fn daemon_help(ctx: &Context, bin: &Path) -> String {
    let mina_env = native::mina_env(bin, ctx.profile);
    ctx.runner
        .run(
            bin.join("mina").as_os_str(),
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
        let spec = NetworkSpec::load(&network_path.join(SPEC_FILE))?;
        if let Some(h) = spec
            .hardfork
            .as_ref()
            .filter(|h| matches!(h.at, ForkAt::Date(_)))
        {
            let config = genesis_ledger::read(&network_path)?;
            let c = Constants::from_runtime_config(&config)
                .map_err(|p| anyhow::anyhow!(p.join("; ")))?;
            let schedule = h.schedule(now, c, None).map_err(|p| {
                anyhow::anyhow!(
                    "the fork date of network '{network_id}' does not fit a genesis of now:\n  - {}\n\
                     Change [hardfork] at in {} and create the network again",
                    p.join("\n  - "),
                    network_path.join(SPEC_FILE).display()
                )
            })?;
            info!(
                "Fork at slot_chain_end {} (slot_tx_end {}).",
                schedule.slot_chain_end, schedule.slot_tx_end
            );
            overrides["daemon"] = schedule.daemon_json();
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

#[derive(Debug, Serialize)]
pub struct Status {
    pub network_id: String,
    pub mode: HardforkMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<ForkMethod>,
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
    let config = genesis_ledger::read(&network_path)?;
    let c = Constants::from_runtime_config(&config).map_err(|p| anyhow::anyhow!(p.join("; ")))?;
    let schedule = Schedule::from_runtime_config(&config).with_context(|| {
        format!("the genesis ledger of '{network_id}' has no daemon.slot_tx_end, slot_chain_end and hard_fork_genesis_slot_delta")
    })?;
    let genesis = (!meta.genesis_pending)
        .then(|| config.pointer("/genesis/genesis_state_timestamp")?.as_str())
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
