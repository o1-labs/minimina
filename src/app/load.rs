//! `network load ...`: see [`crate::load`].

use super::Context;
use crate::{
    cli::{LoadCommand, LoadIdArgs, LoadStartArgs},
    load::{
        self, DaemonGateway, FileJournal, LoadError, LoadList, LoadProcess, LoadSpec, LoadStatus,
        LoadStore, LoadSummary, Scenario, SystemClock, Worker, STOP_TIMEOUT,
    },
};
use anyhow::{Context as _, Result};
use std::{
    fs::OpenOptions,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{atomic::AtomicBool, Arc},
};

pub fn run(ctx: &Context, cmd: LoadCommand) -> Result<()> {
    match cmd {
        LoadCommand::Start(args) => println!("{}", start(ctx, &args)?),
        LoadCommand::List(args) => {
            let network_id = args.network_id;
            let loads = store(ctx, &network_id)?.summaries(&network_id)?;
            println!("{}", LoadList { network_id, loads });
        }
        LoadCommand::Status(args) => {
            let network_id = &args.network_id.network_id;
            println!("{}", store(ctx, network_id)?.summary(network_id, &args.id)?);
        }
        LoadCommand::Stop(args) => {
            let network_id = args.network_id.network_id;
            let store = store(ctx, &network_id)?;
            match args.id {
                Some(id) => println!("{}", store.stop(&network_id, &id, STOP_TIMEOUT)?),
                None => {
                    let loads = store.stop_all(&network_id, STOP_TIMEOUT)?;
                    println!("{}", LoadList { network_id, loads });
                }
            }
        }
        LoadCommand::Run(args) => println!("{}", work(ctx, &args)?),
    }
    Ok(())
}

fn store(ctx: &Context, network_id: &str) -> Result<LoadStore> {
    ctx.ensure_network_exists(network_id)?;
    Ok(LoadStore::new(&ctx.dirs.network_path(network_id)))
}

/// Writes the load and starts `minimina network load run` for it, detached
/// from this shell (its own process group, output to `load.log`).
fn start(ctx: &Context, args: &LoadStartArgs) -> Result<LoadSummary> {
    let network_id = &args.network_id.network_id;
    let store = store(ctx, network_id)?;
    let network_path = ctx.dirs.network_path(network_id);
    let services = ctx.dirs.get_services_info(network_id)?;
    let node = load::pick_node(&services, args.node.as_deref(), network_id)?;
    let graphql_uri = node
        .to_node_info()
        .graphql_uri
        .ok_or_else(|| LoadError::NoGraphql(node.service_name.clone()))?;
    let accounts = load::test_accounts(&network_path, ctx.mode, network_id)?;
    let senders = load::pick_senders(&accounts, &args.senders, network_id)?;
    store.ensure_free(network_id, &senders)?;
    let scenario = Scenario::new(
        args.scenario,
        args.count,
        args.interval,
        args.rounds,
        args.duration,
    )?;
    if args.max_failures == 0 {
        return Err(LoadError::Zero("--max-failures").into());
    }

    let id = store.create()?;
    let spec = LoadSpec {
        id: id.clone(),
        network_id: network_id.clone(),
        scenario,
        senders,
        accounts,
        amount: args.amount,
        fee: args.fee,
        node: node.service_name.clone(),
        graphql_uri,
        across_fork: args.across_fork,
        max_failures: args.max_failures,
    };
    store.save_spec(&spec)?;
    let names = spec
        .senders
        .iter()
        .map(|s| (s.name.clone(), s.public_key.clone()));
    store.save_status(&id, &LoadStatus::new(names))?;

    let log_path = store.log_path(&id);
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let exe = std::env::current_exe().map_err(LoadError::Spawn)?;
    let child = Command::new(exe)
        .args(["network", "load", "run", "--network-id", network_id, &id])
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(LoadError::Spawn)?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .map_err(LoadError::Spawn)?;
    store.save_process(&id, &LoadProcess::of(child.id()))?;
    Ok(store.summary(network_id, &id)?)
}

/// The worker of a load, until it stops; SIGTERM (and SIGINT) stop it after
/// its current payment.
fn work(ctx: &Context, args: &LoadIdArgs) -> Result<LoadSummary> {
    let network_id = &args.network_id.network_id;
    let store = store(ctx, network_id)?;
    // also when run by hand, not through `load start`
    store.save_process(&args.id, &LoadProcess::of(std::process::id()))?;
    let spec = store.spec(&args.id)?;
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, stop.clone()).map_err(LoadError::Signal)?;
    }
    let gateway = DaemonGateway::new(&spec.graphql_uri)?;
    let clock = SystemClock::new(stop);
    let mut journal = FileJournal {
        store: &store,
        id: &args.id,
    };
    Worker::new(&spec, &gateway, &clock, &mut journal).run()?;
    Ok(store.summary(network_id, &args.id)?)
}
