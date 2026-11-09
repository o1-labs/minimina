//! `network check vesting` and `network check rosetta`: see [`crate::check`].

use super::{hardfork, Context};
use crate::{
    check::{
        rosetta::{self, CheckDataRun, RosettaClient, RosettaError, RosettaReport},
        vesting::{
            self, DaemonView, ForkSchedule, RosettaView, TimedAccount, VestingError, VestingReport,
            VestingSchedule,
        },
    },
    genesis_ledger::{self, GENESIS_LEDGER_JSON, PREFORK_GENESIS_LEDGER_JSON},
    install::{apt, mina, rosetta_cli},
    network_meta::NetworkMeta,
    node_client,
    service::{ServiceConfig, ServiceType},
    spec::ledger::LedgerAccount,
    utils,
};
use anyhow::{Context as _, Result};
use log::info;
use mina_rosetta_sdk::AccountBalanceResponse;
use mina_sdk::Currency;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

/// The fork config `hardfork prepare` writes.
pub(super) const FORK_CONFIG: &str = "hardfork/fork_config.json";
/// Where `network check rosetta` keeps the rosetta-cli config, data and results.
const ROSETTA_CLI_DIR: &str = "rosetta-cli";

pub fn vesting(ctx: &Context, network_id: &str) -> Result<VestingReport> {
    let network_path = ctx.dirs.network_path(network_id);
    let timed = TimedAccount::of_ledger(&prefork_accounts(&network_path)?)?;
    if timed.is_empty() {
        return Err(VestingError::NoTimedAccounts(network_id.to_string()).into());
    }
    let fork = fork_schedules(&network_path)?;
    let services = ctx.dirs.get_services_info(network_id)?;
    let daemon = rosetta_daemon(&services)
        .or_else(|| services.iter().find(|s| s.is_chain_daemon()))
        .with_context(|| format!("network '{network_id}' has no daemon"))?;
    let rosetta = match rosetta_service(&services) {
        Some(service) => Some(RosettaClient::connect(rosetta_port(service)?)?),
        None => None,
    };
    let slot = node_client::tip(daemon)?.global_slot_since_genesis;
    let mut accounts = Vec::new();
    for account in &timed {
        let data = node_client::account(daemon, &account.public_key)?;
        let view = DaemonView {
            slot,
            schedule: data.timing.as_ref().and_then(VestingSchedule::from_daemon),
            total: data.balance.total,
            locked: data.balance.locked,
        };
        let rosetta_view = match &rosetta {
            Some(client) => Some(rosetta_view(client.balance(&account.public_key)?, daemon)?),
            None => None,
        };
        let fork_schedule = fork.as_ref().map(|f| {
            f.get(&account.public_key)
                .copied()
                .unwrap_or(ForkSchedule::Absent)
        });
        accounts.push(vesting::check_account(
            account,
            fork_schedule.as_ref(),
            &view,
            rosetta_view.as_ref(),
        ));
    }
    Ok(VestingReport::new(
        network_id,
        &daemon.service_name,
        accounts,
    ))
}

pub fn rosetta(
    ctx: &Context,
    network_id: &str,
    rosetta_cli: Option<&Path>,
    start_index: Option<u64>,
    wait: bool,
) -> Result<RosettaReport> {
    let network_path = ctx.dirs.network_path(network_id);
    let services = ctx.dirs.get_services_info(network_id)?;
    let service = rosetta_service(&services)
        .ok_or_else(|| RosettaError::NoRosetta(network_id.to_string()))?;
    let daemon = rosetta_daemon(&services)
        .with_context(|| format!("rosetta of network '{network_id}' reads no daemon"))?;
    let client = RosettaClient::connect(rosetta_port(service)?)?;
    let applied = hardfork::is_applied(ctx, network_id)?;
    if applied {
        wait_for_postfork_tip(ctx, network_id, &client, daemon, wait)?;
    }
    let meta = NetworkMeta::load(&network_path)?
        .with_context(|| format!("network '{network_id}' has no minimina.json"))?;
    let bin_path = meta
        .bin_path
        .with_context(|| format!("network '{network_id}' has no bin_path"))?;
    let template = utils::package_root(&bin_path)
        .map(|root| root.join(rosetta::TEMPLATE))
        .with_context(|| {
            format!(
                "{} is not in a package (<root>/usr/local/bin), so its rosetta-cli config is not \
                 found",
                bin_path.display()
            )
        })?;
    // rosetta's genesis is the postfork one, and rosetta-cli refuses the
    // prefork genesis: block 2 is the first that crosses the fork
    let start_index = start_index.or(applied.then_some(2));
    let dir = network_path.join(ROSETTA_CLI_DIR);
    let program = rosetta_cli::resolve(
        &ctx.dirs.tools_root(),
        rosetta_cli,
        Path::new(apt::OS_RELEASE),
        &mina::Http,
        ctx.runner.as_ref(),
    )?;
    info!(
        "rosetta-cli check:data on {} with {}, from block {}",
        client.url(),
        program.display(),
        start_index.map_or("genesis".to_string(), |i| i.to_string())
    );
    let result = CheckDataRun {
        program,
        template,
        dir: dir.clone(),
        online_url: client.url().to_string(),
        network: client.network().clone(),
        start_index,
    }
    .run(ctx.runner.as_ref())?;
    Ok(RosettaReport::new(network_id, result, start_index, dir))
}

/// After a hardfork: until the postfork chain is taller than the orphaned
/// prefork tip, rosetta answers with orphaned blocks. Fails then, or with
/// `wait`, waits a slot at a time.
fn wait_for_postfork_tip(
    ctx: &Context,
    network_id: &str,
    client: &RosettaClient,
    daemon: &ServiceConfig,
    wait: bool,
) -> Result<()> {
    let slot = Duration::from_millis(
        hardfork::status(ctx, network_id, chrono::Utc::now())?.slot_duration_ms,
    );
    loop {
        let status = client.status()?;
        let tip = node_client::tip(daemon)?.height;
        match rosetta::orphaned_tip(&status, tip) {
            None => return Ok(()),
            Some(e) if !wait => return Err(e.into()),
            Some(_) => {
                info!(
                    "Waiting for the best tip ({tip}) to pass rosetta's orphaned prefork tip ({})",
                    status.current_block_identifier.index
                );
                std::thread::sleep(slot);
            }
        }
    }
}

/// The prefork genesis ledger: the one `hardfork apply` kept, else the current one.
fn prefork_accounts(network_path: &Path) -> Result<Vec<LedgerAccount>> {
    let prefork = network_path.join(PREFORK_GENESIS_LEDGER_JSON);
    let path = match prefork.exists() {
        true => prefork,
        false => network_path.join(GENESIS_LEDGER_JSON),
    };
    ledger_accounts(&path)
}

pub(super) fn ledger_accounts(path: &Path) -> Result<Vec<LedgerAccount>> {
    let config =
        genesis_ledger::read_file(path).with_context(|| format!("reading {}", path.display()))?;
    let accounts = config
        .pointer("/ledger/accounts")
        .cloned()
        .unwrap_or_default();
    serde_json::from_value(accounts).with_context(|| format!("the accounts of {}", path.display()))
}

/// The schedule of each account of the fork ledger; none before `hardfork prepare`.
fn fork_schedules(network_path: &Path) -> Result<Option<BTreeMap<String, ForkSchedule>>> {
    let path: PathBuf = network_path.join(FORK_CONFIG);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(
        ledger_accounts(&path)?
            .iter()
            .map(|a| {
                let schedule = match &a.timing {
                    None => ForkSchedule::Untimed,
                    Some(t) => VestingSchedule::from_timing(t)
                        .map_or(ForkSchedule::Invalid, ForkSchedule::Timed),
                };
                (a.pk.to_string(), schedule)
            })
            .collect(),
    ))
}

fn rosetta_view(balance: AccountBalanceResponse, daemon: &ServiceConfig) -> Result<RosettaView> {
    let meta = balance
        .balance()
        .and_then(|b| b.metadata.clone())
        .with_context(|| {
            format!(
                "rosetta gives no balance metadata at block {}",
                balance.block_identifier.index
            )
        })?;
    let block = balance.block_identifier;
    // the daemon knows the blocks of its frontier, where rosetta's tip is
    let slot = node_client::block(daemon, &block.hash)
        .ok()
        .map(|b| b.global_slot_since_genesis);
    Ok(RosettaView {
        block_index: block.index,
        block_hash: block.hash,
        slot,
        total: Currency::from_nanomina(meta.total_balance),
        locked: Currency::from_nanomina(meta.locked_balance),
        liquid: Currency::from_nanomina(meta.liquid_balance),
    })
}

fn rosetta_service(services: &[ServiceConfig]) -> Option<&ServiceConfig> {
    services
        .iter()
        .find(|s| s.service_type == ServiceType::Rosetta)
}

/// The daemon whose GraphQL API rosetta reads.
fn rosetta_daemon(services: &[ServiceConfig]) -> Option<&ServiceConfig> {
    let name = rosetta_service(services)?.rosetta_graphql_node.as_ref()?;
    services.iter().find(|s| &s.service_name == name)
}

fn rosetta_port(service: &ServiceConfig) -> Result<u16> {
    service
        .client_port
        .with_context(|| format!("'{}' has no port", service.service_name))
}
