//! `network check fork`: see [`crate::check::fork`].

use super::{check::fork_ledger_accounts, hardfork::Prepared, Context};
use crate::{
    check::fork::{
        self, ExpectedFork, ForkAccount, ForkCheckError, ForkReport, GenesisView, PaymentChecks,
        PaymentEvidence,
    },
    hardfork::fork_config::LedgerHashes,
    load::{LoadStore, PaymentRecord},
    network_meta::{HardforkState, NetworkMeta},
    node_client,
    service::{ServiceConfig, ServiceType},
};
use anyhow::{Context as _, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

/// The ledger hashes `hardfork prepare` writes.
const LEDGER_HASHES: &str = "hardfork/ledger_hashes.json";

pub fn run(ctx: &Context, network_id: &str) -> Result<ForkReport> {
    let network_path = ctx.dirs.network_path(network_id);
    let hardfork = NetworkMeta::load(&network_path)?
        .and_then(|m| m.hardfork)
        .filter(|h| h.state == HardforkState::Applied)
        .ok_or_else(|| ForkCheckError::NotApplied(network_id.to_string()))?;
    let expected = expected_fork(&network_path)?;
    let services = ctx.dirs.get_services_info(network_id)?;
    let daemons: Vec<&ServiceConfig> = services.iter().filter(|s| s.is_chain_daemon()).collect();
    let views: BTreeMap<String, Result<GenesisView, String>> = daemons
        .iter()
        .map(|d| (d.service_name.clone(), genesis_view(d)))
        .collect();
    let tip = daemons
        .iter()
        .find_map(|d| node_client::tip(d).ok())
        .map(|b| b.height);
    let chain = fork::chain_checks(&expected, &views, tip);
    let postfork_genesis = views
        .values()
        .find_map(|v| v.as_ref().ok())
        .map(|v| v.state_hash.clone());
    let fork_accounts = fork_accounts(&network_path)?;

    let mut notes = Vec::new();
    if !services
        .iter()
        .any(|s| s.service_type == ServiceType::ArchiveNode)
    {
        notes.push("no archive node: the ledger, archive and payment checks need one".into());
        return Ok(ForkReport::new(
            network_id,
            chain,
            vec![],
            vec![],
            vec![],
            notes,
        ));
    }
    let mut db = ctx
        .archive_db
        .connect(&ctx.native(network_id)?.archive_db_uri())?;
    let migration = db.last_migration()?;
    let blocks = db.chain_from_tip(expected.fork.global_slot_since_genesis)?;
    let mut archive = fork::archive_checks(&expected, migration.as_ref(), &blocks);
    archive.push(fork::pending_check(
        &db.pending_before(expected.fork.global_slot_since_genesis)?,
    ));
    let Some(genesis) = postfork_genesis else {
        notes.push(
            "no daemon answered: the ledger and payment checks need the postfork genesis".into(),
        );
        return Ok(ForkReport::new(
            network_id,
            chain,
            vec![],
            archive,
            vec![],
            notes,
        ));
    };
    // with --hardfork-handover the archive writes the fork ledger to
    // genesis_accounts, at the postfork genesis height
    let ledger = match &fork_accounts {
        None => {
            notes.push(
                "the fork config names the ledgers by hash only (auto mode: the daemons wrote \
                 it), and prepare made no legacy reference (see prepared.json): no fork ledger \
                 accounts to compare with the archive or the nonces"
                    .into(),
            );
            vec![]
        }
        Some(fork_accounts) if hardfork.archive_handover => {
            let height = expected.fork.blockchain_length + 1;
            vec![fork::ledger_check(
                fork_accounts,
                &db.genesis_ledger_accounts(height, fork::MINA_TOKEN)?,
                "genesis_accounts",
            )]
        }
        Some(fork_accounts) => vec![fork::ledger_check(
            fork_accounts,
            &db.genesis_accounts(&genesis, fork::MINA_TOKEN)?,
            "accounts_accessed",
        )],
    };

    let payments = accepted_payments(&network_path)?;
    let hashes: Vec<String> = payments.iter().filter_map(|p| p.hash.clone()).collect();
    let commands = db.commands(&hashes)?;
    let fork_nonces: Option<BTreeMap<String, u64>> = fork_accounts.as_ref().map(|accounts| {
        accounts
            .iter()
            .map(|a| (a.public_key.clone(), a.nonce))
            .collect()
    });
    let postfork_senders: BTreeSet<&str> = payments
        .iter()
        .filter(|p| p.genesis == genesis)
        .map(|p| p.sender.as_str())
        .collect();
    let mut daemon_nonces = BTreeMap::new();
    if let Some(daemon) = daemons.first() {
        for sender in postfork_senders {
            let account = node_client::account(daemon, sender)?;
            daemon_nonces.insert(sender.to_string(), account.nonce);
        }
    }
    let PaymentChecks {
        checks,
        notes: payment_notes,
    } = fork::payment_checks(&PaymentEvidence {
        payments: &payments,
        postfork_genesis: &genesis,
        fork_height: i64::from(expected.fork.blockchain_length),
        chain: &blocks,
        commands: &commands,
        fork_nonces: fork_nonces.as_ref(),
        daemon_nonces: &daemon_nonces,
    });
    notes.extend(payment_notes);
    Ok(ForkReport::new(
        network_id, chain, ledger, archive, checks, notes,
    ))
}

fn expected_fork(network_path: &Path) -> Result<ExpectedFork> {
    let prepared = Prepared::load(network_path)?;
    let path = network_path.join(LEDGER_HASHES);
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let hashes: LedgerHashes =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(ExpectedFork {
        fork: prepared.fork,
        ledger_hash: hashes.ledger.hash,
        staking_ledger_hash: hashes.epoch_data.staking.hash,
    })
}

fn genesis_view(daemon: &ServiceConfig) -> Result<GenesisView, String> {
    node_client::genesis_block(daemon)
        .map(GenesisView::from)
        .map_err(|e| e.to_string())
}

/// The MINA accounts of the fork ledger, if the fork config has them
/// ([`fork_ledger_accounts`]).
fn fork_accounts(network_path: &Path) -> Result<Option<Vec<mina_sdk::AccountData>>> {
    let Some(ledger) = fork_ledger_accounts(network_path)? else {
        return Ok(None);
    };
    let mut accounts = Vec::new();
    for account in ledger {
        accounts.extend(mina_sdk::AccountData::of_ledger(&account)?);
    }
    Ok(Some(accounts))
}

/// The payments the daemons took, of every load of the network.
fn accepted_payments(network_path: &Path) -> Result<Vec<PaymentRecord>> {
    let store = LoadStore::new(network_path);
    let mut payments = Vec::new();
    for id in store.ids()? {
        payments.extend(
            store
                .payments(&id)?
                .into_iter()
                .filter(|p| p.hash.is_some()),
        );
    }
    Ok(payments)
}
