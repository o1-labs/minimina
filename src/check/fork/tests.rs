use super::*;
use crate::{hardfork::fork_config::ForkPoint, load::PaymentRecord, spec::ledger::LedgerAccount};
use mina_sdk::{AccountData, Currency};
use std::collections::BTreeMap;

const FORK: &str = "3NLfork";
const GENESIS: &str = "3NLgenesis";
const PREFORK: &str = "3NKprefork";
const PK1: &str = "B62qnnD55rhDnmWZr2PjxPeQzD8rXSfByEg6rmxEg5X76prKA368NZs";
const PK2: &str = "B62qk1qA5VDrCjSYQUb9qJ2UnZ2vUUJk9iB8MSzeYi9jBhWaswmQMyC";

fn expected() -> ExpectedFork {
    ExpectedFork {
        fork: ForkPoint {
            state_hash: FORK.into(),
            blockchain_length: 3,
            global_slot_since_genesis: 64,
        },
        ledger_hash: "jwLedger".into(),
        staking_ledger_hash: "jwStaking".into(),
    }
}

fn view() -> GenesisView {
    GenesisView {
        state_hash: GENESIS.into(),
        previous_state_hash: FORK.into(),
        height: 4,
        slot: 64,
        ledger_hash: "jwLedger".into(),
        staking_ledger_hash: "jwStaking".into(),
    }
}

fn failed(checks: &[crate::check::Check]) -> Vec<&str> {
    checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.name.as_str())
        .collect()
}

#[test]
fn the_genesis_view_is_taken_from_the_daemons_genesis_block() {
    let epoch = |ledger_hash: &str| mina_sdk::EpochData {
        length: None,
        seed: "seed".into(),
        ledger_hash: ledger_hash.into(),
    };
    let block = mina_sdk::BlockInfo {
        state_hash: GENESIS.into(),
        height: 4,
        global_slot_since_hard_fork: 0,
        global_slot_since_genesis: 64,
        creator_pk: PK1.into(),
        command_transaction_count: 0,
        previous_state_hash: FORK.into(),
        epoch: 0,
        block_creator: PK1.into(),
        coinbase_receiver: None,
        staking_epoch: epoch("jwStaking"),
        next_epoch: epoch("jwNext"),
        date: String::new(),
        utc_date: String::new(),
        snarked_ledger_hash: "jwLedger".into(),
        staged_ledger_hash: "jwStaged".into(),
        coinbase: Currency::from_nanomina(0),
        coinbase_receiver_account: None,
        fee_transfers: vec![],
        user_commands: vec![],
        zkapp_commands: vec![],
        snark_jobs: vec![],
    };
    assert_eq!(GenesisView::from(block), view());
}

#[test]
fn the_postfork_genesis_is_held_against_prepare() {
    let daemons = |views: Vec<(&str, Result<GenesisView, String>)>| -> BTreeMap<_, _> {
        views.into_iter().map(|(n, v)| (n.to_string(), v)).collect()
    };
    let good = daemons(vec![("bp-1", Ok(view())), ("seed-1", Ok(view()))]);
    let checks = chain_checks(&expected(), &good, Some(9));
    assert_eq!(checks.len(), 5);
    assert!(failed(&checks).is_empty(), "{checks:?}");

    let other = GenesisView {
        state_hash: "3NLother".into(),
        previous_state_hash: "3NLorphan".into(),
        height: 5,
        ..view()
    };
    let bad = daemons(vec![
        ("bp-1", Ok(other.clone())),
        ("bp-2", Ok(view())),
        ("seed-1", Err("connection refused".into())),
    ]);
    let checks = chain_checks(&expected(), &bad, Some(5));
    assert_eq!(
        failed(&checks),
        [
            "every daemon runs the same postfork genesis",
            "the postfork genesis follows the fork block",
            "the postfork chain grows"
        ]
    );
    assert_eq!(
        checks[0].detail,
        "3NLgenesis: bp-2; 3NLother: bp-1; seed-1: connection refused"
    );
    let wrong_ledger = daemons(vec![(
        "bp-1",
        Ok(GenesisView {
            staking_ledger_hash: "jwOld".into(),
            slot: 63,
            ..view()
        }),
    )]);
    assert_eq!(
        failed(&chain_checks(&expected(), &wrong_ledger, None)),
        [
            "the postfork genesis is at the fork slot",
            "the postfork genesis ledger is the one prepare made",
            "the postfork chain grows"
        ]
    );
}

fn ledger_account(pk: &str, balance: &str, nonce: Option<&str>) -> LedgerAccount {
    let mut account = LedgerAccount::new(pk.parse().unwrap(), balance.parse().unwrap());
    if let Some(n) = nonce {
        account.other.insert("nonce".into(), n.into());
    }
    account
}

#[test]
fn fork_ledger_accounts_are_read_with_their_nonce_and_mina_only() {
    let a = AccountData::of_ledger(&ledger_account(PK1, "984.6", Some("64")))
        .unwrap()
        .unwrap();
    assert_eq!(a.balance.total, Currency::from_mina("984.6").unwrap());
    assert_eq!(a.nonce, 64);
    let untouched = AccountData::of_ledger(&ledger_account(PK2, "1000", None))
        .unwrap()
        .unwrap();
    assert_eq!(untouched.nonce, 0);
    let mut token = ledger_account(PK2, "1", None);
    token.other.insert("token".into(), "xOtherToken".into());
    assert!(AccountData::of_ledger(&token).unwrap().is_none());
    let bad = ledger_account(PK1, "1", Some("many"));
    assert_eq!(
        AccountData::of_ledger(&bad).unwrap_err().to_string(),
        format!("account {PK1} of the fork ledger has nonce many")
    );
}

fn state(pk: &str, mina: &str, nonce: u64) -> AccountData {
    AccountData::with_balance(pk.into(), Currency::from_mina(mina).unwrap(), nonce)
}

#[test]
fn the_archive_genesis_accounts_must_be_the_fork_ledger() {
    let fork = [state(PK1, "984.6", 64), state(PK2, "1003.5", 55)];
    let check = ledger_check(&fork, &fork);
    assert!(check.passed);
    assert_eq!(check.detail, "2 accounts");

    let archive = [state(PK1, "984.5", 63), state("B62qextra", "1", 0)];
    let check = ledger_check(&fork, &archive);
    assert!(!check.passed);
    assert_eq!(
        check.detail,
        format!(
            "{PK1}: balance 984.500000000 in the archive, 984.600000000 in the fork ledger, \
             nonce 63 in the archive, 64 in the fork ledger; {PK2}: not in the archive; \
             B62qextra: not in the fork ledger"
        )
    );
}

fn block(id: i32, height: i64, hash: &str, status: &str, slot: i64, since_fork: i64) -> ChainBlock {
    ChainBlock {
        id,
        parent_id: (id > 1).then_some(id - 1),
        height,
        state_hash: hash.into(),
        parent_hash: String::new(),
        chain_status: status.into(),
        slot_since_genesis: slot,
        slot_since_hard_fork: since_fork,
    }
}

/// Heights 5 down to 1: two postfork blocks, the fork block at 3.
fn chain() -> Vec<ChainBlock> {
    vec![
        block(5, 5, "3NLtip", "pending", 66, 2),
        block(4, 4, GENESIS, "canonical", 64, 0),
        block(3, 3, FORK, "canonical", 30, 30),
        block(2, 2, "3NL2", "canonical", 20, 20),
        block(1, 1, PREFORK, "canonical", 0, 0),
    ]
}

fn applied() -> ArchiveMigration {
    ArchiveMigration {
        protocol_version: "5.0.0".into(),
        migration_version: "0.0.3".into(),
        status: "applied".into(),
    }
}

#[test]
fn the_archive_has_one_migrated_chain_across_the_fork() {
    let checks = archive_checks(&expected(), Some(&applied()), &chain());
    assert!(failed(&checks).is_empty(), "{checks:?}");
    assert_eq!(checks[1].detail, "5 blocks, height 5 down to 1");

    // no migration, a missing block 2, the fork block orphaned
    let mut broken = chain();
    broken[2].chain_status = "orphaned".into();
    broken.remove(3);
    let checks = archive_checks(&expected(), None, &broken);
    assert_eq!(
        failed(&checks),
        [
            "the archive schema is migrated",
            "one chain from the archive's highest block down to the first",
            "the chain is canonical up to the postfork genesis"
        ]
    );
    assert_eq!(checks[1].detail, "gaps: 3NLfork at 3 after 3NKprefork at 1");

    // another block at the fork height
    let mut other = chain();
    other[2].state_hash = "3NLsibling".into();
    assert_eq!(
        failed(&archive_checks(&expected(), Some(&applied()), &other)),
        ["the chain goes through the fork block to the postfork genesis"]
    );
    assert_eq!(
        failed(&archive_checks(&expected(), Some(&applied()), &[])),
        [
            "one chain from the archive's highest block down to the first",
            "the chain goes through the fork block to the postfork genesis",
            "the chain is canonical up to the postfork genesis"
        ]
    );
}

fn payment(genesis: &str, sender: &str, hash: &str, nonce: u64) -> PaymentRecord {
    PaymentRecord {
        at: String::new(),
        round: 1,
        genesis: genesis.into(),
        sender: sender.into(),
        receiver: PK2.into(),
        amount: Currency::from_mina("1").unwrap(),
        fee: Currency::from_mina("0.1").unwrap(),
        memo: String::new(),
        hash: Some(hash.into()),
        nonce: Some(nonce),
        error: None,
    }
}

fn command(hash: &str, block: &str, height: i64, status: &str) -> IncludedCommand {
    IncludedCommand {
        hash: hash.into(),
        nonce: 0,
        fee_payer: PK1.into(),
        block_state_hash: block.into(),
        height,
        status: status.into(),
    }
}

#[test]
fn payments_land_on_the_right_side_of_the_fork() {
    let payments = [
        payment(PREFORK, PK1, "5Ja", 0),
        payment(PREFORK, PK1, "5Jb", 1),
        // in the pool at slot_tx_end: dropped
        payment(PREFORK, PK1, "5Jc", 2),
        payment(GENESIS, PK1, "5Jd", 2),
        payment(GENESIS, PK1, "5Je", 3),
    ];
    let commands = [
        command("5Ja", "3NL2", 2, "applied"),
        // also in an orphaned block, off the chain
        command("5Jb", "3NLorphan", 3, "applied"),
        command("5Jb", FORK, 3, "applied"),
        command("5Jd", "3NLtip", 5, "applied"),
    ];
    let fork_nonces = BTreeMap::from([(PK1.to_string(), 2)]);
    let daemon_nonces = BTreeMap::from([(PK1.to_string(), 3)]);
    let chain = chain();
    let evidence = PaymentEvidence {
        payments: &payments,
        postfork_genesis: GENESIS,
        fork_height: 3,
        chain: &chain,
        commands: &commands,
        fork_nonces: &fork_nonces,
        daemon_nonces: &daemon_nonces,
    };
    let out = payment_checks(&evidence);
    assert!(out.notes.is_empty());
    assert!(failed(&out.checks).is_empty(), "{:?}", out.checks);
    let details: Vec<&str> = out.checks.iter().map(|c| c.detail.as_str()).collect();
    assert_eq!(
        details,
        [
            "2 of 3 in blocks, 1 dropped (in the pool at slot_tx_end)",
            &format!("{PK1}: 2 in the fork ledger, 2 after its last payment"),
            "1 of 2 in blocks, 1 pending"
        ]
    );

    // a prefork payment replayed after the fork, a failed one, the fork
    // nonce off, a postfork payment whose nonce went to another command
    let commands = [
        command("5Ja", "3NL2", 2, "failed"),
        command("5Jc", "3NLtip", 5, "applied"),
    ];
    let fork_nonces = BTreeMap::from([(PK1.to_string(), 3)]);
    let daemon_nonces = BTreeMap::from([(PK1.to_string(), 4)]);
    let out = payment_checks(&PaymentEvidence {
        commands: &commands,
        fork_nonces: &fork_nonces,
        daemon_nonces: &daemon_nonces,
        ..evidence
    });
    assert_eq!(out.checks.len(), 3);
    assert!(out.checks.iter().all(|c| !c.passed), "{:?}", out.checks);
    assert_eq!(
        out.checks[0].detail,
        "5Ja failed at height 2; 5Jc at height 5, after the fork block"
    );
    assert_eq!(
        out.checks[2].detail,
        "5Jd (nonce 2) is in no block, and the sender's nonce is 4; \
         5Je (nonce 3) is in no block, and the sender's nonce is 4"
    );
}

#[test]
fn without_payments_the_report_says_what_to_run() {
    let chain = chain();
    let none = BTreeMap::new();
    let evidence = PaymentEvidence {
        payments: &[],
        postfork_genesis: GENESIS,
        fork_height: 3,
        chain: &chain,
        commands: &[],
        fork_nonces: &none,
        daemon_nonces: &none,
    };
    let out = payment_checks(&evidence);
    assert!(out.checks.is_empty());
    assert!(out.notes[0].starts_with("no load sent payments"));
    let prefork_only = [payment(PREFORK, PK1, "5Ja", 0)];
    let out = payment_checks(&PaymentEvidence {
        payments: &prefork_only,
        ..evidence
    });
    // dropped is fine; with none in a block there is no nonce to check
    assert_eq!(out.checks.len(), 1);
    assert!(out.checks[0].passed);
    assert!(out.notes[0].starts_with("no payment sent before the fork is in a block"));
    assert!(out.notes[1].starts_with("no payments after the fork"));
    let report = ForkReport::new("n", vec![], vec![], vec![], out.checks, out.notes);
    assert!(report.passed);
}

#[test]
fn a_timed_fork_account_must_keep_its_schedule_in_the_archive() {
    let schedule = crate::check::vesting::VestingSchedule {
        initial_minimum_balance: Currency::from_mina("100").unwrap(),
        cliff_time: 10,
        cliff_amount: Currency::from_mina("10").unwrap(),
        vesting_period: 5,
        vesting_increment: Currency::from_mina("1").unwrap(),
    };
    let timed = AccountData {
        timing: Some(schedule.into()),
        ..state(PK1, "1000", 0)
    };
    assert_eq!(timed.schedule(), Some(schedule));
    assert!(timed.differences(&timed.clone()).is_empty());
    let untimed = state(PK1, "1000", 0);
    assert_eq!(
        timed.differences(&untimed),
        [format!(
            "timing untimed in the archive, {schedule} in the fork ledger"
        )]
    );
}
