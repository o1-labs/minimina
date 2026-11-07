//! The worker against a fake daemon and a fake clock.

use super::*;
use mina_sdk::{Currency, Payment, SubmittedCommand};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    time::Duration,
};

fn mina(s: &str) -> Currency {
    Currency::from_mina(s).unwrap()
}

fn sender(n: u32) -> Sender {
    Sender {
        name: format!("account-{n}"),
        public_key: format!("B62q{n}"),
        key_path: format!("/net/network-keypairs/account-{n}").into(),
    }
}

fn spec(scenario: Scenario, senders: &[u32]) -> LoadSpec {
    LoadSpec {
        id: "load-1".into(),
        network_id: "net".into(),
        scenario,
        senders: senders.iter().map(|n| sender(*n)).collect(),
        accounts: (1..=3).map(sender).collect(),
        amount: mina("1"),
        fee: mina("0.1"),
        node: "bp-1".into(),
        graphql_uri: "http://localhost:3101/graphql".into(),
        across_fork: false,
        max_failures: 3,
    }
}

fn once(per_round: u32) -> Scenario {
    Scenario {
        per_round,
        ..Scenario::preset(ScenarioKind::Once)
    }
}

fn rounds(per_round: u32, rounds: u64) -> Scenario {
    Scenario {
        per_round,
        rounds: Some(rounds),
        ..Scenario::preset(ScenarioKind::Steady)
    }
}

/// A daemon: answers `chain` from a script (then `genesis`, synced), sends
/// with scripted errors (else accepts and spends the balance).
struct FakeDaemon {
    chain: RefCell<VecDeque<Result<ChainView, DaemonError>>>,
    genesis: RefCell<String>,
    sends: RefCell<VecDeque<Result<(), DaemonError>>>,
    unlock_error: RefCell<Option<DaemonError>>,
    unlocked: Cell<u32>,
    liquid: RefCell<HashMap<String, Currency>>,
    sent: RefCell<Vec<(String, String, String)>>,
    nonce: Cell<u64>,
}

impl FakeDaemon {
    fn new(balance: &str) -> Self {
        FakeDaemon {
            chain: RefCell::default(),
            genesis: RefCell::new("3NKgenesis".into()),
            sends: RefCell::default(),
            unlock_error: RefCell::default(),
            unlocked: Cell::new(0),
            liquid: RefCell::new(
                (1..=3)
                    .map(|n| (format!("B62q{n}"), mina(balance)))
                    .collect(),
            ),
            sent: RefCell::default(),
            nonce: Cell::new(0),
        }
    }

    fn chain_then(&self, view: Result<ChainView, DaemonError>) -> &Self {
        self.chain.borrow_mut().push_back(view);
        self
    }

    fn send_then(&self, result: Result<(), DaemonError>) -> &Self {
        self.sends.borrow_mut().push_back(result);
        self
    }
}

fn view(genesis: &str, synced: bool) -> Result<ChainView, DaemonError> {
    Ok(ChainView {
        genesis: genesis.into(),
        synced,
    })
}

fn down() -> DaemonError {
    DaemonError::Unreachable("connection refused".into())
}

impl Gateway for FakeDaemon {
    fn chain(&self) -> Result<ChainView, DaemonError> {
        self.chain.borrow_mut().pop_front().unwrap_or_else(|| {
            Ok(ChainView {
                genesis: self.genesis.borrow().clone(),
                synced: true,
            })
        })
    }

    fn unlock(&self, _: &Sender) -> Result<(), DaemonError> {
        self.unlocked.set(self.unlocked.get() + 1);
        self.unlock_error.borrow().clone().map_or(Ok(()), Err)
    }

    fn liquid(&self, public_key: &str) -> Result<Currency, DaemonError> {
        Ok(self.liquid.borrow()[public_key])
    }

    fn send(&self, payment: Payment) -> Result<SubmittedCommand, DaemonError> {
        self.sends.borrow_mut().pop_front().unwrap_or(Ok(()))?;
        let spent = payment.amount + payment.fee;
        let mut liquid = self.liquid.borrow_mut();
        let balance = liquid.get_mut(&payment.sender).unwrap();
        *balance = balance.checked_sub(spent).unwrap();
        self.nonce.set(self.nonce.get() + 1);
        let memo = payment.memo.clone().unwrap_or_default();
        self.sent
            .borrow_mut()
            .push((payment.sender.clone(), payment.receiver.clone(), memo));
        Ok(SubmittedCommand {
            id: String::new(),
            hash: format!("5Jtx{}", self.nonce.get()),
            nonce: self.nonce.get(),
            kind: "PAYMENT".into(),
            source: payment.sender,
            receiver: payment.receiver,
            amount: Some(payment.amount),
            fee: Some(payment.fee),
            memo: payment.memo.unwrap_or_default(),
        })
    }
}

/// Time passes only in pauses; a stop is asked once `stop_at` is reached.
#[derive(Default)]
struct FakeClock {
    now: Cell<Duration>,
    stop_at: Option<Duration>,
}

impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        self.now.get()
    }

    fn stop_asked(&self) -> bool {
        self.stop_at.is_some_and(|t| self.now.get() >= t)
    }

    fn pause(&self, d: Duration) -> bool {
        self.now.set(self.now.get() + d);
        !self.stop_asked()
    }
}

#[derive(Default)]
struct Memory {
    payments: Vec<PaymentRecord>,
    states: Vec<LoadState>,
}

impl Journal for Memory {
    fn payment(&mut self, record: &PaymentRecord) -> Result<(), LoadError> {
        self.payments.push(record.clone());
        Ok(())
    }

    fn status(&mut self, status: &LoadStatus) -> Result<(), LoadError> {
        if self.states.last() != Some(&status.state) {
            self.states.push(status.state.clone());
        }
        Ok(())
    }
}

fn run(spec: &LoadSpec, daemon: &FakeDaemon, clock: &FakeClock) -> (LoadStatus, Memory) {
    let mut journal = Memory::default();
    let status = Worker::new(spec, daemon, clock, &mut journal)
        .run()
        .unwrap();
    (status, journal)
}

fn reason(status: &LoadStatus) -> StopReason {
    match &status.state {
        LoadState::Finished(reason) => reason.clone(),
        state => panic!("not finished: {state:?}"),
    }
}

#[test]
fn once_sends_its_round_from_the_senders_in_turn_to_the_next_account() {
    let daemon = FakeDaemon::new("100");
    let (status, journal) = run(&spec(once(3), &[1, 3]), &daemon, &FakeClock::default());
    assert_eq!(reason(&status), StopReason::Done);
    assert_eq!((status.rounds, status.accepted, status.rejected), (1, 3, 0));
    assert_eq!(
        *daemon.sent.borrow(),
        [
            ("B62q1".into(), "B62q2".into(), "load-1 1".into()),
            ("B62q3".into(), "B62q1".into(), "load-1 2".into()),
            ("B62q1".into(), "B62q2".into(), "load-1 3".into()),
        ]
    );
    assert_eq!(status.by_sender["account-1"].accepted, 2);
    assert_eq!(status.by_sender["account-3"].liquid, Some(mina("100")));
    assert_eq!(journal.payments[2].hash.as_deref(), Some("5Jtx3"));
    assert_eq!(journal.payments[2].nonce, Some(3));
    assert_eq!(daemon.unlocked.get(), 2);
    assert_eq!(
        journal.states,
        [
            LoadState::Starting,
            LoadState::Running,
            LoadState::Finished(StopReason::Done)
        ]
    );
}

#[test]
fn after_slot_tx_end_closes_the_window_and_other_errors_fail() {
    let daemon = FakeDaemon::new("100");
    daemon
        .send_then(Ok(()))
        .send_then(Err(DaemonError::TxWindowClosed));
    let (status, journal) = run(&spec(rounds(5, 10), &[1]), &daemon, &FakeClock::default());
    assert_eq!(reason(&status), StopReason::TxWindowClosed);
    assert_eq!((status.accepted, status.rejected), (1, 1));
    assert!(journal.payments[1]
        .error
        .as_deref()
        .unwrap()
        .contains("After_slot_tx_end"));

    // a rejection that is not the stop slot counts; three in a row fail
    let daemon = FakeDaemon::new("100");
    let rejected = || Err(DaemonError::Rejected("Invalid_nonce".into()));
    daemon
        .send_then(rejected())
        .send_then(Ok(()))
        .send_then(rejected())
        .send_then(rejected())
        .send_then(rejected());
    let (status, _) = run(&spec(rounds(2, 10), &[1]), &daemon, &FakeClock::default());
    assert_eq!(
        reason(&status),
        StopReason::Failed {
            error: "Invalid_nonce".into()
        }
    );
    assert_eq!((status.accepted, status.rejected, status.rounds), (1, 4, 3));
}

#[test]
fn a_sender_that_cannot_pay_is_skipped_until_none_can() {
    // 2.5 MINA pays two payments of 1 + 0.1
    let daemon = FakeDaemon::new("2.5");
    daemon.liquid.borrow_mut().insert("B62q2".into(), mina("1"));
    let (status, _) = run(
        &spec(rounds(1, 10), &[1, 2]),
        &daemon,
        &FakeClock::default(),
    );
    assert_eq!(reason(&status), StopReason::FundsDrained);
    assert_eq!(status.accepted, 2);
    assert!(status.by_sender["account-2"].drained);
    assert!(status.by_sender["account-1"].drained);
    assert_eq!(status.by_sender["account-1"].liquid, Some(mina("0.3")));

    // the pool's Insufficient_funds is not a failure
    let daemon = FakeDaemon::new("100");
    let funds = || Err(DaemonError::InsufficientFunds("Insufficient_funds".into()));
    daemon
        .send_then(funds())
        .send_then(funds())
        .send_then(funds())
        .send_then(funds());
    let (status, _) = run(&spec(rounds(3, 4), &[1]), &daemon, &FakeClock::default());
    assert_eq!(reason(&status), StopReason::Done);
    assert_eq!((status.accepted, status.rejected), (0, 4));
}

#[test]
fn across_the_fork_it_waits_for_a_new_genesis_and_unlocks_again() {
    let daemon = FakeDaemon::new("100");
    daemon
        .send_then(Ok(()))
        .send_then(Err(DaemonError::TxWindowClosed));
    // start; then the old chain, the restart, the new chain still syncing
    daemon
        .chain_then(view("3NKgenesis", true))
        .chain_then(view("3NKgenesis", true))
        .chain_then(Err(down()))
        .chain_then(Err(down()))
        .chain_then(Err(down()))
        .chain_then(Err(down()))
        .chain_then(view("3NKforked", false));
    *daemon.genesis.borrow_mut() = "3NKforked".into();
    let spec = LoadSpec {
        across_fork: true,
        ..spec(rounds(1, 3), &[1])
    };
    let clock = FakeClock::default();
    let (status, journal) = run(&spec, &daemon, &clock);
    assert_eq!(reason(&status), StopReason::Done);
    assert_eq!((status.accepted, status.rejected), (2, 1));
    assert_eq!(daemon.unlocked.get(), 2);
    let chains: Vec<_> = journal
        .payments
        .iter()
        .map(|p| p.genesis.as_str())
        .collect();
    assert_eq!(chains, ["3NKgenesis", "3NKgenesis", "3NKforked"]);
    assert_eq!(
        journal.states,
        [
            LoadState::Starting,
            LoadState::Running,
            LoadState::WaitingForFork,
            LoadState::Running,
            LoadState::Finished(StopReason::Done)
        ]
    );
    // a pause between rounds 1 and 2, six polls while it waits
    assert_eq!(clock.now.get(), Duration::from_secs(10) + POLL * 6);
}

#[test]
fn a_daemon_that_never_answers_fails_the_start_and_a_stop_stops() {
    let daemon = FakeDaemon::new("100");
    // not synced is waited for; no answer counts
    daemon
        .chain_then(view("3NKgenesis", false))
        .chain_then(Err(down()))
        .chain_then(Err(down()))
        .chain_then(Err(down()));
    let (status, _) = run(&spec(once(1), &[1]), &daemon, &FakeClock::default());
    assert_eq!(
        reason(&status),
        StopReason::Failed {
            error: "connection refused".into()
        }
    );
    assert_eq!(status.last_error.as_deref(), Some("connection refused"));

    let daemon = FakeDaemon::new("100");
    *daemon.unlock_error.borrow_mut() = Some(DaemonError::Rejected("bad password".into()));
    let (status, _) = run(&spec(once(1), &[1]), &daemon, &FakeClock::default());
    assert_eq!(
        reason(&status),
        StopReason::Failed {
            error: "importing and unlocking account-1: bad password".into()
        }
    );

    let daemon = FakeDaemon::new("100");
    let clock = FakeClock {
        stop_at: Some(Duration::from_secs(25)),
        ..Default::default()
    };
    let (status, _) = run(
        &spec(Scenario::preset(ScenarioKind::Steady), &[1]),
        &daemon,
        &clock,
    );
    assert_eq!(reason(&status), StopReason::Stopped);
    assert_eq!(status.accepted, 3);
}
