use super::{
    Clock, DaemonError, Gateway, Journal, LoadError, LoadSpec, LoadState, LoadStatus,
    PaymentRecord, Sender, StopReason,
};
use log::{info, warn};
use mina_sdk::{Payment, SubmittedCommand};
use std::time::Duration;

/// How often the worker asks a daemon that is not synced yet, or not
/// forked yet.
pub const POLL: Duration = Duration::from_secs(10);

/// Runs a load: waits for a synced daemon, unlocks the senders, then sends
/// rounds of payments until the scenario is done or a [`StopReason`].
pub struct Worker<'a, G: Gateway, C: Clock, J: Journal> {
    spec: &'a LoadSpec,
    gateway: &'a G,
    clock: &'a C,
    journal: &'a mut J,
    status: LoadStatus,
    /// Failed daemon calls since the last accepted payment.
    failures: u32,
    /// Payments sent so far, for the memo.
    sent: u64,
    /// The next sender, in turn.
    cursor: usize,
    /// Genesis of the chain the daemon runs.
    genesis: String,
}

/// How a round ended.
enum Round {
    Sent,
    WindowClosed,
    Stop(StopReason),
}

impl<'a, G: Gateway, C: Clock, J: Journal> Worker<'a, G, C, J> {
    pub fn new(spec: &'a LoadSpec, gateway: &'a G, clock: &'a C, journal: &'a mut J) -> Self {
        let senders = spec
            .senders
            .iter()
            .map(|s| (s.name.clone(), s.public_key.clone()));
        Worker {
            spec,
            gateway,
            clock,
            journal,
            status: LoadStatus::new(senders),
            failures: 0,
            sent: 0,
            cursor: 0,
            genesis: String::new(),
        }
    }

    /// Runs until the load stops; the last status says why.
    pub fn run(mut self) -> Result<LoadStatus, LoadError> {
        self.save()?;
        let reason = self.drive()?;
        info!("Load {} stopped: {reason}", self.spec.id);
        self.status.state = LoadState::Finished(reason);
        self.save()?;
        Ok(self.status)
    }

    fn drive(&mut self) -> Result<StopReason, LoadError> {
        self.genesis = match self.wait_for_chain(None)? {
            Ok(genesis) => genesis,
            Err(reason) => return Ok(reason),
        };
        if let Some(reason) = self.unlock_all() {
            return Ok(reason);
        }
        self.set_state(LoadState::Running)?;
        loop {
            if self.clock.stop_asked() {
                return Ok(StopReason::Stopped);
            }
            if self.done() {
                return Ok(StopReason::Done);
            }
            self.status.rounds += 1;
            match self.round()? {
                Round::Sent => {}
                Round::Stop(reason) => return Ok(reason),
                Round::WindowClosed if !self.spec.across_fork => {
                    return Ok(StopReason::TxWindowClosed)
                }
                Round::WindowClosed => {
                    info!("The transaction window is closed; waiting for the postfork chain");
                    self.set_state(LoadState::WaitingForFork)?;
                    let previous = self.genesis.clone();
                    self.genesis = match self.wait_for_chain(Some(&previous))? {
                        Ok(genesis) => genesis,
                        Err(reason) => return Ok(reason),
                    };
                    info!("The daemon runs the postfork chain {}", self.genesis);
                    if let Some(reason) = self.unlock_all() {
                        return Ok(reason);
                    }
                    self.set_state(LoadState::Running)?;
                    continue;
                }
            }
            self.save()?;
            if self.done() {
                return Ok(StopReason::Done);
            }
            if !self.clock.pause(self.spec.scenario.interval) {
                return Ok(StopReason::Stopped);
            }
        }
    }

    fn done(&self) -> bool {
        self.spec
            .scenario
            .is_done(self.status.rounds, self.clock.elapsed())
    }

    /// The genesis of a synced daemon; with `previous`, one that differs
    /// from it. Before the first payment, a daemon that does not answer
    /// `max_failures` times fails the load; while it waits for the fork, the
    /// daemons restart, so it waits.
    fn wait_for_chain(
        &mut self,
        previous: Option<&str>,
    ) -> Result<Result<String, StopReason>, LoadError> {
        loop {
            if self.clock.stop_asked() {
                return Ok(Err(StopReason::Stopped));
            }
            match self.gateway.chain() {
                Ok(chain) if chain.synced && previous.is_none_or(|p| p != chain.genesis) => {
                    self.failures = 0;
                    return Ok(Ok(chain.genesis));
                }
                Ok(_) => {}
                Err(e) if previous.is_none() => {
                    if let Some(reason) = self.failed(e) {
                        return Ok(Err(reason));
                    }
                    self.save()?;
                }
                Err(_) => {}
            }
            if !self.clock.pause(POLL) {
                return Ok(Err(StopReason::Stopped));
            }
        }
    }

    fn unlock_all(&mut self) -> Option<StopReason> {
        for sender in &self.spec.senders {
            if let Err(e) = self.gateway.unlock(sender) {
                return Some(StopReason::Failed {
                    error: format!("importing and unlocking {}: {e}", sender.name),
                });
            }
        }
        None
    }

    /// Counts a failed call; the reason to stop once there are
    /// `max_failures` in a row.
    fn failed(&mut self, e: DaemonError) -> Option<StopReason> {
        warn!("{e}");
        self.failures += 1;
        self.status.last_error = Some(e.to_string());
        (self.failures >= self.spec.max_failures).then(|| StopReason::Failed {
            error: e.to_string(),
        })
    }

    /// The senders that can pay amount + fee now.
    fn payable(&mut self) -> Result<Vec<&'a Sender>, Option<StopReason>> {
        let spec = self.spec;
        let need = spec.amount + spec.fee;
        let mut payable = Vec::new();
        let mut unknown = false;
        for sender in &spec.senders {
            match self.gateway.liquid(&sender.public_key) {
                Ok(liquid) => {
                    let status = self.sender_status(sender);
                    status.liquid = Some(liquid);
                    status.drained = liquid < need;
                    if liquid >= need {
                        payable.push(sender);
                    }
                }
                Err(e) => {
                    unknown = true;
                    if let Some(reason) = self.failed(e) {
                        return Err(Some(reason));
                    }
                }
            }
        }
        match (payable.is_empty(), unknown) {
            (false, _) => Ok(payable),
            (true, false) => Err(Some(StopReason::FundsDrained)),
            (true, true) => Err(None),
        }
    }

    fn round(&mut self) -> Result<Round, LoadError> {
        let mut payable = match self.payable() {
            Ok(payable) => payable,
            Err(Some(reason)) => return Ok(Round::Stop(reason)),
            Err(None) => return Ok(Round::Sent),
        };
        for _ in 0..self.spec.scenario.per_round {
            if self.clock.stop_asked() {
                return Ok(Round::Stop(StopReason::Stopped));
            }
            if payable.is_empty() {
                break;
            }
            let sender = payable[self.cursor % payable.len()];
            self.cursor += 1;
            match self.pay(sender)? {
                Ok(_) => {
                    self.failures = 0;
                    self.status.accepted += 1;
                    self.sender_status(sender).accepted += 1;
                }
                Err(e) => {
                    self.status.rejected += 1;
                    self.sender_status(sender).rejected += 1;
                    match e {
                        DaemonError::TxWindowClosed => return Ok(Round::WindowClosed),
                        // its pending payments spend the rest: not a failure
                        DaemonError::InsufficientFunds(_) => {
                            self.status.last_error = Some(e.to_string());
                            payable.retain(|s| s.public_key != sender.public_key);
                        }
                        e => {
                            if let Some(reason) = self.failed(e) {
                                return Ok(Round::Stop(reason));
                            }
                        }
                    }
                }
            }
        }
        Ok(Round::Sent)
    }

    /// Sends one payment and journals it; a daemon that lost the key gets it
    /// again, once.
    fn pay(&mut self, sender: &Sender) -> Result<Result<SubmittedCommand, DaemonError>, LoadError> {
        let spec = self.spec;
        let receiver = spec.receiver_of(sender);
        self.sent += 1;
        let memo = spec.memo(self.sent);
        let payment = Payment::sender(&sender.public_key)
            .to(&receiver.public_key)
            .amount(spec.amount)
            .fee(spec.fee)
            .memo(&memo);
        let result = match self.gateway.send(payment.clone()) {
            Err(DaemonError::Locked(_)) => self
                .gateway
                .unlock(sender)
                .and_then(|()| self.gateway.send(payment)),
            result => result,
        };
        let (hash, nonce, error) = match &result {
            Ok(sent) => (Some(sent.hash.clone()), Some(sent.nonce), None),
            Err(e) => (None, None, Some(e.to_string())),
        };
        self.journal.payment(&PaymentRecord {
            at: chrono::Local::now().to_rfc3339(),
            round: self.status.rounds,
            genesis: self.genesis.clone(),
            sender: sender.public_key.clone(),
            receiver: receiver.public_key.clone(),
            amount: spec.amount,
            fee: spec.fee,
            memo,
            hash,
            nonce,
            error,
        })?;
        Ok(result)
    }

    fn sender_status(&mut self, sender: &Sender) -> &mut super::SenderStatus {
        self.status
            .by_sender
            .entry(sender.name.clone())
            .or_default()
    }

    fn set_state(&mut self, state: LoadState) -> Result<(), LoadError> {
        self.status.state = state;
        self.save()
    }

    fn save(&mut self) -> Result<(), LoadError> {
        self.status.updated_at = chrono::Local::now().to_rfc3339();
        self.journal.status(&self.status)
    }
}
