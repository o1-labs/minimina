use super::{LoadError, LoadState, LoadStore, LoadSummary, Sender, StopReason};
use log::{info, warn};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::time::{Duration, Instant};

/// How long `stop` waits for a load to finish its payment and exit before
/// it kills it.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(45);

impl LoadStore {
    pub fn summary(&self, network_id: &str, id: &str) -> Result<LoadSummary, LoadError> {
        if !self.exists(id) {
            return Err(LoadError::UnknownLoad {
                network: network_id.to_string(),
                id: id.to_string(),
            });
        }
        let process = self.process(id)?;
        let alive = process.as_ref().is_some_and(|p| p.is_alive());
        Ok(LoadSummary::new(
            self.spec(id)?,
            process,
            alive,
            self.status(id)?,
            self.dir(id),
        ))
    }

    pub fn summaries(&self, network_id: &str) -> Result<Vec<LoadSummary>, LoadError> {
        self.ids()?
            .iter()
            .filter(|id| self.exists(id))
            .map(|id| self.summary(network_id, id))
            .collect()
    }

    /// Fails when one of `senders` pays in a running load: two loads would
    /// fight over its nonces.
    pub fn ensure_free(&self, network_id: &str, senders: &[Sender]) -> Result<(), LoadError> {
        for load in self
            .summaries(network_id)?
            .iter()
            .filter(|l| l.is_running())
        {
            if let Some(sender) = senders.iter().find(|s| load.senders.contains(&s.name)) {
                return Err(LoadError::SenderBusy {
                    sender: sender.name.clone(),
                    load: load.id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Stops a running load: SIGTERM, which it takes after its current
    /// payment, then SIGKILL after `timeout`. A load killed this way, or one
    /// that died, is recorded as stopped.
    pub fn stop(
        &self,
        network_id: &str,
        id: &str,
        timeout: Duration,
    ) -> Result<LoadSummary, LoadError> {
        // fails for an unknown load
        self.summary(network_id, id)?;
        if let Some(process) = self.process(id)?.filter(|p| p.is_alive()) {
            info!("Stopping load {id} (pid {})", process.pid);
            let pid = Pid::from_raw(process.pid as i32);
            let _ = signal::kill(pid, Signal::SIGTERM);
            let deadline = Instant::now() + timeout;
            while process.is_alive() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(200));
            }
            if process.is_alive() {
                warn!(
                    "Load {id} did not stop within {}s; killing it",
                    timeout.as_secs()
                );
                let _ = signal::kill(pid, Signal::SIGKILL);
            }
        }
        if let Some(mut status) = self.status(id)?.filter(|s| !s.state.is_finished()) {
            status.state = LoadState::Finished(StopReason::Stopped);
            status.updated_at = chrono::Local::now().to_rfc3339();
            self.save_status(id, &status)?;
        }
        self.summary(network_id, id)
    }

    /// Stops every running load of the network.
    pub fn stop_all(
        &self,
        network_id: &str,
        timeout: Duration,
    ) -> Result<Vec<LoadSummary>, LoadError> {
        self.summaries(network_id)?
            .into_iter()
            .filter(LoadSummary::is_running)
            .map(|load| self.stop(network_id, &load.id, timeout))
            .collect()
    }
}
