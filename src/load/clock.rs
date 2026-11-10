use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// Time for the worker, and whether it was asked to stop.
pub trait Clock {
    fn elapsed(&self) -> Duration;
    fn stop_asked(&self) -> bool;
    /// Waits `d`; false when a stop was asked meanwhile.
    fn pause(&self, d: Duration) -> bool;
}

/// The wall clock, and a flag SIGTERM sets.
pub struct SystemClock {
    start: Instant,
    stop: Arc<AtomicBool>,
}

const STEP: Duration = Duration::from_millis(250);

impl SystemClock {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        SystemClock {
            start: Instant::now(),
            stop,
        }
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn stop_asked(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn pause(&self, d: Duration) -> bool {
        let deadline = Instant::now() + d;
        while !self.stop_asked() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            std::thread::sleep(left.min(STEP));
        }
        false
    }
}
