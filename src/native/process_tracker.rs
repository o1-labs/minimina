//! `processes.json`: the native processes minimina started for a network.
//!
//! Every read-modify-write holds an exclusive `flock` on `processes.lock` and
//! replaces the file atomically, so concurrent minimina invocations cannot
//! lose records.

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal;
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub service_name: String,
    pub started_at: String,
    pub log_file: PathBuf,
    pub config_dir: PathBuf,
    /// Kernel start time of `pid` (clock ticks since boot, `/proc/<pid>/stat` field 22).
    /// Distinguishes our process from a later one that reused the PID.
    #[serde(default)]
    pub start_time: Option<u64>,
}

impl ProcessRecord {
    /// True while the recorded process (not merely its PID) is running.
    pub fn is_alive(&self) -> bool {
        match proc_stat(self.pid) {
            Some(stat) => !stat.zombie && self.start_time.is_none_or(|t| t == stat.start_time),
            // no procfs: fall back to signal 0
            None => !Path::new("/proc/self").exists() && ProcessTracker::is_alive(self.pid),
        }
    }
}

pub type Records = HashMap<String, ProcessRecord>;

pub struct ProcessTracker {
    path: PathBuf,
    lock_path: PathBuf,
}

impl ProcessTracker {
    pub fn new(network_path: &Path) -> Self {
        ProcessTracker {
            path: network_path.join("processes.json"),
            lock_path: network_path.join("processes.lock"),
        }
    }

    fn lock(&self) -> io::Result<Flock<File>> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)?;
        Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, errno)| io::Error::from(errno))
    }

    fn read(&self) -> io::Result<Records> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }
        let data = fs::read_to_string(&self.path)?;
        serde_json::from_str(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write(&self, records: &Records) -> io::Result<()> {
        let data = serde_json::to_string_pretty(records).map_err(io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &self.path)
    }

    /// Runs `f` on the records under the lock and saves what it leaves behind.
    pub fn update<T>(&self, f: impl FnOnce(&mut Records) -> io::Result<T>) -> io::Result<T> {
        let _lock = self.lock()?;
        let mut records = self.read()?;
        let result = f(&mut records)?;
        self.write(&records)?;
        Ok(result)
    }

    pub fn load(&self) -> io::Result<Records> {
        let _lock = self.lock()?;
        self.read()
    }

    pub fn add(&self, record: ProcessRecord) -> io::Result<()> {
        self.update(|records| {
            records.insert(record.service_name.clone(), record);
            Ok(())
        })
    }

    pub fn remove(&self, service_name: &str) -> io::Result<()> {
        self.update(|records| {
            records.remove(service_name);
            Ok(())
        })
    }

    pub fn get(&self, service_name: &str) -> io::Result<Option<ProcessRecord>> {
        Ok(self.load()?.remove(service_name))
    }

    pub fn list(&self) -> io::Result<Records> {
        self.load()
    }

    /// Signal-0 probe; true for any process with this PID, including zombies.
    pub fn is_alive(pid: u32) -> bool {
        signal::kill(Pid::from_raw(pid as i32), None).is_ok()
    }
}

pub struct ProcStat {
    pub start_time: u64,
    pub zombie: bool,
}

/// Reads state and start time of `pid` from `/proc/<pid>/stat`.
pub fn proc_stat(pid: u32) -> Option<ProcStat> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` (field 2) may contain spaces and parens; fields resume after the last ')'
    let rest = &stat[stat.rfind(')')? + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some(ProcStat {
        zombie: matches!(fields.first(), Some(&"Z") | Some(&"X")),
        // field 22 overall = index 19 after state (field 3)
        start_time: fields.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, pid: u32) -> ProcessRecord {
        ProcessRecord {
            pid,
            service_name: name.into(),
            started_at: "now".into(),
            log_file: "l".into(),
            config_dir: "c".into(),
            start_time: None,
        }
    }

    #[test]
    fn add_get_remove_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = ProcessTracker::new(dir.path());
        assert!(tracker.list().unwrap().is_empty());

        tracker.add(record("a", 1)).unwrap();
        tracker.add(record("b", 2)).unwrap();
        assert_eq!(tracker.get("a").unwrap().unwrap().pid, 1);
        assert_eq!(tracker.list().unwrap().len(), 2);

        tracker.remove("a").unwrap();
        assert!(tracker.get("a").unwrap().is_none());
        assert_eq!(tracker.list().unwrap().len(), 1);
    }

    #[test]
    fn corrupt_tracker_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("processes.json"), "{").unwrap();
        let err = ProcessTracker::new(dir.path()).list().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn is_alive_detects_own_process() {
        assert!(ProcessTracker::is_alive(std::process::id()));
    }

    #[test]
    fn record_liveness_checks_start_time() {
        let me = std::process::id();
        let start = proc_stat(me).unwrap().start_time;
        let mut rec = record("me", me);
        rec.start_time = Some(start);
        assert!(rec.is_alive());
        rec.start_time = Some(start + 1);
        assert!(!rec.is_alive(), "PID reused by another process");
    }

    #[test]
    fn zombie_is_not_alive() {
        let child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        // not reaped yet: the exited child stays a zombie
        for _ in 0..100 {
            if proc_stat(pid).is_some_and(|s| s.zombie) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ProcessTracker::is_alive(pid));
        assert!(!record("z", pid).is_alive());
        drop(child);
    }

    #[test]
    fn writes_leave_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = ProcessTracker::new(dir.path());
        tracker.add(record("a", 1)).unwrap();
        assert!(!dir.path().join("processes.json.tmp").exists());
        assert!(dir.path().join("processes.json").exists());
    }

    #[test]
    fn concurrent_adds_keep_every_record() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|s| {
            for i in 0..8u32 {
                let path = dir.path();
                s.spawn(move || {
                    ProcessTracker::new(path)
                        .add(record(&format!("s{i}"), i))
                        .unwrap()
                });
            }
        });
        assert_eq!(ProcessTracker::new(dir.path()).list().unwrap().len(), 8);
    }
}
