use super::{LoadError, LoadProcess, LoadSpec, LoadStatus, PaymentRecord};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

const PREFIX: &str = "load-";
const SPEC: &str = "load.json";
const PROCESS: &str = "process.json";
const STATUS: &str = "status.json";
const PAYMENTS: &str = "payments.jsonl";
const LOG: &str = "load.log";

/// The loads of a network: `<network>/load/<id>/` with `load.json` (what
/// was asked), `process.json`, `status.json` (what the worker reports),
/// `payments.jsonl` (every payment sent) and `load.log`.
pub struct LoadStore {
    root: PathBuf,
}

impl LoadStore {
    pub fn new(network_path: &Path) -> Self {
        LoadStore {
            root: network_path.join("load"),
        }
    }

    pub fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn log_path(&self, id: &str) -> PathBuf {
        self.dir(id).join(LOG)
    }

    /// A new load directory, `load-<n>` after the highest one.
    pub fn create(&self) -> Result<String, LoadError> {
        fs::create_dir_all(&self.root).map_err(io("creating", &self.root))?;
        let mut n = self.numbers()?.last().map_or(1, |n| n + 1);
        loop {
            let id = format!("{PREFIX}{n}");
            let dir = self.dir(&id);
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(id),
                // another `load start` took it
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
                Err(e) => return Err(io("creating", &dir)(e)),
            }
        }
    }

    fn numbers(&self) -> Result<Vec<u64>, LoadError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let entries = fs::read_dir(&self.root).map_err(io("reading", &self.root))?;
        let mut numbers: Vec<u64> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.strip_prefix(PREFIX)?.parse().ok())
            .collect();
        numbers.sort_unstable();
        Ok(numbers)
    }

    /// The loads of the network, oldest first.
    pub fn ids(&self) -> Result<Vec<String>, LoadError> {
        Ok(self
            .numbers()?
            .into_iter()
            .map(|n| format!("{PREFIX}{n}"))
            .collect())
    }

    pub fn exists(&self, id: &str) -> bool {
        self.dir(id).join(SPEC).exists()
    }

    pub fn save_spec(&self, spec: &LoadSpec) -> Result<(), LoadError> {
        self.write(&spec.id, SPEC, spec)
    }

    pub fn spec(&self, id: &str) -> Result<LoadSpec, LoadError> {
        self.read(id, SPEC)
    }

    pub fn save_process(&self, id: &str, process: &LoadProcess) -> Result<(), LoadError> {
        self.write(id, PROCESS, process)
    }

    /// None until the process is started.
    pub fn process(&self, id: &str) -> Result<Option<LoadProcess>, LoadError> {
        self.read_if_any(id, PROCESS)
    }

    pub fn save_status(&self, id: &str, status: &LoadStatus) -> Result<(), LoadError> {
        self.write(id, STATUS, status)
    }

    pub fn status(&self, id: &str) -> Result<Option<LoadStatus>, LoadError> {
        self.read_if_any(id, STATUS)
    }

    pub fn append_payment(&self, id: &str, record: &PaymentRecord) -> Result<(), LoadError> {
        let path = self.dir(id).join(PAYMENTS);
        let line = serde_json::to_string(record).map_err(json(&path))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(io("opening", &path))?;
        writeln!(file, "{line}").map_err(io("writing", &path))
    }

    pub fn payments(&self, id: &str) -> Result<Vec<PaymentRecord>, LoadError> {
        let path = self.dir(id).join(PAYMENTS);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&path).map_err(io("reading", &path))?;
        BufReader::new(file)
            .lines()
            .map(|line| {
                let line = line.map_err(io("reading", &path))?;
                serde_json::from_str(&line).map_err(json(&path))
            })
            .collect()
    }

    /// Replaces the file atomically, so readers never see half of it.
    fn write<T: Serialize>(&self, id: &str, name: &str, value: &T) -> Result<(), LoadError> {
        let path = self.dir(id).join(name);
        let data = serde_json::to_string_pretty(value).map_err(json(&path))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, data).map_err(io("writing", &tmp))?;
        fs::rename(&tmp, &path).map_err(io("writing", &path))
    }

    fn read<T: DeserializeOwned>(&self, id: &str, name: &str) -> Result<T, LoadError> {
        let path = self.dir(id).join(name);
        let data = fs::read_to_string(&path).map_err(io("reading", &path))?;
        serde_json::from_str(&data).map_err(json(&path))
    }

    fn read_if_any<T: DeserializeOwned>(
        &self,
        id: &str,
        name: &str,
    ) -> Result<Option<T>, LoadError> {
        if self.dir(id).join(name).exists() {
            self.read(id, name).map(Some)
        } else {
            Ok(None)
        }
    }
}

fn io(what: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> LoadError {
    let path = path.to_path_buf();
    move |cause| LoadError::Io { what, path, cause }
}

fn json(path: &Path) -> impl FnOnce(serde_json::Error) -> LoadError {
    let path = path.to_path_buf();
    move |cause| LoadError::Json { path, cause }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_count_up_and_skip_taken_ones() {
        let net = tempfile::tempdir().unwrap();
        let store = LoadStore::new(net.path());
        assert!(store.ids().unwrap().is_empty());
        assert_eq!(store.create().unwrap(), "load-1");
        assert_eq!(store.create().unwrap(), "load-2");
        fs::create_dir(net.path().join("load/load-10")).unwrap();
        fs::create_dir(net.path().join("load/notes")).unwrap();
        assert_eq!(store.create().unwrap(), "load-11");
        assert_eq!(
            store.ids().unwrap(),
            ["load-1", "load-2", "load-10", "load-11"]
        );
        assert!(!store.exists("load-1"));
        assert!(store.status("load-1").unwrap().is_none());
        assert!(store.payments("load-1").unwrap().is_empty());
    }
}
