use super::{root, MinaError, BIN_DIR, INSTALL_FILE};
use crate::install::apt::{self, Channel, PackageVersion};
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A version of mina in the tools directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Installed {
    /// Version of the packages (`4.0.2-84b8d96`), also the directory name.
    pub version: String,
    pub channel: Channel,
    pub codename: String,
    /// `<package> <version>` of each unpacked deb.
    pub packages: Vec<String>,
    #[serde(skip)]
    pub dir: PathBuf,
}

impl Installed {
    /// The directory of `mina`, `mina-archive`, ... (`--bin-path`).
    pub fn bin_path(&self) -> PathBuf {
        self.dir.join(BIN_DIR)
    }

    pub(super) fn load(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(INSTALL_FILE);
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut installed: Installed = serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid", path.display()))?;
        installed.dir = dir.to_path_buf();
        Ok(Some(installed))
    }
}

/// The installed versions, oldest first.
pub fn installed(tools_root: &Path) -> Result<Vec<Installed>> {
    let root = root(tools_root);
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).with_context(|| format!("reading {}", root.display())),
    };
    let mut found = vec![];
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", root.display()))?;
        // Hidden directories are minimina's work in progress, not installs:
        // `.downloads`, and `.<version>.partial`, which already has its
        // install.json in the moment before it is renamed to `<version>`.
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if let Some(installed) = Installed::load(&entry.path())? {
            found.push(installed);
        }
    }
    found.sort_by(|a, b| PackageVersion::compare(&a.version, &b.version));
    Ok(found)
}

/// The installed version `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`).
pub fn resolve(tools_root: &Path, wanted: &str) -> Result<Installed> {
    let all = installed(tools_root)?;
    let versions = |items: &[&Installed]| items.iter().map(|i| i.version.clone()).collect();
    match apt::select(&all, |i| &i.version, wanted).as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(MinaError::NotInstalled {
            wanted: wanted.to_string(),
            installed: versions(&all.iter().collect::<Vec<_>>()),
        }
        .into()),
        many => Err(MinaError::Ambiguous {
            wanted: wanted.to_string(),
            what: "installs",
            versions: versions(many),
        }
        .into()),
    }
}

/// Removes an install.
pub fn uninstall(installed: &Installed) -> Result<()> {
    std::fs::remove_dir_all(&installed.dir)
        .with_context(|| format!("removing {}", installed.dir.display()))
}
