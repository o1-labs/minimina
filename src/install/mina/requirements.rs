//! What a mina version needs from the host, and whether the host has it.
//!
//! Two checks, of different weight:
//! - packages: the `Depends` of the debs, against the dpkg database. Only
//!   advice: the packages declare more than the binaries load (`libpq-dev`
//!   where `libpq5` is enough), and dpkg knows nothing of libraries installed
//!   another way.
//! - libraries: `ldd` on the binaries. A library that is `not found` makes the
//!   binary fail at load time, so this one stops a network from starting.

use super::MinaError;
use crate::install::apt::Dependency;
use crate::install::{dpkg::DpkgDatabase, ldd, ToolError};
use crate::native::binary::Binary;
use crate::runner::Runner;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

/// The binaries minimina runs, whose libraries are checked.
const BINARIES: [Binary; 5] = [
    Binary::Mina,
    Binary::Archive,
    Binary::Rosetta,
    Binary::CreateGenesis,
    Binary::Libp2pHelper,
];

/// What the host lacks for a mina version.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct Requirements {
    /// Libraries the binaries cannot load: they do not run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_libraries: Vec<String>,
    /// Dependencies of the packages that are not installed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_packages: Vec<Dependency>,
    /// The command that installs `missing_packages`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_command: Option<String>,
    /// Checks the host has no tool for (`dpkg-query`, `ldd`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unchecked: Vec<String>,
}

impl Requirements {
    /// Checks `depends` (of the packages) and the binaries in `bin_path`.
    pub fn check(runner: &dyn Runner, depends: &[Dependency], bin_path: &Path) -> Self {
        let mut requirements = Requirements::default();
        match DpkgDatabase::load(runner) {
            Ok(db) => requirements.missing_packages = db.missing(depends),
            Err(e) => requirements.unchecked.push(unchecked("packages", &e)),
        }
        if !requirements.missing_packages.is_empty() {
            let names: Vec<&str> = requirements
                .missing_packages
                .iter()
                .map(Dependency::first)
                .collect();
            requirements.install_command =
                Some(format!("sudo apt-get install {}", names.join(" ")));
        }
        match missing_libraries(runner, bin_path) {
            Ok(libraries) => requirements.missing_libraries = libraries,
            Err(e) => requirements.unchecked.push(unchecked("libraries", &e)),
        }
        requirements
    }

    /// Whether the binaries can be loaded.
    pub fn runnable(&self) -> bool {
        self.missing_libraries.is_empty()
    }

    /// Warns about what is missing.
    pub fn warn(&self, version: &str) {
        if !self.runnable() {
            log::warn!(
                "mina {version} cannot run here: missing libraries {}",
                self.missing_libraries.join(", ")
            );
        }
        if let Some(command) = &self.install_command {
            log::warn!(
                "mina {version} depends on packages that are not installed: {}; to install them: {command}",
                self.missing_packages
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

/// Why `what` was not checked.
fn unchecked(what: &str, e: &ToolError) -> String {
    match e {
        ToolError::Missing { program, .. } => format!("{what}: no {program} on this host"),
        e => format!("{what}: {e}"),
    }
}

/// The libraries the binaries in `bin_path` cannot load.
fn missing_libraries(runner: &dyn Runner, bin_path: &Path) -> Result<Vec<String>, ToolError> {
    let binaries: Vec<_> = BINARIES
        .iter()
        .map(|b| b.path(bin_path))
        .filter(|p| p.is_file())
        .collect();
    let binaries: Vec<&Path> = binaries.iter().map(|p| p.as_path()).collect();
    ldd::missing_libraries(runner, &binaries)
}

/// Fails when a binary in `bin_path` cannot load its libraries. `version` is
/// the installed mina version of `bin_path`, if it is one.
pub fn require_runnable(runner: &dyn Runner, bin_path: &Path, version: Option<&str>) -> Result<()> {
    match missing_libraries(runner, bin_path) {
        Ok(libraries) if !libraries.is_empty() => Err(MinaError::MissingLibraries {
            bin_path: bin_path.to_path_buf(),
            libraries,
            version: version.map(str::to_string),
        }
        .into()),
        Ok(_) => Ok(()),
        // what cannot be checked does not stop a network
        Err(e) => {
            log::warn!("{}", unchecked("the libraries of the mina binaries", &e));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    fn bin_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mina"), b"\x7fELF").unwrap();
        // not looked at: not ELF
        std::fs::write(dir.path().join("mina-archive"), "").unwrap();
        dir
    }

    #[test]
    fn packages_are_advice_and_libraries_decide() {
        let bin = bin_dir();
        let depends = Dependency::parse_list("libssl3t64, libpq-dev, libjemalloc2");
        let fake = FakeRunner::default();
        fake.reply(0, "libssl3t64\tii \t\nlibjemalloc2\tii \t\n", "")
            .reply(0, "\tlibc.so.6 => /lib/libc.so.6\n", "");
        let requirements = Requirements::check(&fake, &depends, bin.path());
        assert!(requirements.runnable());
        assert_eq!(
            requirements.missing_packages,
            [Dependency::from("libpq-dev")]
        );
        assert_eq!(
            requirements.install_command.as_deref(),
            Some("sudo apt-get install libpq-dev")
        );
        assert_eq!(
            fake.lines()[1],
            format!("ldd {}/mina", bin.path().display())
        );

        let fake = FakeRunner::default();
        fake.reply_err(std::io::ErrorKind::NotFound)
            .reply(0, "\tlibssl.so.3 => not found\n", "");
        let requirements = Requirements::check(&fake, &depends, bin.path());
        assert!(!requirements.runnable());
        assert_eq!(requirements.missing_libraries, ["libssl.so.3"]);
        assert_eq!(
            requirements.unchecked,
            ["packages: no dpkg-query on this host"]
        );
    }

    #[test]
    fn unloadable_binaries_are_refused() {
        let bin = bin_dir();
        let fake = FakeRunner::default();
        fake.reply(0, "\tlibssl.so.3 => not found\n", "");
        let err = require_runnable(&fake, bin.path(), Some("4.0.2-84b8d96"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            format!(
                "the mina binaries in {} cannot run here: missing libraries libssl.so.3; \
                 `minimina mina check 4.0.2-84b8d96` lists the packages to install",
                bin.path().display()
            )
        );
        let fake = FakeRunner::default();
        fake.reply(0, "\tlibc.so.6 => /lib/libc.so.6\n", "");
        require_runnable(&fake, bin.path(), None).unwrap();
    }
}
