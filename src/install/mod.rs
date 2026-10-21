//! The tools minimina runs: what it needs on the host, and what it installs.
//!
//! Installed tools live in `<minimina home>/.tools/<tool>/<version>`: one
//! directory per version, so that versions sit side by side. [`npm`] installs
//! npm applications (the archive node api); mina itself will come from its
//! deb packages the same way (#13). [`requirement`] checks programs the host
//! must provide (Node.js, Docker Compose).

pub mod npm;
pub mod requirement;

pub use requirement::{require, Tool, ToolError};

use crate::runner::Runner;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub struct Installer<'a> {
    /// `<minimina home>/.tools`
    root: PathBuf,
    runner: &'a dyn Runner,
}

impl<'a> Installer<'a> {
    pub fn new(root: PathBuf, runner: &'a dyn Runner) -> Self {
        Installer { root, runner }
    }

    /// Directory of `version` of `tool`.
    pub fn dir(&self, tool: &str, version: &str) -> PathBuf {
        self.root.join(tool).join(version)
    }

    /// The executable of an npm application: `own` (the user's build) when
    /// given, else `version` installed with npm once. Either way, the host's
    /// Node.js must be new enough for it.
    pub fn npm_app(&self, app: &npm::App, version: &str, own: Option<&Path>) -> Result<PathBuf> {
        require(self.runner, &app.runtime())?;
        match own {
            Some(bin) if bin.is_file() => Ok(bin.to_path_buf()),
            Some(bin) => bail!("'{}' does not exist", bin.display()),
            None => npm::install(self.runner, &self.dir(app.tool, version), app, version),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;
    use crate::version::Version;

    const APP: npm::App = npm::App {
        tool: "app",
        package: "@org/app",
        bin: "app-server",
        node: Version(22, 12, 0),
    };

    #[test]
    fn npm_apps_need_a_new_enough_node() {
        let root = tempfile::tempdir().unwrap();
        let fake = FakeRunner::default();
        let installer = Installer::new(root.path().to_path_buf(), &fake);
        fake.reply(0, "v18.19.1\n", "");
        let err = installer.npm_app(&APP, "1.0.0", None).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("Node.js 18.19.1 is older than the minimum supported version 22.12.0"),
            "{err}"
        );
        // nothing installed
        assert_eq!(fake.lines(), ["node --version"]);
    }

    #[test]
    fn own_build_is_used_as_given() {
        let root = tempfile::tempdir().unwrap();
        let own = root.path().join("server.js");
        let fake = FakeRunner::default();
        let installer = Installer::new(root.path().join(".tools"), &fake);
        fake.reply(0, "v24.0.0", "");
        let err = installer.npm_app(&APP, "1.0.0", Some(&own)).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
        std::fs::write(&own, "").unwrap();
        fake.reply(0, "v24.0.0", "");
        assert_eq!(installer.npm_app(&APP, "1.0.0", Some(&own)).unwrap(), own);
        // installs go per version under the root
        assert_eq!(
            installer.dir("app", "1.0.0"),
            root.path().join(".tools/app/1.0.0")
        );
    }
}
