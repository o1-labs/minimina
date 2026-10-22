//! Applications published as npm packages, installed with the host's `npm`
//! into a directory of their own (`npm install --prefix <dir>`).

use super::requirement::Tool;
use crate::runner::Runner;
use crate::version::Version;
use anyhow::{bail, Context as _, Result};
use log::info;
use std::path::{Path, PathBuf};

/// An application published on npm.
pub struct App {
    /// Directory of its installs under the tools directory.
    pub tool: &'static str,
    pub package: &'static str,
    /// Its executable in `node_modules/.bin`.
    pub bin: &'static str,
    /// `engines.node` of the package.
    pub node: Version,
}

impl App {
    /// The Node.js the application runs on.
    pub fn runtime(&self) -> Tool<'static> {
        Tool {
            name: "Node.js",
            program: "node",
            version_args: &["--version"],
            min: self.node,
            install: "See https://nodejs.org.",
        }
    }

    fn executable(&self, dir: &Path) -> PathBuf {
        dir.join("node_modules/.bin").join(self.bin)
    }
}

/// Installs `version` of `app` into `dir`, unless it is there already, and
/// returns its executable.
pub fn install(runner: &dyn Runner, dir: &Path, app: &App, version: &str) -> Result<PathBuf> {
    let executable = app.executable(dir);
    if executable.is_file() {
        return Ok(executable);
    }
    let package = format!("{}@{version}", app.package);
    info!("Installing {package} into {}", dir.display());
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    runner
        .run_checked(
            "npm".as_ref(),
            &[
                "install",
                "--prefix",
                &dir.to_string_lossy(),
                "--omit=dev",
                "--no-audit",
                "--no-fund",
                &package,
            ],
            &[],
            &format!("npm install {package}"),
        )
        .context("npm comes with Node.js")?;
    if !executable.is_file() {
        bail!(
            "npm installed {package}, but {} is missing",
            executable.display()
        );
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    const APP: App = App {
        tool: "app",
        package: "@org/app",
        bin: "app-server",
        node: Version(22, 12, 0),
    };

    #[test]
    fn installs_a_version_once() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRunner::default();
        // the fake npm installs nothing
        let err = install(&fake, dir.path(), &APP, "2.0.0").unwrap_err();
        assert!(err.to_string().contains("is missing"), "{err}");
        let line = fake.lines().pop().unwrap();
        assert!(line.starts_with("npm install --prefix "), "{line}");
        assert!(line.ends_with(" @org/app@2.0.0"), "{line}");

        let bin = dir.path().join("node_modules/.bin/app-server");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "").unwrap();
        assert_eq!(install(&fake, dir.path(), &APP, "2.0.0").unwrap(), bin);
        // installed: npm is not asked again
        assert_eq!(fake.lines().len(), 1);
    }

    #[test]
    fn npm_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRunner::default();
        fake.reply(1, "", "E404 not found");
        let err = install(&fake, dir.path(), &APP, "9.9.9").unwrap_err();
        assert!(format!("{err:#}").contains("E404 not found"), "{err:#}");
    }
}
