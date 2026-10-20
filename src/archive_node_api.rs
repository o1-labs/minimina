//! Archive Node API (<https://github.com/o1-labs/Archive-Node-API>): a GraphQL
//! server over the archive database, for events and actions of zkApps.
//!
//! Docker mode runs its image. Native mode runs the npm package, which minimina
//! installs into `~/.minimina/.tools/archive-node-api/<version>` with the host's
//! `npm`; the package needs Node.js 22.12 or newer.

use crate::runner::{check, Runner};
use crate::utils::parse_version;
use anyhow::{bail, Context as _, Result};
use log::info;
use std::path::{Path, PathBuf};

pub const DEFAULT_VERSION: &str = "2.0.0";
const NPM_PACKAGE: &str = "@o1-labs/mina-archive-node-graphql";
const BIN: &str = "mina-archive-node-graphql";
/// `engines.node` of the package.
const MIN_NODE: (u32, u32, u32) = (22, 12, 0);
/// Name of the tool directory under `~/.minimina/.tools`.
pub const TOOL: &str = "archive-node-api";

pub fn docker_image(version: &str) -> String {
    format!("ghcr.io/o1-labs/archive-node-api:{version}")
}

/// Environment of the server: the archive database and its port.
/// It serves GraphQL at `/`.
pub fn env(pg_conn: &str, port: u16) -> Vec<(&'static str, String)> {
    vec![("PG_CONN", pg_conn.to_string()), ("PORT", port.to_string())]
}

/// The server's executable for native mode: `bin` when given, else the managed
/// install of `version` in `tool_dir`, installed with npm when missing.
pub fn ensure_native(
    runner: &dyn Runner,
    tool_dir: &Path,
    version: &str,
    bin: Option<&Path>,
) -> Result<PathBuf> {
    check_node(runner)?;
    if let Some(bin) = bin {
        if !bin.is_file() {
            bail!("archive node api: '{}' does not exist", bin.display());
        }
        return Ok(bin.to_path_buf());
    }

    let installed = tool_dir.join("node_modules/.bin").join(BIN);
    if installed.is_file() {
        return Ok(installed);
    }
    info!(
        "Installing {NPM_PACKAGE}@{version} into {}",
        tool_dir.display()
    );
    std::fs::create_dir_all(tool_dir)
        .with_context(|| format!("creating {}", tool_dir.display()))?;
    let prefix = tool_dir.to_string_lossy();
    let package = format!("{NPM_PACKAGE}@{version}");
    let out = runner
        .run(
            "npm".as_ref(),
            &[
                "install",
                "--prefix",
                &prefix,
                "--omit=dev",
                "--no-audit",
                "--no-fund",
                &package,
            ],
            &[],
        )
        .context("archive node api: running npm (install Node.js and npm)")?;
    check(out, &format!("npm install {package}"))?;
    if !installed.is_file() {
        bail!(
            "archive node api: npm installed {package}, but {} is missing",
            installed.display()
        );
    }
    Ok(installed)
}

/// The package refuses older Node.js; say so before anything starts.
fn check_node(runner: &dyn Runner) -> Result<()> {
    let (major, minor, patch) = MIN_NODE;
    let wanted = format!("Node.js {major}.{minor}.{patch} or newer");
    let out = runner
        .run("node".as_ref(), &["--version"], &[])
        .with_context(|| format!("archive node api needs {wanted}; `node` was not found"))?;
    let out = check(out, "node --version")?;
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    match parse_version(&version) {
        Some(found) if found >= MIN_NODE => Ok(()),
        _ => bail!("archive node api needs {wanted}; found {version}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn old_or_missing_node_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRunner::default();
        fake.reply(0, "v18.19.1\n", "");
        let err = ensure_native(&fake, dir.path(), "2.0.0", None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "archive node api needs Node.js 22.12.0 or newer; found v18.19.1"
        );

        fake.reply_err(std::io::ErrorKind::NotFound);
        let err = ensure_native(&fake, dir.path(), "2.0.0", None).unwrap_err();
        assert!(err.to_string().contains("`node` was not found"), "{err}");
    }

    #[test]
    fn installs_the_pinned_version_once() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRunner::default();
        fake.reply(0, "v24.21.0\n", "").reply(0, "", "");
        // npm "installs": the fake does nothing, so the binary is missing
        let err = ensure_native(&fake, dir.path(), "2.0.0", None).unwrap_err();
        assert!(err.to_string().contains("is missing"), "{err}");
        {
            let calls = fake.calls.borrow();
            assert_eq!(calls[1].program, "npm");
            assert_eq!(
                calls[1].args.last().map(String::as_str),
                Some("@o1-labs/mina-archive-node-graphql@2.0.0")
            );
        }

        let bin = dir
            .path()
            .join("node_modules/.bin/mina-archive-node-graphql");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "").unwrap();
        fake.reply(0, "v22.12.0\n", "");
        assert_eq!(
            ensure_native(&fake, dir.path(), "2.0.0", None).unwrap(),
            bin
        );
        // node check only: nothing installed again
        assert_eq!(fake.calls.borrow().len(), 3);
    }

    #[test]
    fn explicit_binary_is_used_as_given() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server.js");
        let fake = FakeRunner::default();
        fake.reply(0, "v24.0.0", "");
        let err = ensure_native(&fake, dir.path(), "2.0.0", Some(&bin)).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
        std::fs::write(&bin, "").unwrap();
        fake.reply(0, "v24.0.0", "");
        assert_eq!(
            ensure_native(&fake, dir.path(), "2.0.0", Some(&bin)).unwrap(),
            bin
        );
    }
}
