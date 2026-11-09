//! rosetta-cli for `network check rosetta`: coinbase mesh-cli built with
//! Mina's patch of rosetta-sdk-go, as mina CI builds it. Its deb,
//! `mina-rosetta-cli` (baked by `scripts/rosetta-cli-deb.sh`, linked
//! statically), is in the stable channel of packages.o1test.net; it is
//! unpacked once into the tools directory, as the mina debs are.

mod error;

pub use error::RosettaCliError;

use super::apt::{self, Channel, Entry, Repository};
use super::dpkg::{self, DPKG_DEB};
use super::mina::{Fetch, Source};
use super::requirement::require;
use crate::runner::Runner;
use log::info;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// rosetta-cli under the tools directory: `rosetta-cli/<version>/usr/bin/rosetta-cli`.
pub const TOOL: &str = "rosetta-cli";
/// The deb.
pub const PACKAGE: &str = "mina-rosetta-cli";
/// Its version: the mesh-cli version and the tag of Mina's rosetta-sdk-go patch.
pub const VERSION: &str = "0.10.1-stake-delegation-v1";
/// Where the deb puts rosetta-cli.
const BIN: &str = "usr/bin/rosetta-cli";
/// Debs being downloaded, under `<tools>/rosetta-cli`.
const DOWNLOADS: &str = ".downloads";

/// The rosetta-cli to run: `given`, else [`VERSION`] under
/// `<tools>/rosetta-cli`, installed there from its deb for this host
/// (`os_release` names its codename) if it is not yet.
pub fn resolve(
    tools_root: &Path,
    given: Option<&Path>,
    os_release: &Path,
    fetch: &dyn Fetch,
    runner: &dyn Runner,
) -> Result<PathBuf, RosettaCliError> {
    if let Some(program) = given {
        return Ok(program.to_path_buf());
    }
    let program = dir(tools_root).join(BIN);
    if program.is_file() {
        return Ok(program);
    }
    install(tools_root, &host_source(os_release)?, fetch, runner)?;
    Ok(program)
}

/// `<tools>/rosetta-cli/<version>`
fn dir(tools_root: &Path) -> PathBuf {
    tools_root.join(TOOL).join(VERSION)
}

/// The stable channel of packages.o1test.net for this host.
fn host_source(os_release: &Path) -> Result<Source, RosettaCliError> {
    let host = |cause| RosettaCliError::Host { cause };
    Ok(Source {
        repository: Repository::default(),
        channel: Channel::default(),
        codename: apt::host_codename(os_release).map_err(host)?,
        arch: apt::host_arch().map_err(host)?.to_string(),
    })
}

/// Downloads the deb of [`VERSION`], checks it against the index and unpacks
/// it into `<tools>/rosetta-cli/<version>`.
fn install(
    tools_root: &Path,
    source: &Source,
    fetch: &dyn Fetch,
    runner: &dyn Runner,
) -> Result<(), RosettaCliError> {
    let deb = find(source, fetch)?;
    require(runner, &DPKG_DEB).map_err(|cause| RosettaCliError::Unpack {
        cause: cause.into(),
    })?;
    let root = tools_root.join(TOOL);
    let downloads = root.join(DOWNLOADS);
    // unpacked next to its place and renamed: an interrupted install is not one
    let partial = root.join(format!(".{VERSION}.partial"));
    let _ = fs::remove_dir_all(&partial);
    for dir in [&downloads, &partial] {
        fs::create_dir_all(dir).map_err(io_error(dir))?;
    }
    let file = downloads.join(format!("{PACKAGE}_{VERSION}_{}.deb", source.arch));
    let unpacked =
        download(source, fetch, &deb, &file).and_then(|()| unpack(runner, &deb, &file, &partial));
    let _ = fs::remove_file(&file);
    let installed = unpacked.and_then(|()| {
        let dir = dir(tools_root);
        fs::rename(&partial, &dir).map_err(io_error(&dir))
    });
    if installed.is_err() {
        let _ = fs::remove_dir_all(&partial);
    }
    installed
}

/// The deb of [`VERSION`] in the index of `source`.
fn find(source: &Source, fetch: &dyn Fetch) -> Result<Entry, RosettaCliError> {
    let index = source
        .index(fetch)
        .map_err(|cause| RosettaCliError::Index { cause })?;
    index
        .entry(PACKAGE, VERSION)
        .cloned()
        .ok_or_else(|| RosettaCliError::NotPublished {
            from: source.clone(),
        })
}

/// Downloads `deb` to `file`, checking its SHA-256 against the index.
fn download(
    source: &Source,
    fetch: &dyn Fetch,
    deb: &Entry,
    file: &Path,
) -> Result<(), RosettaCliError> {
    let url = source.repository.deb_url(deb);
    info!(
        "Installing {PACKAGE} {VERSION} from {} {} ({} MiB)",
        source.channel,
        source.codename,
        deb.size >> 20
    );
    let found = fetch
        .download(&url, file)
        .map_err(|cause| RosettaCliError::Download {
            url: url.clone(),
            cause,
        })?;
    if found != deb.sha256 {
        return Err(RosettaCliError::ChecksumMismatch {
            url,
            expected: deb.sha256.clone(),
            found,
        });
    }
    Ok(())
}

/// `dpkg-deb -x` of `file` into `into`, which must then hold rosetta-cli.
fn unpack(
    runner: &dyn Runner,
    deb: &Entry,
    file: &Path,
    into: &Path,
) -> Result<(), RosettaCliError> {
    dpkg::unpack(runner, file, into).map_err(|cause| RosettaCliError::Unpack { cause })?;
    if !into.join(BIN).is_file() {
        return Err(RosettaCliError::NoBinary {
            deb: deb.filename.clone(),
            path: BIN,
        });
    }
    Ok(())
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> RosettaCliError {
    let path = path.to_path_buf();
    move |cause| RosettaCliError::Io { path, cause }
}

#[cfg(test)]
mod tests;
