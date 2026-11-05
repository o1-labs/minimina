use super::{root, Fetch, Installed, MinaError, Source, BIN_DIR, INSTALL_FILE};
use crate::install::apt::Release;
use crate::install::dpkg::{self, DPKG_DEB};
use crate::install::requirement::require;
use crate::native::binary::Binary;
use crate::runner::Runner;
use anyhow::{Context as _, Result};
use log::info;
use std::path::Path;

/// Debs being downloaded, under `<tools>/mina`.
const DOWNLOADS: &str = ".downloads";
/// Name of the directory a version is unpacked into before it is moved to
/// `<tools>/mina/<version>`, so that an interrupted install is not one.
fn partial_name(version: &str) -> String {
    format!(".{version}.partial")
}

/// Installs `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`) from `source`,
/// unless it is installed already. Returns the install and whether it is new.
pub fn install(
    tools_root: &Path,
    runner: &dyn Runner,
    fetch: &dyn Fetch,
    wanted: &str,
    source: &Source,
) -> Result<(Installed, bool)> {
    let index = source.index(fetch)?;
    let release = source.find(fetch, &index, wanted)?;
    let root = root(tools_root);
    let dir = root.join(&release.version);
    if let Some(installed) = Installed::load(&dir)? {
        return Ok((installed, false));
    }
    // before hundreds of MB are downloaded
    require(runner, &DPKG_DEB)?;

    // unpacked into a hidden directory first: an interrupted install is not one
    let partial = root.join(partial_name(&release.version));
    if partial.exists() {
        std::fs::remove_dir_all(&partial)
            .with_context(|| format!("removing {}", partial.display()))?;
    }
    let unpacked = unpack(&root, &partial, runner, fetch, source, &release);
    if let Err(e) = unpacked {
        let _ = std::fs::remove_dir_all(&partial);
        return Err(e);
    }
    let installed = Installed {
        version: release.version.clone(),
        channel: source.channel.clone(),
        codename: source.codename.clone(),
        packages: release
            .debs
            .iter()
            .map(|d| format!("{} {}", d.package, d.version))
            .collect(),
        depends: release.depends(),
        dir: dir.clone(),
    };
    std::fs::write(
        partial.join(INSTALL_FILE),
        serde_json::to_string_pretty(&installed)?,
    )
    .context("recording the install")?;
    std::fs::rename(&partial, &dir)
        .with_context(|| format!("moving {} to {}", partial.display(), dir.display()))?;
    info!("Installed mina {} in {}", release.version, dir.display());
    Ok((installed, true))
}

/// Downloads the debs of `release` one at a time, checks each against the
/// index and unpacks it into `into`.
fn unpack(
    root: &Path,
    into: &Path,
    runner: &dyn Runner,
    fetch: &dyn Fetch,
    source: &Source,
    release: &Release,
) -> Result<()> {
    let downloads = root.join(DOWNLOADS);
    for dir in [into, &downloads] {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    info!(
        "Installing mina {} from {} {} ({} MiB to download)",
        release.version,
        source.channel,
        source.codename,
        release.size() >> 20
    );
    for deb in &release.debs {
        let name = Path::new(&deb.filename)
            .file_name()
            .with_context(|| format!("bad file name '{}'", deb.filename))?;
        let file = downloads.join(name);
        info!("Downloading {} ({} MiB)", deb.package, deb.size >> 20);
        let result = fetch
            .download(&source.repository.deb_url(deb), &file)
            .and_then(|sha256| {
                if sha256 != deb.sha256 {
                    return Err(MinaError::Checksum {
                        file: deb.filename.clone(),
                        found: sha256,
                        expected: deb.sha256.clone(),
                    }
                    .into());
                }
                dpkg::unpack(runner, &file, into)
            });
        let _ = std::fs::remove_file(&file);
        result?;
    }
    if !Binary::Mina.path(&into.join(BIN_DIR)).is_file() {
        return Err(MinaError::NoBinary {
            version: release.version.clone(),
        }
        .into());
    }
    Ok(())
}
