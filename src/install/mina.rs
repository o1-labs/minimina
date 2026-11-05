//! mina versions from their deb packages, side by side in
//! `<tools>/mina/<version>`.
//!
//! The debs are unpacked with `dpkg-deb -x`, not installed with apt: apt keeps
//! one version in `/usr/local/bin`, but a hardfork test runs two at once. The
//! binaries of a version are in `<tools>/mina/<version>/usr/local/bin`, the
//! layout [`crate::utils::package_root`] expects, so the archive schema of
//! the package is found next to them.

use super::apt::{self, Channel, Index, Release};
use crate::native::binary::Binary;
use crate::runner::Runner;
use anyhow::{bail, Context as _, Result};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Directory of the mina installs under the tools directory.
pub const TOOL: &str = "mina";
/// Where the packages put their binaries, under the install directory.
pub const BIN_DIR: &str = "usr/local/bin";
/// What was installed, in the install directory; a directory without it is
/// not an install.
const INSTALL_FILE: &str = "install.json";
/// Downloads in progress, under `<tools>/mina`.
const DOWNLOADS: &str = ".downloads";

/// How minimina gets files from the package repositories.
pub trait Fetch {
    fn text(&self, url: &str) -> Result<String>;
    /// Saves `url` as `dest` and returns the SHA-256 (hex) of what it saved.
    fn download(&self, url: &str, dest: &Path) -> Result<String>;
}

/// [`Fetch`] over HTTP.
pub struct Http;

impl Http {
    fn get(url: &str) -> Result<reqwest::blocking::Response> {
        // no overall timeout: mina-generic is about 350 MB
        // the repositories answer 403 to requests without a user agent
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("minimina/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(30))
            .timeout(None)
            .build()?;
        client
            .get(url)
            .send()
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("fetching {url}"))
    }
}

impl Fetch for Http {
    fn text(&self, url: &str) -> Result<String> {
        Self::get(url)?
            .text()
            .with_context(|| format!("reading {url}"))
    }

    fn download(&self, url: &str, dest: &Path) -> Result<String> {
        let mut response = Self::get(url)?;
        let total = response.content_length().filter(|t| *t > 0);
        let mut file =
            std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let (mut done, mut reported) = (0u64, 0u64);
        loop {
            let n = response
                .read(&mut buf)
                .with_context(|| format!("downloading {url}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])
                .with_context(|| format!("writing {}", dest.display()))?;
            done += n as u64;
            if let Some(total) = total {
                let percent = done * 100 / total;
                if percent >= reported + 10 {
                    reported = percent - percent % 10;
                    info!("  {reported}%");
                }
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// The repository, codename and architecture to install from.
#[derive(Debug, Clone)]
pub struct Source {
    pub channel: Channel,
    pub codename: String,
    pub arch: String,
}

impl Source {
    pub fn index(&self, fetch: &dyn Fetch) -> Result<Index> {
        let url = self.channel.index_url(&self.codename, &self.arch);
        match fetch.text(&url) {
            Ok(text) => Ok(Index::parse(&text)),
            Err(e) => {
                // say which channels there are when the channel is not one
                let channels = fetch
                    .text(&apt::release_url(&self.codename))
                    .map(|release| apt::channels(&release))
                    .unwrap_or_default();
                if !channels.is_empty() && !channels.contains(&self.channel.to_string()) {
                    bail!(
                        "{} has no channel {} for {}; channels: {}",
                        apt::REPOSITORY,
                        self.channel,
                        self.codename,
                        channels.join(", ")
                    );
                }
                Err(e)
                    .with_context(|| format!("no {} packages for {}", self.channel, self.codename))
            }
        }
    }
}

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

    fn load(dir: &Path) -> Result<Option<Self>> {
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

/// `<tools>/mina`
pub fn root(tools_root: &Path) -> PathBuf {
    tools_root.join(TOOL)
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
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if let Some(installed) = Installed::load(&entry.path())? {
            found.push(installed);
        }
    }
    let mut versions: Vec<String> = found.iter().map(|i| i.version.clone()).collect();
    apt::sort_versions(&mut versions);
    found.sort_by_key(|i| versions.iter().position(|v| *v == i.version));
    Ok(found)
}

/// The installed version `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`).
pub fn resolve(tools_root: &Path, wanted: &str) -> Result<Installed> {
    let all = installed(tools_root)?;
    let found: Vec<&Installed> = if wanted == "latest" {
        all.last().into_iter().collect()
    } else {
        all.iter()
            .filter(|i| apt::matches(&i.version, wanted))
            .collect()
    };
    match found.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!(
            "mina {wanted} is not installed; run `minimina mina install {wanted}`{}",
            if all.is_empty() {
                String::new()
            } else {
                format!(
                    " (installed: {})",
                    all.iter()
                        .map(|i| i.version.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ),
        many => bail!(
            "mina {wanted} names several installs: {}; give the whole version",
            many.iter()
                .map(|i| i.version.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
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
    let Some(release) = index.find(wanted)? else {
        bail!(not_found(fetch, wanted, source, &index));
    };
    let root = root(tools_root);
    let dir = root.join(&release.version);
    if let Some(installed) = Installed::load(&dir)? {
        return Ok((installed, false));
    }

    // unpacked into a hidden directory first: an interrupted install is not one
    let partial = root.join(format!(".{}.partial", release.version));
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
        let sha256 = fetch.download(&Channel::deb_url(&deb.filename), &file);
        let result = sha256.and_then(|sha256| {
            if sha256 != deb.sha256 {
                bail!(
                    "{} does not match the index: SHA-256 {sha256}, expected {}",
                    deb.filename,
                    deb.sha256
                );
            }
            runner
                .run_checked(
                    "dpkg-deb".as_ref(),
                    &["-x", &file.to_string_lossy(), &into.to_string_lossy()],
                    &[],
                    &format!("dpkg-deb -x {}", name.to_string_lossy()),
                )
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => anyhow::anyhow!(
                        "dpkg-deb unpacks the mina packages, but it was not found (package dpkg)"
                    ),
                    _ => e.into(),
                })?;
            Ok(())
        });
        let _ = std::fs::remove_file(&file);
        result?;
    }
    let mina = Binary::Mina.path(&into.join(BIN_DIR));
    if !mina.is_file() {
        bail!(
            "the packages of mina {} have no {}/{}",
            release.version,
            BIN_DIR,
            Binary::Mina
        );
    }
    Ok(())
}

/// Why `wanted` is not in the index of `source`, and where it is.
fn not_found(fetch: &dyn Fetch, wanted: &str, source: &Source, index: &Index) -> String {
    let elsewhere: Vec<&str> = apt::CODENAMES
        .iter()
        .copied()
        .filter(|c| *c != source.codename)
        .filter(|c| {
            let other = Source {
                codename: c.to_string(),
                ..source.clone()
            };
            other
                .index(fetch)
                .is_ok_and(|i| i.find(wanted).is_ok_and(|r| r.is_some()))
        })
        .collect();
    let mut message = format!(
        "mina {wanted} is not in the {} channel for {}",
        source.channel, source.codename
    );
    if !elsewhere.is_empty() {
        message += &format!("; available for: {}", elsewhere.join(", "));
    }
    let versions = index.versions();
    if !versions.is_empty() {
        let recent = &versions[versions.len().saturating_sub(5)..];
        message += &format!("; {} has: {}", source.codename, recent.join(", "));
    }
    message
}

/// Removes an install.
pub fn uninstall(installed: &Installed) -> Result<()> {
    std::fs::remove_dir_all(&installed.dir)
        .with_context(|| format!("removing {}", installed.dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::apt::PACKAGES;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::process::Output;

    /// Serves an index of `versions`, each package a deb of its name.
    #[derive(Default)]
    struct FakeRepo {
        files: HashMap<String, Vec<u8>>,
        fetched: RefCell<Vec<String>>,
    }

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    impl FakeRepo {
        fn with(mut self, source: &Source, versions: &[&str]) -> Self {
            let mut index = String::new();
            for version in versions {
                for package in PACKAGES {
                    let filename = format!("pool/{package}_{version}.deb");
                    let bytes = package.as_bytes().to_vec();
                    index += &format!(
                        "Package: {package}\nVersion: {version}\nFilename: {filename}\n\
                         Size: {}\nSHA256: {}\n\n",
                        bytes.len(),
                        sha(&bytes)
                    );
                    self.files.insert(Channel::deb_url(&filename), bytes);
                }
            }
            self.files.insert(
                source.channel.index_url(&source.codename, &source.arch),
                index.into_bytes(),
            );
            self
        }

        fn get(&self, url: &str) -> Result<&Vec<u8>> {
            self.fetched.borrow_mut().push(url.to_string());
            self.files.get(url).with_context(|| format!("404 {url}"))
        }
    }

    impl Fetch for FakeRepo {
        fn text(&self, url: &str) -> Result<String> {
            Ok(String::from_utf8(self.get(url)?.clone())?)
        }

        fn download(&self, url: &str, dest: &Path) -> Result<String> {
            let bytes = self.get(url)?;
            std::fs::write(dest, bytes)?;
            Ok(sha(bytes))
        }
    }

    /// `dpkg-deb -x <deb> <dir>`: writes `<dir>/usr/local/bin/<package>`,
    /// and `mina` for `mina-generic`.
    #[derive(Default)]
    struct FakeDpkg {
        lines: RefCell<Vec<String>>,
        fail: bool,
    }

    impl Runner for FakeDpkg {
        fn run(
            &self,
            program: &OsStr,
            args: &[&str],
            _: &[(&str, &str)],
        ) -> std::io::Result<Output> {
            self.lines.borrow_mut().push(format!(
                "{} {}",
                program.to_string_lossy(),
                args.join(" ")
            ));
            if self.fail {
                return Ok(crate::runner::fake::output(2, "", "bad deb"));
            }
            let package = std::fs::read_to_string(args[1])?;
            let bin = Path::new(args[2]).join(BIN_DIR);
            std::fs::create_dir_all(&bin)?;
            let name = if package == "mina-generic" {
                "mina"
            } else {
                &package
            };
            std::fs::write(bin.join(name), "")?;
            Ok(crate::runner::fake::output(0, "", ""))
        }
    }

    fn noble() -> Source {
        Source {
            channel: Channel::default(),
            codename: "noble".into(),
            arch: "amd64".into(),
        }
    }

    #[test]
    fn installs_a_version_once_side_by_side() {
        let tools = tempfile::tempdir().unwrap();
        let repo = FakeRepo::default().with(&noble(), &["4.0.2-84b8d96", "4.0.4-c9e2eac"]);
        let dpkg = FakeDpkg::default();

        let (installed, new) = install(tools.path(), &dpkg, &repo, "4.0.2", &noble()).unwrap();
        assert!(new);
        assert_eq!(installed.version, "4.0.2-84b8d96");
        assert_eq!(
            installed.bin_path(),
            tools.path().join("mina/4.0.2-84b8d96/usr/local/bin")
        );
        assert!(installed.bin_path().join("mina").is_file());
        assert!(installed.bin_path().join("mina-archive-generic").is_file());
        assert_eq!(dpkg.lines.borrow().len(), PACKAGES.len());
        assert!(dpkg.lines.borrow()[0].starts_with("dpkg-deb -x "));
        // the debs are gone, the install is recorded
        let downloads = tools.path().join("mina/.downloads");
        assert_eq!(std::fs::read_dir(downloads).unwrap().count(), 0);
        assert_eq!(installed.packages[0], "mina-generic 4.0.2-84b8d96");

        // installed: nothing is downloaded or unpacked again
        let (again, new) = install(tools.path(), &dpkg, &repo, "4.0.2", &noble()).unwrap();
        assert!(!new);
        assert_eq!(again, installed);
        assert_eq!(dpkg.lines.borrow().len(), PACKAGES.len());

        install(tools.path(), &dpkg, &repo, "latest", &noble()).unwrap();
        let all = super::installed(tools.path()).unwrap();
        let versions: Vec<&str> = all.iter().map(|i| i.version.as_str()).collect();
        assert_eq!(versions, ["4.0.2-84b8d96", "4.0.4-c9e2eac"]);
        assert_eq!(
            resolve(tools.path(), "latest").unwrap().version,
            "4.0.4-c9e2eac"
        );
        assert_eq!(
            resolve(tools.path(), "4.0.2-84b8d96").unwrap().bin_path(),
            installed.bin_path()
        );

        uninstall(&all[0]).unwrap();
        let err = resolve(tools.path(), "4.0.2").unwrap_err().to_string();
        assert_eq!(
            err,
            "mina 4.0.2 is not installed; run `minimina mina install 4.0.2` (installed: 4.0.4-c9e2eac)"
        );
    }

    #[test]
    fn a_failed_install_leaves_nothing() {
        let tools = tempfile::tempdir().unwrap();
        let repo = FakeRepo::default().with(&noble(), &["4.0.2-84b8d96"]);
        let dpkg = FakeDpkg {
            fail: true,
            ..Default::default()
        };
        let err = install(tools.path(), &dpkg, &repo, "4.0.2", &noble()).unwrap_err();
        assert!(format!("{err:#}").contains("bad deb"), "{err:#}");
        // stops at the first package
        assert_eq!(dpkg.lines.borrow().len(), 1);
        let left: Vec<_> = std::fs::read_dir(tools.path().join("mina"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [".downloads"]);
        assert_eq!(
            std::fs::read_dir(tools.path().join("mina/.downloads"))
                .unwrap()
                .count(),
            0
        );
        assert!(installed(tools.path()).unwrap().is_empty());
    }

    #[test]
    fn a_corrupt_download_is_rejected() {
        let tools = tempfile::tempdir().unwrap();
        let mut repo = FakeRepo::default().with(&noble(), &["4.0.2-84b8d96"]);
        // the index lies about the first package
        let url = Channel::default().index_url("noble", "amd64");
        let index = String::from_utf8(repo.files[&url].clone()).unwrap();
        let first = sha(b"mina-generic");
        repo.files
            .insert(url, index.replacen(&first, &"0".repeat(64), 1).into_bytes());
        let err = install(tools.path(), &FakeDpkg::default(), &repo, "4.0.2", &noble())
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match the index"), "{err}");
    }

    #[test]
    fn a_missing_version_says_where_it_is() {
        let tools = tempfile::tempdir().unwrap();
        let jammy = Source {
            codename: "jammy".into(),
            ..noble()
        };
        let repo = FakeRepo::default()
            .with(&noble(), &["4.0.4-c9e2eac"])
            .with(&jammy, &["4.0.2-84b8d96"]);
        let err = install(tools.path(), &FakeDpkg::default(), &repo, "4.0.2", &noble())
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "mina 4.0.2 is not in the stable channel for noble; available for: jammy; \
             noble has: 4.0.4-c9e2eac"
        );
    }

    #[test]
    fn an_unknown_channel_lists_the_channels() {
        let tools = tempfile::tempdir().unwrap();
        let mut repo = FakeRepo::default().with(&noble(), &["4.0.4-c9e2eac"]);
        repo.files.insert(
            apt::release_url("noble"),
            b"Codename: noble\nComponents: alpha stable\n".to_vec(),
        );
        let nightly = Source {
            channel: "nightly".parse().unwrap(),
            ..noble()
        };
        let err = install(
            tools.path(),
            &FakeDpkg::default(),
            &repo,
            "latest",
            &nightly,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "https://packages.o1test.net has no channel nightly for noble; channels: alpha, stable"
        );
    }
}
