//! [`install`] against a fake repository and a fake `dpkg-deb`.

use super::*;
use crate::install::apt::{self, Channel, Repository, PACKAGES};
use crate::runner::Runner;
use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
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
                let entry = apt::Entry {
                    package: package.to_string(),
                    version: version.to_string(),
                    filename: filename.clone(),
                    size: 0,
                    sha256: String::new(),
                };
                self.files.insert(source.repository.deb_url(&entry), bytes);
            }
        }
        self.files.insert(
            source
                .repository
                .index_url(&source.codename, &source.channel, &source.arch),
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
    fn run(&self, program: &OsStr, args: &[&str], _: &[(&str, &str)]) -> std::io::Result<Output> {
        if args == ["--version"] {
            let version = "Debian 'dpkg-deb' package management program version 1.22.6 (amd64).";
            return Ok(crate::runner::fake::output(0, version, ""));
        }
        self.lines
            .borrow_mut()
            .push(format!("{} {}", program.to_string_lossy(), args.join(" ")));
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
        repository: Repository::default(),
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
fn dpkg_deb_is_required_before_anything_is_downloaded() {
    let tools = tempfile::tempdir().unwrap();
    let repo = FakeRepo::default().with(&noble(), &["4.0.2-84b8d96"]);
    let runner = crate::runner::fake::FakeRunner::default();
    runner.reply_err(std::io::ErrorKind::NotFound);
    let err = install(tools.path(), &runner, &repo, "4.0.2", &noble()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "dpkg-deb is required, but `dpkg-deb` was not found. Install the dpkg package."
    );
    // only the index was fetched
    assert_eq!(repo.fetched.borrow().len(), 1);
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
    let url = Repository::default().index_url("noble", &Channel::default(), "amd64");
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
        Repository::default().release_url("noble"),
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
