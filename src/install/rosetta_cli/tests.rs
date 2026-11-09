//! [`resolve`] against a fake repository and a fake `dpkg-deb`.

use super::*;
use crate::runner::fake::output;
use anyhow::Context as _;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, ffi::OsStr, process::Output};

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The stable noble index of packages.o1test.net, and the URLs asked for.
#[derive(Default)]
struct FakeRepo {
    files: BTreeMap<String, Vec<u8>>,
    fetched: RefCell<Vec<String>>,
}

impl FakeRepo {
    fn source() -> Source {
        Source {
            repository: Repository::default(),
            channel: Channel::default(),
            codename: "noble".into(),
            arch: apt::host_arch().unwrap().into(),
        }
    }

    fn deb() -> Entry {
        let arch = apt::host_arch().unwrap();
        Entry {
            package: PACKAGE.into(),
            version: VERSION.into(),
            filename: format!("pool/noble/m/mi/{PACKAGE}_{VERSION}_{arch}.deb"),
            size: 0,
            sha256: String::new(),
            depends: vec![],
        }
    }

    /// An index of `packages` (name, version), whose deb is `deb` with the
    /// SHA-256 of `indexed`.
    fn with(packages: &[(&str, &str)], deb: &[u8], indexed: &[u8]) -> Self {
        let source = Self::source();
        let index: String = packages
            .iter()
            .map(|(package, version)| {
                format!(
                    "Package: {package}\nVersion: {version}\nFilename: {}\nSize: {}\nSHA256: {}\n\n",
                    Self::deb().filename,
                    deb.len(),
                    sha256(indexed)
                )
            })
            .collect();
        let mut repo = FakeRepo::default();
        let index_url =
            source
                .repository
                .index_url(&source.codename, &source.channel, &source.arch);
        repo.files.insert(index_url, index.into_bytes());
        repo.files
            .insert(source.repository.deb_url(&Self::deb()), deb.to_vec());
        repo
    }

    fn published(deb: &[u8]) -> Self {
        Self::with(&[(PACKAGE, VERSION)], deb, deb)
    }

    fn get(&self, url: &str) -> anyhow::Result<&Vec<u8>> {
        self.fetched.borrow_mut().push(url.to_string());
        self.files.get(url).with_context(|| format!("404 {url}"))
    }
}

impl Fetch for FakeRepo {
    fn text(&self, url: &str) -> anyhow::Result<String> {
        Ok(String::from_utf8(self.get(url)?.clone())?)
    }

    fn download(&self, url: &str, dest: &Path) -> anyhow::Result<String> {
        let bytes = self.get(url)?;
        fs::write(dest, bytes)?;
        Ok(sha256(bytes))
    }
}

/// `dpkg-deb -x <deb> <dir>`: a deb is the path it holds, written under `dir`.
#[derive(Default)]
struct FakeDpkg {
    unpacked: RefCell<usize>,
}

impl Runner for FakeDpkg {
    fn run(&self, _: &OsStr, args: &[&str], _: &[(&str, &str)]) -> io::Result<Output> {
        if args == ["--version"] {
            let version = "Debian 'dpkg-deb' package management program version 1.22.6 (amd64).";
            return Ok(output(0, version, ""));
        }
        *self.unpacked.borrow_mut() += 1;
        let path = Path::new(args[2]).join(fs::read_to_string(args[1])?);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, "")?;
        Ok(output(0, "", ""))
    }
}

/// A tools directory, and an os-release of noble.
fn host() -> (tempfile::TempDir, PathBuf) {
    let tools = tempfile::tempdir().unwrap();
    let os_release = tools.path().join("os-release");
    fs::write(&os_release, "VERSION_CODENAME=noble\n").unwrap();
    (tools, os_release)
}

fn left_in(tools: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(tools.join(TOOL))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_given_rosetta_cli_is_not_installed() {
    let (tools, os_release) = host();
    let given = Path::new("/opt/rosetta-cli");
    let program = resolve(
        tools.path(),
        Some(given),
        &os_release,
        &FakeRepo::default(),
        &FakeDpkg::default(),
    )
    .unwrap();
    assert_eq!(program, given);
}

#[test]
fn rosetta_cli_is_installed_once_from_its_deb() {
    let (tools, os_release) = host();
    let repo = FakeRepo::published(BIN.as_bytes());
    let dpkg = FakeDpkg::default();
    let program = resolve(tools.path(), None, &os_release, &repo, &dpkg).unwrap();
    assert_eq!(
        program,
        tools
            .path()
            .join("rosetta-cli/0.10.1-stake-delegation-v1/usr/bin/rosetta-cli")
    );
    assert!(program.is_file());
    assert_eq!(left_in(tools.path()), [".downloads", VERSION]);
    assert_eq!(
        fs::read_dir(tools.path().join(TOOL).join(DOWNLOADS))
            .unwrap()
            .count(),
        0
    );

    // the next run finds it
    let fetched = repo.fetched.borrow().len();
    resolve(tools.path(), None, &os_release, &repo, &dpkg).unwrap();
    assert_eq!(repo.fetched.borrow().len(), fetched);
    assert_eq!(*dpkg.unpacked.borrow(), 1);
}

#[test]
fn a_deb_with_another_checksum_is_not_unpacked() {
    let (tools, os_release) = host();
    let repo = FakeRepo::with(&[(PACKAGE, VERSION)], BIN.as_bytes(), b"the real deb");
    let dpkg = FakeDpkg::default();
    let err = resolve(tools.path(), None, &os_release, &repo, &dpkg).unwrap_err();
    assert!(
        matches!(err, RosettaCliError::ChecksumMismatch { .. }),
        "{err}"
    );
    assert_eq!(*dpkg.unpacked.borrow(), 0);
    assert_eq!(left_in(tools.path()), [".downloads"]);
}

#[test]
fn a_deb_without_rosetta_cli_leaves_nothing() {
    let (tools, os_release) = host();
    let repo = FakeRepo::published(b"usr/local/bin/rosetta-cli");
    let err = resolve(tools.path(), None, &os_release, &repo, &FakeDpkg::default())
        .unwrap_err()
        .to_string();
    assert!(err.ends_with("has no usr/bin/rosetta-cli"), "{err}");
    assert_eq!(left_in(tools.path()), [".downloads"]);
}

#[test]
fn an_unpublished_version_says_where_it_was_looked_for() {
    let (tools, os_release) = host();
    let repo = FakeRepo::with(&[(PACKAGE, "0.10.3-x")], b"", b"");
    let err = resolve(tools.path(), None, &os_release, &repo, &FakeDpkg::default())
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        format!(
            "mina-rosetta-cli 0.10.1-stake-delegation-v1 is not in the stable packages of \
             https://packages.o1test.net for noble {}: give the path of a rosetta-cli to \
             --rosetta-cli",
            apt::host_arch().unwrap()
        )
    );
}
