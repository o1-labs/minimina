//! Debian repositories, read without apt.
//!
//! - [`Repository`]: where the files of a repository are (`Release`,
//!   `Packages`, the debs).
//! - [`ControlFile`]: the `Field: value` format both index files are written in;
//!   [`ReleaseInfo`] and [`Index`] read what minimina needs from them.
//! - [`PackageVersion`]: the versions mina packages carry (`4.0.2-84b8d96`).

use crate::version::Version;
use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::Path;

/// The packages of one mina release that minimina installs.
///
/// Only `-generic` builds: the network packages (`mina-devnet`, ...) depend on
/// `mina-<net>-config`, whose `config_<commit>.json` the daemon merges into
/// every config, so a local network would get a public peer list and fork point.
pub const PACKAGES: [&str; 4] = [
    "mina-generic",
    "mina-archive-generic",
    "mina-rosetta-generic",
    "mina-logproc",
];

/// Codenames mina is built for, to say where a missing version is available.
pub const CODENAMES: [&str; 3] = ["noble", "jammy", "bookworm"];

/// A Debian repository: the URLs of its files.
///
/// ```text
/// <url>/dists/<codename>/Release                              ReleaseInfo
/// <url>/dists/<codename>/<channel>/binary-<arch>/Packages     Index
/// <url>/<Filename of an Index entry>                          a deb
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    url: String,
}

impl Repository {
    /// The repository mina packages are installed from.
    pub const O1TEST: &str = "https://packages.o1test.net";

    pub fn new(url: &str) -> Self {
        Repository {
            url: url.trim_end_matches('/').to_string(),
        }
    }

    pub fn release_url(&self, codename: &str) -> String {
        format!("{}/dists/{codename}/Release", self.url)
    }

    pub fn index_url(&self, codename: &str, channel: &Channel, arch: &str) -> String {
        format!(
            "{}/dists/{codename}/{channel}/binary-{arch}/Packages",
            self.url
        )
    }

    pub fn deb_url(&self, entry: &Entry) -> String {
        format!("{}/{}", self.url, entry.filename.trim_start_matches('/'))
    }
}

impl Default for Repository {
    fn default() -> Self {
        Repository::new(Self::O1TEST)
    }
}

impl std::fmt::Display for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.url)
    }
}

/// A channel of a [`Repository`]: one of its apt components (`stable`,
/// `unstable`, `alpha`, ...), which [`ReleaseInfo::channels`] lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Channel(String);

impl Default for Channel {
    fn default() -> Self {
        Channel("stable".into())
    }
}

impl std::str::FromStr for Channel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        // it goes into URLs
        if s.is_empty()
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(format!("'{s}' is not a channel name"));
        }
        Ok(Channel(s.to_string()))
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A file of `Field: value` stanzas separated by blank lines (deb822), as
/// `Release` and `Packages` are. A line that starts with a space continues
/// the field before it.
#[derive(Debug, Default)]
pub struct ControlFile {
    pub stanzas: Vec<Stanza>,
}

/// One stanza of a [`ControlFile`].
#[derive(Debug, Default)]
pub struct Stanza {
    fields: Vec<(String, String)>,
}

impl Stanza {
    /// The value of `name` (field names are case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl ControlFile {
    pub fn parse(text: &str) -> Self {
        let mut stanzas = vec![];
        let mut stanza = Stanza::default();
        for line in text.lines() {
            if line.trim().is_empty() {
                if !stanza.fields.is_empty() {
                    stanzas.push(std::mem::take(&mut stanza));
                }
            } else if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = stanza.fields.last_mut() {
                    value.push('\n');
                    value.push_str(line.trim());
                }
            } else if let Some((key, value)) = line.split_once(':') {
                stanza
                    .fields
                    .push((key.trim().to_string(), value.trim().to_string()));
            }
        }
        if !stanza.fields.is_empty() {
            stanzas.push(stanza);
        }
        ControlFile { stanzas }
    }
}

/// What minimina reads from the `Release` file of a codename.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// The channels (`Components`) the codename has.
    pub channels: Vec<String>,
}

impl ReleaseInfo {
    pub fn parse(text: &str) -> Self {
        let file = ControlFile::parse(text);
        let channels = file
            .stanzas
            .first()
            .and_then(|s| s.get("Components"))
            .map(|c| c.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        ReleaseInfo { channels }
    }
}

/// `VERSION_CODENAME` of an `os-release` file (`/etc/os-release`).
pub fn host_codename(os_release: &Path) -> Result<String> {
    let text = std::fs::read_to_string(os_release)
        .with_context(|| format!("reading {}", os_release.display()))?;
    text.lines()
        .find_map(|l| l.strip_prefix("VERSION_CODENAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
        .with_context(|| {
            format!(
                "{} has no VERSION_CODENAME; pass --codename",
                os_release.display()
            )
        })
}

/// Debian architecture of this build of minimina.
pub fn host_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => bail!("mina packages are not built for {other}"),
    }
}

/// The version of a mina package: a release and the commit it was built
/// from, `<release>-<commit>`. The release may have dashes of its own
/// (`4.0.0-mainnet-893c877`); a version without a commit is all release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageVersion<'a> {
    pub release: &'a str,
    pub commit: Option<&'a str>,
}

impl<'a> PackageVersion<'a> {
    pub fn parse(version: &'a str) -> Self {
        match version.rsplit_once('-') {
            Some((release, commit))
                if commit.len() >= 7 && commit.chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                PackageVersion {
                    release,
                    commit: Some(commit),
                }
            }
            _ => PackageVersion {
                release: version,
                commit: None,
            },
        }
    }

    /// Whether the user means this version by `wanted`: the whole version
    /// (`4.0.2-84b8d96`), or its release (`4.0.2`). `4.0.0` is not
    /// `4.0.0-mainnet-893c877`, whose release is `4.0.0-mainnet`.
    pub fn matches(&self, wanted: &str) -> bool {
        wanted == self.release
            || self
                .commit
                .is_some_and(|commit| wanted == format!("{}-{commit}", self.release))
    }

    /// Oldest first: numerically by release (`4.0.2` < `4.0.10`), then as text.
    pub fn compare(a: &str, b: &str) -> Ordering {
        let release = |v| Version::parse(PackageVersion::parse(v).release);
        release(a).cmp(&release(b)).then_with(|| a.cmp(b))
    }
}

/// The items of `all` (sorted oldest first) that `wanted` names: the newest
/// for `latest`, else those [`PackageVersion::matches`] picks.
pub fn select<'a, T>(all: &'a [T], version: impl Fn(&T) -> &str, wanted: &str) -> Vec<&'a T> {
    if wanted == "latest" {
        all.last().into_iter().collect()
    } else {
        all.iter()
            .filter(|item| PackageVersion::parse(version(item)).matches(wanted))
            .collect()
    }
}

/// One package of the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub package: String,
    pub version: String,
    /// Path of the `.deb` from the repository root.
    pub filename: String,
    pub size: u64,
    pub sha256: String,
}

impl Entry {
    /// `None` without the fields minimina needs.
    fn from_stanza(stanza: &Stanza) -> Option<Self> {
        Some(Entry {
            package: stanza.get("Package")?.to_string(),
            version: stanza.get("Version")?.to_string(),
            filename: stanza.get("Filename")?.to_string(),
            size: stanza.get("Size")?.parse().ok()?,
            sha256: stanza.get("SHA256")?.to_ascii_lowercase(),
        })
    }
}

/// The [`PACKAGES`] of one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub debs: Vec<Entry>,
}

impl Release {
    pub fn size(&self) -> u64 {
        self.debs.iter().map(|d| d.size).sum()
    }
}

/// A `Packages` index.
#[derive(Debug, Default)]
pub struct Index {
    entries: Vec<Entry>,
}

impl Index {
    pub fn parse(text: &str) -> Self {
        let entries = ControlFile::parse(text)
            .stanzas
            .iter()
            .filter_map(Entry::from_stanza)
            .collect();
        Index { entries }
    }

    /// Versions that have every one of [`PACKAGES`], oldest first.
    pub fn versions(&self) -> Vec<String> {
        let mut versions: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.package == PACKAGES[0])
            .map(|e| e.version.clone())
            .filter(|v| self.release(v).is_some())
            .collect();
        versions.sort_by(|a, b| PackageVersion::compare(a, b));
        versions.dedup();
        versions
    }

    /// The packages of `version` (a whole version), if the index has them all.
    pub fn release(&self, version: &str) -> Option<Release> {
        let debs = PACKAGES
            .iter()
            .map(|p| {
                self.entries
                    .iter()
                    .find(|e| e.package == *p && e.version == version)
                    .cloned()
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Release {
            version: version.to_string(),
            debs,
        })
    }

    /// The releases `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`) names.
    pub fn select(&self, wanted: &str) -> Vec<Release> {
        let versions = self.versions();
        select(&versions, |v| v, wanted)
            .into_iter()
            .filter_map(|v| self.release(v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(package: &str, version: &str) -> String {
        format!(
            "Package: {package}\nVersion: {version}\nDepends: libssl3t64, libgmp10\n\
             Filename: pool/noble/m/mi/{package}_{version}_amd64.deb\nSize: 100\n\
             SHA256: ABC{version}\nDescription: x\n built from y\n"
        )
    }

    fn index(versions: &[&str]) -> Index {
        let text: Vec<String> = versions
            .iter()
            .flat_map(|v| PACKAGES.iter().map(move |p| stanza(p, v)))
            .collect();
        Index::parse(&text.join("\n"))
    }

    #[test]
    fn repository_urls() {
        let repo = Repository::default();
        let alpha: Channel = "alpha".parse().unwrap();
        assert_eq!(
            repo.release_url("noble"),
            "https://packages.o1test.net/dists/noble/Release"
        );
        assert_eq!(
            repo.index_url("jammy", &alpha, "arm64"),
            "https://packages.o1test.net/dists/jammy/alpha/binary-arm64/Packages"
        );
        let entry = &index(&["4.0.2-84b8d96"]).entries[0];
        assert_eq!(
            Repository::new("http://x/").deb_url(entry),
            "http://x/pool/noble/m/mi/mina-generic_4.0.2-84b8d96_amd64.deb"
        );
        assert!("../x".parse::<Channel>().is_err());
        assert!("".parse::<Channel>().is_err());
    }

    #[test]
    fn control_files_parse() {
        let file = ControlFile::parse(
            "Codename: noble\nComponents: alpha stable\nMD5Sum:\n abc 1 x\n def 2 y\n\n\nPackage: a\n",
        );
        assert_eq!(file.stanzas.len(), 2);
        assert_eq!(file.stanzas[0].get("components"), Some("alpha stable"));
        assert_eq!(file.stanzas[0].get("MD5Sum"), Some("\nabc 1 x\ndef 2 y"));
        assert_eq!(file.stanzas[1].get("Package"), Some("a"));
        assert_eq!(
            ReleaseInfo::parse("Codename: noble\nComponents: alpha stable umt-no-upgrade\n")
                .channels,
            ["alpha", "stable", "umt-no-upgrade"]
        );
    }

    #[test]
    fn index_stanzas_parse() {
        let index = Index::parse(&stanza("mina-generic", "4.0.2-84b8d96"));
        assert_eq!(
            index.entries,
            vec![Entry {
                package: "mina-generic".into(),
                version: "4.0.2-84b8d96".into(),
                filename: "pool/noble/m/mi/mina-generic_4.0.2-84b8d96_amd64.deb".into(),
                size: 100,
                sha256: "abc4.0.2-84b8d96".into(),
            }]
        );
        // a stanza without a size is skipped
        assert!(Index::parse("Package: a\nVersion: 1\n").entries.is_empty());
    }

    #[test]
    fn versions_need_every_package_and_sort_numerically() {
        let mut text = index(&["4.0.10-aaaaaaa", "4.0.2-84b8d96"])
            .entries
            .iter()
            .map(|e| stanza(&e.package, &e.version))
            .collect::<Vec<_>>();
        // 4.0.3 has no archive package
        text.push(stanza("mina-generic", "4.0.3-73134bf"));
        let index = Index::parse(&text.join("\n"));
        assert_eq!(index.versions(), ["4.0.2-84b8d96", "4.0.10-aaaaaaa"]);
        assert_eq!(index.select("latest")[0].version, "4.0.10-aaaaaaa");
        assert!(index.select("4.0.3").is_empty());
        let release = index.release("4.0.2-84b8d96").unwrap();
        assert_eq!(release.debs.len(), PACKAGES.len());
        assert_eq!(release.size(), 400);
    }

    #[test]
    fn package_versions_match_with_or_without_the_commit() {
        assert_eq!(
            PackageVersion::parse("4.0.0-mainnet-893c877"),
            PackageVersion {
                release: "4.0.0-mainnet",
                commit: Some("893c877")
            }
        );
        assert_eq!(PackageVersion::parse("4.0.2").commit, None);
        let matches = |v, wanted| PackageVersion::parse(v).matches(wanted);
        assert!(matches("4.0.2-84b8d96", "4.0.2"));
        assert!(matches("4.0.2-84b8d96", "4.0.2-84b8d96"));
        assert!(!matches("4.0.20-84b8d96", "4.0.2"));
        assert!(!matches("4.0.0-mainnet-893c877", "4.0.0"));
        let index = index(&["3.2.0-49b523c", "3.2.0-97ad487"]);
        assert_eq!(index.select("3.2.0").len(), 2);
        assert_eq!(index.select("3.2.0-97ad487")[0].version, "3.2.0-97ad487");
    }

    #[test]
    fn codename_comes_from_os_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        std::fs::write(&path, "NAME=\"Ubuntu\"\nVERSION_CODENAME=noble\n").unwrap();
        assert_eq!(host_codename(&path).unwrap(), "noble");
        std::fs::write(&path, "NAME=x\n").unwrap();
        assert!(host_codename(&path)
            .unwrap_err()
            .to_string()
            .contains("--codename"));
    }
}
