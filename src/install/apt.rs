//! The apt repositories mina is published to, read without apt: the
//! `Packages` index of one codename, and the `.deb` files it points at.

use crate::version::Version;
use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};
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

/// The repository mina packages are installed from.
pub const REPOSITORY: &str = "https://packages.o1test.net";

/// A channel of [`REPOSITORY`]: one of its apt components (`stable`,
/// `unstable`, `alpha`, ...), which the `Release` file of a codename lists.
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

impl Channel {
    /// URL of the `Packages` index of `codename` for `arch`.
    pub fn index_url(&self, codename: &str, arch: &str) -> String {
        format!("{REPOSITORY}/dists/{codename}/{self}/binary-{arch}/Packages")
    }

    /// URL of a `.deb`, from the `Filename` of its index entry.
    pub fn deb_url(filename: &str) -> String {
        format!("{REPOSITORY}/{}", filename.trim_start_matches('/'))
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// URL of the `Release` file of `codename`, which lists its channels.
pub fn release_url(codename: &str) -> String {
    format!("{REPOSITORY}/dists/{codename}/Release")
}

/// The channels (`Components`) of a `Release` file.
pub fn channels(release: &str) -> Vec<String> {
    release
        .lines()
        .find_map(|l| l.strip_prefix("Components:"))
        .map(|c| c.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
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

/// Whether the package version `deb` is what the user asked for with `wanted`:
/// the whole version (`4.0.2-84b8d96`), or the release with the commit left
/// out (`4.0.2`). `4.0.0` does not match `4.0.0-mainnet-893c877`.
pub fn matches(deb: &str, wanted: &str) -> bool {
    deb == wanted
        || deb
            .strip_prefix(wanted)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|commit| {
                commit.len() >= 7 && commit.chars().all(|c| c.is_ascii_hexdigit())
            })
}

/// Sorts package versions oldest first: numerically by release, then as text.
pub fn sort_versions(versions: &mut [String]) {
    versions.sort_by(|a, b| {
        Version::parse(a)
            .cmp(&Version::parse(b))
            .then_with(|| a.cmp(b))
    });
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
    /// Parses the stanzas of an index; ones without the fields minimina
    /// needs are left out.
    pub fn parse(text: &str) -> Self {
        let entries = text
            .split("\n\n")
            .filter_map(|stanza| {
                let field = |name: &str| {
                    stanza.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        (key == name).then(|| value.trim().to_string())
                    })
                };
                Some(Entry {
                    package: field("Package")?,
                    version: field("Version")?,
                    filename: field("Filename")?,
                    size: field("Size")?.parse().ok()?,
                    sha256: field("SHA256")?.to_ascii_lowercase(),
                })
            })
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
            .filter(|v| self.release_of(v).is_some())
            .collect();
        sort_versions(&mut versions);
        versions.dedup();
        versions
    }

    fn release_of(&self, version: &str) -> Option<Release> {
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

    /// The release `wanted` (`4.0.2`, `4.0.2-84b8d96` or `latest`); `None`
    /// when the index has no such version.
    pub fn find(&self, wanted: &str) -> Result<Option<Release>> {
        let versions = self.versions();
        let found: Vec<&String> = if wanted == "latest" {
            versions.last().into_iter().collect()
        } else {
            versions.iter().filter(|v| matches(v, wanted)).collect()
        };
        match found.as_slice() {
            [] => Ok(None),
            [version] => Ok(self.release_of(version)),
            many => bail!(
                "mina {wanted} names several builds: {}; give the whole version",
                many.iter()
                    .map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
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
    fn channels_are_components_of_the_repository() {
        assert_eq!(
            Channel::default().index_url("noble", "amd64"),
            "https://packages.o1test.net/dists/noble/stable/binary-amd64/Packages"
        );
        let alpha: Channel = "alpha".parse().unwrap();
        assert_eq!(
            alpha.index_url("jammy", "arm64"),
            "https://packages.o1test.net/dists/jammy/alpha/binary-arm64/Packages"
        );
        assert_eq!(
            Channel::deb_url("pool/x.deb"),
            "https://packages.o1test.net/pool/x.deb"
        );
        assert!("../x".parse::<Channel>().is_err());
        assert!("".parse::<Channel>().is_err());
        assert_eq!(
            channels("Codename: noble\nComponents: alpha stable umt-no-upgrade\nSuite: x\n"),
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
        assert_eq!(
            index.find("latest").unwrap().unwrap().version,
            "4.0.10-aaaaaaa"
        );
        assert_eq!(index.find("4.0.3").unwrap(), None);
        let release = index.find("4.0.2").unwrap().unwrap();
        assert_eq!(release.debs.len(), PACKAGES.len());
        assert_eq!(release.size(), 400);
    }

    #[test]
    fn versions_match_with_or_without_the_commit() {
        assert!(matches("4.0.2-84b8d96", "4.0.2"));
        assert!(matches("4.0.2-84b8d96", "4.0.2-84b8d96"));
        assert!(!matches("4.0.20-84b8d96", "4.0.2"));
        assert!(!matches("4.0.0-mainnet-893c877", "4.0.0"));
        let index = index(&["3.2.0-49b523c", "3.2.0-97ad487"]);
        let err = index.find("3.2.0").unwrap_err();
        assert!(err.to_string().contains("several builds"), "{err}");
        assert!(index.find("3.2.0-97ad487").unwrap().is_some());
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
