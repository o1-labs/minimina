use super::{Channel, Entry};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
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
        let entry = Entry {
            package: "mina-generic".into(),
            version: "4.0.2-84b8d96".into(),
            filename: "/pool/noble/m/mi/mina-generic_4.0.2-84b8d96_amd64.deb".into(),
            size: 100,
            sha256: "abc".into(),
            depends: vec![],
        };
        assert_eq!(
            Repository::new("http://x/").deb_url(&entry),
            "http://x/pool/noble/m/mi/mina-generic_4.0.2-84b8d96_amd64.deb"
        );
    }
}
