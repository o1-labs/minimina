use serde::Deserialize;

/// A GitHub release of the accounts manager, as the GitHub API gives it.
#[derive(Debug, Deserialize)]
pub struct Release {
    pub assets: Vec<Asset>,
}

/// A file of a release: the binary of one architecture.
#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
    /// `sha256:<hex>`.
    pub digest: Option<String>,
}

impl Release {
    /// The GitHub API URL of release `v<version>`.
    pub fn url(version: &str) -> String {
        format!(
            "https://api.github.com/repos/o1-labs/mina-accounts-manager/releases/tags/v{version}"
        )
    }

    /// The binary for `arch` (amd64, arm64).
    pub fn binary(&self, arch: &str) -> Option<&Asset> {
        let name = format!("accounts-manager-{arch}");
        self.assets.iter().find(|a| a.name == name)
    }
}

impl Asset {
    /// The SHA-256 (hex) GitHub computed of the file.
    pub fn sha256(&self) -> Option<&str> {
        self.digest.as_deref()?.strip_prefix("sha256:")
    }
}
