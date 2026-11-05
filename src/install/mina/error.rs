use super::BIN_DIR;
use crate::install::apt::{Channel, Repository};

/// Why a mina version cannot be installed, used or removed.
#[derive(Debug, thiserror::Error)]
pub enum MinaError {
    #[error("mina {wanted} is not installed; run `minimina mina install {wanted}`{}",
        listed(" (installed: ", .installed, ")"))]
    NotInstalled {
        wanted: String,
        installed: Vec<String>,
    },
    #[error("mina {wanted} names several {what}: {}; give the whole version", .versions.join(", "))]
    Ambiguous {
        wanted: String,
        /// `builds` (of the index) or `installs`
        what: &'static str,
        versions: Vec<String>,
    },
    #[error("mina {wanted} is not in the {channel} channel for {codename}{}{}",
        listed("; available for: ", .elsewhere, ""),
        listed(&format!("; {codename} has: "), .recent, ""))]
    NotAvailable {
        wanted: String,
        channel: Channel,
        codename: String,
        /// Other codenames whose index has it.
        elsewhere: Vec<String>,
        /// The newest versions the index has.
        recent: Vec<String>,
    },
    #[error("{repository} has no channel {channel} for {codename}; channels: {}", .channels.join(", "))]
    UnknownChannel {
        repository: Repository,
        channel: Channel,
        codename: String,
        channels: Vec<String>,
    },
    #[error("{file} does not match the index: SHA-256 {found}, expected {expected}")]
    Checksum {
        file: String,
        found: String,
        expected: String,
    },
    #[error("the packages of mina {version} have no {BIN_DIR}/mina")]
    NoBinary { version: String },
    #[error("the mina binaries in {} cannot run here: missing libraries {}; {}",
        .bin_path.display(),
        .libraries.join(", "),
        match .version {
            Some(v) => format!("`minimina mina check {v}` lists the packages to install"),
            None => "install the packages that provide them".to_string(),
        })]
    MissingLibraries {
        bin_path: std::path::PathBuf,
        libraries: Vec<String>,
        /// The installed mina version of `bin_path`, if it is one.
        version: Option<String>,
    },
    #[error("mina {version} is used by network(s) {}; delete them first, or pass --force", .networks.join(", "))]
    InUse {
        version: String,
        networks: Vec<String>,
    },
}

/// `<before><items joined by ", "><after>`, or nothing without items.
fn listed(before: &str, items: &[String], after: &str) -> String {
    if items.is_empty() {
        String::new()
    } else {
        format!("{before}{}{after}", items.join(", "))
    }
}
