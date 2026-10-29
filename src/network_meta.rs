//! `minimina.json`: how a network was created, so later commands use the same mode.

use crate::cli::{ExecutionMode, Profile};
use crate::daemon_args::DaemonFeatures;
use crate::hardfork::{ForkMethod, HardforkMode};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const FILE: &str = "minimina.json";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NetworkMeta {
    pub mode: ExecutionMode,
    /// Directory of the `mina` binaries (native mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_path: Option<PathBuf>,
    /// Postgres server URI without database (native archive nodes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_uri: Option<String>,
    /// Build profile of the mina processes; networks created before it was
    /// recorded use the default.
    #[serde(default)]
    pub profile: Profile,
    /// Version-dependent daemon flags, probed at create.
    #[serde(default)]
    pub features: DaemonFeatures,
    /// The first `network start` sets the genesis timestamp, so that the
    /// first slots are not gone before the daemons run.
    #[serde(default)]
    pub genesis_pending: bool,
    /// The `[hardfork]` of the spec, checked at create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardfork: Option<HardforkMeta>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HardforkMeta {
    pub mode: HardforkMode,
    /// Manual mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ForkMethod>,
    /// Directory of the postfork binaries.
    pub postfork_bin_path: PathBuf,
}

impl NetworkMeta {
    /// Reads the metadata; `None` for networks created before it was recorded.
    pub fn load(network_path: &Path) -> io::Result<Option<Self>> {
        let path = network_path.join(FILE);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)?;
        serde_json::from_str(&data).map(Some).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }

    pub fn save(&self, network_path: &Path) -> io::Result<()> {
        let data = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(network_path.join(FILE), data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_absence() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(NetworkMeta::load(dir.path()).unwrap(), None);

        let meta = NetworkMeta {
            mode: ExecutionMode::Native,
            bin_path: Some("/usr/bin".into()),
            postgres_uri: None,
            profile: Profile::Lightnet,
            features: DaemonFeatures {
                precomputed_blocks_dir: true,
                hardfork_handling: false,
            },
            genesis_pending: true,
            hardfork: Some(HardforkMeta {
                mode: HardforkMode::Manual,
                method: Some(ForkMethod::Legacy),
                postfork_bin_path: "/opt/post".into(),
            }),
        };
        meta.save(dir.path()).unwrap();
        assert_eq!(NetworkMeta::load(dir.path()).unwrap(), Some(meta));
        let raw = fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(raw.contains("\"mode\": \"native\""));
        assert!(!raw.contains("postgres_uri"));
        assert!(raw.contains("\"profile\": \"lightnet\""));
    }

    #[test]
    fn missing_profile_defaults_to_devnet() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), "{\"mode\":\"native\"}").unwrap();
        let meta = NetworkMeta::load(dir.path()).unwrap().unwrap();
        assert_eq!(meta.profile, Profile::Devnet);
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), "{\"mode\":\"kvm\"}").unwrap();
        assert!(NetworkMeta::load(dir.path()).is_err());
    }
}
