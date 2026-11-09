use super::{DataConfig, RosettaError};
use mina_rosetta_sdk::NetworkIdentifier;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{fs, io, path::Path, path::PathBuf};

/// A rosetta-cli configuration file, as the mina package ships it
/// (`etc/mina/rosetta/rosetta-cli-config/config.json`). The fields minimina
/// sets are typed; the others (timeouts, concurrency, ...) are kept as the
/// package has them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RosettaCliConfig {
    pub network: NetworkIdentifier,
    pub online_url: String,
    pub data_directory: PathBuf,
    /// `check:construction`'s settings; `check:data` does not need them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub construction: Option<Value>,
    #[serde(default)]
    pub data: DataConfig,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl RosettaCliConfig {
    pub fn read(path: &Path) -> Result<Self, RosettaError> {
        let text = fs::read_to_string(path).map_err(|cause| match cause.kind() {
            io::ErrorKind::NotFound => RosettaError::NoTemplate(path.to_path_buf()),
            _ => RosettaError::Io {
                path: path.to_path_buf(),
                cause,
            },
        })?;
        serde_json::from_str(&text).map_err(|cause| RosettaError::Json {
            path: path.to_path_buf(),
            cause,
        })
    }

    pub fn write(&self, path: &Path) -> Result<(), RosettaError> {
        let text = serde_json::to_string_pretty(self).map_err(|cause| RosettaError::Json {
            path: path.to_path_buf(),
            cause,
        })?;
        fs::write(path, text).map_err(|cause| RosettaError::Io {
            path: path.to_path_buf(),
            cause,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config of the mina package (4.0.4), shortened.
    const PACKAGE_CONFIG: &str = r#"{
        "network": {"blockchain": "mina", "network": "PLACEHOLDER_NETWORK_NAME"},
        "online_url": "http://localhost:PLACEHOLDER_ROSETTA_ONLINE_PORT",
        "data_directory": "",
        "http_timeout": 300,
        "max_retries": 5,
        "construction": {"offline_url": "http://localhost:PLACEHOLDER_ROSETTA_OFFLINE_PORT"},
        "data": {
            "active_reconciliation_concurrency": 16,
            "results_output_file": "",
            "end_conditions": {"reconciliation_coverage": {"from_tip": true, "coverage": 1.0}}
        },
        "perf": null
    }"#;

    #[test]
    fn the_package_config_is_read_and_written_back_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, PACKAGE_CONFIG).unwrap();
        let config = RosettaCliConfig::read(&path).unwrap();
        assert_eq!(config.network.network, "PLACEHOLDER_NETWORK_NAME");
        assert_eq!(config.data.start_index, None);

        let copy = dir.path().join("copy.json");
        config.write(&copy).unwrap();
        let written: Value = serde_json::from_str(&fs::read_to_string(&copy).unwrap()).unwrap();
        let original: Value = serde_json::from_str(PACKAGE_CONFIG).unwrap();
        assert_eq!(written, original);
    }

    #[test]
    fn a_missing_config_is_a_missing_template() {
        let err = RosettaCliConfig::read(Path::new("/nonexistent/config.json")).unwrap_err();
        assert!(matches!(err, RosettaError::NoTemplate(_)), "{err}");
    }
}
