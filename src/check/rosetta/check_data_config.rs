use super::RosettaCliConfig;
use mina_rosetta_sdk::NetworkIdentifier;
use std::path::PathBuf;

/// What minimina sets in the rosetta-cli config the mina package ships, the
/// one mina CI runs `check:data` with. The `construction` section is left
/// out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckDataConfig {
    pub online_url: String,
    pub network: NetworkIdentifier,
    pub data_directory: PathBuf,
    pub results_file: PathBuf,
    /// The first block to sync; default: rosetta's genesis.
    pub start_index: Option<u64>,
}

impl CheckDataConfig {
    pub fn apply(&self, template: RosettaCliConfig) -> RosettaCliConfig {
        let mut config = RosettaCliConfig {
            network: self.network.clone(),
            online_url: self.online_url.clone(),
            data_directory: self.data_directory.clone(),
            construction: None,
            ..template
        };
        config.data.results_output_file = self.results_file.clone();
        config.data.start_index = self.start_index.or(config.data.start_index);
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::rosetta::DataConfig;
    use serde_json::json;

    #[test]
    fn the_package_template_gets_the_network_and_the_files() {
        let template: RosettaCliConfig = serde_json::from_value(json!({
            "network": {"blockchain": "mina", "network": "PLACEHOLDER_NETWORK_NAME"},
            "online_url": "http://localhost:PLACEHOLDER_ROSETTA_ONLINE_PORT",
            "data_directory": "",
            "http_timeout": 300,
            "construction": {"offline_url": "x"},
            "data": {"results_output_file": "", "end_conditions": {"reconciliation_coverage": {"coverage": 1.0}}}
        }))
        .unwrap();
        let config = CheckDataConfig {
            online_url: "http://localhost:3140".into(),
            network: NetworkIdentifier::mina("testnet"),
            data_directory: "/net/rosetta-cli/data".into(),
            results_file: "/net/rosetta-cli/results.json".into(),
            start_index: Some(2),
        }
        .apply(template);
        assert_eq!(config.network, NetworkIdentifier::mina("testnet"));
        assert_eq!(config.online_url, "http://localhost:3140");
        assert_eq!(
            config.data_directory,
            PathBuf::from("/net/rosetta-cli/data")
        );
        assert_eq!(config.construction, None);
        // what minimina does not set stays as the package has it
        assert_eq!(config.other["http_timeout"], 300);
        let DataConfig {
            results_output_file,
            start_index,
            other,
        } = config.data;
        assert_eq!(
            results_output_file,
            PathBuf::from("/net/rosetta-cli/results.json")
        );
        assert_eq!(start_index, Some(2));
        assert_eq!(
            other["end_conditions"]["reconciliation_coverage"]["coverage"],
            1.0
        );
    }
}
