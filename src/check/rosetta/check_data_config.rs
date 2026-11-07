use super::api::NetworkIdentifier;
use serde_json::{json, Value};
use std::path::PathBuf;

/// What minimina sets in the rosetta-cli config the mina package ships
/// (`etc/mina/rosetta/rosetta-cli-config/config.json`), the one mina CI runs
/// `check:data` with. The `construction` section is left out.
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
    pub fn apply(&self, mut template: Value) -> Value {
        template["network"] = json!(self.network);
        template["online_url"] = json!(self.online_url);
        template["data_directory"] = json!(self.data_directory);
        if let Some(config) = template.as_object_mut() {
            config.remove("construction");
        }
        let data = &mut template["data"];
        data["results_output_file"] = json!(self.results_file);
        if let Some(start) = self.start_index {
            data["start_index"] = json!(start);
        }
        template
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_package_template_gets_the_network_and_the_files() {
        let template = json!({
            "network": {"blockchain": "mina", "network": "PLACEHOLDER_NETWORK_NAME"},
            "online_url": "http://localhost:PLACEHOLDER_ROSETTA_ONLINE_PORT",
            "data_directory": "",
            "construction": {"offline_url": "x"},
            "data": {"interesting_accounts": "", "end_conditions": {"reconciliation_coverage": {"coverage": 1.0}}}
        });
        let config = CheckDataConfig {
            online_url: "http://localhost:3140".into(),
            network: NetworkIdentifier {
                blockchain: "mina".into(),
                network: "testnet".into(),
            },
            data_directory: "/net/rosetta-cli/data".into(),
            results_file: "/net/rosetta-cli/results.json".into(),
            start_index: Some(2),
        }
        .apply(template);
        assert_eq!(config["network"]["network"], "testnet");
        assert_eq!(config["online_url"], "http://localhost:3140");
        assert_eq!(config["data_directory"], "/net/rosetta-cli/data");
        assert!(config.get("construction").is_none());
        assert_eq!(
            config["data"]["results_output_file"],
            "/net/rosetta-cli/results.json"
        );
        assert_eq!(config["data"]["start_index"], 2);
        assert_eq!(
            config["data"]["end_conditions"]["reconciliation_coverage"]["coverage"],
            1.0
        );
    }
}
