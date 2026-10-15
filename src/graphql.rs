use log::info;

use crate::{directory_manager::DirectoryManager, output::network, utils::TIMEOUT_IN_SECS};
use std::io::{Error, ErrorKind, Result};

pub struct GraphQl {
    directory_manager: DirectoryManager,
}

impl GraphQl {
    pub fn new(directory_manager: DirectoryManager) -> Self {
        Self { directory_manager }
    }

    /// Returns the node's GraphQL URI, or `None` if the network or node has none.
    pub fn get_endpoint(&self, node_id: &str, network_id: &str) -> Result<Option<String>> {
        let Ok(nodes) = self.directory_manager.get_network_info(network_id) else {
            return Ok(None);
        };
        let info = serde_json::from_str::<network::Create>(&nodes).map_err(Error::from)?;
        Ok(info
            .nodes
            .get(node_id)
            .and_then(|node| node.graphql_uri.clone()))
    }

    /// Waits for graphql server to start
    pub fn wait_for_server(&self, gql_ep: &str) -> Result<()> {
        let mut retries = 0;
        let mut graphql_running = false;
        info!("Waiting for graphql to start '{gql_ep}'");
        let client = reqwest::blocking::Client::new();

        while !graphql_running && retries < TIMEOUT_IN_SECS {
            let response = client
                .get(gql_ep)
                .header("Content-Type", "application/json")
                .send();

            if response.is_ok() {
                graphql_running = true;
            } else {
                retries += 1;
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        if !graphql_running {
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("Failed to start graphql '{gql_ep}' within {TIMEOUT_IN_SECS}s"),
            ));
        }
        Ok(())
    }

    /// Requests filtered logs via graphql
    pub fn request_filtered_logs(&self, gql_ep: &str) -> Result<()> {
        // Filtered logs request payload
        let query = r#"{
        "query": "mutation MyMutation 
                    { startFilteredLog(filter: [\"21ccae8c619bc2666474085272d5fe1d\", 
                                                \"ef1182dc30f3e0aa9f6bf11c0ab90ba6\",
                                                \"64e2d3e86c37c09b15efdaf7470ce879\",
                                                \"db06cb5030f39e86e84b30d033f3bc5c\", 
                                                \"60076de624bf0c5fc0843b875001cf84\", 
                                                \"27953f46376ba8abc0c61400e2c38f8b\", 
                                                \"b4b5f5b1d1a0c457cbd13a35d1c8b57b\", 
                                                \"0fc65f5594c5e9ee0b6f0ddde747c758\", 
                                                \"b5a89d6d616a35fb6f73d1eaad6b2dbd\", 
                                                \"1c4150aa7058a3058c4d20ae90ff7ec3\", 
                                                \"f7254e63ad51092a0bd3078580ef9ce3\", 
                                                \"74a81f1e2f8d548e4550faa136c68160\", 
                                                \"30fe76cee159ea215fc05549e861501e\"]) }"
    }"#;

        let client = reqwest::blocking::Client::new();
        info!("Sending request to: {gql_ep}");
        let response = client
            .post(gql_ep)
            .header("Content-Type", "application/json")
            .body(query)
            .send()
            .map_err(|e| {
                Error::other(format!(
                    "Failed to send request to graphql endpoint '{gql_ep}': {e}"
                ))
            })?;

        let response_body = response.text().map_err(|e| {
            Error::other(format!(
                "Failed to read response body from graphql endpoint '{gql_ep}': {e}"
            ))
        })?;
        info!("Response body: {response_body}");

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_get_endpoint() {
        use super::*;
        use crate::directory_manager::DirectoryManager;
        use std::fs::File;
        use std::io::Write;
        use std::path::PathBuf;

        let tempdir = tempfile::Builder::new()
            .prefix("test_get_endpoint")
            .tempdir()
            .expect("Cannot create temporary directory");
        let network_info_str = "{
            \"network_id\": \"test_deserialize\",
            \"nodes\": {
                \"mina-archive\": {
                    \"graphql_uri\": null,
                    \"private_key\": null,
                    \"node_type\": \"Archive_node\"
                },
                \"mina-snark-coordinator\": {
                    \"graphql_uri\": \"http://localhost:7001/graphql\",
                    \"private_key\": null,
                    \"node_type\": \"Snark_coordinator\"
                },
                \"mina-bp-1\": {
                    \"graphql_uri\": \"http://localhost:4001/graphql\",
                    \"private_key\": null,
                    \"node_type\": \"Block_producer\"
                },
                \"mina-bp-2\": {
                    \"graphql_uri\": \"http://localhost:4006/graphql\",
                    \"private_key\": null,
                    \"node_type\": \"Block_producer\"
                },
                \"mina-seed-1\": {
                    \"graphql_uri\": \"http://localhost:3101/graphql\",
                    \"private_key\": null,
                    \"node_type\": \"Seed_node\"
                },
                \"mina-snark-worker-1\": {
                    \"graphql_uri\": null,
                    \"private_key\": null,
                    \"node_type\": \"Snark_worker\"
                }
            }
        }";
        let base_path = PathBuf::from(tempdir.path());
        let network_id = "test_deserialize";
        let directory_manager = DirectoryManager::with_base_path(base_path);
        directory_manager
            .create_network_directory(network_id)
            .unwrap();
        let network_info_file = directory_manager.network_file_path(network_id);
        let mut file = File::create(&network_info_file).unwrap();
        file.write_all(network_info_str.as_bytes()).unwrap();

        let graphql = GraphQl::new(directory_manager);

        let endpoint = graphql.get_endpoint("mina-bp-1", network_id).unwrap();
        assert_eq!(endpoint.as_deref(), Some("http://localhost:4001/graphql"));

        let endpoint = graphql.get_endpoint("mina-bp-2", network_id).unwrap();
        assert_eq!(endpoint.as_deref(), Some("http://localhost:4006/graphql"));

        let endpoint = graphql
            .get_endpoint("mina-snark-worker-1", network_id)
            .unwrap();
        assert_eq!(endpoint, None);

        let endpoint = graphql
            .get_endpoint("mina-bp-1", "no-such-network")
            .unwrap();
        assert_eq!(endpoint, None);

        std::fs::write(&network_info_file, "{").unwrap();
        assert!(graphql.get_endpoint("mina-bp-1", network_id).is_err());
    }
}
