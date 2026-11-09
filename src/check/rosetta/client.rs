use super::RosettaError;
use mina_rosetta_sdk::{AccountBalanceResponse, NetworkIdentifier, NetworkStatusResponse};
use tokio::runtime::Runtime;

/// The Rosetta API of a network's `mina-rosetta`, through `mina-rosetta-sdk`.
///
/// The SDK is async and minimina is not, so each method blocks: the client
/// keeps a single-threaded tokio runtime and waits on it for the SDK's
/// future (`Runtime::block_on`), as [`crate::node_client`] does for the
/// daemon and archive SDKs.
pub struct RosettaClient {
    client: mina_rosetta_sdk::RosettaClient,
    runtime: Runtime,
}

impl RosettaClient {
    /// The rosetta at `port`, for the network it serves (the first of
    /// `/network/list`).
    pub fn connect(port: u16) -> Result<Self, RosettaError> {
        let runtime =
            crate::utils::sdk_runtime().map_err(|cause| RosettaError::Runtime { cause })?;
        let client = runtime
            .block_on(mina_rosetta_sdk::RosettaClient::discover(format!(
                "http://localhost:{port}"
            )))
            .map_err(|cause| RosettaError::Api { cause })?;
        Ok(RosettaClient { client, runtime })
    }

    pub fn url(&self) -> &str {
        self.client.base_url()
    }

    pub fn network(&self) -> &NetworkIdentifier {
        self.client.network()
    }

    pub fn status(&self) -> Result<NetworkStatusResponse, RosettaError> {
        self.runtime
            .block_on(self.client.network_status())
            .map_err(|cause| RosettaError::Api { cause })
    }

    /// The balance of `public_key` at rosetta's current block.
    pub fn balance(&self, public_key: &str) -> Result<AccountBalanceResponse, RosettaError> {
        self.runtime
            .block_on(self.client.account_balance(public_key, None))
            .map_err(|cause| RosettaError::Api { cause })
    }
}
