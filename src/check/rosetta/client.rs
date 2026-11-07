use super::{
    api::{AccountBalance, NetworkIdentifier, NetworkList, NetworkStatus},
    RosettaError,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

/// The Rosetta API of a network's `mina-rosetta`.
pub struct RosettaClient {
    url: String,
    http: reqwest::blocking::Client,
}

impl RosettaClient {
    pub fn new(port: u16) -> Result<Self, RosettaError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|source| RosettaError::Http {
                path: "client",
                source,
            })?;
        Ok(RosettaClient {
            url: format!("http://localhost:{port}"),
            http,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The network rosetta serves: the first of `/network/list`.
    pub fn network(&self) -> Result<NetworkIdentifier, RosettaError> {
        let list: NetworkList = self.post("/network/list", json!({}))?;
        list.network_identifiers
            .into_iter()
            .next()
            .ok_or(RosettaError::NoNetwork)
    }

    pub fn status(&self, network: &NetworkIdentifier) -> Result<NetworkStatus, RosettaError> {
        self.post("/network/status", json!({ "network_identifier": network }))
    }

    pub fn balance(
        &self,
        network: &NetworkIdentifier,
        public_key: &str,
    ) -> Result<AccountBalance, RosettaError> {
        self.post(
            "/account/balance",
            json!({
                "network_identifier": network,
                "account_identifier": { "address": public_key },
            }),
        )
    }

    fn post<T: DeserializeOwned>(
        &self,
        path: &'static str,
        body: Value,
    ) -> Result<T, RosettaError> {
        let http = |source| RosettaError::Http { path, source };
        let response = self
            .http
            .post(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .map_err(http)?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(RosettaError::Status {
                path,
                status: status.as_u16(),
                body: response.text().unwrap_or_default(),
            });
        }
        response.json().map_err(http)
    }
}
