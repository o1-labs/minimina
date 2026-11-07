use super::{ChainView, DaemonError, Gateway, LoadError, Sender};
use crate::keys::KEY_PASSWORD;
use mina_sdk::{ClientConfig, Currency, MinaClient, Payment, SubmittedCommand, SyncStatus};
use serde_json::json;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

const IMPORT_ACCOUNT: &str = "mutation ($path: String!, $password: String!) {
  importAccount(path: $path, password: $password) { publicKey alreadyImported }
}";

/// [`Gateway`] to a daemon's GraphQL, through `mina-sdk`.
pub struct DaemonGateway {
    client: MinaClient,
    runtime: tokio::runtime::Runtime,
}

impl DaemonGateway {
    pub fn new(graphql_uri: &str) -> Result<Self, LoadError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(LoadError::Runtime)?;
        let client = MinaClient::with_config(ClientConfig {
            graphql_uri: graphql_uri.to_string(),
            retries: 1,
            retry_delay: Duration::from_millis(500),
            timeout: TIMEOUT,
        });
        Ok(DaemonGateway { client, runtime })
    }
}

impl Gateway for DaemonGateway {
    fn chain(&self) -> Result<ChainView, DaemonError> {
        self.runtime.block_on(async {
            let synced = self.client.get_sync_status().await? == SyncStatus::Synced;
            let genesis = self.client.get_genesis_block().await?.state_hash;
            Ok(ChainView { genesis, synced })
        })
    }

    fn unlock(&self, sender: &Sender) -> Result<(), DaemonError> {
        let path = sender.key_path.to_string_lossy();
        self.runtime.block_on(async {
            self.client
                .query(IMPORT_ACCOUNT)
                .variables(json!({ "path": path, "password": KEY_PASSWORD }))
                .name("importAccount")
                .send()
                .await?;
            self.client
                .unlock_account(&sender.public_key, KEY_PASSWORD)
                .await?;
            Ok(())
        })
    }

    fn liquid(&self, public_key: &str) -> Result<Currency, DaemonError> {
        let account = self
            .runtime
            .block_on(self.client.get_account(public_key, None))?;
        Ok(account.balance.liquid.unwrap_or(account.balance.total))
    }

    fn send(&self, payment: Payment) -> Result<SubmittedCommand, DaemonError> {
        Ok(self.runtime.block_on(self.client.send_payment(payment))?)
    }
}
