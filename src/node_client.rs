//! Queries to running nodes through the Mina SDKs: `mina-sdk` for daemons and
//! `mina-archive-sdk` for the Archive Node API.
//!
//! The SDKs are async and minimina is not: each call runs on a small runtime of
//! its own, and the nodes of a network are asked in parallel.

use crate::service::{ServiceConfig, ServiceType};
use anyhow::{bail, Context as _, Result};
use log::info;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

/// A status request to a node that does not answer in this time counts as down.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// What a running node reports about the chain.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Health {
    /// Daemon: CONNECTING, LISTENING, OFFLINE, BOOTSTRAP, SYNCED or CATCHUP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<String>,
    /// Daemon: length of its best chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<usize>,
    /// Archive node api: highest canonical and pending block in the archive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_height: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_height: Option<i64>,
    /// Why the node did not answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Health {
    fn failed(e: impl std::fmt::Display) -> Self {
        Health {
            error: Some(e.to_string()),
            ..Default::default()
        }
    }

    pub fn is_synced(&self) -> bool {
        self.sync_status.as_deref() == Some("SYNCED")
    }
}

/// How minimina asks a service about the chain, if it can.
enum Probe {
    Daemon(String),
    ArchiveNodeApi(String),
}

fn probe(service: &ServiceConfig) -> Option<Probe> {
    let uri = service.to_node_info().graphql_uri?;
    match service.service_type {
        ServiceType::Seed
        | ServiceType::BlockProducer
        | ServiceType::PlainNode
        | ServiceType::SnarkCoordinator
        | ServiceType::ArchiveNode => Some(Probe::Daemon(uri)),
        ServiceType::ArchiveNodeApi => Some(Probe::ArchiveNodeApi(uri)),
        ServiceType::SnarkWorker | ServiceType::UptimeServiceBackend | ServiceType::Rosetta => None,
    }
}

fn daemon_client(uri: &str) -> mina_sdk::MinaClient {
    mina_sdk::MinaClient::with_config(mina_sdk::ClientConfig {
        graphql_uri: uri.to_string(),
        retries: 1,
        retry_delay: Duration::from_millis(100),
        timeout: QUERY_TIMEOUT,
    })
}

async fn ask(probe: Probe) -> Health {
    match probe {
        Probe::Daemon(uri) => match daemon_client(&uri).get_daemon_status().await {
            Ok(status) => Health {
                sync_status: Some(status.sync_status.to_string()),
                height: status.blockchain_length,
                peers: status.peers.map(|p| p.len()),
                ..Default::default()
            },
            Err(e) => Health::failed(e),
        },
        Probe::ArchiveNodeApi(uri) => {
            let mut config = mina_archive_sdk::ClientConfig::new(uri);
            config.retries = 1;
            config.retry_delay = Duration::from_millis(100);
            config.timeout = QUERY_TIMEOUT;
            match mina_archive_sdk::ArchiveClient::with_config(config)
                .get_network_state()
                .await
            {
                Ok(state) => Health {
                    canonical_height: state
                        .max_block_height
                        .as_ref()
                        .map(|h| h.canonical_max_block_height),
                    pending_height: state.max_block_height.map(|h| h.pending_max_block_height),
                    ..Default::default()
                },
                Err(e) => Health::failed(e),
            }
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime for node queries")
}

/// Health of every service that can report it, by service name. All are
/// asked at once, so a network with stopped nodes takes one timeout, not one
/// per node.
pub fn health(services: &[ServiceConfig]) -> Result<BTreeMap<String, Health>> {
    let probes: Vec<(String, Probe)> = services
        .iter()
        .filter_map(|s| Some((s.service_name.clone(), probe(s)?)))
        .collect();
    runtime()?.block_on(async {
        let mut tasks = tokio::task::JoinSet::new();
        for (name, probe) in probes {
            tasks.spawn(async move { (name, ask(probe).await) });
        }
        let mut health = BTreeMap::new();
        while let Some(done) = tasks.join_next().await {
            let (name, h) = done.context("node query task failed")?;
            health.insert(name, h);
        }
        Ok(health)
    })
}

/// Waits until every daemon reports SYNCED, asking every `interval`.
pub fn wait_synced(
    services: &[ServiceConfig],
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    let daemons = services
        .iter()
        .filter(|s| matches!(probe(s), Some(Probe::Daemon(_))))
        .count();
    let deadline = Instant::now() + timeout;
    loop {
        let health = health(services)?;
        let waiting: Vec<String> = health
            .iter()
            .filter(|(_, h)| h.sync_status.is_some() || h.error.is_some())
            .filter(|(_, h)| h.canonical_height.is_none() && !h.is_synced())
            .map(|(name, h)| {
                // the full error is in `network status`; here one word per node
                let state = h.sync_status.as_deref().unwrap_or("no answer");
                format!("{name}: {state}")
            })
            .collect();
        if waiting.is_empty() {
            info!("All {daemons} daemons are SYNCED");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "nodes not ready after {}s: {}",
                timeout.as_secs(),
                waiting.join(", ")
            );
        }
        info!("Waiting for daemons to sync: {}", waiting.join(", "));
        std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Waits until the daemon at `uri` answers GraphQL, up to `timeout`.
pub fn wait_for_graphql(uri: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let client = daemon_client(uri);
    runtime()?.block_on(async {
        loop {
            match client.get_sync_status().await {
                Ok(_) => return Ok(()),
                Err(e) if Instant::now() >= deadline => {
                    bail!(
                        "GraphQL at {uri} did not answer within {}s: {e}",
                        timeout.as_secs()
                    )
                }
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    })
}

/// Turns on the daemon's filtered log for the structured events the
/// integration tests read (`startFilteredLog`).
pub fn start_filtered_log(uri: &str) -> Result<()> {
    const EVENT_IDS: &[&str] = &[
        "21ccae8c619bc2666474085272d5fe1d",
        "ef1182dc30f3e0aa9f6bf11c0ab90ba6",
        "64e2d3e86c37c09b15efdaf7470ce879",
        "db06cb5030f39e86e84b30d033f3bc5c",
        "60076de624bf0c5fc0843b875001cf84",
        "27953f46376ba8abc0c61400e2c38f8b",
        "b4b5f5b1d1a0c457cbd13a35d1c8b57b",
        "0fc65f5594c5e9ee0b6f0ddde747c758",
        "b5a89d6d616a35fb6f73d1eaad6b2dbd",
        "1c4150aa7058a3058c4d20ae90ff7ec3",
        "f7254e63ad51092a0bd3078580ef9ce3",
        "74a81f1e2f8d548e4550faa136c68160",
        "30fe76cee159ea215fc05549e861501e",
    ];
    let client = daemon_client(uri);
    let response = runtime()?.block_on(
        client
            .query("mutation ($filter: [String!]!) { startFilteredLog(filter: $filter) }")
            .variables(serde_json::json!({ "filter": EVENT_IDS }))
            .name("startFilteredLog")
            .send(),
    )?;
    info!("startFilteredLog at {uri}: {response}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(service_type: ServiceType, name: &str, port: u16) -> ServiceConfig {
        ServiceConfig {
            service_type,
            service_name: name.into(),
            client_port: Some(port),
            ..Default::default()
        }
    }

    #[test]
    fn only_nodes_with_graphql_are_asked() {
        let kinds = [
            (ServiceType::Seed, true),
            (ServiceType::PlainNode, true),
            (ServiceType::ArchiveNode, true),
            (ServiceType::SnarkWorker, false),
            (ServiceType::Rosetta, false),
        ];
        for (kind, asked) in kinds {
            assert_eq!(
                matches!(probe(&service(kind, "n", 3100)), Some(Probe::Daemon(_))),
                asked,
                "{kind:?}"
            );
        }
        match probe(&service(ServiceType::ArchiveNodeApi, "a", 8080)) {
            Some(Probe::ArchiveNodeApi(uri)) => assert_eq!(uri, "http://localhost:8080/"),
            _ => panic!("archive node api is asked through the archive sdk"),
        }
    }

    #[test]
    fn stopped_nodes_report_an_error_quickly() {
        // nothing listens on these ports
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let services = [
            service(ServiceType::Seed, "seed", port - 1),
            service(ServiceType::ArchiveNodeApi, "ana", port),
            service(ServiceType::Rosetta, "rosetta", port),
        ];
        let start = Instant::now();
        let health = health(&services).unwrap();
        assert!(start.elapsed() < QUERY_TIMEOUT * 2, "{:?}", start.elapsed());
        assert_eq!(health.len(), 2, "{health:?}");
        assert!(health["seed"].error.is_some());
        assert!(health["ana"].error.is_some());

        let err = wait_synced(&services, Duration::ZERO, Duration::ZERO).unwrap_err();
        assert_eq!(
            err.to_string(),
            "nodes not ready after 0s: ana: no answer, seed: no answer"
        );
    }
}
