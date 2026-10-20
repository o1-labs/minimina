//! Network spec: a short TOML description of a network. minimina generates
//! the keys, ports, peers and genesis ledger from it.
//!
//! ```toml
//! profile = "lightnet"            # optional; --profile overrides it
//!
//! [[nodes]]
//! role = "seed"
//!
//! [[nodes]]
//! role = "block-producer"
//! count = 2                       # bp-1, bp-2
//! balance = "10000000"
//!
//! [[nodes]]
//! role = "plain"                  # follows the chain, produces nothing
//!
//! [[nodes]]
//! role = "archive"
//!
//! [[nodes]]
//! role = "rosetta"                # reads the archive and the archive's daemon
//!
//! [ledger]                        # funded accounts for tests: account-1 ...
//! accounts = 5
//! balance = "1000"
//!
//! [runtime_config]                # merged into the genesis runtime config
//! proof = { block_window_duration_ms = 30000 }
//! ```

use crate::cli::Profile;
use anyhow::{bail, Context as _, Result};
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path};

/// Genesis balance of a block producer that sets none.
pub const DEFAULT_BLOCK_PRODUCER_BALANCE: &str = "11550000";
/// First client port of automatically placed daemons; each takes `PORT_STEP` ports.
const FIRST_CLIENT_PORT: u16 = 3100;
/// Client, rest, external, metrics, libp2p metrics, archive.
const PORT_STEP: u16 = 10;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    pub profile: Option<Profile>,
    #[serde(default)]
    pub nodes: Vec<NodeGroup>,
    #[serde(default)]
    pub ledger: LedgerSpec,
    /// Merged into the generated genesis runtime config (`genesis`, `proof`, `daemon`, ...).
    pub runtime_config: Option<toml::Table>,
    #[serde(default)]
    pub docker: DockerSpec,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Seed,
    BlockProducer,
    Plain,
    Archive,
    SnarkCoordinator,
    /// `mina-rosetta`, not a daemon: needs an archive node.
    Rosetta,
}

impl Role {
    fn default_name(&self) -> &'static str {
        match self {
            Role::Seed => "seed",
            Role::BlockProducer => "bp",
            Role::Plain => "node",
            Role::Archive => "archive",
            Role::SnarkCoordinator => "snark-coordinator",
            Role::Rosetta => "rosetta",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeGroup {
    pub role: Role,
    /// Name of the node; only for `count = 1`. Default: `<role>-<n>`.
    pub name: Option<String>,
    #[serde(default = "one")]
    pub count: u16,
    /// Genesis balance of each node. Block producers default to
    /// [`DEFAULT_BLOCK_PRODUCER_BALANCE`]; other nodes get no account.
    pub balance: Option<String>,
    /// Client port (others follow it). Default: the next free block from 3100.
    pub client_port: Option<u16>,
    /// Archive node: port of the `mina-archive` process. Default: client port + 5.
    pub archive_port: Option<u16>,
    /// Snark coordinator: number of snark workers.
    pub workers: Option<u16>,
    /// Snark coordinator: fee per snark work.
    pub fee: Option<String>,
    /// Rosetta: the daemon whose GraphQL API it reads. Default: the archive node.
    pub node: Option<String>,
}

fn one() -> u16 {
    1
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LedgerSpec {
    /// Funded accounts with generated keys (`account-1`, ...), for transactions in tests.
    #[serde(default)]
    pub accounts: u16,
    pub balance: Option<String>,
}

/// Images of docker mode; the built-in images when not set.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DockerSpec {
    pub daemon_image: Option<String>,
    pub archive_image: Option<String>,
    pub rosetta_image: Option<String>,
}

/// One node of the network, with its name and ports decided.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedNode {
    pub name: String,
    pub role: Role,
    pub balance: Option<String>,
    pub client_port: u16,
    pub archive_port: Option<u16>,
    /// Snark coordinator: names of its workers.
    pub workers: Vec<String>,
    pub fee: Option<String>,
    /// Rosetta: name and client port of the daemon it reads.
    pub graphql_node: Option<(String, u16)>,
}

impl PlannedNode {
    /// Whether the node needs a block producer key pair (a block producer,
    /// or a coordinator, whose public key receives the snark fees).
    /// Whether the node is a mina daemon (has libp2p keys and peers).
    pub fn is_daemon(&self) -> bool {
        self.role != Role::Rosetta
    }

    pub fn needs_key(&self) -> bool {
        matches!(self.role, Role::BlockProducer | Role::SnarkCoordinator) || self.balance.is_some()
    }
}

impl NetworkSpec {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading network spec {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing network spec {}", path.display()))
    }

    /// The network `network create` makes without a spec, topology or ledger.
    pub fn default_network() -> Self {
        let node = |role, name: &str, client_port| NodeGroup {
            role,
            name: Some(name.into()),
            count: 1,
            balance: None,
            client_port: Some(client_port),
            archive_port: None,
            workers: None,
            fee: None,
            node: None,
        };
        let mut archive = node(Role::Archive, "mina-archive", 5005);
        archive.archive_port = Some(3086);
        let mut coordinator = node(Role::SnarkCoordinator, "mina-snark-coordinator", 7000);
        coordinator.workers = Some(1);
        coordinator.fee = Some("0.001".into());
        NetworkSpec {
            profile: None,
            nodes: vec![
                node(Role::Seed, "mina-seed-1", 3100),
                node(Role::BlockProducer, "mina-bp-1", 4000),
                node(Role::BlockProducer, "mina-bp-2", 4005),
                coordinator,
                archive,
            ],
            ledger: LedgerSpec::default(),
            runtime_config: None,
            docker: DockerSpec::default(),
        }
    }

    /// Names, ports and workers of every node, after checking the spec.
    pub fn plan(&self) -> Result<Vec<PlannedNode>> {
        let count = |role| {
            self.nodes
                .iter()
                .filter(|g| g.role == role)
                .map(|g| g.count as usize)
                .sum::<usize>()
        };
        if count(Role::Seed) == 0 {
            bail!("the network spec has no seed; add a node with role = \"seed\"");
        }
        for role in [Role::Archive, Role::SnarkCoordinator] {
            if count(role) > 1 {
                bail!("the network spec has more than one {role:?} node; at most one is supported");
            }
        }

        let explicit_ports: BTreeSet<u16> =
            self.nodes.iter().filter_map(|g| g.client_port).collect();
        let mut next_port = FIRST_CLIENT_PORT;
        let mut auto_port = || {
            while explicit_ports
                .iter()
                .any(|p| p.abs_diff(next_port) < PORT_STEP)
            {
                next_port += PORT_STEP;
            }
            let port = next_port;
            next_port += PORT_STEP;
            port
        };

        let mut index = std::collections::HashMap::<&str, usize>::new();
        let mut nodes = Vec::new();
        for group in &self.nodes {
            if group.count == 0 {
                bail!("{:?} nodes: count must be at least 1", group.role);
            }
            if group.count > 1 && (group.name.is_some() || group.client_port.is_some()) {
                bail!(
                    "{:?} nodes: `name` and `client_port` need count = 1",
                    group.role
                );
            }
            if group.role != Role::SnarkCoordinator
                && (group.workers.is_some() || group.fee.is_some())
            {
                bail!(
                    "{:?} nodes: `workers` and `fee` are for snark coordinators",
                    group.role
                );
            }
            if group.role != Role::Archive && group.archive_port.is_some() {
                bail!(
                    "{:?} nodes: `archive_port` is for the archive node",
                    group.role
                );
            }
            if group.role != Role::Rosetta && group.node.is_some() {
                bail!("{:?} nodes: `node` is for rosetta", group.role);
            }
            if group.role == Role::Rosetta && group.balance.is_some() {
                bail!("rosetta is not a daemon and has no account: remove `balance`");
            }
            for _ in 0..group.count {
                let prefix = group.role.default_name();
                let n = index.entry(prefix).or_default();
                *n += 1;
                let name = group.name.clone().unwrap_or_else(|| match group.role {
                    // only one of each
                    Role::Archive | Role::SnarkCoordinator => prefix.to_string(),
                    _ => format!("{prefix}-{n}"),
                });
                let client_port = group.client_port.unwrap_or_else(&mut auto_port);
                let balance = group.balance.clone().or_else(|| {
                    (group.role == Role::BlockProducer)
                        .then(|| DEFAULT_BLOCK_PRODUCER_BALANCE.to_string())
                });
                let workers = (1..=group.workers.unwrap_or(0))
                    .map(|i| match name.strip_suffix("coordinator") {
                        Some(stem) => format!("{stem}worker-{i}"),
                        None => format!("{name}-worker-{i}"),
                    })
                    .collect();
                nodes.push(PlannedNode {
                    archive_port: (group.role == Role::Archive)
                        .then(|| group.archive_port.unwrap_or(client_port + 5)),
                    name,
                    role: group.role,
                    balance,
                    client_port,
                    workers,
                    fee: group.fee.clone(),
                    graphql_node: None,
                });
            }
        }

        // rosetta reads the archive database and a daemon's GraphQL API
        if count(Role::Rosetta) > 0 && count(Role::Archive) == 0 {
            bail!("rosetta needs an archive node; add a node with role = \"archive\"");
        }
        let groups = self
            .nodes
            .iter()
            .flat_map(|g| std::iter::repeat_n(g, g.count as usize));
        let daemons: Vec<(String, u16, Role)> = nodes
            .iter()
            .map(|n| (n.name.clone(), n.client_port, n.role))
            .collect();
        for (node, group) in nodes.iter_mut().zip(groups) {
            if node.role != Role::Rosetta {
                continue;
            }
            let wanted = |d: &&(String, u16, Role)| match &group.node {
                Some(name) => &d.0 == name,
                None => d.2 == Role::Archive,
            };
            let (name, port, role) = daemons.iter().find(wanted).with_context(|| {
                format!(
                    "rosetta '{}': no node '{}'",
                    node.name,
                    group.node.as_deref().unwrap_or_default()
                )
            })?;
            if *role == Role::Rosetta {
                bail!("rosetta '{}': '{name}' is not a daemon", node.name);
            }
            node.graphql_node = Some((name.clone(), *port));
        }

        let mut names = BTreeSet::new();
        for name in nodes
            .iter()
            .flat_map(|n| std::iter::once(&n.name).chain(&n.workers))
        {
            if !names.insert(name) {
                bail!("node name '{name}' is used twice in the network spec");
            }
        }
        let mut ports = BTreeSet::new();
        for node in &nodes {
            if !ports.insert(node.client_port) {
                bail!(
                    "client port {} is used twice in the network spec",
                    node.client_port
                );
            }
        }
        Ok(nodes)
    }

    /// Names of the funded test accounts.
    pub fn ledger_accounts(&self) -> Vec<String> {
        (1..=self.ledger.accounts)
            .map(|i| format!("account-{i}"))
            .collect()
    }

    /// `runtime_config` as JSON, to merge into the genesis runtime config.
    pub fn runtime_config_json(&self) -> Result<Option<serde_json::Value>> {
        self.runtime_config
            .as_ref()
            .map(|t| serde_json::to_value(t).context("runtime_config is not valid JSON"))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(toml: &str) -> NetworkSpec {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn short_spec_expands_to_named_nodes_with_ports() {
        let s = spec(
            r#"
            profile = "lightnet"
            [[nodes]]
            role = "seed"
            [[nodes]]
            role = "block-producer"
            count = 2
            [[nodes]]
            role = "plain"
            [[nodes]]
            role = "archive"
            [[nodes]]
            role = "snark-coordinator"
            workers = 2
            fee = "0.01"
            [ledger]
            accounts = 2
            balance = "1000"
            [runtime_config.proof]
            block_window_duration_ms = 30000
            "#,
        );
        assert_eq!(s.profile, Some(Profile::Lightnet));
        let plan = s.plan().unwrap();
        let summary: Vec<_> = plan
            .iter()
            .map(|n| (n.name.as_str(), n.client_port, n.balance.as_deref()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("seed-1", 3100, None),
                ("bp-1", 3110, Some(DEFAULT_BLOCK_PRODUCER_BALANCE)),
                ("bp-2", 3120, Some(DEFAULT_BLOCK_PRODUCER_BALANCE)),
                ("node-1", 3130, None),
                ("archive", 3140, None),
                ("snark-coordinator", 3150, None),
            ]
        );
        assert_eq!(plan[4].archive_port, Some(3145));
        assert_eq!(plan[5].workers, ["snark-worker-1", "snark-worker-2"]);
        assert!(plan[1].needs_key() && plan[5].needs_key() && !plan[3].needs_key());
        assert_eq!(s.ledger_accounts(), ["account-1", "account-2"]);
        assert_eq!(
            s.runtime_config_json().unwrap().unwrap(),
            serde_json::json!({"proof": {"block_window_duration_ms": 30000}})
        );
    }

    #[test]
    fn rosetta_reads_the_archive_unless_told_otherwise() {
        let s = spec(
            r#"
            [[nodes]]
            role = "seed"
            [[nodes]]
            role = "plain"
            [[nodes]]
            role = "archive"
            [[nodes]]
            role = "rosetta"
            [[nodes]]
            role = "rosetta"
            node = "node-1"
            "#,
        );
        let plan = s.plan().unwrap();
        assert_eq!(plan[3].name, "rosetta-1");
        assert_eq!(plan[3].graphql_node, Some(("archive".to_string(), 3120)));
        assert_eq!(plan[4].graphql_node, Some(("node-1".to_string(), 3110)));
        assert!(!plan[3].is_daemon() && !plan[3].needs_key());
    }

    #[test]
    fn rosetta_needs_an_archive_and_a_daemon() {
        let err = |toml: &str| spec(toml).plan().unwrap_err().to_string();
        assert!(
            err("[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"rosetta\"")
                .contains("rosetta needs an archive node")
        );
        let base = "[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"archive\"\n";
        assert!(err(&format!(
            "{base}[[nodes]]\nrole = \"rosetta\"\nnode = \"nope\""
        ))
        .contains("no node 'nope'"));
        assert!(err(&format!(
            "{base}[[nodes]]\nrole = \"rosetta\"\n[[nodes]]\nrole = \"rosetta\"\nnode = \"rosetta-1\""
        ))
        .contains("'rosetta-1' is not a daemon"));
        assert!(err(&format!(
            "{base}[[nodes]]\nrole = \"plain\"\nnode = \"seed-1\""
        ))
        .contains("`node` is for rosetta"));
    }

    #[test]
    fn automatic_ports_avoid_explicit_ones() {
        let s = spec(
            r#"
            [[nodes]]
            role = "seed"
            client_port = 3110
            [[nodes]]
            role = "plain"
            count = 2
            "#,
        );
        let ports: Vec<_> = s.plan().unwrap().iter().map(|n| n.client_port).collect();
        assert_eq!(ports, [3110, 3100, 3120]);
    }

    #[test]
    fn default_network_keeps_its_names_and_ports() {
        let plan = NetworkSpec::default_network().plan().unwrap();
        let summary: Vec<_> = plan
            .iter()
            .map(|n| (n.name.as_str(), n.client_port))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("mina-seed-1", 3100),
                ("mina-bp-1", 4000),
                ("mina-bp-2", 4005),
                ("mina-snark-coordinator", 7000),
                ("mina-archive", 5005),
            ]
        );
        assert_eq!(plan[3].workers, ["mina-snark-worker-1"]);
        assert_eq!(plan[4].archive_port, Some(3086));
    }

    #[test]
    fn invalid_specs_are_explained() {
        let err = |toml: &str| spec(toml).plan().unwrap_err().to_string();
        assert!(err("[[nodes]]\nrole = \"plain\"").contains("has no seed"));
        assert!(
            err("[[nodes]]\nrole = \"seed\"\n[[nodes]]\nrole = \"archive\"\ncount = 2")
                .contains("more than one Archive")
        );
        assert!(err(
            "[[nodes]]\nrole = \"seed\"\nname = \"x\"\n[[nodes]]\nrole = \"plain\"\nname = \"x\""
        )
        .contains("'x' is used twice"));
        assert!(
            err("[[nodes]]\nrole = \"seed\"\ncount = 2\nname = \"s\"").contains("need count = 1")
        );
        assert!(err("[[nodes]]\nrole = \"seed\"\nworkers = 1").contains("for snark coordinators"));
        assert!(toml::from_str::<NetworkSpec>("[[nodes]]\nrole = \"seed\"\ncolour = 1").is_err());
        assert!(toml::from_str::<NetworkSpec>("[[nodes]]\nrole = \"wizard\"").is_err());
    }
}
