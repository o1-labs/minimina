//! The ports of a planned network: no two processes of the network may
//! listen on one port.

use super::{PlannedNode, Role, SpecError};
use std::{collections::HashMap, fmt};

/// What a daemon listens on, by offset from its client port.
const DAEMON_PORTS: [&str; 5] = ["client", "rest", "external", "metrics", "libp2p metrics"];

/// One port of the network: the node that listens on it, and what for.
#[derive(Debug, Clone, PartialEq)]
pub struct PortUse {
    pub node: String,
    pub purpose: &'static str,
}

impl fmt::Display for PortUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}' ({} port)", self.node, self.purpose)
    }
}

/// Every port the processes of `node` listen on.
fn uses(node: &PlannedNode) -> Vec<(u16, PortUse)> {
    let used = |port, purpose| {
        (
            port,
            PortUse {
                node: node.name.clone(),
                purpose,
            },
        )
    };
    let mut ports = Vec::new();
    if node.is_daemon() {
        for (offset, purpose) in (0u16..).zip(DAEMON_PORTS) {
            ports.push(used(node.client_port.saturating_add(offset), purpose));
        }
    }
    if matches!(
        node.role,
        Role::Rosetta | Role::ArchiveNodeApi | Role::AccountsManager
    ) {
        ports.push(used(node.client_port, "api"));
    }
    if let Some(port) = node.archive_port {
        ports.push(used(port, "mina-archive"));
    }
    ports
}

/// Fails on the first port two processes of `nodes` would both listen on.
pub fn check(nodes: &[PlannedNode]) -> Result<(), SpecError> {
    let mut taken: HashMap<u16, PortUse> = HashMap::new();
    for (port, second) in nodes.iter().flat_map(uses) {
        if let Some(first) = taken.get(&port) {
            return Err(SpecError::PortConflict {
                port,
                first: first.clone(),
                second,
            });
        }
        taken.insert(port, second);
    }
    Ok(())
}
