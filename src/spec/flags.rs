//! The node flags of `network create` and `spec init` (see
//! [`NodeFlags`]), applied to a spec.

use super::{NetworkSpec, NodeGroup, Role};
use crate::cli::NodeFlags;

/// Fee per snark work of a coordinator the flags add.
const DEFAULT_SNARK_FEE: &str = "0.001";

impl NetworkSpec {
    /// The spec with `flags` on top: a count replaces the nodes of its role
    /// (0 removes them), a switch adds its node when there is none.
    pub fn with_flags(mut self, flags: &NodeFlags) -> Self {
        let counts = [
            (Role::Seed, flags.seeds),
            (Role::BlockProducer, flags.block_producers),
            (Role::Plain, flags.plain_nodes),
        ];
        for (role, count) in counts {
            if let Some(count) = count {
                self.set_count(role, count);
            }
        }
        let switches = [
            (Role::Archive, flags.archive),
            (Role::Rosetta, flags.rosetta),
            (Role::ArchiveNodeApi, flags.archive_node_api),
        ];
        for (role, on) in switches {
            if on && !self.has(role) {
                self.insert(NodeGroup::new(role, 1));
            }
        }
        match flags.snark_workers {
            None => {}
            Some(0) => self.nodes.retain(|g| g.role != Role::SnarkCoordinator),
            Some(workers) => {
                if !self.has(Role::SnarkCoordinator) {
                    self.insert(NodeGroup {
                        fee: Some(DEFAULT_SNARK_FEE.into()),
                        ..NodeGroup::new(Role::SnarkCoordinator, 1)
                    });
                }
                for group in self.groups_mut(Role::SnarkCoordinator) {
                    group.workers = Some(workers);
                }
            }
        }
        if let Some(accounts) = flags.accounts {
            self.ledger.accounts = accounts;
        }
        self
    }

    fn has(&self, role: Role) -> bool {
        self.nodes.iter().any(|g| g.role == role)
    }

    fn groups_mut(&mut self, role: Role) -> impl Iterator<Item = &mut NodeGroup> {
        self.nodes.iter_mut().filter(move |g| g.role == role)
    }

    /// `count` nodes of `role`: the first group of the role keeps its settings
    /// (a name or client port only while it is one node), the others go.
    fn set_count(&mut self, role: Role, count: u16) {
        let Some(first) = self.nodes.iter().position(|g| g.role == role) else {
            if count > 0 {
                self.insert(NodeGroup::new(role, count));
            }
            return;
        };
        let mut kept = self.nodes.remove(first);
        self.nodes.retain(|g| g.role != role);
        if count == 0 {
            return;
        }
        kept.count = count;
        if count > 1 {
            kept.name = None;
            kept.client_port = None;
        }
        self.nodes.insert(first.min(self.nodes.len()), kept);
    }

    /// Adds `group` after the nodes of its role and of the roles before it.
    fn insert(&mut self, group: NodeGroup) {
        let at = self
            .nodes
            .iter()
            .position(|g| g.role > group.role)
            .unwrap_or(self.nodes.len());
        self.nodes.insert(at, group);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(spec: &NetworkSpec) -> Vec<(Role, u16)> {
        spec.nodes.iter().map(|g| (g.role, g.count)).collect()
    }

    #[test]
    fn flags_alone_change_a_seed_and_a_block_producer() {
        let flags = NodeFlags {
            block_producers: Some(2),
            plain_nodes: Some(1),
            archive: true,
            rosetta: true,
            archive_node_api: true,
            snark_workers: Some(2),
            accounts: Some(3),
            ..Default::default()
        };
        let spec = NetworkSpec::flags_base().with_flags(&flags);
        assert_eq!(
            roles(&spec),
            [
                (Role::Seed, 1),
                (Role::BlockProducer, 2),
                (Role::Plain, 1),
                (Role::Archive, 1),
                (Role::SnarkCoordinator, 1),
                (Role::Rosetta, 1),
                (Role::ArchiveNodeApi, 1),
            ]
        );
        let coordinator = &spec.nodes[4];
        assert_eq!(coordinator.workers, Some(2));
        assert_eq!(coordinator.fee.as_deref(), Some("0.001"));
        assert_eq!(spec.ledger.accounts, 3);
        // a valid network
        let planned = spec.plan().unwrap();
        assert_eq!(planned.len(), 8);
    }

    #[test]
    fn flags_replace_what_the_spec_says_of_their_role() {
        let spec: NetworkSpec = toml::from_str(
            r#"
            [[nodes]]
            role = "seed"
            name = "boot"
            client_port = 5000
            [[nodes]]
            role = "block-producer"
            balance = "500"
            [[nodes]]
            role = "block-producer"
            name = "whale"
            balance = "9000000"
            [[nodes]]
            role = "archive"
            [[nodes]]
            role = "snark-coordinator"
            workers = 1
            fee = "0.5"
            "#,
        )
        .unwrap();
        let flags = NodeFlags {
            seeds: Some(2),
            block_producers: Some(3),
            archive: true,
            snark_workers: Some(4),
            ..Default::default()
        };
        let spec = spec.with_flags(&flags);
        assert_eq!(
            roles(&spec),
            [
                (Role::Seed, 2),
                (Role::BlockProducer, 3),
                (Role::Archive, 1),
                (Role::SnarkCoordinator, 1),
            ]
        );
        // two seeds cannot share a name and a port; the balance stays
        assert_eq!(spec.nodes[0].name, None);
        assert_eq!(spec.nodes[0].client_port, None);
        assert_eq!(spec.nodes[1].balance.as_deref(), Some("500"));
        assert_eq!(spec.nodes[3].workers, Some(4));
        assert_eq!(spec.nodes[3].fee.as_deref(), Some("0.5"));

        let none = NodeFlags {
            block_producers: Some(0),
            snark_workers: Some(0),
            ..Default::default()
        };
        assert_eq!(
            roles(&spec.with_flags(&none)),
            [(Role::Seed, 2), (Role::Archive, 1)]
        );
    }

    #[test]
    fn one_node_keeps_its_name() {
        let spec: NetworkSpec =
            toml::from_str("[[nodes]]\nrole = \"seed\"\nname = \"boot\"\n").unwrap();
        let flags = NodeFlags {
            seeds: Some(1),
            ..Default::default()
        };
        assert_eq!(
            spec.with_flags(&flags).nodes[0].name.as_deref(),
            Some("boot")
        );
    }
}
