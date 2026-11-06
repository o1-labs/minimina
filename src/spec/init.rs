//! What `spec init` prints: a spec file to start from, for the user to edit
//! and pass to `network create --spec`. The file is
//! `templates/spec_init.toml`: the spec's profile, nodes and ledger, with
//! comments on what each part does and commented examples of the rest.
//! Without edits it reads back as the same spec.

use super::{NetworkSpec, Role};

/// The spec file of `spec`, with `command` (the command that wrote it) in
/// its header. Writes the profile, nodes and ledger: what the flags make.
#[derive(askama::Template)]
#[template(path = "spec_init.toml", escape = "none")]
pub struct SpecInit<'a> {
    pub command: &'a str,
    pub spec: &'a NetworkSpec,
}

mod filters {
    /// A value as TOML writes it: strings quoted and escaped.
    #[askama::filter_fn]
    pub fn toml<T: serde::Serialize>(value: T, _: &dyn askama::Values) -> askama::Result<String> {
        ::toml::Value::try_from(value)
            .map(|value| value.to_string())
            .map_err(askama::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{NodeFlags, Profile};
    use crate::spec::{LedgerSpec, NodeGroup};
    use askama::Template;

    fn render(spec: &NetworkSpec) -> String {
        SpecInit {
            command: "minimina spec init --seeds 2",
            spec,
        }
        .render()
        .unwrap()
    }

    #[test]
    fn reads_back_as_the_same_spec() {
        let flags = NodeFlags {
            seeds: Some(2),
            block_producers: Some(3),
            plain_nodes: Some(1),
            archive: true,
            rosetta: true,
            archive_node_api: true,
            snark_workers: Some(2),
            accounts: Some(4),
        };
        let spec = NetworkSpec::flags_base().with_flags(&flags);
        let text = render(&spec);
        assert!(
            text.starts_with("# minimina network spec, written by `minimina spec init --seeds 2`.")
        );
        assert!(
            text.contains(
                "\n[[nodes]]\n# Produce blocks. `balance`: genesis balance in MINA \
                 (default \"11550000\").\nrole = \"block-producer\"\ncount = 3\n"
            ),
            "{text}"
        );
        assert!(text.contains("# profile = \"devnet\"\n"), "{text}");
        assert!(text.contains("# balance = \"1000\"\n"), "{text}");
        let back: NetworkSpec = toml::from_str(&text).unwrap();
        assert_eq!(back, spec);
    }

    /// Every field the template writes; the struct literals have no
    /// `..Default::default()`, so a new field shows up here.
    #[test]
    fn every_set_field_is_written() {
        let node = NodeGroup {
            role: Role::Rosetta,
            name: Some("r \"1\"".into()),
            count: 1,
            balance: Some("5.5".parse().unwrap()),
            client_port: Some(4000),
            archive_port: Some(4005),
            workers: Some(2),
            fee: Some("0.1".into()),
            node: Some("bp-1".into()),
            version: Some("1.2.3".into()),
            bin: Some("/opt/a b/server".into()),
        };
        let spec = NetworkSpec {
            profile: Some(Profile::Lightnet),
            nodes: vec![node],
            ledger: LedgerSpec {
                accounts: 3,
                balance: Some("7".parse().unwrap()),
                file: Some("/tmp/a b.csv".into()),
            },
            ..NetworkSpec::default_network()
        };
        let text = render(&spec);
        assert!(text.contains("profile = \"lightnet\"\n"), "{text}");
        assert!(text.contains("name = 'r \"1\"'\n"), "{text}");
        let back: NetworkSpec = toml::from_str(&text).unwrap();
        assert_eq!(back, spec);
    }
}
