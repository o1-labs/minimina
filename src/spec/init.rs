//! What `spec init` prints: a spec file to start from. The spec is written
//! as TOML with comments that say what each part does, for the user to edit
//! and pass to `network create --spec`; without edits it is the same spec.

use super::{NetworkSpec, Role, DEFAULT_BLOCK_PRODUCER_BALANCE};
use anyhow::{Context as _, Result};
use toml_edit::{DocumentMut, Item, Table};

/// Column where the comment after a value starts.
const COMMENT_COLUMN: usize = 30;

/// The top of the file; `{command}` is the command that wrote it.
const HEADER: &str = "\
# minimina network spec, written by `{command}`.
# Create the network: minimina network create -n <network> --spec <this file>
#
# minimina generates the keys, ports, peers and genesis ledger. Node names
# default to <role>-<n> (seed-1, bp-1, node-1, ...); client ports are
# assigned from 3100 in steps of 10 unless a node sets `client_port`.
# The build profile of the mina binaries (dev, devnet, lightnet, mainnet;
# default devnet) is `profile = \"...\"`; --profile overrides it.
";

/// Before `[ledger]`.
const LEDGER_COMMENT: &str = "
# Funded accounts for transactions in tests: account-1 .. account-N, with
# `balance` each (default \"1000\"); keys are in <network dir>/network-keypairs.
# `file` gives accounts to start with; the generated ones are added after them:
#   .json: a runtime config ledger (ledger.accounts), as -g takes it
#   .csv:  a header line, then public_key,balance[,private_key,delegate] per
#          line; balances in MINA
";

/// The end of the file: sections the flags do not make.
const FOOTER: &str = "
# Merged into the generated genesis runtime config.
# [runtime_config.genesis]
# k = 10
# [runtime_config.proof]
# block_window_duration_ms = 30000

# Docker mode images (defaults: the built-in images).
# [docker]
# daemon_image = \"minaprotocol/mina-daemon:...\"

# A fork to postfork binaries (native mode only); see the README.
# [hardfork]
# mode = \"manual\"
# at = { slot = 42 }
# postfork = { mina_version = \"4.0.4\" }
";

/// What a node of each role does, after its `role`.
fn role_comment(role: Role) -> String {
    match role {
        Role::Seed => "peers find each other through the seeds".into(),
        Role::BlockProducer => {
            format!("produces blocks; balance default \"{DEFAULT_BLOCK_PRODUCER_BALANCE}\"")
        }
        Role::Plain => "follows the chain, produces no blocks".into(),
        Role::Archive => "+ mina-archive and a postgres database".into(),
        Role::SnarkCoordinator => "hands out snark work to its workers".into(),
        Role::Rosetta => "reads the archive and a daemon's GraphQL (node, default: archive)".into(),
        Role::ArchiveNodeApi => "GraphQL over the archive database (events, actions)".into(),
    }
}

/// A spec as a TOML document with comments.
pub struct SpecDocument {
    doc: DocumentMut,
}

impl SpecDocument {
    /// Writes `spec` as TOML (what `toml` makes of it), then comments it.
    pub fn new(spec: &NetworkSpec) -> Result<Self> {
        let doc: DocumentMut = spec
            .to_toml()?
            .parse()
            .context("reading back the spec as TOML")?;
        let mut document = SpecDocument { doc };
        document.comment_nodes();
        document.comment_ledger();
        Ok(document)
    }

    fn comment_nodes(&mut self) {
        let Some(nodes) = self
            .doc
            .get_mut("nodes")
            .and_then(Item::as_array_of_tables_mut)
        else {
            return;
        };
        for node in nodes.iter_mut() {
            node.decor_mut().set_prefix("\n");
            let role = node
                .get("role")
                .and_then(|r| r.as_str())
                .and_then(|r| toml::Value::String(r.into()).try_into::<Role>().ok());
            if let Some(role) = role {
                comment_after(node, "role", &role_comment(role));
            }
            comment_after(node, "balance", "MINA");
            comment_after(node, "fee", "MINA per snark work");
        }
    }

    fn comment_ledger(&mut self) {
        if let Some(ledger) = self.doc.get_mut("ledger").and_then(Item::as_table_mut) {
            ledger.decor_mut().set_prefix(LEDGER_COMMENT);
        }
    }

    /// The file: a header naming `command`, the spec, and examples of the
    /// sections the flags do not make.
    pub fn render(&self, command: &str) -> String {
        format!(
            "{}{}{FOOTER}",
            HEADER.replace("{command}", command),
            self.doc
        )
    }
}

/// `# comment` after the value of `key` in `table`, if it has one.
fn comment_after(table: &mut Table, key: &str, comment: &str) {
    let Some(value) = table.get_mut(key).and_then(Item::as_value_mut) else {
        return;
    };
    let width = format!("{key} = {value}").trim_end().len();
    let pad = COMMENT_COLUMN.saturating_sub(width).max(1);
    value
        .decor_mut()
        .set_suffix(format!("{}# {comment}", " ".repeat(pad)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::NodeFlags;

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
        let text = SpecDocument::new(&spec)
            .unwrap()
            .render("minimina spec init --seeds 2");
        assert!(
            text.starts_with("# minimina network spec, written by `minimina spec init --seeds 2`.")
        );
        assert!(
            text.contains(
                "role = \"block-producer\"      # produces blocks; balance default \"11550000\"\ncount = 3\n"
            ),
            "{text}"
        );
        assert!(text.contains("fee = \"0.001\"                # MINA per snark work"));
        let back: NetworkSpec = toml::from_str(&text).unwrap();
        assert_eq!(back, spec);

        // set values are written
        let mut spec = NetworkSpec::default_network();
        spec.profile = Some(crate::cli::Profile::Lightnet);
        spec.ledger.balance = Some("5.5".into());
        spec.ledger.file = Some("/tmp/a b.csv".into());
        let text = SpecDocument::new(&spec).unwrap().render("x");
        assert!(text.contains("profile = \"lightnet\""), "{text}");
        let back: NetworkSpec = toml::from_str(&text).unwrap();
        assert_eq!(back, spec);
    }
}
