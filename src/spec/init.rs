//! A spec as commented TOML: what `spec init` writes, for the user to edit
//! and keep. It reads back as the same spec.

use super::{NetworkSpec, NodeGroup, Role, DEFAULT_BLOCK_PRODUCER_BALANCE};
use std::fmt::Write as _;

/// What each role is, next to its `role` line.
fn role_comment(role: Role) -> &'static str {
    match role {
        Role::Seed => "peers find each other through the seeds",
        Role::BlockProducer => "produces blocks with its stake",
        Role::Plain => "follows the chain, produces no blocks",
        Role::Archive => "+ mina-archive and a postgres database",
        Role::SnarkCoordinator => "hands out snark work to its workers",
        Role::Rosetta => "mina-rosetta: reads the archive database",
        Role::ArchiveNodeApi => "GraphQL over the archive database (events, actions)",
    }
}

fn quoted(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// `key = value` with a comment aligned after it.
fn line(out: &mut String, assignment: &str, comment: &str) {
    if comment.is_empty() {
        let _ = writeln!(out, "{assignment}");
    } else {
        let _ = writeln!(out, "{assignment:<30}# {comment}");
    }
}

fn group(out: &mut String, g: &NodeGroup) {
    let _ = writeln!(out, "\n[[nodes]]");
    let role = toml::Value::try_from(g.role)
        .map(|v| v.to_string())
        .unwrap_or_default();
    line(out, &format!("role = {role}"), role_comment(g.role));
    if g.count != 1 {
        line(out, &format!("count = {}", g.count), "");
    }
    if let Some(name) = &g.name {
        line(out, &format!("name = {}", quoted(name)), "");
    }
    match (&g.balance, g.role) {
        (Some(balance), _) => line(out, &format!("balance = {}", quoted(balance)), "MINA"),
        (None, Role::BlockProducer) => line(
            out,
            &format!("# balance = {}", quoted(DEFAULT_BLOCK_PRODUCER_BALANCE)),
            "default",
        ),
        _ => {}
    }
    if let Some(port) = g.client_port {
        line(out, &format!("client_port = {port}"), "");
    }
    if let Some(port) = g.archive_port {
        line(out, &format!("archive_port = {port}"), "");
    }
    if let Some(workers) = g.workers {
        line(out, &format!("workers = {workers}"), "");
    }
    if let Some(fee) = &g.fee {
        line(
            out,
            &format!("fee = {}", quoted(fee)),
            "MINA per snark work",
        );
    }
    if let Some(node) = &g.node {
        line(out, &format!("node = {}", quoted(node)), "");
    }
    if g.role == Role::Rosetta && g.node.is_none() {
        line(
            out,
            "# node = \"node-1\"",
            "the daemon whose GraphQL it reads (default: the archive node)",
        );
    }
    if let Some(version) = &g.version {
        line(out, &format!("version = {}", quoted(version)), "");
    }
    if let Some(bin) = &g.bin {
        line(
            out,
            &format!("bin = {}", quoted(&bin.to_string_lossy())),
            "",
        );
    }
}

/// `spec` as commented TOML. `command` is the command that made it.
pub fn render(spec: &NetworkSpec, command: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# minimina network spec, written by `{command}`.\n\
         # Create the network: minimina network create -n <network> --spec <this file>\n\
         #\n\
         # minimina generates the keys, ports, peers and genesis ledger. Node names\n\
         # default to <role>-<n> (seed-1, bp-1, node-1, ...); client ports are\n\
         # assigned from 3100 in steps of 10 unless a node sets `client_port`.\n"
    );
    let _ = writeln!(
        out,
        "# Build profile of the mina binaries: dev, devnet, lightnet, mainnet.\n\
         # --profile overrides it."
    );
    match spec.profile {
        Some(profile) => line(&mut out, &format!("profile = \"{profile}\""), ""),
        None => line(&mut out, "# profile = \"devnet\"", "default"),
    }
    for g in &spec.nodes {
        group(&mut out, g);
    }

    let _ = writeln!(
        out,
        "\n# Funded accounts for transactions in tests: account-1 .. account-N."
    );
    let _ = writeln!(out, "# Keys are in <network dir>/network-keypairs.");
    let _ = writeln!(out, "[ledger]");
    line(
        &mut out,
        &format!("accounts = {}", spec.ledger.accounts),
        "",
    );
    match &spec.ledger.balance {
        Some(balance) => line(&mut out, &format!("balance = {}", quoted(balance)), "MINA"),
        None => line(&mut out, "# balance = \"1000\"", "default"),
    }
    match &spec.ledger.file {
        Some(file) => line(
            &mut out,
            &format!("file = {}", quoted(&file.to_string_lossy())),
            "",
        ),
        None => {
            line(
                &mut out,
                "# file = \"accounts.csv\"",
                "accounts to start with; the generated ones are added",
            );
            let _ = writeln!(
                out,
                "#   .json: a runtime config ledger (ledger.accounts), as -g takes it\n\
                 #   .csv:  a header line, then public_key,balance[,private_key,delegate]\n\
                 #          per line; balances in MINA"
            );
        }
    }

    let _ = writeln!(
        out,
        "\n# Merged into the generated genesis runtime config.\n\
         # [runtime_config.genesis]\n\
         # k = 10\n\
         # [runtime_config.proof]\n\
         # block_window_duration_ms = 30000\n\
         \n\
         # Docker mode images (defaults: the built-in images).\n\
         # [docker]\n\
         # daemon_image = \"minaprotocol/mina-daemon:...\"\n\
         \n\
         # A fork to postfork binaries (native mode only); see the README.\n\
         # [hardfork]\n\
         # mode = \"manual\"\n\
         # at = {{ slot = 42 }}\n\
         # postfork = {{ mina_version = \"4.0.4\" }}"
    );
    out
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
        let text = render(&spec, "minimina spec init --seeds 2");
        assert!(
            text.starts_with("# minimina network spec, written by `minimina spec init --seeds 2`.")
        );
        assert!(text.contains(
            "role = \"block-producer\"       # produces blocks with its stake\ncount = 3\n"
        ));
        let back: NetworkSpec = toml::from_str(&text).unwrap();
        assert_eq!(back, spec);

        // set values are written, not commented
        let mut spec = NetworkSpec::default_network();
        spec.profile = Some(crate::cli::Profile::Lightnet);
        spec.ledger.balance = Some("5.5".into());
        spec.ledger.file = Some("/tmp/a b.csv".into());
        let back: NetworkSpec = toml::from_str(&render(&spec, "x")).unwrap();
        assert_eq!(back, spec);
    }
}
