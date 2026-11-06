//! `minimina spec ...` handlers.

use crate::{
    cli::{SpecCommand, SpecInitArgs},
    spec::{init::SpecInit, NetworkSpec},
};
use anyhow::Result;
use askama::Template as _;

pub fn run(cmd: SpecCommand) -> Result<()> {
    match cmd {
        // askama drops the template's last newline
        SpecCommand::Init(args) => println!("{}", spec_init(&args, &invocation())?),
    }
    Ok(())
}

/// The command line this process was run with, for the header. The program
/// is its file name: the path it was run by (`./target/release/minimina`,
/// `/usr/local/bin/minimina`) says nothing about the spec.
fn invocation() -> String {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_default();
    let program = std::path::Path::new(&program)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or(program);
    std::iter::once(program)
        .chain(args)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The spec of the flags, as commented TOML. Not JSON like the other
/// commands: it is meant to be redirected into a file.
fn spec_init(args: &SpecInitArgs, command: &str) -> Result<String> {
    let mut spec = NetworkSpec::flags_base().with_flags(&args.nodes);
    spec.profile = args.profile;
    // a spec that `network create` would refuse is not written
    spec.plan()?;
    Ok(SpecInit {
        command,
        spec: &spec,
    }
    .render()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::NodeFlags;

    #[test]
    fn init_refuses_a_network_create_would() {
        let args = SpecInitArgs {
            profile: None,
            nodes: NodeFlags {
                seeds: Some(0),
                ..Default::default()
            },
        };
        let err = spec_init(&args, "x").unwrap_err().to_string();
        assert!(err.contains("no seed"), "{err}");
        let args = SpecInitArgs {
            profile: None,
            nodes: NodeFlags {
                rosetta: true,
                ..Default::default()
            },
        };
        let err = spec_init(&args, "x").unwrap_err().to_string();
        assert!(err.contains("needs an archive node"), "{err}");
    }
}
