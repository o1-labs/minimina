//! `minimina spec ...` handlers.

use crate::{
    cli::{SpecCommand, SpecInitArgs},
    spec::{init::SpecDocument, NetworkSpec},
};
use anyhow::Result;

pub fn run(cmd: SpecCommand) -> Result<()> {
    match cmd {
        SpecCommand::Init(args) => {
            let command = std::iter::once("minimina".to_string())
                .chain(std::env::args().skip(1))
                .collect::<Vec<_>>()
                .join(" ");
            print!("{}", spec_init(&args, &command)?);
        }
    }
    Ok(())
}

/// The spec of the flags, as commented TOML. Not JSON like the other
/// commands: it is meant to be redirected into a file.
fn spec_init(args: &SpecInitArgs, command: &str) -> Result<String> {
    let mut spec = NetworkSpec::flags_base().with_flags(&args.nodes);
    spec.profile = args.profile;
    // a spec that `network create` would refuse is not written
    spec.plan()?;
    Ok(SpecDocument::new(&spec)?.render(command))
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
