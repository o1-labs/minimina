//! What `network create` makes a network from, read and checked before an
//! old network of the same name is stopped and deleted: a mistake in the
//! spec or its ledger file leaves the old network as it was.

use crate::{
    cli::CreateNetworkArgs,
    spec::{
        ledger::{LedgerAccount, LedgerFile},
        NetworkSpec, PlannedNode,
    },
};
use anyhow::Result;

/// The spec of `network create`: the node flags on top of `--spec`, else of
/// [`NetworkSpec::flags_base`]; with neither, the default network.
pub fn create_spec(cmd: &CreateNetworkArgs) -> Result<NetworkSpec> {
    let spec = match (&cmd.spec, cmd.nodes.is_empty()) {
        (Some(path), _) => NetworkSpec::load(path)?,
        (None, false) => NetworkSpec::flags_base(),
        (None, true) => NetworkSpec::default_network(),
    };
    Ok(spec.with_flags(&cmd.nodes))
}

/// The spec of `network create`, checked as far as it can be without the
/// network: its nodes are planned and the accounts of its ledger file read.
pub struct CreateInputs {
    pub spec: NetworkSpec,
    pub nodes: Vec<PlannedNode>,
    /// The accounts of `[ledger] file`, first in the genesis ledger.
    pub given: Vec<LedgerAccount>,
}

impl CreateInputs {
    pub fn read(cmd: &CreateNetworkArgs) -> Result<Self> {
        let spec = create_spec(cmd)?;
        let nodes = spec.plan()?;
        let given = match &spec.ledger.file {
            Some(file) => LedgerFile::load(file)?.accounts,
            None => vec![],
        };
        Ok(CreateInputs { spec, nodes, given })
    }
}
