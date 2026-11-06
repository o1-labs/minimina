use super::InputsError;
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
    if !cmd.nodes.is_empty() && cmd.uses_legacy_files() {
        return Err(InputsError::FlagsWithLegacyFiles.into());
    }
    let spec = match (&cmd.spec, cmd.nodes.is_empty()) {
        (Some(path), _) => NetworkSpec::load(path)?,
        (None, false) => NetworkSpec::flags_base(),
        (None, true) => NetworkSpec::default_network(),
    };
    Ok(spec.with_flags(&cmd.nodes))
}

/// A spec checked as far as it can be without the network: its nodes are
/// planned and the accounts of its ledger file are read.
pub struct SpecInputs {
    pub spec: NetworkSpec,
    pub nodes: Vec<PlannedNode>,
    /// The accounts of `[ledger] file`, first in the genesis ledger.
    pub given: Vec<LedgerAccount>,
}

impl SpecInputs {
    pub fn check(spec: NetworkSpec) -> Result<Self> {
        let nodes = spec.plan()?;
        let given = match &spec.ledger.file {
            Some(file) => LedgerFile::load(file)?.accounts,
            None => vec![],
        };
        Ok(SpecInputs { spec, nodes, given })
    }
}
