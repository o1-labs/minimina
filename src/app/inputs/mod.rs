//! What `network create` makes a network from, read and checked before an
//! old network of the same name is stopped and deleted: a mistake in a spec,
//! its ledger file or the legacy files leaves the old network as it was.

mod error;
mod legacy;
mod spec;

pub use error::InputsError;
pub use legacy::LegacyInputs;
pub use spec::{create_spec, SpecInputs};

use crate::{cli::CreateNetworkArgs, spec::NetworkSpec};
use anyhow::Result;

pub enum CreateInputs {
    /// `-t` and `-g`: nodes and keys from the topology, the ledger as given.
    Legacy(LegacyInputs),
    /// A spec: `--spec`, the node flags, or the default network.
    Spec(Box<SpecInputs>),
}

impl CreateInputs {
    pub fn read(cmd: &CreateNetworkArgs) -> Result<Self> {
        match (&cmd.topology, &cmd.genesis_ledger) {
            (Some(topology), Some(ledger)) => {
                if !cmd.nodes.is_empty() {
                    return Err(InputsError::FlagsWithLegacyFiles.into());
                }
                Ok(CreateInputs::Legacy(LegacyInputs::read(topology, ledger)?))
            }
            // the topology's keys are the ledger's accounts
            (None, Some(_)) => Err(InputsError::LedgerWithoutTopology.into()),
            (Some(_), None) => Err(InputsError::TopologyWithoutLedger.into()),
            (None, None) => Ok(CreateInputs::Spec(Box::new(SpecInputs::check(
                create_spec(cmd)?,
            )?))),
        }
    }

    /// The spec, unless the network comes from the legacy files.
    pub fn spec(&self) -> Option<&NetworkSpec> {
        match self {
            CreateInputs::Legacy(_) => None,
            CreateInputs::Spec(inputs) => Some(&inputs.spec),
        }
    }
}
