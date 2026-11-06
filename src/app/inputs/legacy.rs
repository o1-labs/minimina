use super::InputsError;
use crate::{genesis_ledger, topology::Topology};
use std::path::{Path, PathBuf};

/// The legacy `-t` topology, parsed, and `-g` genesis ledger, read.
pub struct LegacyInputs {
    pub topology_path: PathBuf,
    pub topology: Topology,
    pub genesis_ledger: PathBuf,
}

impl LegacyInputs {
    pub fn read(topology_path: &Path, genesis_ledger: &Path) -> Result<Self, InputsError> {
        let topology = Topology::new(topology_path).map_err(|source| InputsError::Topology {
            path: topology_path.to_path_buf(),
            source,
        })?;
        if !topology.has_seed() {
            return Err(InputsError::NoSeed);
        }
        // copied later; a file that is not JSON stops here
        genesis_ledger::read_file(genesis_ledger).map_err(|source| InputsError::GenesisLedger {
            path: genesis_ledger.to_path_buf(),
            source,
        })?;
        Ok(LegacyInputs {
            topology_path: topology_path.to_path_buf(),
            topology,
            genesis_ledger: genesis_ledger.to_path_buf(),
        })
    }
}
