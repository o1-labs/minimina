//! Executables of a mina package, by the names the packages install them as.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    /// The daemon and client.
    Mina,
    Archive,
    Rosetta,
    /// `runtime_genesis_ledger`: makes genesis ledgers from a runtime config.
    CreateGenesis,
    Libp2pHelper,
}

impl Binary {
    pub const fn file_name(self) -> &'static str {
        match self {
            Binary::Mina => "mina",
            Binary::Archive => "mina-archive",
            Binary::Rosetta => "mina-rosetta",
            Binary::CreateGenesis => "mina-create-genesis",
            Binary::Libp2pHelper => "coda-libp2p_helper",
        }
    }

    /// The executable in the binary directory `bin_path`.
    pub fn path(self, bin_path: &Path) -> PathBuf {
        bin_path.join(self.file_name())
    }
}

impl std::fmt::Display for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.file_name())
    }
}
