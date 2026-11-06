use std::path::PathBuf;

/// Why the inputs of `network create` cannot make a network.
#[derive(Debug, thiserror::Error)]
pub enum InputsError {
    #[error(
        "the node flags (--seeds, --block-producers, ...) cannot be combined with -t/-g: \
         the legacy topology and ledger files bring their own nodes and keys; use --spec instead"
    )]
    FlagsWithLegacyFiles,
    #[error(
        "Must provide a topology file with a genesis ledger, keys will be incompatible otherwise."
    )]
    LedgerWithoutTopology,
    #[error(
        "Must provide a genesis ledger with a topology file, keys will be incompatible otherwise."
    )]
    TopologyWithoutLedger,
    #[error("Error occured while parsing the topology file:\npath: {}: {source}", .path.display())]
    Topology {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("There are no seed nodes declared in this network. You must include seed nodes.")]
    NoSeed,
    #[error("genesis ledger {}: {source}", .path.display())]
    GenesisLedger {
        path: PathBuf,
        source: std::io::Error,
    },
}
