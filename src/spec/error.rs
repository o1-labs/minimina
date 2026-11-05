use std::path::PathBuf;

/// Why a spec, its flags or its ledger file cannot make a network.
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error(
        "the node flags (--seeds, --block-producers, ...) cannot be combined with -t/-g: \
         the legacy topology and ledger files bring their own nodes and keys; use --spec instead"
    )]
    FlagsWithLegacyFiles,
    #[error("ledger file {}: {problem}", .file.display())]
    LedgerFile {
        file: PathBuf,
        problem: LedgerProblem,
    },
}

/// What is wrong with a ledger file (see [`super::ledger`]).
#[derive(Debug, thiserror::Error)]
pub enum LedgerProblem {
    #[error("cannot read it: {0}")]
    Unreadable(std::io::Error),
    #[error("must be .json or .csv")]
    Extension,
    #[error("not valid JSON: {0}")]
    Json(serde_json::Error),
    #[error("no accounts: expected ledger.accounts, accounts, or an array")]
    NoAccounts,
    #[error("account {index}: {cause}")]
    JsonAccount {
        index: usize,
        cause: serde_json::Error,
    },
    #[error("empty: expected a header line")]
    NoHeader,
    #[error("unknown column '{0}'; the columns are public_key, balance, private_key, delegate")]
    UnknownColumn(String),
    #[error("the header needs a public_key and a balance column")]
    RequiredColumns,
    #[error("line {line}: {values} values for {columns} columns")]
    ValueCount {
        line: usize,
        values: usize,
        columns: usize,
    },
    #[error("line {line}: {problem}")]
    Line {
        line: usize,
        problem: Box<LedgerProblem>,
    },
    #[error("public_key and balance are required")]
    RequiredValues,
    #[error("'{0}' is not a mina public key (B62..., 55 characters)")]
    PublicKey(String),
    #[error("balance '{0}' is not an amount of MINA (like 1000 or 0.5)")]
    Balance(String),
    #[error("account {0} is there twice")]
    Duplicate(String),
}
