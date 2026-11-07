use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("network '{0}' has no test accounts: give its spec [ledger] accounts = N (keys account-N in network-keypairs)")]
    NoAccounts(String),
    #[error("network '{network}' has no test account '{name}'; it has {known}")]
    UnknownSender {
        network: String,
        name: String,
        known: String,
    },
    #[error(
        "'{sender}' already pays in {load}, which is running; a sender can be in one running load"
    )]
    SenderBusy { sender: String, load: String },
    #[error("network '{network}' has no daemon '{node}'")]
    UnknownNode { network: String, node: String },
    #[error("network '{0}' has no daemon to send payments through")]
    NoDaemon(String),
    #[error("'{0}' has no GraphQL port")]
    NoGraphql(String),
    #[error("network '{network}' has no load '{id}'")]
    UnknownLoad { network: String, id: String },
    #[error("{0} must be at least 1")]
    Zero(&'static str),
    #[error("{what} {}: {cause}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        cause: std::io::Error,
    },
    #[error("{}: {cause}", path.display())]
    Json {
        path: PathBuf,
        cause: serde_json::Error,
    },
    #[error("starting the load process: {0}")]
    Spawn(std::io::Error),
    #[error("starting the runtime for daemon queries: {0}")]
    Runtime(std::io::Error),
    #[error("listening for SIGTERM: {0}")]
    Signal(std::io::Error),
}
