use std::{io, path::PathBuf};

/// Why seeded keys cannot be made. The cause of an error is in its message,
/// not its `source`, so `{:#}` does not print it twice.
#[derive(Debug, thiserror::Error)]
pub enum SeededKeyError {
    #[error("deriving the key file encryption key: {0}")]
    Password(String),
    #[error("reading random bytes for a key file: {0}")]
    Random(String),
    #[error("encrypting the key file of '{0}'")]
    Encrypt(String),
    #[error("the public key of '{0}' is not a point of the Pallas curve")]
    PublicKey(String),
    #[error("writing '{}': {cause}", path.display())]
    Write { path: PathBuf, cause: io::Error },
    #[error("writing the key file of '{name}': {cause}")]
    Json {
        name: String,
        cause: serde_json::Error,
    },
}
