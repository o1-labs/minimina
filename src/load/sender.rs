use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A test account a load pays from (and to).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender {
    /// Key file name in `network-keypairs` (`account-1`).
    pub name: String,
    pub public_key: String,
    /// The key file as the daemon sees it: on the host for a native network,
    /// under `/local-network` in a docker one.
    pub key_path: PathBuf,
}
