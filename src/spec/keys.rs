use serde::{Deserialize, Serialize};

/// `[keys]`: where the keys of the network come from.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeysSpec {
    /// Makes every key from this seed and the node or account name (see
    /// [`crate::seeded_keys`]), so each create gives the same accounts and
    /// peer ids. Without it, every create generates new keys with mina.
    pub seed: Option<String>,
}

impl KeysSpec {
    pub(super) fn is_empty(&self) -> bool {
        *self == KeysSpec::default()
    }
}
