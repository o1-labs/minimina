use crate::spec::LedgerProblem;
use serde::{Deserialize, Serialize};

/// A mina public key: `B62` and 52 more base58 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKey(String);

impl std::str::FromStr for PublicKey {
    type Err = LedgerProblem;

    fn from_str(key: &str) -> Result<Self, LedgerProblem> {
        if key.len() != 55 || !key.starts_with("B62") {
            return Err(LedgerProblem::PublicKey(key.to_string()));
        }
        Ok(PublicKey(key.to_string()))
    }
}

impl TryFrom<String> for PublicKey {
    type Error = LedgerProblem;

    fn try_from(key: String) -> Result<Self, LedgerProblem> {
        key.parse()
    }
}

impl From<PublicKey> for String {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b62_and_55_characters() {
        let key = "B62qrPN5Y5yq8kGE3FbVKbGTdTAJNdtNtB5sNVpxyRwWGcDEhpMzc8g";
        assert_eq!(key.parse::<PublicKey>().unwrap().to_string(), key);
        assert!("B62x".parse::<PublicKey>().is_err());
        assert!(key.replace("B62", "B63").parse::<PublicKey>().is_err());
    }
}
