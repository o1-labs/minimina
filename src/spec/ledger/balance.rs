use crate::spec::LedgerProblem;
use serde::{Deserialize, Serialize};

/// An amount of MINA with at most 9 decimals (`1000`, `0.5`), written as the
/// runtime config writes balances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Balance(String);

impl Balance {
    /// `mina` whole MINA.
    pub fn mina(mina: u64) -> Self {
        Balance(mina.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for Balance {
    type Err = LedgerProblem;

    fn from_str(balance: &str) -> Result<Self, LedgerProblem> {
        let (whole, fraction) = match balance.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (balance, None),
        };
        let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        let valid = digits(whole) && fraction.is_none_or(|f| digits(f) && f.len() <= 9);
        if !valid {
            return Err(LedgerProblem::Balance(balance.to_string()));
        }
        Ok(Balance(balance.to_string()))
    }
}

impl TryFrom<String> for Balance {
    type Error = LedgerProblem;

    fn try_from(balance: String) -> Result<Self, LedgerProblem> {
        balance.parse()
    }
}

impl From<Balance> for String {
    fn from(balance: Balance) -> Self {
        balance.0
    }
}

impl std::fmt::Display for Balance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mina_with_at_most_nine_decimals() {
        for ok in ["0", "1000", "0.5", "1.000000001"] {
            ok.parse::<Balance>().unwrap();
        }
        for bad in ["", "1.", ".5", "-1", "1.0000000001", "1,5", "1e9"] {
            assert!(bad.parse::<Balance>().is_err(), "{bad}");
        }
    }
}
