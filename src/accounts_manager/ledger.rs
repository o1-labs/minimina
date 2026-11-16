use super::{AccountsManagerError, KeyPair, ACCOUNTS_KEPT};
use serde::Serialize;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// The ledger file the accounts manager reads: a runtime config's `ledger`,
/// with only the accounts it may hand out.
#[derive(Debug, Serialize)]
pub struct AccountsLedger {
    ledger: Accounts,
}

#[derive(Debug, Serialize)]
struct Accounts {
    name: &'static str,
    accounts: Vec<KeyPair>,
}

impl AccountsLedger {
    /// The ledger of `accounts`; the accounts manager keeps
    /// [`ACCOUNTS_KEPT`] of them unused, so there must be more.
    pub fn new(accounts: Vec<KeyPair>) -> Result<Self, AccountsManagerError> {
        if accounts.len() <= ACCOUNTS_KEPT {
            return Err(AccountsManagerError::TooFewAccounts {
                found: accounts.len(),
            });
        }
        Ok(AccountsLedger {
            ledger: Accounts {
                name: "minimina",
                accounts,
            },
        })
    }

    pub fn write(&self, path: &Path) -> Result<(), AccountsManagerError> {
        let io = |cause| AccountsManagerError::Io {
            path: path.to_path_buf(),
            cause,
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|e| io(e.into()))?;
        fs::write(path, json).map_err(io)?;
        // it holds private keys
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(AccountsManagerError::io(path))
    }

    /// How many accounts it hands out at most.
    pub fn served(&self) -> usize {
        self.ledger.accounts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(i: usize) -> KeyPair {
        let pk = format!("B62q{:0>51}", i).parse().unwrap();
        KeyPair {
            pk,
            sk: format!("EK{i}"),
        }
    }

    #[test]
    fn needs_more_accounts_than_it_keeps() {
        let ten: Vec<_> = (0..10).map(pair).collect();
        let err = AccountsLedger::new(ten).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the accounts manager needs more than 10 accounts with a private key, \
             as it keeps 10 of them unused; the network has 10: add `accounts` in \
             [ledger], or accounts with a private key to its file"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts-manager/ledger.json");
        let ledger = AccountsLedger::new((0..11).map(pair).collect()).unwrap();
        ledger.write(&path).unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["ledger"]["name"], "minimina");
        assert_eq!(written["ledger"]["accounts"].as_array().unwrap().len(), 11);
        assert_eq!(written["ledger"]["accounts"][3]["sk"], "EK3");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
