//! Mina Accounts-Manager (<https://github.com/o1-labs/mina-accounts-manager>):
//! hands funded accounts of the network out to tests, one at a time
//! (`GET /acquire-account`, `PUT /release-account`); o1js's
//! `Lightnet.acquireKeyPair` asks it.
//!
//! It is a native binary, published per architecture on the project's
//! GitHub releases; [`install`] downloads it. It reads the accounts it hands
//! out, with their private keys, from a ledger file minimina writes at
//! `network create` ([`AccountsLedger`]), and asks a daemon's GraphQL API on
//! `localhost` whether an account is a zkApp, so it runs in native mode only.
//! To unlock an account in that daemon it imports the account's key file,
//! named by its public key, from `MINA_KEYS_PATH`.

mod error;
pub mod install;
mod key_pair;
mod ledger;
mod release;

pub use error::AccountsManagerError;
pub use key_pair::KeyPair;
pub use ledger::AccountsLedger;

use crate::keys::KEY_PASSWORD;
use crate::spec::ledger::LedgerAccount;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub const DEFAULT_VERSION: &str = "0.1.2";

/// Under the tools directory: `accounts-manager/<version>/accounts-manager`.
pub const TOOL: &str = "accounts-manager";

/// It never hands out the last accounts of its ledger: a ledger needs more.
pub const ACCOUNTS_KEPT: usize = 10;

/// Directory of the accounts manager in the network directory: its ledger
/// file and its key files.
const DIR: &str = "accounts-manager";

/// The ledger file of the network's accounts manager.
pub fn ledger_path(network_path: &Path) -> PathBuf {
    network_path.join(DIR).join("ledger.json")
}

/// The key files of the network's accounts manager (`MINA_KEYS_PATH`), named
/// by public key.
pub fn keys_dir(network_path: &Path) -> PathBuf {
    network_path.join(DIR).join("keys")
}

/// Arguments of the accounts manager: its ledger file, its port, the GraphQL
/// port of its daemon, and the password of the key files.
pub fn args(ledger: &str, port: u16, graphql_port: u16) -> Vec<String> {
    vec![
        ledger.to_string(),
        port.to_string(),
        graphql_port.to_string(),
        KEY_PASSWORD.to_string(),
    ]
}

/// Environment of the accounts manager: where it finds key files to import.
pub fn env(keys: &str) -> Vec<(&'static str, String)> {
    vec![("MINA_KEYS_PATH", keys.to_string())]
}

/// A test account minimina generated: its key pair, and its key file.
#[derive(Debug, Clone)]
pub struct GeneratedAccount {
    pub pair: KeyPair,
    pub key_file: PathBuf,
}

/// Writes what the network's accounts manager reads: its ledger, of the
/// `given` accounts that have a private key and the `generated` ones, and its
/// key files, named by public key: those of `generated`, and every file of
/// `keys` (the given accounts' key files).
pub fn prepare(
    network_path: &Path,
    given: &[LedgerAccount],
    generated: &[GeneratedAccount],
    keys: Option<&Path>,
) -> Result<AccountsLedger, AccountsManagerError> {
    let pairs = given
        .iter()
        .filter_map(|a| {
            a.sk.clone().map(|sk| KeyPair {
                pk: a.pk.clone(),
                sk,
            })
        })
        .chain(generated.iter().map(|g| g.pair.clone()))
        .collect();
    let ledger = AccountsLedger::new(pairs)?;
    ledger.write(&ledger_path(network_path))?;

    let dir = keys_dir(network_path);
    fs::create_dir_all(&dir).map_err(AccountsManagerError::io(&dir))?;
    let given_files = match keys {
        Some(keys) => fs::read_dir(keys)
            .and_then(|entries| entries.map(|e| e.map(|e| e.path())).collect())
            .map_err(AccountsManagerError::io(keys))?,
        None => vec![],
    };
    let named = given_files
        .into_iter()
        .filter(|path| path.is_file())
        .filter_map(|path| Some((path.file_name()?.to_owned(), path)))
        .chain(
            generated
                .iter()
                .map(|g| (String::from(g.pair.pk.clone()).into(), g.key_file.clone())),
        );
    for (name, from) in named {
        let to = dir.join(name);
        fs::copy(&from, &to).map_err(AccountsManagerError::io(&from))?;
        // the daemon refuses key files others can read
        fs::set_permissions(&to, fs::Permissions::from_mode(0o600))
            .map_err(AccountsManagerError::io(&to))?;
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(AccountsManagerError::io(&dir))?;
    Ok(ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ledger::Balance;

    fn pk(i: usize) -> crate::spec::ledger::PublicKey {
        format!("B62q{:0>51}", i).parse().unwrap()
    }

    #[test]
    fn serves_given_accounts_with_a_key_and_generated_ones() {
        let net = tempfile::tempdir().unwrap();
        let generated_keys = net.path().join("network-keypairs");
        fs::create_dir_all(&generated_keys).unwrap();
        // ten given accounts with a private key, one without
        let mut given: Vec<_> = (0..11)
            .map(|i| LedgerAccount::new(pk(i), Balance::mina(1550)))
            .collect();
        for (i, account) in given.iter_mut().enumerate().take(10) {
            account.sk = Some(format!("EKgiven{i}"));
        }
        let key_file = generated_keys.join("account-1");
        fs::write(&key_file, "encrypted account-1").unwrap();
        let generated = [GeneratedAccount {
            pair: KeyPair {
                pk: pk(100),
                sk: "EKgenerated".into(),
            },
            key_file,
        }];
        let given_keys = tempfile::tempdir().unwrap();
        fs::write(given_keys.path().join(String::from(pk(0))), "encrypted 0").unwrap();

        let ledger = prepare(net.path(), &given, &generated, Some(given_keys.path())).unwrap();
        assert_eq!(ledger.served(), 11);
        let written: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(ledger_path(net.path())).unwrap()).unwrap();
        let accounts = written["ledger"]["accounts"].as_array().unwrap();
        assert_eq!(accounts[0]["sk"], "EKgiven0");
        assert_eq!(accounts[10]["pk"], String::from(pk(100)));
        assert_eq!(accounts[10]["sk"], "EKgenerated");

        // key files by public key, readable by the owner only
        let keys = keys_dir(net.path());
        for (name, content) in [
            (String::from(pk(0)), "encrypted 0"),
            (String::from(pk(100)), "encrypted account-1"),
        ] {
            let file = keys.join(name);
            assert_eq!(fs::read_to_string(&file).unwrap(), content);
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // without the generated one: ten, too few
        let err = prepare(net.path(), &given, &[], None).unwrap_err();
        assert!(matches!(
            err,
            AccountsManagerError::TooFewAccounts { found: 10 }
        ));
    }

    #[test]
    fn runs_with_its_ledger_port_daemon_and_password() {
        assert_eq!(
            args("/n/accounts-manager/ledger.json", 8181, 3085),
            [
                "/n/accounts-manager/ledger.json",
                "8181",
                "3085",
                "naughty blue worm"
            ]
        );
        assert_eq!(env("/n/keys"), [("MINA_KEYS_PATH", "/n/keys".to_string())]);
    }
}
