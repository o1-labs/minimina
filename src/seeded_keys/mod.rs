//! Keys from a seed: the spec's `[keys] seed` makes every key of a network
//! (block producers, snark coordinator, test accounts, libp2p) from the seed
//! and the node or account name, so a network gets the same accounts and peer
//! ids on every create and every machine.
//!
//! minimina makes them itself, in mina's formats: key files mina reads with
//! the password [`KEY_PASSWORD`], `<name>.pub` and `<name>.peerid` next to
//! them. Encrypting a key file costs mina about half a second each; here the
//! encryption key is derived once ([`SecretBox`]), so a thousand accounts take
//! about a second.
//!
//! Why not mina-rust's keys (`mina-node-account`, `mina-p2p`, `mina-signer`):
//! - they derive the encryption key for every file, so a thousand accounts
//!   take minutes, they cannot write libp2p key files yet, and they do not
//!   make keys from a seed;
//! - they would pull in all of mina's wire types for a few lines of code;
//! - they are not on crates.io, only git dependencies.
//!
//! Both build on the same crates (`argon2`, `crypto_secretbox`,
//! `ed25519-dalek`, `bs58`), and the tests here check the keys against files
//! and keys mina made. If mina-rust's keys gain seeds and one encryption key
//! for many files, [`AccountKey`] can use them instead.

mod account_key;
mod error;
mod libp2p_key;
mod secret_box;
mod secret_file;

pub use account_key::AccountKey;
pub use error::SeededKeyError;
pub use libp2p_key::Libp2pKey;
pub use secret_box::SecretBox;
pub use secret_file::SecretFile;

use crate::{
    directory_manager::{LIBP2P_KEYPAIRS, NETWORK_KEYPAIRS},
    keys::{NodeKey, KEY_PASSWORD},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Writes the keys of a network from its seed.
pub struct SeededKeys {
    seed: String,
    network_path: PathBuf,
    /// Where the nodes find `network_path`: itself in native mode,
    /// `/local-network` in the containers of docker mode.
    key_root: String,
    secret_box: SecretBox,
}

impl SeededKeys {
    /// Keys of `seed`, written to `network_path`.
    pub fn new(seed: &str, network_path: &Path, key_root: &str) -> Result<Self, SeededKeyError> {
        Ok(Self::with_secret_box(
            seed,
            network_path,
            key_root,
            SecretBox::new(KEY_PASSWORD)?,
        ))
    }

    fn with_secret_box(
        seed: &str,
        network_path: &Path,
        key_root: &str,
        secret_box: SecretBox,
    ) -> Self {
        SeededKeys {
            seed: seed.to_string(),
            network_path: network_path.to_path_buf(),
            key_root: key_root.to_string(),
            secret_box,
        }
    }

    /// The account keys of `names`: `network-keypairs/<name>` and
    /// `<name>.pub`, by name.
    pub fn account_keys(&self, names: &[&str]) -> Result<HashMap<String, NodeKey>, SeededKeyError> {
        let dir = self.network_path.join(NETWORK_KEYPAIRS);
        let mut keys = HashMap::new();
        for &name in names {
            let key = AccountKey::derive(&self.seed, name);
            let public_key = key.public_key(name)?;
            let file = self.secret_box.seal(name, &key.file_contents())?;
            write(&dir, name, &file, 0o600)?;
            write(
                &dir,
                &format!("{name}.pub"),
                &format!("{public_key}\n"),
                0o644,
            )?;
            keys.insert(
                name.to_string(),
                NodeKey {
                    key_string: public_key,
                    key_path: format!("{}/{NETWORK_KEYPAIRS}/{name}", self.key_root),
                },
            );
        }
        Ok(keys)
    }

    /// The libp2p keys of `names`: `libp2p-keypairs/<name>` and
    /// `<name>.peerid`, by name.
    pub fn libp2p_keys(&self, names: &[&str]) -> Result<HashMap<String, NodeKey>, SeededKeyError> {
        let dir = self.network_path.join(LIBP2P_KEYPAIRS);
        let mut keys = HashMap::new();
        for &name in names {
            let key = Libp2pKey::derive(&self.seed, name);
            let keypair = key.keypair();
            let file = self.secret_box.seal(name, keypair.as_bytes())?;
            write(&dir, name, &file, 0o600)?;
            write(
                &dir,
                &format!("{name}.peerid"),
                &format!("{}\n", key.peer_id()),
                0o644,
            )?;
            keys.insert(
                name.to_string(),
                NodeKey {
                    key_string: keypair,
                    key_path: format!("{}/{LIBP2P_KEYPAIRS}/{name}", self.key_root),
                },
            );
        }
        Ok(keys)
    }

    /// The private key of account `name` (`EK...`).
    pub fn private_key(&self, name: &str) -> String {
        AccountKey::derive(&self.seed, name).private_key()
    }
}

/// 32 bytes of `seed` and `name` for keys of `kind`; each part is
/// length-prefixed, so no two (kind, seed, name) give the same bytes.
fn seed_hash(kind: &str, seed: &str, name: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in ["minimina", kind, seed, name] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}

/// Writes `contents` to `dir/name` with `mode`; `dir` is made 0700 if missing.
fn write(dir: &Path, name: &str, contents: &str, mode: u32) -> Result<(), SeededKeyError> {
    let path = dir.join(name);
    let failed = |cause| SeededKeyError::Write {
        path: path.clone(),
        cause,
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(failed)?;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn keys(seed: &str, net: &Path) -> SeededKeys {
        let cheap = SecretBox::with_cost(KEY_PASSWORD, 64 * 1024, 1).unwrap();
        SeededKeys::with_secret_box(seed, net, "/local-network", cheap)
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn writes_account_key_files_mina_reads() {
        let net = tempfile::tempdir().unwrap();
        let written = keys("lightnet", net.path())
            .account_keys(&["bp-1", "account-1"])
            .unwrap();
        let key = AccountKey::derive("lightnet", "bp-1");
        let public_key = key.public_key("bp-1").unwrap();
        assert_eq!(written["bp-1"].key_string, public_key);
        assert_eq!(
            written["bp-1"].key_path,
            "/local-network/network-keypairs/bp-1"
        );

        let dir = net.path().join("network-keypairs");
        let file = std::fs::read_to_string(dir.join("bp-1")).unwrap();
        assert_eq!(secret_box::open(KEY_PASSWORD, &file), key.file_contents());
        assert_eq!(
            std::fs::read_to_string(dir.join("bp-1.pub")).unwrap(),
            format!("{public_key}\n")
        );
        assert_eq!(mode(&dir.join("bp-1")), 0o600);
        assert_eq!(mode(&dir.join("bp-1.pub")), 0o644);
        assert_eq!(mode(&dir), 0o700);
        assert_ne!(written["account-1"].key_string, public_key);
    }

    #[test]
    fn writes_libp2p_key_files_mina_reads() {
        let net = tempfile::tempdir().unwrap();
        let written = keys("lightnet", net.path())
            .libp2p_keys(&["seed-1"])
            .unwrap();
        let key = Libp2pKey::derive("lightnet", "seed-1");
        assert_eq!(written["seed-1"].key_string, key.keypair());
        assert_eq!(
            written["seed-1"].key_path,
            "/local-network/libp2p-keypairs/seed-1"
        );
        let dir = net.path().join("libp2p-keypairs");
        let file = std::fs::read_to_string(dir.join("seed-1")).unwrap();
        assert_eq!(
            secret_box::open(KEY_PASSWORD, &file),
            key.keypair().as_bytes()
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("seed-1.peerid")).unwrap(),
            format!("{}\n", key.peer_id())
        );
        assert_eq!(mode(&dir.join("seed-1")), 0o600);
    }

    #[test]
    fn same_seed_gives_the_same_keys_on_every_create() {
        let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let names = ["bp-1", "account-1"];
        let a = keys("lightnet", first.path()).account_keys(&names).unwrap();
        let b = keys("lightnet", second.path())
            .account_keys(&names)
            .unwrap();
        for name in names {
            assert_eq!(a[name].key_string, b[name].key_string);
        }
        let other = keys("other", second.path()).account_keys(&names).unwrap();
        assert_ne!(a["bp-1"].key_string, other["bp-1"].key_string);
        assert_eq!(
            keys("lightnet", first.path()).private_key("account-1"),
            AccountKey::derive("lightnet", "account-1").private_key()
        );
    }

    #[test]
    fn parts_of_the_seed_do_not_run_together() {
        assert_ne!(
            seed_hash("account", "a", "bc"),
            seed_hash("account", "ab", "c")
        );
        assert_ne!(
            seed_hash("account", "a", "b"),
            seed_hash("libp2p", "a", "b")
        );
    }
}
