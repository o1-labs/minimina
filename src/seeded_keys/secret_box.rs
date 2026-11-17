//! Encrypts key files the way mina does. mina derives a file's encryption
//! key from the password with argon2i, which costs about half a second and
//! 128 MiB per file; every file here shares one salt, so the key is derived
//! once and each file gets its own nonce.

use super::{error::SeededKeyError, secret_file::SecretFile};
use argon2::{Algorithm, Argon2, Params, Version};
use crypto_secretbox::{
    aead::{Aead, KeyInit},
    Key, Nonce, XSalsa20Poly1305,
};

/// base58check version byte of the nonce, salt and ciphertext of a key file.
const BYTES_VERSION: u8 = 0x02;
/// argon2i memory of mina's key files, in bytes.
pub const MINA_MEMORY: u64 = 134_217_728;
/// argon2i passes of mina's key files.
pub const MINA_PASSES: u32 = 6;

/// Seals key files under one password.
pub struct SecretBox {
    salt: [u8; 16],
    key: [u8; 32],
    memory: u64,
    passes: u32,
}

impl SecretBox {
    /// Key files that mina reads with `password`, at mina's argon2i cost.
    pub fn new(password: &str) -> Result<Self, SeededKeyError> {
        Self::with_cost(password, MINA_MEMORY, MINA_PASSES)
    }

    /// Key files at an argon2i cost of `memory` bytes and `passes`; each
    /// file records the cost, so mina reads it at any cost.
    pub fn with_cost(password: &str, memory: u64, passes: u32) -> Result<Self, SeededKeyError> {
        let mut salt = [0u8; 16];
        random(&mut salt)?;
        let key = derive(password, &salt, memory, passes)?;
        Ok(SecretBox {
            salt,
            key,
            memory,
            passes,
        })
    }

    /// The key file of `plaintext`, as JSON; `name` is for errors.
    pub fn seal(&self, name: &str, plaintext: &[u8]) -> Result<String, SeededKeyError> {
        let mut nonce = [0u8; 24];
        random(&mut nonce)?;
        let ciphertext = XSalsa20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| SeededKeyError::Encrypt(name.to_string()))?;
        let file = SecretFile {
            box_primitive: "xsalsa20poly1305".into(),
            pw_primitive: "argon2i".into(),
            nonce: base58check(&nonce),
            pwsalt: base58check(&self.salt),
            pwdiff: (self.memory, self.passes),
            ciphertext: base58check(&ciphertext),
        };
        serde_json::to_string(&file).map_err(|cause| SeededKeyError::Json {
            name: name.to_string(),
            cause,
        })
    }
}

/// argon2i (version 0x13, one lane) of `password`: the encryption key.
fn derive(
    password: &str,
    salt: &[u8],
    memory: u64,
    passes: u32,
) -> Result<[u8; 32], SeededKeyError> {
    let failed = |e: argon2::Error| SeededKeyError::Password(e.to_string());
    let kib = u32::try_from(memory / 1024)
        .map_err(|_| SeededKeyError::Password(format!("{memory} bytes is too much memory")))?;
    let params = Params::new(kib, passes, 1, Some(32)).map_err(failed)?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2i, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(failed)?;
    Ok(key)
}

fn random(bytes: &mut [u8]) -> Result<(), SeededKeyError> {
    getrandom::fill(bytes).map_err(|e| SeededKeyError::Random(e.to_string()))
}

fn base58check(bytes: &[u8]) -> String {
    bs58::encode(bytes)
        .with_check_version(BYTES_VERSION)
        .into_string()
}

/// Opens a key file the way mina does.
#[cfg(test)]
pub fn open(password: &str, json: &str) -> Vec<u8> {
    let file: SecretFile = serde_json::from_str(json).unwrap();
    let bytes = |s: &str| {
        let raw = bs58::decode(s)
            .with_check(Some(BYTES_VERSION))
            .into_vec()
            .unwrap();
        raw[1..].to_vec()
    };
    let key = derive(password, &bytes(&file.pwsalt), file.pwdiff.0, file.pwdiff.1).unwrap();
    XSalsa20Poly1305::new(Key::from_slice(&key))
        .decrypt(
            Nonce::from_slice(&bytes(&file.nonce)),
            bytes(&file.ciphertext).as_slice(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_with_the_password_it_was_sealed_with() {
        let secret_box = SecretBox::with_cost("naughty blue worm", 64 * 1024, 2).unwrap();
        let first = secret_box.seal("a", b"first key").unwrap();
        let second = secret_box.seal("b", b"second key").unwrap();
        assert_eq!(open("naughty blue worm", &first), b"first key");
        assert_eq!(open("naughty blue worm", &second), b"second key");

        let (first, second): (SecretFile, SecretFile) = (
            serde_json::from_str(&first).unwrap(),
            serde_json::from_str(&second).unwrap(),
        );
        assert_eq!(first.pwsalt, second.pwsalt);
        assert_ne!(first.nonce, second.nonce);
        assert_eq!(first.pwdiff, (65536, 2));
        assert_eq!(first.box_primitive, "xsalsa20poly1305");
        assert_eq!(first.pw_primitive, "argon2i");
    }

    /// lightnet's key file of libp2p key whale_0, written by mina.
    #[test]
    fn opens_a_key_file_mina_wrote() {
        let file = r#"{"box_primitive":"xsalsa20poly1305","pw_primitive":"argon2i","nonce":"6hFNdupdn2LrdPEr1enFifSh3vjfvghunZx62FJ","pwsalt":"A63sSCBkLQdC2Mdo7Gagqni83w9m","pwdiff":[134217728,6],"ciphertext":"8gbs6he2H5R6KV7FjvEkJqcDsiY1ATCZAodPqTRt1LjiDLB5h7t3iyYtLzQyMaFhdpkvFLSV3D1kPMq3b2VMEz9inUsMctqCsmaHUJqpwYthEeLSrtFtoPr3xfUGXsD87RQqdCeteV5vWf95hFhJqG8RV2JJ3L2GD1y8WBQQxi1GNocdeh7bZPytuboZiS1QwnqKyopkoQvu4QvaPhrtbaZqNeQNSssMW9L7r2885RLTH7RsZmUiPcDPwf7MJabWAkAjRCSmaLjBsfAyNX2W29VxmXxFp4TNPrDEp"}"#;
        let keypair = String::from_utf8(open("naughty blue worm", file)).unwrap();
        assert!(
            keypair.ends_with(",12D3KooWKZEpVsZdWr94ChZisfmC4BPgg7J1bGrvQr5DNaLSKUAU"),
            "{keypair}"
        );
    }
}
