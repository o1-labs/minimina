use serde::{Deserialize, Serialize};

/// A key file as mina writes it: `ciphertext` is the key, encrypted with
/// xsalsa20poly1305 under a key that argon2i derives from the password,
/// `pwsalt` and `pwdiff` (memory in bytes, passes). Bytes are base58check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFile {
    pub box_primitive: String,
    pub pw_primitive: String,
    pub nonce: String,
    pub pwsalt: String,
    pub pwdiff: (u64, u32),
    pub ciphertext: String,
}
