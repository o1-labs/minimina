//! A mina account key derived from a seed and a name: the same pair gives
//! the same key on every machine.
//!
//! The public key is computed here rather than with mina-rust's
//! `mina-signer`; the module docs of [`super`] say why.

use super::{error::SeededKeyError, seed_hash};
use pasta_curves::{
    arithmetic::CurveAffine,
    group::{ff::PrimeField, Curve},
    pallas,
};

/// base58check version byte of mina's private keys (`EK...`).
const PRIVATE_KEY_VERSION: u8 = 0x5a;
/// base58check version byte of mina's compressed public keys (`B62...`).
const PUBLIC_KEY_VERSION: u8 = 0xcb;
/// The `y` of mina's Pallas generator `(1, y)`, as little-endian limbs.
const GENERATOR_Y: [u64; 4] = [
    0x19cf_7a23_caed_2abb,
    0x8f65_5bd4_333d_4771,
    0x53df_a9f0_6378_ee54,
    0x1b74_b5a3_0a12_937c,
];

/// The private key of a mina account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKey {
    /// A scalar of the Pallas curve, little-endian, below 2^252.
    scalar: [u8; 32],
}

impl AccountKey {
    /// The key of `name` under `seed`.
    pub fn derive(seed: &str, name: &str) -> Self {
        let mut scalar = seed_hash("account", seed, name);
        // below 2^252, so below the order of the scalar field (about 2^254)
        scalar[31] &= 0x0f;
        AccountKey { scalar }
    }

    /// The private key as mina prints it (`EK...`).
    pub fn private_key(&self) -> String {
        bs58::encode(self.file_contents())
            .with_check_version(PRIVATE_KEY_VERSION)
            .into_string()
    }

    /// The public key as mina prints it (`B62...`): `name` is for the error.
    pub fn public_key(&self, name: &str) -> Result<String, SeededKeyError> {
        let no_point = || SeededKeyError::PublicKey(name.to_string());
        let generator: Option<pallas::Affine> =
            pallas::Affine::from_xy(pallas::Base::one(), pallas::Base::from_raw(GENERATOR_Y))
                .into();
        let point = (generator.ok_or_else(no_point)? * self.field_scalar()).to_affine();
        let coordinates: Option<pasta_curves::arithmetic::Coordinates<pallas::Affine>> =
            point.coordinates().into();
        let coordinates = coordinates.ok_or_else(no_point)?;
        let mut payload = vec![0x01, 0x01];
        payload.extend_from_slice(&coordinates.x().to_repr());
        payload.push(coordinates.y().to_repr()[0] & 1);
        Ok(bs58::encode(payload)
            .with_check_version(PUBLIC_KEY_VERSION)
            .into_string())
    }

    /// What mina's key file of this key encrypts: a version byte, then the
    /// scalar.
    pub fn file_contents(&self) -> Vec<u8> {
        let mut contents = vec![0x01];
        contents.extend_from_slice(&self.scalar);
        contents
    }

    fn field_scalar(&self) -> pallas::Scalar {
        let mut limbs = [0u64; 4];
        for (limb, bytes) in limbs.iter_mut().zip(self.scalar.chunks_exact(8)) {
            let mut le = [0u8; 8];
            le.copy_from_slice(bytes);
            *limb = u64::from_le_bytes(le);
        }
        pallas::Scalar::from_raw(limbs)
    }
}

#[cfg(test)]
impl AccountKey {
    /// The key of a known scalar.
    pub fn from_scalar(scalar: [u8; 32]) -> Self {
        AccountKey { scalar }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// lightnet's online_whale_account_0, decrypted from its key file, and
    /// the public key mina wrote next to it.
    #[test]
    fn gives_the_public_key_mina_gives() {
        let key = AccountKey::from_scalar(scalar(
            "cf17dac9f1ace61ed148f9d124cd3da8d6c4034db0bcf6ecab6b341d9dc9fd11",
        ));
        assert_eq!(
            key.public_key("whale").unwrap(),
            "B62qikT41XWwfMuoRC1SBvQxBfvHPnYfY7Hm9TUWNQXMLka5eP4xowB"
        );
    }

    #[test]
    fn same_seed_and_name_give_the_same_key() {
        let key = AccountKey::derive("lightnet", "bp-1");
        assert_eq!(key, AccountKey::derive("lightnet", "bp-1"));
        assert_ne!(key, AccountKey::derive("lightnet", "bp-2"));
        assert_ne!(key, AccountKey::derive("lightnet2", "bp-1"));
        assert!(key.scalar[31] < 0x10);
        assert!(key.private_key().starts_with("EK"), "{}", key.private_key());
        assert!(key.public_key("bp-1").unwrap().starts_with("B62q"));
        assert_eq!(key.file_contents().len(), 33);
    }
}
