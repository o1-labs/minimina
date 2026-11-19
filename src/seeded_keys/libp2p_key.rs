//! A libp2p (ed25519) key derived from a seed and a name, in the form mina
//! prints and stores it: `<private>,<public>,<peer id>`.

use super::seed_hash;
use base64::Engine;
use ed25519_dalek::SigningKey;

/// libp2p's protobuf header of an ed25519 private key: key type 1, then the
/// 64 bytes of secret and public key.
const PRIVATE_KEY_HEADER: [u8; 4] = [0x08, 0x01, 0x12, 0x40];
/// libp2p's protobuf header of an ed25519 public key (32 bytes).
const PUBLIC_KEY_HEADER: [u8; 4] = [0x08, 0x01, 0x12, 0x20];
/// Multihash header of a peer id: the identity hash of the 36-byte public key.
const PEER_ID_HEADER: [u8; 2] = [0x00, 0x24];

/// The libp2p key of a daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Libp2pKey {
    secret: [u8; 32],
}

impl Libp2pKey {
    /// The key of `name` under `seed`.
    pub fn derive(seed: &str, name: &str) -> Self {
        Libp2pKey {
            secret: seed_hash("libp2p", seed, name),
        }
    }

    /// The key pair as `mina libp2p generate-keypair` prints it and its key
    /// file holds: base64 private and public key, then the peer id.
    pub fn keypair(&self) -> String {
        let base64 = base64::engine::general_purpose::STANDARD;
        let mut private = PRIVATE_KEY_HEADER.to_vec();
        private.extend_from_slice(&self.secret);
        private.extend_from_slice(&self.public());
        format!(
            "{},{},{}",
            base64.encode(private),
            base64.encode(self.public_protobuf()),
            self.peer_id()
        )
    }

    /// The peer id (`12D3KooW...`).
    pub fn peer_id(&self) -> String {
        let mut multihash = PEER_ID_HEADER.to_vec();
        multihash.extend_from_slice(&self.public_protobuf());
        bs58::encode(multihash).into_string()
    }

    fn public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .to_bytes()
    }

    fn public_protobuf(&self) -> Vec<u8> {
        let mut public = PUBLIC_KEY_HEADER.to_vec();
        public.extend_from_slice(&self.public());
        public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A key whose file mina 4.0.4 read back (`libp2p dump-keypair`), and
    /// whose peer id a daemon running on it reported.
    #[test]
    fn gives_the_keypair_and_peer_id_mina_gives() {
        let key = Libp2pKey {
            secret: Sha256::digest(b"libp2p:seed_0").into(),
        };
        let keypair = key.keypair();
        let parts: Vec<&str> = keypair.split(',').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].starts_with("CAESQ"), "{keypair}");
        assert_eq!(parts[1], "CAESIDAZLPGj2X208ijSPsMW3a9oB1o+5kqe8B50APiAK8wM");
        assert_eq!(
            parts[2],
            "12D3KooWD481Ah7gamjQ32SMrMheYrAcKmCrcCDUvMJxv4doNtzF"
        );
        assert_eq!(key.peer_id(), parts[2]);
    }

    #[test]
    fn same_seed_and_name_give_the_same_key() {
        let key = Libp2pKey::derive("lightnet", "seed-1");
        assert_eq!(key, Libp2pKey::derive("lightnet", "seed-1"));
        assert_ne!(key, Libp2pKey::derive("lightnet", "seed-2"));
        // not the account key of the same seed and name
        assert_ne!(key.secret, seed_hash("account", "lightnet", "seed-1"));
    }
}
