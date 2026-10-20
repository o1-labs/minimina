//! # Keys Module
//!
//! This module provides functionalities related to key management for local network.
//! It contains:
//! - Structures to represent mina node keys (`NodeKey`).
//! - A manager (`KeysManager`) that provides methods for generating:
//!   - Block producer key pairs.
//!   - libp2p key pairs.
//!
//! The `KeysManager` relies on Docker and a specific Docker image to generate these key pairs,
//! and uses the filesystem to store and manage these keys. It is designed to produce keys for multiple services
//! and ensure the necessary environment settings are present during the key generation process.
//!
//! Typical use involves creating a `KeysManager` instance with the desired configurations,
//! then invoking the key generation methods as needed.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    rc::Rc,
};

use log::{debug, info};

use crate::cli::Profile;
use crate::runner::{check, Runner};
use crate::utils::get_current_user_uid_gid;

/// Parses `mina advanced generate-keypair` output: `Public key: <B62...>`.
pub fn parse_public_key(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Public key:"))
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
}

/// Parses `mina libp2p generate-keypair` output: the keypair is printed on
/// the line after the `libp2p keypair:` header.
pub fn parse_libp2p_keypair(stdout: &str) -> Option<String> {
    let (_, rest) = stdout.split_once("libp2p keypair:")?;
    rest.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

#[derive(Debug)]
pub struct NodeKey {
    pub key_string: String,
    pub key_path: String,
}

pub struct KeysManager {
    pub network_path: PathBuf,
    pub docker_image: String,
    profile_env: String,
    runner: Rc<dyn Runner>,
}

impl KeysManager {
    pub fn new(
        network_path: &Path,
        docker_image: &str,
        profile: Profile,
        runner: Rc<dyn Runner>,
    ) -> Self {
        KeysManager {
            network_path: network_path.to_path_buf(),
            docker_image: docker_image.to_string(),
            profile_env: format!("{}={profile}", Profile::ENV),
            runner,
        }
    }

    fn volume(&self) -> std::io::Result<String> {
        let path = self.network_path.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "network path '{}' is not valid UTF-8",
                    self.network_path.display()
                ),
            )
        })?;
        Ok(format!("{path}:/local-network"))
    }
    // generate bp key pair for single service
    pub fn generate_bp_key_pair(&self, service_name: &str) -> std::io::Result<NodeKey> {
        info!("Creating block producer keys for: {}", service_name);
        let uid_gid = match get_current_user_uid_gid() {
            Some(uid_gid) => uid_gid,
            None => {
                return Err(std::io::Error::other(
                    "Unable to retrieve UID and GID of current user",
                ))
            }
        };

        let key_subdir = "network-keypairs";
        let volume_path = self.volume()?;
        let pkey_path = format!("/local-network/{}/{}", key_subdir, service_name);
        let args = vec![
            "run",
            "--rm",
            "--user",
            uid_gid.as_str(),
            "--env",
            "MINA_PRIVKEY_PASS=naughty blue worm",
            "--env",
            &self.profile_env,
            "--entrypoint",
            "mina",
            "-v",
            &volume_path,
            self.docker_image.as_str(),
            "advanced",
            "generate-keypair",
            "-privkey-path",
            &pkey_path,
        ];

        let output = check(
            self.runner.run("docker".as_ref(), &args, &[])?,
            &format!("generating block producer key for '{service_name}'"),
        )?;

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let public_key = parse_public_key(&stdout_str).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Could not parse public key from output: {stdout_str}"),
            )
        })?;

        let keys = NodeKey {
            key_string: public_key,
            key_path: pkey_path,
        };
        debug!("Generated keypair: {:?}", keys);
        Ok(keys)
    }

    // generate bp key pairs for multiple services
    pub fn generate_bp_key_pairs(
        &self,
        service_names: &[&str],
    ) -> std::io::Result<HashMap<String, NodeKey>> {
        let mut public_keys = HashMap::new();
        for &service_name in service_names {
            let public_key = self.generate_bp_key_pair(service_name)?;
            public_keys.insert(service_name.to_string(), public_key);
        }
        Ok(public_keys)
    }

    // generate libp2p key pair for single service
    pub fn generate_libp2p_key_pair(&self, service_name: &str) -> std::io::Result<NodeKey> {
        info!("Creating libp2p keys for: {}", service_name);

        let key_subdir = "libp2p-keypairs";
        let volume_path = self.volume()?;
        let pkey_path = format!("/local-network/{}/{}", key_subdir, service_name);

        let args = vec![
            "run",
            "--rm",
            // "--user",
            // "1000:1000",
            "--env",
            "MINA_LIBP2P_PASS=naughty blue worm",
            "--env",
            &self.profile_env,
            "--entrypoint",
            "mina",
            "-v",
            &volume_path,
            self.docker_image.as_str(),
            "libp2p",
            "generate-keypair",
            "-privkey-path",
            &pkey_path,
        ];

        let output = check(
            self.runner.run("docker".as_ref(), &args, &[])?,
            &format!("generating libp2p key for '{service_name}'"),
        )?;

        // Extract the full keypair
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let keypair = parse_libp2p_keypair(&stdout_str).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Could not parse libp2p keypair from output: {stdout_str}"),
            )
        })?;
        let keys = NodeKey {
            key_string: keypair,
            key_path: pkey_path,
        };
        debug!("Generated keypair: {:?}", keys);
        Ok(keys)
    }

    // generate libp2p key pairs for multiple services
    pub fn generate_libp2p_key_pairs(
        &self,
        service_names: &[&str],
    ) -> std::io::Result<HashMap<String, NodeKey>> {
        let mut keypairs = HashMap::new();
        for &service_name in service_names {
            let keypair = self.generate_libp2p_key_pair(service_name)?;
            keypairs.insert(service_name.to_string(), keypair);
        }
        Ok(keypairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn parses_public_key() {
        let out = "Keypair generated\nPublic key: B62qabc\nRaw public key: xyz\n";
        assert_eq!(parse_public_key(out).as_deref(), Some("B62qabc"));
        assert_eq!(parse_public_key("Public key:   \n"), None);
        assert_eq!(parse_public_key("nothing"), None);
    }

    #[test]
    fn parses_libp2p_keypair_from_next_line() {
        // mina prints `libp2p keypair:\n<keypair>\n` (src/app/cli/src/init/client.ml)
        let out = "libp2p keypair:\nCAESQ,CAES,12D3KooW\n";
        assert_eq!(
            parse_libp2p_keypair(out).as_deref(),
            Some("CAESQ,CAES,12D3KooW")
        );
        assert_eq!(
            parse_libp2p_keypair("libp2p keypair: a,b,c").as_deref(),
            Some("a,b,c")
        );
        assert_eq!(parse_libp2p_keypair("libp2p keypair:\n\n"), None);
        assert_eq!(parse_libp2p_keypair("error"), None);
    }

    #[test]
    fn generates_keys_through_docker() {
        let fake = Rc::new(FakeRunner::default());
        fake.reply(0, "Public key: B62qbp\n", "")
            .reply(0, "libp2p keypair:\na,b,peer\n", "");
        let keys = KeysManager::new(Path::new("/net"), "img:1", Profile::Devnet, fake.clone());

        let bp = keys.generate_bp_key_pair("bp-1").unwrap();
        assert_eq!(bp.key_string, "B62qbp");
        assert_eq!(bp.key_path, "/local-network/network-keypairs/bp-1");
        let p2p = keys.generate_libp2p_key_pair("bp-1").unwrap();
        assert_eq!(p2p.key_string, "a,b,peer");

        let lines = fake.lines();
        assert!(lines[0].starts_with("docker run --rm --user "));
        assert!(lines[0].ends_with(
            "-v /net:/local-network img:1 advanced generate-keypair -privkey-path /local-network/network-keypairs/bp-1"
        ));
        assert!(lines[1].ends_with(
            "img:1 libp2p generate-keypair -privkey-path /local-network/libp2p-keypairs/bp-1"
        ));
    }

    #[test]
    fn docker_key_generation_failure_is_reported() {
        let fake = Rc::new(FakeRunner::default());
        fake.reply(125, "", "pull access denied");
        let keys = KeysManager::new(Path::new("/net"), "img:1", Profile::Devnet, fake);
        let err = keys.generate_bp_key_pairs(&["bp-1"]).unwrap_err();
        assert!(err.to_string().contains("pull access denied"));
    }
}
