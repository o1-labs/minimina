use super::binary::Binary;
use crate::cli::Profile;
use crate::keys::{parse_libp2p_keypair, parse_public_key, NodeKey};
use crate::runner::{check, Runner};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

fn mina_command_error(mina_bin: &Path, service_name: &str, e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::NotFound {
        io::Error::new(
            e.kind(),
            format!(
                "Failed to run '{}': {}. Is mina installed and in your PATH or specified via --bin-path?",
                mina_bin.display(), e
            ),
        )
    } else {
        io::Error::other(format!("Failed to run mina for {}: {}", service_name, e))
    }
}

pub struct NativeKeysManager {
    pub network_path: PathBuf,
    pub bin_path: PathBuf,
    profile: Profile,
    runner: Rc<dyn Runner>,
}

fn utf8(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path '{}' is not valid UTF-8", path.display()),
        )
    })
}

impl NativeKeysManager {
    pub fn new(
        network_path: &Path,
        bin_path: &Path,
        profile: Profile,
        runner: Rc<dyn Runner>,
    ) -> Self {
        NativeKeysManager {
            network_path: network_path.to_path_buf(),
            bin_path: bin_path.to_path_buf(),
            profile,
            runner,
        }
    }

    pub fn generate_bp_key_pair(&self, service_name: &str) -> io::Result<NodeKey> {
        let keypair_dir = self.network_path.join("network-keypairs");
        std::fs::create_dir_all(&keypair_dir)?;

        let privkey_path = keypair_dir.join(service_name);
        let mina_bin = Binary::Mina.path(&self.bin_path);
        let mina_env = super::mina_env(&self.bin_path, self.profile);
        let output = self
            .runner
            .run(
                mina_bin.as_os_str(),
                &[
                    "advanced",
                    "generate-keypair",
                    "-privkey-path",
                    utf8(&privkey_path)?,
                ],
                &super::env_refs(&[("MINA_PRIVKEY_PASS", "naughty blue worm")], &mina_env),
            )
            .map_err(|e| mina_command_error(&mina_bin, service_name, e))?;

        let output = check(output, &format!("Generating bp keypair for {service_name}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let public_key = parse_public_key(&stdout).ok_or_else(|| {
            io::Error::other(format!(
                "Could not parse public key from output: {}",
                stdout
            ))
        })?;

        Ok(NodeKey {
            key_string: public_key,
            key_path: format!(
                "{}/network-keypairs/{}",
                self.network_path.display(),
                service_name
            ),
        })
    }

    pub fn generate_bp_key_pairs(
        &self,
        service_names: &[&str],
    ) -> io::Result<HashMap<String, NodeKey>> {
        let mut keys = HashMap::new();
        for name in service_names {
            let key = self.generate_bp_key_pair(name)?;
            keys.insert(name.to_string(), key);
        }
        Ok(keys)
    }

    pub fn generate_libp2p_key_pair(&self, service_name: &str) -> io::Result<NodeKey> {
        let keypair_dir = self.network_path.join("libp2p-keypairs");
        std::fs::create_dir_all(&keypair_dir)?;

        let privkey_path = keypair_dir.join(service_name);
        let mina_bin = Binary::Mina.path(&self.bin_path);
        let mina_env = super::mina_env(&self.bin_path, self.profile);
        let output = self
            .runner
            .run(
                mina_bin.as_os_str(),
                &[
                    "libp2p",
                    "generate-keypair",
                    "-privkey-path",
                    utf8(&privkey_path)?,
                ],
                &super::env_refs(&[("MINA_LIBP2P_PASS", "naughty blue worm")], &mina_env),
            )
            .map_err(|e| mina_command_error(&mina_bin, service_name, e))?;

        let output = check(
            output,
            &format!("Generating libp2p keypair for {service_name}"),
        )?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let keypair = parse_libp2p_keypair(&stdout).ok_or_else(|| {
            io::Error::other(format!(
                "Could not parse libp2p keypair from output: {}",
                stdout
            ))
        })?;

        Ok(NodeKey {
            key_string: keypair,
            key_path: format!(
                "{}/libp2p-keypairs/{}",
                self.network_path.display(),
                service_name
            ),
        })
    }

    pub fn generate_libp2p_key_pairs(
        &self,
        service_names: &[&str],
    ) -> io::Result<HashMap<String, NodeKey>> {
        let mut keys = HashMap::new();
        for name in service_names {
            let key = self.generate_libp2p_key_pair(name)?;
            keys.insert(name.to_string(), key);
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn generates_keys_with_local_mina() {
        let net = tempfile::tempdir().unwrap();
        let fake = Rc::new(FakeRunner::default());
        fake.reply(0, "Public key: B62qn\n", "")
            .reply(0, "libp2p keypair:\nx,y,peer\n", "");
        let keys = NativeKeysManager::new(
            net.path(),
            Path::new("/opt/mina/bin"),
            Profile::Devnet,
            fake.clone(),
        );

        let bp = keys.generate_bp_key_pairs(&["bp"]).unwrap();
        assert_eq!(bp["bp"].key_string, "B62qn");
        let p2p = keys.generate_libp2p_key_pairs(&["bp"]).unwrap();
        assert_eq!(p2p["bp"].key_string, "x,y,peer");
        assert!(net.path().join("network-keypairs").is_dir());

        let calls = fake.calls.borrow();
        assert_eq!(calls[0].program, "/opt/mina/bin/mina");
        assert_eq!(
            calls[1].envs,
            vec![
                ("MINA_LIBP2P_PASS".into(), "naughty blue worm".into()),
                ("MINA_PROFILE".into(), "devnet".into())
            ]
        );
    }

    #[test]
    fn missing_mina_binary_points_at_bin_path() {
        let net = tempfile::tempdir().unwrap();
        let fake = Rc::new(FakeRunner::default());
        fake.reply_err(io::ErrorKind::NotFound);
        let keys = NativeKeysManager::new(net.path(), Path::new("/nope"), Profile::Devnet, fake);
        let err = keys.generate_bp_key_pair("bp").unwrap_err();
        assert!(err.to_string().contains("--bin-path"));
    }

    #[test]
    fn failed_generation_reports_stderr() {
        let net = tempfile::tempdir().unwrap();
        let fake = Rc::new(FakeRunner::default());
        fake.reply(1, "", "bad password");
        let keys = NativeKeysManager::new(net.path(), Path::new("/m"), Profile::Devnet, fake);
        let err = keys.generate_libp2p_key_pair("bp").unwrap_err();
        assert!(err.to_string().contains("bad password"));
    }
}
