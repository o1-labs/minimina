use super::{LoadError, Sender};
use crate::{
    cli::ExecutionMode,
    directory_manager::NETWORK_KEYPAIRS,
    service::{ServiceConfig, ServiceType},
};
use std::{fs, path::Path};

const ACCOUNT_PREFIX: &str = "account-";
/// Where docker containers see the network directory.
const DOCKER_NETWORK_DIR: &str = "/local-network";

/// The test accounts of a network (`account-1`, ... in `network-keypairs`),
/// in order, with their key files as the daemons see them.
pub fn test_accounts(
    network_path: &Path,
    mode: ExecutionMode,
    network_id: &str,
) -> Result<Vec<Sender>, LoadError> {
    let dir = network_path.join(NETWORK_KEYPAIRS);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return Err(LoadError::NoAccounts(network_id.to_string())),
    };
    let mut numbered: Vec<(u64, String)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let file = e.file_name().into_string().ok()?;
            let name = file.strip_suffix(".pub")?;
            let n = name.strip_prefix(ACCOUNT_PREFIX)?.parse().ok()?;
            Some((n, name.to_string()))
        })
        .collect();
    numbered.sort_unstable();
    if numbered.is_empty() {
        return Err(LoadError::NoAccounts(network_id.to_string()));
    }
    numbered
        .into_iter()
        .map(|(_, name)| {
            let pub_file = dir.join(format!("{name}.pub"));
            let public_key = fs::read_to_string(&pub_file)
                .map_err(|cause| LoadError::Io {
                    what: "reading",
                    path: pub_file,
                    cause,
                })?
                .trim()
                .to_string();
            let key_path = match mode {
                ExecutionMode::Native => dir.join(&name),
                ExecutionMode::Docker => Path::new(DOCKER_NETWORK_DIR)
                    .join(NETWORK_KEYPAIRS)
                    .join(&name),
            };
            Ok(Sender {
                name,
                public_key,
                key_path,
            })
        })
        .collect()
}

/// The senders asked for by key name or public key; all test accounts when
/// none are.
pub fn pick_senders(
    accounts: &[Sender],
    asked: &[String],
    network_id: &str,
) -> Result<Vec<Sender>, LoadError> {
    if asked.is_empty() {
        return Ok(accounts.to_vec());
    }
    asked
        .iter()
        .map(|a| {
            accounts
                .iter()
                .find(|s| &s.name == a || &s.public_key == a)
                .cloned()
                .ok_or_else(|| LoadError::UnknownSender {
                    network: network_id.to_string(),
                    name: a.clone(),
                    known: accounts
                        .iter()
                        .map(|s| s.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                })
        })
        .collect()
}

/// The daemon asked for, else the first block producer, else the first
/// daemon with a chain.
pub fn pick_node<'s>(
    services: &'s [ServiceConfig],
    asked: Option<&str>,
    network_id: &str,
) -> Result<&'s ServiceConfig, LoadError> {
    let found = match asked {
        Some(name) => services
            .iter()
            .find(|s| s.service_name == name && s.is_chain_daemon())
            .ok_or_else(|| LoadError::UnknownNode {
                network: network_id.to_string(),
                node: name.to_string(),
            })?,
        None => services
            .iter()
            .find(|s| s.service_type == ServiceType::BlockProducer)
            .or_else(|| services.iter().find(|s| s.is_chain_daemon()))
            .ok_or_else(|| LoadError::NoDaemon(network_id.to_string()))?,
    };
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(dir: &Path, names: &[&str]) {
        let keys = dir.join(NETWORK_KEYPAIRS);
        fs::create_dir_all(&keys).unwrap();
        for name in names {
            fs::write(keys.join(name), "secret").unwrap();
            fs::write(keys.join(format!("{name}.pub")), format!("B62q{name}\n")).unwrap();
        }
    }

    #[test]
    fn test_accounts_in_order_with_the_key_path_the_daemon_sees() {
        let net = tempfile::tempdir().unwrap();
        assert!(matches!(
            test_accounts(net.path(), ExecutionMode::Native, "n"),
            Err(LoadError::NoAccounts(_))
        ));
        keys(
            net.path(),
            &["bp-1", "account-10", "account-2", "account-1"],
        );
        let native = test_accounts(net.path(), ExecutionMode::Native, "n").unwrap();
        let names: Vec<_> = native.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["account-1", "account-2", "account-10"]);
        assert_eq!(native[0].public_key, "B62qaccount-1");
        assert_eq!(
            native[0].key_path,
            net.path().join("network-keypairs/account-1")
        );
        let docker = test_accounts(net.path(), ExecutionMode::Docker, "n").unwrap();
        assert_eq!(
            docker[1].key_path,
            Path::new("/local-network/network-keypairs/account-2")
        );

        let picked =
            pick_senders(&native, &["B62qaccount-2".into(), "account-1".into()], "n").unwrap();
        assert_eq!(picked[0].name, "account-2");
        assert_eq!(picked[1].name, "account-1");
        assert_eq!(pick_senders(&native, &[], "n").unwrap().len(), 3);
        let err = pick_senders(&native, &["bp-1".into()], "n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "network 'n' has no test account 'bp-1'; it has account-1, account-2, account-10"
        );
    }

    #[test]
    fn the_first_block_producer_unless_asked() {
        let service = |name: &str, service_type| ServiceConfig {
            service_name: name.into(),
            service_type,
            ..Default::default()
        };
        let services = [
            service("seed", ServiceType::Seed),
            service("bp-1", ServiceType::BlockProducer),
            service("rosetta", ServiceType::Rosetta),
        ];
        assert_eq!(
            pick_node(&services, None, "n").unwrap().service_name,
            "bp-1"
        );
        assert_eq!(
            pick_node(&services, Some("seed"), "n")
                .unwrap()
                .service_name,
            "seed"
        );
        assert!(matches!(
            pick_node(&services, Some("rosetta"), "n"),
            Err(LoadError::UnknownNode { .. })
        ));
        assert!(matches!(
            pick_node(&services[2..], None, "n"),
            Err(LoadError::NoDaemon(_))
        ));
        assert_eq!(
            pick_node(&services[..1], None, "n").unwrap().service_name,
            "seed"
        );
    }
}
