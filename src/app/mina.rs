//! `minimina mina ...` handlers: mina versions in the tools directory.

use crate::{
    cli::{MinaCommand, MinaListArgs, MinaSourceArgs, MinaUninstallArgs},
    directory_manager::DirectoryManager,
    install::{
        apt::{self, Repository},
        mina::{self, Fetch, Installed, MinaError, Source},
    },
    network_meta::NetworkMeta,
    output::mina as output,
    runner::Runner,
};
use anyhow::Result;
use std::path::Path;

const OS_RELEASE: &str = "/etc/os-release";

pub fn run(
    dirs: &DirectoryManager,
    runner: &dyn Runner,
    fetch: &dyn Fetch,
    cmd: MinaCommand,
) -> Result<()> {
    let tools = dirs.tools_root();
    let out = match cmd {
        MinaCommand::Install(args) => {
            install(&tools, runner, fetch, &args.version, &args.source)?.to_string()
        }
        MinaCommand::Upgrade(args) => install(&tools, runner, fetch, "latest", &args)?.to_string(),
        MinaCommand::List(args) => list(&tools, fetch, &args)?.to_string(),
        MinaCommand::Uninstall(args) => uninstall(dirs, &args)?.to_string(),
    };
    println!("{out}");
    Ok(())
}

fn install(
    tools: &Path,
    runner: &dyn Runner,
    fetch: &dyn Fetch,
    wanted: &str,
    args: &MinaSourceArgs,
) -> Result<output::Install> {
    let source = source(args, Path::new(OS_RELEASE))?;
    let (installed, new) = mina::install(tools, runner, fetch, wanted, &source)?;
    Ok(output::Install::new(installed, new))
}

fn list(tools: &Path, fetch: &dyn Fetch, args: &MinaListArgs) -> Result<output::List> {
    let installed = mina::installed(tools)?;
    let available = if args.available {
        Some(available(fetch, &args.source, &installed)?)
    } else {
        None
    };
    Ok(output::List {
        installed: installed.into_iter().map(output::Installed::from).collect(),
        available,
    })
}

/// The versions the channel has, and which of them are installed.
fn available(
    fetch: &dyn Fetch,
    args: &MinaSourceArgs,
    installed: &[Installed],
) -> Result<output::Available> {
    let source = source(args, Path::new(OS_RELEASE))?;
    let versions = source.index(fetch)?.versions();
    Ok(output::Available {
        channel: source.channel,
        codename: source.codename,
        versions: versions
            .into_iter()
            .map(|version| output::AvailableVersion {
                installed: installed.iter().any(|i| i.version == version),
                version,
            })
            .collect(),
    })
}

/// Removes an install, unless a network runs it (or `--force`).
fn uninstall(dirs: &DirectoryManager, args: &MinaUninstallArgs) -> Result<output::Uninstall> {
    let installed = mina::resolve(&dirs.tools_root(), &args.version)?;
    let users = networks_using(dirs, &installed)?;
    if !users.is_empty() && !args.force {
        return Err(MinaError::InUse {
            version: installed.version,
            networks: users,
        }
        .into());
    }
    mina::uninstall(&installed)?;
    Ok(output::Uninstall {
        version: installed.version,
        dir: installed.dir.display().to_string(),
        used_by: users,
    })
}

fn source(args: &MinaSourceArgs, os_release: &Path) -> Result<Source> {
    Ok(Source {
        repository: Repository::default(),
        channel: args.channel.clone(),
        codename: match &args.codename {
            Some(codename) => codename.clone(),
            None => apt::host_codename(os_release)?,
        },
        arch: apt::host_arch()?.to_string(),
    })
}

/// Networks whose daemons (or postfork daemons) run binaries of `installed`.
fn networks_using(dirs: &DirectoryManager, installed: &Installed) -> Result<Vec<String>> {
    let mut users = vec![];
    for network in dirs.list_network_directories()? {
        // a network that cannot be read does not stop the uninstall
        let Ok(Some(meta)) = NetworkMeta::load(&dirs.network_path(&network)) else {
            continue;
        };
        let postfork = meta.hardfork.as_ref().map(|h| &h.postfork_bin_path);
        if meta
            .bin_path
            .iter()
            .chain(postfork)
            .any(|bin| bin.starts_with(&installed.dir))
        {
            users.push(network);
        }
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Channel, ExecutionMode};
    use crate::runner::fake::FakeRunner;
    use anyhow::bail;

    struct NoNetwork;

    impl Fetch for NoNetwork {
        fn text(&self, url: &str) -> Result<String> {
            bail!("offline: {url}")
        }
        fn download(&self, url: &str, _: &Path) -> Result<String> {
            bail!("offline: {url}")
        }
    }

    /// An install of `version` as `mina::install` leaves it.
    fn fake_install(dirs: &DirectoryManager, version: &str) -> Installed {
        let dir = mina::root(&dirs.tools_root()).join(version);
        std::fs::create_dir_all(dir.join(mina::BIN_DIR)).unwrap();
        std::fs::write(dir.join(mina::BIN_DIR).join("mina"), "").unwrap();
        let installed = Installed {
            version: version.into(),
            channel: Channel::default(),
            codename: "noble".into(),
            packages: vec![],
            dir,
        };
        std::fs::write(
            installed.dir.join("install.json"),
            serde_json::to_string(&installed).unwrap(),
        )
        .unwrap();
        installed
    }

    fn uninstall(dirs: &DirectoryManager, version: &str, force: bool) -> Result<()> {
        let cmd = MinaCommand::Uninstall(MinaUninstallArgs {
            version: version.into(),
            force,
        });
        run(dirs, &FakeRunner::default(), &NoNetwork, cmd)
    }

    #[test]
    fn uninstall_keeps_versions_that_networks_run() {
        let home = tempfile::tempdir().unwrap();
        let dirs = DirectoryManager::with_base_path(home.path().to_path_buf());
        let installed = fake_install(&dirs, "4.0.2-84b8d96");
        dirs.create_network_directory("net").unwrap();
        NetworkMeta {
            mode: ExecutionMode::Native,
            bin_path: Some(installed.bin_path()),
            mina_version: Some(installed.version.clone()),
            postgres_uri: None,
            profile: Default::default(),
            features: Default::default(),
            genesis_pending: false,
            hardfork: None,
        }
        .save(&dirs.network_path("net"))
        .unwrap();

        let err = uninstall(&dirs, "4.0.2", false).unwrap_err().to_string();
        assert_eq!(
            err,
            "mina 4.0.2-84b8d96 is used by network(s) net; delete them first, or pass --force"
        );
        assert!(installed.dir.is_dir());
        uninstall(&dirs, "4.0.2", true).unwrap();
        assert!(!installed.dir.exists());
        assert!(uninstall(&dirs, "4.0.2", true).is_err());
    }

    #[test]
    fn list_needs_no_network_unless_available() {
        let home = tempfile::tempdir().unwrap();
        let dirs = DirectoryManager::with_base_path(home.path().to_path_buf());
        fake_install(&dirs, "4.0.2-84b8d96");
        let list = |available| {
            let cmd = MinaCommand::List(MinaListArgs {
                available,
                source: MinaSourceArgs {
                    channel: Channel::default(),
                    codename: Some("noble".into()),
                },
            });
            run(&dirs, &FakeRunner::default(), &NoNetwork, cmd)
        };
        list(false).unwrap();
        let err = format!("{:#}", list(true).unwrap_err());
        assert!(
            err.contains("offline: https://packages.o1test.net/dists/noble/stable/"),
            "{err}"
        );
    }

    #[test]
    fn source_defaults_to_the_host_codename() {
        let dir = tempfile::tempdir().unwrap();
        let os_release = dir.path().join("os-release");
        std::fs::write(&os_release, "VERSION_CODENAME=bookworm\n").unwrap();
        let args = MinaSourceArgs {
            channel: "alpha".parse().unwrap(),
            codename: None,
        };
        let source = source(&args, &os_release).unwrap();
        assert_eq!(source.codename, "bookworm");
        assert_eq!(source.channel.to_string(), "alpha");
    }
}
