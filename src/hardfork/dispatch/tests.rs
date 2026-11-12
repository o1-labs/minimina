use super::*;

fn dispatch(network: &Path) -> Dispatch {
    Dispatch::new(Path::new("/src/dispatcher.sh"), network, Profile::Devnet)
}

#[test]
fn install_writes_the_settings_and_links_the_runtimes() {
    let net = tempfile::tempdir().unwrap();
    let d = dispatch(net.path());
    d.install(Path::new("/pre/bin"), Path::new("/post/bin"))
        .unwrap();

    let runtimes = net.path().join("dispatch/runtimes");
    assert_eq!(d.program(), net.path().join("dispatch/bin/mina"));
    assert_eq!(
        fs::read_link(d.program()).unwrap(),
        Path::new("/src/dispatcher.sh")
    );
    assert_eq!(
        fs::read_link(runtimes.join("berkeley")).unwrap(),
        Path::new("/pre/bin")
    );
    assert_eq!(
        fs::read_link(runtimes.join("mesa")).unwrap(),
        Path::new("/post/bin")
    );
    let settings = fs::read_to_string(net.path().join("dispatch/mina-dispatch")).unwrap();
    assert_eq!(
        settings,
        format!(
            "MINA_NETWORK=mesa\nMINA_PROFILE=devnet\nRUNTIMES_BASE_PATH={}\n\
             MINA_LIBP2P_ENVVAR_NAME=MINA_LIBP2P_HELPER_PATH\n",
            runtimes.display()
        )
    );

    // again, for another postfork
    d.install(Path::new("/pre/bin"), Path::new("/other/bin"))
        .unwrap();
    assert_eq!(
        fs::read_link(runtimes.join("mesa")).unwrap(),
        Path::new("/other/bin")
    );
}

#[test]
fn a_daemon_runs_with_its_config_directory_as_the_state_dir() {
    let d = dispatch(Path::new("/net"));
    assert_eq!(
        d.env(Path::new("/net/config-directory/bp-1")),
        vec![
            ("SOURCE_FILE", "/net/dispatch/mina-dispatch".to_string()),
            (
                "MINA_HARDFORK_STATE_DIR",
                "/net/config-directory/bp-1".to_string()
            ),
        ]
    );
}

#[test]
fn the_fork_config_is_activated_by_its_marker() {
    let config = tempfile::tempdir().unwrap();
    let d = dispatch(Path::new("/net"));
    let fork = d.fork_dir(config.path());
    assert_eq!(fork, config.path().join("auto-fork-mesa-devnet"));
    assert!(!d.is_activated(config.path()));
    fs::create_dir_all(&fork).unwrap();
    fs::write(fork.join("daemon.json"), "{}").unwrap();
    assert!(!d.is_activated(config.path()), "written, not yet activated");
    fs::write(fork.join("activated"), "").unwrap();
    assert!(d.is_activated(config.path()));
}

#[test]
fn only_devnet_and_mainnet_daemons() {
    let net = tempfile::tempdir().unwrap();
    let d = Dispatch::new(Path::new("/d.sh"), net.path(), Profile::Lightnet);
    let err = d.install(Path::new("/a"), Path::new("/b")).unwrap_err();
    assert!(err.to_string().contains("not lightnet"), "{err}");
}
