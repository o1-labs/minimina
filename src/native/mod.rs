pub mod keys;
pub mod manager;
pub mod mina_locator;
pub mod port_manager;
pub mod process_tracker;

use crate::cli::Profile;
use std::path::Path;

/// Name of the libp2p helper in mina packages.
const LIBP2P_HELPER: &str = "coda-libp2p_helper";

/// Environment every native mina process runs with, on top of its own.
///
/// * `MINA_PROFILE`: generic 4.x binaries refuse to run without a profile.
/// * `MINA_LIBP2P_HELPER_PATH`: mina looks for the helper as `<dir of mina>/libp2p_helper`,
///   then as `mina-libp2p_helper` / `coda-libp2p_helper` on `PATH`. Packages ship
///   `coda-libp2p_helper`, so a `bin_path` that is not on `PATH` makes every
///   libp2p command exit 20 without a message.
pub fn mina_env(bin_path: &Path, profile: Profile) -> Vec<(&'static str, String)> {
    let mut env = vec![(Profile::ENV, profile.as_str().to_string())];
    let helper = bin_path.join(LIBP2P_HELPER);
    if helper.exists() {
        env.push((
            "MINA_LIBP2P_HELPER_PATH",
            helper.to_string_lossy().into_owned(),
        ));
    }
    env
}

/// `extra` followed by [`mina_env`], borrowed the way [`crate::runner::Runner`] takes it.
pub fn env_refs<'a>(
    extra: &[(&'a str, &'a str)],
    mina_env: &'a [(&'static str, String)],
) -> Vec<(&'a str, &'a str)> {
    extra
        .iter()
        .copied()
        .chain(mina_env.iter().map(|(k, v)| (*k, v.as_str())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_points_at_the_packaged_libp2p_helper() {
        let bin = tempfile::tempdir().unwrap();
        assert_eq!(
            mina_env(bin.path(), Profile::Dev),
            vec![("MINA_PROFILE", "dev".to_string())]
        );

        std::fs::write(bin.path().join(LIBP2P_HELPER), "").unwrap();
        let env = mina_env(bin.path(), Profile::Mainnet);
        let helper = bin
            .path()
            .join(LIBP2P_HELPER)
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            env,
            vec![
                ("MINA_PROFILE", "mainnet".to_string()),
                ("MINA_LIBP2P_HELPER_PATH", helper.clone()),
            ]
        );
        assert_eq!(
            env_refs(&[("A", "b")], &env),
            vec![
                ("A", "b"),
                ("MINA_PROFILE", "mainnet"),
                ("MINA_LIBP2P_HELPER_PATH", helper.as_str()),
            ]
        );
    }
}
