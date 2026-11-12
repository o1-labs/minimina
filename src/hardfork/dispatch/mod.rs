//! Auto mode: every daemon runs through Mina's hardfork dispatcher
//! (`scripts/hardfork/dispatcher.sh`, packaged as `mina-dispatch`), as on a
//! node with the automode package.
//!
//! Before the fork the dispatcher runs the prefork `mina daemon` with
//! `--hardfork-handling migrate-exit`. At `slot_chain_end` that daemon writes
//! its fork config to `<config dir>/auto-fork-mesa-<profile>` (`daemon.json`,
//! `genesis/` and an `activated` marker) and exits. From then on the
//! dispatcher runs the postfork daemon with that fork config. Restarting the
//! daemons is the operator's job: `network hardfork apply`.
//!
//! The dispatcher reads its settings from a file (`SOURCE_FILE`) and finds the
//! binaries under `RUNTIMES_BASE_PATH`: `berkeley/` before the fork, `mesa/`
//! after. It runs the program it is called as, so the package links `mina` to
//! it. minimina writes all three into `<network>/dispatch` at `network create`.

mod error;

pub use error::DispatchError;

use crate::cli::Profile;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Under the network directory.
pub const DISPATCH_DIR: &str = "dispatch";
/// The dispatcher's settings, its `SOURCE_FILE`.
const SOURCE_FILE: &str = "mina-dispatch";
/// `RUNTIMES_BASE_PATH`: one directory of binaries per runtime.
const RUNTIMES: &str = "runtimes";
/// `mina`, linked to the dispatcher, under `<network>/dispatch`.
const BIN: &str = "bin";
/// The runtime before the fork.
const PREFORK_RUNTIME: &str = "berkeley";
/// The runtime after the fork.
const POSTFORK_RUNTIME: &str = "mesa";
/// `MINA_NETWORK`: the prefork daemon names its fork directory
/// `auto-fork-mesa-<signature>`, and the dispatcher looks for
/// `auto-fork-<MINA_NETWORK>-<MINA_PROFILE>`.
const FORK_NETWORK: &str = "mesa";
/// The marker a prefork daemon writes last into its fork directory.
const ACTIVATED: &str = "activated";

/// How minimina runs the daemons of an auto mode network.
#[derive(Debug, Clone, PartialEq)]
pub struct Dispatch {
    /// The dispatcher script.
    pub script: PathBuf,
    /// `<network>/dispatch`.
    pub dir: PathBuf,
    /// The profile, also the signature kind in the fork directory's name.
    pub profile: Profile,
}

impl Dispatch {
    pub fn new(script: &Path, network_path: &Path, profile: Profile) -> Self {
        Dispatch {
            script: script.to_path_buf(),
            dir: network_path.join(DISPATCH_DIR),
            profile,
        }
    }

    /// Whether the dispatcher can run daemons of `profile`. It sources
    /// `MINA_PROFILE` from its settings, which then is also the daemon's
    /// profile; it must name the daemon's fork directory, which is named after
    /// the signature kind (`devnet` or `mainnet`).
    pub fn supports(profile: Profile) -> bool {
        matches!(profile, Profile::Devnet | Profile::Mainnet)
    }

    /// Writes the dispatcher's settings, links `mina` to it and its runtimes
    /// to the prefork and postfork binary directories.
    pub fn install(&self, prefork_bin: &Path, postfork_bin: &Path) -> Result<(), DispatchError> {
        if !Self::supports(self.profile) {
            return Err(DispatchError::Profile {
                profile: self.profile,
            });
        }
        let runtimes = self.dir.join(RUNTIMES);
        fs::create_dir_all(&runtimes).map_err(io_error(&runtimes))?;
        let bin = self.dir.join(BIN);
        fs::create_dir_all(&bin).map_err(io_error(&bin))?;
        link(&self.script, &self.program())?;
        link(prefork_bin, &runtimes.join(PREFORK_RUNTIME))?;
        link(postfork_bin, &runtimes.join(POSTFORK_RUNTIME))?;
        let source = self.dir.join(SOURCE_FILE);
        fs::write(&source, self.settings(&runtimes)).map_err(io_error(&source))
    }

    /// The `SOURCE_FILE` of the dispatcher.
    fn settings(&self, runtimes: &Path) -> String {
        format!(
            "MINA_NETWORK={FORK_NETWORK}\n\
             MINA_PROFILE={}\n\
             RUNTIMES_BASE_PATH={}\n\
             MINA_LIBP2P_ENVVAR_NAME=MINA_LIBP2P_HELPER_PATH\n",
            self.profile.as_str(),
            runtimes.display()
        )
    }

    /// What a daemon runs: `mina`, the dispatcher under that name.
    pub fn program(&self) -> PathBuf {
        self.dir.join(BIN).join("mina")
    }

    /// The environment of a daemon with config directory `config_dir`. The
    /// dispatcher and the postfork daemon require `MINA_HARDFORK_STATE_DIR`
    /// to be that directory.
    pub fn env(&self, config_dir: &Path) -> Vec<(&'static str, String)> {
        vec![
            (
                "SOURCE_FILE",
                self.dir.join(SOURCE_FILE).to_string_lossy().into_owned(),
            ),
            (
                "MINA_HARDFORK_STATE_DIR",
                config_dir.to_string_lossy().into_owned(),
            ),
        ]
    }

    /// The directory a prefork daemon with config directory `config_dir`
    /// writes its fork config to.
    pub fn fork_dir(&self, config_dir: &Path) -> PathBuf {
        config_dir.join(format!(
            "auto-fork-{FORK_NETWORK}-{}",
            self.profile.as_str()
        ))
    }

    /// Whether that daemon finished writing its fork config.
    pub fn is_activated(&self, config_dir: &Path) -> bool {
        self.fork_dir(config_dir).join(ACTIVATED).is_file()
    }
}

/// Links `link` to `target`, replacing an older link.
fn link(target: &Path, link: &Path) -> Result<(), DispatchError> {
    match fs::remove_file(link) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_error(link)(e)),
        _ => {}
    }
    std::os::unix::fs::symlink(target, link).map_err(io_error(link))
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> DispatchError {
    let path = path.to_path_buf();
    move |cause| DispatchError::Io { path, cause }
}

#[cfg(test)]
mod tests;
