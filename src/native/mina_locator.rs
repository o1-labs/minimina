//! Locate the `mina` binary for native mode.
//!
//! Only invoked when the user did not pass `--bin-path` on the CLI.
//! Search order:
//!   1. `/usr/local/bin` (source / manual installs)
//!   2. `/usr/bin`       (debian package installs)
//!   3. first `mina` on `PATH` (via `which mina`)

use super::binary::Binary;
use crate::cli::Profile;
use crate::runner::Runner;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_SEARCH_PATHS: &[&str] = &["/usr/local/bin", "/usr/bin"];

/// Returns the directory containing the `mina` binary, or a descriptive
/// `NotFound` error listing what was tried.
pub fn locate() -> io::Result<PathBuf> {
    for dir in DEFAULT_SEARCH_PATHS {
        if Binary::Mina.path(Path::new(dir)).exists() {
            return Ok(PathBuf::from(dir));
        }
    }

    if let Some(parent) = which_mina().as_deref().and_then(Path::parent) {
        return Ok(parent.to_path_buf());
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "Mina binary not found. Searched {} and PATH. \
             Please install mina or use --bin-path to specify the location.",
            DEFAULT_SEARCH_PATHS.join(", ")
        ),
    ))
}

fn which_mina() -> Option<PathBuf> {
    let output = Command::new("which")
        .arg(Binary::Mina.file_name())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Directories mina searches for `config_<commit>.json` (`Cache_dir.possible_paths`).
fn config_search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![std::env::var_os("MINA_KEYS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/coda"))];
    dirs.extend(
        [
            "/usr/local/var/coda",
            "/tmp/s3_cache_dir",
            "/tmp/coda_cache_dir",
            "/var/lib/coda",
        ]
        .map(PathBuf::from),
    );
    dirs
}

/// Network config installed for the `mina` in `bin_path`, if any.
///
/// Network-specific mina packages install `config_<commit>.json`, which the
/// daemon merges into every config it runs with: its fork point, peer list
/// and constants leak into a local network and cannot be unset from there.
pub fn installed_network_config(
    runner: &dyn Runner,
    bin_path: &Path,
    profile: Profile,
) -> Option<PathBuf> {
    // generic 4.x binaries refuse to run, even `version`, without a profile
    let mina_env = super::mina_env(bin_path, profile);
    let out = runner
        .run(
            Binary::Mina.path(bin_path).as_os_str(),
            &["version"],
            &super::env_refs(&[], &mina_env),
        )
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let commit = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Commit "))?
        .trim()
        .to_string();
    config_search_dirs().into_iter().find_map(|dir| {
        std::fs::read_dir(&dir).ok()?.flatten().find_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let short = name.strip_prefix("config_")?.strip_suffix(".json")?;
            (short.len() >= 7 && commit.starts_with(short)).then(|| entry.path())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn finds_config_matching_the_binary_commit() {
        let keys = tempfile::tempdir().unwrap();
        std::fs::write(keys.path().join("config_68503010.json"), "{}").unwrap();
        std::fs::write(keys.path().join("config_6965b502.json"), "{}").unwrap();
        // MINA_KEYS_PATH is read per call; no other test sets it
        std::env::set_var("MINA_KEYS_PATH", keys.path());

        let fake = FakeRunner::default();
        fake.reply(
            0,
            "Commit 685030107ff328e59936410a0e72ddaca59cb9d6 on branch x\n",
            "",
        );
        assert_eq!(
            installed_network_config(&fake, Path::new("/opt"), Profile::Devnet),
            Some(keys.path().join("config_68503010.json"))
        );
        assert_eq!(fake.lines(), vec!["/opt/mina version"]);

        fake.reply(0, "Commit 1e9d1419466c54dd2cee38dce85945b7346e98a4\n", "");
        let other = installed_network_config(&fake, Path::new("/opt"), Profile::Devnet);
        assert!(other.is_none_or(|p| !p.starts_with(keys.path())));

        fake.reply(1, "", "boom");
        assert_eq!(
            installed_network_config(&fake, Path::new("/opt"), Profile::Devnet),
            None
        );
        std::env::remove_var("MINA_KEYS_PATH");
    }
}
