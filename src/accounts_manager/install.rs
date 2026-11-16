//! Installs the accounts manager: the binary of a release for this host,
//! downloaded once into `<tools>/accounts-manager/<version>` and checked
//! against the SHA-256 GitHub gives for it.

use super::release::Release;
use super::{AccountsManagerError, TOOL};
use crate::install::apt;
use crate::install::mina::Fetch;
use log::info;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// The accounts manager to run: `own` (the user's build) when given, else
/// `version` under `<tools>/accounts-manager`, installed there if it is not
/// yet.
pub fn resolve(
    tools_root: &Path,
    version: &str,
    own: Option<&Path>,
    fetch: &dyn Fetch,
) -> Result<PathBuf, AccountsManagerError> {
    if let Some(bin) = own {
        if !bin.is_file() {
            return Err(AccountsManagerError::NoOwnBuild(bin.to_path_buf()));
        }
        return Ok(bin.to_path_buf());
    }
    let dir = tools_root.join(TOOL).join(version);
    let program = dir.join(TOOL);
    if program.is_file() {
        return Ok(program);
    }
    let arch = apt::host_arch().map_err(|cause| AccountsManagerError::Host { cause })?;
    install(&dir, version, arch, fetch)?;
    Ok(program)
}

/// Downloads the binary of `version` for `arch` into `dir`. An interrupted
/// download leaves nothing behind: the file is renamed into place last.
fn install(
    dir: &Path,
    version: &str,
    arch: &str,
    fetch: &dyn Fetch,
) -> Result<(), AccountsManagerError> {
    let release_error = |cause| AccountsManagerError::Release {
        version: version.to_string(),
        cause,
    };
    let release: Release = fetch
        .text(&Release::url(version))
        .and_then(|text| Ok(serde_json::from_str(&text)?))
        .map_err(release_error)?;
    let asset = release
        .binary(arch)
        .ok_or_else(|| AccountsManagerError::NoAsset {
            version: version.to_string(),
            asset: format!("accounts-manager-{arch}"),
        })?;
    fs::create_dir_all(dir).map_err(AccountsManagerError::io(dir))?;
    let partial = dir.join(format!("{TOOL}.partial"));
    let url = &asset.browser_download_url;
    info!("Installing the accounts manager {version} ({arch})");
    let found = fetch
        .download(url, &partial)
        .map_err(|cause| AccountsManagerError::Download {
            url: url.clone(),
            cause,
        });
    let checked = found.and_then(|found| match asset.sha256() {
        Some(expected) if expected == found => Ok(()),
        expected => Err(AccountsManagerError::ChecksumMismatch {
            url: url.clone(),
            expected: expected.unwrap_or("no checksum").to_string(),
            found,
        }),
    });
    let installed = checked.and_then(|()| {
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o755))
            .map_err(AccountsManagerError::io(&partial))?;
        let program = dir.join(TOOL);
        fs::rename(&partial, &program).map_err(AccountsManagerError::io(&program))
    });
    if installed.is_err() {
        let _ = fs::remove_file(&partial);
    }
    installed
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;

    const BINARY: &[u8] = b"\x7fELF accounts manager";

    /// GitHub, with one release whose amd64 binary has `digest`.
    struct FakeGitHub {
        digest: String,
        urls: RefCell<Vec<String>>,
    }

    impl FakeGitHub {
        fn new(digest: &str) -> Self {
            FakeGitHub {
                digest: digest.to_string(),
                urls: RefCell::new(vec![]),
            }
        }
    }

    impl Fetch for FakeGitHub {
        fn text(&self, url: &str) -> Result<String> {
            self.urls.borrow_mut().push(url.to_string());
            Ok(serde_json::json!({
                "assets": [{
                    "name": "accounts-manager-amd64",
                    "browser_download_url": "https://github.com/am/accounts-manager-amd64",
                    "digest": self.digest,
                }]
            })
            .to_string())
        }

        fn download(&self, url: &str, dest: &Path) -> Result<String> {
            self.urls.borrow_mut().push(url.to_string());
            fs::write(dest, BINARY)?;
            Ok(format!("{:x}", Sha256::digest(BINARY)))
        }
    }

    #[test]
    fn installs_the_release_binary_once() {
        let tools = tempfile::tempdir().unwrap();
        let dir = tools.path().join("accounts-manager/0.1.2");
        let github = FakeGitHub::new(&format!("sha256:{:x}", Sha256::digest(BINARY)));
        install(&dir, "0.1.2", "amd64", &github).unwrap();
        let program = dir.join("accounts-manager");
        assert_eq!(fs::read(&program).unwrap(), BINARY);
        assert_eq!(
            fs::metadata(&program).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            *github.urls.borrow(),
            [
                "https://api.github.com/repos/o1-labs/mina-accounts-manager/releases/tags/v0.1.2",
                "https://github.com/am/accounts-manager-amd64",
            ]
        );
        // installed: resolve asks nothing more
        let again = FakeGitHub::new("unused");
        assert_eq!(
            resolve(tools.path(), "0.1.2", None, &again).unwrap(),
            program
        );
        assert!(again.urls.borrow().is_empty());
    }

    #[test]
    fn a_wrong_checksum_installs_nothing() {
        let tools = tempfile::tempdir().unwrap();
        let dir = tools.path().join("accounts-manager/0.1.2");
        let github = FakeGitHub::new("sha256:0000");
        let err = install(&dir, "0.1.2", "amd64", &github).unwrap_err();
        assert!(err.to_string().contains("the release has 0000"), "{err}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);

        let err = install(&dir, "0.1.2", "arm64", &github).unwrap_err();
        assert_eq!(
            err.to_string(),
            "release v0.1.2 of the accounts manager has no accounts-manager-arm64"
        );
    }

    #[test]
    fn own_build_must_exist() {
        let tools = tempfile::tempdir().unwrap();
        let own = tools.path().join("my-accounts-manager");
        let github = FakeGitHub::new("unused");
        let err = resolve(tools.path(), "0.1.2", Some(&own), &github).unwrap_err();
        assert!(err.to_string().ends_with("does not exist"));
        fs::write(&own, "").unwrap();
        assert_eq!(
            resolve(tools.path(), "0.1.2", Some(&own), &github).unwrap(),
            own
        );
    }
}
