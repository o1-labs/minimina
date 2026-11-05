//! The codename and architecture of this machine, which pick the index.

use anyhow::{bail, Context as _, Result};
use std::path::Path;

/// `VERSION_CODENAME` of an `os-release` file (`/etc/os-release`).
pub fn host_codename(os_release: &Path) -> Result<String> {
    let text = std::fs::read_to_string(os_release)
        .with_context(|| format!("reading {}", os_release.display()))?;
    text.lines()
        .find_map(|l| l.strip_prefix("VERSION_CODENAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
        .with_context(|| {
            format!(
                "{} has no VERSION_CODENAME; pass --codename",
                os_release.display()
            )
        })
}

/// Debian architecture of this build of minimina.
pub fn host_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => bail!("mina packages are not built for {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codename_comes_from_os_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        std::fs::write(&path, "NAME=\"Ubuntu\"\nVERSION_CODENAME=noble\n").unwrap();
        assert_eq!(host_codename(&path).unwrap(), "noble");
        std::fs::write(&path, "NAME=x\n").unwrap();
        assert!(host_codename(&path)
            .unwrap_err()
            .to_string()
            .contains("--codename"));
    }
}
