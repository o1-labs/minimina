//! mina versions from their deb packages, side by side in
//! `<tools>/mina/<version>`.
//!
//! The debs are unpacked with `dpkg-deb -x`, not installed with apt: apt keeps
//! one version in `/usr/local/bin`, but a hardfork test runs two at once. The
//! binaries of a version are in `<tools>/mina/<version>/usr/local/bin`, the
//! layout [`crate::utils::package_root`] expects, so the archive schema of
//! the package is found next to them.
//!
//! - [`Source`]: the repository, channel, codename and architecture to
//!   install from.
//! - [`install()`] downloads and unpacks a version; [`Installed`] is a version
//!   in the tools directory, which [`installed()`], [`resolve()`] and
//!   [`uninstall()`] work with.
//! - [`Fetch`] gets files from the repository ([`Http`] for real).
//! - [`MinaError`]: why a version cannot be installed, used or removed.

mod error;
mod fetch;
mod install;
mod installed;
mod source;
#[cfg(test)]
mod tests;

pub use error::MinaError;
pub use fetch::{Fetch, Http};
pub use install::install;
pub use installed::{installed, resolve, uninstall, Installed};
pub use source::Source;

use std::path::{Path, PathBuf};

/// Directory of the mina installs under the tools directory.
pub const TOOL: &str = "mina";
/// Where the packages put their binaries, under the install directory.
pub const BIN_DIR: &str = "usr/local/bin";
/// What was installed, in the install directory; a directory without it is
/// not an install.
const INSTALL_FILE: &str = "install.json";

/// `<tools>/mina`
pub fn root(tools_root: &Path) -> PathBuf {
    tools_root.join(TOOL)
}
