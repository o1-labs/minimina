//! Debian repositories, read without apt.
//!
//! - [`Repository`]: where the files of a repository are (`Release`,
//!   `Packages`, the debs), and its [`Channel`]s.
//! - [`ControlFile`] of [`Stanza`]s: the `Field: value` format both index
//!   files are written in; [`ReleaseInfo`] and [`Index`] (of [`Entry`]s,
//!   grouped into [`Release`]s) read what minimina needs from them.
//! - [`PackageVersion`]: the versions mina packages carry (`4.0.2-84b8d96`).
//! - [`host`]: the codename and architecture of this machine.

mod channel;
mod control_file;
mod entry;
pub mod host;
mod index;
mod package_version;
mod release;
mod release_info;
mod repository;
mod stanza;

pub use channel::Channel;
pub use control_file::ControlFile;
pub use entry::Entry;
pub use host::{host_arch, host_codename};
pub use index::Index;
pub use package_version::{select, PackageVersion};
pub use release::Release;
pub use release_info::ReleaseInfo;
pub use repository::Repository;
pub use stanza::Stanza;

/// The packages of one mina release that minimina installs.
///
/// Only `-generic` builds: the network packages (`mina-devnet`, ...) depend on
/// `mina-<net>-config`, whose `config_<commit>.json` the daemon merges into
/// every config, so a local network would get a public peer list and fork point.
pub const PACKAGES: [&str; 4] = [
    "mina-generic",
    "mina-archive-generic",
    "mina-rosetta-generic",
    "mina-logproc",
];

/// Codenames mina is built for, to say where a missing version is available.
pub const CODENAMES: [&str; 3] = ["noble", "jammy", "bookworm"];
