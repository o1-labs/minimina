//! Archive Node API (<https://github.com/o1-labs/Archive-Node-API>): a GraphQL
//! server over the archive database, for events and actions of zkApps.
//!
//! Docker mode runs its image; native mode runs its npm package, which
//! [`crate::install`] installs.

use crate::install::npm;
use crate::version::Version;

pub const DEFAULT_VERSION: &str = "2.0.0";

/// The npm package native mode runs.
pub const APP: npm::App = npm::App {
    tool: "archive-node-api",
    package: "@o1-labs/mina-archive-node-graphql",
    bin: "mina-archive-node-graphql",
    node: Version(22, 12, 0),
};

pub fn docker_image(version: &str) -> String {
    format!("ghcr.io/o1-labs/archive-node-api:{version}")
}

/// Environment of the server: the archive database and its port.
/// It serves GraphQL at `/`.
pub fn env(pg_conn: &str, port: u16) -> Vec<(&'static str, String)> {
    vec![("PG_CONN", pg_conn.to_string()), ("PORT", port.to_string())]
}
