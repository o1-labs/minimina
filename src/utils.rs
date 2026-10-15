//! # Utils Module
//!
//! This module provides utility functions to fetch archive schema files
//! and the UID and GID of the current user.

use log::debug;
use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
};
use url::Url;

/// Timeout in seconds for waiting operations
pub const TIMEOUT_IN_SECS: u16 = 180;

/// Fetch the UID and GID of the current user.
///
/// # Returns
///
/// * `Option<String>` - A formatted string "UID:GID", or `None` if unable to retrieve.
pub fn get_current_user_uid_gid() -> Option<String> {
    let current_user = uzers::get_current_uid();
    let current_group = uzers::get_current_gid();

    Some(format!("{current_user}:{current_group}"))
}

/// Fetch the schema from a given URL and save it to a file.
/// The file is saved in the given network path.
pub fn fetch_schema(url: &str, network_path: PathBuf) -> io::Result<PathBuf> {
    debug!("Fetching schema from: {url}");

    let parsed_url = Url::parse(url).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid schema URL '{url}': {e}"),
        )
    })?;
    let filename = parsed_url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .unwrap_or("schema.sql");
    let mut file_path = network_path;

    file_path.push(filename);
    let http_error = |e: reqwest::Error| io::Error::other(format!("fetching '{url}': {e}"));
    let bytes = reqwest::blocking::get(parsed_url)
        .map_err(http_error)?
        .bytes()
        .map_err(http_error)?;
    File::create(&file_path)?.write_all(&bytes)?;

    Ok(file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_user_uid_gid() {
        let uid_gid = get_current_user_uid_gid().unwrap();
        assert!(uid_gid.contains(':'));
    }

    #[test]
    fn test_fetch_schema() {
        let url = "https://raw.githubusercontent.com/MinaProtocol/mina/master/src/app/archive/create_schema.sql";
        let tempdir = tempfile::Builder::new()
            .prefix("test_fetch_schema")
            .tempdir()
            .expect("Cannot create temporary directory");
        let network_path = tempdir.path();
        let file_path = fetch_schema(url, network_path.to_path_buf()).unwrap();
        assert!(file_path.exists());
        assert_eq!(file_path.file_name().unwrap(), "create_schema.sql");
    }
}
