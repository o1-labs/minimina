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

/// Copies an archive schema into `network_path` and returns the copy's path.
///
/// `source` is an `http(s)://` URL (downloaded; HTTP errors fail), a `file://`
/// URL or a local path.
pub fn fetch_schema(source: &str, network_path: PathBuf) -> io::Result<PathBuf> {
    debug!("Fetching schema from: {source}");

    let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidInput, msg);
    let local = match Url::parse(source) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => None,
        Ok(url) if url.scheme() == "file" => Some(
            url.to_file_path()
                .map_err(|_| invalid(format!("invalid schema file URL '{source}'")))?,
        ),
        Ok(url) => {
            return Err(invalid(format!(
                "unsupported schema URL scheme '{}' in '{source}'",
                url.scheme()
            )))
        }
        // not a URL: a path
        Err(_) => Some(PathBuf::from(source)),
    };

    let file_name = match &local {
        Some(path) => path.file_name().map(|n| n.to_string_lossy().into_owned()),
        None => Url::parse(source)
            .ok()
            .and_then(|u| u.path_segments()?.next_back().map(str::to_string)),
    }
    .filter(|n| !n.is_empty())
    .ok_or_else(|| invalid(format!("schema '{source}' has no file name")))?;
    let file_path = network_path.join(file_name);

    match local {
        Some(path) => {
            std::fs::copy(&path, &file_path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("copying schema '{}': {e}", path.display()),
                )
            })?;
        }
        None => {
            let http_error =
                |e: reqwest::Error| io::Error::other(format!("fetching '{source}': {e}"));
            let bytes = reqwest::blocking::get(source)
                .and_then(|r| r.error_for_status())
                .map_err(http_error)?
                .bytes()
                .map_err(http_error)?;
            File::create(&file_path)?.write_all(&bytes)?;
        }
    }
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

    #[test]
    fn test_fetch_schema_rejects_http_errors() {
        let tempdir = tempfile::tempdir().unwrap();
        // removed from the archive after zkApp tables moved into create_schema.sql
        let url = "https://raw.githubusercontent.com/MinaProtocol/mina/84b8d96/src/app/archive/zkapp_tables.sql";
        let err = fetch_schema(url, tempdir.path().to_path_buf()).unwrap_err();
        assert!(err.to_string().contains("404"), "{err}");
        assert!(!tempdir.path().join("zkapp_tables.sql").exists());
    }

    #[test]
    fn test_fetch_schema_copies_local_files() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let schema = src.path().join("create_schema.sql");
        std::fs::write(&schema, "CREATE TABLE t ();").unwrap();

        let copied = fetch_schema(schema.to_str().unwrap(), dest.path().to_path_buf()).unwrap();
        assert_eq!(copied, dest.path().join("create_schema.sql"));
        assert_eq!(
            std::fs::read_to_string(&copied).unwrap(),
            "CREATE TABLE t ();"
        );

        let url = Url::from_file_path(&schema).unwrap();
        fetch_schema(url.as_str(), dest.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_fetch_schema_rejects_missing_and_unsupported_sources() {
        let dest = tempfile::tempdir().unwrap();
        let err = fetch_schema("/no/such/schema.sql", dest.path().to_path_buf()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let err = fetch_schema("ftp://host/schema.sql", dest.path().to_path_buf()).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported schema URL scheme 'ftp'"));
    }
}
