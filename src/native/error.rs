//! Errors of native mode. Callers get them as `io::Error` with a kind that
//! tells them apart (a running service is `AlreadyExists`, a missing one
//! `NotFound`), so `?` keeps working through the `io::Result` API.

use std::{io, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    #[error("'{name}' is already running (pid {pid})")]
    AlreadyRunning { name: String, pid: u32 },
    #[error("'{name}' is running (pid {pid}); stop it first")]
    RunningDuringReset { name: String, pid: u32 },
    #[error("already running: {}", .0.join(", "))]
    NetworkRunning(Vec<String>),
    #[error("Service '{0}' is not running")]
    NotRunning(String),
    #[error("the uptime service backend is not supported in native mode")]
    UptimeServiceUnsupported,
    #[error("seed '{seed}' exited during startup; see {}", .log.display())]
    SeedExited { seed: String, log: PathBuf },
    #[error("seed '{seed}' did not accept connections on port {port} within {secs}s")]
    SeedTimeout { seed: String, port: u16, secs: u64 },
    #[error("Failed to start {name} ({}): {cause}", .binary.display())]
    Spawn {
        name: String,
        binary: PathBuf,
        cause: io::Error,
    },
    #[error("no {what} for '{service}' at {}: {cause}", .path.display())]
    Unreadable {
        what: &'static str,
        service: String,
        path: PathBuf,
        cause: io::Error,
    },
    #[error("path '{}' is not valid UTF-8", .0.display())]
    NotUtf8(PathBuf),
}

impl From<NativeError> for io::Error {
    fn from(e: NativeError) -> Self {
        use io::ErrorKind::*;
        let kind = match &e {
            NativeError::NotUtf8(_) => InvalidInput,
            NativeError::AlreadyRunning { .. }
            | NativeError::RunningDuringReset { .. }
            | NativeError::NetworkRunning(_) => AlreadyExists,
            NativeError::NotRunning(_) => NotFound,
            NativeError::UptimeServiceUnsupported => Unsupported,
            NativeError::SeedTimeout { .. } => TimedOut,
            NativeError::SeedExited { .. } => Other,
            NativeError::Spawn { cause, .. } | NativeError::Unreadable { cause, .. } => {
                cause.kind()
            }
        };
        io::Error::new(kind, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_tell_errors_apart() {
        let io = |e: NativeError| io::Error::from(e);
        let running = io(NativeError::AlreadyRunning {
            name: "a".into(),
            pid: 7,
        });
        assert_eq!(running.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(running.to_string(), "'a' is already running (pid 7)");
        assert_eq!(
            io(NativeError::NotRunning("a".into())).kind(),
            io::ErrorKind::NotFound
        );
        let spawn = io(NativeError::Spawn {
            name: "a".into(),
            binary: "/x/mina".into(),
            cause: io::Error::from(io::ErrorKind::PermissionDenied),
        });
        assert_eq!(spawn.kind(), io::ErrorKind::PermissionDenied);
        assert!(spawn
            .to_string()
            .starts_with("Failed to start a (/x/mina): "));
    }
}
